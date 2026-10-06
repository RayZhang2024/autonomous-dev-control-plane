from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import threading
import time
from datetime import datetime, timedelta, timezone

import pytest

import autodev_control.workplane.codex_cli_candidate_producer as o2c
from autodev_control.workplane.candidate_producer import ProducerStatus, ProposedChangeKind


FIXED_NOW = datetime(2030, 1, 1, tzinfo=timezone.utc)
WORKER_ENVIRONMENT_ID = "fixture-vm-instance-01"


class FakePreflight:
    def __init__(self, *, reject: bool = False) -> None:
        self.calls = 0
        self.reject = reject

    def inspect(self, executable_path, expected_version, child_environment, timeout_seconds, deployment):
        self.calls += 1
        assert child_environment["TEMP"].endswith("runtime-tmp")
        if self.reject:
            raise o2c.O2cPreflightError("incompatible fake effective state")
        raw_version, package_version = o2c._parse_codex_cli_version(expected_version.encode("utf-8"))
        return o2c.CodexEffectiveState(
            tuple((name, False) for name in o2c.CAPABILITY_DENY_SET),
            0,
            "mxc",
            0,
            raw_version,
            package_version,
        )


class FakeRunner:
    def __init__(self, *, status="success", mutate=None):
        self.calls = 0
        self.status = status
        self.mutate = mutate
        self.workspace = None
        self.environment = None
        self.prompt = None

    def run(self, executable_path, arguments, workspace, child_environment, prompt_bytes, timeout_seconds):
        self.calls += 1
        self.workspace = Path(workspace)
        self.environment = dict(child_environment)
        self.prompt = prompt_bytes
        assert arguments[0] == "exec"
        assert arguments[-1] == "-"
        assert "--dangerously-bypass-approvals-and-sandbox" not in arguments
        if self.mutate:
            self.mutate(self.workspace)
        if self.status == "timeout":
            return outcome(root_exit_code=1, timed_out=True)
        if self.status == "nonzero":
            return outcome(root_exit_code=7)
        if self.status == "violation":
            return outcome(resource_limit_violation=True)
        if self.status == "no-assignment":
            return outcome(job_assignment_succeeded=False)
        if self.status == "not-resumed":
            return outcome(root_process_resumed_after_assignment=False)
        if self.status == "large-output":
            data = b"x" * 100_000
            return outcome(stdout_byte_count=len(data), stdout_sha256=hashlib.sha256(data).hexdigest(),
                           stderr_byte_count=len(data), stderr_sha256=hashlib.sha256(data).hexdigest())
        return outcome()


def outcome(**overrides):
    values = dict(
        root_exit_code=0,
        timed_out=False,
        process_tree_quiescent=True,
        resource_limit_violation=False,
        stdout_byte_count=3,
        stdout_sha256=hashlib.sha256(b"out").hexdigest(),
        stderr_byte_count=0,
        stderr_sha256=hashlib.sha256(b"").hexdigest(),
        elapsed_milliseconds=12,
    )
    values.update(overrides)
    return o2c.ContainedExecutionOutcome(**values)


def deployment(configuration, *, now=FIXED_NOW, **overrides):
    values = dict(
        format_version="o2c-deployment-attestation/1",
        worker_isolation_kind="dedicated_vm",
        worker_identity=o2c._current_worker_identity(),
        attestation_id="a" * 64,
        worker_environment_id=configuration.expected_worker_environment_id,
        issued_at_utc=now - timedelta(minutes=1),
        expires_at_utc=now + timedelta(minutes=1),
        source_head_sha=configuration.expected_source_head_sha,
        codex_executable_path=configuration.absolute_codex_executable_path,
        codex_executable_version=configuration.expected_codex_version,
        codex_executable_sha256=configuration.expected_codex_executable_sha256,
        evidence_items=tuple(
            o2c.CodexDeploymentEvidence(
                check_id, "pass", "fixture", "offline-test-fixture",
                hashlib.sha256(check_id.encode()).hexdigest(), f"fixture://{check_id}"
            ) for check_id in o2c.DEPLOYMENT_CHECKS
        ),
    )
    values.update(overrides)
    return o2c.CodexWorkerDeploymentAttestation(**values)


def configured(tmp_path, *, preflight=None, runner=None, seed=None, deployment_facts=None, clock=None):
    worker_home = tmp_path / "worker-home"
    codex_home = worker_home / ".codex-worker"
    scratch_root = tmp_path / "scratch"
    executable = tmp_path / "codex.exe"
    for path in (worker_home, codex_home, scratch_root):
        path.mkdir(parents=True)
    executable.write_bytes(b"pinned codex executable fixture")
    config = o2c.CodexCliConfiguration(
        str(executable), "codex-cli 1.2.3", hashlib.sha256(executable.read_bytes()).hexdigest(),
        str(worker_home), str(codex_home), str(scratch_root), 30, "a" * 40, WORKER_ENVIRONMENT_ID,
    )
    environment = {"HOME": str(worker_home), "USERPROFILE": str(worker_home), "CODEX_HOME": str(codex_home), "PATH": "safe-path", "OPENAI_API_KEY": "must-not-leak", "GH_TOKEN": "must-not-leak", "TEMP": "operator-temp", "TMP": "operator-tmp"}
    producer = o2c.CodexCliCandidateProducer(
        config,
        seed or o2c.CodexWorkspaceSeed("a" * 40, (o2c.CodexWorkspaceFile("base.txt", b"before", "100755"),)),
        deployment_facts or deployment(config),
        preflight=preflight or FakePreflight(),
        runner=runner or FakeRunner(),
        parent_environment=environment,
        clock=clock or (lambda: FIXED_NOW),
    )
    return producer, executable, environment


def test_success_extracts_exact_add_replace_delete_order_and_preserves_modes(tmp_path):
    def mutate(workspace):
        (workspace / "base.txt").write_bytes(b"after")
        (workspace / "z.txt").unlink()
        (workspace / "added.txt").write_bytes(b"new")

    seed = o2c.CodexWorkspaceSeed("a" * 40, (
        o2c.CodexWorkspaceFile("z.txt", b"delete me", "100644"),
        o2c.CodexWorkspaceFile("base.txt", b"before", "100755"),
    ))
    runner = FakeRunner(mutate=mutate)
    producer, _, _ = configured(tmp_path, runner=runner, seed=seed)
    result = producer.invoke(b"implement exactly this request\n")
    assert result.status is ProducerStatus.SUCCESS
    changes = result.candidate_proposal.changes
    assert [(change.kind, change.path) for change in changes] == [
        (ProposedChangeKind.ADD, "added.txt"),
        (ProposedChangeKind.REPLACE, "base.txt"),
        (ProposedChangeKind.DELETE, "z.txt"),
    ]
    assert changes[0].content_bytes == b"new" and changes[0].mode == "100644"
    assert changes[1].content_bytes == b"after" and changes[1].mode is None
    assert changes[2].content_bytes is None and changes[2].mode is None
    assert result.candidate_proposal.claimed_base_revision == "a" * 40
    assert runner.calls == producer.task_attempt_count == 1
    assert runner.prompt.endswith(b"implement exactly this request\n")
    assert runner.environment["TEMP"].endswith("runtime-tmp")
    assert runner.environment["TMP"].endswith("runtime-tmp")
    assert "OPENAI_API_KEY" not in runner.environment and "GH_TOKEN" not in runner.environment
    assert not runner.workspace.parent.exists()
    assert result.untrusted_metadata.stdout_sha256 == hashlib.sha256(b"out").hexdigest()
    assert result.untrusted_metadata.stderr_sha256 == hashlib.sha256(b"").hexdigest()
    assert result.untrusted_metadata.codex_cli_version_raw == "codex-cli 1.2.3"
    assert result.untrusted_metadata.codex_package_version == "1.2.3"
    assert result.untrusted_metadata.codex_version == producer._deployment.codex_executable_version
    assert not hasattr(result.untrusted_metadata, "stdout")


@pytest.mark.parametrize("request_bytes", [b"\xff", b"x" * (o2c.MAX_REQUEST_BYTES + 1)], ids=["invalid-utf8", "oversized"])
def test_invalid_or_oversized_request_fails_before_one_task_attempt(tmp_path, request_bytes):
    runner = FakeRunner()
    producer, _, _ = configured(tmp_path, runner=runner)
    result = producer.invoke(request_bytes)
    assert result.status is ProducerStatus.PRODUCER_ERROR
    assert result.candidate_proposal is None
    assert runner.calls == producer.task_attempt_count == 0


@pytest.mark.parametrize(("status", "expected"), [
    ("timeout", ProducerStatus.TIMEOUT),
    ("nonzero", ProducerStatus.PRODUCER_ERROR),
    ("violation", ProducerStatus.PRODUCER_ERROR),
    ("no-assignment", ProducerStatus.PRODUCER_ERROR),
    ("not-resumed", ProducerStatus.PRODUCER_ERROR),
])
def test_timeout_nonzero_and_resource_violation_never_propose(tmp_path, status, expected):
    runner = FakeRunner(status=status, mutate=lambda root: (root / "partial.py").write_text("partial"))
    producer, _, _ = configured(tmp_path, runner=runner)
    result = producer.invoke(b"request")
    assert result.status is expected and result.candidate_proposal is None
    assert runner.calls == producer.task_attempt_count == 1


def test_task_output_above_64kib_is_streamed_as_count_and_digest_only(tmp_path):
    runner = FakeRunner(status="large-output")
    producer, _, _ = configured(tmp_path, runner=runner)
    result = producer.invoke(b"request")
    assert result.status is ProducerStatus.SUCCESS
    metadata = result.untrusted_metadata
    assert metadata.stdout_byte_count == metadata.stderr_byte_count == 100_000
    assert metadata.stdout_sha256 == metadata.stderr_sha256 == hashlib.sha256(b"x" * 100_000).hexdigest()
    assert not hasattr(metadata, "stdout") and not hasattr(metadata, "stderr")


def test_preflight_fails_closed_before_task_attempt(tmp_path):
    runner = FakeRunner()
    producer, _, _ = configured(tmp_path, preflight=FakePreflight(reject=True), runner=runner)
    result = producer.invoke(b"request")
    assert result.status is ProducerStatus.PRODUCER_ERROR
    assert runner.calls == producer.task_attempt_count == 0


def test_noop_is_a_valid_empty_proposal(tmp_path):
    producer, _, _ = configured(tmp_path, runner=FakeRunner())
    result = producer.invoke(b"request")
    assert result.status is ProducerStatus.SUCCESS
    assert result.candidate_proposal.changes == ()


def test_executable_hash_change_after_task_fails_without_proposal(tmp_path):
    runner = FakeRunner()
    producer, executable, _ = configured(tmp_path, runner=runner)
    original_run = runner.run
    def mutate_executable(*args):
        original_run(*args)
        executable.write_bytes(b"changed pinned executable")
        return outcome()
    runner.run = mutate_executable
    result = producer.invoke(b"request")
    assert result.status is ProducerStatus.PRODUCER_ERROR
    assert result.candidate_proposal is None
    assert producer.task_attempt_count == 1


def test_workspace_symlink_and_hard_link_outputs_are_rejected(tmp_path):
    def symlink_mutation(workspace):
        (workspace / "link.txt").symlink_to(workspace / "base.txt")
    producer, _, _ = configured(tmp_path / "symlink", runner=FakeRunner(mutate=symlink_mutation))
    try:
        symlink_result = producer.invoke(b"request")
    except OSError:
        pytest.skip("filesystem does not allow creation of test symlinks")
    assert symlink_result.status is ProducerStatus.PRODUCER_ERROR

    def hardlink_mutation(workspace):
        os.link(workspace / "base.txt", workspace / "hardlink.txt")
    producer, _, _ = configured(tmp_path / "hardlink", runner=FakeRunner(mutate=hardlink_mutation))
    assert producer.invoke(b"request").status is ProducerStatus.PRODUCER_ERROR


def test_cleanup_failure_erases_otherwise_successful_result(tmp_path, monkeypatch):
    producer, _, _ = configured(tmp_path, runner=FakeRunner())
    monkeypatch.setattr(o2c.shutil, "rmtree", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("cleanup blocked")))
    result = producer.invoke(b"request")
    assert result.status is ProducerStatus.PRODUCER_ERROR
    assert result.candidate_proposal is None


@pytest.mark.parametrize("path", ["", "/absolute", "trailing/", "a//b", "a/../b", "a\\b", ".git/config", ".codex", ".agents/skills/x", "a\x00b"])
def test_seed_path_grammar_and_reserved_names(path):
    seed = o2c.CodexWorkspaceSeed("a" * 40, (o2c.CodexWorkspaceFile(path, b"", "100644"),))
    with pytest.raises(o2c.O2cPreflightError):
        o2c._validate_seed(seed)


def test_reserved_paths_and_windows_alias_collisions_are_rejected():
    for path in (".GIT/config", ".Codex/config", ".AGENTS/plugins"):
        with pytest.raises(o2c.O2cPreflightError):
            o2c._validate_seed(o2c.CodexWorkspaceSeed("a" * 40, (o2c.CodexWorkspaceFile(path, b"x", "100644"),)))
    for files in (
        (o2c.CodexWorkspaceFile("Name", b"a", "100644"), o2c.CodexWorkspaceFile("name", b"b", "100644")),
        (o2c.CodexWorkspaceFile("Name", b"a", "100644"), o2c.CodexWorkspaceFile("name/child", b"b", "100644")),
    ):
        with pytest.raises(o2c.O2cPreflightError):
            o2c._validate_seed(o2c.CodexWorkspaceSeed("a" * 40, files))


def test_duplicate_prefix_mode_and_seed_limits_fail_closed():
    with pytest.raises(o2c.O2cPreflightError):
        o2c._validate_seed(o2c.CodexWorkspaceSeed("a" * 40, (o2c.CodexWorkspaceFile("x", b"1", "100644"), o2c.CodexWorkspaceFile("x", b"2", "100644"))))
    with pytest.raises(o2c.O2cPreflightError):
        o2c._validate_seed(o2c.CodexWorkspaceSeed("a" * 40, (o2c.CodexWorkspaceFile("x", b"1", "100644"), o2c.CodexWorkspaceFile("x/y", b"2", "100644"))))
    with pytest.raises(o2c.O2cPreflightError):
        o2c._validate_seed(o2c.CodexWorkspaceSeed("a" * 40, (o2c.CodexWorkspaceFile("x", b"1", "100755 "),)))
    assert o2c.MAX_REQUEST_BYTES == 131_072
    assert o2c.MAX_BASE_FILES == o2c.MAX_OUTPUT_FILES == 4_096
    assert o2c.MAX_PROPOSAL_CHANGES == 1_024
    assert o2c.MAX_PROPOSAL_CONTENT_BYTES == 16_777_216
    assert o2c.MAX_JOB_ACTIVE_PROCESSES == 64
    assert o2c.MAX_JOB_MEMORY_BYTES == 4_294_967_296
    assert o2c.JOB_CPU_HARD_CAP_PERCENT == 80


def test_invalid_base_revision_utf8_depth_and_bounded_observation(tmp_path, monkeypatch):
    for revision in ("A" * 40, "g" * 40, "a" * 39, "a" * 41):
        with pytest.raises(o2c.O2cPreflightError):
            o2c._validate_seed(o2c.CodexWorkspaceSeed(revision, ()))
    with pytest.raises(o2c.O2cPreflightError):
        o2c._validate_seed(o2c.CodexWorkspaceSeed("a" * 40, (o2c.CodexWorkspaceFile("bad\ud800", b"", "100644"),)))
    too_deep = "/".join(["d"] * (o2c.MAX_TREE_DEPTH + 1))
    with pytest.raises(o2c.O2cPreflightError):
        o2c._validate_seed(o2c.CodexWorkspaceSeed("a" * 40, (o2c.CodexWorkspaceFile(too_deep, b"", "100644"),)))
    workspace = tmp_path / "observe"
    workspace.mkdir()
    (workspace / "large.bin").write_bytes(b"123")
    monkeypatch.setattr(o2c, "MAX_FILE_BYTES", 2)
    with pytest.raises(o2c.O2cPreflightError):
        o2c._observe_workspace(workspace)


def test_executable_must_be_absolute_exact_exe_with_configured_hash(tmp_path):
    producer, _, _ = configured(tmp_path)
    configuration = producer._configuration
    with pytest.raises(o2c.O2cPreflightError):
        o2c._validate_configuration(o2c.CodexCliConfiguration(
            "codex.exe", configuration.expected_codex_version, configuration.expected_codex_executable_sha256,
            configuration.worker_home, configuration.codex_home, configuration.scratch_root, configuration.timeout_seconds,
            configuration.expected_source_head_sha, configuration.expected_worker_environment_id,
        ))


def test_frozen_command_profile_and_environment_allowlist():
    args = o2c.build_codex_arguments("C:/scratch/workspace")
    assert args[:12] == (
        "exec", "--strict-config", "-c", 'windows.sandbox="unelevated"',
        "--sandbox", "workspace-write", "--skip-git-repo-check", "--ephemeral",
        "--ignore-user-config", "--ignore-rules", "--cd", "C:/scratch/workspace",
    )
    assert tuple(args[i + 1] for i, arg in enumerate(args[:-1]) if arg == "--disable") == o2c.CAPABILITY_DENY_SET
    child = o2c.build_child_environment({"PATH": "p", "TEMP": "bad", "TMP": "bad", "OPENAI_API_KEY": "secret", "GH_TOKEN": "secret", "AWS_SECRET_ACCESS_KEY": "secret"}, worker_home="home", codex_home="codex", runtime_tmp="runtime")
    assert child["TEMP"] == child["TMP"] == "runtime"
    assert child["PATH"] == "p"
    assert not ({"OPENAI_API_KEY", "GH_TOKEN", "AWS_SECRET_ACCESS_KEY"} & child.keys())
    profile = o2c.configured_execution_profile()
    assert profile.sandbox_profile == "workspace-write"
    assert profile.approval_policy == "never" and profile.shell_network is False
    assert profile.web_search_requested == "disabled" and profile.extra_writable_roots == ()
    assert profile.sandbox_tmp_writability_exclusions_enabled
    assert profile.auth_credential_store_requested == "keyring" and profile.login_method_requested == "chatgpt"
    assert profile.ephemeral and profile.ignore_user_config and profile.ignore_rules
    assert profile.job_object_limits == o2c.JobObjectLimits(True, False, False, 64, 4_294_967_296, 80)
    assert profile.process_containment_kind == "windows_job_object"
    assert profile.workspace_path_class == "fresh_invocation_plain_non_git_workspace"
    assert profile.target_repository_credentials_intentionally_present is False
    assert profile.control_root_credentials_intentionally_present is False


def test_home_codex_home_and_deployment_preflight_reject_unsuitable_state(tmp_path):
    producer, _, environment = configured(tmp_path)
    codex_home = Path(producer._configuration.codex_home)
    (codex_home / "config.toml").write_text("unsafe")
    result = producer.invoke(b"request")
    assert result.status is ProducerStatus.PRODUCER_ERROR
    (codex_home / "config.toml").unlink()
    (Path(producer._configuration.worker_home) / ".agents" / "skills").mkdir(parents=True)
    assert producer.invoke(b"request").status is ProducerStatus.PRODUCER_ERROR
    assert environment["TEMP"] == "operator-temp"


def test_effective_state_rejects_unknown_enabled_mcp_and_capabilities():
    with pytest.raises(o2c.O2cPreflightError):
        o2c._validate_effective_state(o2c.CodexEffectiveState((("unknown_required", True),), 0, "mxc", 0, "codex-cli fixture", "fixture"))
    with pytest.raises(o2c.O2cPreflightError):
        o2c._validate_effective_state(o2c.CodexEffectiveState(tuple((name, False) for name in o2c.CAPABILITY_DENY_SET), 1, "mxc", 0, "codex-cli fixture", "fixture"))
    with pytest.raises(o2c.O2cPreflightError):
        o2c._validate_effective_state(o2c.CodexEffectiveState(tuple((name, False) for name in o2c.CAPABILITY_DENY_SET) + (("browser_use", True),), 0, "mxc", 0, "codex-cli fixture", "fixture"))


DOCTOR_VERSION = "1.2.3"
_UNSET = object()


def doctor_json_fixture(
    *, schema_version=1, codex_version=DOCTOR_VERSION, checks=_UNSET, check=_UNSET,
    include_schema=True, include_checks=True, include_version=True,
):
    if check is _UNSET:
        check = {
            "id": "sandbox.helpers", "category": "sandbox", "status": "ok",
            "summary": "fixture", "details": {"sandbox backend": "mxc"},
            "issues": [], "notes": [], "remediation": None, "durationMs": 0,
        }
    report = {"generatedAt": "fixture", "overallStatus": "ok"}
    if include_schema:
        report["schemaVersion"] = schema_version
    if include_version:
        report["codexVersion"] = codex_version
    if include_checks:
        report["checks"] = {"sandbox.helpers": check} if checks is _UNSET else checks
    return json.dumps(report).encode("utf-8")


def test_sandbox_doctor_json_extracts_exact_backend_value():
    assert o2c._sandbox_implementation(doctor_json_fixture(), DOCTOR_VERSION) == "mxc"


def test_codex_01601_doctor_normalizes_only_exact_redacted_backend():
    check = {"id": "sandbox.helpers", "category": "sandbox", "status": "ok", "details": {"sandbox backend": "<redacted>"}}
    report = doctor_json_fixture(codex_version="0.160.1", check=check)
    assert "<redacted>" not in o2c.SUPPORTED_WINDOWS_SANDBOX_IMPLEMENTATIONS
    assert o2c._sandbox_implementation(report, "0.160.1") == "restricted-token"
    with pytest.raises(o2c.O2cPreflightError):
        o2c._sandbox_implementation(report, "0.160.2")
    with pytest.raises(o2c.O2cPreflightError):
        o2c._sandbox_implementation(doctor_json_fixture(codex_version="0.160.2", check=check), "0.160.2")


@pytest.mark.parametrize("backend", sorted(o2c.SUPPORTED_WINDOWS_SANDBOX_IMPLEMENTATIONS))
@pytest.mark.parametrize("version", [DOCTOR_VERSION, "0.160.1"])
def test_windows_sandbox_doctor_accepts_supported_enabled_backends(backend, version):
    check = {"id": "sandbox.helpers", "category": "sandbox", "status": "ok", "details": {"sandbox backend": backend}}
    assert o2c._sandbox_implementation(doctor_json_fixture(codex_version=version, check=check), version) == backend


@pytest.mark.parametrize("backend", ["disabled", "unknown", "", "fixture-backend"])
def test_windows_sandbox_doctor_rejects_disabled_and_unknown_backends(backend):
    check = {"id": "sandbox.helpers", "category": "sandbox", "status": "ok", "details": {"sandbox backend": backend}}
    with pytest.raises(o2c.O2cPreflightError):
        o2c._sandbox_implementation(doctor_json_fixture(check=check), DOCTOR_VERSION)


@pytest.mark.parametrize("details", [
    {},
    {"sandbox backend": "disabled"},
    {"sandbox backend": "unknown"},
    {"sandbox backend": ""},
    {"sandbox backend": "<redacted> "},
    {"sandbox backend": ["<redacted>"]},
    {"sandbox backend": None},
])
def test_codex_01601_doctor_rejects_other_backend_values(details):
    check = {"id": "sandbox.helpers", "category": "sandbox", "status": "ok", "details": details}
    with pytest.raises(o2c.O2cPreflightError):
        o2c._sandbox_implementation(doctor_json_fixture(codex_version="0.160.1", check=check), "0.160.1")


def test_codex_01601_doctor_rejects_failing_sandbox_check_even_when_backend_is_redacted():
    check = {"id": "sandbox.helpers", "category": "sandbox", "status": "fail", "details": {"sandbox backend": "<redacted>"}}
    with pytest.raises(o2c.O2cPreflightError):
        o2c._sandbox_implementation(doctor_json_fixture(codex_version="0.160.1", check=check), "0.160.1")


def test_codex_cli_version_parser_preserves_raw_line_and_derives_package_version():
    assert o2c._parse_codex_cli_version(b"codex-cli 0.153.4\r\n") == (
        "codex-cli 0.153.4", "0.153.4"
    )


@pytest.mark.parametrize("raw", [
    b"codex 0.153.4\n",
    b"Codex-cli 0.153.4\n",
    b"codex-cli\n",
    b"codex-cli \n",
    b"codex-cli 0.153.4 extra\n",
    b" codex-cli 0.153.4\n",
    b"codex-cli  0.153.4\n",
    b"codex-cli 0.153.4 \n",
    b"codex-cli 0.153.4\nextra\n",
    b"codex-cli 0.153.4\x01\n",
    b"codex-cli " + b"x" * 129 + b"\n",
])
def test_codex_cli_version_parser_rejects_malformed_raw_output(raw):
    with pytest.raises(o2c.O2cPreflightError):
        o2c._parse_codex_cli_version(raw)


@pytest.mark.parametrize("kwargs", [
    {"include_schema": False},
    {"schema_version": 2},
    {"schema_version": True},
    {"schema_version": "1"},
    {"include_checks": False},
    {"checks": []},
    {"checks": "bad"},
    {"checks": None},
    {"checks": False},
    {"include_version": False},
    {"checks": {}},
    {"checks": {"sandbox.helpers": None}},
    {"checks": {"sandbox.helpers": []}},
    {"check": {"id": "other", "category": "sandbox", "status": "ok", "details": {"sandbox backend": "mxc"}}},
    {"check": {"id": "sandbox.helpers", "category": "other", "status": "ok", "details": {"sandbox backend": "mxc"}}},
    {"check": {"id": "sandbox.helpers", "category": "sandbox", "status": "fail", "details": {"sandbox backend": "mxc"}}},
    {"check": {"id": "sandbox.helpers", "category": "sandbox", "status": "unknown", "details": {"sandbox backend": "mxc"}}},
    {"check": {"id": "sandbox.helpers", "category": "sandbox", "status": 1, "details": {"sandbox backend": "mxc"}}},
    {"check": {"id": "sandbox.helpers", "category": "sandbox", "status": "ok"}},
    {"check": {"id": "sandbox.helpers", "category": "sandbox", "status": "ok", "details": []}},
    {"check": {"id": "sandbox.helpers", "category": "sandbox", "status": "ok", "details": {}}},
    {"check": {"id": "sandbox.helpers", "category": "sandbox", "status": "ok", "details": {"sandbox backend": ["mxc", "elevated"]}}},
    {"check": {"id": "sandbox.helpers", "category": "sandbox", "status": "ok", "details": {"sandbox backend": ""}}},
    {"check": {"id": "sandbox.helpers", "category": "sandbox", "status": "ok", "details": {"sandbox backend": "x" * 129}}},
    {"check": {"id": "sandbox.helpers", "category": "sandbox", "status": "ok", "details": {"sandbox backend": "mxc\x00bad"}}},
    {"check": {"id": "sandbox.helpers", "category": "sandbox", "status": "ok", "details": {"sandbox backend": "mxc\x01bad"}}},
    {"codex_version": "codex 1.2.3-extra"},
    {"codex_version": "1.2.4"},
    {"codex_version": ""},
    {"codex_version": 1},
])
def test_sandbox_doctor_json_fails_closed_for_unsupported_report(kwargs):
    with pytest.raises(o2c.O2cPreflightError):
        o2c._sandbox_implementation(doctor_json_fixture(**kwargs), DOCTOR_VERSION)


@pytest.mark.parametrize("fixture", [
    b'[]',
    b'{"schemaVersion":1,"codexVersion":"1.2.3","sandbox.helpers":{"status":"ok","details":{"sandbox backend":"mxc"}}}',
    b'{"schemaVersion":1,"codexVersion":"1.2.3","checks":{},"checks":{}}',
    b'{"schemaVersion":1,"codexVersion":"1.2.3","checks":{"sandbox.helpers":{},"sandbox.helpers":{}}}',
    b'{"schemaVersion":1,"codexVersion":"1.2.3","checks":{"sandbox.helpers":{"id":"sandbox.helpers","category":"sandbox","status":"ok","details":{},"details":{}}}}',
    b'{"schemaVersion":1,"codexVersion":"1.2.3","checks":{"sandbox.helpers":{"id":"sandbox.helpers","category":"sandbox","status":"ok","details":{"sandbox backend":"mxc","sandbox backend":"elevated"}}}}',
    b'{not json}',
])
def test_sandbox_doctor_json_rejects_duplicate_keys_and_malformed_json(fixture):
    with pytest.raises(o2c.O2cPreflightError):
        o2c._sandbox_implementation(fixture, DOCTOR_VERSION)


@pytest.mark.parametrize("status", ["ok", "warning"])
def test_sandbox_doctor_json_accepts_nonfailing_check_statuses(status):
    check = {"id": "sandbox.helpers", "category": "sandbox", "status": status, "details": {"sandbox backend": "mxc"}}
    assert o2c._sandbox_implementation(doctor_json_fixture(check=check), DOCTOR_VERSION) == "mxc"


def test_unsupported_doctor_diagnostic_fails_producer_preflight_without_task_attempt(tmp_path, monkeypatch):
    runner = FakeRunner()
    producer, _, _ = configured(tmp_path, preflight=o2c.CodexCliPreflightProbe(), runner=runner)
    features = b"".join(f"{name} stable false\n".encode() for name in o2c.CAPABILITY_DENY_SET)

    calls = []

    def diagnostic(command, child_environment, timeout_seconds):
        calls.append(tuple(command))
        if command[-1:] == ("--version",):
            stdout = producer._configuration.expected_codex_version.encode() + b"\n"
        elif command[-2:] == ("features", "list"):
            stdout = features
        elif command[-3:] == ("mcp", "list", "--json"):
            stdout = b"[]"
        elif command[-2:] == ("doctor", "--json"):
            stdout = doctor_json_fixture(check={
                "id": "sandbox.helpers", "category": "sandbox", "status": "fail",
                "details": {"sandbox backend": "mxc"},
            })
        else:
            raise AssertionError(f"unexpected diagnostic command: {command!r}")
        exit_code = 9 if command[-2:] == ("doctor", "--json") else 0
        return o2c._DiagnosticOutput(exit_code, stdout, 0, hashlib.sha256(b"").hexdigest())

    monkeypatch.setattr(o2c, "_run_bounded_diagnostic", diagnostic)
    result = producer.invoke(b"request")
    assert result.status is ProducerStatus.PRODUCER_ERROR
    assert result.candidate_proposal is None
    assert producer.task_attempt_count == runner.calls == 0
    disabled_features = tuple(
        argument
        for feature in o2c.CAPABILITY_DENY_SET
        for argument in ("--disable", feature)
    )
    diagnostic_prefix = ("-c", o2c.WINDOWS_SANDBOX_CONFIG_OVERRIDE, *disabled_features)
    assert calls == [
        (producer._configuration.absolute_codex_executable_path, "--version"),
        (producer._configuration.absolute_codex_executable_path, *diagnostic_prefix, "features", "list"),
        (producer._configuration.absolute_codex_executable_path, *diagnostic_prefix, "mcp", "list", "--json"),
        (producer._configuration.absolute_codex_executable_path, "--strict-config", *diagnostic_prefix, "doctor", "--json"),
    ]
    assert all("--ignore-user-config" not in command and "--ignore-rules" not in command for command in calls[1:])


def test_cli_raw_version_must_match_attested_raw_version_before_other_diagnostics(tmp_path, monkeypatch):
    runner = FakeRunner()
    producer, _, _ = configured(tmp_path, preflight=o2c.CodexCliPreflightProbe(), runner=runner)
    assert producer._deployment.codex_executable_version == "codex-cli 1.2.3"
    calls = []

    def diagnostic(command, child_environment, timeout_seconds):
        calls.append(tuple(command))
        return o2c._DiagnosticOutput(
            0, b"codex-cli 9.9.9\n", 0, hashlib.sha256(b"").hexdigest()
        )

    monkeypatch.setattr(o2c, "_run_bounded_diagnostic", diagnostic)
    result = producer.invoke(b"request")
    assert result.status is ProducerStatus.PRODUCER_ERROR
    assert result.candidate_proposal is None
    assert len(calls) == 1 and calls[0][-1] == "--version"
    assert producer.task_attempt_count == runner.calls == 0


@pytest.mark.parametrize("row", [
    b"browser_use experimental true\n",
    b"computer_use under development false\n",
    b"apps stable false\n",
    b"plugins deprecated false\n",
    b"mcp removed false\n",
])
def test_feature_rows_accept_known_stages_and_final_boolean(row):
    assert o2c._feature_rows(row)[0][1] is (row.rstrip().endswith(b"true"))


@pytest.mark.parametrize("row", [
    b"feature true\n", b"feature unknown false\n", b"feature stable maybe\n", b"feature stable false extra\n",
])
def test_feature_rows_reject_malformed_unknown_stage_or_boolean(row):
    with pytest.raises(o2c.O2cPreflightError):
        o2c._feature_rows(row)


def test_job_notification_ids_classify_only_documented_resource_limit_messages():
    for message_id in (3, 9, 10, 11):
        assert o2c._is_resource_limit_notification(message_id)
    for message_id in (0, 1, 2, 4, 5, 6, 7, 8, 12):
        assert not o2c._is_resource_limit_notification(message_id)


def test_native_process_pipe_handles_have_one_central_close_owner(monkeypatch):
    class Kernel:
        def __init__(self):
            self.closed = []

        def CloseHandle(self, handle):
            self.closed.append(handle)
            return True

    api = object.__new__(o2c._NativeWindowsJobObjectApi)
    api._kernel = Kernel()
    chunks = iter((b"x" * 100_000, b""))
    monkeypatch.setattr(api, "_read", lambda _handle: next(chunks))
    output = {}
    api._drain(2, "stdout", output)
    assert output["stdout_count"] == 100_000
    assert output["stdout_hash"] == hashlib.sha256(b"x" * 100_000).hexdigest()
    process = o2c._NativeProcessState(5, 4, 1, 2, 3, b"")
    api.close_process(process)
    assert api._kernel.closed == [1, 2, 3, 4, 5]
    assert (process.stdin_handle, process.stdout_handle, process.stderr_handle, process.thread_handle, process.process_handle) == (0, 0, 0, 0, 0)


def test_deployment_attestation_requires_complete_consistent_bound_evidence(tmp_path):
    from dataclasses import replace

    producer, executable, _ = configured(tmp_path)
    attestation = deployment(producer._configuration)
    o2c._validate_deployment(attestation, producer._configuration, o2c._current_worker_identity(), hashlib.sha256(executable.read_bytes()).hexdigest(), FIXED_NOW)
    bad_items = attestation.evidence_items[:-1]
    with pytest.raises(o2c.O2cPreflightError):
        o2c._validate_deployment(replace(attestation, evidence_items=bad_items), producer._configuration, o2c._current_worker_identity(), attestation.codex_executable_sha256, FIXED_NOW)
    with pytest.raises(o2c.O2cPreflightError):
        o2c._validate_deployment(replace(attestation, source_head_sha="b" * 40), producer._configuration, o2c._current_worker_identity(), attestation.codex_executable_sha256, FIXED_NOW)
    with pytest.raises(o2c.O2cPreflightError):
        o2c._validate_deployment(replace(attestation, codex_executable_sha256="0" * 64), producer._configuration, o2c._current_worker_identity(), attestation.codex_executable_sha256, FIXED_NOW)
    conflicting = replace(attestation.evidence_items[0], result="fail")
    with pytest.raises(o2c.O2cPreflightError):
        o2c._validate_deployment(replace(attestation, evidence_items=(conflicting, *attestation.evidence_items[1:])), producer._configuration, o2c._current_worker_identity(), attestation.codex_executable_sha256, FIXED_NOW)


@pytest.mark.parametrize("mutation", [
    {"expires_at_utc": FIXED_NOW - timedelta(seconds=1)},
    {"issued_at_utc": FIXED_NOW + timedelta(seconds=o2c.MAX_ATTESTATION_FUTURE_SKEW_SECONDS + 1)},
    {"expires_at_utc": FIXED_NOW + timedelta(seconds=o2c.MAX_ATTESTATION_VALIDITY_SECONDS + 1)},
    {"expires_at_utc": FIXED_NOW - timedelta(minutes=1), "issued_at_utc": FIXED_NOW - timedelta(minutes=1)},
    {"worker_environment_id": ""},
    {"worker_environment_id": "wrong-environment"},
    {"source_head_sha": "b" * 40},
    {"codex_executable_path": "C:\\different\\codex.exe"},
    {"codex_executable_version": "codex 9.9"},
    {"codex_executable_sha256": "0" * 64},
    {"issued_at_utc": datetime(2030, 1, 1)},
    {"issued_at_utc": datetime(2030, 1, 1, tzinfo=timezone(timedelta(hours=1)))},
    {"attestation_id": "not-an-immutable-id"},
])
def test_deployment_attestation_freshness_and_binding_rejects_invalid_values(tmp_path, mutation):
    from dataclasses import replace

    producer, executable, _ = configured(tmp_path)
    attestation = replace(deployment(producer._configuration), **mutation)
    with pytest.raises(o2c.O2cPreflightError):
        o2c._validate_deployment(
            attestation, producer._configuration, o2c._current_worker_identity(),
            hashlib.sha256(executable.read_bytes()).hexdigest(), FIXED_NOW,
        )


def test_deployment_attestation_accepts_maximum_window_and_future_skew_boundary(tmp_path):
    from dataclasses import replace

    producer, executable, _ = configured(tmp_path)
    issued = FIXED_NOW + timedelta(seconds=o2c.MAX_ATTESTATION_FUTURE_SKEW_SECONDS)
    attestation = replace(
        deployment(producer._configuration),
        issued_at_utc=issued,
        expires_at_utc=issued + timedelta(seconds=o2c.MAX_ATTESTATION_VALIDITY_SECONDS),
    )
    o2c._validate_deployment(
        attestation, producer._configuration, o2c._current_worker_identity(),
        hashlib.sha256(executable.read_bytes()).hexdigest(), FIXED_NOW,
    )


def test_deployment_attestation_rejects_issue_beyond_future_skew(tmp_path):
    from dataclasses import replace

    producer, executable, _ = configured(tmp_path)
    issued = FIXED_NOW + timedelta(seconds=o2c.MAX_ATTESTATION_FUTURE_SKEW_SECONDS + 1)
    attestation = replace(
        deployment(producer._configuration), issued_at_utc=issued,
        expires_at_utc=issued + timedelta(seconds=60),
    )
    with pytest.raises(o2c.O2cPreflightError):
        o2c._validate_deployment(
            attestation, producer._configuration, o2c._current_worker_identity(),
            hashlib.sha256(executable.read_bytes()).hexdigest(), FIXED_NOW,
        )


def test_expired_attestation_fails_before_provider_attempt(tmp_path):
    from dataclasses import replace

    producer, _, _ = configured(tmp_path)
    producer._deployment = replace(
        producer._deployment,
        issued_at_utc=FIXED_NOW - timedelta(hours=1),
        expires_at_utc=FIXED_NOW - timedelta(seconds=1),
    )
    result = producer.invoke(b"request")
    assert result.status is ProducerStatus.PRODUCER_ERROR
    assert result.candidate_proposal is None
    assert producer.task_attempt_count == 0


def test_attestation_expiring_during_preflight_fails_before_task_attempt(tmp_path):
    times = iter((FIXED_NOW, FIXED_NOW + timedelta(minutes=2)))
    runner = FakeRunner()
    producer, _, _ = configured(tmp_path, runner=runner, clock=lambda: next(times))
    result = producer.invoke(b"request")
    assert result.status is ProducerStatus.PRODUCER_ERROR
    assert result.candidate_proposal is None
    assert runner.calls == producer.task_attempt_count == 0


def test_duplicate_parsed_feature_key_fails_actual_producer_preflight(tmp_path):
    class DuplicateFeaturePreflight(FakePreflight):
        def inspect(self, *args):
            self.calls += 1
            duplicate_rows = o2c._feature_rows(b"apps stable false\napps stable true\n")
            remaining = tuple((name, False) for name in o2c.CAPABILITY_DENY_SET if name != "apps")
            raw_version, package_version = o2c._parse_codex_cli_version(args[1].encode("utf-8"))
            return o2c.CodexEffectiveState(
                (*duplicate_rows, *remaining), 0, "mxc", 0, raw_version, package_version
            )

    runner = FakeRunner()
    producer, _, _ = configured(tmp_path, preflight=DuplicateFeaturePreflight(), runner=runner)
    result = producer.invoke(b"request")
    assert result.status is ProducerStatus.PRODUCER_ERROR
    assert result.candidate_proposal is None
    assert runner.calls == producer.task_attempt_count == 0


class FakeJobApi:
    def __init__(self, *, fail_assignment=False):
        self.events = []
        self.fail_assignment = fail_assignment
        self.limits = None

    def create_suspended_process(self, *args):
        self.events.append("suspended")
        return object()

    def create_job(self):
        self.events.append("create_job")
        return object()

    def configure_job(self, job, limits):
        self.events.append("configure")
        self.limits = limits

    def assign_process(self, job, process):
        self.events.append("assign")
        if self.fail_assignment:
            raise RuntimeError("assignment failure")

    def resume_process(self, process):
        self.events.append("resume")

    def execute_and_quiesce(self, job, process, timeout_seconds, limits):
        self.events.append("execute_quiesce")
        return outcome()

    def terminate_process(self, process):
        self.events.append("terminate")

    def close_job(self, job):
        self.events.append("close_job")

    def close_process(self, process):
        self.events.append("close_process")


def test_job_object_sequence_limits_and_fail_assignment_never_resumes(monkeypatch):
    monkeypatch.setattr(o2c.os, "name", "nt")
    api = FakeJobApi()
    result = o2c.WindowsJobObjectRunner(api).run("codex.exe", ("exec",), "workspace", {}, b"task", 3)
    assert result.process_tree_quiescent
    assert api.events[:5] == ["suspended", "create_job", "configure", "assign", "resume"]
    assert api.limits == o2c.JobObjectLimits(True, False, False, 64, 4_294_967_296, 80)
    failed = FakeJobApi(fail_assignment=True)
    with pytest.raises(RuntimeError):
        o2c.WindowsJobObjectRunner(failed).run("codex.exe", ("exec",), "workspace", {}, b"task", 3)
    assert "terminate" in failed.events and "resume" not in failed.events


def test_delayed_descendant_is_quiescent_before_workspace_observation(tmp_path, monkeypatch):
    child_alive = threading.Event()
    attempted = threading.Event()

    class DelayedDescendantRunner(FakeRunner):
        def run(self, executable_path, arguments, workspace, child_environment, prompt_bytes, timeout_seconds):
            self.calls += 1
            root = Path(workspace)
            child_alive.set()  # root exits zero while a contained child remains
            def delayed_write():
                time.sleep(0.03)
                (root / "late.txt").write_text("delayed child write")
                attempted.set()
                child_alive.clear()
            child = threading.Thread(target=delayed_write)
            child.start()
            while child_alive.is_set():
                time.sleep(0.005)
            child.join()
            return outcome()  # runner has established active-process count zero

    original_observer = o2c._observe_workspace
    def observe_only_when_empty(path):
        assert not child_alive.is_set() and attempted.is_set()
        return original_observer(path)

    monkeypatch.setattr(o2c, "_observe_workspace", observe_only_when_empty)
    producer, _, _ = configured(tmp_path, runner=DelayedDescendantRunner())
    result = producer.invoke(b"request")
    assert result.status is ProducerStatus.SUCCESS
    assert result.candidate_proposal.changes[0].path == "late.txt"


def test_production_module_has_no_trusted_o2b_or_publication_imports():
    source = Path(o2c.__file__).read_text(encoding="utf-8")
    assert "autodev_control.trusted" not in source
    assert "candidate_materializer" not in source
    assert "git push" not in source.lower()
    assert "github" not in source.lower()
