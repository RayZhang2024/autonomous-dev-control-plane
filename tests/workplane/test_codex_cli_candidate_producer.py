from __future__ import annotations

import hashlib
import os
from pathlib import Path
import threading
import time

import pytest

import autodev_control.workplane.codex_cli_candidate_producer as o2c
from autodev_control.workplane.candidate_producer import ProducerStatus, ProposedChangeKind


class FakePreflight:
    def __init__(self, *, reject: bool = False) -> None:
        self.calls = 0
        self.reject = reject

    def inspect(self, executable_path, expected_version, child_environment, timeout_seconds, deployment):
        self.calls += 1
        assert child_environment["TEMP"].endswith("runtime-tmp")
        if self.reject:
            raise o2c.O2cPreflightError("incompatible fake effective state")
        return o2c.CodexEffectiveState(
            tuple((name, False) for name in o2c.CAPABILITY_DENY_SET),
            0,
            "disabled",
            False,
            True,
            True,
            (),
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
        if self.status == "large-output":
            return outcome(stderr_byte_count=o2c.MAX_STDIO_DIAGNOSTIC_BYTES + 1)
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


def deployment(**overrides):
    values = dict(
        isolation_kind="dedicated_vm",
        readable_data_set_minimal=True,
        forbidden_stores_absent_or_inaccessible=True,
        worker_account_non_admin=True,
        worker_account_not_trusted_role=True,
        dedicated_codex_principal=True,
        principal_inference_only=True,
        principal_has_no_target_control_root_rights=True,
        principal_has_no_unrelated_private_apps_or_data=True,
        codex_credential_may_be_accessible_to_worker=True,
        keyring_credentials_store="keyring",
        forced_login_method="chatgpt",
        mcp_configuration_sources_absent=True,
        managed_system_policy_inspected=True,
        managed_system_external_broadening=(),
        exec_policy_rules_absent=True,
        effective_web_search_mode="disabled",
    )
    values.update(overrides)
    return o2c.CodexWorkerDeployment(**values)


def configured(tmp_path, *, preflight=None, runner=None, seed=None, deployment_facts=None):
    worker_home = tmp_path / "worker-home"
    codex_home = worker_home / ".codex-worker"
    scratch_root = tmp_path / "scratch"
    executable = tmp_path / "codex.exe"
    for path in (worker_home, codex_home, scratch_root):
        path.mkdir(parents=True)
    executable.write_bytes(b"pinned codex executable fixture")
    config = o2c.CodexCliConfiguration(
        str(executable), "codex 1.2.3", hashlib.sha256(executable.read_bytes()).hexdigest(),
        str(worker_home), str(codex_home), str(scratch_root), 30,
    )
    environment = {"HOME": str(worker_home), "USERPROFILE": str(worker_home), "CODEX_HOME": str(codex_home), "PATH": "safe-path", "OPENAI_API_KEY": "must-not-leak", "GH_TOKEN": "must-not-leak", "TEMP": "operator-temp", "TMP": "operator-tmp"}
    producer = o2c.CodexCliCandidateProducer(
        config,
        seed or o2c.CodexWorkspaceSeed("a" * 40, (o2c.CodexWorkspaceFile("base.txt", b"before", "100755"),)),
        deployment_facts or deployment(),
        preflight=preflight or FakePreflight(),
        runner=runner or FakeRunner(),
        parent_environment=environment,
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
    ("large-output", ProducerStatus.PRODUCER_ERROR),
])
def test_timeout_nonzero_and_resource_violation_never_propose(tmp_path, status, expected):
    runner = FakeRunner(status=status, mutate=lambda root: (root / "partial.py").write_text("partial"))
    producer, _, _ = configured(tmp_path, runner=runner)
    result = producer.invoke(b"request")
    assert result.status is expected and result.candidate_proposal is None
    assert runner.calls == producer.task_attempt_count == 1


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
        ))


def test_frozen_command_profile_and_environment_allowlist():
    args = o2c.build_codex_arguments("C:/scratch/workspace")
    assert args[:10] == ("exec", "--strict-config", "--sandbox", "workspace-write", "--skip-git-repo-check", "--ephemeral", "--ignore-user-config", "--ignore-rules", "--cd", "C:/scratch/workspace")
    assert len([i for i, arg in enumerate(args) if arg == "--disable"]) == len(o2c.CAPABILITY_DENY_SET)
    assert all(args[i + 1] in o2c.CAPABILITY_DENY_SET for i, arg in enumerate(args[:-1]) if arg == "--disable")
    child = o2c.build_child_environment({"PATH": "p", "TEMP": "bad", "TMP": "bad", "OPENAI_API_KEY": "secret", "GH_TOKEN": "secret", "AWS_SECRET_ACCESS_KEY": "secret"}, worker_home="home", codex_home="codex", runtime_tmp="runtime")
    assert child["TEMP"] == child["TMP"] == "runtime"
    assert child["PATH"] == "p"
    assert not ({"OPENAI_API_KEY", "GH_TOKEN", "AWS_SECRET_ACCESS_KEY"} & child.keys())


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


def test_effective_state_rejects_unknown_enabled_mcp_and_policy_broadening():
    with pytest.raises(o2c.O2cPreflightError):
        o2c._validate_effective_state(o2c.CodexEffectiveState((("unknown_required", True),), 0, "disabled", False, True, True, ()))
    with pytest.raises(o2c.O2cPreflightError):
        o2c._validate_effective_state(o2c.CodexEffectiveState(tuple((name, False) for name in o2c.CAPABILITY_DENY_SET), 1, "disabled", False, True, True, ()))
    with pytest.raises(o2c.O2cPreflightError):
        o2c._validate_deployment(deployment(managed_system_external_broadening=("browser",)))


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
