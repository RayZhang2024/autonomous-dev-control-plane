"""Fake-containment linkage tests plus a disabled-by-default real smoke harness."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
from dataclasses import asdict
from datetime import datetime, timedelta, timezone

import pytest

import autodev_control.workplane.codex_cli_candidate_producer as o2c
from autodev_control.workplane.candidate_producer import ProducerStatus
from autodev_control.workplane.fixture_candidate_materializer import (
    DeterministicFixtureCandidateMaterializer,
    FixtureBaseSnapshot,
    MaterializationStatus,
)
from tests.integration import test_o2b_fixture_candidate_materialization as o2b_test


FIXED_NOW = datetime(2030, 1, 1, tzinfo=timezone.utc)
PINNED_CODEX_01601 = Path(r"C:\O2C\bin\codex-0.160.1\bin\codex.exe")
PINNED_CODEX_01601_SHA256 = "9e7c59c05cc1ce5677b1f94e835b2ac038ca3be14504e78d558eacdb0ea3f55d"


class FakePreflight:
    def inspect(self, *args):
        raw_version, package_version = o2c._parse_codex_cli_version(args[1].encode("utf-8"))
        return o2c.CodexEffectiveState(
            tuple((name, False) for name in o2c.CAPABILITY_DENY_SET), 0, "mxc", 0,
            raw_version, package_version,
        )


class FakeContainedRunner:
    def __init__(self):
        self.calls = 0
        self.arguments = None

    def run(self, executable, arguments, workspace, environment, prompt_bytes, timeout_seconds):
        self.calls += 1
        self.arguments = tuple(arguments)
        (Path(workspace) / "o2c-output.txt").write_bytes(b"proposal from isolated fake worker")
        return o2c.ContainedExecutionOutcome(
            0, False, True, False, 0, hashlib.sha256(b"").hexdigest(),
            0, hashlib.sha256(b"").hexdigest(), 1,
        )


def _fixture_attestation(configuration: o2c.CodexCliConfiguration) -> o2c.CodexWorkerDeploymentAttestation:
    evidence = tuple(
        o2c.CodexDeploymentEvidence(
            check_id, "pass", "fixture", "offline-integration-fixture",
            hashlib.sha256(check_id.encode()).hexdigest(), f"fixture://{check_id}"
        ) for check_id in o2c.DEPLOYMENT_CHECKS
    )
    return o2c.CodexWorkerDeploymentAttestation(
        format_version="o2c-deployment-attestation/1",
        worker_isolation_kind="dedicated_vm",
        worker_identity=o2c._current_worker_identity(),
        source_head_sha=configuration.expected_source_head_sha,
        codex_executable_path=configuration.absolute_codex_executable_path,
        codex_executable_version=configuration.expected_codex_version,
        codex_executable_sha256=configuration.expected_codex_executable_sha256,
        evidence_items=evidence,
        attestation_id="b" * 64,
        worker_environment_id=configuration.expected_worker_environment_id,
        issued_at_utc=FIXED_NOW - timedelta(minutes=1),
        expires_at_utc=FIXED_NOW + timedelta(minutes=1),
    )


def test_fake_o2c_proposal_links_through_o2b_independent_verifier_and_trusted_admission(tmp_path):
    base_store = o2b_test.base_only_store()
    base_snapshot = o2b_test.project_exact_base(base_store, o2b_test.REPOSITORY, o2b_test.BASE)
    worker_home, codex_home, scratch_root = (tmp_path / name for name in ("worker-home", "codex-home", "scratch"))
    for path in (worker_home, codex_home, scratch_root):
        path.mkdir()
    executable = tmp_path / "codex.exe"
    executable.write_bytes(b"fake pinned executable")
    environment = {"PATH": "system-path", "HOME": str(worker_home), "USERPROFILE": str(worker_home), "CODEX_HOME": str(codex_home)}
    seed = o2c.CodexWorkspaceSeed(
        o2b_test.BASE.value,
        (o2c.CodexWorkspaceFile("o2c-input.txt", b"input", "100644"),),
    )
    runner = FakeContainedRunner()
    configuration = o2c.CodexCliConfiguration(
            str(executable), "codex-cli 0", hashlib.sha256(executable.read_bytes()).hexdigest(),
            str(worker_home), str(codex_home), str(scratch_root), 30, o2b_test.BASE.value, "fixture-environment-id",
        )
    producer = o2c.CodexCliCandidateProducer(
        configuration,
        seed,
        _fixture_attestation(configuration),
        preflight=FakePreflight(),
        runner=runner,
        parent_environment=environment,
        clock=lambda: FIXED_NOW,
    )
    produced = producer.invoke(b"add the requested fixture file")
    assert produced.status is ProducerStatus.SUCCESS
    assert runner.calls == producer.task_attempt_count == 1
    proposal = produced.candidate_proposal

    materialized = DeterministicFixtureCandidateMaterializer().materialize(proposal, base_snapshot)
    assert materialized.status is MaterializationStatus.MATERIALIZED
    assert materialized.candidate is not None
    combined = o2b_test.independently_verify_and_combine(base_store, base_snapshot, proposal, materialized)
    admitted = o2b_test._trusted_admit_candidate(
        base_store, combined, materialized.candidate.candidate_commit_id, "issue69-o2c-fake-linkage"
    )
    assert admitted.candidate_commit.value == materialized.candidate.candidate_commit_id
    assert admitted.mutation_inventory.mutations == o2b_test._independent_mutation_facts(base_snapshot, proposal)
    record = _build_smoke_record(
        producer._deployment, produced.untrusted_metadata, proposal,
        materialized.candidate.candidate_commit_id, admitted.mutation_inventory.mutations,
        source_head_before=o2b_test.BASE.value, source_head_after=o2b_test.BASE.value,
        source_clean_before=True, source_clean_after=True,
    )
    assert set(record) == {
        "deployment_attestation", "measured_runtime", "configured_requested_execution_profile",
        "containment_result", "candidate_and_admission",
    }
    assert record["deployment_attestation"]["attestation_id"] == "b" * 64
    assert record["deployment_attestation"]["worker_environment_id"] == "fixture-environment-id"
    assert record["deployment_attestation"]["evidence_items"]
    assert record["deployment_attestation"]["codex_executable_version"] == "codex-cli 0"
    assert record["measured_runtime"]["codex_cli_version_raw"] == "codex-cli 0"
    assert record["measured_runtime"]["codex_package_version"] == "0"
    assert record["measured_runtime"]["codex_version"]["value"] == "codex-cli 0"
    assert record["measured_runtime"]["codex_executable_sha256_before"] == record["measured_runtime"]["codex_executable_sha256_after"]
    assert record["measured_runtime"]["candidate_workspace_git_present"] is False
    assert record["measured_runtime"]["sandbox_implementation"] == "mxc"
    assert record["configured_requested_execution_profile"]["sandbox_profile"] == "workspace-write"
    assert record["configured_requested_execution_profile"]["bundled_skills_enabled"] is False
    assert record["configured_requested_execution_profile"]["process_containment_kind"] == "windows_job_object"
    assert record["configured_requested_execution_profile"]["workspace_path_class"] == "fresh_invocation_plain_non_git_workspace"
    assert record["configured_requested_execution_profile"]["target_github_credentials_intentionally_present"] is False
    assert record["configured_requested_execution_profile"]["control_root_credentials_intentionally_present"] is False
    assert record["configured_requested_execution_profile"]["job_object_limits"]["kill_on_job_close"] is True
    assert record["containment_result"]["job_assignment_succeeded"] is True
    external_checks = {item["check_id"] for item in record["deployment_attestation"]["evidence_items"]}
    assert {
        "target_repository_publication_authority_absent",
        "control_state_authority_absent",
        "root_authority_absent",
    } <= external_checks
    assert record["candidate_and_admission"]["o2b_candidate_commit_id"] == materialized.candidate.candidate_commit_id
    assert "safe" not in record


@pytest.mark.parametrize("doctor_exit_code", [0, 9])
def test_doctor_fixture_flows_through_real_preflight_into_measured_smoke_record(tmp_path, monkeypatch, doctor_exit_code):
    worker_home, codex_home, scratch_root = (tmp_path / name for name in ("worker-home", "codex-home", "scratch"))
    for path in (worker_home, codex_home, scratch_root):
        path.mkdir()
    executable = tmp_path / "codex.exe"
    executable.write_bytes(b"fake pinned executable")
    configuration = o2c.CodexCliConfiguration(
        str(executable), "codex-cli 0", hashlib.sha256(executable.read_bytes()).hexdigest(),
        str(worker_home), str(codex_home), str(scratch_root), 30, o2b_test.BASE.value, "fixture-environment-id",
    )
    environment = {
        "PATH": "system-path", "HOME": str(worker_home), "USERPROFILE": str(worker_home),
        "CODEX_HOME": str(codex_home),
    }
    seed = o2c.CodexWorkspaceSeed(
        o2b_test.BASE.value,
        (o2c.CodexWorkspaceFile("o2c-input.txt", b"input", "100644"),),
    )
    features = b"".join(f"{name} stable false\n".encode() for name in o2c.CAPABILITY_DENY_SET)
    calls = []

    def diagnostic(command, child_environment, timeout_seconds):
        calls.append(tuple(command))
        assert child_environment["CODEX_HOME"] == str(codex_home)
        assert child_environment["HOME"] == str(worker_home)
        if command == (str(executable), "--version"):
            stdout = b"codex-cli 0\n"
        elif command[-2:] == ("features", "list"):
            stdout = features
        elif command[-3:] == ("mcp", "list", "--json"):
            stdout = b"[]"
        elif command[-2:] == ("doctor", "--json"):
            report_checks = {
                "sandbox.helpers": {
                    "id": "sandbox.helpers", "category": "sandbox", "status": "ok",
                    "summary": "fixture", "details": {"sandbox backend": "mxc"},
                    "issues": [], "notes": [], "remediation": None, "durationMs": 0,
                },
            }
            if doctor_exit_code != 0:
                report_checks["unrelated.check"] = {"id": "unrelated.check", "status": "fail"}
            stdout = json.dumps({
                "schemaVersion": 1, "generatedAt": "fixture",
                "overallStatus": "fail" if doctor_exit_code != 0 else "ok",
                "codexVersion": "0", "checks": report_checks,
            }).encode("utf-8")
        else:
            raise AssertionError(f"unexpected diagnostic command: {command!r}")
        exit_code = doctor_exit_code if command[-2:] == ("doctor", "--json") else 0
        return o2c._DiagnosticOutput(exit_code, stdout, 0, hashlib.sha256(b"").hexdigest())

    monkeypatch.setattr(o2c, "_run_bounded_diagnostic", diagnostic)
    runner = FakeContainedRunner()
    producer = o2c.CodexCliCandidateProducer(
        configuration,
        seed,
        _fixture_attestation(configuration),
        preflight=o2c.CodexCliPreflightProbe(),
        runner=runner,
        parent_environment=environment,
        clock=lambda: FIXED_NOW,
    )
    result = producer.invoke(b"fixture request")
    assert result.status is ProducerStatus.SUCCESS
    assert result.untrusted_metadata.sandbox_implementation == "mxc"
    assert result.untrusted_metadata.doctor_exit_code == doctor_exit_code
    assert result.untrusted_metadata.codex_cli_version_raw == "codex-cli 0"
    assert result.untrusted_metadata.codex_package_version == "0"
    disabled_features = tuple(
        argument
        for feature in o2c.CAPABILITY_DENY_SET
        for argument in ("--disable", feature)
    )
    diagnostic_prefix = (
        "-c", o2c.WINDOWS_SANDBOX_CONFIG_OVERRIDE,
        "-c", o2c.BUNDLED_SKILLS_CONFIG_OVERRIDE,
        *disabled_features,
    )
    assert calls == [
        (str(executable), "--version"),
        (str(executable), *diagnostic_prefix, "features", "list"),
        (str(executable), *diagnostic_prefix, "mcp", "list", "--json"),
        (str(executable), "--strict-config", *diagnostic_prefix, "doctor", "--json"),
    ]
    assert runner.arguments is not None
    assert ("-c", o2c.WINDOWS_SANDBOX_CONFIG_OVERRIDE) == runner.arguments[2:4]
    assert runner.arguments.count(o2c.BUNDLED_SKILLS_CONFIG_OVERRIDE) == 1
    record = _build_smoke_record(
        producer._deployment, result.untrusted_metadata, result.candidate_proposal, "fixture-candidate",
        (), source_head_before=o2b_test.BASE.value, source_head_after=o2b_test.BASE.value,
        source_clean_before=True, source_clean_after=True,
    )
    assert record["measured_runtime"]["sandbox_implementation"] == "mxc"
    assert record["measured_runtime"]["doctor_exit_code"] == doctor_exit_code
    assert record["configured_requested_execution_profile"]["sandbox_profile"] == "workspace-write"
    assert record["measured_runtime"]["candidate_workspace_git_present"] is False


def _real_smoke_context() -> tuple[dict[str, object], Path]:
    context_path_text = os.environ.get("O2C_REAL_SMOKE_CONTEXT")
    if not context_path_text:
        pytest.fail("O2C_REAL_SMOKE=1 requires O2C_REAL_SMOKE_CONTEXT")
    context_path = Path(context_path_text)
    if not context_path.is_absolute() or not context_path.is_file():
        pytest.fail("real-smoke context must be an existing absolute JSON file")
    try:
        context = json.loads(context_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        pytest.fail(f"real-smoke context is unreadable or malformed: {error}")
    if type(context) is not dict:
        pytest.fail("real-smoke context must be a JSON object")
    return context, context_path


def _real_smoke_attestation(context: dict[str, object]) -> o2c.CodexWorkerDeploymentAttestation:
    raw = context.get("deployment_attestation")
    if type(raw) is not dict:
        pytest.fail("real-smoke context lacks structured deployment_attestation")
    try:
        values = dict(raw)
        evidence = values.get("evidence_items")
        if type(evidence) is not list:
            raise TypeError("evidence_items must be a JSON array")
        values["evidence_items"] = tuple(o2c.CodexDeploymentEvidence(**item) for item in evidence)
        for key in ("issued_at_utc", "expires_at_utc"):
            timestamp = values.get(key)
            if type(timestamp) is not str or not timestamp.endswith("Z"):
                raise ValueError(f"{key} must be an explicit UTC timestamp ending in Z")
            values[key] = datetime.fromisoformat(timestamp[:-1] + "+00:00")
            if values[key].tzinfo is not timezone.utc:
                raise ValueError(f"{key} did not parse as UTC")
        return o2c.CodexWorkerDeploymentAttestation(**values)
    except (TypeError, ValueError) as error:
        pytest.fail(f"real-smoke deployment attestation is malformed: {error}")


@pytest.mark.parametrize("missing_field", ("worker_environment_id", "issued_at_utc", "expires_at_utc"))
def test_real_smoke_context_rejects_missing_attestation_freshness_fields(missing_field):
    evidence = tuple(
        o2c.CodexDeploymentEvidence(
            check_id, "pass", "fixture", "offline-test",
            hashlib.sha256(check_id.encode()).hexdigest(), f"fixture://{check_id}"
        ) for check_id in o2c.DEPLOYMENT_CHECKS
    )
    valid = {
        "format_version": "o2c-deployment-attestation/1",
        "worker_isolation_kind": "dedicated_vm",
        "worker_identity": o2c._current_worker_identity(),
        "source_head_sha": "a" * 40,
        "codex_executable_path": "C:\\fixture\\codex.exe",
        "codex_executable_version": "codex-cli fixture",
        "codex_executable_sha256": "b" * 64,
        "evidence_items": [asdict(item) for item in evidence],
        "attestation_id": "c" * 64,
        "worker_environment_id": "fixture-environment",
        "issued_at_utc": "2030-01-01T00:00:00Z",
        "expires_at_utc": "2030-01-01T00:10:00Z",
    }
    valid.pop(missing_field)
    with pytest.raises(pytest.fail.Exception):
        _real_smoke_attestation({"deployment_attestation": valid})


@pytest.mark.skipif(not PINNED_CODEX_01601.is_file(), reason="pinned Codex 0.160.1 compatibility CLI is not installed")
def test_codex_01601_accepts_exact_preflight_diagnostic_argv(tmp_path):
    executable = str(PINNED_CODEX_01601)
    assert hashlib.sha256(PINNED_CODEX_01601.read_bytes()).hexdigest() == PINNED_CODEX_01601_SHA256
    version = subprocess.run((executable, "--version"), check=True, capture_output=True, text=True, timeout=10)
    assert version.stdout.strip() == "codex-cli 0.160.1"

    codex_home = tmp_path / "codex-home"
    codex_home.mkdir()
    assert not o2c._path_exists_or_link(codex_home / "skills")
    environment = {key: os.environ[key] for key in o2c._WINDOWS_ENV_ALLOWLIST if key in os.environ}
    environment["CODEX_HOME"] = str(codex_home)
    disabled_features = tuple(
        argument
        for feature in o2c.CAPABILITY_DENY_SET
        for argument in ("--disable", feature)
    )
    diagnostic_prefix = (
        "-c", o2c.WINDOWS_SANDBOX_CONFIG_OVERRIDE,
        "-c", o2c.BUNDLED_SKILLS_CONFIG_OVERRIDE,
        *disabled_features,
    )
    commands = (
        (("features", "list"), (*diagnostic_prefix, "features", "list")),
        (("mcp", "list", "--json"), (*diagnostic_prefix, "mcp", "list", "--json")),
        (("doctor", "--json"), ("--strict-config", *diagnostic_prefix, "doctor", "--json")),
    )
    results = []
    for tail, arguments in commands:
        assert o2c._build_preflight_diagnostic_arguments(*tail) == arguments
        result = subprocess.run(
            (executable, *arguments),
            cwd=tmp_path,
            env=environment,
            capture_output=True,
            timeout=30,
        )
        assert b"unexpected argument" not in result.stderr.lower(), result.stderr.decode(errors="replace")
        results.append(result)
    assert results[0].returncode == 0, results[0].stderr.decode(errors="replace")
    assert results[1].returncode == 0, results[1].stderr.decode(errors="replace")
    assert o2c._sandbox_implementation(results[2].stdout, "0.160.1") == "restricted-token"
    assert not o2c._path_exists_or_link(codex_home / "skills")


def _build_smoke_record(
    attestation: o2c.CodexWorkerDeploymentAttestation,
    metadata: o2c.CodexRunDiagnostics,
    proposal: object,
    candidate_commit_id: str,
    mutation_inventory: tuple[object, ...],
    *,
    source_head_before: str,
    source_head_after: str,
    source_clean_before: bool,
    source_clean_after: bool,
) -> dict[str, object]:
    evidence_items = [asdict(item) for item in attestation.evidence_items]
    configured_profile = asdict(o2c.configured_execution_profile())
    configured_profile["target_github_credentials_intentionally_present"] = configured_profile.pop(
        "target_repository_credentials_intentionally_present"
    )
    return {
        "deployment_attestation": {
            "attestation_id": attestation.attestation_id,
            "worker_environment_id": attestation.worker_environment_id,
            "issued_at_utc": attestation.issued_at_utc.isoformat().replace("+00:00", "Z"),
            "expires_at_utc": attestation.expires_at_utc.isoformat().replace("+00:00", "Z"),
            "worker_isolation_kind": attestation.worker_isolation_kind,
            "worker_identity": attestation.worker_identity,
            "source_head_sha": attestation.source_head_sha,
            "codex_executable_path": attestation.codex_executable_path,
            "codex_executable_version": attestation.codex_executable_version,
            "codex_executable_sha256": attestation.codex_executable_sha256,
            "evidence_items": evidence_items,
            "trust_status": "untrusted work-plane evidence",
        },
        "measured_runtime": {
            "source_head_before_and_after": {"before": source_head_before, "after": source_head_after},
            "source_checkout_clean_before_and_after": {"before": source_clean_before, "after": source_clean_after},
            "worker_identity": metadata.worker_identity_measured,
            "worker_HOME_path": metadata.worker_home_path,
            "worker_USERPROFILE_path": metadata.userprofile_path,
            "worker_agents_clean_preflight": metadata.worker_agents_clean,
            "CODEX_HOME_path": metadata.codex_home_path,
            "CODEX_HOME_clean_preflight": metadata.codex_home_clean,
            "codex_executable_absolute_path": attestation.codex_executable_path,
            "codex_version": {"value": metadata.codex_version, "measured_before_task": metadata.codex_version_measured_before_task},
            "codex_executable_sha256_before": metadata.codex_executable_sha256_before,
            "codex_executable_sha256_after": metadata.codex_executable_sha256_after,
            "codex_cli_version_raw": metadata.codex_cli_version_raw,
            "codex_package_version": metadata.codex_package_version,
            "effective_denied_feature_map": dict(metadata.measured_features),
            "configured_mcp_server_count": metadata.measured_mcp_server_count,
            "sandbox_implementation": metadata.sandbox_implementation,
            "doctor_exit_code": metadata.doctor_exit_code,
            "stdout": {"byte_count": metadata.stdout_byte_count, "sha256": metadata.stdout_sha256},
            "stderr": {"byte_count": metadata.stderr_byte_count, "sha256": metadata.stderr_sha256},
            "workspace_final_regular_file_count": metadata.workspace_file_count,
            "proposal_change_count": metadata.proposal_change_count,
            "candidate_workspace_git_present": metadata.candidate_workspace_git_present,
        },
        "configured_requested_execution_profile": configured_profile,
        "containment_result": {
            "job_assignment_succeeded": metadata.job_assignment_succeeded,
            "root_process_resumed_after_assignment": metadata.root_process_resumed_after_assignment,
            "root_exit_code": metadata.root_exit_code,
            "descendant_quiescence_before_scan": metadata.process_tree_quiescent,
            "active_process_count_before_scan": metadata.active_process_count_before_scan,
            "resource_limit_violation": metadata.resource_limit_violation,
            "resource_violation_types": list(metadata.resource_violation_types),
        },
        "candidate_and_admission": {
            "proposal_base_revision": proposal.claimed_base_revision,
            "proposal_changed_paths": [change.path for change in proposal.changes],
            "o2b_candidate_commit_id": candidate_commit_id,
            "trusted_admitted_mutation_inventory": [
                {"path": fact.path.value, "kind": fact.kind.value} for fact in mutation_inventory
            ],
        },
    }


@pytest.mark.skipif(os.environ.get("O2C_REAL_SMOKE") != "1", reason="dedicated-worker Codex smoke is explicitly opt-in")
def test_opt_in_real_codex_smoke_records_exact_head_o2b_and_trusted_admission(tmp_path):
    """Run only on a manually prepared dedicated worker and write its complete record."""
    context, context_path = _real_smoke_context()
    attestation = _real_smoke_attestation(context)
    expected_head = context.get("exact_pr_head_sha")
    if type(expected_head) is not str or len(expected_head) not in (40, 64) or any(char not in "0123456789abcdef" for char in expected_head):
        pytest.fail("real-smoke context is missing exact published PR-head SHA")
    if os.name != "nt":
        pytest.fail("frozen Phase-1 real Codex worker profile requires native Windows Job Objects")
    repo_root = Path(__file__).resolve().parents[2]
    actual_head = subprocess.run(("git", "rev-parse", "HEAD"), cwd=repo_root, check=True, capture_output=True, text=True).stdout.strip()
    if actual_head != expected_head:
        pytest.fail("checked-out source does not equal the exact published PR head")
    source_clean_before = not subprocess.run(("git", "status", "--porcelain"), cwd=repo_root, check=True, capture_output=True, text=True).stdout.strip()
    if not source_clean_before:
        pytest.fail("real smoke requires a clean source checkout before invocation")

    request_file = Path(os.environ.get("O2C_REAL_REQUEST_FILE", ""))
    output_file = Path(os.environ.get("O2C_REAL_SMOKE_RECORD_OUTPUT", ""))
    if not request_file.is_absolute() or not request_file.is_file() or not output_file.is_absolute():
        pytest.fail("real smoke requires absolute request input and record output paths")
    if output_file.resolve().is_relative_to(repo_root.resolve()):
        pytest.fail("real-smoke record output must remain outside the source checkout")
    base_store = o2b_test.base_only_store()
    base_snapshot = o2b_test.project_exact_base(base_store, o2b_test.REPOSITORY, o2b_test.BASE)
    worker_home = os.environ.get("O2C_WORKER_HOME", "")
    codex_home = os.environ.get("CODEX_HOME", "")
    worker_environment_id = os.environ.get("O2C_WORKER_ENVIRONMENT_ID", "")
    scratch_root = os.environ.get("O2C_SCRATCH_ROOT", "")
    executable = os.environ.get("O2C_CODEX_EXECUTABLE", "")
    version = os.environ.get("O2C_CODEX_VERSION", "")
    executable_hash = os.environ.get("O2C_CODEX_SHA256", "")
    for value in (worker_home, codex_home, worker_environment_id, scratch_root, executable, version, executable_hash):
        if not value:
            pytest.fail("real-smoke Codex identity/home/scratch configuration is incomplete")
    environment = dict(os.environ)
    configuration = o2c.CodexCliConfiguration(
        executable, version, executable_hash, worker_home, codex_home, scratch_root, 1800,
        expected_head, worker_environment_id,
    )
    producer = o2c.CodexCliCandidateProducer(
        configuration,
        o2c.CodexWorkspaceSeed(o2b_test.BASE.value, (o2c.CodexWorkspaceFile("o2c-smoke-input.txt", b"fixture input", "100644"),)),
        attestation,
        parent_environment=environment,
    )
    started_head = actual_head
    result = producer.invoke(request_file.read_bytes())
    if result.status is not ProducerStatus.SUCCESS or result.candidate_proposal is None:
        pytest.fail(f"real Codex producer failed with transport status {result.status.value}")
    materialized = DeterministicFixtureCandidateMaterializer().materialize(result.candidate_proposal, base_snapshot)
    if materialized.status is not MaterializationStatus.MATERIALIZED or materialized.candidate is None:
        pytest.fail("O2b rejected the real O2c proposal")
    combined = o2b_test.independently_verify_and_combine(base_store, base_snapshot, result.candidate_proposal, materialized)
    admitted = o2b_test._trusted_admit_candidate(
        base_store, combined, materialized.candidate.candidate_commit_id, "issue69-o2c-real-smoke-candidate"
    )
    expected_inventory = o2b_test._independent_mutation_facts(base_snapshot, result.candidate_proposal)
    if admitted.mutation_inventory.mutations != expected_inventory:
        pytest.fail("trusted mutation inventory differs from the independent fixture verifier")
    source_head_after = subprocess.run(("git", "rev-parse", "HEAD"), cwd=repo_root, check=True, capture_output=True, text=True).stdout.strip()
    source_clean_after = not subprocess.run(("git", "status", "--porcelain"), cwd=repo_root, check=True, capture_output=True, text=True).stdout.strip()
    if source_head_after != started_head:
        pytest.fail("source identity changed during the real smoke")
    if not source_clean_after:
        pytest.fail("real smoke modified the source checkout")
    metadata = result.untrusted_metadata
    record = _build_smoke_record(
        attestation, metadata, result.candidate_proposal,
        materialized.candidate.candidate_commit_id,
        admitted.mutation_inventory.mutations,
        source_head_before=started_head,
        source_head_after=source_head_after,
        source_clean_before=source_clean_before,
        source_clean_after=source_clean_after,
    )
    output_file.write_text(json.dumps(record, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    assert output_file.is_file()
