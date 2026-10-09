"""Fake-containment linkage tests plus a disabled-by-default real smoke harness."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import autodev_control.workplane.codex_cli_candidate_producer as o2c
from autodev_control.workplane.candidate_producer import (
    CandidateProposal,
    ProposedChangeKind,
    ProposedFileChange,
    ProducerStatus,
)
from autodev_control.workplane.fixture_candidate_materializer import (
    DeterministicFixtureCandidateMaterializer,
    FixtureBaseSnapshot,
    MaterializationStatus,
)
from tests.integration import test_o2b_fixture_candidate_materialization as o2b_test


FIXED_NOW = datetime(2030, 1, 1, tzinfo=timezone.utc)
PINNED_CODEX_01601 = Path(r"C:\O2C\bin\codex-0.160.1\bin\codex.exe")
PINNED_CODEX_01601_SHA256 = "9e7c59c05cc1ce5677b1f94e835b2ac038ca3be14504e78d558eacdb0ea3f55d"
_EXPECTED_REAL_SMOKE_PATH = "o2c-output.txt"
_EXPECTED_REAL_SMOKE_CONTENT = b"o2c-real-worker-pass\n"
_EXPECTED_REAL_SMOKE_MODE = "100644"
# The real worker intentionally gets a minimal one-file fixture seed. O2b
# materializes the proposal against its richer exact-base repository fixture.
# This is a fixture simplification, not proof that the worker seed is an exact
# checkout of that base; exact-base linkage remains outside this smoke.
_EXPECTED_REAL_SMOKE_SEED = o2c.CodexWorkspaceSeed(
    o2b_test.BASE.value,
    (o2c.CodexWorkspaceFile("o2c-smoke-input.txt", b"fixture input", "100644"),),
)
_EXPECTED_REAL_SMOKE_PROPOSAL = CandidateProposal(
    o2b_test.BASE.value,
    (ProposedFileChange(
        ProposedChangeKind.ADD,
        _EXPECTED_REAL_SMOKE_PATH,
        _EXPECTED_REAL_SMOKE_CONTENT,
        _EXPECTED_REAL_SMOKE_MODE,
    ),),
)
_REAL_SMOKE_MISMATCH_REASONS = frozenset({
    "proposal_mismatch",
    "workspace_observation_mismatch",
    "o2b_materialization_rejected",
    "materialized_candidate_mismatch",
    "trusted_mutation_inventory_mismatch",
})
_MAX_MISMATCH_PATHS = 16
_MAX_MISMATCH_PATH_LENGTH = 96
_MAX_MISMATCH_RECORD_BYTES = 8192
_MISMATCH_GIT_ID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")


def _assert_expected_real_smoke_seed(seed: object) -> None:
    if type(seed) is not o2c.CodexWorkspaceSeed or seed != _EXPECTED_REAL_SMOKE_SEED:
        raise AssertionError("real-smoke seed differs from its fixed expected input")


def _assert_expected_real_smoke_proposal(proposal: object) -> None:
    if type(proposal) is not CandidateProposal or proposal != _EXPECTED_REAL_SMOKE_PROPOSAL:
        raise AssertionError("real-smoke proposal differs from its fixed expected addition")


def _assert_expected_real_smoke_observation(proposal: object, metadata: object) -> None:
    _assert_expected_real_smoke_proposal(proposal)
    if (
        type(metadata) is not o2c.CodexRunDiagnostics
        or metadata.workspace_file_count != len(_EXPECTED_REAL_SMOKE_SEED.files) + 1
        or metadata.proposal_change_count != len(_EXPECTED_REAL_SMOKE_PROPOSAL.changes)
    ):
        raise AssertionError("real-smoke workspace observation differs from its fixed expected addition")


def _expected_real_smoke_candidate(base_snapshot: FixtureBaseSnapshot):
    expected_files, expected_content, expected_trees = o2b_test._expected_materialization(
        base_snapshot, _EXPECTED_REAL_SMOKE_PROPOSAL
    )
    expected_blob_id = o2b_test._independent_digest(
        o2b_test.TEST_BLOB_DOMAIN, _EXPECTED_REAL_SMOKE_CONTENT
    )
    if expected_files.get(_EXPECTED_REAL_SMOKE_PATH) != (_EXPECTED_REAL_SMOKE_MODE, expected_blob_id):
        raise AssertionError("fixed smoke addition is absent from the independent O2b file model")
    if expected_content != {expected_blob_id: _EXPECTED_REAL_SMOKE_CONTENT}:
        raise AssertionError("independent O2b content model differs from the fixed smoke bytes")

    expected_trees_by_path = tuple(
        o2b_test.FixtureMaterializedTree(
            directory,
            tree_id,
            tuple(
                o2b_test.FixtureMaterializedTreeEntry(
                    name, o2b_test.FixtureObjectKind(kind), mode, object_id
                )
                for name, kind, mode, object_id in entries
            ),
        )
        for directory, (tree_id, entries) in sorted(
            expected_trees.items(), key=lambda item: item[0].encode("utf-8")
        )
    )
    expected_blobs = tuple(
        o2b_test.FixtureMaterializedBlob(blob_id, content)
        for blob_id, content in sorted(expected_content.items(), key=lambda item: item[0].encode("ascii"))
    )
    result_tree_id = expected_trees[""][0]
    candidate_commit_id = o2b_test._independent_digest(
        o2b_test.TEST_COMMIT_DOMAIN,
        base_snapshot.expected_base_revision.encode("ascii"),
        result_tree_id.encode("ascii"),
    )
    return o2b_test.FixtureMaterializedCandidate(
        base_snapshot.repository_id,
        base_snapshot.expected_base_revision,
        candidate_commit_id,
        result_tree_id,
        expected_trees_by_path,
        expected_blobs,
    )


def _assert_expected_real_smoke_candidate(candidate: object, base_snapshot: FixtureBaseSnapshot) -> None:
    expected = _expected_real_smoke_candidate(base_snapshot)
    if type(candidate) is not type(expected) or candidate != expected:
        raise AssertionError("materialized O2b candidate differs from the fixed expected addition")


def _expected_real_smoke_mutations(base_snapshot: FixtureBaseSnapshot):
    if any(leaf.path == _EXPECTED_REAL_SMOKE_PATH for leaf in base_snapshot.leaves):
        raise AssertionError("fixed smoke output path already exists in the base snapshot")
    expected_blob_id = o2b_test._independent_digest(
        o2b_test.TEST_BLOB_DOMAIN, _EXPECTED_REAL_SMOKE_CONTENT
    )
    return (
        o2b_test.MutationFact(
            o2b_test.CanonicalGitPath(_EXPECTED_REAL_SMOKE_PATH),
            o2b_test.MutationKind.ADDED,
            None,
            o2b_test.GitSha(expected_blob_id),
            None,
            o2b_test.GitBlobMode(_EXPECTED_REAL_SMOKE_MODE),
        ),
    )


def _assert_expected_real_smoke_mutations(mutations: object, base_snapshot: FixtureBaseSnapshot) -> None:
    if type(mutations) is not tuple or mutations != _expected_real_smoke_mutations(base_snapshot):
        raise AssertionError("trusted mutation inventory differs from the fixed expected addition")


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
        (Path(workspace) / _EXPECTED_REAL_SMOKE_PATH).write_bytes(_EXPECTED_REAL_SMOKE_CONTENT)
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
    seed = _EXPECTED_REAL_SMOKE_SEED
    _assert_expected_real_smoke_seed(seed)
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
    _assert_expected_real_smoke_observation(proposal, produced.untrusted_metadata)

    materialized = DeterministicFixtureCandidateMaterializer().materialize(proposal, base_snapshot)
    assert materialized.status is MaterializationStatus.MATERIALIZED
    assert materialized.candidate is not None
    _assert_expected_real_smoke_candidate(materialized.candidate, base_snapshot)
    combined = o2b_test.independently_verify_and_combine(base_store, base_snapshot, proposal, materialized)
    admitted = o2b_test._trusted_admit_candidate(
        base_store, combined, materialized.candidate.candidate_commit_id, "issue69-o2c-fake-linkage"
    )
    assert admitted.candidate_commit.value == materialized.candidate.candidate_commit_id
    _assert_expected_real_smoke_mutations(admitted.mutation_inventory.mutations, base_snapshot)
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


_NONEXACT_REAL_SMOKE_CHANGES = (
    pytest.param((), id="no-op-missing-addition"),
    pytest.param((ProposedFileChange(
        ProposedChangeKind.ADD, "wrong-output.txt", _EXPECTED_REAL_SMOKE_CONTENT,
        _EXPECTED_REAL_SMOKE_MODE,
    ),), id="wrong-path"),
    pytest.param((ProposedFileChange(
        ProposedChangeKind.ADD, _EXPECTED_REAL_SMOKE_PATH, b"wrong content\n",
        _EXPECTED_REAL_SMOKE_MODE,
    ),), id="wrong-content"),
    pytest.param((ProposedFileChange(
        ProposedChangeKind.ADD, _EXPECTED_REAL_SMOKE_PATH, _EXPECTED_REAL_SMOKE_CONTENT,
        "100755",
    ),), id="wrong-mode"),
    pytest.param((
        _EXPECTED_REAL_SMOKE_PROPOSAL.changes[0],
        ProposedFileChange(ProposedChangeKind.ADD, "unexpected-extra.txt", b"extra\n", "100644"),
    ), id="extra-mutation"),
)


@pytest.mark.parametrize("changes", _NONEXACT_REAL_SMOKE_CHANGES)
def test_real_smoke_expected_effect_rejects_nonexact_proposals(changes):
    proposal = CandidateProposal(o2b_test.BASE.value, changes)
    with pytest.raises(AssertionError, match="fixed expected addition"):
        _assert_expected_real_smoke_proposal(proposal)


def test_real_smoke_expected_effect_rejects_changed_seed_input():
    changed_seed = o2c.CodexWorkspaceSeed(
        o2b_test.BASE.value,
        (o2c.CodexWorkspaceFile("o2c-smoke-input.txt", b"changed input", "100644"),),
    )
    with pytest.raises(AssertionError, match="fixed expected input"):
        _assert_expected_real_smoke_seed(changed_seed)


@pytest.mark.parametrize("changes", _NONEXACT_REAL_SMOKE_CHANGES)
def test_real_smoke_expected_effect_rejects_nonexact_materialized_candidates(changes):
    base_snapshot = o2b_test.project_exact_base(
        o2b_test.base_only_store(), o2b_test.REPOSITORY, o2b_test.BASE
    )
    proposal = CandidateProposal(o2b_test.BASE.value, changes)
    materialized = DeterministicFixtureCandidateMaterializer().materialize(proposal, base_snapshot)
    assert materialized.status is MaterializationStatus.MATERIALIZED
    assert materialized.candidate is not None
    with pytest.raises(AssertionError, match="fixed expected addition"):
        _assert_expected_real_smoke_candidate(materialized.candidate, base_snapshot)


def test_real_smoke_expected_effect_rejects_missing_and_extra_trusted_mutations():
    base_snapshot = o2b_test.project_exact_base(
        o2b_test.base_only_store(), o2b_test.REPOSITORY, o2b_test.BASE
    )
    expected = _expected_real_smoke_mutations(base_snapshot)
    extra = o2b_test.MutationFact(
        o2b_test.CanonicalGitPath("unexpected-extra.txt"),
        o2b_test.MutationKind.ADDED,
        None,
        o2b_test.GitSha("a" * 40),
        None,
        o2b_test.GitBlobMode("100644"),
    )

    with pytest.raises(AssertionError, match="fixed expected addition"):
        _assert_expected_real_smoke_mutations((), base_snapshot)
    with pytest.raises(AssertionError, match="fixed expected addition"):
        _assert_expected_real_smoke_mutations((*expected, extra), base_snapshot)


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
    assert runner.arguments[:10] == (
        "exec", "--model", "gpt-5.6-terra", "--strict-config",
        "-c", 'model_reasoning_effort="medium"',
        "-c", o2c.WINDOWS_SANDBOX_CONFIG_OVERRIDE,
        "-c", o2c.BUNDLED_SKILLS_CONFIG_OVERRIDE,
    )
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


def _build_failure_smoke_record(
    result: object,
    producer: o2c.CodexCliCandidateProducer,
) -> dict[str, object]:
    diagnostic = producer.failure_diagnostic
    return {
        "format_version": "o2c-smoke-failure/1",
        "producer_status": result.status.value,
        "task_attempt_count": producer.task_attempt_count,
        "failure_diagnostic": None if diagnostic is None else {
            "stages": [stage.value for stage in diagnostic.stages],
            **({} if diagnostic.process_exit_code is None else {
                "process_exit_code": diagnostic.process_exit_code,
                "process_exit_category": diagnostic.process_exit_category.value,
            }),
        },
    }


def _validate_failure_smoke_output_path(output_file: Path, repo_root: Path) -> None:
    if not output_file.is_absolute():
        raise ValueError("failure diagnostic output must be absolute")
    try:
        resolved_output = output_file.resolve()
        resolved_repo = repo_root.resolve()
        parent_is_directory = output_file.parent.is_dir()
        parent_directories = (output_file.parent, *output_file.parent.parents)
        unsafe_parent = any(o2c._is_reparse_point(directory) for directory in parent_directories)
        output_exists = o2c._path_exists_or_link(output_file)
        unsafe_output = output_exists and (o2c._is_reparse_point(output_file) or not output_file.is_file())
    except (OSError, RuntimeError):
        raise ValueError("failure diagnostic output path cannot be safely inspected") from None
    if resolved_output.is_relative_to(resolved_repo) or not parent_is_directory or unsafe_parent or unsafe_output:
        raise ValueError("failure diagnostic output requires an existing safe directory outside the checkout")


def _write_failure_smoke_record(
    output_file: Path,
    repo_root: Path,
    result: object,
    producer: o2c.CodexCliCandidateProducer,
) -> None:
    _validate_failure_smoke_output_path(output_file, repo_root)
    output_file.write_text(
        json.dumps(_build_failure_smoke_record(result, producer), sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )


def _safe_mismatch_path(path: object) -> str:
    if type(path) is not str or not path or len(path) > _MAX_MISMATCH_PATH_LENGTH:
        return "<redacted-path>"
    if (
        path.startswith("/")
        or "\\" in path
        or ":" in path
        or any(ord(character) < 32 or ord(character) == 127 for character in path)
    ):
        return "<redacted-path>"
    parts = path.split("/")
    if any(part in ("", ".", "..") for part in parts):
        return "<redacted-path>"
    return path


def _safe_mismatch_identity(value: object, *, max_length: int = 256) -> str:
    if (
        type(value) is not str
        or not value
        or len(value) > max_length
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        return "<redacted-identity>"
    return value


def _safe_mismatch_git_id(value: object) -> str:
    return value if type(value) is str and _MISMATCH_GIT_ID.fullmatch(value) is not None else "<invalid-git-id>"


def _mismatch_observed_effect(proposal: object, metadata: object) -> dict[str, object]:
    if type(proposal) is CandidateProposal:
        change_count: int | None = len(proposal.changes)
        paths = [_safe_mismatch_path(change.path) for change in proposal.changes[:_MAX_MISMATCH_PATHS]]
        omitted_path_count = max(0, change_count - len(paths))
    else:
        change_count = None
        paths = []
        omitted_path_count = 0
    reported_value = getattr(metadata, "proposal_change_count", None)
    reported_count = reported_value if type(reported_value) is int and reported_value >= 0 else None
    workspace_value = getattr(metadata, "workspace_file_count", None)
    workspace_file_count = workspace_value if type(workspace_value) is int and workspace_value >= 0 else None
    return {
        "proposal_change_count": change_count,
        "reported_proposal_change_count": reported_count,
        "proposal_changed_paths": paths,
        "omitted_path_count": omitted_path_count,
        "workspace_file_count": workspace_file_count,
    }


def _build_real_smoke_mismatch_record(
    mismatch_reason: str,
    attestation: o2c.CodexWorkerDeploymentAttestation,
    proposal: object,
    metadata: object,
    *,
    expected_source_head: str,
    source_head_before: str,
    source_head_after: str,
    source_clean_before: bool,
    source_clean_after: bool,
    task_attempt_count: int,
) -> dict[str, object]:
    reason = mismatch_reason if mismatch_reason in _REAL_SMOKE_MISMATCH_REASONS else "unknown_mismatch"
    return {
        "format_version": "o2c-smoke-mismatch/1",
        "producer_status": "SUCCESS",
        "task_attempt_count": task_attempt_count,
        "mismatch_reason": reason,
        "source_identity": {
            "expected_pr_head_sha": _safe_mismatch_git_id(expected_source_head),
            "source_head_before": _safe_mismatch_git_id(source_head_before),
            "source_head_after": _safe_mismatch_git_id(source_head_after),
            "source_clean_before": source_clean_before,
            "source_clean_after": source_clean_after,
        },
        "attestation_identity": {
            "attestation_id": _safe_mismatch_git_id(attestation.attestation_id),
            "source_head_sha": _safe_mismatch_git_id(attestation.source_head_sha),
            "worker_environment_id": _safe_mismatch_identity(attestation.worker_environment_id),
            "codex_executable_version": _safe_mismatch_identity(attestation.codex_executable_version),
            "codex_executable_sha256": _safe_mismatch_git_id(attestation.codex_executable_sha256),
        },
        "observed_effect": _mismatch_observed_effect(proposal, metadata),
    }


def _write_real_smoke_mismatch_record(
    output_file: Path,
    repo_root: Path,
    mismatch_reason: str,
    attestation: o2c.CodexWorkerDeploymentAttestation,
    proposal: object,
    metadata: object,
    *,
    expected_source_head: str,
    source_head_before: str,
    source_head_after: str,
    source_clean_before: bool,
    source_clean_after: bool,
    task_attempt_count: int,
) -> None:
    _validate_failure_smoke_output_path(output_file, repo_root)
    record = _build_real_smoke_mismatch_record(
        mismatch_reason,
        attestation,
        proposal,
        metadata,
        expected_source_head=expected_source_head,
        source_head_before=source_head_before,
        source_head_after=source_head_after,
        source_clean_before=source_clean_before,
        source_clean_after=source_clean_after,
        task_attempt_count=task_attempt_count,
    )
    serialized = (json.dumps(record, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
    if len(serialized) > _MAX_MISMATCH_RECORD_BYTES:
        raise ValueError("bounded mismatch record exceeded its fixed size limit")
    output_file.write_bytes(serialized)


def _current_source_identity(repo_root: Path) -> tuple[str, bool]:
    head = subprocess.run(
        ("git", "rev-parse", "HEAD"), cwd=repo_root, check=True,
        capture_output=True, text=True,
    ).stdout.strip()
    clean = not subprocess.run(
        ("git", "status", "--porcelain"), cwd=repo_root, check=True,
        capture_output=True, text=True,
    ).stdout.strip()
    return head, clean


def _expected_real_smoke_observation_mismatch(proposal: object, metadata: object) -> str | None:
    if type(proposal) is not CandidateProposal or proposal != _EXPECTED_REAL_SMOKE_PROPOSAL:
        return "proposal_mismatch"
    if (
        type(metadata) is not o2c.CodexRunDiagnostics
        or metadata.workspace_file_count != len(_EXPECTED_REAL_SMOKE_SEED.files) + 1
        or metadata.proposal_change_count != len(_EXPECTED_REAL_SMOKE_PROPOSAL.changes)
    ):
        return "workspace_observation_mismatch"
    return None


def _fail_real_smoke_mismatch(
    output_file: Path,
    repo_root: Path,
    mismatch_reason: str,
    attestation: o2c.CodexWorkerDeploymentAttestation,
    result: o2c.CandidateProducerResult,
    *,
    expected_source_head: str,
    source_head_before: str,
    source_head_after: str,
    source_clean_before: bool,
    source_clean_after: bool,
    task_attempt_count: int,
) -> None:
    try:
        _write_real_smoke_mismatch_record(
            output_file,
            repo_root,
            mismatch_reason,
            attestation,
            result.candidate_proposal,
            result.untrusted_metadata,
            expected_source_head=expected_source_head,
            source_head_before=source_head_before,
            source_head_after=source_head_after,
            source_clean_before=source_clean_before,
            source_clean_after=source_clean_after,
            task_attempt_count=task_attempt_count,
        )
    except (OSError, ValueError):
        pytest.fail("real Codex outcome mismatched the fixed expectation and its bounded external record could not be written", pytrace=False)
    pytest.fail(
        f"real Codex producer returned SUCCESS but failed the fixed expected outcome ({mismatch_reason}); bounded mismatch evidence was written",
        pytrace=False,
    )


def _write_mismatch_and_fail(
    output_file: Path,
    repo_root: Path,
    mismatch_reason: str,
    attestation: o2c.CodexWorkerDeploymentAttestation,
    result: o2c.CandidateProducerResult,
    *,
    expected_source_head: str,
    source_head_before: str,
    source_clean_before: bool,
    task_attempt_count: int,
) -> None:
    source_head_after, source_clean_after = _current_source_identity(repo_root)
    _fail_real_smoke_mismatch(
        output_file,
        repo_root,
        mismatch_reason,
        attestation,
        result,
        expected_source_head=expected_source_head,
        source_head_before=source_head_before,
        source_head_after=source_head_after,
        source_clean_before=source_clean_before,
        source_clean_after=source_clean_after,
        task_attempt_count=task_attempt_count,
    )


def test_failure_smoke_record_is_written_outside_checkout_without_sensitive_details(tmp_path, monkeypatch):
    repo_root = tmp_path / "source-checkout"
    repo_root.mkdir()
    output_directory = tmp_path / "external" / "diagnostics"
    output_directory.mkdir(parents=True)
    output_file = output_directory / "failure.json"

    class FailedProducer:
        task_attempt_count = 1
        failure_diagnostic = o2c.O2cFailureDiagnostic(
            (o2c.O2cFailureStage.PROCESS_EXIT,), 73, o2c.O2cProcessExitCategory.AUTHENTICATION,
        )

    result = o2c.CandidateProducerResult(ProducerStatus.PRODUCER_ERROR)
    _write_failure_smoke_record(output_file, repo_root, result, FailedProducer())

    serialized = output_file.read_text(encoding="utf-8")
    assert json.loads(serialized) == {
        "format_version": "o2c-smoke-failure/1",
        "producer_status": "PRODUCER_ERROR",
        "task_attempt_count": 1,
        "failure_diagnostic": {
            "stages": ["process_exit"],
            "process_exit_code": 73,
            "process_exit_category": "authentication",
        },
    }
    assert "stdout" not in serialized and "stderr" not in serialized
    assert "prompt" not in serialized and "credential" not in serialized
    assert not output_file.resolve().is_relative_to(repo_root.resolve())

    with pytest.raises(ValueError):
        _write_failure_smoke_record(repo_root / "failure.json", repo_root, result, FailedProducer())

    missing_directory = tmp_path / "not-created" / "diagnostics"
    with pytest.raises(ValueError):
        _write_failure_smoke_record(missing_directory / "failure.json", repo_root, result, FailedProducer())
    assert not missing_directory.exists()

    non_directory = tmp_path / "output-is-a-file"
    non_directory.write_text("fixture", encoding="utf-8")
    with pytest.raises(ValueError):
        _write_failure_smoke_record(non_directory / "failure.json", repo_root, result, FailedProducer())

    unsafe_directory = tmp_path / "external" / "unsafe"
    unsafe_directory.mkdir()
    is_reparse_point = o2c._is_reparse_point
    monkeypatch.setattr(
        o2c, "_is_reparse_point",
        lambda path: Path(path) == unsafe_directory or is_reparse_point(path),
    )
    with pytest.raises(ValueError):
        _write_failure_smoke_record(unsafe_directory / "failure.json", repo_root, result, FailedProducer())


def _fixture_smoke_diagnostics(*, workspace_file_count: int = 2, proposal_change_count: int = 1):
    return o2c.CodexRunDiagnostics(
        runner_version="fixture-runner",
        worker_identity_measured="fixture-worker",
        codex_version="codex-cli fixture",
        codex_version_measured_before_task=True,
        codex_executable_sha256_before="a" * 64,
        codex_executable_sha256_after="a" * 64,
        worker_home_path="C:\\fixture\\worker",
        userprofile_path="C:\\fixture\\worker",
        worker_agents_clean=True,
        codex_home_path="C:\\fixture\\codex-home",
        codex_home_clean=True,
        root_exit_code=0,
        elapsed_milliseconds=12,
        workspace_file_count=workspace_file_count,
        proposal_change_count=proposal_change_count,
        stdout_byte_count=0,
        stdout_sha256=hashlib.sha256(b"").hexdigest(),
        stderr_byte_count=0,
        stderr_sha256=hashlib.sha256(b"").hexdigest(),
        process_tree_quiescent=True,
        resource_limit_violation=False,
        measured_features=tuple((name, False) for name in o2c.CAPABILITY_DENY_SET),
        measured_mcp_server_count=0,
        sandbox_implementation="mxc",
        doctor_exit_code=0,
        codex_cli_version_raw="codex-cli fixture",
        codex_package_version="fixture",
        candidate_workspace_git_present=False,
        job_assignment_succeeded=True,
        root_process_resumed_after_assignment=True,
        active_process_count_before_scan=0,
        resource_violation_types=(),
    )


def _mismatch_fixture_attestation() -> o2c.CodexWorkerDeploymentAttestation:
    configuration = o2c.CodexCliConfiguration(
        "C:\\fixture\\codex.exe", "codex-cli fixture", "a" * 64,
        "C:\\fixture\\worker", "C:\\fixture\\codex-home", "C:\\fixture\\scratch",
        30, o2b_test.BASE.value, "fixture-environment-id",
    )
    return _fixture_attestation(configuration)


@pytest.mark.parametrize(
    "proposal",
    (
        CandidateProposal(o2b_test.BASE.value, ()),
        CandidateProposal(o2b_test.BASE.value, (
            ProposedFileChange(ProposedChangeKind.ADD, "wrong-output.txt", b"fixture", "100644"),
        )),
        CandidateProposal(o2b_test.BASE.value, (
            ProposedFileChange(ProposedChangeKind.ADD, _EXPECTED_REAL_SMOKE_PATH, b"credential-marker", "100644"),
        )),
        CandidateProposal(o2b_test.BASE.value, (
            ProposedFileChange(ProposedChangeKind.ADD, _EXPECTED_REAL_SMOKE_PATH, _EXPECTED_REAL_SMOKE_CONTENT, "100755"),
        )),
        CandidateProposal(o2b_test.BASE.value, (
            *_EXPECTED_REAL_SMOKE_PROPOSAL.changes,
            ProposedFileChange(ProposedChangeKind.ADD, "unexpected-extra.txt", b"private-response-marker", "100644"),
        )),
    ),
    ids=("no-op", "wrong-path", "wrong-content", "wrong-mode", "unexpected-extra"),
)
def test_real_smoke_success_mismatch_writes_bounded_external_record_and_fails(tmp_path, proposal):
    repo_root = tmp_path / "source-checkout"
    repo_root.mkdir()
    output_directory = tmp_path / "external" / "diagnostics"
    output_directory.mkdir(parents=True)
    output_file = output_directory / "mismatch.json"
    metadata = _fixture_smoke_diagnostics(workspace_file_count=1 if not proposal.changes else 3)
    result = o2c.CandidateProducerResult(ProducerStatus.SUCCESS, proposal, metadata)
    reason = _expected_real_smoke_observation_mismatch(proposal, metadata)
    assert reason == "proposal_mismatch"

    with pytest.raises(pytest.fail.Exception, match="returned SUCCESS but failed the fixed expected outcome"):
        _fail_real_smoke_mismatch(
            output_file,
            repo_root,
            reason,
            _mismatch_fixture_attestation(),
            result,
            expected_source_head=o2b_test.BASE.value,
            source_head_before=o2b_test.BASE.value,
            source_head_after=o2b_test.BASE.value,
            source_clean_before=True,
            source_clean_after=True,
            task_attempt_count=1,
        )

    serialized = output_file.read_text(encoding="utf-8")
    record = json.loads(serialized)
    assert record["format_version"] == "o2c-smoke-mismatch/1"
    assert record["producer_status"] == "SUCCESS"
    assert record["task_attempt_count"] == 1
    assert record["mismatch_reason"] == "proposal_mismatch"
    assert record["source_identity"] == {
        "expected_pr_head_sha": o2b_test.BASE.value,
        "source_head_before": o2b_test.BASE.value,
        "source_head_after": o2b_test.BASE.value,
        "source_clean_before": True,
        "source_clean_after": True,
    }
    assert record["attestation_identity"] == {
        "attestation_id": "b" * 64,
        "source_head_sha": o2b_test.BASE.value,
        "worker_environment_id": "fixture-environment-id",
        "codex_executable_version": "codex-cli fixture",
        "codex_executable_sha256": "a" * 64,
    }
    assert record["observed_effect"]["proposal_change_count"] == len(proposal.changes)
    assert record["observed_effect"]["reported_proposal_change_count"] == 1
    assert record["observed_effect"]["workspace_file_count"] == metadata.workspace_file_count
    assert record["observed_effect"]["proposal_changed_paths"] == [change.path for change in proposal.changes]
    assert "credential-marker" not in serialized and "private-response-marker" not in serialized
    assert "stdout" not in serialized and "stderr" not in serialized and "prompt" not in serialized
    assert len(serialized.encode("utf-8")) <= _MAX_MISMATCH_RECORD_BYTES
    assert not output_file.resolve().is_relative_to(repo_root.resolve())


def test_real_smoke_workspace_observation_mismatch_writes_record_and_fails(tmp_path):
    repo_root = tmp_path / "source-checkout"
    repo_root.mkdir()
    output_directory = tmp_path / "external"
    output_directory.mkdir()
    output_file = output_directory / "mismatch.json"
    metadata = _fixture_smoke_diagnostics(workspace_file_count=1)
    proposal = _EXPECTED_REAL_SMOKE_PROPOSAL
    result = o2c.CandidateProducerResult(ProducerStatus.SUCCESS, proposal, metadata)
    reason = _expected_real_smoke_observation_mismatch(proposal, metadata)
    assert reason == "workspace_observation_mismatch"
    with pytest.raises(pytest.fail.Exception):
        _fail_real_smoke_mismatch(
            output_file, repo_root, reason, _mismatch_fixture_attestation(), result,
            expected_source_head=o2b_test.BASE.value,
            source_head_before=o2b_test.BASE.value,
            source_head_after=o2b_test.BASE.value,
            source_clean_before=True,
            source_clean_after=True,
            task_attempt_count=1,
        )
    record = json.loads(output_file.read_text(encoding="utf-8"))
    assert record["mismatch_reason"] == "workspace_observation_mismatch"
    assert record["observed_effect"]["workspace_file_count"] == 1
    assert record["observed_effect"]["proposal_changed_paths"] == [_EXPECTED_REAL_SMOKE_PATH]


@pytest.mark.parametrize(
    "reason",
    (
        "o2b_materialization_rejected",
        "materialized_candidate_mismatch",
        "trusted_mutation_inventory_mismatch",
    ),
)
def test_real_smoke_downstream_mismatch_record_remains_a_failure(tmp_path, reason):
    repo_root = tmp_path / "source-checkout"
    repo_root.mkdir()
    output_directory = tmp_path / "external"
    output_directory.mkdir()
    output_file = output_directory / "mismatch.json"
    result = o2c.CandidateProducerResult(
        ProducerStatus.SUCCESS, _EXPECTED_REAL_SMOKE_PROPOSAL, _fixture_smoke_diagnostics()
    )
    with pytest.raises(pytest.fail.Exception):
        _fail_real_smoke_mismatch(
            output_file, repo_root, reason, _mismatch_fixture_attestation(), result,
            expected_source_head=o2b_test.BASE.value,
            source_head_before=o2b_test.BASE.value,
            source_head_after=o2b_test.BASE.value,
            source_clean_before=True,
            source_clean_after=True,
            task_attempt_count=1,
        )
    record = json.loads(output_file.read_text(encoding="utf-8"))
    assert record["mismatch_reason"] == reason
    assert record["format_version"] == "o2c-smoke-mismatch/1"
    assert "admission" not in record and "completion" not in record


def test_real_smoke_mismatch_record_caps_paths_and_redacts_unsafe_path_text(tmp_path):
    repo_root = tmp_path / "source-checkout"
    repo_root.mkdir()
    output_directory = tmp_path / "external"
    output_directory.mkdir()
    output_file = output_directory / "mismatch.json"
    changes = tuple(
        ProposedFileChange(ProposedChangeKind.ADD, f"C:\\private\\{index}.txt", b"private-content", "100644")
        for index in range(_MAX_MISMATCH_PATHS + 5)
    )
    proposal = CandidateProposal(o2b_test.BASE.value, changes)
    metadata = _fixture_smoke_diagnostics(
        workspace_file_count=len(_EXPECTED_REAL_SMOKE_SEED.files) + len(changes),
        proposal_change_count=len(changes),
    )
    record = _build_real_smoke_mismatch_record(
        "proposal_mismatch", _mismatch_fixture_attestation(), proposal, metadata,
        expected_source_head=o2b_test.BASE.value,
        source_head_before=o2b_test.BASE.value,
        source_head_after=o2b_test.BASE.value,
        source_clean_before=True,
        source_clean_after=True,
        task_attempt_count=1,
    )
    _write_real_smoke_mismatch_record(
        output_file, repo_root, "proposal_mismatch", _mismatch_fixture_attestation(), proposal, metadata,
        expected_source_head=o2b_test.BASE.value,
        source_head_before=o2b_test.BASE.value,
        source_head_after=o2b_test.BASE.value,
        source_clean_before=True,
        source_clean_after=True,
        task_attempt_count=1,
    )
    serialized = output_file.read_text(encoding="utf-8")
    loaded = json.loads(serialized)
    assert record == loaded
    assert loaded["observed_effect"]["proposal_change_count"] == _MAX_MISMATCH_PATHS + 5
    assert loaded["observed_effect"]["omitted_path_count"] == 5
    assert loaded["observed_effect"]["proposal_changed_paths"] == ["<redacted-path>"] * _MAX_MISMATCH_PATHS
    assert "private-content" not in serialized and "C:\\private" not in serialized
    assert len(serialized.encode("utf-8")) <= _MAX_MISMATCH_RECORD_BYTES


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
    if not request_file.is_absolute() or not request_file.is_file():
        pytest.fail("real smoke requires absolute request input and record output paths")
    try:
        _validate_failure_smoke_output_path(output_file, repo_root)
    except ValueError:
        pytest.fail("real-smoke record output requires an existing safe directory outside the checkout")
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
    seed = _EXPECTED_REAL_SMOKE_SEED
    _assert_expected_real_smoke_seed(seed)
    producer = o2c.CodexCliCandidateProducer(
        configuration,
        seed,
        attestation,
        parent_environment=environment,
    )
    started_head = actual_head
    result = producer.invoke(request_file.read_bytes())
    if result.status is not ProducerStatus.SUCCESS or result.candidate_proposal is None:
        try:
            _write_failure_smoke_record(output_file, repo_root, result, producer)
        except (OSError, ValueError):
            pytest.fail("real Codex producer failed and its external stage diagnostic could not be written")
        pytest.fail("real Codex producer failed; bounded stage diagnostic was written outside the checkout")
    mismatch_reason = _expected_real_smoke_observation_mismatch(
        result.candidate_proposal, result.untrusted_metadata
    )
    if mismatch_reason is not None:
        _write_mismatch_and_fail(
            output_file,
            repo_root,
            mismatch_reason,
            attestation,
            result,
            expected_source_head=expected_head,
            source_head_before=started_head,
            source_clean_before=source_clean_before,
            task_attempt_count=producer.task_attempt_count,
        )
    materialized = DeterministicFixtureCandidateMaterializer().materialize(result.candidate_proposal, base_snapshot)
    if materialized.status is not MaterializationStatus.MATERIALIZED or materialized.candidate is None:
        _write_mismatch_and_fail(
            output_file,
            repo_root,
            "o2b_materialization_rejected",
            attestation,
            result,
            expected_source_head=expected_head,
            source_head_before=started_head,
            source_clean_before=source_clean_before,
            task_attempt_count=producer.task_attempt_count,
        )
    try:
        _assert_expected_real_smoke_candidate(materialized.candidate, base_snapshot)
    except AssertionError:
        _write_mismatch_and_fail(
            output_file,
            repo_root,
            "materialized_candidate_mismatch",
            attestation,
            result,
            expected_source_head=expected_head,
            source_head_before=started_head,
            source_clean_before=source_clean_before,
            task_attempt_count=producer.task_attempt_count,
        )
    combined = o2b_test.independently_verify_and_combine(base_store, base_snapshot, result.candidate_proposal, materialized)
    admitted = o2b_test._trusted_admit_candidate(
        base_store, combined, materialized.candidate.candidate_commit_id, "issue69-o2c-real-smoke-candidate"
    )
    try:
        _assert_expected_real_smoke_mutations(admitted.mutation_inventory.mutations, base_snapshot)
    except AssertionError:
        _write_mismatch_and_fail(
            output_file,
            repo_root,
            "trusted_mutation_inventory_mismatch",
            attestation,
            result,
            expected_source_head=expected_head,
            source_head_before=started_head,
            source_clean_before=source_clean_before,
            task_attempt_count=producer.task_attempt_count,
        )
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
    try:
        _validate_failure_smoke_output_path(output_file, repo_root)
    except ValueError:
        pytest.fail("real-smoke record output is no longer an existing safe directory outside the checkout")
    output_file.write_text(json.dumps(record, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    assert output_file.is_file()
