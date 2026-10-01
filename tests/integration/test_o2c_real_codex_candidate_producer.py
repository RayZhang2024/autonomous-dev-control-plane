"""Fake-containment linkage tests plus a disabled-by-default real smoke harness."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess

import pytest

import autodev_control.workplane.codex_cli_candidate_producer as o2c
from autodev_control.workplane.candidate_producer import ProducerStatus
from autodev_control.workplane.fixture_candidate_materializer import (
    DeterministicFixtureCandidateMaterializer,
    FixtureBaseSnapshot,
    MaterializationStatus,
)
from tests.integration import test_o2b_fixture_candidate_materialization as o2b_test


class FakePreflight:
    def inspect(self, *args):
        return o2c.CodexEffectiveState(
            tuple((name, False) for name in o2c.CAPABILITY_DENY_SET), 0, "disabled", False, True, True, ()
        )


class FakeContainedRunner:
    def __init__(self):
        self.calls = 0

    def run(self, executable, arguments, workspace, environment, prompt_bytes, timeout_seconds):
        self.calls += 1
        (Path(workspace) / "o2c-output.txt").write_bytes(b"proposal from isolated fake worker")
        return o2c.ContainedExecutionOutcome(
            0, False, True, False, 0, hashlib.sha256(b"").hexdigest(),
            0, hashlib.sha256(b"").hexdigest(), 1,
        )


def _deployment() -> o2c.CodexWorkerDeployment:
    return o2c.CodexWorkerDeployment(
        "dedicated_vm", True, True, True, True, True, True, True, True, True,
        "keyring", "chatgpt", True, True, (), True, "disabled",
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
    producer = o2c.CodexCliCandidateProducer(
        o2c.CodexCliConfiguration(
            str(executable), "fixture-codex 0", hashlib.sha256(executable.read_bytes()).hexdigest(),
            str(worker_home), str(codex_home), str(scratch_root), 30,
        ),
        seed,
        _deployment(),
        preflight=FakePreflight(),
        runner=runner,
        parent_environment=environment,
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


@pytest.mark.skipif(os.environ.get("O2C_REAL_SMOKE") != "1", reason="dedicated-worker Codex smoke is explicitly opt-in")
def test_opt_in_real_codex_smoke_records_exact_head_o2b_and_trusted_admission(tmp_path):
    """Run only on a manually prepared dedicated worker and write its complete record."""
    context, context_path = _real_smoke_context()
    required_true = (
        "read_isolated_worker", "non_admin_worker", "clean_worker_home", "clean_codex_home",
        "dedicated_codex_principal", "principal_inference_only", "principal_no_target_control_root_rights",
        "no_unrelated_private_apps_or_data", "credential_may_be_accessible", "mcp_configuration_sources_absent",
        "managed_system_policy_inspected", "exec_policy_rules_absent",
    )
    if any(context.get(name) is not True for name in required_true):
        pytest.fail("real-smoke context does not establish every frozen dedicated-worker prerequisite")
    if context.get("managed_system_external_broadening") != [] or context.get("effective_web_search_mode") != "disabled":
        pytest.fail("real-smoke context reports external capability broadening")
    if context.get("keyring_credentials_store") != "keyring" or context.get("forced_login_method") != "chatgpt":
        pytest.fail("real-smoke authentication profile is incompatible")
    expected_head = context.get("exact_pr_head_sha")
    if type(expected_head) is not str or len(expected_head) not in (40, 64) or any(char not in "0123456789abcdef" for char in expected_head):
        pytest.fail("real-smoke context is missing exact published PR-head SHA")
    if os.name != "nt":
        pytest.fail("frozen Phase-1 real Codex worker profile requires native Windows Job Objects")
    repo_root = Path(__file__).resolve().parents[2]
    actual_head = subprocess.run(("git", "rev-parse", "HEAD"), cwd=repo_root, check=True, capture_output=True, text=True).stdout.strip()
    if actual_head != expected_head:
        pytest.fail("checked-out source does not equal the exact published PR head")
    if subprocess.run(("git", "status", "--porcelain"), cwd=repo_root, check=True, capture_output=True, text=True).stdout.strip():
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
    scratch_root = os.environ.get("O2C_SCRATCH_ROOT", "")
    executable = os.environ.get("O2C_CODEX_EXECUTABLE", "")
    version = os.environ.get("O2C_CODEX_VERSION", "")
    executable_hash = os.environ.get("O2C_CODEX_SHA256", "")
    for value in (worker_home, codex_home, scratch_root, executable, version, executable_hash):
        if not value:
            pytest.fail("real-smoke Codex identity/home/scratch configuration is incomplete")
    environment = dict(os.environ)
    deployment = _deployment()
    producer = o2c.CodexCliCandidateProducer(
        o2c.CodexCliConfiguration(executable, version, executable_hash, worker_home, codex_home, scratch_root, 1800),
        o2c.CodexWorkspaceSeed(o2b_test.BASE.value, (o2c.CodexWorkspaceFile("o2c-smoke-input.txt", b"fixture input", "100644"),)),
        deployment,
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
    if subprocess.run(("git", "rev-parse", "HEAD"), cwd=repo_root, check=True, capture_output=True, text=True).stdout.strip() != started_head:
        pytest.fail("source identity changed during the real smoke")
    if subprocess.run(("git", "status", "--porcelain"), cwd=repo_root, check=True, capture_output=True, text=True).stdout.strip():
        pytest.fail("real smoke modified the source checkout")
    metadata = result.untrusted_metadata
    record = {
        "exact_pr_head_sha": expected_head,
        "source_head_before_and_after": started_head,
        "worker_classification": {key: context[key] for key in required_true},
        "clean_worker_home": context["clean_worker_home"],
        "clean_codex_home": context["clean_codex_home"],
        "codex_executable_path": executable,
        "codex_version": metadata.codex_version,
        "codex_executable_sha256": metadata.codex_executable_sha256,
        "effective_denied_capabilities": list(o2c.CAPABILITY_DENY_SET),
        "mcp_server_count": 0,
        "sandbox_profile": "workspace-write; network_access=false; writable_roots=[]",
        "job_object_containment": "Windows Job Object; kill-on-close; no breakaway; limits verified by configured runner",
        "zero_descendants_before_scan": True,
        "producer_status": result.status.value,
        "proposal": [{"kind": change.kind.value, "path": change.path} for change in result.candidate_proposal.changes],
        "o2b_candidate_commit_id": materialized.candidate.candidate_commit_id,
        "trusted_mutation_inventory": [
            {"path": fact.path.value, "kind": fact.kind.value} for fact in admitted.mutation_inventory.mutations
        ],
        "stdout_byte_count": metadata.stdout_byte_count,
        "stdout_sha256": metadata.stdout_sha256,
        "stderr_byte_count": metadata.stderr_byte_count,
        "stderr_sha256": metadata.stderr_sha256,
        "real_smoke": "completed; no publication or merge performed",
    }
    output_file.write_text(json.dumps(record, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    assert output_file.is_file()
