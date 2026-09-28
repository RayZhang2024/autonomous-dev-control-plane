"""G9 v0.3 candidate assembly and external-boundary adversarial proofs."""

from __future__ import annotations

import hashlib
import ast
import copy
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import zipfile

import pytest

from assemble_candidate import (
    _EXECUTION_ISOLATION_DOMAIN,
    _EXECUTION_ISOLATION_PROFILE_FIELDS,
    _derive_execution_isolation_dependency_id,
    _make_graph_resources,
    _manifest_external_tcb_dependencies,
    assemble_candidate,
)
from external_profiles import build_external_profiles
from build_definition import (
    APPLICATION_BASE, AUTHORIZED_BASE, R2_EXECUTABLE_BASE, RUNTIME_MEMBERS, SOURCE_MEMBERS,
    canonical_json_bytes,
)
from fixture_root_store import TemporaryRootStore
from ipc import decode_ack, decode_message, encode_message

REPOSITORY = Path(__file__).resolve().parents[2]
TOOLS = REPOSITORY / "tools" / "genesis"
EXPECTED_MODULES = frozenset({
    "autodev_control/trusted/errors.py",
    "autodev_control/trusted/identity.py",
    "autodev_control/trusted/parsing.py",
    "autodev_control/trusted/scope.py",
    "autodev_control/trusted/resources.py",
    "autodev_control/trusted/manifest.py",
    "autodev_control/trusted/genesis_resource_graph.py",
    "autodev_control/trusted/decision.py",
    "autodev_control/trusted/contract.py",
    "autodev_control/trusted/target_registration.py",
    "autodev_control/trusted/authorization.py",
    "autodev_control/trusted/operation.py",
    "autodev_control/trusted/state.py",
    "autodev_control/trusted/evidence.py",
    "autodev_control/trusted/review.py",
    "autodev_control/trusted/semantic_config.py",
    "autodev_control/trusted/semantic_context.py",
    "autodev_control/trusted/current_semantic_review.py",
    "autodev_control/trusted/__init__.py",
    "autodev_control/trusted/audit.py",
    "autodev_control/trusted/backend.py",
    "autodev_control/trusted/state_reader.py",
    "autodev_control/trusted/materialization.py",
    "autodev_control/trusted/protected_effect.py",
    "autodev_control/trusted/runtime_authority.py",
    "autodev_control/trusted/runtime_roles.py",
})


def _test_external_profiles():
    return build_external_profiles(
        str(REPOSITORY),
        root_admin_principal={
            "account": r"TEST\human-root-admin", "sid": "S-1-5-21-711519901-190585334-3846127459-2010",
            "administrator": True,
        },
        substrate_principal={
            "account": r"TEST\fixture-substrate", "sid": "S-1-5-21-711519901-190585334-3846127459-2020",
            "token_type": "PRIMARY", "administrator": False,
        },
        python_runtime={
            "identity": "CPython", "version": "3.13.14",
            "path": r"C:\AutodevG9\shared\python313\python.exe", "sha256": "8" * 64,
        },
    )


@pytest.fixture(scope="module")
def package():
    root_profile, substrate_profile, anchor_id, _ = _test_external_profiles()
    return assemble_candidate(
        git_cwd=str(REPOSITORY), root_fence_profile=root_profile,
        fixture_substrate_profile=substrate_profile, root_anchor_id=anchor_id,
    )


def test_execution_isolation_dependency_id_is_exactly_derived_from_closed_profile(package):
    build = json.loads(package.build_definition)
    profile = build["execution_isolation_profile"]
    expected = "dep-execution-isolation-" + hashlib.sha256(
        _EXECUTION_ISOLATION_DOMAIN + canonical_json_bytes(profile)
    ).hexdigest()
    assert set(profile) == set(_EXECUTION_ISOLATION_PROFILE_FIELDS)
    assert build["execution_isolation_dependency_id"] == expected
    assert package.dependency_lock
    assert json.loads(package.deterministic_evidence)["execution_isolation_dependency_id"] == expected
    with zipfile.ZipFile(__import__("io").BytesIO(package.candidate_package)) as archive:
        descriptor = json.loads(archive.read("candidate-package.json"))
    assert descriptor["preimage"]["execution_isolation_dependency_id"] == expected
    assert descriptor["preimage"]["execution_isolation_profile"] == profile


@pytest.mark.parametrize("path", (
    "tools/genesis/ipc.py",
    "tools/genesis/role_worker.py",
    "tools/genesis/windows_role_launcher.py",
    "tools/genesis/windows_role_runner.py",
    "tools/genesis/role_adapter.py",
    "tools/genesis/fixture_substrate.py",
))
def test_external_isolation_code_digest_changes_dependency_assumption_manifest_and_contexts(package, path):
    profile = json.loads(package.build_definition)["execution_isolation_profile"]
    original_id = _derive_execution_isolation_dependency_id(profile)
    changed = copy.deepcopy(profile)
    item = next(value for value in changed["external_adapter_material"] if value["path"] == path)
    item["sha256"] = "f" * 64
    for module in changed["role_interpreter_modules"]:
        if module["path"] == path:
            module["sha256"] = item["sha256"]
    changed_id = _derive_execution_isolation_dependency_id(changed)
    assert changed_id != original_id

    raw, _, graph = _make_graph_resources("runtime", changed_id)
    assumption = json.loads(raw["assumption-execution-isolation"])
    assert assumption == {
        "format": "autodev.genesis-external-tcb-assumption/v1",
        "role": "EXECUTION_ISOLATION",
        "dependency_id": changed_id,
    }
    graph_binding = next(item for item in graph["external_tcb_roles"]
                         if item["role"] == "EXECUTION_ISOLATION")
    assert graph_binding["dependency_id"] == changed_id
    assert {item["dependency_id"] for item in _manifest_external_tcb_dependencies(graph)} >= {changed_id}
    for role in ("T", "C", "P", "M"):
        assert json.loads(raw[f"security-{role}"])["external_isolation_dependency_id"] == changed_id


@pytest.mark.parametrize("role", ("T", "C", "P", "M"))
def test_each_reviewed_role_sid_changes_execution_isolation_profile_identity(package, role):
    profile = json.loads(package.build_definition)["execution_isolation_profile"]
    original_id = _derive_execution_isolation_dependency_id(profile)
    changed = copy.deepcopy(profile)
    principal = next(item for item in changed["role_principals"] if item["role"] == role)
    principal["sid"] += "-99"
    assert _derive_execution_isolation_dependency_id(changed) != original_id


@pytest.mark.parametrize("field,value", (
    ("sha256", "0" * 64),
    ("version", "3.13.15"),
    ("path", r"C:\AutodevG9\other-python\python.exe"),
))
def test_staged_cpython_profile_change_changes_execution_isolation_identity(package, field, value):
    profile = json.loads(package.build_definition)["execution_isolation_profile"]
    original_id = _derive_execution_isolation_dependency_id(profile)
    changed = copy.deepcopy(profile)
    changed["python_runtime"][field] = value
    assert _derive_execution_isolation_dependency_id(changed) != original_id


def test_module_loading_policy_allowlists_exact_external_role_modules_outside_candidate_runtime(package):
    build = json.loads(package.build_definition)
    profile = build["execution_isolation_profile"]
    policy = json.loads(package.raw_resources["module-policy"])
    assert policy["third_party_runtime_policy"]["third_party_module_allowlist"] == [
        "fixture_substrate", "ipc", "role_adapter", "role_worker",
    ]
    assert not set(policy["third_party_runtime_policy"]["third_party_module_allowlist"]) & set(
        policy["allowed_candidate_modules"]
    )
    assert profile["role_interpreter_modules"] == [
        {"module_name": "ipc", "execution": "IMPORTED", "path": "tools/genesis/ipc.py",
         "sha256": next(item["sha256"] for item in build["external_tcb_material"]
                        if item["path"] == "tools/genesis/ipc.py")},
        {"module_name": "role_worker", "execution": "SCRIPT", "path": "tools/genesis/role_worker.py",
         "sha256": next(item["sha256"] for item in build["external_tcb_material"]
                        if item["path"] == "tools/genesis/role_worker.py")},
        {"module_name": "role_adapter", "execution": "IMPORTED", "path": "tools/genesis/role_adapter.py",
         "sha256": next(item["sha256"] for item in build["external_tcb_material"]
                        if item["path"] == "tools/genesis/role_adapter.py")},
        {"module_name": "fixture_substrate", "execution": "IMPORTED",
         "path": "tools/genesis/fixture_substrate.py",
         "sha256": next(item["sha256"] for item in build["external_tcb_material"]
                        if item["path"] == "tools/genesis/fixture_substrate.py")},
    ]
    with zipfile.ZipFile(__import__("io").BytesIO(package.runtime_artifact)) as archive:
        names = set(archive.namelist())
    assert not {"ipc.py", "role_worker.py", "role_adapter.py", "fixture_substrate.py"} & names
    assert all(item not in RUNTIME_MEMBERS for item in policy["third_party_runtime_policy"]["third_party_module_allowlist"])


def test_exact_26_source_runtime_bijection_and_deterministic_repeat_builds(package):
    assert AUTHORIZED_BASE == APPLICATION_BASE == "fd0cf5d910bf59e6f28aa36ae7b34a3b00eb3001"
    assert R2_EXECUTABLE_BASE == "1c859faad04978a341a3527e034b41c0a849da1f"
    assert len(SOURCE_MEMBERS) == len(RUNTIME_MEMBERS) == 26
    assert len(set(SOURCE_MEMBERS)) == len(set(RUNTIME_MEMBERS)) == 26
    assert all(runtime == source.removeprefix("src/")
               for source, runtime in zip(SOURCE_MEMBERS, RUNTIME_MEMBERS, strict=True))
    with zipfile.ZipFile(__import__("io").BytesIO(package.runtime_artifact)) as archive:
        names = frozenset(name for name in archive.namelist() if not name.endswith("/"))
        assert names == EXPECTED_MODULES
        assert "autodev_control/__init__.py" not in names
        assert all(not name.startswith(("tests/", "fixtures/")) for name in names)
        assert all("__pycache__" not in name and not name.endswith(".pyc") for name in names)
        assert all(info.compress_type == zipfile.ZIP_STORED for info in archive.infolist())
        assert all(info.date_time == (1980, 1, 1, 0, 0, 0) for info in archive.infolist())
        assert {name for name in archive.namelist() if name.endswith("/")} == {
            "autodev_control/", "autodev_control/trusted/"
        }
    root_profile, substrate_profile, anchor_id, _ = _test_external_profiles()
    repeated = assemble_candidate(
        git_cwd=str(REPOSITORY), root_fence_profile=root_profile,
        fixture_substrate_profile=substrate_profile, root_anchor_id=anchor_id,
    )
    assert package.source_bundle == repeated.source_bundle
    assert package.runtime_artifact == repeated.runtime_artifact
    assert package.build_definition == repeated.build_definition
    assert package.dependency_lock == repeated.dependency_lock
    assert package.manifest == repeated.manifest
    assert package.deterministic_evidence == repeated.deterministic_evidence
    assert package.candidate_package == repeated.candidate_package


def test_candidate_import_closure_is_exact_and_unexpected_security_modules_fail_closed(package, tmp_path):
    with zipfile.ZipFile(__import__("io").BytesIO(package.runtime_artifact)) as archive:
        for path in EXPECTED_MODULES:
            tree = ast.parse(archive.read(path), filename=path)
            source_module = path[:-3].replace("/", ".")
            if source_module.endswith(".__init__"):
                source_module = source_module[:-9]
            package_name = source_module.rpartition(".")[0]
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    names = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom):
                    if node.level:
                        base = package_name.split(".")[:len(package_name.split(".")) - node.level + 1]
                        absolute = ".".join((*base, *((node.module or "").split("."))))
                        names = [absolute]
                        if node.module is None:
                            names.extend(f"{absolute}.{alias.name}" for alias in node.names)
                    else:
                        names = [node.module or ""]
                else:
                    continue
                for name in names:
                    if name == "autodev_control" or name.startswith("autodev_control."):
                        member_path = name.replace(".", "/") + ".py"
                        init_path = name.replace(".", "/") + "/__init__.py"
                        assert member_path in EXPECTED_MODULES or init_path in EXPECTED_MODULES
                    else:
                        assert name.split(".")[0] in sys.stdlib_module_names, (path, name)
    runtime = tmp_path / "candidate.zip"
    runtime.write_bytes(package.runtime_artifact)
    program = "\n".join((
        "import importlib, sys",
        "sys.path.insert(0, sys.argv[1])",
        "try:",
        "    importlib.import_module('autodev_control.trusted.fixture_platform')",
        "except ModuleNotFoundError:",
        "    pass",
        "else:",
        "    raise AssertionError('excluded fixture module loaded')",
    ))
    result = subprocess.run([sys.executable, "-I", "-S", "-c", program, str(runtime)],
                            capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stderr


def test_fresh_isolated_namespace_imports_exact_runtime_closure(package, tmp_path):
    runtime = tmp_path / "runtime.zip"
    runtime.write_bytes(package.runtime_artifact)
    imports = "\n".join(
        f"importlib.import_module({name[:-3].replace('/', '.').replace('.__init__', '')!r})"
        for name in sorted(EXPECTED_MODULES)
    )
    program = (
        "import importlib,sys;sys.path.insert(0,sys.argv[1]);"
        "import autodev_control;assert autodev_control.__spec__.origin is None;"
        f"{imports};"
        "assert 'autodev_control' in sys.modules"
    )
    completed = subprocess.run(
        [sys.executable, "-I", "-S", "-c", program, str(runtime)],
        cwd=tmp_path, check=False, capture_output=True, text=True, timeout=30,
    )
    assert completed.returncode == 0, completed.stderr


def test_r4_resource_graph_manifest_and_external_tcb_closure_pass(package):
    from autodev_control.trusted.errors import GenesisResourceGraphFailure
    from autodev_control.trusted.genesis_resource_graph import validate_genesis_resource_graph
    from autodev_control.trusted.manifest import CandidateTrustedManifest, load_candidate_trusted_manifest

    manifest = load_candidate_trusted_manifest(package.manifest)
    assert type(manifest) is CandidateTrustedManifest
    result = validate_genesis_resource_graph(manifest, dict(package.raw_resources))
    assert type(result) is not GenesisResourceGraphFailure
    assert result.manifest_id == manifest.manifest_id
    assert len(manifest.trusted_core_members) == 4
    assert len(manifest.external_tcb_dependencies) == 3
    assert {item.kind.value for item in manifest.root_managed_resources
            if item.resource_id.value.startswith("assumption-")} == {"EXTERNAL_TCB_ASSUMPTION_DOCUMENT"}
    changed = dict(package.raw_resources)
    changed["runtime"] = changed["runtime"] + b"tamper"
    rejected = validate_genesis_resource_graph(manifest, changed)
    assert type(rejected) is GenesisResourceGraphFailure
    assert rejected.code.value == "GRAPH_RESOURCE_DIGEST_MISMATCH"
    expected = {item.resource_id.value for item in manifest.root_managed_resources}
    assert set(package.raw_resources) == expected
    assert {item.resource_id.value for item in result.verified_resource_refs} == expected
    assert {item.value for item in result.consumed_resource_ids} == expected


def test_role_specific_entrypoints_credentials_and_capability_wiring(package):
    graph = json.loads(package.graph)
    raw = package.raw_resources
    role_names = {"T": "TrustedControllerRuntime", "C": "ControlStateGateRuntime",
                  "P": "PublicationGateRuntime", "M": "MergeGateRuntime"}
    substrate_profile = json.loads(package.build_definition)["fixture_substrate_profile"]
    wiring = {"T": ("READ", "NONE", "NONE"), "C": ("READ_WRITE", "NONE", "NONE"),
              "P": ("READ", substrate_profile["p_target_fence"]["endpoint_id"],
                    substrate_profile["publication_authority_endpoint"]["endpoint_id"]),
              "M": ("READ", substrate_profile["m_target_fence"]["endpoint_id"],
                    substrate_profile["merge_authority_endpoint"]["endpoint_id"])}
    for member in graph["members"]:
        role = member["role"]
        entry = json.loads(raw[member["entry_point_config_resource"]])
        creds = json.loads(raw[member["credential_routing_resource"]])
        caps = json.loads(raw[member["capability_wiring_resource"]])
        assert entry["callable"] == role_names[role]
        assert creds["production_github_mutation_credentials"] == "NONE"
        assert (caps["canonical_state_access"], caps["target_fence_binding"],
                caps["publication_authority_binding"] if role == "P" else caps["merge_authority_binding"]) == wiring[role]
    assert {record["role"] for record in graph["external_tcb_roles"]} == {
        "ROOT_ACTIVATION_FENCE", "EXECUTION_ISOLATION", "FIXTURE_EFFECT_SUBSTRATE"
    }
    assert len({member["service_principal"] for member in graph["members"]}) == 4


def test_closed_ipc_authentication_role_and_payload_rejection():
    key = secrets.token_bytes(32)
    frame = encode_message(channel="authenticated-t-to-c", request_id="req-1",
                           payload={"command": "BOOTSTRAP_PROBE", "nonce": "n-1"}, key=key)
    decoded = decode_message(frame, expected_role="C", key=key)
    assert decoded["destination_role"] == "C"
    with pytest.raises(ValueError):
        decode_message(frame, expected_role="P", key=key)
    with pytest.raises(ValueError):
        decode_message(frame, expected_role="C", key=secrets.token_bytes(32))
    with pytest.raises(ValueError):
        encode_message(channel="authenticated-t-to-m", request_id="x", payload={"command": "RELEASE_ROOT"}, key=key)
    with pytest.raises(ValueError):
        encode_message(channel="authenticated-t-to-p", request_id="x", payload={"command": "FAST_FORWARD_MERGE"}, key=key)
    with pytest.raises(ValueError):
        decode_message(frame[:-1] + b" ", expected_role="C", key=key)
    duplicate_field = frame[:-1] + b',"format":"autodev.genesis-ipc/v1"}'
    with pytest.raises(ValueError):
        decode_message(duplicate_field, expected_role="C", key=key)


def test_actual_role_worker_is_single_process_and_has_a_closed_credential_boundary():
    worker = (TOOLS / "role_worker.py").read_text(encoding="utf-8")
    launcher = (TOOLS / "windows_role_launcher.py").read_text(encoding="utf-8")
    runner = (TOOLS / "windows_role_runner.py").read_text(encoding="utf-8")
    assert "subprocess.Popen" not in worker
    assert "channel_keys" not in worker
    assert '"channel_key_hex"' in worker
    assert "CreateProcessWithLogonW" in launcher
    assert "getpass.getpass" in launcher
    assert "password" not in runner.split("if __name__", 1)[-1].lower()
    assert "PYTHONPATH" not in launcher
    assert "runas" not in launcher.lower()


@pytest.mark.skipif(
    os.name != "nt" or os.environ.get("AUTODEV_G9_RUN_WINDOWS_ROLES") != "1",
    reason="requires explicit local run with secure interactive role-password prompts",
)
def test_four_real_windows_role_tokens_and_acl_boundaries(package):
    from windows_role_runner import run_realized_roles

    evidence = run_realized_roles()
    roles = evidence["roles"]
    assert set(roles) == {"T", "C", "P", "M"}
    assert len({item["pid"] for item in roles.values()}) == 4
    assert len({item["sid"] for item in roles.values()}) == 4
    assert {item["sid"] for item in roles.values()} == {
        "S-1-5-21-711519901-190585334-3846127459-1016",
        "S-1-5-21-711519901-190585334-3846127459-1017",
        "S-1-5-21-711519901-190585334-3846127459-1018",
        "S-1-5-21-711519901-190585334-3846127459-1019",
    }
    assert all(item["administrator"] is False for item in roles.values())
    assert evidence["root_store_write_denial"] is True
    assert evidence["external_fence_release_denial"] is True


def test_external_sqlite_root_store_is_temporary_create_once_and_revision_cas():
    with TemporaryRootStore() as store:
        assert store.create_if_absent("fixture-root", b"candidate-only")
        assert not store.create_if_absent("fixture-root", b"replacement")
        assert store.read("fixture-root") == (0, b"candidate-only")
        assert not store.compare_and_swap("fixture-root", 7, b"stale-write")
        assert store.compare_and_swap("fixture-root", 0, b"updated-fixture")
        assert store.read("fixture-root") == (1, b"updated-fixture")


def test_candidate_package_evidence_is_deterministic_non_self_referential_and_unactivated(package):
    descriptor = None
    with zipfile.ZipFile(__import__("io").BytesIO(package.candidate_package)) as archive:
        assert archive.namelist() == sorted(archive.namelist())
        assert "candidate-package.json" in archive.namelist()
        descriptor = json.loads(archive.read("candidate-package.json"))
        assert archive.read("candidate-manifest.json") == package.manifest
        assert archive.read("deterministic-evidence.json") == package.deterministic_evidence
    assert descriptor["candidate_package_id"] == package.candidate_package_id
    assert descriptor["preimage"]["repository_application_base"] == APPLICATION_BASE
    assert descriptor["preimage"]["r2_executable_baseline"] == R2_EXECUTABLE_BASE
    assert descriptor["preimage"]["r3_resource"] == {
        "resource_id": "conformance",
        "git_blob": "30d4efcaa2adb38acbc0df5635c3bcba4710fa18",
        "sha256": "36498b5d51227a553d452ee21d3fbc61aed7483dc9304939befddb2651acfd35",
    }
    assert hashlib.sha256(json.dumps(descriptor["preimage"], ensure_ascii=False,
                                     sort_keys=True, separators=(",", ":")).encode()).hexdigest() == package.candidate_package_id
    text = package.candidate_package.decode("latin-1", errors="ignore")
    assert "GenesisAcceptanceRecord" not in text
    assert "93b18deb0279a829ac3c5605192f7314afa80ac6" not in text
    assert "5d341c0f0b8668ce792cc459b465cd27d777794b97a08beac0fd94c573a24fb0" not in text
    assert b"GENESIS ACTIVE" not in package.deterministic_evidence
    assert json.loads(package.dependency_lock)["runtime_dependencies"] == []
    assert package.deterministic_evidence_id == "D-" + hashlib.sha256(package.deterministic_evidence).hexdigest()[:24]
    with pytest.raises(TypeError):
        package.raw_resources["new-resource"] = b"not permitted"
