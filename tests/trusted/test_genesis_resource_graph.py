"""Adversarial tests for the frozen pre-G9 R4 resource-graph boundary."""

from __future__ import annotations

import copy
from dataclasses import FrozenInstanceError
import hashlib
import json
from collections.abc import Callable

import pytest

from autodev_control.trusted.errors import (
    GenesisResourceGraphFailure,
    GenesisResourceGraphFailureCode,
    ManifestFailure,
    ManifestFailureCode,
)
from autodev_control.trusted import genesis_resource_graph as graph_module
from autodev_control.trusted.genesis_resource_graph import (
    GENESIS_RESOURCE_GRAPH_CONFIG_ID,
    ValidatedGenesisResourceGraph,
    validate_genesis_resource_graph,
)
from autodev_control.trusted.manifest import CandidateTrustedManifest, load_candidate_trusted_manifest


def _json_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


_FIXTURE_BINDINGS = {
    "f_read_verify_binding": "endpoint-f-read",
    "f_read_verify_mode": "READ_ONLY",
    "publication_authority_binding": "endpoint-publication",
    "merge_authority_binding": "endpoint-merge",
    "external_recovery_binding": "endpoint-external-recovery",
    "p_target_fence_binding": "endpoint-p-fence",
    "m_target_fence_binding": "endpoint-m-fence",
    "target_fence_namespace": "namespace-target-fence",
}
_EXCLUSIONS = sorted((
    "tests/**",
    "src/autodev_control/trusted/gates.py",
    "src/autodev_control/trusted/fixture_audit.py",
    "src/autodev_control/trusted/fixture_capabilities.py",
    "src/autodev_control/trusted/fixture_transport.py",
    "src/autodev_control/trusted/fixture_platform.py",
))


def _fixture(
    *,
    graph_change: Callable[[dict[str, object]], None] | None = None,
    resource_change: Callable[[dict[str, dict[str, object]]], None] | None = None,
    fixture_binding_change: Callable[[dict[str, str]], None] | None = None,
    manifest_change: Callable[[dict[str, object]], None] | None = None,
    include_schema: bool = False,
    extra_resources: tuple[tuple[str, str, bytes], ...] = (),
) -> tuple[CandidateTrustedManifest, dict[str, bytes], dict[str, object]]:
    raw: dict[str, bytes] = {
        "core": b"synthetic core policy",
        "implementation": b"synthetic trusted implementation",
        "build": b"synthetic build definition",
        "runtime": b"synthetic runtime artifact",
        "conformance": b"synthetic frozen conformance policy bytes",
    }
    resource_kinds: dict[str, str] = {
        "core": "CORE_POLICY",
        "implementation": "TRUSTED_CODE",
        "build": "BUILD_DEFINITION",
        "runtime": "RUNTIME_ARTIFACT",
        "lock": "DEPENDENCY_LOCK",
        "module-policy": "MODULE_LOADING_POLICY",
        "conformance": "POLICY",
        "graph": "TRUSTED_CONFIG",
    }
    if include_schema:
        raw["schema"] = b'{"type":"object"}'
        resource_kinds["schema"] = "TRUSTED_SCHEMA"
    for resource_id, kind, data in extra_resources:
        resource_kinds[resource_id] = kind
        raw[resource_id] = data

    members: list[dict[str, str]] = []
    entry_values: dict[str, dict[str, object]] = {}
    security_values: dict[str, dict[str, object]] = {}
    wiring_values: dict[str, dict[str, object]] = {}
    credential_values: dict[str, dict[str, object]] = {}
    for role in ("T", "C", "P", "M"):
        entry_id = f"entry-{role}"
        security_id = f"security-{role}"
        wiring_id = f"wiring-{role}"
        credential_id = f"credential-{role}"
        resource_kinds.update({
            entry_id: "ENTRY_POINT_CONFIG",
            security_id: "SECURITY_CONTEXT_CONFIG",
            wiring_id: "CAPABILITY_WIRING",
            credential_id: "CREDENTIAL_ROUTING",
        })
        members.append({
            "role": role,
            "member_id": role,
            "service_principal": f"service-{role}",
            "implementation_resource": "implementation",
            "runtime_artifact_resource": "runtime",
            "entry_point_config_resource": entry_id,
            "security_context_config_resource": security_id,
            "capability_wiring_resource": wiring_id,
            "credential_routing_resource": credential_id,
        })
        entry_values[entry_id] = {
            "format": "autodev.genesis-entry-point/v1",
            "role": role,
            "member_id": role,
            "runtime_artifact_resource": "runtime",
            "module": f"autodev_control.role_{role.lower()}",
            "callable": f"run_{role.lower()}",
        }
        security_values[security_id] = {
            "format": "autodev.genesis-security-context/v1",
            "role": role,
            "member_id": role,
            "context_id": security_id,
            "service_principal": f"service-{role}",
            "runtime_binding": f"runtime-binding-{role}",
            "runtime_generation_binding": "runtime-generation-1",
            "root_context_binding": "root-context-1",
            "external_isolation_dependency_id": "dep-execution-isolation",
            "channels": [],
        }
        access = {"T": "READ", "C": "READ_WRITE", "P": "READ", "M": "READ"}[role]
        state_binding = {
            "T": "endpoint-t-read-client",
            "C": "endpoint-c-owned-writer",
            "P": "endpoint-canonical-start-read",
            "M": "endpoint-canonical-start-read",
        }[role]
        wiring_values[wiring_id] = {
            "format": "autodev.genesis-capability-wiring/v1",
            "role": role,
            "member_id": role,
            "canonical_state_access": access,
            "canonical_state_binding": state_binding,
            "f_read_verify_binding": _FIXTURE_BINDINGS["f_read_verify_binding"],
            "target_fence_binding": {"T": "NONE", "C": "NONE", "P": "endpoint-p-fence", "M": "endpoint-m-fence"}[role],
            "publication_authority_binding": "endpoint-publication" if role == "P" else "NONE",
            "merge_authority_binding": "endpoint-merge" if role == "M" else "NONE",
            "external_recovery_binding": "NONE",
        }
        credential_values[credential_id] = {
            "format": "autodev.genesis-credential-routing/v1",
            "role": role,
            "member_id": role,
            "production_github_mutation_credentials": "NONE",
        }

    channel_values: dict[str, dict[str, object]] = {}
    for destination in ("C", "P", "M"):
        channel_values[destination] = {
            "channel_id": f"authenticated-t-to-{destination.lower()}",
            "source_role": "T",
            "source_member_id": "T",
            "source_context_resource": "security-T",
            "destination_role": destination,
            "destination_member_id": destination,
            "destination_context_resource": f"security-{destination}",
            "root_context_binding": "root-context-1",
            "runtime_generation_binding": "runtime-generation-1",
            "source_runtime_binding": "runtime-binding-T",
            "destination_runtime_binding": f"runtime-binding-{destination}",
            "authenticated_channel_binding": f"channel-binding-{destination.lower()}",
            "verifier_binding": f"verifier-binding-{destination.lower()}",
        }
    security_values["security-T"]["channels"] = list(channel_values.values())
    for destination, channel in channel_values.items():
        security_values[f"security-{destination}"]["channels"] = [copy.deepcopy(channel)]

    assumption_ids = {
        "ROOT_ACTIVATION_FENCE": ("dep-root-fence", "assumption-root"),
        "EXECUTION_ISOLATION": ("dep-execution-isolation", "assumption-isolation"),
        "FIXTURE_EFFECT_SUBSTRATE": ("dep-fixture-substrate", "assumption-fixture"),
    }
    for _, assumption_id in assumption_ids.values():
        resource_kinds[assumption_id] = "EXTERNAL_TCB_ASSUMPTION_DOCUMENT"
    external_roles: list[dict[str, object]] = []
    fixture_bindings = copy.deepcopy(_FIXTURE_BINDINGS)
    if fixture_binding_change is not None:
        fixture_binding_change(fixture_bindings)
    for role, (dependency_id, assumption_id) in assumption_ids.items():
        assumption: dict[str, object] = {
            "format": "autodev.genesis-external-tcb-assumption/v1",
            "role": role,
            "dependency_id": dependency_id,
        }
        role_record: dict[str, object] = {
            "role": role,
            "dependency_id": dependency_id,
            "assumption_resource": assumption_id,
        }
        if role == "FIXTURE_EFFECT_SUBSTRATE":
            assumption["bindings"] = copy.deepcopy(fixture_bindings)
            role_record["bindings"] = copy.deepcopy(fixture_bindings)
        external_roles.append(role_record)
        raw[assumption_id] = _json_bytes(assumption)

    for config in (
        entry_values, security_values, wiring_values, credential_values,
    ):
        raw.update({resource_id: _json_bytes(value) for resource_id, value in config.items()})
    raw["module-policy"] = _json_bytes({
        "format": "autodev.genesis-module-loading-policy/v1",
        "allowed_candidate_modules": ["autodev_control/role_c.py", "autodev_control/role_m.py",
                                      "autodev_control/role_p.py", "autodev_control/role_t.py"],
        "explicitly_excluded_modules_or_prefixes": _EXCLUSIONS,
        "third_party_runtime_policy": {
            "standard_library_policy": "ALLOW",
            "third_party_module_allowlist": [],
        },
        "dynamic_import_fallback": "NONE",
    })
    lock = {
        "format": "autodev.genesis-dependency-lock/v1",
        "python_runtime": {"identity": "CPython", "version": "3.13.1", "sha256": "a" * 64},
        "build_backend": {"name": "setuptools", "version": "75.0.0", "sha256": "b" * 64},
        "build_tools": [{"name": "wheel", "version": "0.45.0", "sha256": "c" * 64}],
        "runtime_dependencies": [],
        "locked_resources": [
            {"role": role, "resource_id": resource_id, "sha256": _sha(raw[resource_id])}
            for role, resource_id in (
                ("IMPLEMENTATION", "implementation"),
                ("BUILD_DEFINITION", "build"),
                ("RUNTIME_ARTIFACT", "runtime"),
            )
        ],
    }
    raw["lock"] = _json_bytes(lock)

    graph: dict[str, object] = {
        "format": "autodev.genesis-resource-graph/v1",
        "genesis_scope": "fixture-only",
        "implementation_resource": "implementation",
        "build_definition_resource": "build",
        "dependency_lock_resource": "lock",
        "runtime_artifact_resource": "runtime",
        "module_loading_policy_resource": "module-policy",
        "core_policy_resource": "core",
        "genesis_conformance_resource": "conformance",
        "members": members,
        "policy_resources": ["conformance"],
        "trusted_schema_resources": ["schema"] if include_schema else [],
        "trusted_config_bindings": [{
            "config_id": GENESIS_RESOURCE_GRAPH_CONFIG_ID,
            "resource_id": "graph",
            "purpose": "GENESIS_RESOURCE_GRAPH",
            "expected_format": "autodev.genesis-resource-graph/v1",
            "schema_resource": "schema" if include_schema else None,
            "grammar_id": None if include_schema else "autodev.genesis-resource-graph/v1",
        }],
        "external_tcb_roles": external_roles,
    }
    if graph_change is not None:
        graph_change(graph)
    if resource_change is not None:
        resource_change({
            **entry_values,
            **security_values,
            **wiring_values,
            **credential_values,
        })
    for config in (entry_values, security_values, wiring_values, credential_values):
        raw.update({resource_id: _json_bytes(value) for resource_id, value in config.items()})
    raw["graph"] = _json_bytes(graph)
    resource_kinds["graph"] = "TRUSTED_CONFIG"

    manifest: dict[str, object] = {
        "format": "autodev.trusted-manifest/v1",
        "kind": "genesis",
        "predecessor_manifest": None,
        "root_managed_resources": [
            {"resource_id": resource_id, "kind": kind, "sha256": _sha(raw[resource_id])}
            for resource_id, kind in resource_kinds.items()
        ],
        "core_policy": "core",
        "policy_resources": ["conformance"],
        "trusted_core_members": [
            {
                "member_id": role,
                "implementation_resource": "implementation",
                "runtime_artifact_resource": "runtime",
                "entry_point_config_resource": f"entry-{role}",
            }
            for role in ("T", "C", "P", "M")
        ],
        "trusted_schemas": ["schema"] if include_schema else [],
        "trusted_configs": [{"config_id": GENESIS_RESOURCE_GRAPH_CONFIG_ID, "resource": "graph"}],
        "external_tcb_dependencies": [
            {"dependency_id": dep, "assumption_resource": assumption}
            for dep, assumption in assumption_ids.values()
        ],
    }
    if manifest_change is not None:
        manifest_change(manifest)
    parsed = load_candidate_trusted_manifest(_json_bytes(manifest))
    assert type(parsed) is CandidateTrustedManifest
    return parsed, raw, graph


def _failure(
    fixture: tuple[CandidateTrustedManifest, dict[str, bytes], dict[str, object]],
    code: GenesisResourceGraphFailureCode,
) -> None:
    manifest, raw, _ = fixture
    result = validate_genesis_resource_graph(manifest, raw)
    assert type(result) is GenesisResourceGraphFailure
    assert result.code is code


def _rebind_raw_resource(
    manifest: CandidateTrustedManifest,
    raw: dict[str, bytes],
    resource_id: str,
    replacement: bytes,
) -> CandidateTrustedManifest:
    raw[resource_id] = replacement
    document = json.loads(manifest.source_document.raw_bytes)
    next(item for item in document["root_managed_resources"]
         if item["resource_id"] == resource_id)["sha256"] = _sha(replacement)
    result = load_candidate_trusted_manifest(_json_bytes(document))
    assert type(result) is CandidateTrustedManifest
    return result


def test_manifest_v1_parse_alone_is_not_genesis_acceptance() -> None:
    manifest, raw, _ = _fixture()
    assert type(manifest) is CandidateTrustedManifest
    assert not isinstance(manifest, ValidatedGenesisResourceGraph)
    assert validate_genesis_resource_graph(manifest, {}) is not None
    assert isinstance(validate_genesis_resource_graph(manifest, raw), ValidatedGenesisResourceGraph)


def test_exact_synthetic_graph_with_all_resource_contents_is_accepted_and_non_bearer() -> None:
    manifest, raw, _ = _fixture(include_schema=True)
    result = validate_genesis_resource_graph(manifest, raw)
    assert type(result) is ValidatedGenesisResourceGraph
    assert result.manifest_id == manifest.manifest_id
    assert result.policy_epoch_identity == manifest.policy_epoch_identity
    assert result.graph_resource.resource_id.value == "graph"
    assert result.graph_sha256.value == _sha(raw["graph"])
    assert {item.value for item in result.consumed_resource_ids} == {
        item.resource_id.value for item in manifest.root_managed_resources
    }
    assert not hasattr(result, "activate")
    assert not hasattr(result, "authorize_protected_operation")
    with pytest.raises(FrozenInstanceError):
        result.manifest_id = manifest.manifest_id
    with pytest.raises(TypeError):
        ValidatedGenesisResourceGraph()


def test_missing_reserved_graph_binding_fails_closed() -> None:
    _failure(_fixture(manifest_change=lambda manifest: manifest.update(trusted_configs=[])),
             GenesisResourceGraphFailureCode.GRAPH_CONFIG_MISSING)


def test_duplicate_reserved_graph_binding_is_rejected_by_manifest_boundary() -> None:
    manifest, raw, _ = _fixture()
    # The canonical G2 loader rejects duplicate semantic config identities before R4.
    document = json.loads(manifest.source_document.raw_bytes)
    document["trusted_configs"].append(document["trusted_configs"][0])
    parsed = load_candidate_trusted_manifest(_json_bytes(document))
    assert type(parsed) is ManifestFailure
    assert parsed.code is ManifestFailureCode.DUPLICATE_IDENTITY
    assert validate_genesis_resource_graph(manifest, raw) is not None


def test_wrong_reserved_graph_resource_kind_is_rejected_by_manifest_boundary() -> None:
    manifest, _, _ = _fixture()
    document = json.loads(manifest.source_document.raw_bytes)
    graph_ref = next(item for item in document["root_managed_resources"] if item["resource_id"] == "graph")
    graph_ref["kind"] = "MODULE_LOADING_POLICY"
    parsed = load_candidate_trusted_manifest(_json_bytes(document))
    assert type(parsed) is ManifestFailure
    assert parsed.code is ManifestFailureCode.RESOURCE_KIND_MISMATCH


def test_graph_digest_mismatch_is_rejected() -> None:
    manifest, raw, _ = _fixture()
    raw["graph"] += b" "
    _failure((manifest, raw, {}), GenesisResourceGraphFailureCode.GRAPH_RESOURCE_DIGEST_MISMATCH)


@pytest.mark.parametrize("change", [
    lambda graph: graph.update(unrecognized=True),
    lambda graph: graph.update(format="wrong"),
    lambda graph: graph.update(genesis_scope="production"),
])
def test_malformed_or_unknown_field_graph_is_rejected(change: Callable[[dict[str, object]], None]) -> None:
    _failure(_fixture(graph_change=change), GenesisResourceGraphFailureCode.GRAPH_FORMAT_INVALID)


def test_malformed_graph_json_is_rejected_with_structured_parse_failure() -> None:
    manifest, raw, _ = _fixture()
    reparsed = _rebind_raw_resource(manifest, raw, "graph", b"{")
    _failure((reparsed, raw, {}), GenesisResourceGraphFailureCode.GRAPH_PARSE_FAILED)


@pytest.mark.parametrize("members", [
    lambda rows: rows[:-1],
    lambda rows: rows + [copy.deepcopy(rows[0]) | {"role": "X", "member_id": "X"}],
])
def test_missing_or_extra_graph_member_is_rejected(members: Callable[[list[dict[str, str]]], list[dict[str, str]]]) -> None:
    _failure(_fixture(graph_change=lambda graph: graph.update(members=members(graph["members"]))),
             GenesisResourceGraphFailureCode.GRAPH_MEMBER_SET_MISMATCH)


def test_cross_role_graph_member_binding_is_rejected() -> None:
    def change(graph: dict[str, object]) -> None:
        graph["members"][1]["member_id"] = "T"
    _failure(_fixture(graph_change=change), GenesisResourceGraphFailureCode.GRAPH_MEMBER_BINDING_MISMATCH)


@pytest.mark.parametrize("field,extra_id,kind", [
    ("implementation_resource", "implementation-2", "TRUSTED_CODE"),
    ("runtime_artifact_resource", "runtime-2", "RUNTIME_ARTIFACT"),
])
def test_non_shared_implementation_or_runtime_is_rejected(
    field: str, extra_id: str, kind: str,
) -> None:
    def graph_change(graph: dict[str, object]) -> None:
        graph["members"][1][field] = extra_id
        if field == "implementation_resource":
            graph["implementation_resource"] = extra_id
        else:
            graph["runtime_artifact_resource"] = extra_id

    def manifest_change(manifest: dict[str, object]) -> None:
        manifest["trusted_core_members"][1][field] = extra_id

    _failure(_fixture(graph_change=graph_change, manifest_change=manifest_change,
                      extra_resources=((extra_id, kind, b"second artifact"),)),
             GenesisResourceGraphFailureCode.GRAPH_SHARED_RESOURCE_MISMATCH)


def test_entry_point_content_mismatch_is_rejected() -> None:
    def change(configs: dict[str, dict[str, object]]) -> None:
        configs["entry-T"]["role"] = "C"
    _failure(_fixture(resource_change=change), GenesisResourceGraphFailureCode.GRAPH_ENTRY_POINT_MISMATCH)


def test_security_context_content_mismatch_is_rejected() -> None:
    def change(configs: dict[str, dict[str, object]]) -> None:
        configs["security-P"]["service_principal"] = "service-M"
    _failure(_fixture(resource_change=change), GenesisResourceGraphFailureCode.GRAPH_SECURITY_CONTEXT_MISMATCH)


@pytest.mark.parametrize("role,field,value", [
    ("P", "merge_authority_binding", "endpoint-merge"),
    ("M", "publication_authority_binding", "endpoint-publication"),
    ("C", "publication_authority_binding", "endpoint-publication"),
    ("C", "merge_authority_binding", "endpoint-merge"),
    ("T", "target_fence_binding", "endpoint-p-fence"),
    ("T", "publication_authority_binding", "endpoint-publication"),
    ("T", "merge_authority_binding", "endpoint-merge"),
    ("T", "external_recovery_binding", "endpoint-external-recovery"),
    ("C", "external_recovery_binding", "endpoint-external-recovery"),
    ("P", "external_recovery_binding", "endpoint-external-recovery"),
    ("M", "external_recovery_binding", "endpoint-external-recovery"),
])
def test_role_authority_cross_wiring_and_member_recovery_are_rejected(
    role: str, field: str, value: str,
) -> None:
    def change(configs: dict[str, dict[str, object]]) -> None:
        configs[f"wiring-{role}"][field] = value
    _failure(_fixture(resource_change=change),
             GenesisResourceGraphFailureCode.GRAPH_CAPABILITY_WIRING_MISMATCH)


def test_explicit_non_none_production_credential_route_is_rejected() -> None:
    def change(configs: dict[str, dict[str, object]]) -> None:
        configs["credential-C"]["production_github_mutation_credentials"] = "credential-prod"
    _failure(_fixture(resource_change=change),
             GenesisResourceGraphFailureCode.GRAPH_CREDENTIAL_ROUTING_MISMATCH)


def test_module_loading_policy_mismatch_is_rejected() -> None:
    manifest, raw, _ = _fixture()
    replacement = _json_bytes({
        "format": "autodev.genesis-module-loading-policy/v1",
        "allowed_candidate_modules": ["tests/fallback.py"],
        "explicitly_excluded_modules_or_prefixes": _EXCLUSIONS,
        "third_party_runtime_policy": {"standard_library_policy": "ALLOW", "third_party_module_allowlist": []},
        "dynamic_import_fallback": "NONE",
    })
    parsed = _rebind_raw_resource(manifest, raw, "module-policy", replacement)
    _failure((parsed, raw, {}), GenesisResourceGraphFailureCode.GRAPH_MODULE_LOADING_MISMATCH)


def test_module_loading_policy_rejects_dynamic_import_fallback() -> None:
    manifest, raw, _ = _fixture()
    replacement = _json_bytes({
        "format": "autodev.genesis-module-loading-policy/v1",
        "allowed_candidate_modules": ["autodev_control/role_t.py"],
        "explicitly_excluded_modules_or_prefixes": _EXCLUSIONS,
        "third_party_runtime_policy": {"standard_library_policy": "ALLOW", "third_party_module_allowlist": []},
        "dynamic_import_fallback": "ALLOW_ANY",
    })
    parsed = _rebind_raw_resource(manifest, raw, "module-policy", replacement)
    _failure((parsed, raw, {}), GenesisResourceGraphFailureCode.GRAPH_MODULE_LOADING_MISMATCH)


@pytest.mark.parametrize("mutate_lock", [
    lambda lock: lock["build_backend"].update(version="setuptools>=75"),
    lambda lock: lock["locked_resources"][0].update(sha256="f" * 64),
    lambda lock: lock["locked_resources"].pop(),
])
def test_dependency_lock_requires_exact_versions_and_complete_hash_bindings(
    mutate_lock: Callable[[dict[str, object]], None],
) -> None:
    manifest, raw, _ = _fixture()
    lock = json.loads(raw["lock"])
    mutate_lock(lock)
    parsed = _rebind_raw_resource(manifest, raw, "lock", _json_bytes(lock))
    _failure((parsed, raw, {}), GenesisResourceGraphFailureCode.GRAPH_FORMAT_INVALID)


def test_exact_policy_and_schema_raw_bytes_are_digest_checked() -> None:
    manifest, raw, _ = _fixture(include_schema=True)
    raw["conformance"] += b" changed"
    _failure((manifest, raw, {}), GenesisResourceGraphFailureCode.GRAPH_RESOURCE_DIGEST_MISMATCH)
    manifest, raw, _ = _fixture(include_schema=True)
    raw["schema"] += b" changed"
    _failure((manifest, raw, {}), GenesisResourceGraphFailureCode.GRAPH_RESOURCE_DIGEST_MISMATCH)


def test_aggregate_resource_bytes_are_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    manifest, raw, _ = _fixture()
    monkeypatch.setattr(graph_module, "_MAX_TOTAL_RESOURCE_BYTES", 1)
    _failure((manifest, raw, {}), GenesisResourceGraphFailureCode.GRAPH_PARSE_FAILED)


@pytest.mark.parametrize("field,code", [
    ("build_definition_resource", GenesisResourceGraphFailureCode.GRAPH_BUILD_ROLE_MISSING),
    ("dependency_lock_resource", GenesisResourceGraphFailureCode.GRAPH_LOCK_ROLE_MISSING),
])
def test_missing_build_definition_or_lock_role_is_rejected(field: str, code: GenesisResourceGraphFailureCode) -> None:
    _failure(_fixture(graph_change=lambda graph: graph.pop(field)), code)


def test_policy_set_mismatch_is_rejected() -> None:
    _failure(_fixture(graph_change=lambda graph: graph.update(policy_resources=[])),
             GenesisResourceGraphFailureCode.GRAPH_POLICY_SET_MISMATCH)


def test_trusted_schema_set_mismatch_is_rejected() -> None:
    _failure(_fixture(include_schema=True, graph_change=lambda graph: graph.update(trusted_schema_resources=[])),
             GenesisResourceGraphFailureCode.GRAPH_SCHEMA_SET_MISMATCH)


def test_trusted_config_binding_set_mismatch_is_rejected() -> None:
    _failure(_fixture(graph_change=lambda graph: graph.update(trusted_config_bindings=[])),
             GenesisResourceGraphFailureCode.GRAPH_CONFIG_SET_MISMATCH)


def test_external_tcb_role_dependency_mismatch_is_rejected() -> None:
    def change(graph: dict[str, object]) -> None:
        graph["external_tcb_roles"][0]["dependency_id"] = "not-the-manifest-dependency"
    _failure(_fixture(graph_change=change), GenesisResourceGraphFailureCode.GRAPH_EXTERNAL_TCB_MISMATCH)


def test_orphan_root_managed_resource_is_rejected() -> None:
    _failure(_fixture(extra_resources=(("orphan", "TRUSTED_CODE", b"unused"),)),
             GenesisResourceGraphFailureCode.GRAPH_UNKNOWN_ORPHAN_RESOURCE)


def test_wrong_module_policy_resource_kind_is_rejected() -> None:
    _failure(_fixture(graph_change=lambda graph: graph.update(module_loading_policy_resource="graph")),
             GenesisResourceGraphFailureCode.GRAPH_RESOURCE_KIND_MISMATCH)


@pytest.mark.parametrize("role,access", [("C", "READ"), ("T", "READ_WRITE"), ("P", "READ_WRITE"), ("M", "READ_WRITE")])
def test_canonical_access_domain_is_exact(role: str, access: str) -> None:
    def change(configs: dict[str, dict[str, object]]) -> None:
        configs[f"wiring-{role}"]["canonical_state_access"] = access
    _failure(_fixture(resource_change=change), GenesisResourceGraphFailureCode.GRAPH_CAPABILITY_WIRING_MISMATCH)


@pytest.mark.parametrize("role,value", [
    ("T", "endpoint-canonical-start-read"),
    ("C", "endpoint-canonical-start-read"),
    ("P", "endpoint-p-fence"),
    ("M", "endpoint-m-fence"),
])
def test_canonical_endpoint_roles_and_p_m_identity_are_exact(role: str, value: str) -> None:
    def change(configs: dict[str, dict[str, object]]) -> None:
        configs[f"wiring-{role}"]["canonical_state_binding"] = value
    _failure(_fixture(resource_change=change), GenesisResourceGraphFailureCode.GRAPH_CAPABILITY_WIRING_MISMATCH)


@pytest.mark.parametrize("role", ["T", "C", "P", "M"])
def test_every_member_requires_exact_read_only_f_binding(role: str) -> None:
    def change(configs: dict[str, dict[str, object]]) -> None:
        configs[f"wiring-{role}"]["f_read_verify_binding"] = "NONE"
    _failure(_fixture(resource_change=change), GenesisResourceGraphFailureCode.GRAPH_CAPABILITY_WIRING_MISMATCH)


@pytest.mark.parametrize("role", ["T", "C", "P", "M"])
def test_mutation_endpoint_cannot_replace_f_read_verify(role: str) -> None:
    def change(configs: dict[str, dict[str, object]]) -> None:
        configs[f"wiring-{role}"]["f_read_verify_binding"] = "endpoint-publication"
    _failure(_fixture(resource_change=change), GenesisResourceGraphFailureCode.GRAPH_CAPABILITY_WIRING_MISMATCH)


@pytest.mark.parametrize("role", ["P", "M"])
def test_target_fence_binding_is_required_and_role_scoped(role: str) -> None:
    def change(configs: dict[str, dict[str, object]]) -> None:
        configs[f"wiring-{role}"]["target_fence_binding"] = "NONE" if role == "P" else "endpoint-p-fence"
    _failure(_fixture(resource_change=change), GenesisResourceGraphFailureCode.GRAPH_CAPABILITY_WIRING_MISMATCH)


@pytest.mark.parametrize("role,wrong_fence", [
    ("P", "endpoint-m-fence"),
    ("M", "endpoint-p-fence"),
])
def test_target_fences_cannot_be_crossed_between_p_and_m(role: str, wrong_fence: str) -> None:
    def change(configs: dict[str, dict[str, object]]) -> None:
        configs[f"wiring-{role}"]["target_fence_binding"] = wrong_fence
    _failure(_fixture(resource_change=change), GenesisResourceGraphFailureCode.GRAPH_CAPABILITY_WIRING_MISMATCH)


def test_fixture_f_endpoint_must_be_explicitly_read_only() -> None:
    _failure(_fixture(fixture_binding_change=lambda bindings: bindings.update(f_read_verify_mode="READ_WRITE")),
             GenesisResourceGraphFailureCode.GRAPH_EXTERNAL_TCB_MISMATCH)


@pytest.mark.parametrize("destination", ["C", "P", "M"])
@pytest.mark.parametrize("alter", ["missing", "mismatched"])
def test_authenticated_t_to_member_channel_is_required_and_cross_checked(destination: str, alter: str) -> None:
    def change(configs: dict[str, dict[str, object]]) -> None:
        channels = configs["security-T"]["channels"]
        if alter == "missing":
            configs["security-T"]["channels"] = [item for item in channels if item["destination_role"] != destination]
        else:
            configs[f"security-{destination}"]["channels"][0]["verifier_binding"] = "wrong-verifier"
    _failure(_fixture(resource_change=change), GenesisResourceGraphFailureCode.GRAPH_SECURITY_CONTEXT_MISMATCH)


def test_authenticated_channel_identity_cannot_use_absence_sentinel() -> None:
    def change(configs: dict[str, dict[str, object]]) -> None:
        configs["security-T"]["channels"][0]["channel_id"] = "NONE"
        configs["security-C"]["channels"][0]["channel_id"] = "NONE"
    _failure(_fixture(resource_change=change), GenesisResourceGraphFailureCode.GRAPH_SECURITY_CONTEXT_MISMATCH)


def test_graph_and_structured_resource_identity_disagreement_fails_closed() -> None:
    def change(configs: dict[str, dict[str, object]]) -> None:
        configs["entry-M"]["runtime_artifact_resource"] = "implementation"
    _failure(_fixture(resource_change=change), GenesisResourceGraphFailureCode.GRAPH_ENTRY_POINT_MISMATCH)


def test_external_fixture_substrate_must_distinguish_exact_endpoints() -> None:
    def graph_change(graph: dict[str, object]) -> None:
        fixture_role = next(item for item in graph["external_tcb_roles"] if item["role"] == "FIXTURE_EFFECT_SUBSTRATE")
        fixture_role["bindings"]["m_target_fence_binding"] = "endpoint-p-fence"
    _failure(_fixture(graph_change=graph_change), GenesisResourceGraphFailureCode.GRAPH_EXTERNAL_TCB_MISMATCH)


def test_missing_required_raw_resource_is_structured_failure() -> None:
    manifest, raw, _ = _fixture()
    raw.pop("security-C")
    _failure((manifest, raw, {}), GenesisResourceGraphFailureCode.GRAPH_RESOURCE_MISSING)


def test_unknown_raw_resource_input_is_rejected() -> None:
    manifest, raw, _ = _fixture()
    raw["not-in-manifest"] = b"untrusted"
    _failure((manifest, raw, {}), GenesisResourceGraphFailureCode.GRAPH_UNKNOWN_ORPHAN_RESOURCE)


def test_result_is_exactly_bound_to_verified_resource_references() -> None:
    manifest, raw, _ = _fixture()
    result = validate_genesis_resource_graph(manifest, raw)
    assert type(result) is ValidatedGenesisResourceGraph
    verified_ids = {item.resource_id.value for item in result.verified_resource_refs}
    assert {
        "graph", "module-policy", "lock", "conformance", "entry-T", "security-C",
        "wiring-P", "credential-M", "assumption-fixture",
    }.issubset(verified_ids)
