import copy
import hashlib
import json

import pytest

from autodev_control.trusted.errors import ManifestFailure, ManifestFailureCode, ParseFailureCode, ResourceFailureCode
from autodev_control.trusted.manifest import (
    CandidateTrustedManifest,
    ExternalTcbDependency,
    ManifestKind,
    TrustedConfigBinding,
    TrustedCoreMember,
    load_candidate_trusted_manifest,
)
from autodev_control.trusted.resources import (
    G2_MANIFEST_MAX_BYTES,
    RootManagedResourceId,
    RootManagedResourceKind,
)


def resource(resource_id: str, kind: str, digest: str = "a" * 64) -> dict[str, object]:
    return {"resource_id": resource_id, "kind": kind, "sha256": digest}


def valid_manifest() -> dict[str, object]:
    return {
        "format": "autodev.trusted-manifest/v1",
        "kind": "genesis",
        "predecessor_manifest": None,
        "root_managed_resources": [
            resource("core", "CORE_POLICY"),
            resource("code", "TRUSTED_CODE"),
            resource("runtime", "RUNTIME_ARTIFACT"),
            resource("entry", "ENTRY_POINT_CONFIG"),
            resource("policy", "POLICY"),
            resource("schema", "TRUSTED_SCHEMA"),
            resource("config", "TRUSTED_CONFIG"),
            resource("assumption", "EXTERNAL_TCB_ASSUMPTION_DOCUMENT"),
            resource("lock", "DEPENDENCY_LOCK"),
        ],
        "core_policy": "core",
        "policy_resources": ["policy"],
        "trusted_core_members": [{
            "member_id": "member",
            "implementation_resource": "code",
            "runtime_artifact_resource": "runtime",
            "entry_point_config_resource": "entry",
        }],
        "trusted_schemas": ["schema"],
        "trusted_configs": [{"config_id": "config-id", "resource": "config"}],
        "external_tcb_dependencies": [{"dependency_id": "external", "assumption_resource": "assumption"}],
    }


def encode(value: object, *, pretty: bool = False, sort_keys: bool = False) -> bytes:
    if pretty:
        return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=sort_keys).encode()
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=sort_keys).encode()


def load(value: object) -> CandidateTrustedManifest | ManifestFailure:
    return load_candidate_trusted_manifest(encode(value))


def assert_failure(value: object, code: ManifestFailureCode) -> ManifestFailure:
    result = load(value)
    assert type(result) is ManifestFailure
    assert result.code is code
    return result


def test_valid_candidate_identity_bindings_and_optional_empty_collections() -> None:
    value = valid_manifest()
    value["policy_resources"] = []
    value["trusted_schemas"] = []
    value["trusted_configs"] = []
    value["external_tcb_dependencies"] = []
    raw = encode(value)
    first = load_candidate_trusted_manifest(raw)
    second = load_candidate_trusted_manifest(raw)
    assert isinstance(first, CandidateTrustedManifest)
    assert first.manifest_id == second.manifest_id
    assert first.manifest_id.raw_sha256 == first.source_document.raw_sha256
    assert first.manifest_id.raw_sha256.value == hashlib.sha256(raw).hexdigest()
    assert first.policy_epoch_identity.manifest_id == first.manifest_id
    assert first.kind is ManifestKind.GENESIS
    assert first.root_managed_resources[-1].kind is RootManagedResourceKind.DEPENDENCY_LOCK


def test_candidate_success_has_no_public_constructor_and_is_deeply_immutable() -> None:
    with pytest.raises(TypeError):
        CandidateTrustedManifest()
    with pytest.raises(TypeError):
        CandidateTrustedManifest._from_validated(object())
    candidate = load(valid_manifest())
    assert isinstance(candidate, CandidateTrustedManifest)
    with pytest.raises(AttributeError):
        candidate.kind = ManifestKind.SUCCESSOR
    with pytest.raises(AttributeError):
        candidate.root_managed_resources.append(object())
    with pytest.raises(AttributeError):
        candidate.trusted_core_members[0].member_id = object()
    with pytest.raises(TypeError):
        candidate.policy_resources[0] = RootManagedResourceId("changed")
    with pytest.raises(AttributeError):
        candidate.trusted_schemas.append(RootManagedResourceId("changed"))
    with pytest.raises(TypeError):
        candidate.trusted_configs[0] = object()
    with pytest.raises(AttributeError):
        candidate.external_tcb_dependencies.append(object())
    with pytest.raises(AttributeError):
        candidate.trusted_configs[0].resource = RootManagedResourceId("changed")
    with pytest.raises(AttributeError):
        candidate.external_tcb_dependencies[0].assumption_resource = RootManagedResourceId("changed")
    assert isinstance(candidate.trusted_core_members[0], TrustedCoreMember)
    assert isinstance(candidate.trusted_configs[0], TrustedConfigBinding)
    assert isinstance(candidate.external_tcb_dependencies[0], ExternalTcbDependency)
    mutable = list(candidate.root_managed_resources)
    mutable.clear()
    assert candidate.root_managed_resources
    assert candidate.manifest_id.raw_sha256.value == hashlib.sha256(candidate.source_document.raw_bytes).hexdigest()


def test_manifest_byte_and_parse_precedence() -> None:
    assert load_candidate_trusted_manifest("not bytes").code is ManifestFailureCode.INVALID_INPUT_TYPE
    oversized = b"{" + b" " * G2_MANIFEST_MAX_BYTES
    assert len(oversized) == G2_MANIFEST_MAX_BYTES + 1
    assert load_candidate_trusted_manifest(oversized).code is ManifestFailureCode.BYTE_LIMIT_EXCEEDED
    valid = encode(valid_manifest())
    exact = valid + b" " * (G2_MANIFEST_MAX_BYTES - len(valid))
    assert len(exact) == G2_MANIFEST_MAX_BYTES
    assert isinstance(load_candidate_trusted_manifest(exact), CandidateTrustedManifest)
    parsed_failure = load_candidate_trusted_manifest(b"{")
    assert parsed_failure.code is ManifestFailureCode.PARSE_FAILED
    assert type(parsed_failure.parse_failure.code) is ParseFailureCode
    assert load_candidate_trusted_manifest(b"[]").code is ManifestFailureCode.INVALID_TOP_LEVEL


def test_raw_identity_uses_exact_valid_bytes_without_normalization() -> None:
    value = valid_manifest()
    compact = load_candidate_trusted_manifest(encode(value))
    pretty = load_candidate_trusted_manifest(encode(value, pretty=True))
    reordered = load_candidate_trusted_manifest(encode(value, sort_keys=True))
    unicode_value = valid_manifest()
    unicode_value["trusted_core_members"][0]["member_id"] = "é"
    literal = encode(unicode_value)
    escaped = json.dumps(unicode_value, ensure_ascii=True, separators=(",", ":")).encode()
    literal_candidate = load_candidate_trusted_manifest(literal)
    escaped_candidate = load_candidate_trusted_manifest(escaped)
    for candidate in (compact, pretty, reordered, literal_candidate, escaped_candidate):
        assert isinstance(candidate, CandidateTrustedManifest)
    assert compact.manifest_id != pretty.manifest_id
    assert compact.manifest_id != reordered.manifest_id
    assert literal_candidate.trusted_core_members == escaped_candidate.trusted_core_members
    assert literal_candidate.manifest_id != escaped_candidate.manifest_id


@pytest.mark.parametrize("field", ["manifest_id", "active", "is_active", "activation_state"])
def test_candidate_cannot_self_declare_identity_or_activation(field: str) -> None:
    value = valid_manifest()
    value[field] = True
    assert_failure(value, ManifestFailureCode.UNKNOWN_FIELD)


def test_format_kind_and_predecessor_rules() -> None:
    value = valid_manifest()
    value["format"] = "autodev.trusted-manifest/v2"
    assert_failure(value, ManifestFailureCode.INVALID_FIELD_VALUE)
    value = valid_manifest()
    value["predecessor_manifest"] = "a" * 64
    assert_failure(value, ManifestFailureCode.INVALID_PREDECESSOR)
    value = valid_manifest()
    value["kind"] = "successor"
    assert_failure(value, ManifestFailureCode.INVALID_PREDECESSOR)
    value["predecessor_manifest"] = "not-a-digest"
    assert_failure(value, ManifestFailureCode.INVALID_PREDECESSOR)
    value["predecessor_manifest"] = "b" * 64
    successor = load(value)
    assert isinstance(successor, CandidateTrustedManifest)
    assert successor.predecessor_manifest.raw_sha256.value == "b" * 64


def test_required_set_and_core_policy_lexical_precedence() -> None:
    value = valid_manifest()
    value["core_policy"] = ""
    value["root_managed_resources"] = []
    assert_failure(value, ManifestFailureCode.INVALID_FIELD_VALUE)
    value["core_policy"] = "core"
    assert_failure(value, ManifestFailureCode.EMPTY_REQUIRED_SET)
    value = valid_manifest()
    value["trusted_core_members"] = []
    assert_failure(value, ManifestFailureCode.EMPTY_REQUIRED_SET)
    value["root_managed_resources"] = []
    assert_failure(value, ManifestFailureCode.EMPTY_REQUIRED_SET)


def test_resource_registry_core_policy_and_closure_rules() -> None:
    value = valid_manifest()
    assert isinstance(load(value), CandidateTrustedManifest)
    value = valid_manifest()
    value["root_managed_resources"].append(resource("duplicate-digest", "BUILD_DEFINITION"))
    assert isinstance(load(value), CandidateTrustedManifest)
    value = valid_manifest()
    value["root_managed_resources"].append(copy.deepcopy(value["root_managed_resources"][0]))
    assert_failure(value, ManifestFailureCode.DUPLICATE_IDENTITY)
    value = valid_manifest()
    value["root_managed_resources"][0]["sha256"] = "bad"
    assert_failure(value, ManifestFailureCode.INVALID_FIELD_VALUE)
    value = valid_manifest()
    value["root_managed_resources"][0]["kind"] = "UNKNOWN"
    assert_failure(value, ManifestFailureCode.INVALID_FIELD_VALUE)
    value = valid_manifest()
    value["root_managed_resources"][0]["kind"] = "POLICY"
    assert_failure(value, ManifestFailureCode.INVALID_FIELD_VALUE)
    value = valid_manifest()
    value["root_managed_resources"].append(resource("core2", "CORE_POLICY"))
    assert_failure(value, ManifestFailureCode.INVALID_FIELD_VALUE)
    value = valid_manifest()
    value["core_policy"] = "missing"
    assert_failure(value, ManifestFailureCode.UNKNOWN_RESOURCE_REFERENCE)
    value = valid_manifest()
    value["core_policy"] = "policy"
    assert_failure(value, ManifestFailureCode.RESOURCE_KIND_MISMATCH)


def test_policy_member_schema_config_and_external_bindings() -> None:
    value = valid_manifest()
    value["policy_resources"].append("policy")
    assert_failure(value, ManifestFailureCode.DUPLICATE_IDENTITY)
    value = valid_manifest()
    value["policy_resources"] = [""]
    assert_failure(value, ManifestFailureCode.INVALID_FIELD_VALUE)
    value = valid_manifest()
    value["policy_resources"] = ["missing"]
    assert_failure(value, ManifestFailureCode.UNKNOWN_RESOURCE_REFERENCE)
    value = valid_manifest()
    value["policy_resources"] = ["schema"]
    assert_failure(value, ManifestFailureCode.RESOURCE_KIND_MISMATCH)
    value = valid_manifest()
    value["policy_resources"] = ["core"]
    assert_failure(value, ManifestFailureCode.INVALID_FIELD_VALUE)

    for field, wrong in (
        ("implementation_resource", "runtime"),
        ("runtime_artifact_resource", "code"),
        ("entry_point_config_resource", "code"),
    ):
        value = valid_manifest()
        value["trusted_core_members"][0][field] = wrong
        assert_failure(value, ManifestFailureCode.RESOURCE_KIND_MISMATCH)
    value = valid_manifest()
    second = copy.deepcopy(value["trusted_core_members"][0])
    second["member_id"] = "second"
    value["trusted_core_members"].append(second)
    assert isinstance(load(value), CandidateTrustedManifest)
    value["trusted_core_members"][1]["member_id"] = "member"
    assert_failure(value, ManifestFailureCode.DUPLICATE_IDENTITY)

    collection_cases = (
        ("trusted_schemas", "schema", "code"),
        ("trusted_configs", {"config_id": "config-id", "resource": "config"}, {"config_id": "config-id", "resource": "code"}),
        ("external_tcb_dependencies", {"dependency_id": "external", "assumption_resource": "assumption"}, {"dependency_id": "external", "assumption_resource": "code"}),
    )
    for field, duplicate, wrong in collection_cases:
        value = valid_manifest()
        if field == "trusted_schemas":
            value[field].append(duplicate)
        else:
            value[field].append(copy.deepcopy(duplicate))
        assert_failure(value, ManifestFailureCode.DUPLICATE_IDENTITY)
        value = valid_manifest()
        value[field] = [wrong]
        assert_failure(value, ManifestFailureCode.RESOURCE_KIND_MISMATCH)


def test_local_reference_validation_for_every_role() -> None:
    mutations = (
        ("trusted_core_members", "implementation_resource"),
        ("trusted_core_members", "runtime_artifact_resource"),
        ("trusted_core_members", "entry_point_config_resource"),
        ("trusted_configs", "resource"),
        ("external_tcb_dependencies", "assumption_resource"),
    )
    for collection, field in mutations:
        value = valid_manifest()
        value[collection][0][field] = ""
        assert_failure(value, ManifestFailureCode.INVALID_FIELD_VALUE)
    value = valid_manifest()
    value["trusted_schemas"] = [""]
    assert_failure(value, ManifestFailureCode.INVALID_FIELD_VALUE)


@pytest.mark.parametrize(
    "collection, field",
    [
        ("trusted_core_members", "implementation_resource"),
        ("trusted_core_members", "runtime_artifact_resource"),
        ("trusted_core_members", "entry_point_config_resource"),
        ("trusted_configs", "resource"),
        ("external_tcb_dependencies", "assumption_resource"),
    ],
)
def test_each_record_reference_must_resolve(collection: str, field: str) -> None:
    value = valid_manifest()
    value[collection][0][field] = "missing"
    assert_failure(value, ManifestFailureCode.UNKNOWN_RESOURCE_REFERENCE)


def test_schema_reference_must_resolve() -> None:
    value = valid_manifest()
    value["trusted_schemas"] = ["missing"]
    assert_failure(value, ManifestFailureCode.UNKNOWN_RESOURCE_REFERENCE)


def test_config_binding_is_scoped_by_exact_manifest_identity() -> None:
    first_value = valid_manifest()
    second_value = valid_manifest()
    second_value["root_managed_resources"][6]["sha256"] = "b" * 64
    first = load(first_value)
    second = load(second_value)
    assert isinstance(first, CandidateTrustedManifest)
    assert isinstance(second, CandidateTrustedManifest)
    assert first.trusted_configs[0].config_id == second.trusted_configs[0].config_id
    assert first.trusted_configs[0].resource == RootManagedResourceId("config")
    assert first.manifest_id != second.manifest_id


def test_nested_and_top_level_field_precedence() -> None:
    value = valid_manifest()
    del value["format"]
    value["unknown"] = True
    assert_failure(value, ManifestFailureCode.MISSING_FIELD)
    value = valid_manifest()
    value["unknown"] = True
    value["format"] = 1
    assert_failure(value, ManifestFailureCode.UNKNOWN_FIELD)
    value = valid_manifest()
    value["format"] = 1
    value["kind"] = "wrong"
    assert_failure(value, ManifestFailureCode.INVALID_FIELD_TYPE)
    value = valid_manifest()
    entry = value["root_managed_resources"][0]
    del entry["resource_id"]
    entry["unknown"] = True
    assert_failure(value, ManifestFailureCode.MISSING_FIELD)
    value = valid_manifest()
    entry = value["root_managed_resources"][0]
    entry["unknown"] = True
    entry["resource_id"] = 1
    assert_failure(value, ManifestFailureCode.UNKNOWN_FIELD)
    value = valid_manifest()
    entry = value["root_managed_resources"][0]
    entry["resource_id"] = 1
    entry["kind"] = "UNKNOWN"
    assert_failure(value, ManifestFailureCode.INVALID_FIELD_TYPE)
    value = valid_manifest()
    value["root_managed_resources"][0]["resource_id"] = ""
    del value["root_managed_resources"][1]["kind"]
    assert_failure(value, ManifestFailureCode.INVALID_FIELD_VALUE)


def test_cross_collection_precedence_is_deterministic() -> None:
    value = valid_manifest()
    value["core_policy"] = "missing-core"
    value["policy_resources"] = ["missing-policy"]
    value["trusted_core_members"][0]["implementation_resource"] = "missing-code"
    value["trusted_schemas"] = ["missing-schema"]
    value["trusted_configs"][0]["resource"] = "missing-config"
    value["external_tcb_dependencies"][0]["assumption_resource"] = "missing-assumption"
    for _ in range(3):
        assert_failure(value, ManifestFailureCode.UNKNOWN_RESOURCE_REFERENCE)
    value = valid_manifest()
    value["policy_resources"] = ["core"]
    value["trusted_core_members"][0]["implementation_resource"] = "runtime"
    assert_failure(value, ManifestFailureCode.INVALID_FIELD_VALUE)
    value = valid_manifest()
    value["root_managed_resources"].append(copy.deepcopy(value["root_managed_resources"][0]))
    value["policy_resources"] = ["missing"]
    assert_failure(value, ManifestFailureCode.DUPLICATE_IDENTITY)
    value = valid_manifest()
    value["policy_resources"] = ["missing"]
    value["trusted_core_members"][0]["implementation_resource"] = "runtime"
    assert_failure(value, ManifestFailureCode.UNKNOWN_RESOURCE_REFERENCE)


def test_large_indexed_collections_validate_without_pairwise_scans() -> None:
    value = valid_manifest()
    for index in range(1500):
        value["root_managed_resources"].append(resource(f"closure-{index}", "CAPABILITY_WIRING"))
    assert isinstance(load(value), CandidateTrustedManifest)


def test_failure_domains_reject_cross_domain_values() -> None:
    with pytest.raises(TypeError):
        ManifestFailure("PARSE_FAILED")
    with pytest.raises(TypeError):
        ManifestFailure(ResourceFailureCode.PARSE_FAILED)
    assert ManifestFailure(ManifestFailureCode.PARSE_FAILED).parse_failure is None
