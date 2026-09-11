import hashlib

import pytest

from autodev_control.trusted.errors import (
    ManifestFailureCode,
    ParseFailureCode,
    ResourceFailure,
    ResourceFailureCode,
)
from autodev_control.trusted.identity import GitSha, RawSha256
from autodev_control.trusted.manifest import (
    ExternalTcbDependencyId,
    ManifestKind,
    PolicyEpochIdentity,
    TrustedManifestId,
    TrustedMemberId,
)
from autodev_control.trusted.resources import (
    G2_INLINE_RESOURCE_MAX_BYTES,
    G2_JSON_RESOURCE_MAX_BYTES,
    ResolvedTrustedJsonResource,
    RootManagedResourceId,
    RootManagedResourceKind,
    RootManagedResourceRef,
    VerifiedInlineRootManagedResource,
    resolve_trusted_json_resource,
    verify_inline_resource_bytes,
)


def ref(kind: RootManagedResourceKind, raw: bytes) -> RootManagedResourceRef:
    return RootManagedResourceRef(
        RootManagedResourceId("resource"), kind, RawSha256(hashlib.sha256(raw).hexdigest())
    )


@pytest.mark.parametrize("identity", [RootManagedResourceId, TrustedMemberId, ExternalTcbDependencyId])
def test_logical_identifier_domains_are_exact_and_nominal(identity: type) -> None:
    assert identity("x").value == "x"
    assert identity("x" * 512).value == "x" * 512
    assert identity(" é ").value == " é "
    assert identity("é") != identity("é")
    assert identity("symbols / 😀").value == "symbols / 😀"
    for invalid in ("", "x" * 513, 1, True):
        with pytest.raises(ValueError):
            identity(invalid)
    assert RootManagedResourceId("x") != TrustedMemberId("x")
    assert TrustedMemberId("x") != ExternalTcbDependencyId("x")


def test_manifest_and_epoch_identity_domains_are_exact() -> None:
    raw = RawSha256("a" * 64)
    manifest_id = TrustedManifestId(raw)
    epoch = PolicyEpochIdentity(manifest_id)
    assert manifest_id.raw_sha256 is raw
    assert epoch.manifest_id is manifest_id
    assert epoch != manifest_id
    for invalid in ("a" * 64, GitSha("a" * 64), RootManagedResourceId("x")):
        with pytest.raises(TypeError):
            TrustedManifestId(invalid)
    with pytest.raises(TypeError):
        PolicyEpochIdentity(raw)


def test_exact_closed_enum_domains_and_nominal_failures() -> None:
    assert {item.name for item in RootManagedResourceKind} == {
        "CORE_POLICY", "POLICY", "TRUSTED_CODE", "TRUSTED_SCHEMA", "TRUSTED_CONFIG",
        "DEPENDENCY_LOCK", "BUILD_DEFINITION", "RUNTIME_ARTIFACT", "ENTRY_POINT_CONFIG",
        "SECURITY_CONTEXT_CONFIG", "CAPABILITY_WIRING", "CREDENTIAL_ROUTING",
        "MODULE_LOADING_POLICY", "EXTERNAL_TCB_ASSUMPTION_DOCUMENT",
    }
    assert {item.name for item in ManifestKind} == {"GENESIS", "SUCCESSOR"}
    assert {item.name for item in ManifestFailureCode} == {
        "INVALID_INPUT_TYPE", "BYTE_LIMIT_EXCEEDED", "PARSE_FAILED", "INVALID_TOP_LEVEL",
        "UNKNOWN_FIELD", "MISSING_FIELD", "INVALID_FIELD_TYPE", "INVALID_FIELD_VALUE",
        "DUPLICATE_IDENTITY", "UNKNOWN_RESOURCE_REFERENCE", "RESOURCE_KIND_MISMATCH",
        "INVALID_PREDECESSOR", "EMPTY_REQUIRED_SET",
    }
    assert {item.name for item in ResourceFailureCode} == {
        "INVALID_INPUT_TYPE", "INLINE_BYTE_LIMIT_EXCEEDED", "DIGEST_MISMATCH",
        "RESOURCE_KIND_MISMATCH", "JSON_BYTE_LIMIT_EXCEEDED", "PARSE_FAILED",
    }
    assert RootManagedResourceKind.CORE_POLICY != "CORE_POLICY"
    assert ManifestKind.GENESIS != "genesis"
    assert ManifestFailureCode.PARSE_FAILED != "PARSE_FAILED"
    assert ResourceFailureCode.PARSE_FAILED != "PARSE_FAILED"
    with pytest.raises(TypeError):
        ResourceFailure("DIGEST_MISMATCH")
    with pytest.raises(TypeError):
        ResourceFailure(ManifestFailureCode.PARSE_FAILED)
    with pytest.raises(TypeError):
        ResourceFailure(ResourceFailureCode.PARSE_FAILED, ParseFailureCode.INVALID_JSON)


def test_resource_ref_enforces_exact_domains() -> None:
    digest = RawSha256("a" * 64)
    with pytest.raises(TypeError):
        RootManagedResourceRef("r", RootManagedResourceKind.POLICY, digest)
    with pytest.raises(TypeError):
        RootManagedResourceRef(RootManagedResourceId("r"), "POLICY", digest)
    with pytest.raises(TypeError):
        RootManagedResourceRef(RootManagedResourceId("r"), RootManagedResourceKind.POLICY, GitSha("a" * 64))


def test_success_types_have_no_unchecked_public_constructor() -> None:
    with pytest.raises(TypeError):
        VerifiedInlineRootManagedResource(object(), b"")
    with pytest.raises(TypeError):
        ResolvedTrustedJsonResource(object(), object())
    with pytest.raises(TypeError):
        VerifiedInlineRootManagedResource._from_validated(
            object(), object(), b"caller-controlled"
        )
    with pytest.raises(TypeError):
        ResolvedTrustedJsonResource._from_validated(object(), object(), object())


def test_inline_verification_exact_precedence_and_boundaries() -> None:
    raw = b"exact bytes"
    resource = ref(RootManagedResourceKind.RUNTIME_ARTIFACT, raw)
    assert isinstance(verify_inline_resource_bytes(resource, raw), VerifiedInlineRootManagedResource)
    assert verify_inline_resource_bytes(object(), "bad").code is ResourceFailureCode.INVALID_INPUT_TYPE
    assert verify_inline_resource_bytes(resource, "bad").code is ResourceFailureCode.INVALID_INPUT_TYPE
    oversized = b"x" * (G2_INLINE_RESOURCE_MAX_BYTES + 1)
    assert verify_inline_resource_bytes(resource, oversized).code is ResourceFailureCode.INLINE_BYTE_LIMIT_EXCEEDED
    assert verify_inline_resource_bytes(resource, b"wrong").code is ResourceFailureCode.DIGEST_MISMATCH
    exact = b"x" * G2_INLINE_RESOURCE_MAX_BYTES
    exact_result = verify_inline_resource_bytes(ref(RootManagedResourceKind.RUNTIME_ARTIFACT, exact), exact)
    assert isinstance(exact_result, VerifiedInlineRootManagedResource)
    oversized_ref = ref(RootManagedResourceKind.RUNTIME_ARTIFACT, oversized)
    assert oversized_ref.sha256.value == hashlib.sha256(oversized).hexdigest()
    assert verify_inline_resource_bytes(oversized_ref, oversized).code is ResourceFailureCode.INLINE_BYTE_LIMIT_EXCEEDED


def test_json_resolution_precedence_and_success() -> None:
    malformed = b"{"
    wrong_digest = ref(RootManagedResourceKind.TRUSTED_CODE, b"other")
    assert resolve_trusted_json_resource(wrong_digest, malformed).code is ResourceFailureCode.DIGEST_MISMATCH
    wrong_kind = ref(RootManagedResourceKind.TRUSTED_CODE, malformed)
    assert resolve_trusted_json_resource(wrong_kind, malformed).code is ResourceFailureCode.RESOURCE_KIND_MISMATCH
    malformed_ref = ref(RootManagedResourceKind.TRUSTED_CONFIG, malformed)
    failure = resolve_trusted_json_resource(malformed_ref, malformed)
    assert failure.code is ResourceFailureCode.PARSE_FAILED
    assert failure.parse_failure.code is ParseFailureCode.INVALID_JSON
    valid = b'{"a":[1]}'
    resolved = resolve_trusted_json_resource(ref(RootManagedResourceKind.TRUSTED_CONFIG, valid), valid)
    assert isinstance(resolved, ResolvedTrustedJsonResource)
    assert resolved.source_document.raw_bytes == valid
    with pytest.raises(AttributeError):
        resolved.source_document.value["a"].append(2)


def test_json_resolution_byte_ceiling_after_digest_and_kind() -> None:
    oversized_json = b'"' + b"x" * G2_JSON_RESOURCE_MAX_BYTES + b'"'
    matching_wrong_kind = ref(RootManagedResourceKind.RUNTIME_ARTIFACT, oversized_json)
    assert resolve_trusted_json_resource(matching_wrong_kind, oversized_json).code is ResourceFailureCode.RESOURCE_KIND_MISMATCH
    matching_json_kind = ref(RootManagedResourceKind.TRUSTED_CONFIG, oversized_json)
    assert resolve_trusted_json_resource(matching_json_kind, oversized_json).code is ResourceFailureCode.JSON_BYTE_LIMIT_EXCEEDED
    exact_json = b'"' + b"x" * (G2_JSON_RESOURCE_MAX_BYTES - 2) + b'"'
    exact_result = resolve_trusted_json_resource(
        ref(RootManagedResourceKind.TRUSTED_CONFIG, exact_json), exact_json
    )
    assert isinstance(exact_result, ResolvedTrustedJsonResource)
