"""Content-addressed root-managed resource declarations and bounded verification."""

from dataclasses import dataclass
from enum import Enum
import hashlib

from .errors import ParseFailure, ResourceFailure, ResourceFailureCode
from .identity import LogicalIdentifier, RawSha256
from .parsing import ParseLimits, ParsedJsonDocument, parse_trusted_json

G2_MANIFEST_MAX_BYTES = 1 * 1024 * 1024
G2_MANIFEST_MAX_DEPTH = 32
G2_JSON_RESOURCE_MAX_BYTES = 8 * 1024 * 1024
G2_JSON_RESOURCE_MAX_DEPTH = 32
G2_INLINE_RESOURCE_MAX_BYTES = 16 * 1024 * 1024
_SUCCESS_CONSTRUCTION_KEY = object()


class RootManagedResourceKind(Enum):
    CORE_POLICY = "CORE_POLICY"
    POLICY = "POLICY"
    TRUSTED_CODE = "TRUSTED_CODE"
    TRUSTED_SCHEMA = "TRUSTED_SCHEMA"
    TRUSTED_CONFIG = "TRUSTED_CONFIG"
    DEPENDENCY_LOCK = "DEPENDENCY_LOCK"
    BUILD_DEFINITION = "BUILD_DEFINITION"
    RUNTIME_ARTIFACT = "RUNTIME_ARTIFACT"
    ENTRY_POINT_CONFIG = "ENTRY_POINT_CONFIG"
    SECURITY_CONTEXT_CONFIG = "SECURITY_CONTEXT_CONFIG"
    CAPABILITY_WIRING = "CAPABILITY_WIRING"
    CREDENTIAL_ROUTING = "CREDENTIAL_ROUTING"
    MODULE_LOADING_POLICY = "MODULE_LOADING_POLICY"
    EXTERNAL_TCB_ASSUMPTION_DOCUMENT = "EXTERNAL_TCB_ASSUMPTION_DOCUMENT"


@dataclass(frozen=True, slots=True)
class RootManagedResourceId:
    value: str

    def __post_init__(self) -> None:
        LogicalIdentifier(self.value)


@dataclass(frozen=True, slots=True)
class RootManagedResourceRef:
    resource_id: RootManagedResourceId
    kind: RootManagedResourceKind
    sha256: RawSha256

    def __post_init__(self) -> None:
        if type(self.resource_id) is not RootManagedResourceId:
            raise TypeError("resource_id must be exactly RootManagedResourceId")
        if type(self.kind) is not RootManagedResourceKind:
            raise TypeError("kind must be exactly RootManagedResourceKind")
        if type(self.sha256) is not RawSha256:
            raise TypeError("sha256 must be exactly RawSha256")


@dataclass(frozen=True, slots=True, init=False)
class VerifiedInlineRootManagedResource:
    """Local verification result; it is not a transferable authority token."""

    resource_ref: RootManagedResourceRef
    raw_bytes: bytes

    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("use verify_inline_resource_bytes")

    @classmethod
    def _from_validated(
        cls, key: object, resource_ref: RootManagedResourceRef, raw_bytes: bytes
    ) -> "VerifiedInlineRootManagedResource":
        if key is not _SUCCESS_CONSTRUCTION_KEY:
            raise TypeError("internal validated construction only")
        result = object.__new__(cls)
        object.__setattr__(result, "resource_ref", resource_ref)
        object.__setattr__(result, "raw_bytes", raw_bytes)
        return result


@dataclass(frozen=True, slots=True, init=False)
class ResolvedTrustedJsonResource:
    """Exact verified bytes parsed as JSON; no schema or authority claim is made."""

    resource_ref: RootManagedResourceRef
    source_document: ParsedJsonDocument

    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("use resolve_trusted_json_resource")

    @classmethod
    def _from_validated(
        cls, key: object, resource_ref: RootManagedResourceRef, source_document: ParsedJsonDocument
    ) -> "ResolvedTrustedJsonResource":
        if key is not _SUCCESS_CONSTRUCTION_KEY:
            raise TypeError("internal validated construction only")
        result = object.__new__(cls)
        object.__setattr__(result, "resource_ref", resource_ref)
        object.__setattr__(result, "source_document", source_document)
        return result


_JSON_RESOURCE_KINDS = frozenset(
    {
        RootManagedResourceKind.TRUSTED_SCHEMA,
        RootManagedResourceKind.TRUSTED_CONFIG,
        RootManagedResourceKind.ENTRY_POINT_CONFIG,
        RootManagedResourceKind.SECURITY_CONTEXT_CONFIG,
        RootManagedResourceKind.CAPABILITY_WIRING,
        RootManagedResourceKind.CREDENTIAL_ROUTING,
        RootManagedResourceKind.MODULE_LOADING_POLICY,
        RootManagedResourceKind.EXTERNAL_TCB_ASSUMPTION_DOCUMENT,
    }
)


def _digest_matches(resource_ref: RootManagedResourceRef, raw_bytes: bytes) -> bool:
    return hashlib.sha256(raw_bytes).hexdigest() == resource_ref.sha256.value


def verify_inline_resource_bytes(
    resource_ref: object, raw_bytes: object
) -> VerifiedInlineRootManagedResource | ResourceFailure:
    if type(resource_ref) is not RootManagedResourceRef:
        return ResourceFailure(ResourceFailureCode.INVALID_INPUT_TYPE)
    if type(raw_bytes) is not bytes:
        return ResourceFailure(ResourceFailureCode.INVALID_INPUT_TYPE)
    if len(raw_bytes) > G2_INLINE_RESOURCE_MAX_BYTES:
        return ResourceFailure(ResourceFailureCode.INLINE_BYTE_LIMIT_EXCEEDED)
    if not _digest_matches(resource_ref, raw_bytes):
        return ResourceFailure(ResourceFailureCode.DIGEST_MISMATCH)
    return VerifiedInlineRootManagedResource._from_validated(
        _SUCCESS_CONSTRUCTION_KEY, resource_ref, raw_bytes
    )


def resolve_trusted_json_resource(
    resource_ref: object, raw_bytes: object
) -> ResolvedTrustedJsonResource | ResourceFailure:
    if type(resource_ref) is not RootManagedResourceRef:
        return ResourceFailure(ResourceFailureCode.INVALID_INPUT_TYPE)
    if type(raw_bytes) is not bytes:
        return ResourceFailure(ResourceFailureCode.INVALID_INPUT_TYPE)
    if len(raw_bytes) > G2_INLINE_RESOURCE_MAX_BYTES:
        return ResourceFailure(ResourceFailureCode.INLINE_BYTE_LIMIT_EXCEEDED)
    if not _digest_matches(resource_ref, raw_bytes):
        return ResourceFailure(ResourceFailureCode.DIGEST_MISMATCH)
    if resource_ref.kind not in _JSON_RESOURCE_KINDS:
        return ResourceFailure(ResourceFailureCode.RESOURCE_KIND_MISMATCH)
    if len(raw_bytes) > G2_JSON_RESOURCE_MAX_BYTES:
        return ResourceFailure(ResourceFailureCode.JSON_BYTE_LIMIT_EXCEEDED)
    document = parse_trusted_json(
        raw_bytes,
        ParseLimits(G2_JSON_RESOURCE_MAX_BYTES, G2_JSON_RESOURCE_MAX_DEPTH),
    )
    if type(document) is ParseFailure:
        return ResourceFailure(ResourceFailureCode.PARSE_FAILED, document)
    return ResolvedTrustedJsonResource._from_validated(
        _SUCCESS_CONSTRUCTION_KEY, resource_ref, document
    )
