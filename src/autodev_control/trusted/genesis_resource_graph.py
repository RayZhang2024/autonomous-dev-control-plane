"""Closed, content-bound pre-G9 genesis resource-graph admission.

Successful validation is a local conformance result only. It is bound to the
exact candidate manifest and resources that were checked; it grants no
activation, deployment, credential, or protected-operation authority.
"""

from dataclasses import dataclass
import hashlib
import re
from types import MappingProxyType

from .errors import (
    GenesisResourceGraphFailure,
    GenesisResourceGraphFailureCode,
    IdentityValidationError,
    ParseFailure,
    ResourceFailure,
)
from .identity import LogicalIdentifier, RawSha256
from .manifest import (
    CandidateTrustedManifest,
    ExternalTcbDependency,
    ManifestKind,
    PolicyEpochIdentity,
    TrustedConfigBinding,
    TrustedCoreMember,
    TrustedManifestId,
)
from .parsing import ParseLimits, ParsedJsonDocument, parse_trusted_json
from .resources import (
    G2_INLINE_RESOURCE_MAX_BYTES,
    G2_JSON_RESOURCE_MAX_BYTES,
    G2_JSON_RESOURCE_MAX_DEPTH,
    RootManagedResourceId,
    RootManagedResourceKind,
    RootManagedResourceRef,
    ResolvedTrustedJsonResource,
    resolve_trusted_json_resource,
)

GENESIS_RESOURCE_GRAPH_CONFIG_ID = "autodev.genesis-resource-graph/v1"
GENESIS_RESOURCE_GRAPH_FORMAT = "autodev.genesis-resource-graph/v1"
_ENTRY_FORMAT = "autodev.genesis-entry-point/v1"
_SECURITY_FORMAT = "autodev.genesis-security-context/v1"
_WIRING_FORMAT = "autodev.genesis-capability-wiring/v1"
_CREDENTIAL_FORMAT = "autodev.genesis-credential-routing/v1"
_MODULE_POLICY_FORMAT = "autodev.genesis-module-loading-policy/v1"
_LOCK_FORMAT = "autodev.genesis-dependency-lock/v1"
_ASSUMPTION_FORMAT = "autodev.genesis-external-tcb-assumption/v1"
_ROLES = ("T", "C", "P", "M")
_EXTERNAL_ROLES = (
    "ROOT_ACTIVATION_FENCE",
    "EXECUTION_ISOLATION",
    "FIXTURE_EFFECT_SUBSTRATE",
)
_GRAPH_FIELDS = (
    "format",
    "genesis_scope",
    "implementation_resource",
    "build_definition_resource",
    "dependency_lock_resource",
    "runtime_artifact_resource",
    "module_loading_policy_resource",
    "core_policy_resource",
    "genesis_conformance_resource",
    "members",
    "policy_resources",
    "trusted_schema_resources",
    "trusted_config_bindings",
    "external_tcb_roles",
)
_MEMBER_FIELDS = (
    "role",
    "member_id",
    "service_principal",
    "implementation_resource",
    "runtime_artifact_resource",
    "entry_point_config_resource",
    "security_context_config_resource",
    "capability_wiring_resource",
    "credential_routing_resource",
)
_CONFIG_BINDING_FIELDS = (
    "config_id",
    "resource_id",
    "purpose",
    "expected_format",
    "schema_resource",
    "grammar_id",
)
_CONFIG_PURPOSE_FORMATS = {
    "GENESIS_RESOURCE_GRAPH": GENESIS_RESOURCE_GRAPH_FORMAT,
    "MODULE_LOADING_POLICY": _MODULE_POLICY_FORMAT,
    **{
        f"{purpose}:{role}": format_id
        for purpose, format_id in (
            ("ENTRY_POINT_CONFIG", _ENTRY_FORMAT),
            ("SECURITY_CONTEXT_CONFIG", _SECURITY_FORMAT),
            ("CAPABILITY_WIRING", _WIRING_FORMAT),
            ("CREDENTIAL_ROUTING", _CREDENTIAL_FORMAT),
        )
        for role in _ROLES
    },
}
_BASE_CHANNEL_FIELDS = (
    "channel_id",
    "source_role",
    "source_member_id",
    "source_context_resource",
    "destination_role",
    "destination_member_id",
    "destination_context_resource",
    "root_context_binding",
    "runtime_generation_binding",
    "source_runtime_binding",
    "destination_runtime_binding",
    "authenticated_channel_binding",
    "verifier_binding",
)
_FIXTURE_BINDING_FIELDS = (
    "f_read_verify_binding",
    "f_read_verify_mode",
    "publication_authority_binding",
    "merge_authority_binding",
    "external_recovery_binding",
    "p_target_fence_binding",
    "m_target_fence_binding",
    "target_fence_namespace",
)
_REQUIRED_EXCLUSIONS = frozenset(
    {
        "tests/**",
        "src/autodev_control/trusted/gates.py",
        "src/autodev_control/trusted/fixture_audit.py",
        "src/autodev_control/trusted/fixture_capabilities.py",
        "src/autodev_control/trusted/fixture_transport.py",
        "src/autodev_control/trusted/fixture_platform.py",
    }
)
_SUCCESS_CONSTRUCTION_KEY = object()
_MAX_TOTAL_RESOURCE_BYTES = G2_JSON_RESOURCE_MAX_BYTES * 32


@dataclass(frozen=True, slots=True, init=False)
class ValidatedGenesisResourceGraph:
    """Manifest/resource-bound conformance result, never a bearer authority."""

    manifest_id: TrustedManifestId
    policy_epoch_identity: PolicyEpochIdentity
    graph_resource: RootManagedResourceRef
    graph_sha256: RawSha256
    consumed_resource_ids: tuple[RootManagedResourceId, ...]
    verified_resource_refs: tuple[RootManagedResourceRef, ...]

    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("use validate_genesis_resource_graph")

    @classmethod
    def _from_validated(cls, key: object, **fields: object) -> "ValidatedGenesisResourceGraph":
        if key is not _SUCCESS_CONSTRUCTION_KEY:
            raise TypeError("internal validated construction only")
        result = object.__new__(cls)
        for name, value in fields.items():
            object.__setattr__(result, name, value)
        return result


def _failure(
    code: GenesisResourceGraphFailureCode, parse_failure: ParseFailure | None = None
) -> GenesisResourceGraphFailure:
    return GenesisResourceGraphFailure(code, parse_failure)


def _fields(value: object, expected: tuple[str, ...]) -> bool:
    return (
        type(value) is MappingProxyType
        and all(field in value for field in expected)
        and all(field in expected for field in value)
    )


def _text(value: object, *, identifier: bool = False) -> bool:
    if type(value) is not str:
        return False
    if identifier:
        try:
            LogicalIdentifier(value)
        except IdentityValidationError:
            return False
        return True
    return 1 <= len(value) <= 512 and not any(0xD800 <= ord(ch) <= 0xDFFF for ch in value)


def _resource_id(value: object) -> RootManagedResourceId | None:
    if not _text(value, identifier=True):
        return None
    try:
        return RootManagedResourceId(value)
    except IdentityValidationError:
        return None


def _array(value: object) -> bool:
    return type(value) is tuple


def _unique(values: tuple[str, ...]) -> bool:
    return len(set(values)) == len(values)


def _sorted_unique_strings(value: object) -> tuple[str, ...] | None:
    if not _array(value) or any(not _text(item) for item in value):
        return None
    result = tuple(value)
    if not _unique(result) or result != tuple(sorted(result)):
        return None
    return result


def _resource_index(
    manifest: CandidateTrustedManifest,
) -> dict[str, RootManagedResourceRef]:
    return {item.resource_id.value: item for item in manifest.root_managed_resources}


def _expected_kind(
    resource_id: object,
    kind: RootManagedResourceKind,
    resources: dict[str, RootManagedResourceRef],
) -> GenesisResourceGraphFailure | None:
    reference = _resource_id(resource_id)
    if reference is None:
        return _failure(GenesisResourceGraphFailureCode.GRAPH_FORMAT_INVALID)
    found = resources.get(reference.value)
    if found is None:
        return _failure(GenesisResourceGraphFailureCode.GRAPH_RESOURCE_MISSING)
    if found.kind is not kind:
        return _failure(GenesisResourceGraphFailureCode.GRAPH_RESOURCE_KIND_MISMATCH)
    return None


def _verify_raw(
    resource_id: str,
    raw_resources: dict[str, bytes],
    resources: dict[str, RootManagedResourceRef],
) -> tuple[RootManagedResourceRef, bytes] | GenesisResourceGraphFailure:
    reference = resources.get(resource_id)
    if reference is None:
        return _failure(GenesisResourceGraphFailureCode.GRAPH_RESOURCE_MISSING)
    raw = raw_resources.get(resource_id)
    if type(raw) is not bytes:
        return _failure(GenesisResourceGraphFailureCode.GRAPH_RESOURCE_MISSING)
    if len(raw) > G2_INLINE_RESOURCE_MAX_BYTES:
        return _failure(GenesisResourceGraphFailureCode.GRAPH_PARSE_FAILED)
    if hashlib.sha256(raw).hexdigest() != reference.sha256.value:
        return _failure(GenesisResourceGraphFailureCode.GRAPH_RESOURCE_DIGEST_MISMATCH)
    return reference, raw


def _load_json(
    resource_id: str,
    expected_kind: RootManagedResourceKind,
    raw_resources: dict[str, bytes],
    resources: dict[str, RootManagedResourceRef],
) -> tuple[RootManagedResourceRef, ParsedJsonDocument] | GenesisResourceGraphFailure:
    kind_failure = _expected_kind(resource_id, expected_kind, resources)
    if kind_failure is not None:
        return kind_failure
    verified = _verify_raw(resource_id, raw_resources, resources)
    if type(verified) is GenesisResourceGraphFailure:
        return verified
    reference, raw = verified
    parsed = resolve_trusted_json_resource(reference, raw)
    if type(parsed) is ResourceFailure:
        if parsed.code.value == "DIGEST_MISMATCH":
            return _failure(GenesisResourceGraphFailureCode.GRAPH_RESOURCE_DIGEST_MISMATCH)
        if parsed.code.value == "RESOURCE_KIND_MISMATCH":
            return _failure(GenesisResourceGraphFailureCode.GRAPH_RESOURCE_KIND_MISMATCH)
        return _failure(
            GenesisResourceGraphFailureCode.GRAPH_PARSE_FAILED,
            parsed.parse_failure,
        )
    if type(parsed) is not ResolvedTrustedJsonResource:
        return _failure(GenesisResourceGraphFailureCode.GRAPH_PARSE_FAILED)
    return reference, parsed.source_document


def _load_lock(
    resource_id: str,
    raw_resources: dict[str, bytes],
    resources: dict[str, RootManagedResourceRef],
) -> tuple[RootManagedResourceRef, ParsedJsonDocument] | GenesisResourceGraphFailure:
    kind_failure = _expected_kind(resource_id, RootManagedResourceKind.DEPENDENCY_LOCK, resources)
    if kind_failure is not None:
        return kind_failure
    verified = _verify_raw(resource_id, raw_resources, resources)
    if type(verified) is GenesisResourceGraphFailure:
        return verified
    reference, raw = verified
    parsed = parse_trusted_json(
        raw, ParseLimits(G2_JSON_RESOURCE_MAX_BYTES, G2_JSON_RESOURCE_MAX_DEPTH)
    )
    if type(parsed) is ParseFailure:
        return _failure(GenesisResourceGraphFailureCode.GRAPH_PARSE_FAILED, parsed)
    return reference, parsed


def _string_array(value: object) -> tuple[str, ...] | None:
    if not _array(value) or any(not _text(item) for item in value):
        return None
    result = tuple(value)
    return result if _unique(result) else None


def _same_fields(left: MappingProxyType, right: MappingProxyType, fields: tuple[str, ...]) -> bool:
    return all(left[field] == right[field] for field in fields)


def _parse_channels(
    context: object,
) -> tuple[tuple[object, ...], ...] | None:
    if not _fields(context, ("format", "role", "member_id", "context_id", "service_principal",
                             "runtime_binding", "runtime_generation_binding", "root_context_binding",
                             "external_isolation_dependency_id", "channels")):
        return None
    if context["format"] != _SECURITY_FORMAT:
        return None
    for key in ("role", "member_id", "context_id", "service_principal", "runtime_binding",
                "runtime_generation_binding", "root_context_binding", "external_isolation_dependency_id"):
        if not _text(context[key], identifier=True):
            return None
    if context["role"] not in _ROLES or not _array(context["channels"]):
        return None
    normalized: list[tuple[object, ...]] = []
    for channel in context["channels"]:
        if not _fields(channel, _BASE_CHANNEL_FIELDS):
            return None
        if any(not _text(channel[field], identifier=True) for field in _BASE_CHANNEL_FIELDS):
            return None
        if any(channel[field] == "NONE" for field in _BASE_CHANNEL_FIELDS):
            return None
        if channel["source_role"] not in _ROLES or channel["destination_role"] not in _ROLES:
            return None
        normalized.append(tuple(channel[field] for field in _BASE_CHANNEL_FIELDS))
    if len({item[0] for item in normalized}) != len(normalized):
        return None
    return tuple(normalized)


def _valid_exact_version(value: object) -> bool:
    return type(value) is str and re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,3}", value) is not None


def _valid_hash(value: object) -> bool:
    try:
        RawSha256(value)
    except IdentityValidationError:
        return False
    return True


def _check_entry_point(
    value: object, member: MappingProxyType
) -> GenesisResourceGraphFailure | None:
    fields = ("format", "role", "member_id", "runtime_artifact_resource", "module", "callable")
    if not _fields(value, fields):
        return _failure(GenesisResourceGraphFailureCode.GRAPH_ENTRY_POINT_MISMATCH)
    if (
        value["format"] != _ENTRY_FORMAT
        or value["role"] != member["role"]
        or value["member_id"] != member["member_id"]
        or value["runtime_artifact_resource"] != member["runtime_artifact_resource"]
        or not _text(value["module"], identifier=True)
        or not _text(value["callable"], identifier=True)
    ):
        return _failure(GenesisResourceGraphFailureCode.GRAPH_ENTRY_POINT_MISMATCH)
    return None


def _check_security_contexts(
    contexts: dict[str, MappingProxyType], members: dict[str, MappingProxyType],
    fixture_dependency_id: str,
) -> GenesisResourceGraphFailure | None:
    context_channels: dict[str, tuple[tuple[object, ...], ...]] = {}
    for role in _ROLES:
        member = members[role]
        resource_id = member["security_context_config_resource"]
        context = contexts.get(resource_id)
        channels = _parse_channels(context)
        if (
            channels is None
            or context["role"] != role
            or context["member_id"] != member["member_id"]
            or context["context_id"] != resource_id
            or context["service_principal"] != member["service_principal"]
            or context["external_isolation_dependency_id"] != fixture_dependency_id
        ):
            return _failure(GenesisResourceGraphFailureCode.GRAPH_SECURITY_CONTEXT_MISMATCH)
        context_channels[role] = channels
    expected_pairs = {("T", "C"), ("T", "P"), ("T", "M")}
    declared_pairs: set[tuple[str, str]] = set()
    source_records = context_channels["T"]
    for record in source_records:
        channel = dict(zip(_BASE_CHANNEL_FIELDS, record, strict=True))
        pair = (channel["source_role"], channel["destination_role"])
        if pair not in expected_pairs or pair in declared_pairs:
            return _failure(GenesisResourceGraphFailureCode.GRAPH_SECURITY_CONTEXT_MISMATCH)
        declared_pairs.add(pair)
        source = contexts.get(channel["source_context_resource"])
        destination = contexts.get(channel["destination_context_resource"])
        if source is None or destination is None:
            return _failure(GenesisResourceGraphFailureCode.GRAPH_SECURITY_CONTEXT_MISMATCH)
        if (
            channel["source_member_id"] != members[pair[0]]["member_id"]
            or channel["destination_member_id"] != members[pair[1]]["member_id"]
            or channel["source_context_resource"] != members[pair[0]]["security_context_config_resource"]
            or channel["destination_context_resource"] != members[pair[1]]["security_context_config_resource"]
            or channel["root_context_binding"] != source["root_context_binding"]
            or channel["root_context_binding"] != destination["root_context_binding"]
            or channel["runtime_generation_binding"] != source["runtime_generation_binding"]
            or channel["runtime_generation_binding"] != destination["runtime_generation_binding"]
            or channel["source_runtime_binding"] != source["runtime_binding"]
            or channel["destination_runtime_binding"] != destination["runtime_binding"]
        ):
            return _failure(GenesisResourceGraphFailureCode.GRAPH_SECURITY_CONTEXT_MISMATCH)
        expected_record = record
        if expected_record not in context_channels[pair[1]]:
            return _failure(GenesisResourceGraphFailureCode.GRAPH_SECURITY_CONTEXT_MISMATCH)
    if declared_pairs != expected_pairs:
        return _failure(GenesisResourceGraphFailureCode.GRAPH_SECURITY_CONTEXT_MISMATCH)
    if len(context_channels["T"]) != 3:
        return _failure(GenesisResourceGraphFailureCode.GRAPH_SECURITY_CONTEXT_MISMATCH)
    if len({contexts[member["security_context_config_resource"]]["runtime_binding"]
            for member in members.values()}) != len(_ROLES):
        return _failure(GenesisResourceGraphFailureCode.GRAPH_SECURITY_CONTEXT_MISMATCH)
    declared_channels = context_channels["T"]
    if (
        len({item[0] for item in declared_channels}) != 3
        or len({item[10] for item in declared_channels}) != 3
        or len({item[11] for item in declared_channels}) != 3
    ):
        return _failure(GenesisResourceGraphFailureCode.GRAPH_SECURITY_CONTEXT_MISMATCH)
    for role in ("C", "P", "M"):
        incoming = [record for record in context_channels[role] if record == next(
            source_record for source_record in source_records
            if source_record[1] == "T" and source_record[4] == role
        )]
        if len(context_channels[role]) != 1 or len(incoming) != 1:
            return _failure(GenesisResourceGraphFailureCode.GRAPH_SECURITY_CONTEXT_MISMATCH)
    return None


def _check_wirings(
    wirings: dict[str, MappingProxyType], members: dict[str, MappingProxyType],
    fixture_bindings: MappingProxyType,
) -> GenesisResourceGraphFailure | None:
    expected_fields = (
        "format", "role", "member_id", "canonical_state_access", "canonical_state_binding",
        "f_read_verify_binding", "target_fence_binding", "publication_authority_binding",
        "merge_authority_binding", "external_recovery_binding",
    )
    parsed: dict[str, MappingProxyType] = {}
    for role in _ROLES:
        member = members[role]
        wiring = wirings.get(member["capability_wiring_resource"])
        if not _fields(wiring, expected_fields):
            return _failure(GenesisResourceGraphFailureCode.GRAPH_CAPABILITY_WIRING_MISMATCH)
        if wiring["format"] != _WIRING_FORMAT or wiring["role"] != role or wiring["member_id"] != member["member_id"]:
            return _failure(GenesisResourceGraphFailureCode.GRAPH_CAPABILITY_WIRING_MISMATCH)
        if wiring["canonical_state_access"] not in ("READ", "READ_WRITE"):
            return _failure(GenesisResourceGraphFailureCode.GRAPH_CAPABILITY_WIRING_MISMATCH)
        for field in expected_fields[4:]:
            if field == "format" or field == "role" or field == "member_id":
                continue
            value = wiring[field]
            if value != "NONE" and not _text(value, identifier=True):
                return _failure(GenesisResourceGraphFailureCode.GRAPH_CAPABILITY_WIRING_MISMATCH)
        if wiring["f_read_verify_binding"] != fixture_bindings["f_read_verify_binding"]:
            return _failure(GenesisResourceGraphFailureCode.GRAPH_CAPABILITY_WIRING_MISMATCH)
        if wiring["external_recovery_binding"] != "NONE":
            return _failure(GenesisResourceGraphFailureCode.GRAPH_CAPABILITY_WIRING_MISMATCH)
        parsed[role] = wiring
    t, c, p, m = (parsed[role] for role in _ROLES)
    if (
        t["canonical_state_access"] != "READ"
        or c["canonical_state_access"] != "READ_WRITE"
        or p["canonical_state_access"] != "READ"
        or m["canonical_state_access"] != "READ"
        or not _text(t["canonical_state_binding"], identifier=True)
        or not _text(c["canonical_state_binding"], identifier=True)
        or not _text(p["canonical_state_binding"], identifier=True)
        or not _text(m["canonical_state_binding"], identifier=True)
        or any(
            wiring["canonical_state_binding"] == "NONE"
            for wiring in (t, c, p, m)
        )
        or p["canonical_state_binding"] != m["canonical_state_binding"]
        or t["canonical_state_binding"] in (p["canonical_state_binding"], c["canonical_state_binding"])
        or c["canonical_state_binding"] == p["canonical_state_binding"]
    ):
        return _failure(GenesisResourceGraphFailureCode.GRAPH_CAPABILITY_WIRING_MISMATCH)
    expected = {
        "T": ("NONE", "NONE", "NONE", "NONE"),
        "C": ("NONE", "NONE", "NONE", "NONE"),
        "P": (fixture_bindings["p_target_fence_binding"], fixture_bindings["publication_authority_binding"], "NONE", "NONE"),
        "M": (fixture_bindings["m_target_fence_binding"], "NONE", fixture_bindings["merge_authority_binding"], "NONE"),
    }
    for role, wiring in parsed.items():
        wanted = expected[role]
        actual = (
            wiring["target_fence_binding"], wiring["publication_authority_binding"],
            wiring["merge_authority_binding"], wiring["external_recovery_binding"],
        )
        if actual != wanted:
            return _failure(GenesisResourceGraphFailureCode.GRAPH_CAPABILITY_WIRING_MISMATCH)
    unique_endpoints = [
        fixture_bindings[field]
        for field in (
            "f_read_verify_binding", "publication_authority_binding", "merge_authority_binding",
            "external_recovery_binding", "p_target_fence_binding", "m_target_fence_binding",
            "target_fence_namespace",
        )
    ]
    if len(set(unique_endpoints)) != len(unique_endpoints):
        return _failure(GenesisResourceGraphFailureCode.GRAPH_CAPABILITY_WIRING_MISMATCH)
    return None


def _check_credentials(
    credentials: dict[str, MappingProxyType], members: dict[str, MappingProxyType]
) -> GenesisResourceGraphFailure | None:
    fields = ("format", "role", "member_id", "production_github_mutation_credentials")
    for role in _ROLES:
        member = members[role]
        value = credentials.get(member["credential_routing_resource"])
        if (
            not _fields(value, fields)
            or value["format"] != _CREDENTIAL_FORMAT
            or value["role"] != role
            or value["member_id"] != member["member_id"]
            or value["production_github_mutation_credentials"] != "NONE"
        ):
            return _failure(GenesisResourceGraphFailureCode.GRAPH_CREDENTIAL_ROUTING_MISMATCH)
    return None


def _check_module_policy(value: object) -> GenesisResourceGraphFailure | None:
    fields = ("format", "allowed_candidate_modules", "explicitly_excluded_modules_or_prefixes",
              "third_party_runtime_policy", "dynamic_import_fallback")
    if not _fields(value, fields) or value["format"] != _MODULE_POLICY_FORMAT:
        return _failure(GenesisResourceGraphFailureCode.GRAPH_MODULE_LOADING_MISMATCH)
    if value["dynamic_import_fallback"] != "NONE":
        return _failure(GenesisResourceGraphFailureCode.GRAPH_MODULE_LOADING_MISMATCH)
    allowed = _sorted_unique_strings(value["allowed_candidate_modules"])
    excluded = _sorted_unique_strings(value["explicitly_excluded_modules_or_prefixes"])
    if not allowed or not excluded or not _REQUIRED_EXCLUSIONS.issubset(excluded):
        return _failure(GenesisResourceGraphFailureCode.GRAPH_MODULE_LOADING_MISMATCH)
    for path in allowed:
        if (
            path.startswith("/")
            or "\\" in path
            or any(part in ("", ".", "..") for part in path.split("/"))
            or path.startswith("tests/")
            or path in _REQUIRED_EXCLUSIONS
        ):
            return _failure(GenesisResourceGraphFailureCode.GRAPH_MODULE_LOADING_MISMATCH)
        if any(path.startswith(prefix) for prefix in excluded if prefix.endswith("/")):
            return _failure(GenesisResourceGraphFailureCode.GRAPH_MODULE_LOADING_MISMATCH)
    third_party = value["third_party_runtime_policy"]
    if not _fields(third_party, ("standard_library_policy", "third_party_module_allowlist")):
        return _failure(GenesisResourceGraphFailureCode.GRAPH_MODULE_LOADING_MISMATCH)
    allowlist = _sorted_unique_strings(third_party["third_party_module_allowlist"])
    if third_party["standard_library_policy"] != "ALLOW" or allowlist is None:
        return _failure(GenesisResourceGraphFailureCode.GRAPH_MODULE_LOADING_MISMATCH)
    return None


def _check_config_binding_mirrors(
    config_values: dict[str, MappingProxyType],
    bindings: object,
    members: dict[str, MappingProxyType],
    entry_values: dict[str, MappingProxyType],
    contexts: dict[str, MappingProxyType],
    wirings: dict[str, MappingProxyType],
    credentials: dict[str, MappingProxyType],
    module_policy: MappingProxyType,
) -> GenesisResourceGraphFailure | None:
    """Require every generic config to be the exact value checked by its consumer."""
    if not _array(bindings):
        return _failure(GenesisResourceGraphFailureCode.GRAPH_CONFIG_SET_MISMATCH)
    for binding in bindings:
        purpose = binding["purpose"]
        resource_id = binding["resource_id"]
        actual = config_values.get(resource_id)
        if actual is None:
            return _failure(GenesisResourceGraphFailureCode.GRAPH_CONFIG_SET_MISMATCH)
        if purpose == "GENESIS_RESOURCE_GRAPH":
            expected = config_values.get(resource_id)
        elif purpose == "MODULE_LOADING_POLICY":
            expected = module_policy
        else:
            prefix, role = purpose.split(":", 1)
            member = members[role]
            resource_field, value_map = {
                "ENTRY_POINT_CONFIG": ("entry_point_config_resource", entry_values),
                "SECURITY_CONTEXT_CONFIG": ("security_context_config_resource", contexts),
                "CAPABILITY_WIRING": ("capability_wiring_resource", wirings),
                "CREDENTIAL_ROUTING": ("credential_routing_resource", credentials),
            }[prefix]
            expected = value_map.get(member[resource_field])
        if expected is None or actual != expected:
            return _failure(GenesisResourceGraphFailureCode.GRAPH_CONFIG_SET_MISMATCH)
    return None


def _check_lock(
    value: object,
    manifest_resources: dict[str, RootManagedResourceRef],
    graph: MappingProxyType,
) -> GenesisResourceGraphFailure | None:
    fields = ("format", "python_runtime", "build_backend", "build_tools", "runtime_dependencies", "locked_resources")
    if not _fields(value, fields) or value["format"] != _LOCK_FORMAT:
        return _failure(GenesisResourceGraphFailureCode.GRAPH_FORMAT_INVALID)
    runtime = value["python_runtime"]
    backend = value["build_backend"]
    if (
        not _fields(runtime, ("identity", "version", "sha256"))
        or not _text(runtime["identity"], identifier=True)
        or not _valid_exact_version(runtime["version"])
        or not _valid_hash(runtime["sha256"])
        or not _fields(backend, ("name", "version", "sha256"))
        or not _text(backend["name"], identifier=True)
        or not _valid_exact_version(backend["version"])
        or not _valid_hash(backend["sha256"])
    ):
        return _failure(GenesisResourceGraphFailureCode.GRAPH_FORMAT_INVALID)
    for collection_name in ("build_tools", "runtime_dependencies"):
        records = value[collection_name]
        if not _array(records):
            return _failure(GenesisResourceGraphFailureCode.GRAPH_FORMAT_INVALID)
        names: list[str] = []
        for record in records:
            if (
                not _fields(record, ("name", "version", "sha256"))
                or not _text(record["name"], identifier=True)
                or not _valid_exact_version(record["version"])
                or not _valid_hash(record["sha256"])
            ):
                return _failure(GenesisResourceGraphFailureCode.GRAPH_FORMAT_INVALID)
            names.append(record["name"])
        if names != sorted(names) or not _unique(tuple(names)):
            return _failure(GenesisResourceGraphFailureCode.GRAPH_FORMAT_INVALID)
    locks = value["locked_resources"]
    if not _array(locks):
        return _failure(GenesisResourceGraphFailureCode.GRAPH_FORMAT_INVALID)
    lock_by_role: dict[str, MappingProxyType] = {}
    for record in locks:
        if not _fields(record, ("role", "resource_id", "sha256")):
            return _failure(GenesisResourceGraphFailureCode.GRAPH_FORMAT_INVALID)
        if (
            record["role"] not in ("IMPLEMENTATION", "BUILD_DEFINITION", "RUNTIME_ARTIFACT")
            or not _text(record["resource_id"], identifier=True)
            or not _valid_hash(record["sha256"])
            or record["role"] in lock_by_role
        ):
            return _failure(GenesisResourceGraphFailureCode.GRAPH_FORMAT_INVALID)
        lock_by_role[record["role"]] = record
    expected_resources = {
        "IMPLEMENTATION": graph["implementation_resource"],
        "BUILD_DEFINITION": graph["build_definition_resource"],
        "RUNTIME_ARTIFACT": graph["runtime_artifact_resource"],
    }
    if set(lock_by_role) != set(expected_resources):
        return _failure(GenesisResourceGraphFailureCode.GRAPH_FORMAT_INVALID)
    for role, resource_id in expected_resources.items():
        reference = manifest_resources.get(resource_id)
        if reference is None or (
            lock_by_role[role]["resource_id"] != resource_id
            or lock_by_role[role]["sha256"] != reference.sha256.value
        ):
            return _failure(GenesisResourceGraphFailureCode.GRAPH_FORMAT_INVALID)
    return None


def _parse_member_records(value: object) -> tuple[dict[str, MappingProxyType], GenesisResourceGraphFailure | None]:
    if not _array(value):
        return {}, _failure(GenesisResourceGraphFailureCode.GRAPH_MEMBER_SET_MISMATCH)
    result: dict[str, MappingProxyType] = {}
    for member in value:
        if not _fields(member, _MEMBER_FIELDS):
            return {}, _failure(GenesisResourceGraphFailureCode.GRAPH_FORMAT_INVALID)
        role = member["role"]
        if type(role) is not str or role not in _ROLES or role in result:
            return {}, _failure(GenesisResourceGraphFailureCode.GRAPH_MEMBER_SET_MISMATCH)
        if any(not _text(member[field], identifier=True) for field in _MEMBER_FIELDS[1:]):
            return {}, _failure(GenesisResourceGraphFailureCode.GRAPH_FORMAT_INVALID)
        result[role] = member
    if set(result) != set(_ROLES):
        return {}, _failure(GenesisResourceGraphFailureCode.GRAPH_MEMBER_SET_MISMATCH)
    return result, None


def _validate_manifest_members(
    members: dict[str, MappingProxyType], manifest: CandidateTrustedManifest
) -> GenesisResourceGraphFailure | None:
    if type(manifest.trusted_core_members) is not tuple or len(manifest.trusted_core_members) != 4:
        return _failure(GenesisResourceGraphFailureCode.GRAPH_MEMBER_SET_MISMATCH)
    manifest_by_id: dict[str, TrustedCoreMember] = {}
    for record in manifest.trusted_core_members:
        if type(record) is not TrustedCoreMember or record.member_id.value in manifest_by_id:
            return _failure(GenesisResourceGraphFailureCode.GRAPH_MEMBER_SET_MISMATCH)
        manifest_by_id[record.member_id.value] = record
    if set(manifest_by_id) != set(_ROLES):
        return _failure(GenesisResourceGraphFailureCode.GRAPH_MEMBER_SET_MISMATCH)
    implementations: set[str] = set()
    runtimes: set[str] = set()
    entry_points: set[str] = set()
    principals: set[str] = set()
    for role in _ROLES:
        graph_member = members[role]
        declared_id = graph_member["member_id"]
        canonical = manifest_by_id.get(declared_id)
        if (
            canonical is None
            or declared_id != role
            or graph_member["implementation_resource"] != canonical.implementation_resource.value
            or graph_member["runtime_artifact_resource"] != canonical.runtime_artifact_resource.value
            or graph_member["entry_point_config_resource"] != canonical.entry_point_config_resource.value
        ):
            return _failure(GenesisResourceGraphFailureCode.GRAPH_MEMBER_BINDING_MISMATCH)
        implementations.add(graph_member["implementation_resource"])
        runtimes.add(graph_member["runtime_artifact_resource"])
        entry_points.add(graph_member["entry_point_config_resource"])
        principals.add(graph_member["service_principal"])
    if len(implementations) != 1 or len(runtimes) != 1:
        return _failure(GenesisResourceGraphFailureCode.GRAPH_SHARED_RESOURCE_MISMATCH)
    if len(entry_points) != 4 or len(principals) != 4:
        return _failure(GenesisResourceGraphFailureCode.GRAPH_MEMBER_BINDING_MISMATCH)
    return None


def _parse_config_bindings(
    value: object,
    manifest: CandidateTrustedManifest,
    resources: dict[str, RootManagedResourceRef],
    raw_resources: dict[str, bytes],
) -> tuple[dict[str, MappingProxyType], set[str], GenesisResourceGraphFailure | None]:
    if not _array(value):
        return {}, set(), _failure(GenesisResourceGraphFailureCode.GRAPH_CONFIG_SET_MISMATCH)
    manifest_pairs = {
        (item.config_id.value, item.resource.value) for item in manifest.trusted_configs
        if type(item) is TrustedConfigBinding
    }
    if len(manifest_pairs) != len(manifest.trusted_configs):
        return {}, set(), _failure(GenesisResourceGraphFailureCode.GRAPH_CONFIG_SET_MISMATCH)
    seen_configs: set[str] = set()
    seen_resources: set[str] = set()
    parsed_by_resource: dict[str, MappingProxyType] = {}
    purpose_by_resource: dict[str, str] = {}
    used_schema_ids: set[str] = set()
    declared_pairs: set[tuple[str, str]] = set()
    for binding in value:
        if not _fields(binding, _CONFIG_BINDING_FIELDS):
            return {}, set(), _failure(GenesisResourceGraphFailureCode.GRAPH_FORMAT_INVALID)
        config_id, resource_id = binding["config_id"], binding["resource_id"]
        if not _text(config_id, identifier=True) or not _text(resource_id, identifier=True):
            return {}, set(), _failure(GenesisResourceGraphFailureCode.GRAPH_FORMAT_INVALID)
        if config_id in seen_configs or resource_id in seen_resources:
            return {}, set(), _failure(GenesisResourceGraphFailureCode.GRAPH_CONFIG_SET_MISMATCH)
        seen_configs.add(config_id)
        seen_resources.add(resource_id)
        declared_pairs.add((config_id, resource_id))
        purpose = binding["purpose"]
        expected_format = binding["expected_format"]
        if (
            not _text(purpose, identifier=True)
            or purpose not in _CONFIG_PURPOSE_FORMATS
            or not _text(expected_format, identifier=True)
            or expected_format != _CONFIG_PURPOSE_FORMATS[purpose]
            or purpose in purpose_by_resource.values()
        ):
            return {}, set(), _failure(GenesisResourceGraphFailureCode.GRAPH_CONFIG_SET_MISMATCH)
        schema_resource = binding["schema_resource"]
        grammar_id = binding["grammar_id"]
        # R4 accepts only grammar identities for which this module executes a
        # closed deterministic validator. Schema resources remain independently
        # closed by the manifest/graph sets and raw digest checks below; a schema
        # declaration is not treated as validation merely because its bytes exist.
        if (
            schema_resource is not None
            or not _text(grammar_id, identifier=True)
            or grammar_id != expected_format
        ):
            return {}, set(), _failure(GenesisResourceGraphFailureCode.GRAPH_CONFIG_SET_MISMATCH)
        config_ref = resources.get(resource_id)
        if config_ref is None:
            return {}, set(), _failure(GenesisResourceGraphFailureCode.GRAPH_RESOURCE_MISSING)
        if config_ref.kind is not RootManagedResourceKind.TRUSTED_CONFIG:
            return {}, set(), _failure(GenesisResourceGraphFailureCode.GRAPH_RESOURCE_KIND_MISMATCH)
        if not any(item.config_id.value == config_id and item.resource.value == resource_id
                   for item in manifest.trusted_configs):
            return {}, set(), _failure(GenesisResourceGraphFailureCode.GRAPH_CONFIG_SET_MISMATCH)
        parsed = _load_json(resource_id, RootManagedResourceKind.TRUSTED_CONFIG,
                            raw_resources, resources)
        if type(parsed) is GenesisResourceGraphFailure:
            return {}, set(), parsed
        parsed_by_resource[resource_id] = parsed[1].value
        purpose_by_resource[resource_id] = purpose
        if (
            type(parsed[1].value) is not MappingProxyType
            or parsed[1].value.get("format") != expected_format
        ):
            return {}, set(), _failure(GenesisResourceGraphFailureCode.GRAPH_CONFIG_SET_MISMATCH)
        if (config_id == GENESIS_RESOURCE_GRAPH_CONFIG_ID) != (purpose == "GENESIS_RESOURCE_GRAPH"):
            return {}, set(), _failure(GenesisResourceGraphFailureCode.GRAPH_CONFIG_SET_MISMATCH)
        closed_fields = {
            "GENESIS_RESOURCE_GRAPH": _GRAPH_FIELDS,
            "MODULE_LOADING_POLICY": (
                "format", "allowed_candidate_modules", "explicitly_excluded_modules_or_prefixes",
                "third_party_runtime_policy", "dynamic_import_fallback",
            ),
        }
        for role in _ROLES:
            closed_fields.update({
                f"ENTRY_POINT_CONFIG:{role}": ("format", "role", "member_id", "runtime_artifact_resource", "module", "callable"),
                f"SECURITY_CONTEXT_CONFIG:{role}": (
                    "format", "role", "member_id", "context_id", "service_principal", "runtime_binding",
                    "runtime_generation_binding", "root_context_binding", "external_isolation_dependency_id", "channels",
                ),
                f"CAPABILITY_WIRING:{role}": (
                    "format", "role", "member_id", "canonical_state_access", "canonical_state_binding",
                    "f_read_verify_binding", "target_fence_binding", "publication_authority_binding",
                    "merge_authority_binding", "external_recovery_binding",
                ),
                f"CREDENTIAL_ROUTING:{role}": (
                    "format", "role", "member_id", "production_github_mutation_credentials",
                ),
            })
        if not _fields(parsed[1].value, closed_fields[purpose]):
            return {}, set(), _failure(GenesisResourceGraphFailureCode.GRAPH_CONFIG_SET_MISMATCH)
    if declared_pairs != manifest_pairs or seen_resources != {resource for _, resource in manifest_pairs}:
        return {}, set(), _failure(GenesisResourceGraphFailureCode.GRAPH_CONFIG_SET_MISMATCH)
    if GENESIS_RESOURCE_GRAPH_CONFIG_ID not in seen_configs:
        return {}, set(), _failure(GenesisResourceGraphFailureCode.GRAPH_CONFIG_MISSING)
    return parsed_by_resource, used_schema_ids, None


def _load_member_resource(
    resource_id: str,
    kind: RootManagedResourceKind,
    raw_resources: dict[str, bytes],
    resources: dict[str, RootManagedResourceRef],
    failure_code: GenesisResourceGraphFailureCode,
) -> MappingProxyType | GenesisResourceGraphFailure:
    loaded = _load_json(resource_id, kind, raw_resources, resources)
    if type(loaded) is GenesisResourceGraphFailure:
        if loaded.code in (
            GenesisResourceGraphFailureCode.GRAPH_RESOURCE_MISSING,
            GenesisResourceGraphFailureCode.GRAPH_RESOURCE_KIND_MISMATCH,
            GenesisResourceGraphFailureCode.GRAPH_RESOURCE_DIGEST_MISMATCH,
            GenesisResourceGraphFailureCode.GRAPH_PARSE_FAILED,
        ):
            return loaded
        return _failure(failure_code, loaded.parse_failure)
    return loaded[1].value


def _parse_external_roles(
    value: object,
    manifest: CandidateTrustedManifest,
    raw_resources: dict[str, bytes],
    resources: dict[str, RootManagedResourceRef],
) -> tuple[MappingProxyType | None, tuple[RootManagedResourceRef, ...], GenesisResourceGraphFailure | None]:
    if not _array(value) or len(value) != len(_EXTERNAL_ROLES):
        return None, (), _failure(GenesisResourceGraphFailureCode.GRAPH_EXTERNAL_TCB_MISMATCH)
    manifest_dependencies: dict[str, ExternalTcbDependency] = {}
    for item in manifest.external_tcb_dependencies:
        if type(item) is not ExternalTcbDependency or item.dependency_id.value in manifest_dependencies:
            return None, (), _failure(GenesisResourceGraphFailureCode.GRAPH_EXTERNAL_TCB_MISMATCH)
        manifest_dependencies[item.dependency_id.value] = item
    if len(manifest_dependencies) != 3:
        return None, (), _failure(GenesisResourceGraphFailureCode.GRAPH_EXTERNAL_TCB_MISMATCH)
    roles: dict[str, MappingProxyType] = {}
    seen_dependencies: set[str] = set()
    seen_assumptions: set[str] = set()
    verified: list[RootManagedResourceRef] = []
    fixture_bindings: MappingProxyType | None = None
    for record in value:
        role = record.get("role") if type(record) is MappingProxyType else None
        if role not in _EXTERNAL_ROLES or role in roles:
            return None, (), _failure(GenesisResourceGraphFailureCode.GRAPH_EXTERNAL_TCB_MISMATCH)
        expected_fields = (
            ("role", "dependency_id", "assumption_resource", "bindings")
            if role == "FIXTURE_EFFECT_SUBSTRATE"
            else ("role", "dependency_id", "assumption_resource")
        )
        if not _fields(record, expected_fields):
            return None, (), _failure(GenesisResourceGraphFailureCode.GRAPH_FORMAT_INVALID)
        dependency_id = record["dependency_id"]
        assumption_id = record["assumption_resource"]
        if not _text(dependency_id, identifier=True) or not _text(assumption_id, identifier=True):
            return None, (), _failure(GenesisResourceGraphFailureCode.GRAPH_FORMAT_INVALID)
        if dependency_id in seen_dependencies or assumption_id in seen_assumptions:
            return None, (), _failure(GenesisResourceGraphFailureCode.GRAPH_EXTERNAL_TCB_MISMATCH)
        seen_dependencies.add(dependency_id)
        seen_assumptions.add(assumption_id)
        dependency = manifest_dependencies.get(dependency_id)
        if dependency is None or dependency.assumption_resource.value != assumption_id:
            return None, (), _failure(GenesisResourceGraphFailureCode.GRAPH_EXTERNAL_TCB_MISMATCH)
        loaded = _load_json(
            assumption_id,
            RootManagedResourceKind.EXTERNAL_TCB_ASSUMPTION_DOCUMENT,
            raw_resources,
            resources,
        )
        if type(loaded) is GenesisResourceGraphFailure:
            return None, (), loaded
        assumption_ref, document = loaded
        verified.append(assumption_ref)
        assumption = document.value
        if role == "FIXTURE_EFFECT_SUBSTRATE":
            if not _fields(record["bindings"], _FIXTURE_BINDING_FIELDS):
                return None, (), _failure(GenesisResourceGraphFailureCode.GRAPH_EXTERNAL_TCB_MISMATCH)
            fixture_bindings = record["bindings"]
            if (
                not _fields(
                    assumption,
                    ("format", "role", "dependency_id", "bindings"),
                )
                or not _fields(assumption["bindings"], _FIXTURE_BINDING_FIELDS)
                or assumption["format"] != _ASSUMPTION_FORMAT
                or assumption["role"] != role
                or assumption["dependency_id"] != dependency_id
                or not _same_fields(assumption["bindings"], fixture_bindings, _FIXTURE_BINDING_FIELDS)
            ):
                return None, (), _failure(GenesisResourceGraphFailureCode.GRAPH_EXTERNAL_TCB_MISMATCH)
            values = tuple(fixture_bindings[field] for field in _FIXTURE_BINDING_FIELDS)
            if (
                fixture_bindings["f_read_verify_mode"] != "READ_ONLY"
                or any(
                    not _text(item, identifier=True) or item == "NONE"
                    for field, item in zip(_FIXTURE_BINDING_FIELDS, values, strict=True)
                    if field != "f_read_verify_mode"
                )
                or len(set(item for field, item in zip(_FIXTURE_BINDING_FIELDS, values, strict=True)
                           if field != "f_read_verify_mode")) != len(_FIXTURE_BINDING_FIELDS) - 1
            ):
                return None, (), _failure(GenesisResourceGraphFailureCode.GRAPH_EXTERNAL_TCB_MISMATCH)
        else:
            if (
                not _fields(assumption, ("format", "role", "dependency_id"))
                or assumption["format"] != _ASSUMPTION_FORMAT
                or assumption["role"] != role
                or assumption["dependency_id"] != dependency_id
            ):
                return None, (), _failure(GenesisResourceGraphFailureCode.GRAPH_EXTERNAL_TCB_MISMATCH)
        roles[role] = record
    if set(roles) != set(_EXTERNAL_ROLES) or seen_dependencies != set(manifest_dependencies):
        return None, (), _failure(GenesisResourceGraphFailureCode.GRAPH_EXTERNAL_TCB_MISMATCH)
    if fixture_bindings is None:
        return None, (), _failure(GenesisResourceGraphFailureCode.GRAPH_EXTERNAL_TCB_MISMATCH)
    return fixture_bindings, tuple(verified), None


def _validate_raw_input(
    manifest: object, resource_bytes: object
) -> tuple[
    CandidateTrustedManifest,
    dict[str, bytes],
    dict[str, RootManagedResourceRef],
    dict[str, RootManagedResourceRef],
] | GenesisResourceGraphFailure:
    if type(manifest) is not CandidateTrustedManifest:
        return _failure(GenesisResourceGraphFailureCode.GRAPH_FORMAT_INVALID)
    if manifest.kind is not ManifestKind.GENESIS or manifest.predecessor_manifest is not None:
        return _failure(GenesisResourceGraphFailureCode.GRAPH_FORMAT_INVALID)
    if type(resource_bytes) not in (dict, MappingProxyType):
        return _failure(GenesisResourceGraphFailureCode.GRAPH_FORMAT_INVALID)
    if any(not _text(key, identifier=True) or type(value) is not bytes
           for key, value in resource_bytes.items()):
        return _failure(GenesisResourceGraphFailureCode.GRAPH_FORMAT_INVALID)
    resources = _resource_index(manifest)
    raw_resources: dict[str, bytes] = {}
    total_bytes = 0
    for key in sorted(resource_bytes):
        value = resource_bytes[key]
        if key not in resources:
            return _failure(GenesisResourceGraphFailureCode.GRAPH_UNKNOWN_ORPHAN_RESOURCE)
        total_bytes += len(value)
        if total_bytes > _MAX_TOTAL_RESOURCE_BYTES:
            return _failure(GenesisResourceGraphFailureCode.GRAPH_PARSE_FAILED)
        raw_resources[key] = value
    manifest_resource_ids = set(resources)
    supplied_resource_ids = set(raw_resources)
    if supplied_resource_ids != manifest_resource_ids:
        # Unknown supplied IDs were rejected above; only missing manifest
        # resources can remain at this point.
        return _failure(GenesisResourceGraphFailureCode.GRAPH_RESOURCE_MISSING)
    verified_refs: dict[str, RootManagedResourceRef] = {}
    for resource_id in sorted(manifest_resource_ids):
        verified = _verify_raw(resource_id, raw_resources, resources)
        if type(verified) is GenesisResourceGraphFailure:
            return verified
        verified_refs[resource_id] = verified[0]
    return manifest, raw_resources, resources, verified_refs


def validate_genesis_resource_graph(
    candidate_manifest: object,
    resource_bytes: object,
) -> ValidatedGenesisResourceGraph | GenesisResourceGraphFailure:
    """Validate the reserved R4 resource graph and the complete genesis closure.

    ``resource_bytes`` is an untrusted mapping from exact manifest resource ID
    strings to raw bytes. Bytes are accepted only when their SHA-256 matches
    the exact manifest RootManagedResourceRef. Structured inputs are parsed
    from those verified bytes; caller-parsed objects are never accepted.
    """
    checked = _validate_raw_input(candidate_manifest, resource_bytes)
    if type(checked) is GenesisResourceGraphFailure:
        return checked
    manifest, raw_resources, resources, preverified_refs = checked

    graph_bindings = [
        item for item in manifest.trusted_configs
        if type(item) is TrustedConfigBinding
        and item.config_id.value == GENESIS_RESOURCE_GRAPH_CONFIG_ID
    ]
    if not graph_bindings:
        return _failure(GenesisResourceGraphFailureCode.GRAPH_CONFIG_MISSING)
    if len(graph_bindings) != 1:
        return _failure(GenesisResourceGraphFailureCode.GRAPH_CONFIG_DUPLICATE)
    graph_binding = graph_bindings[0]
    graph_id = graph_binding.resource.value
    graph_kind_failure = _expected_kind(
        graph_id, RootManagedResourceKind.TRUSTED_CONFIG, resources
    )
    if graph_kind_failure is not None:
        return graph_kind_failure
    graph_loaded = _load_json(
        graph_id, RootManagedResourceKind.TRUSTED_CONFIG, raw_resources, resources
    )
    if type(graph_loaded) is GenesisResourceGraphFailure:
        return graph_loaded
    graph_ref, graph_document = graph_loaded
    graph = graph_document.value

    if type(graph) is not MappingProxyType:
        return _failure(GenesisResourceGraphFailureCode.GRAPH_FORMAT_INVALID)
    if "build_definition_resource" not in graph:
        return _failure(GenesisResourceGraphFailureCode.GRAPH_BUILD_ROLE_MISSING)
    if "dependency_lock_resource" not in graph:
        return _failure(GenesisResourceGraphFailureCode.GRAPH_LOCK_ROLE_MISSING)
    if any(field not in graph for field in _GRAPH_FIELDS) or any(field not in _GRAPH_FIELDS for field in graph):
        return _failure(GenesisResourceGraphFailureCode.GRAPH_FORMAT_INVALID)
    if graph["format"] != GENESIS_RESOURCE_GRAPH_FORMAT or graph["genesis_scope"] != "fixture-only":
        return _failure(GenesisResourceGraphFailureCode.GRAPH_FORMAT_INVALID)

    for field in (
        "implementation_resource", "build_definition_resource", "dependency_lock_resource",
        "runtime_artifact_resource", "module_loading_policy_resource", "core_policy_resource",
        "genesis_conformance_resource",
    ):
        if not _text(graph[field], identifier=True):
            code = (
                GenesisResourceGraphFailureCode.GRAPH_BUILD_ROLE_MISSING
                if field == "build_definition_resource"
                else GenesisResourceGraphFailureCode.GRAPH_LOCK_ROLE_MISSING
                if field == "dependency_lock_resource"
                else GenesisResourceGraphFailureCode.GRAPH_FORMAT_INVALID
            )
            return _failure(code)
    if graph["core_policy_resource"] != manifest.core_policy.value:
        return _failure(GenesisResourceGraphFailureCode.GRAPH_POLICY_SET_MISMATCH)

    members, member_failure = _parse_member_records(graph["members"])
    if member_failure is not None:
        return member_failure
    member_check = _validate_manifest_members(members, manifest)
    if member_check is not None:
        return member_check
    shared_implementation = next(iter(members.values()))["implementation_resource"]
    shared_runtime = next(iter(members.values()))["runtime_artifact_resource"]
    if graph["implementation_resource"] != shared_implementation or graph["runtime_artifact_resource"] != shared_runtime:
        return _failure(GenesisResourceGraphFailureCode.GRAPH_SHARED_RESOURCE_MISMATCH)

    policy_ids = _string_array(graph["policy_resources"])
    schema_ids = _string_array(graph["trusted_schema_resources"])
    if policy_ids is None or set(policy_ids) != {item.value for item in manifest.policy_resources}:
        return _failure(GenesisResourceGraphFailureCode.GRAPH_POLICY_SET_MISMATCH)
    if schema_ids is None or set(schema_ids) != {item.value for item in manifest.trusted_schemas}:
        return _failure(GenesisResourceGraphFailureCode.GRAPH_SCHEMA_SET_MISMATCH)
    if graph["genesis_conformance_resource"] not in set(policy_ids):
        return _failure(GenesisResourceGraphFailureCode.GRAPH_POLICY_SET_MISMATCH)

    for resource_id, kind in (
        (manifest.core_policy.value, RootManagedResourceKind.CORE_POLICY),
        (graph["genesis_conformance_resource"], RootManagedResourceKind.POLICY),
        (graph["implementation_resource"], RootManagedResourceKind.TRUSTED_CODE),
        (graph["build_definition_resource"], RootManagedResourceKind.BUILD_DEFINITION),
        (graph["dependency_lock_resource"], RootManagedResourceKind.DEPENDENCY_LOCK),
        (graph["runtime_artifact_resource"], RootManagedResourceKind.RUNTIME_ARTIFACT),
        (graph["module_loading_policy_resource"], RootManagedResourceKind.MODULE_LOADING_POLICY),
    ):
        problem = _expected_kind(resource_id, kind, resources)
        if problem is not None:
            return problem
    for policy_id in policy_ids:
        problem = _expected_kind(policy_id, RootManagedResourceKind.POLICY, resources)
        if problem is not None:
            return problem
    for schema_id in schema_ids:
        problem = _expected_kind(schema_id, RootManagedResourceKind.TRUSTED_SCHEMA, resources)
        if problem is not None:
            return problem
    for role in _ROLES:
        member = members[role]
        role_kinds = (
            (member["implementation_resource"], RootManagedResourceKind.TRUSTED_CODE),
            (member["runtime_artifact_resource"], RootManagedResourceKind.RUNTIME_ARTIFACT),
            (member["entry_point_config_resource"], RootManagedResourceKind.ENTRY_POINT_CONFIG),
            (member["security_context_config_resource"], RootManagedResourceKind.SECURITY_CONTEXT_CONFIG),
            (member["capability_wiring_resource"], RootManagedResourceKind.CAPABILITY_WIRING),
            (member["credential_routing_resource"], RootManagedResourceKind.CREDENTIAL_ROUTING),
        )
        for resource_id, kind in role_kinds:
            problem = _expected_kind(resource_id, kind, resources)
            if problem is not None:
                return problem

    config_values, used_schema_ids, config_failure = _parse_config_bindings(
        graph["trusted_config_bindings"], manifest, resources, raw_resources
    )
    if config_failure is not None:
        return config_failure
    if not used_schema_ids.issubset(set(schema_ids)):
        return _failure(GenesisResourceGraphFailureCode.GRAPH_SCHEMA_SET_MISMATCH)

    module_value = _load_member_resource(
        graph["module_loading_policy_resource"],
        RootManagedResourceKind.MODULE_LOADING_POLICY,
        raw_resources,
        resources,
        GenesisResourceGraphFailureCode.GRAPH_MODULE_LOADING_MISMATCH,
    )
    if type(module_value) is GenesisResourceGraphFailure:
        return module_value
    module_failure = _check_module_policy(module_value)
    if module_failure is not None:
        return module_failure
    entry_values: dict[str, MappingProxyType] = {}
    contexts: dict[str, MappingProxyType] = {}
    wirings: dict[str, MappingProxyType] = {}
    credentials: dict[str, MappingProxyType] = {}
    for role in _ROLES:
        member = members[role]
        for resource_id, kind, bucket, code, fmt in (
            (member["entry_point_config_resource"], RootManagedResourceKind.ENTRY_POINT_CONFIG,
             entry_values, GenesisResourceGraphFailureCode.GRAPH_ENTRY_POINT_MISMATCH, _ENTRY_FORMAT),
            (member["security_context_config_resource"], RootManagedResourceKind.SECURITY_CONTEXT_CONFIG,
             contexts, GenesisResourceGraphFailureCode.GRAPH_SECURITY_CONTEXT_MISMATCH, _SECURITY_FORMAT),
            (member["capability_wiring_resource"], RootManagedResourceKind.CAPABILITY_WIRING,
             wirings, GenesisResourceGraphFailureCode.GRAPH_CAPABILITY_WIRING_MISMATCH, _WIRING_FORMAT),
            (member["credential_routing_resource"], RootManagedResourceKind.CREDENTIAL_ROUTING,
             credentials, GenesisResourceGraphFailureCode.GRAPH_CREDENTIAL_ROUTING_MISMATCH, _CREDENTIAL_FORMAT),
        ):
            parsed = _load_member_resource(resource_id, kind, raw_resources, resources, code)
            if type(parsed) is GenesisResourceGraphFailure:
                return parsed
            if type(parsed) is not MappingProxyType or parsed.get("format") != fmt:
                return _failure(code)
            bucket[resource_id] = parsed
        entry_failure = _check_entry_point(entry_values[member["entry_point_config_resource"]], member)
        if entry_failure is not None:
            return entry_failure

    fixture_bindings, verified_external, external_failure = _parse_external_roles(
        graph["external_tcb_roles"], manifest, raw_resources, resources
    )
    if external_failure is not None:
        return external_failure
    security_failure = _check_security_contexts(
        contexts, members,
        next(
            record["dependency_id"] for record in graph["external_tcb_roles"]
            if record["role"] == "EXECUTION_ISOLATION"
        ),
    )
    if security_failure is not None:
        return security_failure
    wiring_failure = _check_wirings(wirings, members, fixture_bindings)
    if wiring_failure is not None:
        return wiring_failure
    credential_failure = _check_credentials(credentials, members)
    if credential_failure is not None:
        return credential_failure
    mirror_failure = _check_config_binding_mirrors(
        config_values,
        graph["trusted_config_bindings"],
        members,
        entry_values,
        contexts,
        wirings,
        credentials,
        module_value,
    )
    if mirror_failure is not None:
        return mirror_failure

    lock_loaded = _load_lock(
        graph["dependency_lock_resource"], raw_resources, resources
    )
    if type(lock_loaded) is GenesisResourceGraphFailure:
        return lock_loaded
    lock_ref, lock_document = lock_loaded
    lock_failure = _check_lock(lock_document.value, resources, graph)
    if lock_failure is not None:
        return lock_failure

    # The R3 policy bytes are explicitly checked against the manifest's raw
    # digest; its content is not interpreted by this validator.
    conformance_verified = _verify_raw(
        graph["genesis_conformance_resource"], raw_resources, resources
    )
    if type(conformance_verified) is GenesisResourceGraphFailure:
        return conformance_verified
    conformance_ref, _ = conformance_verified

    consumed: set[str] = {
        manifest.core_policy.value,
        graph["implementation_resource"],
        graph["build_definition_resource"],
        graph["dependency_lock_resource"],
        graph["runtime_artifact_resource"],
        graph["module_loading_policy_resource"],
        graph["core_policy_resource"],
        graph["genesis_conformance_resource"],
        graph_id,
        *policy_ids,
        *schema_ids,
        *(item.resource.value for item in manifest.trusted_configs),
        *(item.assumption_resource.value for item in manifest.external_tcb_dependencies),
    }
    for member in members.values():
        consumed.update(member[field] for field in _MEMBER_FIELDS[3:])
    manifest_resource_ids = {item.resource_id.value for item in manifest.root_managed_resources}
    if consumed != manifest_resource_ids:
        return _failure(GenesisResourceGraphFailureCode.GRAPH_UNKNOWN_ORPHAN_RESOURCE)

    # Schema resource declarations are exact resources; verify their bytes
    # without interpreting schema languages or introducing a schema engine.
    verified_refs: dict[str, RootManagedResourceRef] = dict(preverified_refs)
    verified_refs.update({
        graph_ref.resource_id.value: graph_ref,
        lock_ref.resource_id.value: lock_ref,
        conformance_ref.resource_id.value: conformance_ref,
    })
    verified_refs.update({item.resource_id.value: item for item in verified_external})
    config_resource_ids = set(config_values)
    config_resource_ids.add(graph["module_loading_policy_resource"])
    for member in members.values():
        config_resource_ids.update(member[field] for field in _MEMBER_FIELDS[5:])
    for resource_id in config_resource_ids:
        reference = resources[resource_id]
        verified = _verify_raw(resource_id, raw_resources, resources)
        if type(verified) is GenesisResourceGraphFailure:
            return verified
        verified_refs[resource_id] = reference
    for schema_id in schema_ids:
        verified = _verify_raw(schema_id, raw_resources, resources)
        if type(verified) is GenesisResourceGraphFailure:
            return verified
        verified_refs[schema_id] = verified[0]

    if set(verified_refs) != consumed or consumed != manifest_resource_ids:
        return _failure(GenesisResourceGraphFailureCode.GRAPH_UNKNOWN_ORPHAN_RESOURCE)

    consumed_ids = tuple(RootManagedResourceId(value) for value in sorted(consumed))
    verified_ordered = tuple(verified_refs[key] for key in sorted(verified_refs))
    return ValidatedGenesisResourceGraph._from_validated(
        _SUCCESS_CONSTRUCTION_KEY,
        manifest_id=manifest.manifest_id,
        policy_epoch_identity=manifest.policy_epoch_identity,
        graph_resource=graph_ref,
        graph_sha256=graph_ref.sha256,
        consumed_resource_ids=consumed_ids,
        verified_resource_refs=verified_ordered,
    )
