"""Closed candidate trusted-manifest grammar with deterministic failure precedence."""

from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Callable

from .errors import IdentityValidationError, ManifestFailure, ManifestFailureCode, ParseFailure
from .identity import ImmutableConfigId, LogicalIdentifier, RawSha256
from .parsing import ParseLimits, ParsedJsonDocument, parse_trusted_json
from .resources import (
    G2_MANIFEST_MAX_BYTES,
    G2_MANIFEST_MAX_DEPTH,
    RootManagedResourceId,
    RootManagedResourceKind,
    RootManagedResourceRef,
)

_FORMAT = "autodev.trusted-manifest/v1"
_SUCCESS_CONSTRUCTION_KEY = object()
_TOP_LEVEL_FIELDS = (
    "format",
    "kind",
    "predecessor_manifest",
    "root_managed_resources",
    "core_policy",
    "policy_resources",
    "trusted_core_members",
    "trusted_schemas",
    "trusted_configs",
    "external_tcb_dependencies",
)


class ManifestKind(Enum):
    GENESIS = "genesis"
    SUCCESSOR = "successor"


@dataclass(frozen=True, slots=True)
class TrustedManifestId:
    raw_sha256: RawSha256

    def __post_init__(self) -> None:
        if type(self.raw_sha256) is not RawSha256:
            raise TypeError("raw_sha256 must be exactly RawSha256")


@dataclass(frozen=True, slots=True)
class PolicyEpochIdentity:
    manifest_id: TrustedManifestId

    def __post_init__(self) -> None:
        if type(self.manifest_id) is not TrustedManifestId:
            raise TypeError("manifest_id must be exactly TrustedManifestId")


@dataclass(frozen=True, slots=True)
class TrustedMemberId:
    value: str

    def __post_init__(self) -> None:
        LogicalIdentifier(self.value)


@dataclass(frozen=True, slots=True)
class ExternalTcbDependencyId:
    value: str

    def __post_init__(self) -> None:
        LogicalIdentifier(self.value)


@dataclass(frozen=True, slots=True)
class TrustedCoreMember:
    member_id: TrustedMemberId
    implementation_resource: RootManagedResourceId
    runtime_artifact_resource: RootManagedResourceId
    entry_point_config_resource: RootManagedResourceId

    def __post_init__(self) -> None:
        if type(self.member_id) is not TrustedMemberId:
            raise TypeError("member_id must be exactly TrustedMemberId")
        for value in (
            self.implementation_resource,
            self.runtime_artifact_resource,
            self.entry_point_config_resource,
        ):
            if type(value) is not RootManagedResourceId:
                raise TypeError("member resource references must be exactly RootManagedResourceId")


@dataclass(frozen=True, slots=True)
class TrustedConfigBinding:
    config_id: ImmutableConfigId
    resource: RootManagedResourceId

    def __post_init__(self) -> None:
        if type(self.config_id) is not ImmutableConfigId:
            raise TypeError("config_id must be exactly ImmutableConfigId")
        if type(self.resource) is not RootManagedResourceId:
            raise TypeError("resource must be exactly RootManagedResourceId")


@dataclass(frozen=True, slots=True)
class ExternalTcbDependency:
    dependency_id: ExternalTcbDependencyId
    assumption_resource: RootManagedResourceId

    def __post_init__(self) -> None:
        if type(self.dependency_id) is not ExternalTcbDependencyId:
            raise TypeError("dependency_id must be exactly ExternalTcbDependencyId")
        if type(self.assumption_resource) is not RootManagedResourceId:
            raise TypeError("assumption_resource must be exactly RootManagedResourceId")


@dataclass(frozen=True, slots=True, init=False)
class CandidateTrustedManifest:
    """Validated candidate only; construction and merge do not activate it."""

    source_document: ParsedJsonDocument
    manifest_id: TrustedManifestId
    policy_epoch_identity: PolicyEpochIdentity
    kind: ManifestKind
    predecessor_manifest: TrustedManifestId | None
    root_managed_resources: tuple[RootManagedResourceRef, ...]
    core_policy: RootManagedResourceId
    policy_resources: tuple[RootManagedResourceId, ...]
    trusted_core_members: tuple[TrustedCoreMember, ...]
    trusted_schemas: tuple[RootManagedResourceId, ...]
    trusted_configs: tuple[TrustedConfigBinding, ...]
    external_tcb_dependencies: tuple[ExternalTcbDependency, ...]

    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("use load_candidate_trusted_manifest")

    @classmethod
    def _from_validated(cls, key: object, **fields: object) -> "CandidateTrustedManifest":
        if key is not _SUCCESS_CONSTRUCTION_KEY:
            raise TypeError("internal validated construction only")
        result = object.__new__(cls)
        for name, value in fields.items():
            object.__setattr__(result, name, value)
        return result


def _failure(code: ManifestFailureCode) -> ManifestFailure:
    return ManifestFailure(code)


def _field_set(value: object, required: tuple[str, ...]) -> ManifestFailure | None:
    if type(value) is not MappingProxyType:
        return _failure(ManifestFailureCode.INVALID_FIELD_TYPE)
    if any(field not in value for field in required):
        return _failure(ManifestFailureCode.MISSING_FIELD)
    required_set = frozenset(required)
    if any(field not in required_set for field in value):
        return _failure(ManifestFailureCode.UNKNOWN_FIELD)
    return None


def _exact_string(value: object) -> bool:
    return type(value) is str


def _exact_array(value: object) -> bool:
    return type(value) is tuple


def _resource_id(value: str) -> RootManagedResourceId | None:
    try:
        return RootManagedResourceId(value)
    except IdentityValidationError:
        return None


def _resource_entry(value: object) -> RootManagedResourceRef | ManifestFailure:
    fields = ("resource_id", "kind", "sha256")
    problem = _field_set(value, fields)
    if problem is not None:
        return problem
    for field in fields:
        if not _exact_string(value[field]):
            return _failure(ManifestFailureCode.INVALID_FIELD_TYPE)
    resource_id = _resource_id(value["resource_id"])
    if resource_id is None:
        return _failure(ManifestFailureCode.INVALID_FIELD_VALUE)
    try:
        kind = RootManagedResourceKind(value["kind"])
    except ValueError:
        return _failure(ManifestFailureCode.INVALID_FIELD_VALUE)
    try:
        sha256 = RawSha256(value["sha256"])
    except IdentityValidationError:
        return _failure(ManifestFailureCode.INVALID_FIELD_VALUE)
    return RootManagedResourceRef(resource_id, kind, sha256)


def _member_entry(value: object) -> TrustedCoreMember | ManifestFailure:
    fields = (
        "member_id",
        "implementation_resource",
        "runtime_artifact_resource",
        "entry_point_config_resource",
    )
    problem = _field_set(value, fields)
    if problem is not None:
        return problem
    for field in fields:
        if not _exact_string(value[field]):
            return _failure(ManifestFailureCode.INVALID_FIELD_TYPE)
    try:
        member_id = TrustedMemberId(value["member_id"])
    except IdentityValidationError:
        return _failure(ManifestFailureCode.INVALID_FIELD_VALUE)
    references: list[RootManagedResourceId] = []
    for field in fields[1:]:
        reference = _resource_id(value[field])
        if reference is None:
            return _failure(ManifestFailureCode.INVALID_FIELD_VALUE)
        references.append(reference)
    return TrustedCoreMember(member_id, *references)


def _config_entry(value: object) -> TrustedConfigBinding | ManifestFailure:
    fields = ("config_id", "resource")
    problem = _field_set(value, fields)
    if problem is not None:
        return problem
    for field in fields:
        if not _exact_string(value[field]):
            return _failure(ManifestFailureCode.INVALID_FIELD_TYPE)
    try:
        config_id = ImmutableConfigId(value["config_id"])
    except IdentityValidationError:
        return _failure(ManifestFailureCode.INVALID_FIELD_VALUE)
    resource = _resource_id(value["resource"])
    if resource is None:
        return _failure(ManifestFailureCode.INVALID_FIELD_VALUE)
    return TrustedConfigBinding(config_id, resource)


def _dependency_entry(value: object) -> ExternalTcbDependency | ManifestFailure:
    fields = ("dependency_id", "assumption_resource")
    problem = _field_set(value, fields)
    if problem is not None:
        return problem
    for field in fields:
        if not _exact_string(value[field]):
            return _failure(ManifestFailureCode.INVALID_FIELD_TYPE)
    try:
        dependency_id = ExternalTcbDependencyId(value["dependency_id"])
    except IdentityValidationError:
        return _failure(ManifestFailureCode.INVALID_FIELD_VALUE)
    resource = _resource_id(value["assumption_resource"])
    if resource is None:
        return _failure(ManifestFailureCode.INVALID_FIELD_VALUE)
    return ExternalTcbDependency(dependency_id, resource)


def _convert_entries(
    values: tuple[object, ...], converter: Callable[[object], object | ManifestFailure]
) -> tuple[object, ...] | ManifestFailure:
    converted: list[object] = []
    for value in values:
        result = converter(value)
        if type(result) is ManifestFailure:
            return result
        converted.append(result)
    return tuple(converted)


def _convert_resource_ids(
    values: tuple[object, ...], *, reject_duplicates: bool
) -> tuple[RootManagedResourceId, ...] | ManifestFailure:
    converted: list[RootManagedResourceId] = []
    seen: set[str] = set()
    for value in values:
        if type(value) is not str:
            return _failure(ManifestFailureCode.INVALID_FIELD_TYPE)
        resource_id = _resource_id(value)
        if resource_id is None:
            return _failure(ManifestFailureCode.INVALID_FIELD_VALUE)
        if reject_duplicates and resource_id.value in seen:
            return _failure(ManifestFailureCode.DUPLICATE_IDENTITY)
        seen.add(resource_id.value)
        converted.append(resource_id)
    return tuple(converted)


def _first_duplicate(values: tuple[object, ...], key: Callable[[object], str]) -> bool:
    seen: set[str] = set()
    for value in values:
        identity = key(value)
        if identity in seen:
            return True
        seen.add(identity)
    return False


def load_candidate_trusted_manifest(raw: object) -> CandidateTrustedManifest | ManifestFailure:
    if type(raw) is not bytes:
        return _failure(ManifestFailureCode.INVALID_INPUT_TYPE)
    if len(raw) > G2_MANIFEST_MAX_BYTES:
        return _failure(ManifestFailureCode.BYTE_LIMIT_EXCEEDED)
    document = parse_trusted_json(raw, ParseLimits(G2_MANIFEST_MAX_BYTES, G2_MANIFEST_MAX_DEPTH))
    if type(document) is ParseFailure:
        return ManifestFailure(ManifestFailureCode.PARSE_FAILED, document)
    value = document.value
    if type(value) is not MappingProxyType:
        return _failure(ManifestFailureCode.INVALID_TOP_LEVEL)

    if any(field not in value for field in _TOP_LEVEL_FIELDS):
        return _failure(ManifestFailureCode.MISSING_FIELD)
    top_fields = frozenset(_TOP_LEVEL_FIELDS)
    if any(field not in top_fields for field in value):
        return _failure(ManifestFailureCode.UNKNOWN_FIELD)

    type_checks = (
        ("format", _exact_string),
        ("kind", _exact_string),
        ("predecessor_manifest", lambda item: item is None or type(item) is str),
        ("root_managed_resources", _exact_array),
        ("core_policy", _exact_string),
        ("policy_resources", _exact_array),
        ("trusted_core_members", _exact_array),
        ("trusted_schemas", _exact_array),
        ("trusted_configs", _exact_array),
        ("external_tcb_dependencies", _exact_array),
    )
    for field, check in type_checks:
        if not check(value[field]):
            return _failure(ManifestFailureCode.INVALID_FIELD_TYPE)
    if value["format"] != _FORMAT:
        return _failure(ManifestFailureCode.INVALID_FIELD_VALUE)
    try:
        kind = ManifestKind(value["kind"])
    except ValueError:
        return _failure(ManifestFailureCode.INVALID_FIELD_VALUE)

    predecessor: TrustedManifestId | None = None
    predecessor_value = value["predecessor_manifest"]
    if kind is ManifestKind.GENESIS:
        if predecessor_value is not None:
            return _failure(ManifestFailureCode.INVALID_PREDECESSOR)
    else:
        if predecessor_value is None:
            return _failure(ManifestFailureCode.INVALID_PREDECESSOR)
        try:
            predecessor = TrustedManifestId(RawSha256(predecessor_value))
        except IdentityValidationError:
            return _failure(ManifestFailureCode.INVALID_PREDECESSOR)

    core_policy = _resource_id(value["core_policy"])
    if core_policy is None:
        return _failure(ManifestFailureCode.INVALID_FIELD_VALUE)
    if not value["root_managed_resources"]:
        return _failure(ManifestFailureCode.EMPTY_REQUIRED_SET)
    if not value["trusted_core_members"]:
        return _failure(ManifestFailureCode.EMPTY_REQUIRED_SET)

    resources_result = _convert_entries(value["root_managed_resources"], _resource_entry)
    if type(resources_result) is ManifestFailure:
        return resources_result
    resources = resources_result
    if _first_duplicate(resources, lambda item: item.resource_id.value):
        return _failure(ManifestFailureCode.DUPLICATE_IDENTITY)
    if sum(item.kind is RootManagedResourceKind.CORE_POLICY for item in resources) != 1:
        return _failure(ManifestFailureCode.INVALID_FIELD_VALUE)

    policies_result = _convert_resource_ids(value["policy_resources"], reject_duplicates=True)
    if type(policies_result) is ManifestFailure:
        return policies_result
    policies = policies_result

    members_result = _convert_entries(value["trusted_core_members"], _member_entry)
    if type(members_result) is ManifestFailure:
        return members_result
    members = members_result
    if _first_duplicate(members, lambda item: item.member_id.value):
        return _failure(ManifestFailureCode.DUPLICATE_IDENTITY)

    schemas_result = _convert_resource_ids(value["trusted_schemas"], reject_duplicates=True)
    if type(schemas_result) is ManifestFailure:
        return schemas_result
    schemas = schemas_result

    configs_result = _convert_entries(value["trusted_configs"], _config_entry)
    if type(configs_result) is ManifestFailure:
        return configs_result
    configs = configs_result
    if _first_duplicate(configs, lambda item: item.config_id.value):
        return _failure(ManifestFailureCode.DUPLICATE_IDENTITY)

    dependencies_result = _convert_entries(value["external_tcb_dependencies"], _dependency_entry)
    if type(dependencies_result) is ManifestFailure:
        return dependencies_result
    dependencies = dependencies_result
    if _first_duplicate(dependencies, lambda item: item.dependency_id.value):
        return _failure(ManifestFailureCode.DUPLICATE_IDENTITY)

    resource_index = {item.resource_id.value: item for item in resources}
    reference_order = [core_policy, *policies]
    for member in members:
        reference_order.extend(
            (
                member.implementation_resource,
                member.runtime_artifact_resource,
                member.entry_point_config_resource,
            )
        )
    reference_order.extend(schemas)
    reference_order.extend(config.resource for config in configs)
    reference_order.extend(dependency.assumption_resource for dependency in dependencies)
    for reference in reference_order:
        if reference.value not in resource_index:
            return _failure(ManifestFailureCode.UNKNOWN_RESOURCE_REFERENCE)

    if resource_index[core_policy.value].kind is not RootManagedResourceKind.CORE_POLICY:
        return _failure(ManifestFailureCode.RESOURCE_KIND_MISMATCH)
    for policy in policies:
        if policy == core_policy:
            return _failure(ManifestFailureCode.INVALID_FIELD_VALUE)
        if resource_index[policy.value].kind is not RootManagedResourceKind.POLICY:
            return _failure(ManifestFailureCode.RESOURCE_KIND_MISMATCH)
    for member in members:
        member_requirements = (
            (member.implementation_resource, RootManagedResourceKind.TRUSTED_CODE),
            (member.runtime_artifact_resource, RootManagedResourceKind.RUNTIME_ARTIFACT),
            (member.entry_point_config_resource, RootManagedResourceKind.ENTRY_POINT_CONFIG),
        )
        for reference, expected_kind in member_requirements:
            if resource_index[reference.value].kind is not expected_kind:
                return _failure(ManifestFailureCode.RESOURCE_KIND_MISMATCH)
    for schema in schemas:
        if resource_index[schema.value].kind is not RootManagedResourceKind.TRUSTED_SCHEMA:
            return _failure(ManifestFailureCode.RESOURCE_KIND_MISMATCH)
    for config in configs:
        if resource_index[config.resource.value].kind is not RootManagedResourceKind.TRUSTED_CONFIG:
            return _failure(ManifestFailureCode.RESOURCE_KIND_MISMATCH)
    for dependency in dependencies:
        if (
            resource_index[dependency.assumption_resource.value].kind
            is not RootManagedResourceKind.EXTERNAL_TCB_ASSUMPTION_DOCUMENT
        ):
            return _failure(ManifestFailureCode.RESOURCE_KIND_MISMATCH)

    manifest_id = TrustedManifestId(document.raw_sha256)
    policy_epoch = PolicyEpochIdentity(manifest_id)
    return CandidateTrustedManifest._from_validated(
        _SUCCESS_CONSTRUCTION_KEY,
        source_document=document,
        manifest_id=manifest_id,
        policy_epoch_identity=policy_epoch,
        kind=kind,
        predecessor_manifest=predecessor,
        root_managed_resources=resources,
        core_policy=core_policy,
        policy_resources=policies,
        trusted_core_members=members,
        trusted_schemas=schemas,
        trusted_configs=configs,
        external_tcb_dependencies=dependencies,
    )
