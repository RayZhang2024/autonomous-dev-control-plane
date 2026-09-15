"""Exact issue-contract v1 loading, admission, applicability, and projections."""

from dataclasses import dataclass
from decimal import Decimal
from enum import Enum
import hashlib
from types import MappingProxyType

from .authorization import ContractAuthorityCeiling
from .decision import Decision
from .errors import (
    IdentityValidationError,
    IssueContractAdmissionReasonCode,
    IssueContractFailure,
    IssueContractFailureCode,
    ParseFailure,
    ParseFailureCode,
)
from .identity import GitRef, GitSha, ImmutableConfigId, LogicalIdentifier, RawSha256
from .manifest import PolicyEpochIdentity
from .operation import AuthoritativeStateBindingId
from .parsing import FrozenJsonValue, ParseLimits, ParsedJsonDocument, parse_trusted_json
from .resources import RootManagedResourceId, RootManagedResourceKind, RootManagedResourceRef
from .scope import (
    CanonicalBranchRef,
    ChangeType,
    ContractId,
    ExactPathSelector,
    GitHubRepositoryId,
    MutationScope,
    MutationScopeRule,
    ParsedMutationScope,
    PathPrefixSelector,
    RepositorySelector,
    RiskTier,
    ScopeParseProblem,
    TargetRegistrationId,
    TaskCapability,
    TaskId,
    parse_mutation_scope_json,
    selector_contains,
    selector_overlaps,
)
from .target_registration import AdmittedTargetRegistration

ISSUE_CONTRACT_MAX_BYTES = 1 * 1024 * 1024
ISSUE_CONTRACT_MAX_DEPTH = 32
SUPPORTED_ISSUE_CONTRACT_SCHEMA_VERSION = "1.0"
SUPPORTED_ISSUE_CONTRACT_SCHEMA_RAW_SHA256 = (
    "05fa0aa4a4a8efe813a0a6e03bdbe451a5c980835645190828f351919c08a51f"
)

_CANDIDATE_KEY = object()
_TRUSTED_KEY = object()
_ADMITTED_KEY = object()
_TOP_FIELDS = (
    "schema_version", "contract_id", "task_id", "context_anchor", "objective",
    "target", "scope", "requested_operations", "risk_floor", "acceptance_mode",
    "acceptance_requirements", "runtime_requirements", "repair_policy",
    "human_approval_requirements", "delegation_limits",
)


class EvaluatorMechanism(Enum):
    DETERMINISTIC = "deterministic"
    SEMANTIC = "semantic"
    CONTROLLED_RUNTIME = "controlled_runtime"
    EXTERNAL_OBSERVATION = "external_observation"
    HUMAN_APPROVAL = "human_approval"


class EffectiveRootOverlap(Enum):
    PROVEN_DISJOINT = "PROVEN_DISJOINT"
    EFFECTIVE_OVERLAP = "EFFECTIVE_OVERLAP"
    INDETERMINATE = "INDETERMINATE"


class IssueContractApplicabilityCode(Enum):
    APPLICABLE = "APPLICABLE"
    UNSUPPORTED_SCHEMA_BINDING = "UNSUPPORTED_SCHEMA_BINDING"
    TARGET_CONTEXT_UNAVAILABLE = "TARGET_CONTEXT_UNAVAILABLE"
    TARGET_REGISTRATION_MISMATCH = "TARGET_REGISTRATION_MISMATCH"
    TARGET_POLICY_EPOCH_MISMATCH = "TARGET_POLICY_EPOCH_MISMATCH"
    BASE_STATE_UNAVAILABLE = "BASE_STATE_UNAVAILABLE"
    BASE_BINDING_MISMATCH = "BASE_BINDING_MISMATCH"
    BASE_CHANGED = "BASE_CHANGED"
    ROOT_CONTEXT_UNAVAILABLE = "ROOT_CONTEXT_UNAVAILABLE"
    ROOT_CONTEXT_BINDING_MISMATCH = "ROOT_CONTEXT_BINDING_MISMATCH"
    ROOT_SCOPE_OVERLAP = "ROOT_SCOPE_OVERLAP"
    CONFIG_CONTEXT_UNAVAILABLE = "CONFIG_CONTEXT_UNAVAILABLE"
    CONFIG_POLICY_EPOCH_MISMATCH = "CONFIG_POLICY_EPOCH_MISMATCH"
    CONFIG_BINDING_CHANGED = "CONFIG_BINDING_CHANGED"
    EVALUATOR_CONFIG_MISMATCH = "EVALUATOR_CONFIG_MISMATCH"
    RUNTIME_PROFILE_NOT_APPLICABLE = "RUNTIME_PROFILE_NOT_APPLICABLE"
    REPAIR_POLICY_CONTEXT_UNAVAILABLE = "REPAIR_POLICY_CONTEXT_UNAVAILABLE"
    REPAIR_POLICY_BINDING_MISMATCH = "REPAIR_POLICY_BINDING_MISMATCH"
    REPAIR_NOT_PERMITTED = "REPAIR_NOT_PERMITTED"
    REPAIR_ATTEMPTS_NOT_PERMITTED = "REPAIR_ATTEMPTS_NOT_PERMITTED"
    APPROVAL_ENFORCEMENT_UNAVAILABLE = "APPROVAL_ENFORCEMENT_UNAVAILABLE"


@dataclass(frozen=True, slots=True)
class IssueContextAnchor:
    repository_id: GitHubRepositoryId
    issue_number: int
    issue_id: LogicalIdentifier | None


@dataclass(frozen=True, slots=True)
class ContractTargetBinding:
    target_registration_ref: ImmutableConfigId
    base_ref: GitRef
    base_sha: GitSha
    integration_ref: GitRef | None


@dataclass(frozen=True, slots=True)
class CandidateEvaluatorBinding:
    evaluation_id: LogicalIdentifier
    mechanism: EvaluatorMechanism
    evaluator_ref: ImmutableConfigId
    parameters: MappingProxyType


@dataclass(frozen=True, slots=True)
class CandidateAcceptanceRequirement:
    requirement_id: LogicalIdentifier
    statement: str
    evaluators: tuple[CandidateEvaluatorBinding, ...]


@dataclass(frozen=True, slots=True)
class CandidateHumanApprovalRequirement:
    approval_id: LogicalIdentifier
    before_operation: TaskCapability
    approval_ref: ImmutableConfigId


@dataclass(frozen=True, slots=True)
class ContractDelegationLimits:
    max_depth: int
    delegable_operations: tuple[TaskCapability, ...]
    risk_ceiling: RiskTier | None


@dataclass(frozen=True, slots=True, init=False)
class CandidateIssueContract:
    source_document: ParsedJsonDocument
    schema_version: str
    contract_id: ContractId
    task_id: TaskId
    context_anchor: IssueContextAnchor
    objective: str
    target: ContractTargetBinding
    allowed_mutation_scope: MutationScope
    prohibited_mutation_scope: MutationScope
    requested_operations: tuple[TaskCapability, ...]
    risk_floor: RiskTier
    acceptance_requirements: tuple[CandidateAcceptanceRequirement, ...]
    runtime_profile_ids: tuple[ImmutableConfigId, ...]
    repair_max_attempts: int
    human_approval_requirements: tuple[CandidateHumanApprovalRequirement, ...]
    delegation_limits: ContractDelegationLimits

    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("use load_candidate_issue_contract")


@dataclass(frozen=True, slots=True)
class TrustedConfigIdentity:
    config_id: ImmutableConfigId
    resource_id: RootManagedResourceId
    resource_sha256: RawSha256

    def __post_init__(self) -> None:
        if type(self.config_id) is not ImmutableConfigId:
            raise TypeError("config_id must be exactly ImmutableConfigId")
        if type(self.resource_id) is not RootManagedResourceId:
            raise TypeError("resource_id must be exactly RootManagedResourceId")
        if type(self.resource_sha256) is not RawSha256:
            raise TypeError("resource_sha256 must be exactly RawSha256")


@dataclass(frozen=True, slots=True, init=False)
class ResolvedTrustedConfigBinding:
    policy_epoch_identity: PolicyEpochIdentity
    config_identity: TrustedConfigIdentity

    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("trusted config resolution must come from a trusted boundary")


@dataclass(frozen=True, slots=True, init=False)
class TrustedIssueContractSchemaBinding:
    policy_epoch_identity: PolicyEpochIdentity
    schema_resource: RootManagedResourceRef
    schema_version: str

    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("schema binding must come from a trusted boundary")


@dataclass(frozen=True, slots=True, init=False)
class TrustedIssueIdentityObservation:
    repository_id: GitHubRepositoryId
    issue_number: int
    issue_id: LogicalIdentifier
    authoritative_state_binding_id: AuthoritativeStateBindingId

    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("issue identity must come from an authoritative read boundary")


@dataclass(frozen=True, slots=True, init=False)
class TrustedContractBaseObservation:
    repository_id: GitHubRepositoryId
    ref: CanonicalBranchRef
    sha: GitSha
    authoritative_state_binding_id: AuthoritativeStateBindingId

    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("base observation must come from an authoritative read boundary")


@dataclass(frozen=True, slots=True, init=False)
class TrustedContractRootContext:
    policy_epoch_identity: PolicyEpochIdentity
    repository_id: GitHubRepositoryId
    root_protected_mutation_scope: MutationScope
    determinate: bool

    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("root context must come from the trusted root boundary")


@dataclass(frozen=True, slots=True, init=False)
class TrustedEvaluatorConfigResolution:
    binding: ResolvedTrustedConfigBinding
    mechanism: EvaluatorMechanism
    parameters_valid: bool
    applicable: bool
    operational_prerequisites: tuple[TaskCapability, ...]

    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("evaluator resolution must come from a trusted config boundary")


@dataclass(frozen=True, slots=True, init=False)
class TrustedRuntimeConfigResolution:
    binding: ResolvedTrustedConfigBinding
    applicable: bool

    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("runtime resolution must come from a trusted config boundary")


@dataclass(frozen=True, slots=True, init=False)
class TrustedApprovalConfigResolution:
    binding: ResolvedTrustedConfigBinding
    applicable: bool

    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("approval resolution must come from a trusted config boundary")


@dataclass(frozen=True, slots=True, init=False)
class TrustedRepairPolicyContext:
    policy_epoch_identity: PolicyEpochIdentity
    target_registration_id: TargetRegistrationId
    task_id: TaskId
    contract_id: ContractId
    contract_raw_sha256: RawSha256
    repair_eligible: bool
    maximum_contract_repair_attempts: int

    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("repair policy context must come from a trusted policy boundary")


@dataclass(frozen=True, slots=True, init=False)
class TrustedIssueContractAdmissionContext:
    policy_epoch_identity: PolicyEpochIdentity | None
    schema_binding: TrustedIssueContractSchemaBinding | None
    resolved_target: AdmittedTargetRegistration | None
    issue_identity: TrustedIssueIdentityObservation | None
    base_observation: TrustedContractBaseObservation | None
    evaluator_resolutions: tuple[TrustedEvaluatorConfigResolution, ...] | None
    approval_resolutions: tuple[TrustedApprovalConfigResolution, ...] | None
    runtime_resolutions: tuple[TrustedRuntimeConfigResolution, ...] | None
    root_context: TrustedContractRootContext | None
    repair_policy_context: TrustedRepairPolicyContext | None
    operation_approval_enforcement_available: bool
    admission_event_identity: LogicalIdentifier

    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("admission context must come from assembled trusted resolvers")


@dataclass(frozen=True, slots=True)
class ValidatedEvaluatorParameterBinding:
    evaluation_id: LogicalIdentifier
    evaluator_ref: ImmutableConfigId
    config_identity: TrustedConfigIdentity
    parameter_value_digest: RawSha256


@dataclass(frozen=True, slots=True)
class ContractAcceptanceEvaluator:
    evaluation_id: LogicalIdentifier
    mechanism: EvaluatorMechanism
    evaluator_ref: ImmutableConfigId
    config_identity: TrustedConfigIdentity
    parameter_value_digest: RawSha256


@dataclass(frozen=True, slots=True)
class ContractAcceptanceRequirement:
    requirement_id: LogicalIdentifier
    statement: str
    evaluators: tuple[ContractAcceptanceEvaluator, ...]


@dataclass(frozen=True, slots=True)
class ContractAcceptancePlan:
    contract_id: ContractId
    contract_raw_sha256: RawSha256
    requirements: tuple[ContractAcceptanceRequirement, ...]


@dataclass(frozen=True, slots=True, init=False)
class AdmittedIssueContract:
    contract_id: ContractId
    contract_raw_sha256: RawSha256
    raw_bytes: bytes
    task_id: TaskId
    context_anchor: IssueContextAnchor
    contract_target_registration_ref: ImmutableConfigId
    target_registration_id: TargetRegistrationId
    base_ref: CanonicalBranchRef
    base_sha: GitSha
    integration_ref: CanonicalBranchRef | None
    allowed_mutation_scope: MutationScope
    prohibited_mutation_scope: MutationScope
    requested_operations: tuple[TaskCapability, ...]
    risk_floor: RiskTier
    acceptance_plan: ContractAcceptancePlan
    runtime_profile_identities: tuple[TrustedConfigIdentity, ...]
    repair_max_attempts: int
    human_approval_requirements: tuple[CandidateHumanApprovalRequirement, ...]
    delegation_limits: ContractDelegationLimits
    schema_resource_id: RootManagedResourceId
    schema_resource_sha256: RawSha256
    schema_version: str
    admission_policy_epoch_identity: PolicyEpochIdentity
    admission_event_identity: LogicalIdentifier

    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("use admit_issue_contract and Control-State persistence")


@dataclass(frozen=True, slots=True)
class IssueContractAdmissionResult:
    decision: Decision
    reason_code: IssueContractAdmissionReasonCode
    proposed_contract: AdmittedIssueContract | None = None

    def __post_init__(self) -> None:
        if self.reason_code is IssueContractAdmissionReasonCode.ADMITTED:
            if self.decision is not Decision.ALLOW or type(self.proposed_contract) is not AdmittedIssueContract:
                raise ValueError("admitted result invariant")
        elif self.decision is Decision.ALLOW or self.proposed_contract is not None:
            raise ValueError("failed admission cannot carry a contract")


@dataclass(frozen=True, slots=True, init=False)
class TrustedIssueContractApplicabilityContext:
    policy_epoch_identity: PolicyEpochIdentity | None
    schema_binding: TrustedIssueContractSchemaBinding | None
    resolved_target: AdmittedTargetRegistration | None
    base_observation: TrustedContractBaseObservation | None
    evaluator_resolutions: tuple[TrustedEvaluatorConfigResolution, ...] | None
    runtime_resolutions: tuple[TrustedRuntimeConfigResolution, ...] | None
    root_context: TrustedContractRootContext | None
    repair_policy_context: TrustedRepairPolicyContext | None
    operation_approval_enforcement_available: bool

    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("applicability context must come from assembled trusted resolvers")


@dataclass(frozen=True, slots=True)
class IssueContractApplicabilityResult:
    decision: Decision
    outcome: IssueContractApplicabilityCode


def _new_private(cls: type, key: object, expected: object, **fields: object):
    if key is not expected:
        raise TypeError("internal trusted construction only")
    result = object.__new__(cls)
    for name, value in fields.items():
        object.__setattr__(result, name, value)
    return result


def encode_contract_json_value(value: FrozenJsonValue) -> bytes:
    """Encode one G1 frozen JSON value using the frozen contract subvalue format."""
    if value is None:
        return b"\x00"
    if type(value) is bool:
        return b"\x02" if value else b"\x01"
    if type(value) is str:
        payload = value.encode("utf-8")
        return b"\x03" + len(payload).to_bytes(8, "big") + payload
    if type(value) is Decimal:
        if not value.is_finite():
            raise ValueError("contract numbers must be finite")
        number = value.as_tuple()
        exponent = number.exponent
        if type(exponent) is not int or not -(1 << 63) <= exponent < (1 << 63):
            raise ValueError("decimal exponent cannot be encoded as int64")
        digits = bytes(number.digits)
        return (
            b"\x04" + bytes((number.sign,)) + len(digits).to_bytes(8, "big")
            + digits + exponent.to_bytes(8, "big", signed=True)
        )
    if type(value) is tuple:
        encoded = [encode_contract_json_value(item) for item in value]
        return b"\x05" + len(encoded).to_bytes(8, "big") + b"".join(
            len(item).to_bytes(8, "big") + item for item in encoded
        )
    if type(value) is MappingProxyType:
        members: list[tuple[bytes, bytes]] = []
        for key, item in value.items():
            if type(key) is not str:
                raise TypeError("contract JSON object keys must be strings")
            key_bytes = key.encode("utf-8")
            members.append((key_bytes, encode_contract_json_value(item)))
        members.sort(key=lambda pair: pair[0])
        return b"\x06" + len(members).to_bytes(8, "big") + b"".join(
            len(key).to_bytes(8, "big") + key + len(item).to_bytes(8, "big") + item
            for key, item in members
        )
    raise TypeError("value must be exactly a G1 FrozenJsonValue")


def contract_json_value_digest(value: FrozenJsonValue) -> RawSha256:
    payload = b"autodev.contract-json-value/v1\0" + encode_contract_json_value(value)
    return RawSha256(hashlib.sha256(payload).hexdigest())


def _failure(code: IssueContractFailureCode, parse: ParseFailure | None = None) -> IssueContractFailure:
    return IssueContractFailure(code, parse)


def _field_set(value: MappingProxyType, required: tuple[str, ...], optional: tuple[str, ...] = ()) -> IssueContractFailure | None:
    if any(field not in value for field in required):
        return _failure(IssueContractFailureCode.MISSING_FIELD)
    allowed = frozenset(required + optional)
    if any(field not in allowed for field in value):
        return _failure(IssueContractFailureCode.UNKNOWN_FIELD)
    return None


def _nested_shape(value: object, required: tuple[str, ...], optional: tuple[str, ...] = ()) -> IssueContractFailure | None:
    if type(value) is not MappingProxyType:
        return None
    return _field_set(value, required, optional)


def _shape(document: MappingProxyType) -> IssueContractFailure | None:
    problem = _field_set(document, _TOP_FIELDS)
    if problem is not None:
        return problem
    objects = (
        (document["context_anchor"], ("repository_id", "issue_number"), ("issue_id",)),
        (document["target"], ("target_registration_id", "base_ref", "base_sha"), ("integration_ref",)),
        (document["scope"], ("object_model", "allowed_changes", "prohibited_changes"), ()),
        (document["runtime_requirements"], ("allowed_profile_ids",), ()),
        (document["repair_policy"], ("max_attempts",), ()),
        (document["delegation_limits"], ("max_depth", "delegable_operations"), ("risk_ceiling",)),
    )
    for value, required, optional in objects:
        problem = _nested_shape(value, required, optional)
        if problem is not None:
            return problem
    scope = document["scope"]
    if type(scope) is MappingProxyType:
        for collection_name in ("allowed_changes", "prohibited_changes"):
            collection = scope.get(collection_name)
            if type(collection) is tuple:
                for rule in collection:
                    problem = _nested_shape(rule, ("selector", "change_types"))
                    if problem is not None:
                        return problem
                    if type(rule) is MappingProxyType:
                        selector = rule.get("selector")
                        if type(selector) is MappingProxyType:
                            if "kind" not in selector:
                                return _failure(IssueContractFailureCode.MISSING_FIELD)
                            kind = selector.get("kind")
                            expected = {
                                "repository": ("kind",),
                                "exact_path": ("kind", "path"),
                                "path_prefix": ("kind", "path_prefix"),
                            }.get(kind)
                            if expected is None:
                                if any(key not in ("kind", "path", "path_prefix") for key in selector):
                                    return _failure(IssueContractFailureCode.UNKNOWN_FIELD)
                            else:
                                problem = _field_set(selector, expected)
                                if problem is not None:
                                    return problem
    requirements = document["acceptance_requirements"]
    if type(requirements) is tuple:
        for requirement in requirements:
            problem = _nested_shape(requirement, ("requirement_id", "statement", "evaluation_mode", "evaluators"))
            if problem is not None:
                return problem
            if type(requirement) is MappingProxyType and type(requirement.get("evaluators")) is tuple:
                for evaluator in requirement["evaluators"]:
                    problem = _nested_shape(evaluator, ("evaluation_id", "mechanism", "evaluator_ref", "parameters"))
                    if problem is not None:
                        return problem
    approvals = document["human_approval_requirements"]
    if type(approvals) is tuple:
        for approval in approvals:
            problem = _nested_shape(approval, ("approval_id", "before_operation", "approval_ref"))
            if problem is not None:
                return problem
    return None


def _types(document: MappingProxyType) -> IssueContractFailure | None:
    expected = (
        ("schema_version", str), ("contract_id", str), ("task_id", str),
        ("context_anchor", MappingProxyType), ("objective", str),
        ("target", MappingProxyType), ("scope", MappingProxyType),
        ("requested_operations", tuple), ("risk_floor", str), ("acceptance_mode", str),
        ("acceptance_requirements", tuple), ("runtime_requirements", MappingProxyType),
        ("repair_policy", MappingProxyType), ("human_approval_requirements", tuple),
        ("delegation_limits", MappingProxyType),
    )
    for name, kind in expected:
        if type(document[name]) is not kind:
            return _failure(IssueContractFailureCode.INVALID_FIELD_TYPE)
    context = document["context_anchor"]
    for name, kind in (("repository_id", str), ("issue_number", Decimal)):
        if type(context[name]) is not kind:
            return _failure(IssueContractFailureCode.INVALID_FIELD_TYPE)
    if "issue_id" in context and type(context["issue_id"]) is not str:
        return _failure(IssueContractFailureCode.INVALID_FIELD_TYPE)
    target = document["target"]
    for name in ("target_registration_id", "base_ref", "base_sha"):
        if type(target[name]) is not str:
            return _failure(IssueContractFailureCode.INVALID_FIELD_TYPE)
    if "integration_ref" in target and type(target["integration_ref"]) is not str:
        return _failure(IssueContractFailureCode.INVALID_FIELD_TYPE)
    scope = document["scope"]
    if type(scope["object_model"]) is not str:
        return _failure(IssueContractFailureCode.INVALID_FIELD_TYPE)
    for collection_name in ("allowed_changes", "prohibited_changes"):
        collection = scope[collection_name]
        if type(collection) is not tuple:
            return _failure(IssueContractFailureCode.INVALID_FIELD_TYPE)
        for rule in collection:
            if type(rule) is not MappingProxyType:
                return _failure(IssueContractFailureCode.INVALID_FIELD_TYPE)
            if type(rule["selector"]) is not MappingProxyType or type(rule["change_types"]) is not tuple:
                return _failure(IssueContractFailureCode.INVALID_FIELD_TYPE)
            selector = rule["selector"]
            if type(selector["kind"]) is not str:
                return _failure(IssueContractFailureCode.INVALID_FIELD_TYPE)
            if "path" in selector and type(selector["path"]) is not str:
                return _failure(IssueContractFailureCode.INVALID_FIELD_TYPE)
            if "path_prefix" in selector and type(selector["path_prefix"]) is not str:
                return _failure(IssueContractFailureCode.INVALID_FIELD_TYPE)
            if any(type(change) is not str for change in rule["change_types"]):
                return _failure(IssueContractFailureCode.INVALID_FIELD_TYPE)
    if any(type(item) is not str for item in document["requested_operations"]):
        return _failure(IssueContractFailureCode.INVALID_FIELD_TYPE)
    for requirement in document["acceptance_requirements"]:
        if type(requirement) is not MappingProxyType:
            return _failure(IssueContractFailureCode.INVALID_FIELD_TYPE)
        for name in ("requirement_id", "statement", "evaluation_mode"):
            if type(requirement[name]) is not str:
                return _failure(IssueContractFailureCode.INVALID_FIELD_TYPE)
        if type(requirement["evaluators"]) is not tuple:
            return _failure(IssueContractFailureCode.INVALID_FIELD_TYPE)
        for evaluator in requirement["evaluators"]:
            if type(evaluator) is not MappingProxyType:
                return _failure(IssueContractFailureCode.INVALID_FIELD_TYPE)
            for name in ("evaluation_id", "mechanism", "evaluator_ref"):
                if type(evaluator[name]) is not str:
                    return _failure(IssueContractFailureCode.INVALID_FIELD_TYPE)
            if type(evaluator["parameters"]) is not MappingProxyType:
                return _failure(IssueContractFailureCode.INVALID_FIELD_TYPE)
    runtime = document["runtime_requirements"]["allowed_profile_ids"]
    if type(runtime) is not tuple or any(type(item) is not str for item in runtime):
        return _failure(IssueContractFailureCode.INVALID_FIELD_TYPE)
    if type(document["repair_policy"]["max_attempts"]) is not Decimal:
        return _failure(IssueContractFailureCode.INVALID_FIELD_TYPE)
    for approval in document["human_approval_requirements"]:
        if type(approval) is not MappingProxyType:
            return _failure(IssueContractFailureCode.INVALID_FIELD_TYPE)
        if any(type(approval[name]) is not str for name in ("approval_id", "before_operation", "approval_ref")):
            return _failure(IssueContractFailureCode.INVALID_FIELD_TYPE)
    delegation = document["delegation_limits"]
    if type(delegation["max_depth"]) is not Decimal or type(delegation["delegable_operations"]) is not tuple:
        return _failure(IssueContractFailureCode.INVALID_FIELD_TYPE)
    if any(type(item) is not str for item in delegation["delegable_operations"]):
        return _failure(IssueContractFailureCode.INVALID_FIELD_TYPE)
    if "risk_ceiling" in delegation and type(delegation["risk_ceiling"]) is not str:
        return _failure(IssueContractFailureCode.INVALID_FIELD_TYPE)
    return None


def _integer(value: Decimal) -> int | None:
    if value.is_finite() and value == value.to_integral_value():
        return int(value)
    return None


def _identity(kind: type, value: str):
    try:
        return kind(value)
    except (IdentityValidationError, ValueError):
        return None


def _scope_value(value: tuple) -> ParsedMutationScope | IssueContractFailure:
    if len(value) > 1024:
        return _failure(IssueContractFailureCode.INVALID_FIELD_VALUE)
    parsed = parse_mutation_scope_json(value, defer_duplicates=True)
    if type(parsed) is ScopeParseProblem:
        code = {
            "type": IssueContractFailureCode.INVALID_FIELD_TYPE,
            "missing": IssueContractFailureCode.MISSING_FIELD,
            "unknown": IssueContractFailureCode.UNKNOWN_FIELD,
            "value": IssueContractFailureCode.INVALID_FIELD_VALUE,
            "empty": IssueContractFailureCode.EMPTY_REQUIRED_SET,
            "duplicate": IssueContractFailureCode.DUPLICATE_IDENTITY,
        }[parsed.kind]
        return _failure(code)
    assert type(parsed) is ParsedMutationScope
    return parsed


def load_candidate_issue_contract(raw: object) -> CandidateIssueContract | IssueContractFailure:
    if type(raw) is not bytes:
        return _failure(IssueContractFailureCode.INVALID_INPUT_TYPE)
    if len(raw) > ISSUE_CONTRACT_MAX_BYTES:
        return _failure(IssueContractFailureCode.BYTE_LIMIT_EXCEEDED)
    document = parse_trusted_json(raw, ParseLimits(ISSUE_CONTRACT_MAX_BYTES, ISSUE_CONTRACT_MAX_DEPTH))
    if type(document) is ParseFailure:
        return _failure(IssueContractFailureCode.PARSE_FAILED, document)
    if type(document.value) is not MappingProxyType:
        return _failure(IssueContractFailureCode.INVALID_TOP_LEVEL)
    problem = _shape(document.value)
    if problem is not None:
        return problem
    problem = _types(document.value)
    if problem is not None:
        return problem
    value = document.value
    context = value["context_anchor"]
    target_value = value["target"]
    scope_value = value["scope"]
    runtime_value = value["runtime_requirements"]
    repair_value = value["repair_policy"]
    delegation_value = value["delegation_limits"]

    # Value validation follows frozen top-level and nested field order.
    if value["schema_version"] != SUPPORTED_ISSUE_CONTRACT_SCHEMA_VERSION:
        return _failure(IssueContractFailureCode.INVALID_FIELD_VALUE)
    contract_id = _identity(ContractId, value["contract_id"])
    task_id = _identity(TaskId, value["task_id"])
    repository_id = _identity(GitHubRepositoryId, context["repository_id"])
    issue_number = _integer(context["issue_number"])
    issue_id = None if "issue_id" not in context else _identity(LogicalIdentifier, context["issue_id"])
    if contract_id is None or task_id is None or repository_id is None or issue_number is None or issue_number < 1 or ("issue_id" in context and issue_id is None):
        return _failure(IssueContractFailureCode.INVALID_FIELD_VALUE)
    if not 1 <= len(value["objective"]) <= 16384:
        return _failure(IssueContractFailureCode.INVALID_FIELD_VALUE)
    target_ref = _identity(ImmutableConfigId, target_value["target_registration_id"])
    base_ref = _identity(GitRef, target_value["base_ref"])
    base_sha = _identity(GitSha, target_value["base_sha"])
    integration_ref = None if "integration_ref" not in target_value else _identity(GitRef, target_value["integration_ref"])
    if target_ref is None or base_ref is None or base_sha is None or ("integration_ref" in target_value and integration_ref is None):
        return _failure(IssueContractFailureCode.INVALID_FIELD_VALUE)
    if scope_value["object_model"] != "regular_file_only":
        return _failure(IssueContractFailureCode.INVALID_FIELD_VALUE)
    allowed = _scope_value(scope_value["allowed_changes"])
    prohibited = _scope_value(scope_value["prohibited_changes"])
    if type(allowed) is IssueContractFailure:
        return allowed
    if type(prohibited) is IssueContractFailure:
        return prohibited
    if not 1 <= len(value["requested_operations"]) <= 16:
        return _failure(IssueContractFailureCode.EMPTY_REQUIRED_SET if not value["requested_operations"] else IssueContractFailureCode.INVALID_FIELD_VALUE)
    try:
        requested = tuple(TaskCapability(item) for item in value["requested_operations"])
        risk_floor = RiskTier(value["risk_floor"])
    except ValueError:
        return _failure(IssueContractFailureCode.INVALID_FIELD_VALUE)
    if value["acceptance_mode"] != "all":
        return _failure(IssueContractFailureCode.INVALID_FIELD_VALUE)
    if not 1 <= len(value["acceptance_requirements"]) <= 1024:
        return _failure(IssueContractFailureCode.EMPTY_REQUIRED_SET if not value["acceptance_requirements"] else IssueContractFailureCode.INVALID_FIELD_VALUE)
    requirements: list[CandidateAcceptanceRequirement] = []
    for requirement in value["acceptance_requirements"]:
        requirement_id = _identity(LogicalIdentifier, requirement["requirement_id"])
        if requirement_id is None or not 1 <= len(requirement["statement"]) <= 16384 or requirement["evaluation_mode"] != "all":
            return _failure(IssueContractFailureCode.INVALID_FIELD_VALUE)
        if not 1 <= len(requirement["evaluators"]) <= 16:
            return _failure(IssueContractFailureCode.EMPTY_REQUIRED_SET if not requirement["evaluators"] else IssueContractFailureCode.INVALID_FIELD_VALUE)
        evaluators: list[CandidateEvaluatorBinding] = []
        for evaluator in requirement["evaluators"]:
            evaluation_id = _identity(LogicalIdentifier, evaluator["evaluation_id"])
            evaluator_ref = _identity(ImmutableConfigId, evaluator["evaluator_ref"])
            try:
                mechanism = EvaluatorMechanism(evaluator["mechanism"])
            except ValueError:
                return _failure(IssueContractFailureCode.INVALID_FIELD_VALUE)
            if evaluation_id is None or evaluator_ref is None or len(evaluator["parameters"]) > 64:
                return _failure(IssueContractFailureCode.INVALID_FIELD_VALUE)
            evaluators.append(CandidateEvaluatorBinding(evaluation_id, mechanism, evaluator_ref, evaluator["parameters"]))
        requirements.append(CandidateAcceptanceRequirement(requirement_id, requirement["statement"], tuple(evaluators)))
    if len(runtime_value["allowed_profile_ids"]) > 64:
        return _failure(IssueContractFailureCode.INVALID_FIELD_VALUE)
    runtime_profiles: list[ImmutableConfigId] = []
    for item in runtime_value["allowed_profile_ids"]:
        identity = _identity(ImmutableConfigId, item)
        if identity is None:
            return _failure(IssueContractFailureCode.INVALID_FIELD_VALUE)
        runtime_profiles.append(identity)
    repair_max = _integer(repair_value["max_attempts"])
    if repair_max is None or repair_max < 0:
        return _failure(IssueContractFailureCode.INVALID_FIELD_VALUE)
    if len(value["human_approval_requirements"]) > 64:
        return _failure(IssueContractFailureCode.INVALID_FIELD_VALUE)
    approvals: list[CandidateHumanApprovalRequirement] = []
    for approval in value["human_approval_requirements"]:
        approval_id = _identity(LogicalIdentifier, approval["approval_id"])
        approval_ref = _identity(ImmutableConfigId, approval["approval_ref"])
        try:
            before = TaskCapability(approval["before_operation"])
        except ValueError:
            return _failure(IssueContractFailureCode.INVALID_FIELD_VALUE)
        if approval_id is None or approval_ref is None:
            return _failure(IssueContractFailureCode.INVALID_FIELD_VALUE)
        approvals.append(CandidateHumanApprovalRequirement(approval_id, before, approval_ref))
    depth = _integer(delegation_value["max_depth"])
    if depth is None or not 0 <= depth <= 64 or len(delegation_value["delegable_operations"]) > 16:
        return _failure(IssueContractFailureCode.INVALID_FIELD_VALUE)
    delegable: list[TaskCapability] = []
    try:
        delegable = [TaskCapability(item) for item in delegation_value["delegable_operations"]]
        delegation_risk = None if "risk_ceiling" not in delegation_value else RiskTier(delegation_value["risk_ceiling"])
    except ValueError:
        return _failure(IssueContractFailureCode.INVALID_FIELD_VALUE)

    # Duplicate identities follow complete lexical/value validation.
    identity_sets = (
        requested,
        tuple(item.requirement_id for item in requirements),
        tuple(evaluator.evaluation_id for requirement in requirements for evaluator in requirement.evaluators),
        tuple(runtime_profiles),
        tuple(item.approval_id for item in approvals),
        tuple(delegable),
    )
    if allowed.has_duplicates or prohibited.has_duplicates or any(len(items) != len(set(items)) for items in identity_sets):
        return _failure(IssueContractFailureCode.DUPLICATE_IDENTITY)

    # Cross-field consistency is intentionally last.
    requested_set = frozenset(requested)
    if TaskCapability.MERGE in requested_set and integration_ref is None:
        return _failure(IssueContractFailureCode.INCONSISTENT_CONFIGURATION)
    if (TaskCapability.CONTROLLED_RUNTIME in requested_set) != bool(runtime_profiles):
        return _failure(IssueContractFailureCode.EMPTY_REQUIRED_SET if TaskCapability.CONTROLLED_RUNTIME in requested_set else IssueContractFailureCode.INCONSISTENT_CONFIGURATION)
    if (TaskCapability.REPAIR in requested_set) != (repair_max >= 1):
        return _failure(IssueContractFailureCode.INCONSISTENT_CONFIGURATION)
    if depth == 0 and (delegable or delegation_risk is not None):
        return _failure(IssueContractFailureCode.INCONSISTENT_CONFIGURATION)
    if depth > 0 and (not delegable or delegation_risk is None):
        return _failure(IssueContractFailureCode.EMPTY_REQUIRED_SET if not delegable else IssueContractFailureCode.INCONSISTENT_CONFIGURATION)
    return _new_private(
        CandidateIssueContract, _CANDIDATE_KEY, _CANDIDATE_KEY,
        source_document=document, schema_version=value["schema_version"], contract_id=contract_id,
        task_id=task_id, context_anchor=IssueContextAnchor(repository_id, issue_number, issue_id),
        objective=value["objective"], target=ContractTargetBinding(target_ref, base_ref, base_sha, integration_ref),
        allowed_mutation_scope=MutationScope(allowed.rules), prohibited_mutation_scope=MutationScope(prohibited.rules),
        requested_operations=requested, risk_floor=risk_floor, acceptance_requirements=tuple(requirements),
        runtime_profile_ids=tuple(runtime_profiles), repair_max_attempts=repair_max,
        human_approval_requirements=tuple(approvals),
        delegation_limits=ContractDelegationLimits(depth, tuple(delegable), delegation_risk),
    )


def evaluate_effective_root_overlap(
    allowed_scope: MutationScope,
    prohibited_scope: MutationScope,
    root_protected_scope: MutationScope,
) -> EffectiveRootOverlap:
    if any(type(value) is not MutationScope for value in (allowed_scope, prohibited_scope, root_protected_scope)):
        return EffectiveRootOverlap.INDETERMINATE
    for allowed_rule in allowed_scope.rules:
        for root_rule in root_protected_scope.rules:
            common = tuple(change for change in allowed_rule.change_types if change in root_rule.change_types)
            if not common or not selector_overlaps(allowed_rule.selector, root_rule.selector):
                continue
            if selector_contains(allowed_rule.selector, root_rule.selector):
                intersection = root_rule.selector
            elif selector_contains(root_rule.selector, allowed_rule.selector):
                intersection = allowed_rule.selector
            else:
                return EffectiveRootOverlap.INDETERMINATE
            for change in common:
                if not any(
                    change in prohibition.change_types
                    and selector_contains(prohibition.selector, intersection)
                    for prohibition in prohibited_scope.rules
                ):
                    return EffectiveRootOverlap.EFFECTIVE_OVERLAP
    return EffectiveRootOverlap.PROVEN_DISJOINT


def _admission_result(
    reason: IssueContractAdmissionReasonCode,
    contract: AdmittedIssueContract | None = None,
) -> IssueContractAdmissionResult:
    unavailable = {
        IssueContractAdmissionReasonCode.SCHEMA_CONTEXT_UNAVAILABLE,
        IssueContractAdmissionReasonCode.UNSUPPORTED_SCHEMA_BINDING,
        IssueContractAdmissionReasonCode.POLICY_CONTEXT_UNAVAILABLE,
        IssueContractAdmissionReasonCode.TARGET_CONTEXT_UNAVAILABLE,
        IssueContractAdmissionReasonCode.CONTEXT_ANCHOR_UNAVAILABLE,
        IssueContractAdmissionReasonCode.BASE_STATE_UNAVAILABLE,
        IssueContractAdmissionReasonCode.CONFIG_CONTEXT_UNAVAILABLE,
        IssueContractAdmissionReasonCode.ROOT_CONTEXT_UNAVAILABLE,
        IssueContractAdmissionReasonCode.REPAIR_POLICY_CONTEXT_UNAVAILABLE,
        IssueContractAdmissionReasonCode.APPROVAL_ENFORCEMENT_UNAVAILABLE,
        IssueContractAdmissionReasonCode.UNSUPPORTED_REF_MODEL,
        IssueContractAdmissionReasonCode.ROOT_SCOPE_INDETERMINATE,
    }
    decision = Decision.ALLOW if reason is IssueContractAdmissionReasonCode.ADMITTED else (
        Decision.ESCALATE if reason in unavailable else Decision.DENY
    )
    return IssueContractAdmissionResult(decision, reason, contract)


def _schema_supported(binding: TrustedIssueContractSchemaBinding) -> bool:
    return (
        binding.schema_version == SUPPORTED_ISSUE_CONTRACT_SCHEMA_VERSION
        and binding.schema_resource.kind is RootManagedResourceKind.TRUSTED_SCHEMA
        and binding.schema_resource.sha256.value == SUPPORTED_ISSUE_CONTRACT_SCHEMA_RAW_SHA256
    )


def _by_config_id(values: tuple, expected_type: type) -> dict[ImmutableConfigId, object] | None:
    result: dict[ImmutableConfigId, object] = {}
    for value in values:
        if type(value) is not expected_type:
            return None
        identity = value.binding.config_identity.config_id
        if identity in result:
            return None
        result[identity] = value
    return result


def admit_issue_contract(
    candidate: CandidateIssueContract,
    context: TrustedIssueContractAdmissionContext,
) -> IssueContractAdmissionResult:
    if type(candidate) is not CandidateIssueContract or type(context) is not TrustedIssueContractAdmissionContext:
        raise TypeError("validated candidate and assembled trusted context required")

    # Frozen availability precedence (1-8).
    if context.schema_binding is None:
        return _admission_result(IssueContractAdmissionReasonCode.SCHEMA_CONTEXT_UNAVAILABLE)
    if context.policy_epoch_identity is None:
        return _admission_result(IssueContractAdmissionReasonCode.POLICY_CONTEXT_UNAVAILABLE)
    if context.resolved_target is None:
        return _admission_result(IssueContractAdmissionReasonCode.TARGET_CONTEXT_UNAVAILABLE)
    if context.issue_identity is None:
        return _admission_result(IssueContractAdmissionReasonCode.CONTEXT_ANCHOR_UNAVAILABLE)
    if context.base_observation is None:
        return _admission_result(IssueContractAdmissionReasonCode.BASE_STATE_UNAVAILABLE)
    if context.evaluator_resolutions is None or context.approval_resolutions is None or context.runtime_resolutions is None:
        return _admission_result(IssueContractAdmissionReasonCode.CONFIG_CONTEXT_UNAVAILABLE)
    evaluator_map = _by_config_id(context.evaluator_resolutions, TrustedEvaluatorConfigResolution)
    approval_map = _by_config_id(context.approval_resolutions, TrustedApprovalConfigResolution)
    runtime_map = _by_config_id(context.runtime_resolutions, TrustedRuntimeConfigResolution)
    if evaluator_map is None or approval_map is None or runtime_map is None:
        return _admission_result(IssueContractAdmissionReasonCode.CONFIG_CONTEXT_UNAVAILABLE)
    expected_evaluator_refs = {item.evaluator_ref for requirement in candidate.acceptance_requirements for item in requirement.evaluators}
    expected_approval_refs = {item.approval_ref for item in candidate.human_approval_requirements}
    expected_runtime_refs = set(candidate.runtime_profile_ids)
    if not expected_evaluator_refs.issubset(evaluator_map) or not expected_approval_refs.issubset(approval_map) or not expected_runtime_refs.issubset(runtime_map):
        return _admission_result(IssueContractAdmissionReasonCode.CONFIG_CONTEXT_UNAVAILABLE)
    if context.root_context is None:
        return _admission_result(IssueContractAdmissionReasonCode.ROOT_CONTEXT_UNAVAILABLE)
    if TaskCapability.REPAIR in candidate.requested_operations and context.repair_policy_context is None:
        return _admission_result(IssueContractAdmissionReasonCode.REPAIR_POLICY_CONTEXT_UNAVAILABLE)

    epoch = context.policy_epoch_identity
    schema = context.schema_binding
    target = context.resolved_target
    root = context.root_context
    base = context.base_observation
    # Frozen semantic precedence (9-20).
    if schema.policy_epoch_identity != epoch:
        return _admission_result(IssueContractAdmissionReasonCode.SCHEMA_BINDING_MISMATCH)
    if not _schema_supported(schema):
        return _admission_result(IssueContractAdmissionReasonCode.UNSUPPORTED_SCHEMA_BINDING)
    issue = context.issue_identity
    if (
        issue.repository_id != candidate.context_anchor.repository_id
        or issue.issue_number != candidate.context_anchor.issue_number
        or (candidate.context_anchor.issue_id is not None and issue.issue_id != candidate.context_anchor.issue_id)
    ):
        return _admission_result(IssueContractAdmissionReasonCode.CONTEXT_ANCHOR_MISMATCH)
    if candidate.target.target_registration_ref.value != target.target_registration_id.raw_sha256.value:
        return _admission_result(IssueContractAdmissionReasonCode.TARGET_REGISTRATION_MISMATCH)
    if target.policy_epoch_identity != epoch:
        return _admission_result(IssueContractAdmissionReasonCode.TARGET_POLICY_EPOCH_MISMATCH)
    if root.policy_epoch_identity != epoch or root.repository_id != target.repository_id:
        return _admission_result(IssueContractAdmissionReasonCode.ROOT_CONTEXT_BINDING_MISMATCH)
    try:
        base_ref = CanonicalBranchRef(candidate.target.base_ref.value)
        integration_ref = None if candidate.target.integration_ref is None else CanonicalBranchRef(candidate.target.integration_ref.value)
    except ValueError:
        return _admission_result(IssueContractAdmissionReasonCode.UNSUPPORTED_REF_MODEL)
    if base.repository_id != target.repository_id or base.ref != base_ref or base.sha != candidate.target.base_sha:
        return _admission_result(IssueContractAdmissionReasonCode.BASE_BINDING_MISMATCH)
    if not root.determinate:
        return _admission_result(IssueContractAdmissionReasonCode.ROOT_SCOPE_INDETERMINATE)
    root_result = evaluate_effective_root_overlap(
        candidate.allowed_mutation_scope,
        candidate.prohibited_mutation_scope,
        root.root_protected_mutation_scope,
    )
    if root_result is EffectiveRootOverlap.INDETERMINATE:
        return _admission_result(IssueContractAdmissionReasonCode.ROOT_SCOPE_INDETERMINATE)
    if root_result is EffectiveRootOverlap.EFFECTIVE_OVERLAP:
        return _admission_result(IssueContractAdmissionReasonCode.ROOT_SCOPE_OVERLAP)

    # Evaluator/config checks (21-25), preserving contract source order.
    plan_requirements: list[ContractAcceptanceRequirement] = []
    for requirement in candidate.acceptance_requirements:
        plan_evaluators: list[ContractAcceptanceEvaluator] = []
        for evaluator in requirement.evaluators:
            resolution = evaluator_map[evaluator.evaluator_ref]
            assert type(resolution) is TrustedEvaluatorConfigResolution
            if resolution.binding.policy_epoch_identity != epoch:
                return _admission_result(IssueContractAdmissionReasonCode.CONFIG_POLICY_EPOCH_MISMATCH)
            if resolution.binding.config_identity.config_id != evaluator.evaluator_ref:
                return _admission_result(IssueContractAdmissionReasonCode.CONFIG_BINDING_CHANGED)
            if resolution.mechanism is not evaluator.mechanism or not resolution.applicable:
                return _admission_result(IssueContractAdmissionReasonCode.EVALUATOR_CONFIG_MISMATCH)
            if not resolution.parameters_valid:
                return _admission_result(IssueContractAdmissionReasonCode.EVALUATOR_PARAMETERS_INVALID)
            if not set(resolution.operational_prerequisites).issubset(candidate.requested_operations):
                return _admission_result(IssueContractAdmissionReasonCode.EVALUATOR_OPERATION_OUTSIDE_CONTRACT)
            digest = contract_json_value_digest(evaluator.parameters)
            plan_evaluators.append(ContractAcceptanceEvaluator(
                evaluator.evaluation_id, evaluator.mechanism, evaluator.evaluator_ref,
                resolution.binding.config_identity, digest,
            ))
        plan_requirements.append(ContractAcceptanceRequirement(
            requirement.requirement_id, requirement.statement, tuple(plan_evaluators)
        ))

    # Runtime config checks (26-28).
    runtime_identities: list[TrustedConfigIdentity] = []
    for profile_id in candidate.runtime_profile_ids:
        resolution = runtime_map[profile_id]
        assert type(resolution) is TrustedRuntimeConfigResolution
        if resolution.binding.policy_epoch_identity != epoch:
            return _admission_result(IssueContractAdmissionReasonCode.CONFIG_POLICY_EPOCH_MISMATCH)
        if resolution.binding.config_identity.config_id != profile_id:
            return _admission_result(IssueContractAdmissionReasonCode.CONFIG_BINDING_CHANGED)
        if not resolution.applicable or profile_id not in target.controlled_runtime_profile_ids:
            return _admission_result(IssueContractAdmissionReasonCode.RUNTIME_PROFILE_NOT_APPLICABLE)
        runtime_identities.append(resolution.binding.config_identity)

    # Repair subject and ceiling (29-30).
    if TaskCapability.REPAIR in candidate.requested_operations:
        repair = context.repair_policy_context
        assert type(repair) is TrustedRepairPolicyContext
        if (
            repair.policy_epoch_identity != epoch
            or repair.target_registration_id != target.target_registration_id
            or repair.task_id != candidate.task_id
            or repair.contract_id != candidate.contract_id
            or repair.contract_raw_sha256 != candidate.source_document.raw_sha256
        ):
            return _admission_result(IssueContractAdmissionReasonCode.REPAIR_POLICY_BINDING_MISMATCH)
        if not repair.repair_eligible:
            return _admission_result(IssueContractAdmissionReasonCode.REPAIR_NOT_PERMITTED)
        if candidate.repair_max_attempts > repair.maximum_contract_repair_attempts:
            return _admission_result(IssueContractAdmissionReasonCode.REPAIR_ATTEMPTS_NOT_PERMITTED)

    # Approval config/operation checks precede unsupported enforcement (31-32).
    requested_set = frozenset(candidate.requested_operations)
    for approval in candidate.human_approval_requirements:
        if approval.before_operation not in requested_set:
            return _admission_result(IssueContractAdmissionReasonCode.APPROVAL_OPERATION_OUTSIDE_CONTRACT)
        resolution = approval_map[approval.approval_ref]
        assert type(resolution) is TrustedApprovalConfigResolution
        if resolution.binding.policy_epoch_identity != epoch:
            return _admission_result(IssueContractAdmissionReasonCode.CONFIG_POLICY_EPOCH_MISMATCH)
        if resolution.binding.config_identity.config_id != approval.approval_ref:
            return _admission_result(IssueContractAdmissionReasonCode.CONFIG_BINDING_CHANGED)
        if not resolution.applicable:
            return _admission_result(IssueContractAdmissionReasonCode.EVALUATOR_CONFIG_MISMATCH)
    if candidate.human_approval_requirements:
        return _admission_result(IssueContractAdmissionReasonCode.APPROVAL_ENFORCEMENT_UNAVAILABLE)

    # Delegation consistency (33).
    if not set(candidate.delegation_limits.delegable_operations).issubset(requested_set):
        return _admission_result(IssueContractAdmissionReasonCode.DELEGATION_NOT_PERMITTED)

    # Immutable proposal (34) and ALLOW (35).
    plan = ContractAcceptancePlan(
        candidate.contract_id, candidate.source_document.raw_sha256, tuple(plan_requirements)
    )
    admitted = _new_private(
        AdmittedIssueContract, _ADMITTED_KEY, _ADMITTED_KEY,
        contract_id=candidate.contract_id, contract_raw_sha256=candidate.source_document.raw_sha256,
        raw_bytes=candidate.source_document.raw_bytes, task_id=candidate.task_id,
        context_anchor=candidate.context_anchor,
        contract_target_registration_ref=candidate.target.target_registration_ref,
        target_registration_id=target.target_registration_id, base_ref=base_ref,
        base_sha=candidate.target.base_sha, integration_ref=integration_ref,
        allowed_mutation_scope=candidate.allowed_mutation_scope,
        prohibited_mutation_scope=candidate.prohibited_mutation_scope,
        requested_operations=candidate.requested_operations, risk_floor=candidate.risk_floor,
        acceptance_plan=plan, runtime_profile_identities=tuple(runtime_identities),
        repair_max_attempts=candidate.repair_max_attempts,
        human_approval_requirements=candidate.human_approval_requirements,
        delegation_limits=candidate.delegation_limits,
        schema_resource_id=schema.schema_resource.resource_id,
        schema_resource_sha256=schema.schema_resource.sha256,
        schema_version=schema.schema_version, admission_policy_epoch_identity=epoch,
        admission_event_identity=context.admission_event_identity,
    )
    return _admission_result(IssueContractAdmissionReasonCode.ADMITTED, admitted)


def _applicability_result(code: IssueContractApplicabilityCode) -> IssueContractApplicabilityResult:
    escalating = {
        IssueContractApplicabilityCode.UNSUPPORTED_SCHEMA_BINDING,
        IssueContractApplicabilityCode.TARGET_CONTEXT_UNAVAILABLE,
        IssueContractApplicabilityCode.BASE_STATE_UNAVAILABLE,
        IssueContractApplicabilityCode.ROOT_CONTEXT_UNAVAILABLE,
        IssueContractApplicabilityCode.CONFIG_CONTEXT_UNAVAILABLE,
        IssueContractApplicabilityCode.REPAIR_POLICY_CONTEXT_UNAVAILABLE,
        IssueContractApplicabilityCode.APPROVAL_ENFORCEMENT_UNAVAILABLE,
    }
    decision = Decision.ALLOW if code is IssueContractApplicabilityCode.APPLICABLE else (
        Decision.ESCALATE if code in escalating else Decision.DENY
    )
    return IssueContractApplicabilityResult(decision, code)


def evaluate_issue_contract_applicability(
    contract: AdmittedIssueContract,
    current_context: TrustedIssueContractApplicabilityContext,
) -> IssueContractApplicabilityResult:
    if type(contract) is not AdmittedIssueContract or type(current_context) is not TrustedIssueContractApplicabilityContext:
        raise TypeError("canonical contract and assembled applicability context required")
    epoch = current_context.policy_epoch_identity
    schema = current_context.schema_binding
    if epoch is None or schema is None or schema.policy_epoch_identity != epoch or not _schema_supported(schema):
        return _applicability_result(IssueContractApplicabilityCode.UNSUPPORTED_SCHEMA_BINDING)
    if (
        schema.schema_resource.resource_id != contract.schema_resource_id
        or schema.schema_resource.sha256 != contract.schema_resource_sha256
        or schema.schema_version != contract.schema_version
    ):
        return _applicability_result(IssueContractApplicabilityCode.UNSUPPORTED_SCHEMA_BINDING)
    target = current_context.resolved_target
    if target is None:
        return _applicability_result(IssueContractApplicabilityCode.TARGET_CONTEXT_UNAVAILABLE)
    if target.target_registration_id != contract.target_registration_id:
        return _applicability_result(IssueContractApplicabilityCode.TARGET_REGISTRATION_MISMATCH)
    if target.policy_epoch_identity != epoch:
        return _applicability_result(IssueContractApplicabilityCode.TARGET_POLICY_EPOCH_MISMATCH)
    root = current_context.root_context
    if root is None:
        return _applicability_result(IssueContractApplicabilityCode.ROOT_CONTEXT_UNAVAILABLE)
    if root.policy_epoch_identity != epoch or root.repository_id != target.repository_id:
        return _applicability_result(IssueContractApplicabilityCode.ROOT_CONTEXT_BINDING_MISMATCH)
    if not root.determinate or evaluate_effective_root_overlap(
        contract.allowed_mutation_scope, contract.prohibited_mutation_scope,
        root.root_protected_mutation_scope,
    ) is not EffectiveRootOverlap.PROVEN_DISJOINT:
        return _applicability_result(IssueContractApplicabilityCode.ROOT_SCOPE_OVERLAP)
    base = current_context.base_observation
    if base is None:
        return _applicability_result(IssueContractApplicabilityCode.BASE_STATE_UNAVAILABLE)
    if base.repository_id != target.repository_id or base.ref != contract.base_ref:
        return _applicability_result(IssueContractApplicabilityCode.BASE_BINDING_MISMATCH)
    if base.sha != contract.base_sha:
        return _applicability_result(IssueContractApplicabilityCode.BASE_CHANGED)
    if current_context.evaluator_resolutions is None or current_context.runtime_resolutions is None:
        return _applicability_result(IssueContractApplicabilityCode.CONFIG_CONTEXT_UNAVAILABLE)
    evaluator_map = _by_config_id(current_context.evaluator_resolutions, TrustedEvaluatorConfigResolution)
    runtime_map = _by_config_id(current_context.runtime_resolutions, TrustedRuntimeConfigResolution)
    if evaluator_map is None or runtime_map is None:
        return _applicability_result(IssueContractApplicabilityCode.CONFIG_CONTEXT_UNAVAILABLE)
    for requirement in contract.acceptance_plan.requirements:
        for evaluator in requirement.evaluators:
            resolution = evaluator_map.get(evaluator.evaluator_ref)
            if resolution is None:
                return _applicability_result(IssueContractApplicabilityCode.CONFIG_CONTEXT_UNAVAILABLE)
            assert type(resolution) is TrustedEvaluatorConfigResolution
            if resolution.binding.policy_epoch_identity != epoch:
                return _applicability_result(IssueContractApplicabilityCode.CONFIG_POLICY_EPOCH_MISMATCH)
            if resolution.binding.config_identity != evaluator.config_identity:
                return _applicability_result(IssueContractApplicabilityCode.CONFIG_BINDING_CHANGED)
            if resolution.mechanism is not evaluator.mechanism or not resolution.applicable:
                return _applicability_result(IssueContractApplicabilityCode.EVALUATOR_CONFIG_MISMATCH)
    for profile in contract.runtime_profile_identities:
        resolution = runtime_map.get(profile.config_id)
        if resolution is None:
            return _applicability_result(IssueContractApplicabilityCode.CONFIG_CONTEXT_UNAVAILABLE)
        assert type(resolution) is TrustedRuntimeConfigResolution
        if resolution.binding.policy_epoch_identity != epoch:
            return _applicability_result(IssueContractApplicabilityCode.CONFIG_POLICY_EPOCH_MISMATCH)
        if resolution.binding.config_identity != profile:
            return _applicability_result(IssueContractApplicabilityCode.CONFIG_BINDING_CHANGED)
        if not resolution.applicable or profile.config_id not in target.controlled_runtime_profile_ids:
            return _applicability_result(IssueContractApplicabilityCode.RUNTIME_PROFILE_NOT_APPLICABLE)
    if TaskCapability.REPAIR in contract.requested_operations:
        repair = current_context.repair_policy_context
        if repair is None:
            return _applicability_result(IssueContractApplicabilityCode.REPAIR_POLICY_CONTEXT_UNAVAILABLE)
        if (
            repair.policy_epoch_identity != epoch
            or repair.target_registration_id != contract.target_registration_id
            or repair.task_id != contract.task_id
            or repair.contract_id != contract.contract_id
            or repair.contract_raw_sha256 != contract.contract_raw_sha256
        ):
            return _applicability_result(IssueContractApplicabilityCode.REPAIR_POLICY_BINDING_MISMATCH)
        if not repair.repair_eligible:
            return _applicability_result(IssueContractApplicabilityCode.REPAIR_NOT_PERMITTED)
        if contract.repair_max_attempts > repair.maximum_contract_repair_attempts:
            return _applicability_result(IssueContractApplicabilityCode.REPAIR_ATTEMPTS_NOT_PERMITTED)
    if contract.human_approval_requirements and not current_context.operation_approval_enforcement_available:
        return _applicability_result(IssueContractApplicabilityCode.APPROVAL_ENFORCEMENT_UNAVAILABLE)
    return _applicability_result(IssueContractApplicabilityCode.APPLICABLE)


def derive_contract_authority_ceiling(contract: AdmittedIssueContract) -> ContractAuthorityCeiling:
    if type(contract) is not AdmittedIssueContract:
        raise TypeError("canonical AdmittedIssueContract required")
    from .authorization import _contract_authority_ceiling_from_admitted_contract
    return _contract_authority_ceiling_from_admitted_contract(contract)


def validate_admitted_issue_contract_record(contract: object) -> bool:
    """Re-check every raw-derived canonical field without replaying historical admission."""
    if type(contract) is not AdmittedIssueContract:
        return False
    candidate = load_candidate_issue_contract(contract.raw_bytes)
    if type(candidate) is not CandidateIssueContract:
        return False
    if candidate.source_document.raw_sha256 != contract.contract_raw_sha256:
        return False
    if (
        candidate.contract_id != contract.contract_id
        or candidate.task_id != contract.task_id
        or candidate.context_anchor != contract.context_anchor
        or candidate.target.target_registration_ref != contract.contract_target_registration_ref
        or candidate.target.target_registration_ref.value != contract.target_registration_id.raw_sha256.value
        or candidate.target.base_ref.value != contract.base_ref.value
        or candidate.target.base_sha != contract.base_sha
        or (None if candidate.target.integration_ref is None else candidate.target.integration_ref.value)
           != (None if contract.integration_ref is None else contract.integration_ref.value)
        or candidate.allowed_mutation_scope != contract.allowed_mutation_scope
        or candidate.prohibited_mutation_scope != contract.prohibited_mutation_scope
        or candidate.requested_operations != contract.requested_operations
        or candidate.risk_floor is not contract.risk_floor
        or candidate.repair_max_attempts != contract.repair_max_attempts
        or candidate.human_approval_requirements != contract.human_approval_requirements
        or candidate.delegation_limits != contract.delegation_limits
        or candidate.schema_version != contract.schema_version
        or contract.schema_resource_sha256.value != SUPPORTED_ISSUE_CONTRACT_SCHEMA_RAW_SHA256
    ):
        return False
    if tuple(item.config_id for item in contract.runtime_profile_identities) != candidate.runtime_profile_ids:
        return False
    if contract.acceptance_plan.contract_id != contract.contract_id or contract.acceptance_plan.contract_raw_sha256 != contract.contract_raw_sha256:
        return False
    if len(contract.acceptance_plan.requirements) != len(candidate.acceptance_requirements):
        return False
    for stored_requirement, raw_requirement in zip(contract.acceptance_plan.requirements, candidate.acceptance_requirements):
        if (
            stored_requirement.requirement_id != raw_requirement.requirement_id
            or stored_requirement.statement != raw_requirement.statement
            or len(stored_requirement.evaluators) != len(raw_requirement.evaluators)
        ):
            return False
        for stored, raw_evaluator in zip(stored_requirement.evaluators, raw_requirement.evaluators):
            if (
                stored.evaluation_id != raw_evaluator.evaluation_id
                or stored.mechanism is not raw_evaluator.mechanism
                or stored.evaluator_ref != raw_evaluator.evaluator_ref
                or stored.config_identity.config_id != raw_evaluator.evaluator_ref
                or stored.parameter_value_digest != contract_json_value_digest(raw_evaluator.parameters)
            ):
                return False
    return True
