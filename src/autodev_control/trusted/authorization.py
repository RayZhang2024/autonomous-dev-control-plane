"""Structural authorization proposals and deterministic direct/delegated admission."""

from dataclasses import dataclass
from enum import Enum
import hashlib
from decimal import Decimal
from types import MappingProxyType

from .decision import Decision
from .errors import (
    AuthorizationAdmissionReasonCode,
    AuthorizationProposalFailure,
    AuthorizationProposalFailureCode,
    IdentityValidationError,
    ParseFailure,
)
from .identity import ImmutableConfigId, RawSha256
from .manifest import PolicyEpochIdentity
from .parsing import ParseLimits, ParsedJsonDocument, parse_trusted_json
from .scope import (
    AuthenticationEventId,
    AuthorizationId,
    AuthorizationKind,
    CanonicalBranchRef,
    ContractId,
    G3_MAX_CAPABILITIES,
    G3_MAX_DELEGATION_DEPTH,
    G3_MAX_PROFILE_IDS,
    GitHubRepositoryId,
    HumanPrincipalId,
    MutationScope,
    ParsedMutationScope,
    RiskRelation,
    RiskTier,
    ScopeParseProblem,
    TargetRegistrationId,
    TaskCapability,
    TaskId,
    compare_risk,
    parse_mutation_scope_json,
    scope_contains,
    scopes_overlap,
)
from .target_registration import AdmittedTargetRegistration

G3_AUTHORIZATION_PROPOSAL_MAX_BYTES = 1 * 1024 * 1024
G3_MAX_DEPTH = 32
_FORMAT = "autodev.authorization/v1"
_SUCCESS_KEY = object()
_AUTHORITY_KEY = object()
_COMMON_FIELDS = (
    "format", "kind", "task_id", "contract_id", "contract_sha256", "target_registration_id",
    "capabilities", "mutation_scope", "operational_constraints", "risk_ceiling", "delegation",
)
_DIRECT_FIELDS = ("format", "kind", "issuer_principal_id", *_COMMON_FIELDS[2:])
_DELEGATED_FIELDS = ("format", "kind", "parent_authorization_id", *_COMMON_FIELDS[2:])


class OrdinaryRootProtectionState(Enum):
    NO_ROOT_PROTECTED_MATERIAL = "NO_ROOT_PROTECTED_MATERIAL"
    ROOT_PROTECTED_MUTATION_SCOPE = "ROOT_PROTECTED_MUTATION_SCOPE"


@dataclass(frozen=True, slots=True)
class AuthorizationOperationalConstraints:
    integration_refs: tuple[CanonicalBranchRef, ...]
    controlled_runtime_profile_ids: tuple[ImmutableConfigId, ...]
    repair_max_attempts: int

    def __post_init__(self) -> None:
        _unique_exact(self.integration_refs, CanonicalBranchRef, 1)
        _unique_exact(self.controlled_runtime_profile_ids, ImmutableConfigId, G3_MAX_PROFILE_IDS)
        if type(self.repair_max_attempts) is not int or self.repair_max_attempts < 0:
            raise ValueError("invalid repair maximum")


@dataclass(frozen=True, slots=True)
class DelegationAllowance:
    remaining_depth: int
    delegable_capabilities: tuple[TaskCapability, ...]
    delegable_mutation_scope: MutationScope
    delegable_operational_constraints: AuthorizationOperationalConstraints
    risk_ceiling: RiskTier | None

    def __post_init__(self) -> None:
        if type(self.remaining_depth) is not int or not 0 <= self.remaining_depth <= G3_MAX_DELEGATION_DEPTH:
            raise ValueError("invalid delegation depth")
        _unique_exact(self.delegable_capabilities, TaskCapability, G3_MAX_CAPABILITIES)
        if type(self.delegable_mutation_scope) is not MutationScope:
            raise TypeError("delegable_mutation_scope must be exactly MutationScope")
        if type(self.delegable_operational_constraints) is not AuthorizationOperationalConstraints:
            raise TypeError("delegable operational constraints have wrong type")
        if self.risk_ceiling is not None and type(self.risk_ceiling) is not RiskTier:
            raise TypeError("risk_ceiling must be exact RiskTier or None")
        empty_ops = AuthorizationOperationalConstraints((), (), 0)
        if self.remaining_depth == 0 and (
            self.delegable_capabilities
            or self.delegable_mutation_scope.rules
            or self.delegable_operational_constraints != empty_ops
            or self.risk_ceiling is not None
        ):
            raise ValueError("zero-depth delegation must be empty")
        if self.remaining_depth > 0 and self.risk_ceiling is None:
            raise ValueError("positive-depth delegation requires risk ceiling")


@dataclass(frozen=True, slots=True, init=False)
class CandidateAuthorizationProposal:
    source_document: ParsedJsonDocument
    proposal_raw_sha256: RawSha256
    kind: AuthorizationKind
    issuer_principal_id: HumanPrincipalId | None
    parent_authorization_id: AuthorizationId | None
    task_id: TaskId
    contract_id: ContractId
    contract_raw_sha256: RawSha256
    target_registration_id: TargetRegistrationId
    capabilities: tuple[TaskCapability, ...]
    mutation_scope: MutationScope
    operational_constraints: AuthorizationOperationalConstraints
    risk_ceiling: RiskTier
    delegation: DelegationAllowance

    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("use load_candidate_authorization_proposal")


@dataclass(frozen=True, slots=True, init=False)
class AuthenticatedHumanAuthorizationApproval:
    human_principal_id: HumanPrincipalId
    authentication_event_id: AuthenticationEventId
    proposal_raw_sha256: RawSha256
    policy_epoch_identity: PolicyEpochIdentity

    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("authentication approval must come from trusted boundary")


@dataclass(frozen=True, slots=True, init=False)
class ContractAuthorityCeiling:
    task_id: TaskId
    contract_id: ContractId
    contract_raw_sha256: RawSha256
    target_registration_id: TargetRegistrationId
    requested_capabilities: tuple[TaskCapability, ...]
    allowed_mutation_scope: MutationScope
    prohibited_mutation_scope: MutationScope
    risk_floor: RiskTier
    integration_ref: CanonicalBranchRef | None
    controlled_runtime_profile_ids: tuple[ImmutableConfigId, ...]
    repair_max_attempts: int
    delegation_max_depth: int
    delegable_capabilities: tuple[TaskCapability, ...]
    delegation_risk_ceiling: RiskTier | None

    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("contract ceiling must come from trusted boundary")


@dataclass(frozen=True, slots=True, init=False)
class AuthorizationPolicyContext:
    policy_epoch_identity: PolicyEpochIdentity
    target_registration_id: TargetRegistrationId
    task_id: TaskId
    contract_id: ContractId
    contract_raw_sha256: RawSha256
    maximum_capabilities: tuple[TaskCapability, ...]
    maximum_mutation_scope: MutationScope
    mandatory_forbidden_mutation_scope: MutationScope
    maximum_operational_constraints: AuthorizationOperationalConstraints
    maximum_authorization_risk_ceiling: RiskTier
    effective_authoritative_risk: RiskTier
    risk_relation: RiskRelation
    maximum_delegation_depth: int
    maximum_delegable_capabilities: tuple[TaskCapability, ...]
    maximum_delegable_mutation_scope: MutationScope
    maximum_delegable_operational_constraints: AuthorizationOperationalConstraints
    maximum_delegation_risk_ceiling: RiskTier | None

    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("policy context must come from trusted boundary")


@dataclass(frozen=True, slots=True, init=False)
class DirectIssuerAuthorityEnvelope:
    policy_epoch_identity: PolicyEpochIdentity
    human_principal_id: HumanPrincipalId
    target_registration_id: TargetRegistrationId
    task_id: TaskId
    contract_id: ContractId
    contract_raw_sha256: RawSha256
    maximum_capabilities: tuple[TaskCapability, ...]
    maximum_mutation_scope: MutationScope
    maximum_operational_constraints: AuthorizationOperationalConstraints
    maximum_authorization_risk_ceiling: RiskTier
    maximum_delegation_depth: int
    maximum_delegable_capabilities: tuple[TaskCapability, ...]
    maximum_delegable_mutation_scope: MutationScope
    maximum_delegable_operational_constraints: AuthorizationOperationalConstraints
    maximum_delegation_risk_ceiling: RiskTier | None

    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("issuer envelope must come from trusted boundary")


@dataclass(frozen=True, slots=True, init=False)
class OrdinaryRootProtectionContext:
    policy_epoch_identity: PolicyEpochIdentity
    repository_id: GitHubRepositoryId
    state: OrdinaryRootProtectionState
    root_protected_mutation_scope: MutationScope | None

    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("root context must come from trusted boundary")


@dataclass(frozen=True, slots=True)
class DirectAuthoritySource:
    human_principal_id: HumanPrincipalId
    authentication_event_id: AuthenticationEventId

    def __post_init__(self) -> None:
        if type(self.human_principal_id) is not HumanPrincipalId or type(self.authentication_event_id) is not AuthenticationEventId:
            raise TypeError("wrong direct authority source type")


@dataclass(frozen=True, slots=True)
class DelegatedAuthoritySource:
    parent_authorization_id: AuthorizationId

    def __post_init__(self) -> None:
        if type(self.parent_authorization_id) is not AuthorizationId:
            raise TypeError("wrong delegated authority source type")


AuthoritySource = DirectAuthoritySource | DelegatedAuthoritySource


@dataclass(frozen=True, slots=True, init=False)
class AdmittedAuthorization:
    authorization_id: AuthorizationId
    kind: AuthorizationKind
    authority_source: AuthoritySource
    ancestry: tuple[AuthorizationId, ...]
    task_id: TaskId
    contract_id: ContractId
    contract_raw_sha256: RawSha256
    target_registration_id: TargetRegistrationId
    authorized_capabilities: tuple[TaskCapability, ...]
    authorized_mutation_scope: MutationScope
    authorized_operational_constraints: AuthorizationOperationalConstraints
    effective_authoritative_risk: RiskTier
    authorization_risk_ceiling: RiskTier
    delegation: DelegationAllowance
    policy_epoch_identity: PolicyEpochIdentity

    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("use authorization admission")


@dataclass(frozen=True, slots=True)
class AuthorizationAdmissionResult:
    decision: Decision
    reason_code: AuthorizationAdmissionReasonCode
    admitted_authorization: AdmittedAuthorization | None = None

    def __post_init__(self) -> None:
        if type(self.decision) is not Decision or type(self.reason_code) is not AuthorizationAdmissionReasonCode:
            raise TypeError("wrong authorization result domain")
        if self.reason_code is AuthorizationAdmissionReasonCode.ADMITTED:
            if self.decision is not Decision.ALLOW or type(self.admitted_authorization) is not AdmittedAuthorization:
                raise ValueError("admitted result invariant")
        elif self.decision is Decision.ALLOW or self.admitted_authorization is not None:
            raise ValueError("failure result cannot carry admitted authorization")


def _new_private(cls: type, key: object, expected: object, **fields: object):
    if key is not expected:
        raise TypeError("internal trusted construction only")
    result = object.__new__(cls)
    for name, value in fields.items():
        object.__setattr__(result, name, value)
    return result


def _unique_exact(values: object, item_type: type, maximum: int) -> tuple:
    if type(values) is not tuple or len(values) > maximum:
        raise ValueError("invalid canonical set-like collection")
    seen: set[object] = set()
    for value in values:
        if type(value) is not item_type:
            raise TypeError("wrong canonical item type")
        if value in seen:
            raise ValueError("duplicate canonical identity")
        seen.add(value)
    return values


def _failure(code: AuthorizationProposalFailureCode, parse: ParseFailure | None = None) -> AuthorizationProposalFailure:
    return AuthorizationProposalFailure(code, parse)


def _field_set(value: object, fields: tuple[str, ...]) -> AuthorizationProposalFailure | None:
    if type(value) is not MappingProxyType:
        return _failure(AuthorizationProposalFailureCode.INVALID_FIELD_TYPE)
    if any(field not in value for field in fields):
        return _failure(AuthorizationProposalFailureCode.MISSING_FIELD)
    allowed = frozenset(fields)
    if any(field not in allowed for field in value):
        return _failure(AuthorizationProposalFailureCode.UNKNOWN_FIELD)
    return None


def _map_scope_problem(problem: ScopeParseProblem) -> AuthorizationProposalFailure:
    mapping = {
        "type": AuthorizationProposalFailureCode.INVALID_FIELD_TYPE,
        "missing": AuthorizationProposalFailureCode.MISSING_FIELD,
        "unknown": AuthorizationProposalFailureCode.UNKNOWN_FIELD,
        "value": AuthorizationProposalFailureCode.INVALID_FIELD_VALUE,
        "duplicate": AuthorizationProposalFailureCode.DUPLICATE_IDENTITY,
        "empty": AuthorizationProposalFailureCode.EMPTY_REQUIRED_SET,
    }
    return _failure(mapping[problem.kind])


def _parse_enum_list(value: object) -> tuple[tuple[TaskCapability, ...], bool] | AuthorizationProposalFailure:
    if type(value) is not tuple:
        return _failure(AuthorizationProposalFailureCode.INVALID_FIELD_TYPE)
    if len(value) > G3_MAX_CAPABILITIES:
        return _failure(AuthorizationProposalFailureCode.INVALID_FIELD_VALUE)
    result: list[TaskCapability] = []
    seen: set[TaskCapability] = set()
    duplicate = False
    for item in value:
        if type(item) is not str:
            return _failure(AuthorizationProposalFailureCode.INVALID_FIELD_TYPE)
        try:
            parsed = TaskCapability(item)
        except ValueError:
            return _failure(AuthorizationProposalFailureCode.INVALID_FIELD_VALUE)
        duplicate |= parsed in seen
        seen.add(parsed)
        result.append(parsed)
    return tuple(result), duplicate


def _parse_refs(value: object) -> tuple[tuple[CanonicalBranchRef, ...], bool] | AuthorizationProposalFailure:
    if type(value) is not tuple:
        return _failure(AuthorizationProposalFailureCode.INVALID_FIELD_TYPE)
    result = []
    seen = set()
    duplicate = False
    for item in value:
        if type(item) is not str:
            return _failure(AuthorizationProposalFailureCode.INVALID_FIELD_TYPE)
        try:
            parsed = CanonicalBranchRef(item)
        except ValueError:
            return _failure(AuthorizationProposalFailureCode.INVALID_FIELD_VALUE)
        duplicate |= parsed in seen
        seen.add(parsed)
        result.append(parsed)
    if len(result) > 1 and not duplicate:
        return _failure(AuthorizationProposalFailureCode.INVALID_FIELD_VALUE)
    return tuple(result), duplicate


def _parse_profiles(value: object) -> tuple[tuple[ImmutableConfigId, ...], bool] | AuthorizationProposalFailure:
    if type(value) is not tuple:
        return _failure(AuthorizationProposalFailureCode.INVALID_FIELD_TYPE)
    if len(value) > G3_MAX_PROFILE_IDS:
        return _failure(AuthorizationProposalFailureCode.INVALID_FIELD_VALUE)
    result = []
    seen = set()
    duplicate = False
    for item in value:
        if type(item) is not str:
            return _failure(AuthorizationProposalFailureCode.INVALID_FIELD_TYPE)
        try:
            parsed = ImmutableConfigId(item)
        except IdentityValidationError:
            return _failure(AuthorizationProposalFailureCode.INVALID_FIELD_VALUE)
        duplicate |= parsed in seen
        seen.add(parsed)
        result.append(parsed)
    return tuple(result), duplicate


@dataclass(frozen=True, slots=True)
class _ParsedOperationalConstraints:
    integration_refs: tuple[CanonicalBranchRef, ...]
    controlled_runtime_profile_ids: tuple[ImmutableConfigId, ...]
    repair_max_attempts: int
    has_duplicates: bool

    def canonical(self) -> AuthorizationOperationalConstraints:
        return AuthorizationOperationalConstraints(
            self.integration_refs,
            self.controlled_runtime_profile_ids,
            self.repair_max_attempts,
        )


@dataclass(frozen=True, slots=True)
class _ParsedDelegationAllowance:
    remaining_depth: int
    delegable_capabilities: tuple[TaskCapability, ...]
    delegable_mutation_scope: ParsedMutationScope
    delegable_operational_constraints: _ParsedOperationalConstraints
    risk_ceiling: RiskTier | None
    has_duplicates: bool
    has_zero_depth_inconsistency: bool


def _parse_operational(value: object) -> _ParsedOperationalConstraints | AuthorizationProposalFailure:
    fields = ("integration_refs", "controlled_runtime_profile_ids", "repair_max_attempts")
    problem = _field_set(value, fields)
    if problem is not None:
        return problem
    if type(value["integration_refs"]) is not tuple or type(value["controlled_runtime_profile_ids"]) is not tuple or type(value["repair_max_attempts"]) is not Decimal:
        return _failure(AuthorizationProposalFailureCode.INVALID_FIELD_TYPE)
    refs = _parse_refs(value["integration_refs"])
    if type(refs) is AuthorizationProposalFailure:
        return refs
    profiles = _parse_profiles(value["controlled_runtime_profile_ids"])
    if type(profiles) is AuthorizationProposalFailure:
        return profiles
    repair_max_attempts = value["repair_max_attempts"]
    if repair_max_attempts != repair_max_attempts.to_integral_value() or repair_max_attempts < 0:
        return _failure(AuthorizationProposalFailureCode.INVALID_FIELD_VALUE)
    return _ParsedOperationalConstraints(
        refs[0], profiles[0], int(repair_max_attempts), refs[1] or profiles[1]
    )
def _parse_delegation(value: object) -> _ParsedDelegationAllowance | AuthorizationProposalFailure:
    fields = (
        "remaining_depth", "delegable_capabilities", "delegable_mutation_scope",
        "delegable_operational_constraints", "risk_ceiling",
    )
    problem = _field_set(value, fields)
    if problem is not None:
        return problem
    if type(value["remaining_depth"]) is not Decimal or type(value["delegable_capabilities"]) is not tuple or type(value["delegable_mutation_scope"]) is not tuple or type(value["delegable_operational_constraints"]) is not MappingProxyType or (value["risk_ceiling"] is not None and type(value["risk_ceiling"]) is not str):
        return _failure(AuthorizationProposalFailureCode.INVALID_FIELD_TYPE)
    encoded_depth = value["remaining_depth"]
    if encoded_depth != encoded_depth.to_integral_value() or not 0 <= encoded_depth <= G3_MAX_DELEGATION_DEPTH:
        return _failure(AuthorizationProposalFailureCode.INVALID_FIELD_VALUE)
    depth = int(encoded_depth)
    capabilities = _parse_enum_list(value["delegable_capabilities"])
    if type(capabilities) is AuthorizationProposalFailure:
        return capabilities
    scope = parse_mutation_scope_json(value["delegable_mutation_scope"], defer_duplicates=True)
    if type(scope) is ScopeParseProblem:
        return _map_scope_problem(scope)
    operational = _parse_operational(value["delegable_operational_constraints"])
    if type(operational) is AuthorizationProposalFailure:
        return operational
    try:
        risk = None if value["risk_ceiling"] is None else RiskTier(value["risk_ceiling"])
    except ValueError:
        return _failure(AuthorizationProposalFailureCode.INVALID_FIELD_VALUE)
    duplicate = capabilities[1] or scope.has_duplicates or operational.has_duplicates
    zero_inconsistent = depth == 0 and (
        capabilities[0]
        or scope.rules
        or operational.integration_refs
        or operational.controlled_runtime_profile_ids
        or operational.repair_max_attempts != 0
        or risk is not None
    )
    positive_inconsistent = depth > 0 and risk is None
    return _ParsedDelegationAllowance(
        depth, capabilities[0], scope, operational, risk, duplicate,
        zero_inconsistent or positive_inconsistent,
    )


def load_candidate_authorization_proposal(raw: object) -> CandidateAuthorizationProposal | AuthorizationProposalFailure:
    if type(raw) is not bytes:
        return _failure(AuthorizationProposalFailureCode.INVALID_INPUT_TYPE)
    if len(raw) > G3_AUTHORIZATION_PROPOSAL_MAX_BYTES:
        return _failure(AuthorizationProposalFailureCode.BYTE_LIMIT_EXCEEDED)
    document = parse_trusted_json(raw, ParseLimits(G3_AUTHORIZATION_PROPOSAL_MAX_BYTES, G3_MAX_DEPTH))
    if type(document) is ParseFailure:
        return _failure(AuthorizationProposalFailureCode.PARSE_FAILED, document)
    value = document.value
    if type(value) is not MappingProxyType:
        return _failure(AuthorizationProposalFailureCode.INVALID_TOP_LEVEL)
    if "format" not in value or "kind" not in value:
        return _failure(AuthorizationProposalFailureCode.MISSING_FIELD)
    if type(value["format"]) is not str or value["format"] != _FORMAT:
        return _failure(AuthorizationProposalFailureCode.INVALID_FIELD_TYPE if type(value["format"]) is not str else AuthorizationProposalFailureCode.INVALID_FIELD_VALUE)
    if type(value["kind"]) is not str:
        return _failure(AuthorizationProposalFailureCode.INVALID_FIELD_TYPE)
    try:
        kind = AuthorizationKind(value["kind"])
    except ValueError:
        return _failure(AuthorizationProposalFailureCode.INVALID_FIELD_VALUE)
    fields = _DIRECT_FIELDS if kind is AuthorizationKind.DIRECT_HUMAN else _DELEGATED_FIELDS
    if any(field not in value for field in fields):
        return _failure(AuthorizationProposalFailureCode.MISSING_FIELD)
    allowed = frozenset(fields)
    if any(field not in allowed for field in value):
        return _failure(AuthorizationProposalFailureCode.UNKNOWN_FIELD)
    authority_field = "issuer_principal_id" if kind is AuthorizationKind.DIRECT_HUMAN else "parent_authorization_id"
    for field in (authority_field, "task_id", "contract_id", "contract_sha256", "target_registration_id"):
        if type(value[field]) is not str:
            return _failure(AuthorizationProposalFailureCode.INVALID_FIELD_TYPE)
    if type(value["capabilities"]) is not tuple or type(value["mutation_scope"]) is not tuple or type(value["operational_constraints"]) is not MappingProxyType or type(value["risk_ceiling"]) is not str or type(value["delegation"]) is not MappingProxyType:
        return _failure(AuthorizationProposalFailureCode.INVALID_FIELD_TYPE)
    try:
        issuer = HumanPrincipalId(value[authority_field]) if kind is AuthorizationKind.DIRECT_HUMAN else None
        parent = AuthorizationId(RawSha256(value[authority_field])) if kind is AuthorizationKind.DELEGATED else None
    except (IdentityValidationError, ValueError):
        return _failure(AuthorizationProposalFailureCode.INVALID_FIELD_VALUE)
    try:
        task_id = TaskId(value["task_id"])
        contract_id = ContractId(value["contract_id"])
        contract_sha = RawSha256(value["contract_sha256"])
        target_id = TargetRegistrationId(RawSha256(value["target_registration_id"]))
    except (IdentityValidationError, ValueError):
        return _failure(AuthorizationProposalFailureCode.INVALID_FIELD_VALUE)
    capabilities = _parse_enum_list(value["capabilities"])
    if type(capabilities) is AuthorizationProposalFailure:
        return capabilities
    scope = parse_mutation_scope_json(value["mutation_scope"], defer_duplicates=True)
    if type(scope) is ScopeParseProblem:
        return _map_scope_problem(scope)
    operational = _parse_operational(value["operational_constraints"])
    if type(operational) is AuthorizationProposalFailure:
        return operational
    try:
        risk_ceiling = RiskTier(value["risk_ceiling"])
    except ValueError:
        return _failure(AuthorizationProposalFailureCode.INVALID_FIELD_VALUE)
    delegation = _parse_delegation(value["delegation"])
    if type(delegation) is AuthorizationProposalFailure:
        return delegation
    if capabilities[1] or scope.has_duplicates or operational.has_duplicates or delegation.has_duplicates:
        return _failure(AuthorizationProposalFailureCode.DUPLICATE_IDENTITY)
    if not capabilities[0]:
        return _failure(AuthorizationProposalFailureCode.EMPTY_REQUIRED_SET)
    has_merge = TaskCapability.MERGE in capabilities[0]
    has_runtime = TaskCapability.CONTROLLED_RUNTIME in capabilities[0]
    has_repair = TaskCapability.REPAIR in capabilities[0]
    dops = delegation.delegable_operational_constraints
    delegable_has_merge = TaskCapability.MERGE in delegation.delegable_capabilities
    delegable_has_runtime = TaskCapability.CONTROLLED_RUNTIME in delegation.delegable_capabilities
    if (
        (has_merge and not operational.integration_refs)
        or (has_runtime and not operational.controlled_runtime_profile_ids)
        or (delegable_has_merge and not dops.integration_refs)
        or (delegable_has_runtime and not dops.controlled_runtime_profile_ids)
    ):
        return _failure(AuthorizationProposalFailureCode.EMPTY_REQUIRED_SET)
    if has_merge != bool(operational.integration_refs) or has_runtime != bool(operational.controlled_runtime_profile_ids) or has_repair != (operational.repair_max_attempts >= 1):
        return _failure(AuthorizationProposalFailureCode.INCONSISTENT_CONFIGURATION)
    if (
        delegable_has_merge != bool(dops.integration_refs)
        or delegable_has_runtime != bool(dops.controlled_runtime_profile_ids)
        or (TaskCapability.REPAIR in delegation.delegable_capabilities) != (dops.repair_max_attempts >= 1)
    ):
        return _failure(AuthorizationProposalFailureCode.INCONSISTENT_CONFIGURATION)
    if delegation.has_zero_depth_inconsistency:
        return _failure(AuthorizationProposalFailureCode.INCONSISTENT_CONFIGURATION)
    clean_scope = MutationScope(scope.rules)
    operational_constraints = operational.canonical()
    delegable = DelegationAllowance(
        delegation.remaining_depth,
        delegation.delegable_capabilities,
        MutationScope(delegation.delegable_mutation_scope.rules),
        delegation.delegable_operational_constraints.canonical(),
        delegation.risk_ceiling,
    )
    return _new_private(
        CandidateAuthorizationProposal, _SUCCESS_KEY, _SUCCESS_KEY,
        source_document=document, proposal_raw_sha256=document.raw_sha256, kind=kind,
        issuer_principal_id=issuer, parent_authorization_id=parent, task_id=task_id,
        contract_id=contract_id, contract_raw_sha256=contract_sha, target_registration_id=target_id,
        capabilities=capabilities[0], mutation_scope=clean_scope,
        operational_constraints=operational_constraints, risk_ceiling=risk_ceiling, delegation=delegable,
    )


_AUTH_ESCALATIONS = {
    AuthorizationAdmissionReasonCode.AUTHENTICATED_APPROVAL_UNAVAILABLE,
    AuthorizationAdmissionReasonCode.TARGET_CONTEXT_UNAVAILABLE,
    AuthorizationAdmissionReasonCode.POLICY_CONTEXT_UNAVAILABLE,
    AuthorizationAdmissionReasonCode.CONTRACT_CONTEXT_UNAVAILABLE,
    AuthorizationAdmissionReasonCode.ISSUER_AUTHORITY_UNAVAILABLE,
    AuthorizationAdmissionReasonCode.PARENT_AUTHORIZATION_UNAVAILABLE,
    AuthorizationAdmissionReasonCode.ROOT_CONTEXT_UNAVAILABLE,
    AuthorizationAdmissionReasonCode.RISK_RELATION_UNAVAILABLE,
}


def _result(reason: AuthorizationAdmissionReasonCode, admitted: AdmittedAuthorization | None = None) -> AuthorizationAdmissionResult:
    decision = Decision.ALLOW if reason is AuthorizationAdmissionReasonCode.ADMITTED else (
        Decision.ESCALATE if reason in _AUTH_ESCALATIONS else Decision.DENY
    )
    return AuthorizationAdmissionResult(decision, reason, admitted)


def _ops_fit(child: AuthorizationOperationalConstraints, ceiling: AuthorizationOperationalConstraints) -> AuthorizationAdmissionReasonCode | None:
    if any(ref not in ceiling.integration_refs for ref in child.integration_refs):
        return AuthorizationAdmissionReasonCode.INTEGRATION_REF_NOT_PERMITTED
    if any(profile not in ceiling.controlled_runtime_profile_ids for profile in child.controlled_runtime_profile_ids):
        return AuthorizationAdmissionReasonCode.RUNTIME_PROFILE_NOT_PERMITTED
    if child.repair_max_attempts > ceiling.repair_max_attempts:
        return AuthorizationAdmissionReasonCode.REPAIR_ATTEMPTS_NOT_PERMITTED
    return None


def _ops_fit_all(
    child: AuthorizationOperationalConstraints,
    ceilings: tuple[AuthorizationOperationalConstraints, ...],
    target: AdmittedTargetRegistration,
) -> AuthorizationAdmissionReasonCode | None:
    target_refs = () if target.merge is None else target.merge.allowed_integration_refs
    if any(
        ref not in target_refs or any(ref not in ceiling.integration_refs for ceiling in ceilings)
        for ref in child.integration_refs
    ):
        return AuthorizationAdmissionReasonCode.INTEGRATION_REF_NOT_PERMITTED
    if any(
        profile not in target.controlled_runtime_profile_ids
        or any(profile not in ceiling.controlled_runtime_profile_ids for ceiling in ceilings)
        for profile in child.controlled_runtime_profile_ids
    ):
        return AuthorizationAdmissionReasonCode.RUNTIME_PROFILE_NOT_PERMITTED
    if any(child.repair_max_attempts > ceiling.repair_max_attempts for ceiling in ceilings):
        return AuthorizationAdmissionReasonCode.REPAIR_ATTEMPTS_NOT_PERMITTED
    return None


def _risk_check(policy: AuthorizationPolicyContext, proposal: CandidateAuthorizationProposal, target: AdmittedTargetRegistration, contract: ContractAuthorityCeiling, extra_ceilings: tuple[RiskTier, ...]) -> AuthorizationAdmissionReasonCode | None:
    effective = policy.effective_authoritative_risk
    for lower, upper in ((contract.risk_floor, effective), (effective, target.risk_ceiling), (effective, policy.maximum_authorization_risk_ceiling), (effective, proposal.risk_ceiling)):
        comparison = compare_risk(policy.risk_relation, lower, upper)
        if comparison is None:
            return AuthorizationAdmissionReasonCode.RISK_RELATION_UNAVAILABLE
        if not comparison:
            return AuthorizationAdmissionReasonCode.RISK_NOT_PERMITTED
    for ceiling in extra_ceilings:
        comparison = compare_risk(policy.risk_relation, effective, ceiling)
        if comparison is None:
            return AuthorizationAdmissionReasonCode.RISK_RELATION_UNAVAILABLE
        if not comparison:
            return AuthorizationAdmissionReasonCode.RISK_NOT_PERMITTED
    return None


def _authorization_id(proposal: CandidateAuthorizationProposal, epoch: PolicyEpochIdentity, target_id: TargetRegistrationId) -> AuthorizationId:
    digest = hashlib.sha256(
        b"autodev.authorization-id/v1\0"
        + bytes.fromhex(proposal.proposal_raw_sha256.value)
        + bytes.fromhex(epoch.manifest_id.raw_sha256.value)
        + bytes.fromhex(target_id.raw_sha256.value)
    ).hexdigest()
    return AuthorizationId(RawSha256(digest))


def _binding_mismatch(proposal: CandidateAuthorizationProposal, contract: ContractAuthorityCeiling, policy: AuthorizationPolicyContext, envelope: DirectIssuerAuthorityEnvelope | None = None) -> bool:
    records = (contract, policy) if envelope is None else (contract, policy, envelope)
    return any(
        item.task_id != proposal.task_id
        or item.contract_id != proposal.contract_id
        or item.contract_raw_sha256 != proposal.contract_raw_sha256
        for item in records
    )


def _scope_and_prohibitions(
    proposal: CandidateAuthorizationProposal, target: AdmittedTargetRegistration,
    contract: ContractAuthorityCeiling, policy: AuthorizationPolicyContext,
    extra_allowed: tuple[MutationScope, ...],
) -> AuthorizationAdmissionReasonCode | None:
    if not scope_contains(policy.maximum_mutation_scope, proposal.mutation_scope):
        return AuthorizationAdmissionReasonCode.MUTATION_SCOPE_NOT_PERMITTED
    for ceiling in (contract.allowed_mutation_scope, target.ordinary_allowed_scope, *extra_allowed):
        if not scope_contains(ceiling, proposal.mutation_scope):
            return AuthorizationAdmissionReasonCode.MUTATION_SCOPE_NOT_PERMITTED
    for forbidden in (policy.mandatory_forbidden_mutation_scope, contract.prohibited_mutation_scope, target.ordinary_forbidden_scope):
        if scopes_overlap(proposal.mutation_scope, forbidden):
            return AuthorizationAdmissionReasonCode.MUTATION_SCOPE_NOT_PERMITTED
    return None


def _delegation_fit(
    allowance: DelegationAllowance, authorized_caps: tuple[TaskCapability, ...], authorized_scope: MutationScope,
    authorized_ops: AuthorizationOperationalConstraints, policy: AuthorizationPolicyContext,
    contract: ContractAuthorityCeiling, depth_ceiling: int, cap_ceiling: tuple[TaskCapability, ...],
    scope_ceiling: MutationScope, ops_ceiling: AuthorizationOperationalConstraints,
    authorization_risk_ceiling: RiskTier, authority_delegation_risk_ceiling: RiskTier | None,
) -> AuthorizationAdmissionReasonCode | None:
    if allowance.remaining_depth > min(G3_MAX_DELEGATION_DEPTH, contract.delegation_max_depth, policy.maximum_delegation_depth, depth_ceiling):
        return AuthorizationAdmissionReasonCode.DELEGATION_DEPTH_EXCEEDED
    cap_sets = (authorized_caps, contract.delegable_capabilities, policy.maximum_delegable_capabilities, cap_ceiling)
    if any(any(cap not in ceiling for cap in allowance.delegable_capabilities) for ceiling in cap_sets):
        return AuthorizationAdmissionReasonCode.DELEGATION_NOT_PERMITTED
    for ceiling in (authorized_scope, policy.maximum_delegable_mutation_scope, scope_ceiling):
        if not scope_contains(ceiling, allowance.delegable_mutation_scope):
            return AuthorizationAdmissionReasonCode.DELEGATION_NOT_PERMITTED
    for ceiling in (authorized_ops, policy.maximum_delegable_operational_constraints, ops_ceiling):
        if _ops_fit(allowance.delegable_operational_constraints, ceiling) is not None:
            return AuthorizationAdmissionReasonCode.DELEGATION_NOT_PERMITTED
    if allowance.risk_ceiling is not None:
        for ceiling in (
            authorization_risk_ceiling, contract.delegation_risk_ceiling,
            policy.maximum_delegation_risk_ceiling, authority_delegation_risk_ceiling,
        ):
            if ceiling is None:
                return AuthorizationAdmissionReasonCode.DELEGATION_NOT_PERMITTED
            comparison = compare_risk(policy.risk_relation, allowance.risk_ceiling, ceiling)
            if comparison is None:
                return AuthorizationAdmissionReasonCode.RISK_RELATION_UNAVAILABLE
            if not comparison:
                return AuthorizationAdmissionReasonCode.DELEGATION_NOT_PERMITTED
    return None


def admit_direct_authorization(
    proposal: CandidateAuthorizationProposal,
    target: AdmittedTargetRegistration | None,
    contract: ContractAuthorityCeiling | None,
    policy: AuthorizationPolicyContext | None,
    approval: AuthenticatedHumanAuthorizationApproval | None,
    issuer: DirectIssuerAuthorityEnvelope | None,
    root: OrdinaryRootProtectionContext | None,
) -> AuthorizationAdmissionResult:
    if type(proposal) is not CandidateAuthorizationProposal or proposal.kind is not AuthorizationKind.DIRECT_HUMAN:
        raise TypeError("direct proposal required")
    if target is None: return _result(AuthorizationAdmissionReasonCode.TARGET_CONTEXT_UNAVAILABLE)
    if contract is None: return _result(AuthorizationAdmissionReasonCode.CONTRACT_CONTEXT_UNAVAILABLE)
    if policy is None: return _result(AuthorizationAdmissionReasonCode.POLICY_CONTEXT_UNAVAILABLE)
    if approval is None: return _result(AuthorizationAdmissionReasonCode.AUTHENTICATED_APPROVAL_UNAVAILABLE)
    if issuer is None: return _result(AuthorizationAdmissionReasonCode.ISSUER_AUTHORITY_UNAVAILABLE)
    if root is None: return _result(AuthorizationAdmissionReasonCode.ROOT_CONTEXT_UNAVAILABLE)
    if type(target) is not AdmittedTargetRegistration or type(contract) is not ContractAuthorityCeiling or type(policy) is not AuthorizationPolicyContext or type(approval) is not AuthenticatedHumanAuthorizationApproval or type(issuer) is not DirectIssuerAuthorityEnvelope or type(root) is not OrdinaryRootProtectionContext:
        raise TypeError("wrong exact authority context type")
    if any(item.target_registration_id != proposal.target_registration_id for item in (target, contract, policy, issuer)):
        return _result(AuthorizationAdmissionReasonCode.TARGET_REGISTRATION_MISMATCH)
    if root.repository_id != target.repository_id:
        return _result(AuthorizationAdmissionReasonCode.TARGET_REGISTRATION_MISMATCH)
    epoch = target.policy_epoch_identity
    if policy.policy_epoch_identity != epoch or issuer.policy_epoch_identity != epoch or root.policy_epoch_identity != epoch:
        return _result(AuthorizationAdmissionReasonCode.POLICY_EPOCH_MISMATCH)
    if approval.policy_epoch_identity != epoch:
        return _result(AuthorizationAdmissionReasonCode.POLICY_EPOCH_MISMATCH)
    if proposal.issuer_principal_id != approval.human_principal_id or proposal.issuer_principal_id != issuer.human_principal_id:
        return _result(AuthorizationAdmissionReasonCode.AUTHENTICATION_BINDING_MISMATCH)
    if proposal.proposal_raw_sha256 != approval.proposal_raw_sha256:
        return _result(AuthorizationAdmissionReasonCode.AUTHENTICATION_BINDING_MISMATCH)
    if _binding_mismatch(proposal, contract, policy, issuer):
        return _result(AuthorizationAdmissionReasonCode.CONTRACT_BINDING_MISMATCH)
    if any(cap not in policy.maximum_capabilities for cap in proposal.capabilities):
        return _result(AuthorizationAdmissionReasonCode.CAPABILITY_NOT_PERMITTED)
    for ceiling in (contract.requested_capabilities, target.allowed_task_capabilities, issuer.maximum_capabilities):
        if any(cap not in ceiling for cap in proposal.capabilities):
            return _result(AuthorizationAdmissionReasonCode.CAPABILITY_NOT_PERMITTED)
    scope_reason = _scope_and_prohibitions(proposal, target, contract, policy, (issuer.maximum_mutation_scope,))
    if scope_reason is not None: return _result(scope_reason)
    reason = _ops_fit_all(proposal.operational_constraints, (
        contract_to_ops(contract), policy.maximum_operational_constraints,
        issuer.maximum_operational_constraints,
    ), target)
    if reason is not None: return _result(reason)
    if root.root_protected_mutation_scope is not None and scopes_overlap(proposal.mutation_scope, root.root_protected_mutation_scope):
        return _result(AuthorizationAdmissionReasonCode.ROOT_SCOPE_OVERLAP)
    reason = _risk_check(policy, proposal, target, contract, (issuer.maximum_authorization_risk_ceiling,))
    if reason is not None: return _result(reason)
    reason = _delegation_fit(
        proposal.delegation, proposal.capabilities, proposal.mutation_scope, proposal.operational_constraints,
        policy, contract, issuer.maximum_delegation_depth, issuer.maximum_delegable_capabilities,
        issuer.maximum_delegable_mutation_scope, issuer.maximum_delegable_operational_constraints,
        proposal.risk_ceiling, issuer.maximum_delegation_risk_ceiling,
    )
    if reason is not None: return _result(reason)
    auth_id = _authorization_id(proposal, epoch, target.target_registration_id)
    admitted = _new_private(
        AdmittedAuthorization, _SUCCESS_KEY, _SUCCESS_KEY, authorization_id=auth_id,
        kind=AuthorizationKind.DIRECT_HUMAN,
        authority_source=DirectAuthoritySource(approval.human_principal_id, approval.authentication_event_id),
        ancestry=(), task_id=proposal.task_id, contract_id=proposal.contract_id,
        contract_raw_sha256=proposal.contract_raw_sha256, target_registration_id=proposal.target_registration_id,
        authorized_capabilities=proposal.capabilities, authorized_mutation_scope=proposal.mutation_scope,
        authorized_operational_constraints=proposal.operational_constraints,
        effective_authoritative_risk=policy.effective_authoritative_risk,
        authorization_risk_ceiling=proposal.risk_ceiling, delegation=proposal.delegation,
        policy_epoch_identity=epoch,
    )
    return _result(AuthorizationAdmissionReasonCode.ADMITTED, admitted)


def admit_delegated_authorization(
    proposal: CandidateAuthorizationProposal,
    target: AdmittedTargetRegistration | None,
    contract: ContractAuthorityCeiling | None,
    policy: AuthorizationPolicyContext | None,
    parent: AdmittedAuthorization | None,
    root: OrdinaryRootProtectionContext | None,
) -> AuthorizationAdmissionResult:
    if type(proposal) is not CandidateAuthorizationProposal or proposal.kind is not AuthorizationKind.DELEGATED:
        raise TypeError("delegated proposal required")
    if target is None: return _result(AuthorizationAdmissionReasonCode.TARGET_CONTEXT_UNAVAILABLE)
    if contract is None: return _result(AuthorizationAdmissionReasonCode.CONTRACT_CONTEXT_UNAVAILABLE)
    if policy is None: return _result(AuthorizationAdmissionReasonCode.POLICY_CONTEXT_UNAVAILABLE)
    if parent is None: return _result(AuthorizationAdmissionReasonCode.PARENT_AUTHORIZATION_UNAVAILABLE)
    if root is None: return _result(AuthorizationAdmissionReasonCode.ROOT_CONTEXT_UNAVAILABLE)
    if type(target) is not AdmittedTargetRegistration or type(contract) is not ContractAuthorityCeiling or type(policy) is not AuthorizationPolicyContext or type(parent) is not AdmittedAuthorization or type(root) is not OrdinaryRootProtectionContext:
        raise TypeError("wrong exact authority context type")
    if target.target_registration_id != proposal.target_registration_id or contract.target_registration_id != proposal.target_registration_id or policy.target_registration_id != proposal.target_registration_id:
        return _result(AuthorizationAdmissionReasonCode.TARGET_REGISTRATION_MISMATCH)
    if root.repository_id != target.repository_id:
        return _result(AuthorizationAdmissionReasonCode.TARGET_REGISTRATION_MISMATCH)
    epoch = target.policy_epoch_identity
    if policy.policy_epoch_identity != epoch or root.policy_epoch_identity != epoch:
        return _result(AuthorizationAdmissionReasonCode.POLICY_EPOCH_MISMATCH)
    if proposal.parent_authorization_id != parent.authorization_id:
        return _result(AuthorizationAdmissionReasonCode.PARENT_AUTHORIZATION_MISMATCH)
    if parent.target_registration_id != proposal.target_registration_id:
        return _result(AuthorizationAdmissionReasonCode.PARENT_TARGET_MISMATCH)
    if parent.policy_epoch_identity != epoch:
        return _result(AuthorizationAdmissionReasonCode.PARENT_POLICY_EPOCH_MISMATCH)
    if _binding_mismatch(proposal, contract, policy):
        return _result(AuthorizationAdmissionReasonCode.CONTRACT_BINDING_MISMATCH)
    if len(parent.ancestry) >= G3_MAX_DELEGATION_DEPTH or len(set(parent.ancestry)) != len(parent.ancestry) or parent.authorization_id in parent.ancestry:
        return _result(AuthorizationAdmissionReasonCode.ANCESTRY_INVALID)
    if parent.delegation.remaining_depth < 1:
        return _result(AuthorizationAdmissionReasonCode.DELEGATION_DEPTH_EXCEEDED)
    if any(cap not in policy.maximum_capabilities for cap in proposal.capabilities):
        return _result(AuthorizationAdmissionReasonCode.CAPABILITY_NOT_PERMITTED)
    for ceiling in (parent.delegation.delegable_capabilities, contract.requested_capabilities, target.allowed_task_capabilities):
        if any(cap not in ceiling for cap in proposal.capabilities):
            return _result(AuthorizationAdmissionReasonCode.CAPABILITY_NOT_PERMITTED)
    scope_reason = _scope_and_prohibitions(proposal, target, contract, policy, (parent.delegation.delegable_mutation_scope,))
    if scope_reason is not None: return _result(scope_reason)
    reason = _ops_fit_all(proposal.operational_constraints, (
        parent.delegation.delegable_operational_constraints, contract_to_ops(contract),
        policy.maximum_operational_constraints,
    ), target)
    if reason is not None: return _result(reason)
    if root.root_protected_mutation_scope is not None and scopes_overlap(proposal.mutation_scope, root.root_protected_mutation_scope):
        return _result(AuthorizationAdmissionReasonCode.ROOT_SCOPE_OVERLAP)
    reason = _risk_check(policy, proposal, target, contract, (() if parent.delegation.risk_ceiling is None else (parent.delegation.risk_ceiling,)))
    if reason is not None: return _result(reason)
    reason = _delegation_fit(
        proposal.delegation, proposal.capabilities, proposal.mutation_scope, proposal.operational_constraints,
        policy, contract, parent.delegation.remaining_depth - 1, parent.delegation.delegable_capabilities,
        parent.delegation.delegable_mutation_scope, parent.delegation.delegable_operational_constraints,
        proposal.risk_ceiling, parent.delegation.risk_ceiling,
    )
    if reason is not None: return _result(reason)
    ancestry = parent.ancestry + (parent.authorization_id,)
    if len(ancestry) > G3_MAX_DELEGATION_DEPTH or len(set(ancestry)) != len(ancestry):
        return _result(AuthorizationAdmissionReasonCode.ANCESTRY_INVALID)
    auth_id = _authorization_id(proposal, epoch, target.target_registration_id)
    if auth_id in ancestry:
        return _result(AuthorizationAdmissionReasonCode.ANCESTRY_INVALID)
    admitted = _new_private(
        AdmittedAuthorization, _SUCCESS_KEY, _SUCCESS_KEY, authorization_id=auth_id,
        kind=AuthorizationKind.DELEGATED, authority_source=DelegatedAuthoritySource(parent.authorization_id),
        ancestry=ancestry, task_id=proposal.task_id, contract_id=proposal.contract_id,
        contract_raw_sha256=proposal.contract_raw_sha256, target_registration_id=proposal.target_registration_id,
        authorized_capabilities=proposal.capabilities, authorized_mutation_scope=proposal.mutation_scope,
        authorized_operational_constraints=proposal.operational_constraints,
        effective_authoritative_risk=policy.effective_authoritative_risk,
        authorization_risk_ceiling=proposal.risk_ceiling, delegation=proposal.delegation,
        policy_epoch_identity=epoch,
    )
    return _result(AuthorizationAdmissionReasonCode.ADMITTED, admitted)


def contract_to_ops(contract: ContractAuthorityCeiling) -> AuthorizationOperationalConstraints:
    refs = () if contract.integration_ref is None else (contract.integration_ref,)
    return AuthorizationOperationalConstraints(refs, contract.controlled_runtime_profile_ids, contract.repair_max_attempts)


def _contract_authority_ceiling_from_admitted_contract(contract: object) -> ContractAuthorityCeiling:
    """The sole production construction path from canonical contract to G3 ceiling."""
    from .contract import AdmittedIssueContract

    if type(contract) is not AdmittedIssueContract:
        raise TypeError("exact AdmittedIssueContract required")
    integration_ref = (
        contract.integration_ref
        if TaskCapability.MERGE in contract.requested_operations
        else None
    )
    return _new_private(
        ContractAuthorityCeiling, _AUTHORITY_KEY, _AUTHORITY_KEY,
        task_id=contract.task_id,
        contract_id=contract.contract_id,
        contract_raw_sha256=contract.contract_raw_sha256,
        target_registration_id=contract.target_registration_id,
        requested_capabilities=contract.requested_operations,
        allowed_mutation_scope=contract.allowed_mutation_scope,
        prohibited_mutation_scope=contract.prohibited_mutation_scope,
        risk_floor=contract.risk_floor,
        integration_ref=integration_ref,
        controlled_runtime_profile_ids=tuple(
            identity.config_id for identity in contract.runtime_profile_identities
        ),
        repair_max_attempts=contract.repair_max_attempts,
        delegation_max_depth=contract.delegation_limits.max_depth,
        delegable_capabilities=contract.delegation_limits.delegable_operations,
        delegation_risk_ceiling=contract.delegation_limits.risk_ceiling,
    )
