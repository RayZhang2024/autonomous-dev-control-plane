"""Candidate Target Registration loading and ordinary registration admission."""

from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType

from .decision import Decision
from .errors import (
    IdentityValidationError,
    ParseFailure,
    TargetRegistrationAdmissionReasonCode,
    TargetRegistrationFailure,
    TargetRegistrationFailureCode,
)
from .identity import ImmutableConfigId
from .manifest import PolicyEpochIdentity
from .parsing import ParseLimits, ParsedJsonDocument, parse_trusted_json
from .scope import (
    AuthenticationEventId,
    CanonicalBranchRef,
    GitHubRepositoryId,
    G3_MAX_CAPABILITIES,
    G3_MAX_PROFILE_IDS,
    G3_MAX_PROTECTED_REFS,
    HumanPrincipalId,
    MutationScope,
    ParsedMutationScope,
    RiskRelation,
    RiskTier,
    ScopeParseProblem,
    ServicePrincipalId,
    TargetRegistrationId,
    TaskCapability,
    compare_risk,
    parse_mutation_scope_json,
    scope_contains,
)

G3_TARGET_REGISTRATION_MAX_BYTES = 1 * 1024 * 1024
G3_MAX_DEPTH = 32
_FORMAT = "autodev.target-registration/v1"
_PATH_MODEL = "git_utf8_regular_file/v1"
_SUCCESS_KEY = object()
_AUTHORITY_KEY = object()
_FIELDS = (
    "format", "repository", "path_model", "protected_refs", "allowed_task_capabilities",
    "ordinary_allowed_scope", "ordinary_forbidden_scope", "risk_ceiling", "target_publication",
    "merge", "validation_profile_ids", "controlled_runtime_profile_ids", "event_state_profile_ids",
    "adapter_config_id",
)


class TargetRegistrationRootImpact(Enum):
    NO_ROOT_IMPACT = "NO_ROOT_IMPACT"
    ROOT_IMPACT = "ROOT_IMPACT"
    INDETERMINATE = "INDETERMINATE"


@dataclass(frozen=True, slots=True)
class TargetPublication:
    service_identity: ServicePrincipalId
    publication_profile_id: ImmutableConfigId

    def __post_init__(self) -> None:
        if type(self.service_identity) is not ServicePrincipalId:
            raise TypeError("service_identity must be exactly ServicePrincipalId")
        if type(self.publication_profile_id) is not ImmutableConfigId:
            raise TypeError("publication_profile_id must be exactly ImmutableConfigId")


@dataclass(frozen=True, slots=True)
class MergeConfiguration:
    service_identity: ServicePrincipalId
    merge_profile_id: ImmutableConfigId
    allowed_integration_refs: tuple[CanonicalBranchRef, ...]

    def __post_init__(self) -> None:
        if type(self.service_identity) is not ServicePrincipalId:
            raise TypeError("service_identity must be exactly ServicePrincipalId")
        if type(self.merge_profile_id) is not ImmutableConfigId:
            raise TypeError("merge_profile_id must be exactly ImmutableConfigId")
        _unique_exact(self.allowed_integration_refs, CanonicalBranchRef, G3_MAX_PROTECTED_REFS)
        if not self.allowed_integration_refs:
            raise ValueError("merge refs must be non-empty")


@dataclass(frozen=True, slots=True)
class _ParsedMerge:
    value: MergeConfiguration
    has_duplicates: bool


@dataclass(frozen=True, slots=True, init=False)
class CandidateTargetRegistration:
    source_document: ParsedJsonDocument
    target_registration_id: TargetRegistrationId
    repository_id: GitHubRepositoryId
    repository_display_name: str
    path_model: str
    protected_refs: tuple[CanonicalBranchRef, ...]
    allowed_task_capabilities: tuple[TaskCapability, ...]
    ordinary_allowed_scope: MutationScope
    ordinary_forbidden_scope: MutationScope
    risk_ceiling: RiskTier
    target_publication: TargetPublication | None
    merge: MergeConfiguration | None
    validation_profile_ids: tuple[ImmutableConfigId, ...]
    controlled_runtime_profile_ids: tuple[ImmutableConfigId, ...]
    event_state_profile_ids: tuple[ImmutableConfigId, ...]
    adapter_config_id: ImmutableConfigId

    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("use load_candidate_target_registration")

    @classmethod
    def _from_validated(cls, key: object, **fields: object) -> "CandidateTargetRegistration":
        if key is not _SUCCESS_KEY:
            raise TypeError("internal validated construction only")
        result = object.__new__(cls)
        for name, value in fields.items():
            object.__setattr__(result, name, value)
        return result


@dataclass(frozen=True, slots=True, init=False)
class AuthenticatedTargetAdminApproval:
    human_principal_id: HumanPrincipalId
    authentication_event_id: AuthenticationEventId
    target_registration_id: TargetRegistrationId
    policy_epoch_identity: PolicyEpochIdentity

    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("authority provenance must come from a trusted boundary")


@dataclass(frozen=True, slots=True, init=False)
class TargetRegistrationRootImpactAssessment:
    target_registration_id: TargetRegistrationId
    repository_id: GitHubRepositoryId
    policy_epoch_identity: PolicyEpochIdentity
    root_impact: TargetRegistrationRootImpact

    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("root assessment must come from a trusted boundary")


@dataclass(frozen=True, slots=True, init=False)
class TargetRegistrationPolicyContext:
    policy_epoch_identity: PolicyEpochIdentity
    target_registration_id: TargetRegistrationId
    repository_id: GitHubRepositoryId
    permitted_admin_principals: tuple[HumanPrincipalId, ...]
    maximum_allowed_task_capabilities: tuple[TaskCapability, ...]
    maximum_ordinary_allowed_scope: MutationScope
    maximum_target_risk_ceiling: RiskTier
    permitted_target_publication_service_identities: tuple[ServicePrincipalId, ...]
    permitted_merge_service_identities: tuple[ServicePrincipalId, ...]
    permitted_publication_profile_ids: tuple[ImmutableConfigId, ...]
    permitted_merge_profile_ids: tuple[ImmutableConfigId, ...]
    permitted_validation_profile_ids: tuple[ImmutableConfigId, ...]
    permitted_controlled_runtime_profile_ids: tuple[ImmutableConfigId, ...]
    permitted_event_state_profile_ids: tuple[ImmutableConfigId, ...]
    permitted_adapter_config_ids: tuple[ImmutableConfigId, ...]
    risk_relation: RiskRelation

    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("policy context must come from a trusted boundary")


@dataclass(frozen=True, slots=True, init=False)
class AdmittedTargetRegistration:
    target_registration_id: TargetRegistrationId
    repository_id: GitHubRepositoryId
    policy_epoch_identity: PolicyEpochIdentity
    approved_human_principal_id: HumanPrincipalId
    authentication_event_id: AuthenticationEventId
    path_model: str
    protected_refs: tuple[CanonicalBranchRef, ...]
    allowed_task_capabilities: tuple[TaskCapability, ...]
    ordinary_allowed_scope: MutationScope
    ordinary_forbidden_scope: MutationScope
    risk_ceiling: RiskTier
    target_publication: TargetPublication | None
    merge: MergeConfiguration | None
    validation_profile_ids: tuple[ImmutableConfigId, ...]
    controlled_runtime_profile_ids: tuple[ImmutableConfigId, ...]
    event_state_profile_ids: tuple[ImmutableConfigId, ...]
    adapter_config_id: ImmutableConfigId

    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("use admit_target_registration")


@dataclass(frozen=True, slots=True)
class TargetRegistrationAdmissionResult:
    decision: Decision
    reason_code: TargetRegistrationAdmissionReasonCode
    admitted_registration: AdmittedTargetRegistration | None = None

    def __post_init__(self) -> None:
        if type(self.decision) is not Decision or type(self.reason_code) is not TargetRegistrationAdmissionReasonCode:
            raise TypeError("wrong admission result domain")
        if self.reason_code is TargetRegistrationAdmissionReasonCode.ADMITTED:
            if self.decision is not Decision.ALLOW or type(self.admitted_registration) is not AdmittedTargetRegistration:
                raise ValueError("admitted result invariant")
        elif self.decision is Decision.ALLOW or self.admitted_registration is not None:
            raise ValueError("failure result cannot carry admitted registration")


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
            raise TypeError("wrong canonical collection item type")
        if value in seen:
            raise ValueError("duplicate canonical identity")
        seen.add(value)
    return values


def _failure(code: TargetRegistrationFailureCode, parse: ParseFailure | None = None) -> TargetRegistrationFailure:
    return TargetRegistrationFailure(code, parse)


def _field_set(value: object, fields: tuple[str, ...]) -> TargetRegistrationFailure | None:
    if type(value) is not MappingProxyType:
        return _failure(TargetRegistrationFailureCode.INVALID_FIELD_TYPE)
    if any(field not in value for field in fields):
        return _failure(TargetRegistrationFailureCode.MISSING_FIELD)
    allowed = frozenset(fields)
    if any(field not in allowed for field in value):
        return _failure(TargetRegistrationFailureCode.UNKNOWN_FIELD)
    return None


def _problem(kind: str) -> TargetRegistrationFailure:
    mapping = {
        "type": TargetRegistrationFailureCode.INVALID_FIELD_TYPE,
        "missing": TargetRegistrationFailureCode.MISSING_FIELD,
        "unknown": TargetRegistrationFailureCode.UNKNOWN_FIELD,
        "value": TargetRegistrationFailureCode.INVALID_FIELD_VALUE,
        "duplicate": TargetRegistrationFailureCode.DUPLICATE_IDENTITY,
        "empty": TargetRegistrationFailureCode.EMPTY_REQUIRED_SET,
    }
    return _failure(mapping[kind])


def _enum_values(value: object, enum_type: type[Enum], maximum: int) -> tuple[tuple[Enum, ...], bool] | TargetRegistrationFailure:
    if type(value) is not tuple:
        return _failure(TargetRegistrationFailureCode.INVALID_FIELD_TYPE)
    if len(value) > maximum:
        return _failure(TargetRegistrationFailureCode.INVALID_FIELD_VALUE)
    converted: list[Enum] = []
    seen: set[Enum] = set()
    duplicate = False
    for item in value:
        if type(item) is not str:
            return _failure(TargetRegistrationFailureCode.INVALID_FIELD_TYPE)
        try:
            parsed = enum_type(item)
        except ValueError:
            return _failure(TargetRegistrationFailureCode.INVALID_FIELD_VALUE)
        duplicate |= parsed in seen
        seen.add(parsed)
        converted.append(parsed)
    return tuple(converted), duplicate


def _identity_values(value: object, identity_type: type, maximum: int) -> tuple[tuple[object, ...], bool] | TargetRegistrationFailure:
    if type(value) is not tuple:
        return _failure(TargetRegistrationFailureCode.INVALID_FIELD_TYPE)
    if len(value) > maximum:
        return _failure(TargetRegistrationFailureCode.INVALID_FIELD_VALUE)
    converted: list[object] = []
    seen: set[object] = set()
    duplicate = False
    for item in value:
        if type(item) is not str:
            return _failure(TargetRegistrationFailureCode.INVALID_FIELD_TYPE)
        try:
            parsed = identity_type(item)
        except (IdentityValidationError, ValueError):
            return _failure(TargetRegistrationFailureCode.INVALID_FIELD_VALUE)
        duplicate |= parsed in seen
        seen.add(parsed)
        converted.append(parsed)
    return tuple(converted), duplicate


def _publication(value: object) -> TargetPublication | None | TargetRegistrationFailure:
    if value is None:
        return None
    fields = ("service_identity", "publication_profile_id")
    problem = _field_set(value, fields)
    if problem is not None:
        return problem
    for field in fields:
        if type(value[field]) is not str:
            return _failure(TargetRegistrationFailureCode.INVALID_FIELD_TYPE)
    try:
        return TargetPublication(ServicePrincipalId(value[fields[0]]), ImmutableConfigId(value[fields[1]]))
    except (IdentityValidationError, ValueError):
        return _failure(TargetRegistrationFailureCode.INVALID_FIELD_VALUE)


def _merge(value: object) -> _ParsedMerge | None | TargetRegistrationFailure:
    if value is None:
        return None
    fields = ("service_identity", "merge_profile_id", "allowed_integration_refs")
    problem = _field_set(value, fields)
    if problem is not None:
        return problem
    if type(value[fields[0]]) is not str or type(value[fields[1]]) is not str or type(value[fields[2]]) is not tuple:
        return _failure(TargetRegistrationFailureCode.INVALID_FIELD_TYPE)
    try:
        service_identity = ServicePrincipalId(value[fields[0]])
        merge_profile_id = ImmutableConfigId(value[fields[1]])
    except (IdentityValidationError, ValueError):
        return _failure(TargetRegistrationFailureCode.INVALID_FIELD_VALUE)
    refs_result = _identity_values(value[fields[2]], CanonicalBranchRef, G3_MAX_PROTECTED_REFS)
    if type(refs_result) is TargetRegistrationFailure:
        return refs_result
    refs, duplicate = refs_result
    if not refs:
        return _failure(TargetRegistrationFailureCode.EMPTY_REQUIRED_SET)
    try:
        unique_refs = tuple(dict.fromkeys(refs))
        return _ParsedMerge(MergeConfiguration(
            service_identity, merge_profile_id, unique_refs
        ), duplicate)
    except ValueError:
        return _failure(TargetRegistrationFailureCode.INVALID_FIELD_VALUE)


def load_candidate_target_registration(raw: object) -> CandidateTargetRegistration | TargetRegistrationFailure:
    if type(raw) is not bytes:
        return _failure(TargetRegistrationFailureCode.INVALID_INPUT_TYPE)
    if len(raw) > G3_TARGET_REGISTRATION_MAX_BYTES:
        return _failure(TargetRegistrationFailureCode.BYTE_LIMIT_EXCEEDED)
    document = parse_trusted_json(raw, ParseLimits(G3_TARGET_REGISTRATION_MAX_BYTES, G3_MAX_DEPTH))
    if type(document) is ParseFailure:
        return _failure(TargetRegistrationFailureCode.PARSE_FAILED, document)
    value = document.value
    if type(value) is not MappingProxyType:
        return _failure(TargetRegistrationFailureCode.INVALID_TOP_LEVEL)
    if any(field not in value for field in _FIELDS):
        return _failure(TargetRegistrationFailureCode.MISSING_FIELD)
    allowed = frozenset(_FIELDS)
    if any(field not in allowed for field in value):
        return _failure(TargetRegistrationFailureCode.UNKNOWN_FIELD)
    type_checks = (
        ("format", str), ("repository", MappingProxyType), ("path_model", str),
        ("protected_refs", tuple), ("allowed_task_capabilities", tuple),
        ("ordinary_allowed_scope", tuple), ("ordinary_forbidden_scope", tuple), ("risk_ceiling", str),
        ("target_publication", (MappingProxyType, type(None))), ("merge", (MappingProxyType, type(None))),
        ("validation_profile_ids", tuple), ("controlled_runtime_profile_ids", tuple),
        ("event_state_profile_ids", tuple), ("adapter_config_id", str),
    )
    for field, expected in type_checks:
        if isinstance(expected, tuple):
            valid = type(value[field]) in expected
        else:
            valid = type(value[field]) is expected
        if not valid:
            return _failure(TargetRegistrationFailureCode.INVALID_FIELD_TYPE)
    if value["format"] != _FORMAT:
        return _failure(TargetRegistrationFailureCode.INVALID_FIELD_VALUE)

    repository = value["repository"]
    problem = _field_set(repository, ("platform", "repository_id", "display_name"))
    if problem is not None:
        return problem
    for field in ("platform", "repository_id", "display_name"):
        if type(repository[field]) is not str:
            return _failure(TargetRegistrationFailureCode.INVALID_FIELD_TYPE)
    if repository["platform"] != "github":
        return _failure(TargetRegistrationFailureCode.INVALID_FIELD_VALUE)
    try:
        repository_id = GitHubRepositoryId(repository["repository_id"])
    except ValueError:
        return _failure(TargetRegistrationFailureCode.INVALID_FIELD_VALUE)
    if not 1 <= len(repository["display_name"]) <= 512:
        return _failure(TargetRegistrationFailureCode.INVALID_FIELD_VALUE)
    if value["path_model"] != _PATH_MODEL:
        return _failure(TargetRegistrationFailureCode.INVALID_FIELD_VALUE)

    protected_result = _identity_values(value["protected_refs"], CanonicalBranchRef, G3_MAX_PROTECTED_REFS)
    if type(protected_result) is TargetRegistrationFailure:
        return protected_result
    protected_refs, protected_duplicate = protected_result
    capabilities_result = _enum_values(value["allowed_task_capabilities"], TaskCapability, G3_MAX_CAPABILITIES)
    if type(capabilities_result) is TargetRegistrationFailure:
        return capabilities_result
    capabilities, capability_duplicate = capabilities_result
    allowed_parsed = parse_mutation_scope_json(value["ordinary_allowed_scope"], defer_duplicates=True)
    if type(allowed_parsed) is ScopeParseProblem:
        return _problem(allowed_parsed.kind)
    forbidden_parsed = parse_mutation_scope_json(value["ordinary_forbidden_scope"], defer_duplicates=True)
    if type(forbidden_parsed) is ScopeParseProblem:
        return _problem(forbidden_parsed.kind)
    try:
        risk_ceiling = RiskTier(value["risk_ceiling"])
    except ValueError:
        return _failure(TargetRegistrationFailureCode.INVALID_FIELD_VALUE)
    publication = _publication(value["target_publication"])
    if type(publication) is TargetRegistrationFailure:
        return publication
    parsed_merge = _merge(value["merge"])
    if type(parsed_merge) is TargetRegistrationFailure:
        return parsed_merge
    merge = None if parsed_merge is None else parsed_merge.value
    profile_results = []
    profile_duplicates = []
    for field in ("validation_profile_ids", "controlled_runtime_profile_ids", "event_state_profile_ids"):
        result = _identity_values(value[field], ImmutableConfigId, G3_MAX_PROFILE_IDS)
        if type(result) is TargetRegistrationFailure:
            return result
        profile_results.append(result[0])
        profile_duplicates.append(result[1])
    try:
        adapter_config = ImmutableConfigId(value["adapter_config_id"])
    except IdentityValidationError:
        return _failure(TargetRegistrationFailureCode.INVALID_FIELD_VALUE)

    if protected_duplicate or capability_duplicate or allowed_parsed.has_duplicates or forbidden_parsed.has_duplicates or any(profile_duplicates) or (parsed_merge is not None and parsed_merge.has_duplicates):
        return _failure(TargetRegistrationFailureCode.DUPLICATE_IDENTITY)
    try:
        allowed_scope = MutationScope(allowed_parsed.rules)
        forbidden_scope = MutationScope(forbidden_parsed.rules)
    except ValueError:
        return _failure(TargetRegistrationFailureCode.DUPLICATE_IDENTITY)
    has_publish = TaskCapability.TARGET_PUBLISH in capabilities
    has_merge = TaskCapability.MERGE in capabilities
    has_runtime = TaskCapability.CONTROLLED_RUNTIME in capabilities
    if has_publish != (publication is not None) or has_merge != (merge is not None):
        return _failure(TargetRegistrationFailureCode.INCONSISTENT_CONFIGURATION)
    if has_runtime and not profile_results[1]:
        return _failure(TargetRegistrationFailureCode.EMPTY_REQUIRED_SET)
    if not has_runtime and profile_results[1]:
        return _failure(TargetRegistrationFailureCode.INCONSISTENT_CONFIGURATION)
    if publication is not None and merge is not None and publication.service_identity == merge.service_identity:
        return _failure(TargetRegistrationFailureCode.INCONSISTENT_CONFIGURATION)
    if merge is not None and any(ref not in protected_refs for ref in merge.allowed_integration_refs):
        return _failure(TargetRegistrationFailureCode.INCONSISTENT_CONFIGURATION)

    target_id = TargetRegistrationId(document.raw_sha256)
    return CandidateTargetRegistration._from_validated(
        _SUCCESS_KEY, source_document=document, target_registration_id=target_id,
        repository_id=repository_id, repository_display_name=repository["display_name"], path_model=_PATH_MODEL,
        protected_refs=protected_refs, allowed_task_capabilities=capabilities,
        ordinary_allowed_scope=allowed_scope, ordinary_forbidden_scope=forbidden_scope,
        risk_ceiling=risk_ceiling, target_publication=publication, merge=merge,
        validation_profile_ids=profile_results[0], controlled_runtime_profile_ids=profile_results[1],
        event_state_profile_ids=profile_results[2], adapter_config_id=adapter_config,
    )


_TARGET_ESCALATIONS = {
    TargetRegistrationAdmissionReasonCode.AUTHENTICATED_APPROVAL_UNAVAILABLE,
    TargetRegistrationAdmissionReasonCode.POLICY_CONTEXT_UNAVAILABLE,
    TargetRegistrationAdmissionReasonCode.ROOT_ASSESSMENT_UNAVAILABLE,
    TargetRegistrationAdmissionReasonCode.ROOT_IMPACT_INDETERMINATE,
    TargetRegistrationAdmissionReasonCode.RISK_RELATION_UNAVAILABLE,
}


def _target_result(reason: TargetRegistrationAdmissionReasonCode, admitted: AdmittedTargetRegistration | None = None) -> TargetRegistrationAdmissionResult:
    decision = Decision.ALLOW if reason is TargetRegistrationAdmissionReasonCode.ADMITTED else (
        Decision.ESCALATE if reason in _TARGET_ESCALATIONS else Decision.DENY
    )
    return TargetRegistrationAdmissionResult(decision, reason, admitted)


def admit_target_registration(
    candidate: CandidateTargetRegistration,
    approval: AuthenticatedTargetAdminApproval | None,
    policy_context: TargetRegistrationPolicyContext | None,
    root_assessment: TargetRegistrationRootImpactAssessment | None,
) -> TargetRegistrationAdmissionResult:
    if type(candidate) is not CandidateTargetRegistration:
        raise TypeError("candidate must be exactly CandidateTargetRegistration")
    if approval is None:
        return _target_result(TargetRegistrationAdmissionReasonCode.AUTHENTICATED_APPROVAL_UNAVAILABLE)
    if policy_context is None:
        return _target_result(TargetRegistrationAdmissionReasonCode.POLICY_CONTEXT_UNAVAILABLE)
    if root_assessment is None:
        return _target_result(TargetRegistrationAdmissionReasonCode.ROOT_ASSESSMENT_UNAVAILABLE)
    if type(approval) is not AuthenticatedTargetAdminApproval or type(policy_context) is not TargetRegistrationPolicyContext or type(root_assessment) is not TargetRegistrationRootImpactAssessment:
        raise TypeError("authority context has wrong exact type")
    target_id = candidate.target_registration_id
    if approval.target_registration_id != target_id or policy_context.target_registration_id != target_id or root_assessment.target_registration_id != target_id:
        return _target_result(TargetRegistrationAdmissionReasonCode.IDENTITY_MISMATCH)
    epoch = policy_context.policy_epoch_identity
    if approval.policy_epoch_identity != epoch or root_assessment.policy_epoch_identity != epoch:
        return _target_result(TargetRegistrationAdmissionReasonCode.POLICY_EPOCH_MISMATCH)
    if policy_context.repository_id != candidate.repository_id or root_assessment.repository_id != candidate.repository_id:
        return _target_result(TargetRegistrationAdmissionReasonCode.REPOSITORY_MISMATCH)
    if approval.human_principal_id not in policy_context.permitted_admin_principals:
        return _target_result(TargetRegistrationAdmissionReasonCode.ADMIN_NOT_PERMITTED)
    if root_assessment.root_impact is TargetRegistrationRootImpact.ROOT_IMPACT:
        return _target_result(TargetRegistrationAdmissionReasonCode.ROOT_IMPACT)
    if root_assessment.root_impact is TargetRegistrationRootImpact.INDETERMINATE:
        return _target_result(TargetRegistrationAdmissionReasonCode.ROOT_IMPACT_INDETERMINATE)
    if any(cap not in policy_context.maximum_allowed_task_capabilities for cap in candidate.allowed_task_capabilities):
        return _target_result(TargetRegistrationAdmissionReasonCode.POLICY_CAPABILITY_VIOLATION)
    if not scope_contains(policy_context.maximum_ordinary_allowed_scope, candidate.ordinary_allowed_scope):
        return _target_result(TargetRegistrationAdmissionReasonCode.POLICY_SCOPE_VIOLATION)
    risk = compare_risk(policy_context.risk_relation, candidate.risk_ceiling, policy_context.maximum_target_risk_ceiling)
    if risk is None:
        return _target_result(TargetRegistrationAdmissionReasonCode.RISK_RELATION_UNAVAILABLE)
    if not risk:
        return _target_result(TargetRegistrationAdmissionReasonCode.POLICY_RISK_VIOLATION)
    if candidate.target_publication is not None and (
        candidate.target_publication.service_identity not in policy_context.permitted_target_publication_service_identities
    ):
        return _target_result(TargetRegistrationAdmissionReasonCode.POLICY_SERVICE_IDENTITY_VIOLATION)
    if candidate.merge is not None and (
        candidate.merge.service_identity not in policy_context.permitted_merge_service_identities
    ):
        return _target_result(TargetRegistrationAdmissionReasonCode.POLICY_SERVICE_IDENTITY_VIOLATION)
    config_checks = (
        (() if candidate.target_publication is None else (candidate.target_publication.publication_profile_id,), policy_context.permitted_publication_profile_ids),
        (() if candidate.merge is None else (candidate.merge.merge_profile_id,), policy_context.permitted_merge_profile_ids),
        (candidate.validation_profile_ids, policy_context.permitted_validation_profile_ids),
        (candidate.controlled_runtime_profile_ids, policy_context.permitted_controlled_runtime_profile_ids),
        (candidate.event_state_profile_ids, policy_context.permitted_event_state_profile_ids),
        ((candidate.adapter_config_id,), policy_context.permitted_adapter_config_ids),
    )
    if any(any(item not in ceiling for item in values) for values, ceiling in config_checks):
        return _target_result(TargetRegistrationAdmissionReasonCode.POLICY_CONFIG_VIOLATION)
    admitted = _new_private(
        AdmittedTargetRegistration, _SUCCESS_KEY, _SUCCESS_KEY,
        target_registration_id=target_id, repository_id=candidate.repository_id,
        policy_epoch_identity=epoch, approved_human_principal_id=approval.human_principal_id,
        authentication_event_id=approval.authentication_event_id, path_model=candidate.path_model,
        protected_refs=candidate.protected_refs, allowed_task_capabilities=candidate.allowed_task_capabilities,
        ordinary_allowed_scope=candidate.ordinary_allowed_scope, ordinary_forbidden_scope=candidate.ordinary_forbidden_scope,
        risk_ceiling=candidate.risk_ceiling, target_publication=candidate.target_publication, merge=candidate.merge,
        validation_profile_ids=candidate.validation_profile_ids,
        controlled_runtime_profile_ids=candidate.controlled_runtime_profile_ids,
        event_state_profile_ids=candidate.event_state_profile_ids, adapter_config_id=candidate.adapter_config_id,
    )
    return _target_result(TargetRegistrationAdmissionReasonCode.ADMITTED, admitted)


def _authenticated_target_admin_approval_for_test(**fields: object) -> AuthenticatedTargetAdminApproval:
    _require_authority_fields(fields, {
        "human_principal_id": HumanPrincipalId,
        "authentication_event_id": AuthenticationEventId,
        "target_registration_id": TargetRegistrationId,
        "policy_epoch_identity": PolicyEpochIdentity,
    })
    return _new_private(AuthenticatedTargetAdminApproval, _AUTHORITY_KEY, _AUTHORITY_KEY, **fields)


def _target_registration_root_assessment_for_test(**fields: object) -> TargetRegistrationRootImpactAssessment:
    _require_authority_fields(fields, {
        "target_registration_id": TargetRegistrationId,
        "repository_id": GitHubRepositoryId,
        "policy_epoch_identity": PolicyEpochIdentity,
        "root_impact": TargetRegistrationRootImpact,
    })
    return _new_private(TargetRegistrationRootImpactAssessment, _AUTHORITY_KEY, _AUTHORITY_KEY, **fields)


def _target_registration_policy_context_for_test(**fields: object) -> TargetRegistrationPolicyContext:
    scalar_fields = {
        "policy_epoch_identity": PolicyEpochIdentity,
        "target_registration_id": TargetRegistrationId,
        "repository_id": GitHubRepositoryId,
        "maximum_ordinary_allowed_scope": MutationScope,
        "maximum_target_risk_ceiling": RiskTier,
        "risk_relation": RiskRelation,
    }
    collection_fields = {
        "permitted_admin_principals", "maximum_allowed_task_capabilities",
        "permitted_target_publication_service_identities", "permitted_merge_service_identities",
        "permitted_publication_profile_ids", "permitted_merge_profile_ids",
        "permitted_validation_profile_ids", "permitted_controlled_runtime_profile_ids",
        "permitted_event_state_profile_ids", "permitted_adapter_config_ids",
    }
    if set(fields) != set(scalar_fields) | collection_fields:
        raise TypeError("wrong target policy context fields")
    for name, item_type in scalar_fields.items():
        if type(fields[name]) is not item_type:
            raise TypeError(f"{name} has wrong exact type")
    for name, item_type, maximum in (
        ("permitted_admin_principals", HumanPrincipalId, G3_MAX_PROFILE_IDS),
        ("maximum_allowed_task_capabilities", TaskCapability, G3_MAX_CAPABILITIES),
        ("permitted_target_publication_service_identities", ServicePrincipalId, G3_MAX_PROFILE_IDS),
        ("permitted_merge_service_identities", ServicePrincipalId, G3_MAX_PROFILE_IDS),
        ("permitted_publication_profile_ids", ImmutableConfigId, G3_MAX_PROFILE_IDS),
        ("permitted_merge_profile_ids", ImmutableConfigId, G3_MAX_PROFILE_IDS),
        ("permitted_validation_profile_ids", ImmutableConfigId, G3_MAX_PROFILE_IDS),
        ("permitted_controlled_runtime_profile_ids", ImmutableConfigId, G3_MAX_PROFILE_IDS),
        ("permitted_event_state_profile_ids", ImmutableConfigId, G3_MAX_PROFILE_IDS),
        ("permitted_adapter_config_ids", ImmutableConfigId, G3_MAX_PROFILE_IDS),
    ):
        _unique_exact(fields[name], item_type, maximum)
    return _new_private(TargetRegistrationPolicyContext, _AUTHORITY_KEY, _AUTHORITY_KEY, **fields)


def _require_authority_fields(fields: dict[str, object], schema: dict[str, type]) -> None:
    if set(fields) != set(schema):
        raise TypeError("wrong authority context fields")
    for name, expected in schema.items():
        if type(fields[name]) is not expected:
            raise TypeError(f"{name} has wrong exact type")
