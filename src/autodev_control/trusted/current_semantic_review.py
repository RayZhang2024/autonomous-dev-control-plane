"""Current, non-bearer semantic-review structure (Issue #32).

This module is deliberately a consumer of G1, #33, and B1.  It owns no
configuration registry, observation implementation, persistence, evidence
currentness, or protected-operation authority.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from hashlib import sha256
from types import MappingProxyType

from .authorization import AdmittedAuthorization
from .backend import CanonicalCurrentSemanticReviewInputs, CanonicalStateOccurrenceBinding, ResolvedTargetRegistration
from .contract import (
    AdmittedIssueContract, CandidateIssueContract, ContractAcceptanceEvaluator,
    EvaluatorMechanism, IssueContractApplicabilityCode,
    TrustedEvaluatorConfigResolution, TrustedIssueContractApplicabilityContext,
    TrustedConfigIdentity, contract_json_value_digest, evaluate_issue_contract_applicability,
    load_candidate_issue_contract,
)
from .errors import ParseFailureCode, ResourceFailureCode
from .identity import CandidateMaterializationId, RawSha256, SemanticEvaluatorObligationId
from .materialization import AdmittedCandidateMaterialization, GitBlobMode, MutationFact, MutationKind, admitted_candidate_materialization_is_valid
from .operation import CandidateId
from .scope import GitHubRepositoryId, TaskId
from .scope import CanonicalGitPath
from .resources import RootManagedResourceKind, RootManagedResourceRef
from .review import (
    AssignmentIdentity, MaterialIdentity, RequirementMaterialAssignment,
    PullRequestIdentity, SemanticRequirement, SemanticRequirementId,
    SemanticReviewAssignment, ReviewInvocationId, ReviewSlot,
    SemanticReviewEffectiveSubject, SemanticReviewEffectiveSubjectId, TargetContextId,
)
from .semantic_config import (
    SemanticEvaluatorConfigResolutionReason, SemanticEvaluatorConfigResolutionStatus,
    SemanticReviewContextRequirement, TrustedSemanticEvaluatorResolution,
    resolve_semantic_evaluator_config,
)
from .semantic_context import (
    MAX_CURRENT_SEMANTIC_TARGET_CONTEXT_DEPENDENCIES,
    CurrentSemanticPullRequestContextReason, CurrentSemanticPullRequestContextResolution,
    CurrentSemanticTargetContextReason, CurrentSemanticTargetContextResolution,
    SemanticContextResolutionStatus, TrustedSemanticContextObservationSource,
    resolve_current_semantic_pull_request_context, resolve_current_semantic_target_context,
)
from .state import CandidateRecord, TaskRecord
from .state_reader import AuthoritativeStateDependency, AuthoritativeStateDependencySet

MAX_SEMANTIC_REVIEW_OBLIGATIONS = 256
MAX_SEMANTIC_RESOLUTION_BINDING_CELLS = 262_144
MAX_UNIQUE_SEMANTIC_EVALUATOR_CONFIGS_PER_RESOLUTION = 64
MAX_TOTAL_SEMANTIC_EVALUATOR_CONFIG_BYTES_PER_RESOLUTION = 8 * 1024 * 1024
_READER_KEY = object()
_RESOLVED_OBLIGATION_KEY = object()


class CurrentSemanticReviewResolutionStatus(Enum):
    RESOLVED = "RESOLVED"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    INDETERMINATE = "INDETERMINATE"
    DENIED = "DENIED"


class SemanticEvaluatorObligationResolutionStatus(Enum):
    RESOLVED = "RESOLVED"
    INDETERMINATE = "INDETERMINATE"
    DENIED = "DENIED"


class CurrentSemanticReviewResolutionReason(Enum):
    RESOLVED = "RESOLVED"
    NO_SEMANTIC_EVALUATORS = "NO_SEMANTIC_EVALUATORS"
    CONTRACT_NOT_APPLICABLE = "CONTRACT_NOT_APPLICABLE"
    CONTRACT_APPLICABILITY_INDETERMINATE = "CONTRACT_APPLICABILITY_INDETERMINATE"
    CANONICAL_INPUT_INDETERMINATE = "CANONICAL_INPUT_INDETERMINATE"
    CANONICAL_INPUT_MISMATCH = "CANONICAL_INPUT_MISMATCH"
    PARAMETER_RECOVERY_FAILED = "PARAMETER_RECOVERY_FAILED"
    CANDIDATE_MATERIALIZATION_MISMATCH = "CANDIDATE_MATERIALIZATION_MISMATCH"
    RESOLUTION_LIMIT_EXCEEDED = "RESOLUTION_LIMIT_EXCEEDED"
    SEMANTIC_CONFIG_BYTE_SOURCE_UNAVAILABLE = "SEMANTIC_CONFIG_BYTE_SOURCE_UNAVAILABLE"
    SEMANTIC_CONFIG_BYTE_SOURCE_INVALID = "SEMANTIC_CONFIG_BYTE_SOURCE_INVALID"
    SEMANTIC_CONFIG_AGGREGATE_LIMIT_EXCEEDED = "SEMANTIC_CONFIG_AGGREGATE_LIMIT_EXCEEDED"


class SemanticEvaluatorObligationResolutionReason(Enum):
    RESOLVED = "RESOLVED"
    EVALUATOR_RESOLUTION_UNAVAILABLE = "EVALUATOR_RESOLUTION_UNAVAILABLE"
    EVALUATOR_RESOLUTION_LIMIT_EXCEEDED = "EVALUATOR_RESOLUTION_LIMIT_EXCEEDED"
    EVALUATOR_RESOLUTION_NONCANONICAL = "EVALUATOR_RESOLUTION_NONCANONICAL"
    EVALUATOR_BINDING_MISMATCH = "EVALUATOR_BINDING_MISMATCH"
    EVALUATOR_RESOLUTION_INVALID = "EVALUATOR_RESOLUTION_INVALID"
    TARGET_CONTEXT_UNAVAILABLE = "TARGET_CONTEXT_UNAVAILABLE"
    TARGET_CONTEXT_CONFLICT = "TARGET_CONTEXT_CONFLICT"
    TARGET_CONTEXT_LIMIT_EXCEEDED = "TARGET_CONTEXT_LIMIT_EXCEEDED"
    PR_CONTEXT_UNAVAILABLE = "PR_CONTEXT_UNAVAILABLE"
    PR_CONTEXT_CONFLICT = "PR_CONTEXT_CONFLICT"


class SemanticEvidenceSubjectReconstructionStatus(Enum):
    RECONSTRUCTED = "RECONSTRUCTED"
    NOT_FOUND = "NOT_FOUND"
    NOT_SEMANTIC = "NOT_SEMANTIC"
    INDETERMINATE = "INDETERMINATE"
    DENIED = "DENIED"


@dataclass(frozen=True, slots=True, init=False)
class TrustedSemanticConfigByteReader:
    """Closed assembly input; availability only, never config selection."""
    _bytes_by_ref: MappingProxyType
    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("semantic config byte reader must come from trusted assembly")
    def read_exact(self, expected_ref: RootManagedResourceRef) -> bytes | None:
        if type(expected_ref) is not RootManagedResourceRef:
            raise TypeError("expected_ref must be exact RootManagedResourceRef")
        return self._bytes_by_ref.get(expected_ref)


def _assemble_trusted_semantic_config_byte_reader(key: object, values: MappingProxyType) -> TrustedSemanticConfigByteReader:
    if key is not _READER_KEY or type(values) is not MappingProxyType:
        raise TypeError("internal trusted construction only")
    if any(type(k) is not RootManagedResourceRef or type(v) is not bytes for k, v in values.items()):
        raise TypeError("trusted reader requires exact resource bytes")
    value = object.__new__(TrustedSemanticConfigByteReader)
    object.__setattr__(value, "_bytes_by_ref", values)
    return value


@dataclass(frozen=True, slots=True)
class CurrentReviewMaterial:
    material_id: MaterialIdentity
    repository_id: GitHubRepositoryId
    task_id: TaskId
    candidate_id: CandidateId
    candidate_materialization_id: CandidateMaterializationId
    path: CanonicalGitPath
    kind: MutationKind
    base_object_id: object | None
    candidate_object_id: object | None
    base_mode: GitBlobMode | None
    candidate_mode: GitBlobMode | None


@dataclass(frozen=True, slots=True)
class SemanticEvaluatorObligation:
    obligation_id: SemanticEvaluatorObligationId
    semantic_requirement: SemanticRequirement
    evaluator: ContractAcceptanceEvaluator
    parameters: object
    basic_resolution: TrustedEvaluatorConfigResolution


@dataclass(frozen=True, slots=True, init=False)
class ResolvedSemanticEvaluatorObligation:
    semantic_requirement: SemanticRequirement
    obligation_id: SemanticEvaluatorObligationId
    evaluator_parameters: object
    trusted_evaluator_resolution: TrustedSemanticEvaluatorResolution
    current_review_materials: tuple[CurrentReviewMaterial, ...]
    authoritative_dependencies: tuple[AuthoritativeStateDependency, ...]
    assignment: SemanticReviewAssignment
    effective_subject: SemanticReviewEffectiveSubject

    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("resolved semantic evaluator obligation must come from current trusted resolution")

    @classmethod
    def _from_validated(cls, key: object, **values: object) -> "ResolvedSemanticEvaluatorObligation":
        if key is not _RESOLVED_OBLIGATION_KEY:
            raise TypeError("internal resolved-obligation construction only")
        result = object.__new__(cls)
        for name, value in values.items():
            object.__setattr__(result, name, value)
        return result


@dataclass(frozen=True, slots=True)
class SemanticEvaluatorObligationResolution:
    obligation: SemanticEvaluatorObligation
    status: SemanticEvaluatorObligationResolutionStatus
    reason: SemanticEvaluatorObligationResolutionReason
    semantic_config_status: SemanticEvaluatorConfigResolutionStatus | None = None
    semantic_config_reason: SemanticEvaluatorConfigResolutionReason | None = None
    semantic_config_resource_failure_code: ResourceFailureCode | None = None
    semantic_config_parse_failure_code: ParseFailureCode | None = None
    resolved_obligation: ResolvedSemanticEvaluatorObligation | None = None

    def __post_init__(self) -> None:
        if type(self.obligation) is not SemanticEvaluatorObligation:
            raise TypeError("obligation resolution requires exact semantic obligation")
        if (type(self.status) is not SemanticEvaluatorObligationResolutionStatus
                or type(self.reason) is not SemanticEvaluatorObligationResolutionReason):
            raise TypeError("obligation resolution status and reason are closed enums")
        if type(self.semantic_config_status) is not SemanticEvaluatorConfigResolutionStatus or type(self.semantic_config_reason) is not SemanticEvaluatorConfigResolutionReason:
            raise TypeError("obligation resolution requires exact #33 diagnostics")
        if self.semantic_config_resource_failure_code is not None and type(self.semantic_config_resource_failure_code) is not ResourceFailureCode:
            raise TypeError("resource diagnostic must use the closed G2 resource-failure domain")
        if self.semantic_config_parse_failure_code is not None and type(self.semantic_config_parse_failure_code) is not ParseFailureCode:
            raise TypeError("parse diagnostic must use the closed parser-failure domain")
        if self.status is SemanticEvaluatorObligationResolutionStatus.RESOLVED:
            if (self.reason is not SemanticEvaluatorObligationResolutionReason.RESOLVED
                    or type(self.resolved_obligation) is not ResolvedSemanticEvaluatorObligation):
                raise ValueError("resolved outcome requires its exact resolved-obligation product")
        elif self.resolved_obligation is not None:
            raise ValueError("non-resolved outcome cannot carry a resolved obligation")

    @property
    def obligation_id(self) -> SemanticEvaluatorObligationId:
        return self.obligation.obligation_id

    @property
    def semantic_requirement(self) -> SemanticRequirement:
        return self.obligation.semantic_requirement

    @property
    def trusted_evaluator_resolution(self) -> TrustedSemanticEvaluatorResolution | None:
        return None if self.resolved_obligation is None else self.resolved_obligation.trusted_evaluator_resolution

    @property
    def target_context_id(self) -> object | None:
        return None if self.resolved_obligation is None else self.resolved_obligation.effective_subject.target_context_id

    @property
    def pr_id(self) -> object | None:
        return None if self.resolved_obligation is None else self.resolved_obligation.effective_subject.pr_id

    @property
    def authoritative_dependencies(self) -> tuple[AuthoritativeStateDependency, ...]:
        return () if self.resolved_obligation is None else self.resolved_obligation.authoritative_dependencies

    @property
    def assignment(self) -> SemanticReviewAssignment | None:
        return None if self.resolved_obligation is None else self.resolved_obligation.assignment

    @property
    def effective_subject(self) -> SemanticReviewEffectiveSubject | None:
        return None if self.resolved_obligation is None else self.resolved_obligation.effective_subject


@dataclass(frozen=True, slots=True)
class _ObligationWork:
    obligation: SemanticEvaluatorObligation
    status: CurrentSemanticReviewResolutionStatus
    reason: SemanticEvaluatorObligationResolutionReason
    semantic_config_status: SemanticEvaluatorConfigResolutionStatus | None = None
    semantic_config_reason: SemanticEvaluatorConfigResolutionReason | None = None
    trusted_evaluator_resolution: TrustedSemanticEvaluatorResolution | None = None
    target_context_id: object | None = None
    pr_id: object | None = None
    authoritative_dependencies: tuple[AuthoritativeStateDependency, ...] = ()
    semantic_config_resource_failure_code: ResourceFailureCode | None = None
    semantic_config_parse_failure_code: ParseFailureCode | None = None


@dataclass(frozen=True, slots=True)
class CurrentSemanticReviewResolutionResult:
    status: CurrentSemanticReviewResolutionStatus
    reason: CurrentSemanticReviewResolutionReason
    occurrence: CanonicalStateOccurrenceBinding
    obligation_outcomes: tuple[SemanticEvaluatorObligationResolution, ...]
    authoritative_dependencies: tuple[AuthoritativeStateDependency, ...] = ()
    applicability_code: IssueContractApplicabilityCode | None = None

    def __post_init__(self) -> None:
        if (type(self.status) is not CurrentSemanticReviewResolutionStatus
                or type(self.reason) is not CurrentSemanticReviewResolutionReason
                or type(self.occurrence) is not CanonicalStateOccurrenceBinding):
            raise TypeError("current semantic result uses closed status/reason and exact occurrence")
        if type(self.obligation_outcomes) is not tuple or any(type(item) is not SemanticEvaluatorObligationResolution for item in self.obligation_outcomes):
            raise TypeError("current semantic outcomes must be an exact immutable tuple")
        if type(self.authoritative_dependencies) is not tuple or any(type(item) is not AuthoritativeStateDependency for item in self.authoritative_dependencies):
            raise TypeError("current dependencies must be an exact immutable tuple")
        if self.applicability_code is not None and type(self.applicability_code) is not IssueContractApplicabilityCode:
            raise TypeError("applicability diagnostic must use the exact G1 code domain")
        if self.reason in (
            CurrentSemanticReviewResolutionReason.CONTRACT_NOT_APPLICABLE,
            CurrentSemanticReviewResolutionReason.CONTRACT_APPLICABILITY_INDETERMINATE,
        ):
            if self.applicability_code is None or self.applicability_code is IssueContractApplicabilityCode.APPLICABLE:
                raise ValueError("non-applicable result must preserve its exact non-APPLICABLE G1 code")
        elif self.applicability_code is not None:
            raise ValueError("non-applicability result cannot carry a G1 applicability code")
        try:
            AuthoritativeStateDependencySet(self.authoritative_dependencies)
        except (TypeError, ValueError) as exc:
            raise ValueError("current dependency union must remain canonical") from exc
        if self.status is not CurrentSemanticReviewResolutionStatus.RESOLVED and (self.obligation_outcomes or self.authoritative_dependencies):
            raise ValueError("global non-resolved result cannot expose a partial obligation view")


@dataclass(frozen=True, slots=True)
class SemanticEvidenceSubjectReconstructionResult:
    status: SemanticEvidenceSubjectReconstructionStatus
    subject: object | None = None


def semantic_requirement_id(contract: AdmittedIssueContract, requirement_id: object) -> SemanticRequirementId:
    return SemanticRequirementId(contract_json_value_digest((
        "autodev.contract-semantic-requirement/v1", contract.contract_id.value,
        contract.contract_raw_sha256.value, requirement_id.value,
    )).value)


def semantic_evaluator_obligation_id(contract: AdmittedIssueContract, requirement_id: object, evaluator: ContractAcceptanceEvaluator) -> SemanticEvaluatorObligationId:
    return SemanticEvaluatorObligationId(contract_json_value_digest((
        "autodev.contract-semantic-evaluator-obligation/v1", contract.contract_id.value,
        contract.contract_raw_sha256.value, requirement_id.value, evaluator.evaluation_id.value,
        evaluator.evaluator_ref.value, evaluator.config_identity.config_id.value,
        evaluator.config_identity.resource_id.value, evaluator.config_identity.resource_sha256.value,
        evaluator.parameter_value_digest.value,
    )))


def recover_semantic_evaluator_parameters(contract: AdmittedIssueContract, requirement_id: object, evaluator: ContractAcceptanceEvaluator) -> object | None:
    """Recover from raw admitted bytes only; do not accept a caller parameter tree."""
    if type(contract) is not AdmittedIssueContract or type(evaluator) is not ContractAcceptanceEvaluator:
        return None
    if sha256(contract.raw_bytes).hexdigest() != contract.contract_raw_sha256.value:
        return None
    parsed = load_candidate_issue_contract(contract.raw_bytes)
    if type(parsed) is not CandidateIssueContract:
        return None
    requirements = tuple(x for x in parsed.acceptance_requirements if x.requirement_id == requirement_id)
    if len(requirements) != 1:
        return None
    choices = tuple(x for x in requirements[0].evaluators if x.evaluation_id == evaluator.evaluation_id)
    if len(choices) != 1:
        return None
    raw = choices[0]
    if raw.mechanism is not evaluator.mechanism or raw.evaluator_ref != evaluator.evaluator_ref:
        return None
    if contract_json_value_digest(raw.parameters) != evaluator.parameter_value_digest:
        return None
    return raw.parameters


def _canonical_dependencies(values: tuple[AuthoritativeStateDependency, ...]) -> tuple[AuthoritativeStateDependency, ...] | None:
    by_locator: dict[object, AuthoritativeStateDependency] = {}
    for value in values:
        prior = by_locator.get(value.locator)
        if prior is not None and prior != value:
            return None
        by_locator[value.locator] = value
    result = tuple(sorted(by_locator.values(), key=lambda x: tuple(v.value for v in x.locator)))
    try:
        AuthoritativeStateDependencySet(result)
    except (TypeError, ValueError):
        return None
    return result


def _valid_target(value: object) -> bool:
    if type(value) is not CurrentSemanticTargetContextResolution:
        return False
    if type(value.dependencies) is not tuple:
        return False
    if value.status is SemanticContextResolutionStatus.RESOLVED:
        if (value.reason is not CurrentSemanticTargetContextReason.RESOLVED
                or type(value.target_context_id) is not TargetContextId
                or value.state_read_failure is not None
                or type(value.dependencies) is not tuple):
            return False
        if not 1 <= len(value.dependencies) <= MAX_CURRENT_SEMANTIC_TARGET_CONTEXT_DEPENDENCIES:
            return False
        try: AuthoritativeStateDependencySet(value.dependencies)
        except (TypeError, ValueError): return False
    elif value.target_context_id is not None or value.dependencies:
        return False
    return True


def _valid_pr(value: object) -> bool:
    if type(value) is not CurrentSemanticPullRequestContextResolution:
        return False
    if type(value.dependencies) is not tuple:
        return False
    if value.status is SemanticContextResolutionStatus.RESOLVED:
        if (value.reason is not CurrentSemanticPullRequestContextReason.RESOLVED
                or type(value.pull_request_identity) is not PullRequestIdentity
                or value.state_read_failure is not None
                or type(value.dependencies) is not tuple
                or len(value.dependencies) != 1):
            return False
        try:
            AuthoritativeStateDependencySet(value.dependencies)
        except (TypeError, ValueError):
            return False
        return type(value.dependencies[0]) is AuthoritativeStateDependency
    return value.pull_request_identity is None and not value.dependencies


def _context_reason(target: bool, value: object) -> tuple[CurrentSemanticReviewResolutionStatus, SemanticEvaluatorObligationResolutionReason]:
    if target:
        if not _valid_target(value): return CurrentSemanticReviewResolutionStatus.DENIED, SemanticEvaluatorObligationResolutionReason.TARGET_CONTEXT_CONFLICT
        if value.status is SemanticContextResolutionStatus.RESOLVED: return CurrentSemanticReviewResolutionStatus.RESOLVED, SemanticEvaluatorObligationResolutionReason.RESOLVED
        if value.status is SemanticContextResolutionStatus.INDETERMINATE and value.reason in (CurrentSemanticTargetContextReason.SOURCE_UNAVAILABLE, CurrentSemanticTargetContextReason.TARGET_PROFILE_SET_UNAVAILABLE, CurrentSemanticTargetContextReason.TARGET_PROFILE_SOURCE_UNAVAILABLE, CurrentSemanticTargetContextReason.TARGET_OBSERVATION_UNAVAILABLE): return CurrentSemanticReviewResolutionStatus.INDETERMINATE, SemanticEvaluatorObligationResolutionReason.TARGET_CONTEXT_UNAVAILABLE
        if value.status is SemanticContextResolutionStatus.DENIED and value.reason is CurrentSemanticTargetContextReason.TARGET_CONTEXT_LIMIT_EXCEEDED: return CurrentSemanticReviewResolutionStatus.DENIED, SemanticEvaluatorObligationResolutionReason.TARGET_CONTEXT_LIMIT_EXCEEDED
        return CurrentSemanticReviewResolutionStatus.DENIED, SemanticEvaluatorObligationResolutionReason.TARGET_CONTEXT_CONFLICT
    if not _valid_pr(value): return CurrentSemanticReviewResolutionStatus.DENIED, SemanticEvaluatorObligationResolutionReason.PR_CONTEXT_CONFLICT
    if value.status is SemanticContextResolutionStatus.RESOLVED: return CurrentSemanticReviewResolutionStatus.RESOLVED, SemanticEvaluatorObligationResolutionReason.RESOLVED
    if value.status is SemanticContextResolutionStatus.INDETERMINATE and value.reason in (CurrentSemanticPullRequestContextReason.SOURCE_UNAVAILABLE, CurrentSemanticPullRequestContextReason.PR_CONTEXT_UNAVAILABLE, CurrentSemanticPullRequestContextReason.PR_OBSERVATION_UNAVAILABLE, CurrentSemanticPullRequestContextReason.PR_OBSERVATION_INCOMPLETE, CurrentSemanticPullRequestContextReason.PR_OBSERVATION_MOVED): return CurrentSemanticReviewResolutionStatus.INDETERMINATE, SemanticEvaluatorObligationResolutionReason.PR_CONTEXT_UNAVAILABLE
    return CurrentSemanticReviewResolutionStatus.DENIED, SemanticEvaluatorObligationResolutionReason.PR_CONTEXT_CONFLICT


def derive_current_review_materials(materialization: AdmittedCandidateMaterialization) -> tuple[CurrentReviewMaterial, ...] | None:
    """Derive the complete material tuple directly from #30 mutation truth."""
    if not admitted_candidate_materialization_is_valid(materialization):
        return None
    values: list[CurrentReviewMaterial] = []
    for mutation in materialization.mutation_inventory.mutations:
        material_id = MaterialIdentity(contract_json_value_digest((
            "autodev.current-semantic-review-material/v1", materialization.repository_id.value,
            materialization.task_id.value, materialization.candidate_id.value,
            materialization.materialization_id.raw_sha256.value, mutation.path.value,
            mutation.kind.value, None if mutation.base_object_id is None else mutation.base_object_id.value,
            None if mutation.base_mode is None else mutation.base_mode.value,
            None if mutation.candidate_object_id is None else mutation.candidate_object_id.value,
            None if mutation.candidate_mode is None else mutation.candidate_mode.value,
        )).value)
        values.append(CurrentReviewMaterial(
            material_id, materialization.repository_id, materialization.task_id,
            materialization.candidate_id, materialization.materialization_id,
            mutation.path, mutation.kind, mutation.base_object_id,
            mutation.candidate_object_id, mutation.base_mode, mutation.candidate_mode,
        ))
    return tuple(values)


def _static_binding_cell_count(obligation_count: int, material_count: int) -> int:
    return obligation_count * (1 + material_count)


def _final_binding_cell_count(material_count: int, resolved: tuple[_ObligationWork, ...], dependency_count: int) -> int:
    return dependency_count + sum(
        1 + material_count + len(item.trusted_evaluator_resolution.review_slots)
        + len(item.trusted_evaluator_resolution.required_trusted_context_ids)
        + int(item.trusted_evaluator_resolution.target_context_requirement is SemanticReviewContextRequirement.REQUIRED)
        + int(item.trusted_evaluator_resolution.pr_context_requirement is SemanticReviewContextRequirement.REQUIRED)
        for item in resolved
        if item.status in (
            CurrentSemanticReviewResolutionStatus.RESOLVED,
            SemanticEvaluatorObligationResolutionStatus.RESOLVED,
        )
        and item.trusted_evaluator_resolution is not None
    )


def _basic_map(context: TrustedIssueContractApplicabilityContext) -> dict[object, TrustedEvaluatorConfigResolution] | None:
    values = context.evaluator_resolutions
    if type(values) is not tuple or any(type(x) is not TrustedEvaluatorConfigResolution for x in values):
        return None
    result: dict[object, TrustedEvaluatorConfigResolution] = {}
    for value in values:
        key = value.binding.config_identity.config_id
        if key in result:
            return None
        result[key] = value
    return result


def derive_semantic_obligations(contract: AdmittedIssueContract, context: TrustedIssueContractApplicabilityContext) -> tuple[SemanticEvaluatorObligation, ...] | None:
    """Build semantic obligations solely from the admitted structural plan."""
    basic = _basic_map(context)
    if basic is None:
        return None
    values: list[SemanticEvaluatorObligation] = []
    for requirement in contract.acceptance_plan.requirements:
        semantic = tuple(x for x in requirement.evaluators if x.mechanism is EvaluatorMechanism.SEMANTIC)
        if not semantic:
            continue
        requirement_id = semantic_requirement_id(contract, requirement.requirement_id)
        subject = SemanticRequirement(requirement_id, contract_json_value_digest(requirement.statement))
        for evaluator in semantic:
            parameters = recover_semantic_evaluator_parameters(contract, requirement.requirement_id, evaluator)
            if parameters is None:
                return None
            resolution = basic.get(evaluator.evaluator_ref)
            if resolution is None:
                return None
            values.append(SemanticEvaluatorObligation(
                semantic_evaluator_obligation_id(contract, requirement.requirement_id, evaluator),
                subject, evaluator, parameters, resolution,
            ))
    if len({x.obligation_id for x in values}) != len(values):
        return None
    return tuple(sorted(values, key=lambda x: x.obligation_id.raw_sha256.value))


def _inputs_coherent(inputs: CanonicalCurrentSemanticReviewInputs) -> bool:
    if (type(inputs.canonical_state_occurrence_binding) is not CanonicalStateOccurrenceBinding or type(inputs.contract) is not AdmittedIssueContract
            or type(inputs.authorization) is not AdmittedAuthorization or type(inputs.task) is not TaskRecord
            or type(inputs.resolved_target) is not ResolvedTargetRegistration):
        return False
    c, a, t, target = inputs.contract, inputs.authorization, inputs.task, inputs.resolved_target
    return (t.task_id == c.task_id == a.task_id and t.contract_id == c.contract_id == a.contract_id
            and t.contract_raw_sha256 == c.contract_raw_sha256 == a.contract_raw_sha256
            and t.authorization_id == a.authorization_id and t.target_registration_id == c.target_registration_id == a.target_registration_id == target.target_registration_id
            and t.last_evaluated_policy_epoch_identity == c.admission_policy_epoch_identity == a.policy_epoch_identity == target.policy_epoch_identity)


def _failure(
    occurrence: CanonicalStateOccurrenceBinding,
    status: CurrentSemanticReviewResolutionStatus,
    reason: CurrentSemanticReviewResolutionReason,
    applicability_code: IssueContractApplicabilityCode | None = None,
) -> CurrentSemanticReviewResolutionResult:
    return CurrentSemanticReviewResolutionResult(status, reason, occurrence, (), (), applicability_code)


def _trusted_assignment(
    inputs: CanonicalCurrentSemanticReviewInputs, materialization: AdmittedCandidateMaterialization,
    obligation: SemanticEvaluatorObligation, resolution: TrustedSemanticEvaluatorResolution,
    material_ids: tuple[MaterialIdentity, ...],
) -> SemanticReviewAssignment:
    assignment_id = AssignmentIdentity(contract_json_value_digest((
        "autodev.contract-semantic-review-assignment/v1", obligation.obligation_id.raw_sha256.value,
        resolution.resolution_id.raw_sha256.value, materialization.repository_id.value,
        materialization.task_id.value, materialization.candidate_id.value,
        materialization.materialization_id.raw_sha256.value, inputs.contract.contract_id.value,
        inputs.contract.contract_raw_sha256.value, inputs.contract.target_registration_id.raw_sha256.value,
        inputs.task.last_evaluated_policy_epoch_identity.manifest_id.raw_sha256.value,
        obligation.semantic_requirement.requirement_id.value, tuple(x.value for x in material_ids),
        tuple(x.value for x in resolution.required_trusted_context_ids),
        resolution.composition_rule.composition_rule_id.value, resolution.partition_rule.value,
    )).value)
    value = object.__new__(SemanticReviewAssignment)
    fields = {
        "assignment_id": assignment_id, "repository_id": materialization.repository_id,
        "task_id": materialization.task_id, "contract_id": inputs.contract.contract_id,
        "contract_raw_sha256": inputs.contract.contract_raw_sha256,
        "target_registration_id": inputs.contract.target_registration_id,
        "policy_epoch_identity": inputs.task.last_evaluated_policy_epoch_identity,
        "candidate_id": materialization.candidate_id, "requirements": (obligation.semantic_requirement,),
        "material_assignments": (RequirementMaterialAssignment(obligation.semantic_requirement.requirement_id, material_ids, resolution.required_trusted_context_ids, ()),),
        "required_context_ids": resolution.required_trusted_context_ids,
        "composition_rule": resolution.composition_rule, "partition_rule": resolution.partition_rule,
        "obligation_id": obligation.obligation_id,
        "candidate_materialization_id": materialization.materialization_id,
        "semantic_evaluator_resolution_id": resolution.resolution_id,
    }
    for name, item in fields.items(): object.__setattr__(value, name, item)
    return value


def _trusted_effective_subject(
    inputs: CanonicalCurrentSemanticReviewInputs, materialization: AdmittedCandidateMaterialization,
    obligation: SemanticEvaluatorObligation, assignment: SemanticReviewAssignment,
    target_context_id: object | None, pr_id: object | None, material_ids: tuple[MaterialIdentity, ...],
    contexts: tuple[object, ...],
) -> SemanticReviewEffectiveSubject:
    subject_id = SemanticReviewEffectiveSubjectId(contract_json_value_digest((
        "autodev.current-semantic-review-effective-subject/v1", assignment.assignment_id.value,
        obligation.obligation_id.raw_sha256.value, materialization.repository_id.value,
        materialization.task_id.value, materialization.candidate_id.value,
        materialization.materialization_id.raw_sha256.value, inputs.contract.contract_id.value,
        inputs.contract.contract_raw_sha256.value, inputs.authorization.authorization_id.raw_sha256.value,
        inputs.task.admission_event_id.value, inputs.contract.target_registration_id.raw_sha256.value,
        inputs.task.last_evaluated_policy_epoch_identity.manifest_id.raw_sha256.value,
        inputs.contract.base_sha.value, None if target_context_id is None else target_context_id.value,
        None if pr_id is None else pr_id.value, obligation.semantic_requirement.requirement_id.value,
        tuple(x.value for x in material_ids), tuple(x.value for x in contexts),
        assignment.composition_rule.composition_rule_id.value,
    )).value)
    value = object.__new__(SemanticReviewEffectiveSubject)
    fields = {
        "subject_id": subject_id, "repository_id": materialization.repository_id, "task_id": materialization.task_id,
        "candidate_id": materialization.candidate_id, "contract_id": inputs.contract.contract_id,
        "contract_raw_sha256": inputs.contract.contract_raw_sha256, "authorization_id": inputs.authorization.authorization_id,
        "task_admission_event_id": inputs.task.admission_event_id, "target_registration_id": inputs.contract.target_registration_id,
        "policy_epoch_identity": inputs.task.last_evaluated_policy_epoch_identity, "base": inputs.contract.base_sha,
        "target_context_id": target_context_id, "pr_id": pr_id,
        "requirement_ids": (obligation.semantic_requirement.requirement_id,), "required_material_ids": material_ids,
        "required_context_ids": contexts, "composition_rule_id": assignment.composition_rule.composition_rule_id,
        "assignment_id": assignment.assignment_id, "obligation_id": obligation.obligation_id,
        "candidate_materialization_id": materialization.materialization_id,
    }
    for name, item in fields.items(): object.__setattr__(value, name, item)
    return value


def build_current_semantic_evidence_subject(
    resolved_obligation: ResolvedSemanticEvaluatorObligation, slot: ReviewSlot, invocation_id: ReviewInvocationId,
) -> object:
    """Build a semantic subject exclusively from a freshly resolved subject/slot."""
    from .evidence import EvidenceSubject, SemanticReviewEvidenceBinding
    if (type(resolved_obligation) is not ResolvedSemanticEvaluatorObligation or type(slot) is not ReviewSlot
            or type(invocation_id) is not ReviewInvocationId
            or type(resolved_obligation.effective_subject) is not SemanticReviewEffectiveSubject
            or type(resolved_obligation.obligation_id) is not SemanticEvaluatorObligationId
            or type(resolved_obligation.effective_subject.candidate_materialization_id) is not CandidateMaterializationId):
        raise TypeError("exact resolved obligation, current slot, and invocation required")
    current_slots = tuple(
        current for current in resolved_obligation.trusted_evaluator_resolution.review_slots
        if current.slot_id == slot.slot_id
    )
    if len(current_slots) != 1 or current_slots[0] != slot:
        raise ValueError("review slot is not from this current evaluator resolution")
    effective_subject = resolved_obligation.effective_subject
    return EvidenceSubject(
        effective_subject.repository_id, effective_subject.task_id, effective_subject.contract_id,
        effective_subject.contract_raw_sha256, effective_subject.task_admission_event_id,
        effective_subject.authorization_id, effective_subject.target_registration_id,
        effective_subject.policy_epoch_identity, effective_subject.candidate_id, effective_subject.base,
        effective_subject.target_context_id, effective_subject.pr_id, effective_subject.requirement_ids,
        effective_subject.required_material_ids, effective_subject.required_context_ids, invocation_id,
        slot.slot_id, slot.profile.profile_id, slot.profile.config_id, slot.profile.verdict_schema_id,
        SemanticReviewEvidenceBinding(effective_subject.obligation_id, effective_subject.candidate_materialization_id),
    )


def reconstruct_current_semantic_evidence_subject(
    evidence_id: object, *, backend: object, applicability_context: TrustedIssueContractApplicabilityContext,
    byte_reader: TrustedSemanticConfigByteReader | None,
    semantic_context_source: TrustedSemanticContextObservationSource | None,
) -> SemanticEvidenceSubjectReconstructionResult:
    """Use historical evidence only as selectors; all subject facts are fresh."""
    from .backend import InMemoryCanonicalStateBackend
    from .evidence import EvidenceClass, EvidenceSubject
    from .operation import EvidenceId
    if type(evidence_id) is not EvidenceId or type(backend) is not InMemoryCanonicalStateBackend:
        raise TypeError("exact EvidenceId and canonical backend required")
    historical = backend.read_evidence(evidence_id)
    if historical is None:
        return SemanticEvidenceSubjectReconstructionResult(SemanticEvidenceSubjectReconstructionStatus.NOT_FOUND)
    if historical.evidence_class is not EvidenceClass.SEMANTIC_REVIEW:
        return SemanticEvidenceSubjectReconstructionResult(SemanticEvidenceSubjectReconstructionStatus.NOT_SEMANTIC)
    binding = historical.subject.semantic_review_binding
    if binding is None:
        return SemanticEvidenceSubjectReconstructionResult(SemanticEvidenceSubjectReconstructionStatus.DENIED)
    inputs = backend.read_current_semantic_review_inputs(historical.subject.task_id)
    if inputs is None:
        return SemanticEvidenceSubjectReconstructionResult(SemanticEvidenceSubjectReconstructionStatus.INDETERMINATE)
    current = resolve_current_semantic_review(
        inputs, applicability_context=applicability_context, byte_reader=byte_reader,
        semantic_context_source=semantic_context_source,
    )
    if current.status is CurrentSemanticReviewResolutionStatus.INDETERMINATE:
        return SemanticEvidenceSubjectReconstructionResult(SemanticEvidenceSubjectReconstructionStatus.INDETERMINATE)
    if current.status is not CurrentSemanticReviewResolutionStatus.RESOLVED:
        return SemanticEvidenceSubjectReconstructionResult(SemanticEvidenceSubjectReconstructionStatus.DENIED)
    selected = tuple(
        x for x in current.obligation_outcomes
        if x.obligation.obligation_id == binding.obligation_id
    )
    if len(selected) != 1:
        return SemanticEvidenceSubjectReconstructionResult(SemanticEvidenceSubjectReconstructionStatus.DENIED)
    current_obligation = selected[0]
    if current_obligation.status is SemanticEvaluatorObligationResolutionStatus.INDETERMINATE:
        return SemanticEvidenceSubjectReconstructionResult(SemanticEvidenceSubjectReconstructionStatus.INDETERMINATE)
    if (current_obligation.status is not SemanticEvaluatorObligationResolutionStatus.RESOLVED
            or current_obligation.effective_subject is None
            or current_obligation.trusted_evaluator_resolution is None):
        return SemanticEvidenceSubjectReconstructionResult(SemanticEvidenceSubjectReconstructionStatus.DENIED)
    slot_id = historical.payload.slot_id
    slots = tuple(x for x in current_obligation.trusted_evaluator_resolution.review_slots if x.slot_id == slot_id)
    if len(slots) != 1:
        return SemanticEvidenceSubjectReconstructionResult(SemanticEvidenceSubjectReconstructionStatus.DENIED)
    return SemanticEvidenceSubjectReconstructionResult(
        SemanticEvidenceSubjectReconstructionStatus.RECONSTRUCTED,
        build_current_semantic_evidence_subject(current_obligation.resolved_obligation, slots[0], historical.payload.invocation_id),
    )


def resolve_current_semantic_review(
    inputs: CanonicalCurrentSemanticReviewInputs, *, applicability_context: TrustedIssueContractApplicabilityContext,
    byte_reader: TrustedSemanticConfigByteReader | None,
    semantic_context_source: TrustedSemanticContextObservationSource | None,
) -> CurrentSemanticReviewResolutionResult:
    """Resolve current structure without admitting evidence or changing canonical state."""
    if type(inputs) is not CanonicalCurrentSemanticReviewInputs:
        raise TypeError("exact canonical current-semantic inputs required")
    if not _inputs_coherent(inputs):
        return _failure(inputs.canonical_state_occurrence_binding, CurrentSemanticReviewResolutionStatus.DENIED, CurrentSemanticReviewResolutionReason.CANONICAL_INPUT_MISMATCH)
    if type(applicability_context) is not TrustedIssueContractApplicabilityContext:
        raise TypeError("exact current applicability context required")
    applicability = evaluate_issue_contract_applicability(inputs.contract, applicability_context)
    if applicability.decision.value == "ESCALATE":
        return _failure(
            inputs.canonical_state_occurrence_binding,
            CurrentSemanticReviewResolutionStatus.INDETERMINATE,
            CurrentSemanticReviewResolutionReason.CONTRACT_APPLICABILITY_INDETERMINATE,
            applicability.outcome,
        )
    if applicability.decision.value != "ALLOW":
        return _failure(
            inputs.canonical_state_occurrence_binding,
            CurrentSemanticReviewResolutionStatus.NOT_APPLICABLE,
            CurrentSemanticReviewResolutionReason.CONTRACT_NOT_APPLICABLE,
            applicability.outcome,
        )
    obligations = derive_semantic_obligations(inputs.contract, applicability_context)
    if obligations is None:
        return _failure(inputs.canonical_state_occurrence_binding, CurrentSemanticReviewResolutionStatus.DENIED, CurrentSemanticReviewResolutionReason.PARAMETER_RECOVERY_FAILED)
    if len(obligations) > MAX_SEMANTIC_REVIEW_OBLIGATIONS:
        return _failure(inputs.canonical_state_occurrence_binding, CurrentSemanticReviewResolutionStatus.DENIED, CurrentSemanticReviewResolutionReason.RESOLUTION_LIMIT_EXCEEDED)
    if not obligations:
        return _failure(inputs.canonical_state_occurrence_binding, CurrentSemanticReviewResolutionStatus.RESOLVED, CurrentSemanticReviewResolutionReason.NO_SEMANTIC_EVALUATORS)
    candidate, materialization = inputs.candidate, inputs.materialization
    if type(candidate) is not CandidateRecord or type(materialization) is not AdmittedCandidateMaterialization:
        return _failure(inputs.canonical_state_occurrence_binding, CurrentSemanticReviewResolutionStatus.INDETERMINATE, CurrentSemanticReviewResolutionReason.CANONICAL_INPUT_INDETERMINATE)
    if (inputs.task.current_candidate_id != candidate.candidate_id or candidate.materialization_id != materialization.materialization_id
            or candidate.task_id != inputs.task.task_id or candidate.contract_id != inputs.contract.contract_id
            or candidate.contract_raw_sha256 != inputs.contract.contract_raw_sha256 or candidate.authorization_id != inputs.authorization.authorization_id
            or candidate.base != inputs.contract.base_sha
            or candidate.target_registration_id != inputs.resolved_target.target_registration_id
            or candidate.policy_epoch_identity != inputs.resolved_target.policy_epoch_identity
            or materialization.candidate_id != candidate.candidate_id or materialization.repository_id != inputs.resolved_target.registration.repository_id
            or materialization.task_id != inputs.task.task_id or materialization.contract_id != inputs.contract.contract_id
            or materialization.contract_raw_sha256 != inputs.contract.contract_raw_sha256 or materialization.authorization_id != inputs.authorization.authorization_id
            or materialization.target_registration_id != inputs.resolved_target.target_registration_id
            or materialization.policy_epoch_identity != inputs.resolved_target.policy_epoch_identity or materialization.base_commit != inputs.contract.base_sha):
        return _failure(inputs.canonical_state_occurrence_binding, CurrentSemanticReviewResolutionStatus.DENIED, CurrentSemanticReviewResolutionReason.CANDIDATE_MATERIALIZATION_MISMATCH)
    materials = derive_current_review_materials(materialization)
    if materials is None:
        return _failure(inputs.canonical_state_occurrence_binding, CurrentSemanticReviewResolutionStatus.DENIED, CurrentSemanticReviewResolutionReason.CANDIDATE_MATERIALIZATION_MISMATCH)
    if _static_binding_cell_count(len(obligations), len(materials)) > MAX_SEMANTIC_RESOLUTION_BINDING_CELLS:
        return _failure(inputs.canonical_state_occurrence_binding, CurrentSemanticReviewResolutionStatus.DENIED, CurrentSemanticReviewResolutionReason.RESOLUTION_LIMIT_EXCEEDED)
    if type(byte_reader) is not TrustedSemanticConfigByteReader:
        return _failure(inputs.canonical_state_occurrence_binding, CurrentSemanticReviewResolutionStatus.INDETERMINATE, CurrentSemanticReviewResolutionReason.SEMANTIC_CONFIG_BYTE_SOURCE_UNAVAILABLE)
    identities = tuple(sorted({x.evaluator.config_identity for x in obligations}, key=lambda x: (x.config_id.value, x.resource_id.value, x.resource_sha256.value)))
    if len(identities) > MAX_UNIQUE_SEMANTIC_EVALUATOR_CONFIGS_PER_RESOLUTION:
        return _failure(inputs.canonical_state_occurrence_binding, CurrentSemanticReviewResolutionStatus.DENIED, CurrentSemanticReviewResolutionReason.SEMANTIC_CONFIG_AGGREGATE_LIMIT_EXCEEDED)
    bytes_by_identity: dict[TrustedConfigIdentity, bytes | None] = {}
    total = 0
    for identity in identities:
        raw = byte_reader.read_exact(RootManagedResourceRef(identity.resource_id, RootManagedResourceKind.TRUSTED_CONFIG, identity.resource_sha256))
        if raw is not None and type(raw) is not bytes:
            return _failure(inputs.canonical_state_occurrence_binding, CurrentSemanticReviewResolutionStatus.DENIED, CurrentSemanticReviewResolutionReason.SEMANTIC_CONFIG_BYTE_SOURCE_INVALID)
        total += 0 if raw is None else len(raw)
        if total > MAX_TOTAL_SEMANTIC_EVALUATOR_CONFIG_BYTES_PER_RESOLUTION:
            return _failure(inputs.canonical_state_occurrence_binding, CurrentSemanticReviewResolutionStatus.DENIED, CurrentSemanticReviewResolutionReason.SEMANTIC_CONFIG_AGGREGATE_LIMIT_EXCEEDED)
        bytes_by_identity[identity] = raw
    results = {identity: resolve_semantic_evaluator_config(next(x.basic_resolution for x in obligations if x.evaluator.config_identity == identity), raw) for identity, raw in bytes_by_identity.items()}
    outcomes: list[_ObligationWork] = []
    for obligation in obligations:
        result = results[obligation.evaluator.config_identity]
        if result.status is SemanticEvaluatorConfigResolutionStatus.INDETERMINATE:
            outcomes.append(_ObligationWork(
                obligation, CurrentSemanticReviewResolutionStatus.INDETERMINATE,
                SemanticEvaluatorObligationResolutionReason.EVALUATOR_RESOLUTION_UNAVAILABLE,
                result.status, result.reason,
                semantic_config_resource_failure_code=result.resource_failure_code,
                semantic_config_parse_failure_code=result.parse_failure_code,
            )); continue
        if result.status is SemanticEvaluatorConfigResolutionStatus.DENIED:
            reason = (SemanticEvaluatorObligationResolutionReason.EVALUATOR_RESOLUTION_LIMIT_EXCEEDED if result.reason is SemanticEvaluatorConfigResolutionReason.RESOLUTION_LIMIT_EXCEEDED else SemanticEvaluatorObligationResolutionReason.EVALUATOR_BINDING_MISMATCH if result.reason in (SemanticEvaluatorConfigResolutionReason.BASIC_RESOLUTION_NOT_SEMANTIC, SemanticEvaluatorConfigResolutionReason.BASIC_RESOLUTION_NOT_USABLE, SemanticEvaluatorConfigResolutionReason.BASIC_RESOLUTION_MISMATCH) else SemanticEvaluatorObligationResolutionReason.EVALUATOR_RESOLUTION_NONCANONICAL if result.reason in (SemanticEvaluatorConfigResolutionReason.BASIC_RESOLUTION_NONCANONICAL, SemanticEvaluatorConfigResolutionReason.NONCANONICAL_CONFIG) else SemanticEvaluatorObligationResolutionReason.EVALUATOR_RESOLUTION_INVALID)
            outcomes.append(_ObligationWork(
                obligation, CurrentSemanticReviewResolutionStatus.DENIED, reason,
                result.status, result.reason,
                semantic_config_resource_failure_code=result.resource_failure_code,
                semantic_config_parse_failure_code=result.parse_failure_code,
            )); continue
        resolution = result.resolution
        assert resolution is not None
        if (resolution.policy_epoch_identity != inputs.task.last_evaluated_policy_epoch_identity or resolution.config_identity != obligation.evaluator.config_identity or resolution.mechanism is not EvaluatorMechanism.SEMANTIC or not resolution.parameters_valid or not resolution.applicable or resolution.operational_prerequisites != obligation.basic_resolution.operational_prerequisites or not set(resolution.operational_prerequisites).issubset(inputs.contract.requested_operations)):
            outcomes.append(_ObligationWork(
                obligation, CurrentSemanticReviewResolutionStatus.DENIED,
                SemanticEvaluatorObligationResolutionReason.EVALUATOR_BINDING_MISMATCH,
                result.status, result.reason, semantic_config_resource_failure_code=result.resource_failure_code,
                semantic_config_parse_failure_code=result.parse_failure_code,
            )); continue
        outcomes.append(_ObligationWork(
            obligation, CurrentSemanticReviewResolutionStatus.RESOLVED,
            SemanticEvaluatorObligationResolutionReason.RESOLVED, result.status,
            result.reason, resolution,
            semantic_config_resource_failure_code=result.resource_failure_code,
            semantic_config_parse_failure_code=result.parse_failure_code,
        ))
    # Context projection deliberately follows A7; no B1 demand occurs before this point.
    need_target = any(x.status is CurrentSemanticReviewResolutionStatus.RESOLVED and x.trusted_evaluator_resolution.target_context_requirement is SemanticReviewContextRequirement.REQUIRED for x in outcomes)
    need_pr = any(x.status is CurrentSemanticReviewResolutionStatus.RESOLVED and x.trusted_evaluator_resolution.pr_context_requirement is SemanticReviewContextRequirement.REQUIRED for x in outcomes)
    target_result = resolve_current_semantic_target_context(inputs.resolved_target, semantic_context_source) if need_target else None
    pr_result = resolve_current_semantic_pull_request_context(inputs.resolved_target, inputs.contract, materialization, semantic_context_source) if need_pr else None
    projected: list[_ObligationWork] = []
    for outcome in outcomes:
        resolution = outcome.trusted_evaluator_resolution
        if outcome.status is not CurrentSemanticReviewResolutionStatus.RESOLVED or resolution is None:
            projected.append(outcome); continue
        required_target = resolution.target_context_requirement is SemanticReviewContextRequirement.REQUIRED
        required_pr = resolution.pr_context_requirement is SemanticReviewContextRequirement.REQUIRED
        required_contexts = (
            ((True, target_result),) if required_target else ()
        ) + (
            ((False, pr_result),) if required_pr else ()
        )
        for is_target, context in required_contexts:
            status, reason = _context_reason(is_target, context)
            if status is not CurrentSemanticReviewResolutionStatus.RESOLVED:
                projected.append(_ObligationWork(
                    outcome.obligation, status, reason, outcome.semantic_config_status,
                    outcome.semantic_config_reason, resolution,
                    semantic_config_resource_failure_code=outcome.semantic_config_resource_failure_code,
                    semantic_config_parse_failure_code=outcome.semantic_config_parse_failure_code,
                )); break
        else:
            deps = tuple((target_result.dependencies if required_target else ()) + (pr_result.dependencies if required_pr else ()))
            canonical = _canonical_dependencies(deps)
            if canonical is None:
                return _failure(inputs.canonical_state_occurrence_binding, CurrentSemanticReviewResolutionStatus.DENIED, CurrentSemanticReviewResolutionReason.CANONICAL_INPUT_MISMATCH)
            target_id = target_result.target_context_id if required_target else None
            pr_identity = pr_result.pull_request_identity if required_pr else None
            projected.append(_ObligationWork(
                outcome.obligation, CurrentSemanticReviewResolutionStatus.RESOLVED,
                SemanticEvaluatorObligationResolutionReason.RESOLVED,
                outcome.semantic_config_status, outcome.semantic_config_reason, resolution,
                target_id, pr_identity, canonical,
                semantic_config_resource_failure_code=outcome.semantic_config_resource_failure_code,
                semantic_config_parse_failure_code=outcome.semantic_config_parse_failure_code,
            ))
    global_dependencies = _canonical_dependencies(tuple(x for result in projected if result.status is CurrentSemanticReviewResolutionStatus.RESOLVED for x in result.authoritative_dependencies))
    if global_dependencies is None:
        return _failure(inputs.canonical_state_occurrence_binding, CurrentSemanticReviewResolutionStatus.DENIED, CurrentSemanticReviewResolutionReason.CANONICAL_INPUT_MISMATCH)
    if _final_binding_cell_count(len(materials), tuple(projected), len(global_dependencies)) > MAX_SEMANTIC_RESOLUTION_BINDING_CELLS:
        return _failure(inputs.canonical_state_occurrence_binding, CurrentSemanticReviewResolutionStatus.DENIED, CurrentSemanticReviewResolutionReason.RESOLUTION_LIMIT_EXCEEDED)
    material_ids = tuple(item.material_id for item in materials)
    completed: list[SemanticEvaluatorObligationResolution] = []
    for outcome in projected:
        resolution = outcome.trusted_evaluator_resolution
        if outcome.status is not CurrentSemanticReviewResolutionStatus.RESOLVED or resolution is None:
            completed.append(SemanticEvaluatorObligationResolution(
                outcome.obligation, SemanticEvaluatorObligationResolutionStatus(outcome.status.value), outcome.reason,
                outcome.semantic_config_status, outcome.semantic_config_reason,
                outcome.semantic_config_resource_failure_code,
                outcome.semantic_config_parse_failure_code,
            ))
            continue
        assignment = _trusted_assignment(inputs, materialization, outcome.obligation, resolution, material_ids)
        effective = _trusted_effective_subject(
            inputs, materialization, outcome.obligation, assignment,
            outcome.target_context_id, outcome.pr_id, material_ids,
            resolution.required_trusted_context_ids,
        )
        resolved_obligation = ResolvedSemanticEvaluatorObligation._from_validated(
            _RESOLVED_OBLIGATION_KEY,
            semantic_requirement=outcome.obligation.semantic_requirement,
            obligation_id=outcome.obligation.obligation_id,
            evaluator_parameters=outcome.obligation.parameters,
            trusted_evaluator_resolution=resolution,
            current_review_materials=materials,
            authoritative_dependencies=outcome.authoritative_dependencies,
            assignment=assignment,
            effective_subject=effective,
        )
        completed.append(SemanticEvaluatorObligationResolution(
            outcome.obligation, SemanticEvaluatorObligationResolutionStatus(outcome.status.value), outcome.reason,
            outcome.semantic_config_status, outcome.semantic_config_reason,
            outcome.semantic_config_resource_failure_code,
            outcome.semantic_config_parse_failure_code, resolved_obligation,
        ))
    return CurrentSemanticReviewResolutionResult(CurrentSemanticReviewResolutionStatus.RESOLVED, CurrentSemanticReviewResolutionReason.RESOLVED, inputs.canonical_state_occurrence_binding, tuple(sorted(completed, key=lambda x: x.obligation.obligation_id.raw_sha256.value)), global_dependencies)
