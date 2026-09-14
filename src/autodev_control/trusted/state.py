"""Pure immutable task, candidate, completion, cancellation, and repair logic.

Every value and proposal in this module is non-bearer candidate state.  G4 does
not persist it and does not perform protected effects.
"""

from dataclasses import dataclass, replace
from enum import Enum

from .errors import G4Failure, G4FailureCode
from .identity import CandidateMaterializationId, GitSha, OperationStartBindingId, RawSha256
from .manifest import PolicyEpochIdentity
from .operation import (
    AdmissionEventId,
    AuthoritativeStateBindingId,
    AwaitingInputRequirementId,
    BlockingConditionId,
    CancellationRequestId,
    CandidateId,
    CompletionRuleSetId,
    DecisionEventId,
    EvidenceId,
    IntegrationBound,
    OperationEffectClass,
    OperationId,
    OperationMembershipBindingId,
    OperationPurpose,
    OperationRecord,
    OperationRevision,
    OperationState,
    reserve_operation,
    transition_operation,
)
from .scope import AuthorizationId, ContractId, TargetRegistrationId, TaskId


TaskRevision = int


def _revision(value: object, name: str) -> int:
    if type(value) is not int or value < 1:
        raise ValueError(f"{name} must be an exact positive int")
    return value


def _unique_exact(values: object, item_type: type, name: str) -> tuple:
    if type(values) is not tuple:
        raise TypeError(f"{name} must be exactly tuple")
    seen: set[object] = set()
    for value in values:
        if type(value) is not item_type:
            raise TypeError(f"{name} item has wrong exact type")
        if value in seen:
            raise ValueError(f"duplicate identity in {name}")
        seen.add(value)
    return values


class TaskState(Enum):
    ADMITTED = "admitted"
    EVALUATING = "evaluating"
    AWAITING_INPUT = "awaiting_input"
    INTEGRATION_READY = "integration_ready"
    BLOCKED = "blocked"
    COMPLETED = "completed"
    CANCELLED = "cancelled"


class CancellationStatus(Enum):
    NONE = "NONE"
    REQUESTED = "REQUESTED"
    AUTHORITATIVE = "AUTHORITATIVE"


class ConditionStatus(Enum):
    SATISFIED = "SATISFIED"
    UNSATISFIED = "UNSATISFIED"
    INDETERMINATE = "INDETERMINATE"


@dataclass(frozen=True, slots=True)
class CandidateRecord:
    candidate_id: CandidateId
    task_id: TaskId
    base: GitSha
    contract_id: ContractId
    contract_raw_sha256: RawSha256
    authorization_id: AuthorizationId
    admission_event_id: AdmissionEventId
    target_registration_id: TargetRegistrationId
    policy_epoch_identity: PolicyEpochIdentity
    materialization_id: CandidateMaterializationId
    parent_candidate_ids: tuple[CandidateId, ...]
    creation_operation_id: OperationId | None = None

    def __post_init__(self) -> None:
        exact = (
            (self.candidate_id, CandidateId), (self.task_id, TaskId), (self.base, GitSha),
            (self.contract_id, ContractId), (self.contract_raw_sha256, RawSha256),
            (self.authorization_id, AuthorizationId), (self.admission_event_id, AdmissionEventId),
            (self.target_registration_id, TargetRegistrationId),
            (self.policy_epoch_identity, PolicyEpochIdentity),
            (self.materialization_id, CandidateMaterializationId),
        )
        if any(type(value) is not expected for value, expected in exact):
            raise TypeError("candidate identity field has wrong exact type")
        _unique_exact(self.parent_candidate_ids, CandidateId, "parent_candidate_ids")
        if self.candidate_id in self.parent_candidate_ids:
            raise ValueError("candidate cannot be its own immediate parent")
        if self.creation_operation_id is not None and type(self.creation_operation_id) is not OperationId:
            raise TypeError("creation_operation_id has wrong exact type")


@dataclass(frozen=True, slots=True)
class EvidenceBindingRef:
    evidence_id: EvidenceId
    candidate_id: CandidateId | None

    def __post_init__(self) -> None:
        if type(self.evidence_id) is not EvidenceId:
            raise TypeError("evidence_id must be exactly EvidenceId")
        if self.candidate_id is not None and type(self.candidate_id) is not CandidateId:
            raise TypeError("candidate_id must be exact CandidateId or None")


@dataclass(frozen=True, slots=True)
class RepairBudget:
    maximum_attempts: int
    reserved_operation_ids: tuple[OperationId, ...] = ()
    consumed_operation_ids: tuple[OperationId, ...] = ()
    released_operation_ids: tuple[OperationId, ...] = ()

    def __post_init__(self) -> None:
        if type(self.maximum_attempts) is not int or self.maximum_attempts < 0:
            raise ValueError("maximum_attempts must be an exact non-negative int")
        groups = (
            _unique_exact(self.reserved_operation_ids, OperationId, "reserved_operation_ids"),
            _unique_exact(self.consumed_operation_ids, OperationId, "consumed_operation_ids"),
            _unique_exact(self.released_operation_ids, OperationId, "released_operation_ids"),
        )
        if len(set().union(*map(set, groups))) != sum(map(len, groups)):
            raise ValueError("repair identity collections must be pairwise disjoint")
        if len(self.reserved_operation_ids) + len(self.consumed_operation_ids) > self.maximum_attempts:
            raise ValueError("repair budget exceeds maximum")


@dataclass(frozen=True, slots=True)
class TaskRecord:
    task_id: TaskId
    revision: TaskRevision
    state: TaskState
    contract_id: ContractId
    contract_raw_sha256: RawSha256
    authorization_id: AuthorizationId
    admission_event_id: AdmissionEventId
    target_registration_id: TargetRegistrationId
    last_evaluated_policy_epoch_identity: PolicyEpochIdentity
    current_candidate_id: CandidateId | None
    next_integration_operation_id: OperationId | None
    supporting_evidence_refs: tuple[EvidenceBindingRef, ...]
    repair_budget: RepairBudget
    cancellation_status: CancellationStatus = CancellationStatus.NONE
    cancellation_request_id: CancellationRequestId | None = None
    reason_code: G4FailureCode | None = None

    def __post_init__(self) -> None:
        exact = (
            (self.task_id, TaskId), (self.state, TaskState), (self.contract_id, ContractId),
            (self.contract_raw_sha256, RawSha256), (self.authorization_id, AuthorizationId),
            (self.admission_event_id, AdmissionEventId),
            (self.target_registration_id, TargetRegistrationId),
            (self.last_evaluated_policy_epoch_identity, PolicyEpochIdentity),
            (self.repair_budget, RepairBudget), (self.cancellation_status, CancellationStatus),
        )
        if any(type(value) is not expected for value, expected in exact):
            raise TypeError("task field has wrong exact type")
        _revision(self.revision, "task revision")
        if self.current_candidate_id is not None and type(self.current_candidate_id) is not CandidateId:
            raise TypeError("current_candidate_id has wrong exact type")
        if self.next_integration_operation_id is not None and type(self.next_integration_operation_id) is not OperationId:
            raise TypeError("next integration operation has wrong exact type")
        _evidence_tuple(self.supporting_evidence_refs)
        if self.reason_code is not None and type(self.reason_code) is not G4FailureCode:
            raise TypeError("reason_code has wrong exact type")
        if self.cancellation_status is CancellationStatus.NONE:
            if self.cancellation_request_id is not None:
                raise ValueError("NONE cancellation cannot carry request identity")
        elif type(self.cancellation_request_id) is not CancellationRequestId:
            raise ValueError("pending/authoritative cancellation requires request identity")
        if self.state is TaskState.ADMITTED and (
            self.current_candidate_id is not None or self.next_integration_operation_id is not None
        ):
            raise ValueError("ADMITTED task cannot bind a candidate or next integration operation")
        if self.state is TaskState.EVALUATING and (
            self.current_candidate_id is None or self.next_integration_operation_id is not None
        ):
            raise ValueError("EVALUATING requires candidate and no next operation")
        if self.state is TaskState.INTEGRATION_READY:
            if self.next_integration_operation_id is None:
                raise ValueError("INTEGRATION_READY requires next operation")
        elif self.next_integration_operation_id is not None:
            raise ValueError("only INTEGRATION_READY can carry next operation")
        if self.state is TaskState.COMPLETED and self.cancellation_status is not CancellationStatus.NONE:
            raise ValueError("COMPLETED requires cancellation NONE")
        if self.state is TaskState.CANCELLED and self.cancellation_status is not CancellationStatus.AUTHORITATIVE:
            raise ValueError("CANCELLED requires authoritative cancellation")
        if self.cancellation_status is not CancellationStatus.NONE and self.state is TaskState.COMPLETED:
            raise ValueError("cancellation cannot coexist with completion")
        if self.cancellation_status is CancellationStatus.AUTHORITATIVE and self.next_integration_operation_id is not None:
            raise ValueError("authoritative cancellation clears next operation")


def _evidence_tuple(values: object) -> tuple[EvidenceBindingRef, ...]:
    if type(values) is not tuple:
        raise TypeError("supporting evidence must be exactly tuple")
    seen: dict[EvidenceId, CandidateId | None] = {}
    for value in values:
        if type(value) is not EvidenceBindingRef:
            raise TypeError("supporting evidence item has wrong exact type")
        if value.evidence_id in seen:
            raise ValueError("EvidenceId must be unique")
        seen[value.evidence_id] = value.candidate_id
    return values


@dataclass(frozen=True, slots=True)
class TaskOperationSnapshot:
    task_id: TaskId
    membership_binding_id: OperationMembershipBindingId
    operations: tuple[OperationRecord, ...]

    def __post_init__(self) -> None:
        if type(self.task_id) is not TaskId or type(self.membership_binding_id) is not OperationMembershipBindingId:
            raise TypeError("snapshot identity has wrong exact type")
        if type(self.operations) is not tuple:
            raise TypeError("operations must be exactly tuple")
        seen: set[OperationId] = set()
        for operation in self.operations:
            if type(operation) is not OperationRecord:
                raise TypeError("snapshot operation has wrong exact type")
            if operation.intent.task_id != self.task_id:
                raise ValueError("snapshot operation belongs to another task")
            if operation.intent.operation_id in seen:
                raise ValueError("duplicate OperationId in snapshot")
            seen.add(operation.intent.operation_id)


@dataclass(frozen=True, slots=True)
class OperationRevisionBinding:
    operation_id: OperationId
    revision: OperationRevision

    def __post_init__(self) -> None:
        if type(self.operation_id) is not OperationId:
            raise TypeError("operation_id must be exactly OperationId")
        _revision(self.revision, "bound operation revision")


@dataclass(frozen=True, slots=True, init=False)
class CompletionAggregate:
    completion_rule_set_id: CompletionRuleSetId
    task_id: TaskId
    contract_id: ContractId
    contract_raw_sha256: RawSha256
    authorization_id: AuthorizationId
    admission_event_id: AdmissionEventId
    target_registration_id: TargetRegistrationId
    policy_epoch_identity: PolicyEpochIdentity
    candidate_id: CandidateId | None
    contract_acceptance_status: ConditionStatus
    additional_trusted_completion_conditions_status: ConditionStatus
    required_protected_operation_ids: tuple[OperationId, ...]
    current_applicability_and_authority_status: ConditionStatus

    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("completion aggregate must come from a trusted composition boundary")


@dataclass(frozen=True, slots=True, init=False)
class CandidateApplicabilityDetermination:
    decision_event_id: DecisionEventId
    candidate_id: CandidateId
    task_id: TaskId
    expected_task_revision: TaskRevision
    contract_id: ContractId
    contract_raw_sha256: RawSha256
    authorization_id: AuthorizationId
    admission_event_id: AdmissionEventId
    target_registration_id: TargetRegistrationId
    policy_epoch_identity: PolicyEpochIdentity

    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("candidate applicability must come from a trusted boundary")


@dataclass(frozen=True, slots=True)
class TaskEvaluationInput:
    task_id: TaskId
    expected_task_revision: TaskRevision
    contract_id: ContractId
    contract_raw_sha256: RawSha256
    authorization_id: AuthorizationId
    admission_event_id: AdmissionEventId
    target_registration_id: TargetRegistrationId
    current_policy_epoch_identity: PolicyEpochIdentity
    evaluated_candidate_id: CandidateId | None
    blocking_condition_ids: tuple[BlockingConditionId, ...]
    awaiting_input_requirement_ids: tuple[AwaitingInputRequirementId, ...]
    next_integration_operation_id: OperationId | None
    completion: CompletionAggregate
    operation_snapshot: TaskOperationSnapshot
    expected_membership_binding_id: OperationMembershipBindingId
    expected_operation_revisions: tuple[OperationRevisionBinding, ...]

    def __post_init__(self) -> None:
        exact = (
            (self.task_id, TaskId), (self.contract_id, ContractId),
            (self.contract_raw_sha256, RawSha256), (self.authorization_id, AuthorizationId),
            (self.admission_event_id, AdmissionEventId),
            (self.target_registration_id, TargetRegistrationId),
            (self.current_policy_epoch_identity, PolicyEpochIdentity),
            (self.completion, CompletionAggregate),
            (self.operation_snapshot, TaskOperationSnapshot),
            (self.expected_membership_binding_id, OperationMembershipBindingId),
        )
        if any(type(value) is not expected for value, expected in exact):
            raise TypeError("evaluation field has wrong exact type")
        if self.evaluated_candidate_id is not None and type(self.evaluated_candidate_id) is not CandidateId:
            raise TypeError("evaluated_candidate_id has wrong exact type")
        if self.next_integration_operation_id is not None and type(self.next_integration_operation_id) is not OperationId:
            raise TypeError("next integration operation has wrong exact type")
        _revision(self.expected_task_revision, "expected task revision")
        _unique_exact(self.blocking_condition_ids, BlockingConditionId, "blocking conditions")
        _unique_exact(self.awaiting_input_requirement_ids, AwaitingInputRequirementId, "waiting requirements")
        _unique_exact(self.expected_operation_revisions, OperationRevisionBinding, "operation revision bindings")
        if len({item.operation_id for item in self.expected_operation_revisions}) != len(self.expected_operation_revisions):
            raise ValueError("duplicate bound OperationId")


def _compose_candidate_applicability(
    task: TaskRecord, candidate: CandidateRecord,
    decision_event_id: DecisionEventId,
) -> CandidateApplicabilityDetermination:
    """Produce the trusted applicability result from exact canonical inputs."""
    if type(task) is not TaskRecord or type(candidate) is not CandidateRecord:
        raise TypeError("exact canonical task and candidate required")
    if type(decision_event_id) is not DecisionEventId:
        raise TypeError("exact decision event identity required")
    if not _identity_matches(task, candidate):
        raise ValueError("candidate does not match canonical task authority")
    result = object.__new__(CandidateApplicabilityDetermination)
    for name, value in (
        ("decision_event_id", decision_event_id),
        ("candidate_id", candidate.candidate_id), ("task_id", task.task_id),
        ("expected_task_revision", task.revision),
        ("contract_id", task.contract_id),
        ("contract_raw_sha256", task.contract_raw_sha256),
        ("authorization_id", task.authorization_id),
        ("admission_event_id", task.admission_event_id),
        ("target_registration_id", task.target_registration_id),
        ("policy_epoch_identity", task.last_evaluated_policy_epoch_identity),
    ):
        object.__setattr__(result, name, value)
    return result


def _compose_completion_aggregate(
    *, task: TaskRecord, completion_rule_set_id: CompletionRuleSetId,
    policy_epoch_identity: PolicyEpochIdentity,
    contract_acceptance_status: ConditionStatus,
    additional_conditions_status: ConditionStatus,
    required_operation_ids: tuple[OperationId, ...],
    applicability_status: ConditionStatus,
) -> CompletionAggregate:
    """Trusted-controller composition boundary for an exact completion aggregate."""
    exact = (
        (task, TaskRecord), (completion_rule_set_id, CompletionRuleSetId),
        (policy_epoch_identity, PolicyEpochIdentity),
        (contract_acceptance_status, ConditionStatus),
        (additional_conditions_status, ConditionStatus),
        (applicability_status, ConditionStatus),
    )
    if any(type(value) is not expected for value, expected in exact):
        raise TypeError("completion composition input has wrong exact type")
    _unique_exact(required_operation_ids, OperationId, "required operation ids")
    result = object.__new__(CompletionAggregate)
    values = {
        "completion_rule_set_id": completion_rule_set_id,
        "task_id": task.task_id, "contract_id": task.contract_id,
        "contract_raw_sha256": task.contract_raw_sha256,
        "authorization_id": task.authorization_id,
        "admission_event_id": task.admission_event_id,
        "target_registration_id": task.target_registration_id,
        "policy_epoch_identity": policy_epoch_identity,
        "candidate_id": task.current_candidate_id,
        "contract_acceptance_status": contract_acceptance_status,
        "additional_trusted_completion_conditions_status": additional_conditions_status,
        "required_protected_operation_ids": required_operation_ids,
        "current_applicability_and_authority_status": applicability_status,
    }
    for name, value in values.items():
        object.__setattr__(result, name, value)
    return result


@dataclass(frozen=True, slots=True)
class TaskCreateProposal:
    expected_absent: bool
    proposed: TaskRecord

    def __post_init__(self) -> None:
        if self.expected_absent is not True or type(self.proposed) is not TaskRecord:
            raise ValueError("initial proposal requires expected absent and exact TaskRecord")
        if self.proposed.revision != 1 or self.proposed.state is not TaskState.ADMITTED:
            raise ValueError("initial task must be ADMITTED@1")


@dataclass(frozen=True, slots=True)
class TaskRevisionProposal:
    expected_revision: TaskRevision
    proposed: TaskRecord
    expected_membership_binding_id: OperationMembershipBindingId | None = None
    expected_operation_revisions: tuple[OperationRevisionBinding, ...] = ()

    def __post_init__(self) -> None:
        _revision(self.expected_revision, "expected task revision")
        if type(self.proposed) is not TaskRecord or self.proposed.revision != self.expected_revision + 1:
            raise ValueError("proposed revision must increment exactly once")
        _unique_exact(self.expected_operation_revisions, OperationRevisionBinding, "operation revision bindings")


@dataclass(frozen=True, slots=True)
class OperationCreateProposal:
    expected_absent: bool
    expected_task_revision: TaskRevision
    expected_membership_binding_id: OperationMembershipBindingId
    proposed: OperationRecord

    def __post_init__(self) -> None:
        if self.expected_absent is not True:
            raise ValueError("new operation requires expected absent")
        _revision(self.expected_task_revision, "expected task revision")
        if type(self.expected_membership_binding_id) is not OperationMembershipBindingId:
            raise TypeError("membership binding has wrong exact type")
        if type(self.proposed) is not OperationRecord or (
            self.proposed.revision != 1 or self.proposed.state is not OperationState.RESERVED
        ):
            raise ValueError("new operation must be RESERVED@1")


@dataclass(frozen=True, slots=True)
class OperationStartProposal:
    expected_task_revision: TaskRevision
    expected_operation_revision: OperationRevision
    expected_cancellation_status: CancellationStatus
    expected_candidate_id: CandidateId | None
    expected_authoritative_state_binding_id: AuthoritativeStateBindingId
    operation_start_binding_id: OperationStartBindingId
    proposed_task: TaskRecord | None
    proposed_operation: OperationRecord

    def __post_init__(self) -> None:
        _revision(self.expected_task_revision, "expected task revision")
        _revision(self.expected_operation_revision, "expected operation revision")
        if type(self.expected_cancellation_status) is not CancellationStatus:
            raise TypeError("cancellation binding has wrong exact type")
        if self.expected_candidate_id is not None and type(self.expected_candidate_id) is not CandidateId:
            raise TypeError("candidate binding has wrong exact type")
        if type(self.expected_authoritative_state_binding_id) is not AuthoritativeStateBindingId:
            raise TypeError("authoritative-state binding has wrong exact type")
        if type(self.operation_start_binding_id) is not OperationStartBindingId:
            raise TypeError("operation-start binding has wrong exact type")
        if self.proposed_task is not None and type(self.proposed_task) is not TaskRecord:
            raise TypeError("proposed task has wrong exact type")
        if type(self.proposed_operation) is not OperationRecord:
            raise TypeError("proposed operation has wrong exact type")
        if self.proposed_operation.revision != self.expected_operation_revision + 1:
            raise ValueError("start must increment operation revision exactly once")
        if self.proposed_operation.state is not OperationState.PERFORMING:
            raise ValueError("start proposal must establish PERFORMING")
        if self.proposed_operation.start_binding_id != self.operation_start_binding_id:
            raise ValueError("start proposal must preserve its exact start binding")


@dataclass(frozen=True, slots=True)
class TaskResult:
    proposal: TaskRevisionProposal | None = None
    task: TaskRecord | None = None
    operation: OperationRecord | None = None
    operation_create_proposal: OperationCreateProposal | None = None
    operation_start_proposal: OperationStartProposal | None = None
    replayed: bool = False
    failure: G4Failure | None = None

    def __post_init__(self) -> None:
        values = (
            self.proposal, self.task, self.operation,
            self.operation_create_proposal, self.operation_start_proposal,
        )
        if self.failure is not None and any(value is not None for value in values):
            raise ValueError("failure cannot carry proposed values")
        if self.failure is None and all(value is None for value in values):
            raise ValueError("successful result must carry a value")


_TASK_TRANSITIONS = {
    TaskState.ADMITTED: frozenset((TaskState.EVALUATING, TaskState.AWAITING_INPUT, TaskState.BLOCKED, TaskState.COMPLETED, TaskState.CANCELLED)),
    TaskState.EVALUATING: frozenset((TaskState.ADMITTED, TaskState.AWAITING_INPUT, TaskState.INTEGRATION_READY, TaskState.BLOCKED, TaskState.COMPLETED, TaskState.CANCELLED)),
    TaskState.AWAITING_INPUT: frozenset((TaskState.ADMITTED, TaskState.EVALUATING, TaskState.INTEGRATION_READY, TaskState.BLOCKED, TaskState.COMPLETED, TaskState.CANCELLED)),
    TaskState.INTEGRATION_READY: frozenset((TaskState.ADMITTED, TaskState.EVALUATING, TaskState.AWAITING_INPUT, TaskState.BLOCKED, TaskState.COMPLETED, TaskState.CANCELLED)),
    TaskState.BLOCKED: frozenset((TaskState.ADMITTED, TaskState.EVALUATING, TaskState.AWAITING_INPUT, TaskState.INTEGRATION_READY, TaskState.COMPLETED, TaskState.CANCELLED)),
}


def initial_task_proposal(
    *, task_id: TaskId, contract_id: ContractId, contract_raw_sha256: RawSha256,
    authorization_id: AuthorizationId, admission_event_id: AdmissionEventId,
    target_registration_id: TargetRegistrationId, policy_epoch_identity: PolicyEpochIdentity,
    repair_budget: RepairBudget,
) -> TaskCreateProposal:
    return TaskCreateProposal(True, TaskRecord(
        task_id, 1, TaskState.ADMITTED, contract_id, contract_raw_sha256,
        authorization_id, admission_event_id, target_registration_id, policy_epoch_identity,
        None, None, (), repair_budget,
    ))


def _failure(code: G4FailureCode) -> TaskResult:
    return TaskResult(failure=G4Failure(code))


def _base_check(task: TaskRecord, expected_revision: int) -> G4FailureCode | None:
    _revision(expected_revision, "expected task revision")
    if expected_revision != task.revision:
        return G4FailureCode.REVISION_CONFLICT
    if task.state in (TaskState.COMPLETED, TaskState.CANCELLED):
        return G4FailureCode.TERMINAL_TASK
    return None


def _proposal(task: TaskRecord, proposed: TaskRecord, *, membership=None, bindings=()) -> TaskResult:
    if proposed.state is not task.state and proposed.state not in _TASK_TRANSITIONS.get(task.state, frozenset()):
        return _failure(G4FailureCode.INVALID_TASK_TRANSITION)
    return TaskResult(TaskRevisionProposal(task.revision, proposed, membership, bindings))


def _identity_matches(task: TaskRecord, candidate: CandidateRecord) -> bool:
    return (
        candidate.task_id == task.task_id and candidate.contract_id == task.contract_id
        and candidate.contract_raw_sha256 == task.contract_raw_sha256
        and candidate.authorization_id == task.authorization_id
        and candidate.admission_event_id == task.admission_event_id
        and candidate.target_registration_id == task.target_registration_id
        and candidate.policy_epoch_identity == task.last_evaluated_policy_epoch_identity
    )


def _operation_map(snapshot: TaskOperationSnapshot) -> dict[OperationId, OperationRecord]:
    return {item.intent.operation_id: item for item in snapshot.operations}


def _binding_failure(
    snapshot: TaskOperationSnapshot,
    expected_membership: OperationMembershipBindingId,
    bindings: tuple[OperationRevisionBinding, ...],
    relevant: tuple[OperationRecord, ...],
) -> G4FailureCode | None:
    if expected_membership != snapshot.membership_binding_id:
        return G4FailureCode.OPERATION_MEMBERSHIP_CONFLICT
    expected = {item.operation_id: item.revision for item in bindings}
    for operation in relevant:
        if expected.get(operation.intent.operation_id) != operation.revision:
            return G4FailureCode.REVISION_CONFLICT
    return None


def adopt_candidate(
    task: TaskRecord, candidate: CandidateRecord, determination: CandidateApplicabilityDetermination,
    *, expected_task_revision: TaskRevision,
    snapshot: TaskOperationSnapshot, expected_membership_binding_id: OperationMembershipBindingId,
    expected_operation_revisions: tuple[OperationRevisionBinding, ...],
) -> TaskResult:
    problem = _base_check(task, expected_task_revision)
    if problem:
        return _failure(problem)
    if task.cancellation_status is CancellationStatus.AUTHORITATIVE:
        return _failure(G4FailureCode.INVALID_TASK_TRANSITION)
    if snapshot.task_id != task.task_id:
        return _failure(G4FailureCode.IDENTITY_MISMATCH)
    if type(determination) is not CandidateApplicabilityDetermination:
        raise TypeError("determination must be exactly CandidateApplicabilityDetermination")
    if not _identity_matches(task, candidate) or (
        determination.candidate_id != candidate.candidate_id
        or determination.task_id != task.task_id
        or determination.expected_task_revision != expected_task_revision
        or determination.contract_id != task.contract_id
        or determination.contract_raw_sha256 != task.contract_raw_sha256
        or determination.authorization_id != task.authorization_id
        or determination.admission_event_id != task.admission_event_id
        or determination.target_registration_id != task.target_registration_id
        or determination.policy_epoch_identity != task.last_evaluated_policy_epoch_identity
    ):
        return _failure(G4FailureCode.IDENTITY_MISMATCH)
    if candidate.candidate_id == task.current_candidate_id:
        return _failure(G4FailureCode.IDENTITY_MISMATCH)
    old = task.current_candidate_id
    relevant = tuple(
        operation for operation in snapshot.operations
        if old is not None and operation.intent.candidate_id == old
        and operation.intent.effect_class is OperationEffectClass.PROTECTED_OR_AUTHORITATIVE_EFFECT
        and operation.state in (OperationState.RESERVED, OperationState.PERFORMING, OperationState.INDETERMINATE)
    )
    binding_problem = _binding_failure(snapshot, expected_membership_binding_id, expected_operation_revisions, relevant)
    if binding_problem:
        return _failure(binding_problem)
    if any(item.state in (OperationState.PERFORMING, OperationState.INDETERMINATE) for item in relevant):
        return _failure(G4FailureCode.CANDIDATE_DETACHMENT_UNSAFE)
    evidence = tuple(ref for ref in task.supporting_evidence_refs if ref.candidate_id != old)
    proposed = replace(
        task, revision=task.revision + 1, state=TaskState.EVALUATING,
        current_candidate_id=candidate.candidate_id, next_integration_operation_id=None,
        supporting_evidence_refs=evidence,
    )
    return _proposal(task, proposed, membership=expected_membership_binding_id, bindings=expected_operation_revisions)


def revise_supporting_evidence(
    task: TaskRecord, refs: tuple[EvidenceBindingRef, ...], *, expected_task_revision: TaskRevision,
) -> TaskResult:
    problem = _base_check(task, expected_task_revision)
    if problem:
        return _failure(problem)
    try:
        _evidence_tuple(refs)
    except ValueError:
        return _failure(G4FailureCode.EVIDENCE_BINDING_MISMATCH)
    proposed = replace(task, revision=task.revision + 1, supporting_evidence_refs=refs)
    return _proposal(task, proposed)


def _evaluation_identity_ok(task: TaskRecord, value: TaskEvaluationInput) -> bool:
    completion = value.completion
    common = (
        value.task_id == task.task_id == completion.task_id
        and value.contract_id == task.contract_id == completion.contract_id
        and value.contract_raw_sha256 == task.contract_raw_sha256 == completion.contract_raw_sha256
        and value.authorization_id == task.authorization_id == completion.authorization_id
        and value.admission_event_id == task.admission_event_id == completion.admission_event_id
        and value.target_registration_id == task.target_registration_id == completion.target_registration_id
        and value.current_policy_epoch_identity == completion.policy_epoch_identity
        and value.evaluated_candidate_id == task.current_candidate_id == completion.candidate_id
        and value.operation_snapshot.task_id == task.task_id
    )
    return common


def evaluate_task(task: TaskRecord, evaluation: TaskEvaluationInput) -> TaskResult:
    problem = _base_check(task, evaluation.expected_task_revision)
    if problem:
        return _failure(problem)
    if not _evaluation_identity_ok(task, evaluation):
        return _failure(G4FailureCode.IDENTITY_MISMATCH)
    operations = _operation_map(evaluation.operation_snapshot)
    protected = tuple(
        operation for operation in evaluation.operation_snapshot.operations
        if operation.intent.effect_class is OperationEffectClass.PROTECTED_OR_AUTHORITATIVE_EFFECT
    )
    required: list[OperationRecord] = []
    for operation_id in evaluation.completion.required_protected_operation_ids:
        operation = operations.get(operation_id)
        if operation is None or operation.intent.effect_class is not OperationEffectClass.PROTECTED_OR_AUTHORITATIVE_EFFECT:
            return _failure(G4FailureCode.INCONSISTENT_TASK_EVALUATION)
        required.append(operation)
    next_id = evaluation.next_integration_operation_id
    if next_id is not None and next_id not in operations:
        return _failure(G4FailureCode.INCONSISTENT_TASK_EVALUATION)
    safety_sensitive = tuple(
        operation for operation in protected
        if operation.state in (OperationState.RESERVED, OperationState.PERFORMING, OperationState.INDETERMINATE)
    )
    relevant = tuple({op.intent.operation_id: op for op in (*safety_sensitive, *required)}.values())
    binding_problem = _binding_failure(
        evaluation.operation_snapshot, evaluation.expected_membership_binding_id,
        evaluation.expected_operation_revisions, relevant,
    )
    if binding_problem:
        return _failure(binding_problem)
    statuses_satisfied = (
        evaluation.completion.contract_acceptance_status is ConditionStatus.SATISFIED
        and evaluation.completion.additional_trusted_completion_conditions_status is ConditionStatus.SATISFIED
        and evaluation.completion.current_applicability_and_authority_status is ConditionStatus.SATISFIED
    )
    required_succeeded = all(item.state is OperationState.SUCCEEDED for item in required)
    unresolved = any(item.state in (OperationState.PERFORMING, OperationState.INDETERMINATE) for item in protected)
    completion_claim = statuses_satisfied and required_succeeded and not unresolved
    completion_satisfied = (
        completion_claim and task.cancellation_status is CancellationStatus.NONE
    )
    if completion_satisfied and (
        evaluation.blocking_condition_ids or evaluation.awaiting_input_requirement_ids or next_id is not None
    ):
        return _failure(G4FailureCode.INCONSISTENT_TASK_EVALUATION)
    if (
        evaluation.completion.current_applicability_and_authority_status is not ConditionStatus.SATISFIED
        and not evaluation.blocking_condition_ids and not evaluation.awaiting_input_requirement_ids
    ):
        return _failure(G4FailureCode.INCONSISTENT_TASK_EVALUATION)
    if task.cancellation_status is CancellationStatus.AUTHORITATIVE:
        if unresolved:
            target = task.state
            if target is TaskState.INTEGRATION_READY:
                target = TaskState.EVALUATING if task.current_candidate_id is not None else TaskState.ADMITTED
        else:
            target = TaskState.CANCELLED
        next_id = None
    elif evaluation.blocking_condition_ids:
        target = TaskState.BLOCKED
        next_id = None
    elif completion_satisfied:
        target = TaskState.COMPLETED
        next_id = None
    elif evaluation.awaiting_input_requirement_ids:
        target = TaskState.AWAITING_INPUT
        next_id = None
    elif next_id is not None:
        target = TaskState.INTEGRATION_READY
    elif task.current_candidate_id is not None:
        target = TaskState.EVALUATING
    else:
        target = TaskState.ADMITTED
    proposed = replace(
        task, revision=task.revision + 1, state=target,
        next_integration_operation_id=next_id,
        last_evaluated_policy_epoch_identity=evaluation.current_policy_epoch_identity,
    )
    return _proposal(
        task, proposed, membership=evaluation.expected_membership_binding_id,
        bindings=evaluation.expected_operation_revisions,
    )


def set_cancellation(
    task: TaskRecord, status: CancellationStatus, request_id: CancellationRequestId | None,
    *, expected_task_revision: TaskRevision, snapshot: TaskOperationSnapshot | None = None,
    expected_membership_binding_id: OperationMembershipBindingId | None = None,
    expected_operation_revisions: tuple[OperationRevisionBinding, ...] = (),
) -> TaskResult:
    problem = _base_check(task, expected_task_revision)
    if problem:
        return _failure(problem)
    if type(status) is not CancellationStatus:
        raise TypeError("status must be exactly CancellationStatus")
    allowed = {
        CancellationStatus.NONE: frozenset((CancellationStatus.REQUESTED, CancellationStatus.AUTHORITATIVE)),
        CancellationStatus.REQUESTED: frozenset((CancellationStatus.NONE, CancellationStatus.AUTHORITATIVE)),
        CancellationStatus.AUTHORITATIVE: frozenset(),
    }
    if status not in allowed[task.cancellation_status]:
        return _failure(G4FailureCode.INVALID_TASK_TRANSITION)
    if status is CancellationStatus.NONE:
        request_id = None
    elif type(request_id) is not CancellationRequestId:
        raise TypeError("cancellation request identity required")
    target = task.state
    membership = None
    bindings: tuple[OperationRevisionBinding, ...] = ()
    if status is CancellationStatus.AUTHORITATIVE:
        if snapshot is None or expected_membership_binding_id is None:
            return _failure(G4FailureCode.OPERATION_MEMBERSHIP_CONFLICT)
        if snapshot.task_id != task.task_id:
            return _failure(G4FailureCode.IDENTITY_MISMATCH)
        relevant = tuple(
            operation for operation in snapshot.operations
            if operation.intent.effect_class is OperationEffectClass.PROTECTED_OR_AUTHORITATIVE_EFFECT
            and operation.state in (OperationState.RESERVED, OperationState.PERFORMING, OperationState.INDETERMINATE)
        )
        binding_problem = _binding_failure(snapshot, expected_membership_binding_id, expected_operation_revisions, relevant)
        if binding_problem:
            return _failure(binding_problem)
        unresolved = any(item.state in (OperationState.PERFORMING, OperationState.INDETERMINATE) for item in relevant)
        if unresolved:
            target = task.state
            if target is TaskState.INTEGRATION_READY:
                target = TaskState.EVALUATING if task.current_candidate_id is not None else TaskState.ADMITTED
        else:
            target = TaskState.CANCELLED
        membership, bindings = expected_membership_binding_id, expected_operation_revisions
    next_operation = (
        None if status is CancellationStatus.AUTHORITATIVE
        else task.next_integration_operation_id
    )
    proposed = replace(
        task, revision=task.revision + 1, state=target,
        cancellation_status=status, cancellation_request_id=request_id,
        next_integration_operation_id=next_operation,
    )
    return _proposal(task, proposed, membership=membership, bindings=bindings)


def reserve_repair_attempt(
    task: TaskRecord, operation_id: OperationId, *, expected_task_revision: TaskRevision,
    snapshot: TaskOperationSnapshot,
    expected_membership_binding_id: OperationMembershipBindingId,
) -> TaskResult:
    problem = _base_check(task, expected_task_revision)
    if problem:
        return _failure(problem)
    if snapshot.task_id != task.task_id:
        return _failure(G4FailureCode.IDENTITY_MISMATCH)
    if expected_membership_binding_id != snapshot.membership_binding_id:
        return _failure(G4FailureCode.OPERATION_MEMBERSHIP_CONFLICT)
    if task.cancellation_status is CancellationStatus.AUTHORITATIVE:
        return _failure(G4FailureCode.CANCELLATION_BLOCKS_OPERATION_START)
    budget = task.repair_budget
    historical = (*budget.reserved_operation_ids, *budget.consumed_operation_ids, *budget.released_operation_ids)
    if operation_id in historical:
        return TaskResult(task=task, replayed=True)
    if any(operation.intent.operation_id == operation_id for operation in snapshot.operations):
        return _failure(G4FailureCode.REPAIR_ATTEMPT_REUSE_MISMATCH)
    if len(budget.reserved_operation_ids) + len(budget.consumed_operation_ids) >= budget.maximum_attempts:
        return _failure(G4FailureCode.REPAIR_BUDGET_EXHAUSTED)
    updated = replace(budget, reserved_operation_ids=(*budget.reserved_operation_ids, operation_id))
    proposed = replace(task, revision=task.revision + 1, repair_budget=updated)
    return _proposal(task, proposed, membership=expected_membership_binding_id)


def release_repair_attempt(
    task: TaskRecord, operation_id: OperationId, *, expected_task_revision: TaskRevision,
    snapshot: TaskOperationSnapshot,
    expected_membership_binding_id: OperationMembershipBindingId,
    expected_operation_revision: OperationRevision | None = None,
) -> TaskResult:
    problem = _base_check(task, expected_task_revision)
    if problem:
        return _failure(problem)
    if snapshot.task_id != task.task_id:
        return _failure(G4FailureCode.IDENTITY_MISMATCH)
    if expected_membership_binding_id != snapshot.membership_binding_id:
        return _failure(G4FailureCode.OPERATION_MEMBERSHIP_CONFLICT)
    if operation_id not in task.repair_budget.reserved_operation_ids:
        return _failure(G4FailureCode.REPAIR_ATTEMPT_NOT_RESERVED)
    bindings: tuple[OperationRevisionBinding, ...] = ()
    operation = next(
        (item for item in snapshot.operations if item.intent.operation_id == operation_id),
        None,
    )
    if operation is not None:
        if not operation.intent.is_repair_attempt or operation.state is not OperationState.RESERVED:
            return _failure(G4FailureCode.REPAIR_ATTEMPT_REUSE_MISMATCH)
        if expected_operation_revision != operation.revision:
            return _failure(G4FailureCode.REVISION_CONFLICT)
        bindings = (OperationRevisionBinding(operation_id, operation.revision),)
    elif expected_operation_revision is not None:
        return _failure(G4FailureCode.REPAIR_ATTEMPT_REUSE_MISMATCH)
    budget = task.repair_budget
    updated = replace(
        budget,
        reserved_operation_ids=tuple(item for item in budget.reserved_operation_ids if item != operation_id),
        released_operation_ids=(*budget.released_operation_ids, operation_id),
    )
    proposed = replace(task, revision=task.revision + 1, repair_budget=updated)
    return _proposal(
        task, proposed, membership=expected_membership_binding_id, bindings=bindings
    )


def reserve_task_operation(
    task: TaskRecord, intent, snapshot: TaskOperationSnapshot, *,
    expected_task_revision: TaskRevision,
    expected_membership_binding_id: OperationMembershipBindingId,
) -> TaskResult:
    problem = _base_check(task, expected_task_revision)
    if problem:
        return _failure(problem)
    if expected_membership_binding_id != snapshot.membership_binding_id:
        return _failure(G4FailureCode.OPERATION_MEMBERSHIP_CONFLICT)
    if snapshot.task_id != task.task_id:
        return _failure(G4FailureCode.IDENTITY_MISMATCH)
    if intent.task_id != task.task_id:
        return _failure(G4FailureCode.IDENTITY_MISMATCH)
    if task.cancellation_status is CancellationStatus.AUTHORITATIVE:
        return _failure(G4FailureCode.CANCELLATION_BLOCKS_OPERATION_START)
    if intent.is_repair_attempt and intent.operation_id not in task.repair_budget.reserved_operation_ids:
        return _failure(G4FailureCode.REPAIR_ATTEMPT_NOT_RESERVED)
    result = reserve_operation(intent, snapshot.operations)
    if result.failure is not None:
        return TaskResult(failure=result.failure)
    if result.replayed:
        return TaskResult(task=task, operation=result.operation, replayed=True)
    create = OperationCreateProposal(
        True, expected_task_revision, expected_membership_binding_id, result.operation
    )
    return TaskResult(task=task, operation=result.operation, operation_create_proposal=create)


def start_operation(
    task: TaskRecord, operation: OperationRecord, *, expected_task_revision: TaskRevision,
    expected_operation_revision: OperationRevision,
    expected_cancellation_status: CancellationStatus,
    operation_start_binding_id: OperationStartBindingId,
) -> TaskResult:
    """Return a conditional start proposal; no effect may begin before durable commit."""
    _revision(expected_task_revision, "expected task revision")
    if expected_task_revision != task.revision:
        return _failure(G4FailureCode.REVISION_CONFLICT)
    if operation.revision != expected_operation_revision:
        return _failure(G4FailureCode.REVISION_CONFLICT)
    intent = operation.intent
    if (
        intent.task_id != task.task_id or intent.contract_id != task.contract_id
        or intent.contract_raw_sha256 != task.contract_raw_sha256
        or intent.authorization_id != task.authorization_id
        or intent.admission_event_id != task.admission_event_id
        or intent.target_registration_id != task.target_registration_id
        or intent.policy_epoch_identity != task.last_evaluated_policy_epoch_identity
    ):
        return _failure(G4FailureCode.IDENTITY_MISMATCH)
    if expected_cancellation_status is not task.cancellation_status:
        return _failure(G4FailureCode.REVISION_CONFLICT)
    if task.cancellation_status is CancellationStatus.AUTHORITATIVE and intent.is_repair_attempt:
        return _failure(G4FailureCode.CANCELLATION_BLOCKS_OPERATION_START)
    if (
        task.cancellation_status is CancellationStatus.AUTHORITATIVE
        and intent.effect_class is OperationEffectClass.PROTECTED_OR_AUTHORITATIVE_EFFECT
        and intent.purpose is OperationPurpose.NORMAL
    ):
        return _failure(G4FailureCode.CANCELLATION_BLOCKS_OPERATION_START)
    if task.state in (TaskState.COMPLETED, TaskState.CANCELLED):
        return _failure(G4FailureCode.TERMINAL_TASK)
    if intent.candidate_id is not None and intent.candidate_id != task.current_candidate_id:
        return _failure(G4FailureCode.OPERATION_NOT_STARTABLE)
    if type(intent.integration_binding) is IntegrationBound and (
        task.state is not TaskState.INTEGRATION_READY
        or task.next_integration_operation_id != intent.operation_id
    ):
        return _failure(G4FailureCode.OPERATION_NOT_STARTABLE)
    if operation.state in (OperationState.PERFORMING, OperationState.INDETERMINATE):
        return _failure(G4FailureCode.RECONCILIATION_REQUIRED)
    if operation.state is not OperationState.RESERVED:
        return _failure(G4FailureCode.OPERATION_NOT_STARTABLE)
    updated_task = task
    if intent.is_repair_attempt:
        if intent.operation_id not in task.repair_budget.reserved_operation_ids:
            return _failure(G4FailureCode.REPAIR_ATTEMPT_NOT_RESERVED)
        budget = replace(
            task.repair_budget,
            reserved_operation_ids=tuple(item for item in task.repair_budget.reserved_operation_ids if item != intent.operation_id),
            consumed_operation_ids=(*task.repair_budget.consumed_operation_ids, intent.operation_id),
        )
        updated_task = replace(task, revision=task.revision + 1, repair_budget=budget)
    if type(operation_start_binding_id) is not OperationStartBindingId:
        raise TypeError("operation_start_binding_id has wrong exact type")
    performing = OperationRecord(
        operation.intent, operation.revision + 1, OperationState.PERFORMING,
        start_binding_id=operation_start_binding_id,
    )
    start = OperationStartProposal(
        expected_task_revision=expected_task_revision,
        expected_operation_revision=expected_operation_revision,
        expected_cancellation_status=expected_cancellation_status,
        expected_candidate_id=intent.candidate_id,
        expected_authoritative_state_binding_id=intent.authoritative_state_binding_id,
        operation_start_binding_id=operation_start_binding_id,
        proposed_task=updated_task if intent.is_repair_attempt else None,
        proposed_operation=performing,
    )
    return TaskResult(
        task=updated_task, operation=performing, operation_start_proposal=start
    )
