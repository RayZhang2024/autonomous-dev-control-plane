"""G6 canonical-state reference backend and future state-root contract.

The in-memory backend is a semantic reference implementation only.  It is not
durable production authority and performs no filesystem, network, credential,
GitHub, publication, merge, or protected-effect operation.
"""

from __future__ import annotations

from dataclasses import dataclass, fields, is_dataclass
from enum import Enum
from functools import lru_cache
import hashlib
import json
from threading import RLock
from types import MappingProxyType, UnionType
from typing import TypeAlias, Union, get_args, get_origin, get_type_hints

from .authorization import AdmittedAuthorization
from .evidence import EvidenceRecord, EvidenceSubject, EvidenceSupersessionRecord, SemanticEvidencePayload
from .identity import GitSha, ImmutableConfigId, RawSha256
from .manifest import PolicyEpochIdentity
from .operation import CandidateId, EvidenceId, IntegrationBound, OperationId, OperationMembershipBindingId, OperationRecord, OperationState
from .review import (
    AdmittedSemanticEvidenceBinding,
    CanonicalRequestId,
    EvidenceHistoryMembershipBindingId,
    ReviewInvocationId,
    MaterialIdentity,
    RequirementResult,
    ReviewSlotAttempt,
    ReviewSlotId,
    SemanticReviewEffectiveSubject,
    SemanticReviewEffectiveSubjectId,
    TrustedContextId,
    TrustedEffectiveSubjectEvidenceSnapshot,
    TrustedReviewSlotAttemptSnapshot,
)
from .scope import AuthorizationId, GitHubRepositoryId, TargetRegistrationId, TaskId
from .state import CancellationStatus, CandidateRecord, TaskOperationSnapshot, TaskRecord, TaskState
from .target_registration import AdmittedTargetRegistration


def _positive(value: object, name: str) -> int:
    if type(value) is not int or value < 1:
        raise ValueError(f"{name} must be an exact positive int")
    return value


def _exact_tuple(values: object, expected: type, name: str, *, unique: bool = True) -> tuple:
    if type(values) is not tuple or any(type(item) is not expected for item in values):
        raise TypeError(f"{name} must be an exact tuple of {expected.__name__}")
    if unique and len(set(values)) != len(values):
        raise ValueError(f"{name} must be duplicate-free")
    return values


@dataclass(frozen=True, slots=True)
class BackendGeneration:
    value: int

    def __post_init__(self) -> None:
        _positive(self.value, "backend generation")


@dataclass(frozen=True, slots=True)
class CanonicalStateOccurrenceBinding:
    backend_generation: BackendGeneration | None = None
    state_root: GitSha | None = None

    def __post_init__(self) -> None:
        if (self.backend_generation is None) == (self.state_root is None):
            raise ValueError("canonical occurrence binds exactly one backend generation or state root")
        if self.backend_generation is not None and type(self.backend_generation) is not BackendGeneration:
            raise TypeError("backend_generation has wrong exact type")
        if self.state_root is not None and type(self.state_root) is not GitSha:
            raise TypeError("state_root has wrong exact type")


@dataclass(frozen=True, slots=True, init=False)
class ResolvedTargetRegistration:
    registration: AdmittedTargetRegistration
    target_registration_id: TargetRegistrationId
    root_config_id: ImmutableConfigId
    policy_epoch_identity: PolicyEpochIdentity

    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("resolved target registration must come from root/admin configuration")


@dataclass(frozen=True, slots=True)
class TaskOperationMembershipRecord:
    task_id: TaskId
    membership_revision: int
    membership_binding_id: OperationMembershipBindingId
    operation_ids: tuple[OperationId, ...]

    def __post_init__(self) -> None:
        if type(self.task_id) is not TaskId or type(self.membership_binding_id) is not OperationMembershipBindingId:
            raise TypeError("operation membership identity has wrong exact type")
        _positive(self.membership_revision, "operation membership revision")
        _exact_tuple(self.operation_ids, OperationId, "operation_ids")


@dataclass(frozen=True, slots=True)
class ReviewAttemptBindingRecord:
    effective_subject: SemanticReviewEffectiveSubject
    invocation_id: ReviewInvocationId
    slot_id: ReviewSlotId
    operation_id: OperationId
    canonical_request_id: CanonicalRequestId

    def __post_init__(self) -> None:
        exact = (
            (self.effective_subject, SemanticReviewEffectiveSubject),
            (self.invocation_id, ReviewInvocationId),
            (self.slot_id, ReviewSlotId),
            (self.operation_id, OperationId),
            (self.canonical_request_id, CanonicalRequestId),
        )
        if any(type(value) is not expected for value, expected in exact):
            raise TypeError("review-attempt binding has wrong exact type")


@dataclass(frozen=True, slots=True)
class EvidenceHistoryMembershipRecord:
    effective_subject: SemanticReviewEffectiveSubject
    membership_revision: int
    membership_binding_id: EvidenceHistoryMembershipBindingId
    evidence_ids: tuple[EvidenceId, ...]

    def __post_init__(self) -> None:
        if type(self.effective_subject) is not SemanticReviewEffectiveSubject or type(self.membership_binding_id) is not EvidenceHistoryMembershipBindingId:
            raise TypeError("evidence history identity has wrong exact type")
        _positive(self.membership_revision, "evidence membership revision")
        _exact_tuple(self.evidence_ids, EvidenceId, "evidence_ids")


@dataclass(frozen=True, slots=True)
class CanonicalTaskWorkingSet:
    canonical_state_occurrence_binding: CanonicalStateOccurrenceBinding
    authorization: AdmittedAuthorization
    task: TaskRecord
    candidate: CandidateRecord | None
    task_operation_membership: TaskOperationMembershipRecord
    operations: tuple[OperationRecord, ...]
    supporting_evidence: tuple[EvidenceRecord, ...]

    def task_operation_snapshot(self) -> TaskOperationSnapshot:
        return TaskOperationSnapshot(
            self.task.task_id,
            self.task_operation_membership.membership_binding_id,
            self.operations,
        )


@dataclass(frozen=True, slots=True)
class CanonicalReviewEligibilitySnapshot:
    canonical_state_occurrence_binding: CanonicalStateOccurrenceBinding
    effective_subject: SemanticReviewEffectiveSubject
    evidence_history_membership: EvidenceHistoryMembershipRecord
    canonical_evidence_records: tuple[EvidenceRecord, ...]
    task_operation_membership: TaskOperationMembershipRecord
    review_attempt_bindings: tuple[ReviewAttemptBindingRecord, ...]
    review_attempt_operations: tuple[OperationRecord, ...]

    def g5_evidence_snapshot(self) -> TrustedEffectiveSubjectEvidenceSnapshot:
        value = object.__new__(TrustedEffectiveSubjectEvidenceSnapshot)
        object.__setattr__(value, "canonical_state_occurrence_binding", self.canonical_state_occurrence_binding)
        object.__setattr__(value, "subject", self.effective_subject)
        object.__setattr__(value, "membership_binding", self.evidence_history_membership.membership_binding_id)
        bindings = tuple(
            AdmittedSemanticEvidenceBinding(
                record.evidence_id, record.payload.invocation_id, record.payload.slot_id, True
            )
            for record in self.canonical_evidence_records
        )
        object.__setattr__(value, "admitted_bindings", bindings)
        return value

    def g5_attempt_snapshot(self) -> TrustedReviewSlotAttemptSnapshot:
        value = object.__new__(TrustedReviewSlotAttemptSnapshot)
        object.__setattr__(value, "canonical_state_occurrence_binding", self.canonical_state_occurrence_binding)
        object.__setattr__(value, "subject", self.effective_subject)
        object.__setattr__(value, "operation_membership_binding_id", self.task_operation_membership.membership_binding_id)
        operations = {item.intent.operation_id: item for item in self.review_attempt_operations}
        attempts = tuple(
            ReviewSlotAttempt(
                binding.invocation_id,
                binding.slot_id,
                binding.operation_id,
                operations[binding.operation_id].state,
                binding.canonical_request_id,
            )
            for binding in self.review_attempt_bindings
        )
        object.__setattr__(value, "attempts", attempts)
        return value


class CanonicalNamespace(Enum):
    AUTHORIZATION = "authorizations"
    TASK = "tasks"
    CANDIDATE = "candidates"
    OPERATION = "operations"
    TASK_OPERATION_MEMBERSHIP = "task_operation_memberships"
    REVIEW_ATTEMPT_BINDING = "review_attempt_bindings"
    EVIDENCE = "evidence"
    EVIDENCE_HISTORY = "evidence_histories"
    SUPERSESSION = "supersessions"


class CanonicalWriteStatus(Enum):
    APPLIED = "APPLIED"
    CAS_CONFLICT = "CAS_CONFLICT"
    ALREADY_PRESENT = "ALREADY_PRESENT"
    NOT_FOUND = "NOT_FOUND"
    IDENTITY_CONFLICT = "IDENTITY_CONFLICT"
    INVALID_TRANSACTION = "INVALID_TRANSACTION"
    UNSUPPORTED = "UNSUPPORTED"
    INDETERMINATE = "INDETERMINATE"


class _ClosedBackendInput:
    def __post_init__(self) -> None:
        _validate_closed_backend_input(self)


@dataclass(frozen=True, slots=True)
class CanonicalWriteResult:
    status: CanonicalWriteStatus
    canonical_state_occurrence_binding: CanonicalStateOccurrenceBinding


@dataclass(frozen=True, slots=True)
class RecordAbsent(_ClosedBackendInput):
    namespace: CanonicalNamespace
    identity: object


@dataclass(frozen=True, slots=True)
class RecordPresent(_ClosedBackendInput):
    namespace: CanonicalNamespace
    identity: object


@dataclass(frozen=True, slots=True)
class ExactRecordEquals(_ClosedBackendInput):
    namespace: CanonicalNamespace
    identity: object
    record: object


@dataclass(frozen=True, slots=True)
class AuthorizationExistsAndMatches(_ClosedBackendInput):
    authorization: AdmittedAuthorization


@dataclass(frozen=True, slots=True)
class TaskRevisionEquals(_ClosedBackendInput):
    task_id: TaskId
    revision: int


@dataclass(frozen=True, slots=True)
class OperationRevisionEquals(_ClosedBackendInput):
    operation_id: OperationId
    revision: int


@dataclass(frozen=True, slots=True)
class TaskOperationMembershipEquals(_ClosedBackendInput):
    task_id: TaskId
    membership_binding_id: OperationMembershipBindingId


@dataclass(frozen=True, slots=True)
class EvidenceHistoryMembershipEquals(_ClosedBackendInput):
    subject_id: SemanticReviewEffectiveSubjectId
    membership_binding_id: EvidenceHistoryMembershipBindingId


@dataclass(frozen=True, slots=True)
class BackendGenerationEquals(_ClosedBackendInput):
    generation: BackendGeneration


@dataclass(frozen=True, slots=True)
class TaskCurrentCandidateEquals(_ClosedBackendInput):
    task_id: TaskId
    candidate_id: CandidateId | None


@dataclass(frozen=True, slots=True)
class TaskCancellationStatusEquals(_ClosedBackendInput):
    task_id: TaskId
    cancellation_status: CancellationStatus


@dataclass(frozen=True, slots=True)
class CanonicalStateRootEquals(_ClosedBackendInput):
    state_root: GitSha


CanonicalCondition: TypeAlias = (
    RecordAbsent | RecordPresent | ExactRecordEquals | AuthorizationExistsAndMatches
    | TaskRevisionEquals | OperationRevisionEquals | TaskOperationMembershipEquals
    | EvidenceHistoryMembershipEquals | BackendGenerationEquals
    | TaskCurrentCandidateEquals | TaskCancellationStatusEquals | CanonicalStateRootEquals
)


@dataclass(frozen=True, slots=True)
class CreateAuthorization(_ClosedBackendInput):
    authorization: AdmittedAuthorization


@dataclass(frozen=True, slots=True)
class CreateTaskAndInitialOperationMembership(_ClosedBackendInput):
    task: TaskRecord


@dataclass(frozen=True, slots=True)
class ReplaceTask(_ClosedBackendInput):
    expected_revision: int
    task: TaskRecord


@dataclass(frozen=True, slots=True)
class CreateCandidate(_ClosedBackendInput):
    candidate: CandidateRecord


@dataclass(frozen=True, slots=True)
class CreateOperationAndAdvanceMembership(_ClosedBackendInput):
    operation: OperationRecord
    expected_task_revision: int
    expected_membership_binding_id: OperationMembershipBindingId


@dataclass(frozen=True, slots=True)
class CreateSemanticReviewOperationAndBinding(_ClosedBackendInput):
    operation: OperationRecord
    binding: ReviewAttemptBindingRecord
    expected_task_revision: int
    expected_membership_binding_id: OperationMembershipBindingId


@dataclass(frozen=True, slots=True)
class ReplaceOperation(_ClosedBackendInput):
    expected_revision: int
    operation: OperationRecord


@dataclass(frozen=True, slots=True)
class ReplaceTaskOperationMembership(_ClosedBackendInput):
    task_id: TaskId
    expected_membership_binding_id: OperationMembershipBindingId
    operation_ids: tuple[OperationId, ...]

    def __post_init__(self) -> None:
        _validate_closed_backend_input(self)


@dataclass(frozen=True, slots=True)
class CreateEvidenceHistory(_ClosedBackendInput):
    effective_subject: SemanticReviewEffectiveSubject


@dataclass(frozen=True, slots=True)
class CreateEvidenceAndAdvanceHistory(_ClosedBackendInput):
    effective_subject: SemanticReviewEffectiveSubject
    expected_membership_binding_id: EvidenceHistoryMembershipBindingId
    evidence: EvidenceRecord


@dataclass(frozen=True, slots=True)
class CreateSupersession(_ClosedBackendInput):
    supersession: EvidenceSupersessionRecord


CanonicalMutation: TypeAlias = (
    CreateAuthorization | CreateTaskAndInitialOperationMembership | ReplaceTask
    | CreateCandidate | CreateOperationAndAdvanceMembership
    | CreateSemanticReviewOperationAndBinding | ReplaceOperation
    | ReplaceTaskOperationMembership | CreateEvidenceHistory
    | CreateEvidenceAndAdvanceHistory | CreateSupersession
)


@dataclass(frozen=True, slots=True)
class CanonicalTransaction:
    expected_state_occurrence: CanonicalStateOccurrenceBinding
    conditions: tuple[CanonicalCondition, ...]
    mutations: tuple[CanonicalMutation, ...]

    def __post_init__(self) -> None:
        _validate_closed_transaction(self)


_CONDITION_TYPES = (
    RecordAbsent, RecordPresent, ExactRecordEquals, AuthorizationExistsAndMatches,
    TaskRevisionEquals, OperationRevisionEquals, TaskOperationMembershipEquals,
    EvidenceHistoryMembershipEquals, BackendGenerationEquals, TaskCurrentCandidateEquals,
    TaskCancellationStatusEquals, CanonicalStateRootEquals,
)
_MUTATION_TYPES = (
    CreateAuthorization, CreateTaskAndInitialOperationMembership, ReplaceTask,
    CreateCandidate, CreateOperationAndAdvanceMembership,
    CreateSemanticReviewOperationAndBinding, ReplaceOperation,
    ReplaceTaskOperationMembership, CreateEvidenceHistory,
    CreateEvidenceAndAdvanceHistory, CreateSupersession,
)


_NAMESPACE_TYPES = {
    CanonicalNamespace.AUTHORIZATION: (AuthorizationId, AdmittedAuthorization),
    CanonicalNamespace.TASK: (TaskId, TaskRecord),
    CanonicalNamespace.CANDIDATE: (CandidateId, CandidateRecord),
    CanonicalNamespace.OPERATION: (OperationId, OperationRecord),
    CanonicalNamespace.TASK_OPERATION_MEMBERSHIP: (TaskId, TaskOperationMembershipRecord),
    CanonicalNamespace.REVIEW_ATTEMPT_BINDING: (OperationId, ReviewAttemptBindingRecord),
    CanonicalNamespace.EVIDENCE: (EvidenceId, EvidenceRecord),
    CanonicalNamespace.EVIDENCE_HISTORY: (SemanticReviewEffectiveSubjectId, EvidenceHistoryMembershipRecord),
    CanonicalNamespace.SUPERSESSION: (tuple[EvidenceId, EvidenceId], EvidenceSupersessionRecord),
}


def _runtime_exact(value: object, expected: object) -> None:
    decoded = _decode_canonical_value(_canonical_value(value), expected)
    if decoded != value:
        raise ValueError("runtime value does not equal its exact validated representation")


def _record_identity(namespace: CanonicalNamespace, record: object) -> object:
    if namespace is CanonicalNamespace.AUTHORIZATION:
        return record.authorization_id
    if namespace in (CanonicalNamespace.TASK, CanonicalNamespace.TASK_OPERATION_MEMBERSHIP):
        return record.task_id
    if namespace is CanonicalNamespace.CANDIDATE:
        return record.candidate_id
    if namespace is CanonicalNamespace.OPERATION:
        return record.intent.operation_id
    if namespace is CanonicalNamespace.REVIEW_ATTEMPT_BINDING:
        return record.operation_id
    if namespace is CanonicalNamespace.EVIDENCE:
        return record.evidence_id
    if namespace is CanonicalNamespace.EVIDENCE_HISTORY:
        return record.effective_subject.subject_id
    if namespace is CanonicalNamespace.SUPERSESSION:
        return record.earlier_evidence_id, record.later_evidence_id
    raise ValueError("unsupported canonical namespace")


def _validate_closed_backend_input(value: object) -> None:
    value_type = type(value)
    if value_type in (RecordAbsent, RecordPresent, ExactRecordEquals):
        if type(value.namespace) is not CanonicalNamespace:
            raise TypeError("namespace must be exactly CanonicalNamespace")
        identity_type, record_type = _NAMESPACE_TYPES[value.namespace]
        _runtime_exact(value.identity, identity_type)
        if value_type is ExactRecordEquals:
            _runtime_exact(value.record, record_type)
            if _record_identity(value.namespace, value.record) != value.identity:
                raise ValueError("record identity does not match condition identity")
        return
    if value_type not in (*_CONDITION_TYPES, *_MUTATION_TYPES):
        raise TypeError("value is outside the closed backend input domain")
    for name, annotation in _resolved_fields(value_type):
        _runtime_exact(getattr(value, name), annotation)
    for name in {
        TaskRevisionEquals: ("revision",),
        OperationRevisionEquals: ("revision",),
        ReplaceTask: ("expected_revision",),
        ReplaceOperation: ("expected_revision",),
        CreateOperationAndAdvanceMembership: ("expected_task_revision",),
        CreateSemanticReviewOperationAndBinding: ("expected_task_revision",),
    }.get(value_type, ()):
        _positive(getattr(value, name), name)


def _validate_closed_transaction(transaction: CanonicalTransaction) -> None:
    if type(transaction.expected_state_occurrence) is not CanonicalStateOccurrenceBinding:
        raise TypeError("expected_state_occurrence has wrong exact type")
    _runtime_exact(transaction.expected_state_occurrence, CanonicalStateOccurrenceBinding)
    if type(transaction.conditions) is not tuple or any(type(item) not in _CONDITION_TYPES for item in transaction.conditions):
        raise TypeError("conditions must contain only closed typed conditions")
    if type(transaction.mutations) is not tuple or any(type(item) not in _MUTATION_TYPES for item in transaction.mutations):
        raise TypeError("mutations must contain only closed typed mutations")
    for item in (*transaction.conditions, *transaction.mutations):
        _validate_closed_backend_input(item)


@dataclass(frozen=True, slots=True)
class _State:
    authorizations: dict
    tasks: dict
    candidates: dict
    operations: dict
    memberships: dict
    attempts: dict
    evidence: dict
    histories: dict
    supersessions: dict

    def clone(self) -> _State:
        return _State(*(dict(getattr(self, name)) for name in (
            "authorizations", "tasks", "candidates", "operations", "memberships",
            "attempts", "evidence", "histories", "supersessions",
        )))


def _freeze_state(state: _State) -> _State:
    return _State(*(MappingProxyType(dict(getattr(state, name))) for name in (
        "authorizations", "tasks", "candidates", "operations", "memberships",
        "attempts", "evidence", "histories", "supersessions",
    )))


def _membership_binding(task_id: TaskId, revision: int) -> OperationMembershipBindingId:
    raw = f"autodev.task-operation-membership/v1\n{task_id.value}\n{revision}".encode("utf-8")
    return OperationMembershipBindingId(hashlib.sha256(raw).hexdigest())


def _history_binding(subject_id: SemanticReviewEffectiveSubjectId, revision: int) -> EvidenceHistoryMembershipBindingId:
    raw = f"autodev.semantic-evidence-membership/v1\n{subject_id.value}\n{revision}".encode("utf-8")
    return EvidenceHistoryMembershipBindingId(hashlib.sha256(raw).hexdigest())


def _mutation_priority(mutation: CanonicalMutation) -> int:
    """Dependency order is fixed by mutation type, never caller source order."""
    return {
        CreateAuthorization: 0,
        CreateTaskAndInitialOperationMembership: 1,
        CreateCandidate: 2,
        CreateEvidenceHistory: 3,
        CreateOperationAndAdvanceMembership: 4,
        CreateSemanticReviewOperationAndBinding: 4,
        CreateEvidenceAndAdvanceHistory: 5,
        CreateSupersession: 6,
        ReplaceOperation: 7,
        ReplaceTaskOperationMembership: 8,
        ReplaceTask: 9,
    }[type(mutation)]


def _namespace_map(state: _State, namespace: CanonicalNamespace) -> dict:
    return {
        CanonicalNamespace.AUTHORIZATION: state.authorizations,
        CanonicalNamespace.TASK: state.tasks,
        CanonicalNamespace.CANDIDATE: state.candidates,
        CanonicalNamespace.OPERATION: state.operations,
        CanonicalNamespace.TASK_OPERATION_MEMBERSHIP: state.memberships,
        CanonicalNamespace.REVIEW_ATTEMPT_BINDING: state.attempts,
        CanonicalNamespace.EVIDENCE: state.evidence,
        CanonicalNamespace.EVIDENCE_HISTORY: state.histories,
        CanonicalNamespace.SUPERSESSION: state.supersessions,
    }[namespace]


def _supersession_key(value: EvidenceSupersessionRecord) -> tuple:
    return value.earlier_evidence_id, value.later_evidence_id


class InMemoryCanonicalStateBackend:
    """One-lock, no-retry, whole-graph validated reference backend."""

    __slots__ = ("_lock", "_generation", "_state", "_resolved_targets", "_sealed")

    def __init__(self, resolved_targets: tuple[ResolvedTargetRegistration, ...] = ()) -> None:
        if type(resolved_targets) is not tuple or any(type(item) is not ResolvedTargetRegistration for item in resolved_targets):
            raise TypeError("resolved_targets must be an exact trusted tuple")
        object.__setattr__(self, "_lock", RLock())
        object.__setattr__(self, "_generation", 1)
        object.__setattr__(self, "_state", _freeze_state(_State({}, {}, {}, {}, {}, {}, {}, {}, {})))
        object.__setattr__(self, "_resolved_targets", MappingProxyType({item.target_registration_id: item for item in resolved_targets}))
        if len(self._resolved_targets) != len(resolved_targets) or any(
            item.registration.target_registration_id != item.target_registration_id
            or item.registration.policy_epoch_identity != item.policy_epoch_identity
            for item in resolved_targets
        ):
            raise ValueError("resolved target registration binding mismatch")
        object.__setattr__(self, "_sealed", True)

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False):
            raise AttributeError("canonical backend internals are not caller-replaceable")
        object.__setattr__(self, name, value)

    @property
    def occurrence(self) -> CanonicalStateOccurrenceBinding:
        with self._lock:
            return CanonicalStateOccurrenceBinding(BackendGeneration(self._generation))

    def apply(self, transaction: CanonicalTransaction) -> CanonicalWriteResult:
        if type(transaction) is not CanonicalTransaction:
            raise TypeError("exact CanonicalTransaction required")
        with self._lock:
            occurrence = CanonicalStateOccurrenceBinding(BackendGeneration(self._generation))
            try:
                _validate_closed_transaction(transaction)
            except (AttributeError, KeyError, TypeError, ValueError):
                return CanonicalWriteResult(CanonicalWriteStatus.INVALID_TRANSACTION, occurrence)
            if transaction.expected_state_occurrence != occurrence:
                return CanonicalWriteResult(CanonicalWriteStatus.CAS_CONFLICT, occurrence)
            failed = self._check_conditions(transaction.conditions)
            if failed is not None:
                return CanonicalWriteResult(failed, occurrence)
            if any(
                type(mutation) is CreateSupersession
                and (
                    mutation.supersession.earlier_evidence_id not in self._state.evidence
                    or mutation.supersession.later_evidence_id not in self._state.evidence
                )
                for mutation in transaction.mutations
            ):
                return CanonicalWriteResult(CanonicalWriteStatus.INVALID_TRANSACTION, occurrence)
            membership_subjects = tuple(
                mutation.task_id if type(mutation) is ReplaceTaskOperationMembership else mutation.operation.intent.task_id
                for mutation in transaction.mutations
                if type(mutation) in (
                    CreateOperationAndAdvanceMembership,
                    CreateSemanticReviewOperationAndBinding,
                    ReplaceTaskOperationMembership,
                )
            )
            history_subjects = tuple(
                mutation.effective_subject.subject_id
                for mutation in transaction.mutations
                if type(mutation) is CreateEvidenceAndAdvanceHistory
            )
            if len(set(membership_subjects)) != len(membership_subjects) or len(set(history_subjects)) != len(history_subjects):
                return CanonicalWriteResult(CanonicalWriteStatus.INVALID_TRANSACTION, occurrence)
            candidate = self._state.clone()
            changed = False
            for mutation in sorted(transaction.mutations, key=_mutation_priority):
                status, mutation_changed = self._apply_mutation(candidate, mutation)
                if status is not None:
                    return CanonicalWriteResult(status, occurrence)
                changed = changed or mutation_changed
            if not changed:
                return CanonicalWriteResult(CanonicalWriteStatus.ALREADY_PRESENT, occurrence)
            if not self._valid_graph(candidate):
                return CanonicalWriteResult(CanonicalWriteStatus.INVALID_TRANSACTION, occurrence)
            object.__setattr__(self, "_state", _freeze_state(candidate))
            object.__setattr__(self, "_generation", self._generation + 1)
            return CanonicalWriteResult(
                CanonicalWriteStatus.APPLIED,
                CanonicalStateOccurrenceBinding(BackendGeneration(self._generation)),
            )

    def _check_conditions(self, conditions: tuple) -> CanonicalWriteStatus | None:
        for condition in conditions:
            if type(condition) is BackendGenerationEquals:
                if condition.generation.value != self._generation:
                    return CanonicalWriteStatus.CAS_CONFLICT
                continue
            if type(condition) is CanonicalStateRootEquals:
                return CanonicalWriteStatus.UNSUPPORTED
            if type(condition) in (TaskCurrentCandidateEquals, TaskCancellationStatusEquals):
                current = self._state.tasks.get(condition.task_id)
                if current is None:
                    return CanonicalWriteStatus.NOT_FOUND
                if type(condition) is TaskCurrentCandidateEquals and current.current_candidate_id != condition.candidate_id:
                    return CanonicalWriteStatus.CAS_CONFLICT
                if type(condition) is TaskCancellationStatusEquals and current.cancellation_status is not condition.cancellation_status:
                    return CanonicalWriteStatus.CAS_CONFLICT
                continue
            if type(condition) is AuthorizationExistsAndMatches:
                current = self._state.authorizations.get(condition.authorization.authorization_id)
                if current is None:
                    return CanonicalWriteStatus.NOT_FOUND
                if current != condition.authorization:
                    return CanonicalWriteStatus.IDENTITY_CONFLICT
                continue
            if type(condition) is TaskRevisionEquals:
                current = self._state.tasks.get(condition.task_id)
                if current is None:
                    return CanonicalWriteStatus.NOT_FOUND
                if current.revision != condition.revision:
                    return CanonicalWriteStatus.CAS_CONFLICT
                continue
            if type(condition) is OperationRevisionEquals:
                current = self._state.operations.get(condition.operation_id)
                if current is None:
                    return CanonicalWriteStatus.NOT_FOUND
                if current.revision != condition.revision:
                    return CanonicalWriteStatus.CAS_CONFLICT
                continue
            if type(condition) is TaskOperationMembershipEquals:
                current = self._state.memberships.get(condition.task_id)
                if current is None:
                    return CanonicalWriteStatus.NOT_FOUND
                if current.membership_binding_id != condition.membership_binding_id:
                    return CanonicalWriteStatus.CAS_CONFLICT
                continue
            if type(condition) is EvidenceHistoryMembershipEquals:
                current = self._state.histories.get(condition.subject_id)
                if current is None:
                    return CanonicalWriteStatus.NOT_FOUND
                if current.membership_binding_id != condition.membership_binding_id:
                    return CanonicalWriteStatus.CAS_CONFLICT
                continue
            records = _namespace_map(self._state, condition.namespace)
            current = records.get(condition.identity)
            if type(condition) is RecordAbsent and current is not None:
                return CanonicalWriteStatus.CAS_CONFLICT
            if type(condition) is RecordPresent and current is None:
                return CanonicalWriteStatus.NOT_FOUND
            if type(condition) is ExactRecordEquals:
                if current is None:
                    return CanonicalWriteStatus.NOT_FOUND
                if current != condition.record:
                    return CanonicalWriteStatus.CAS_CONFLICT
        return None

    def _apply_mutation(self, state: _State, mutation: CanonicalMutation) -> tuple[CanonicalWriteStatus | None, bool]:
        if type(mutation) is CreateAuthorization:
            value = mutation.authorization
            if type(value) is not AdmittedAuthorization:
                return CanonicalWriteStatus.INVALID_TRANSACTION, False
            current = state.authorizations.get(value.authorization_id)
            if current is not None:
                return (None, False) if current == value else (CanonicalWriteStatus.IDENTITY_CONFLICT, False)
            state.authorizations[value.authorization_id] = value
            return None, True
        if type(mutation) is CreateTaskAndInitialOperationMembership:
            task = mutation.task
            if type(task) is not TaskRecord or task.revision != 1 or task.state is not TaskState.ADMITTED:
                return CanonicalWriteStatus.INVALID_TRANSACTION, False
            if task.task_id in state.tasks or task.task_id in state.memberships:
                return CanonicalWriteStatus.IDENTITY_CONFLICT, False
            state.tasks[task.task_id] = task
            state.memberships[task.task_id] = TaskOperationMembershipRecord(
                task.task_id, 1, _membership_binding(task.task_id, 1), ()
            )
            return None, True
        if type(mutation) is ReplaceTask:
            task = mutation.task
            current = state.tasks.get(task.task_id)
            if current is None:
                return CanonicalWriteStatus.NOT_FOUND, False
            if current.revision != mutation.expected_revision:
                return CanonicalWriteStatus.CAS_CONFLICT, False
            if task.revision != current.revision + 1 or task.task_id != current.task_id:
                return CanonicalWriteStatus.INVALID_TRANSACTION, False
            state.tasks[task.task_id] = task
            return None, True
        if type(mutation) is CreateCandidate:
            candidate = mutation.candidate
            current = state.candidates.get(candidate.candidate_id)
            if current is not None:
                return (None, False) if current == candidate else (CanonicalWriteStatus.IDENTITY_CONFLICT, False)
            state.candidates[candidate.candidate_id] = candidate
            return None, True
        if type(mutation) in (CreateOperationAndAdvanceMembership, CreateSemanticReviewOperationAndBinding):
            operation = mutation.operation
            task = state.tasks.get(operation.intent.task_id)
            membership = state.memberships.get(operation.intent.task_id)
            if task is None or membership is None:
                return CanonicalWriteStatus.NOT_FOUND, False
            if task.revision != mutation.expected_task_revision or membership.membership_binding_id != mutation.expected_membership_binding_id:
                return CanonicalWriteStatus.CAS_CONFLICT, False
            if operation.intent.operation_id in state.operations:
                current = state.operations[operation.intent.operation_id]
                if current != operation or operation.intent.operation_id not in membership.operation_ids:
                    return CanonicalWriteStatus.IDENTITY_CONFLICT, False
                if type(mutation) is CreateSemanticReviewOperationAndBinding:
                    existing_binding = state.attempts.get(operation.intent.operation_id)
                    if existing_binding != mutation.binding:
                        return CanonicalWriteStatus.IDENTITY_CONFLICT, False
                return None, False
            if operation.revision != 1 or operation.state is not OperationState.RESERVED:
                return CanonicalWriteStatus.INVALID_TRANSACTION, False
            state.operations[operation.intent.operation_id] = operation
            revision = membership.membership_revision + 1
            state.memberships[task.task_id] = TaskOperationMembershipRecord(
                task.task_id, revision, _membership_binding(task.task_id, revision),
                (*membership.operation_ids, operation.intent.operation_id),
            )
            if type(mutation) is CreateSemanticReviewOperationAndBinding:
                binding = mutation.binding
                if binding.operation_id in state.attempts:
                    return CanonicalWriteStatus.IDENTITY_CONFLICT, False
                state.attempts[binding.operation_id] = binding
            return None, True
        if type(mutation) is ReplaceOperation:
            operation = mutation.operation
            current = state.operations.get(operation.intent.operation_id)
            if current is None:
                return CanonicalWriteStatus.NOT_FOUND, False
            if current.revision != mutation.expected_revision:
                return CanonicalWriteStatus.CAS_CONFLICT, False
            if operation.revision != current.revision + 1 or operation.intent != current.intent:
                return CanonicalWriteStatus.INVALID_TRANSACTION, False
            state.operations[operation.intent.operation_id] = operation
            return None, True
        if type(mutation) is ReplaceTaskOperationMembership:
            current = state.memberships.get(mutation.task_id)
            if current is None:
                return CanonicalWriteStatus.NOT_FOUND, False
            if current.membership_binding_id != mutation.expected_membership_binding_id:
                return CanonicalWriteStatus.CAS_CONFLICT, False
            if current.operation_ids == mutation.operation_ids:
                return None, False
            # The closed G6 mutation set has no operation deletion.  Membership
            # therefore advances only atomically with operation creation.
            return CanonicalWriteStatus.INVALID_TRANSACTION, False
        if type(mutation) is CreateEvidenceHistory:
            subject = mutation.effective_subject
            current = state.histories.get(subject.subject_id)
            if current is not None:
                return (None, False) if current.effective_subject == subject else (CanonicalWriteStatus.IDENTITY_CONFLICT, False)
            state.histories[subject.subject_id] = EvidenceHistoryMembershipRecord(
                subject, 1, _history_binding(subject.subject_id, 1), ()
            )
            return None, True
        if type(mutation) is CreateEvidenceAndAdvanceHistory:
            subject, evidence = mutation.effective_subject, mutation.evidence
            history = state.histories.get(subject.subject_id)
            if history is None:
                return CanonicalWriteStatus.NOT_FOUND, False
            if history.effective_subject != subject:
                return CanonicalWriteStatus.IDENTITY_CONFLICT, False
            if history.membership_binding_id != mutation.expected_membership_binding_id:
                return CanonicalWriteStatus.CAS_CONFLICT, False
            current = state.evidence.get(evidence.evidence_id)
            if current is not None:
                return (None, False) if current == evidence else (CanonicalWriteStatus.IDENTITY_CONFLICT, False)
            state.evidence[evidence.evidence_id] = evidence
            revision = history.membership_revision + 1
            state.histories[subject.subject_id] = EvidenceHistoryMembershipRecord(
                subject, revision, _history_binding(subject.subject_id, revision),
                (*history.evidence_ids, evidence.evidence_id),
            )
            return None, True
        if type(mutation) is CreateSupersession:
            value = mutation.supersession
            key = _supersession_key(value)
            current = state.supersessions.get(key)
            if current is not None:
                return (None, False) if current == value else (CanonicalWriteStatus.IDENTITY_CONFLICT, False)
            state.supersessions[key] = value
            return None, True
        return CanonicalWriteStatus.UNSUPPORTED, False

    def _valid_graph(self, state: _State) -> bool:
        # External target resolution is root/admin-governed, never caller inferred.
        for authorization in state.authorizations.values():
            resolved = self._resolved_targets.get(authorization.target_registration_id)
            if resolved is None or resolved.registration.target_registration_id != authorization.target_registration_id:
                return False
        for task_id, task in state.tasks.items():
            authorization = state.authorizations.get(task.authorization_id)
            membership = state.memberships.get(task_id)
            if authorization is None or membership is None:
                return False
            if (
                authorization.task_id != task.task_id
                or authorization.contract_id != task.contract_id
                or authorization.contract_raw_sha256 != task.contract_raw_sha256
                or authorization.target_registration_id != task.target_registration_id
                or membership.task_id != task.task_id
            ):
                return False
            same_task_operation_ids = {
                operation_id
                for operation_id, operation in state.operations.items()
                if operation.intent.task_id == task_id
            }
            if set(membership.operation_ids) != same_task_operation_ids:
                return False
            if task.current_candidate_id is not None:
                candidate = state.candidates.get(task.current_candidate_id)
                if candidate is None or not _candidate_matches_task(candidate, task):
                    return False
            if task.next_integration_operation_id is not None:
                operation = state.operations.get(task.next_integration_operation_id)
                if (
                    operation is None or operation.intent.task_id != task_id
                    or task.next_integration_operation_id not in membership.operation_ids
                    or type(operation.intent.integration_binding) is not IntegrationBound
                ):
                    return False
            repair_ids = (*task.repair_budget.reserved_operation_ids, *task.repair_budget.consumed_operation_ids, *task.repair_budget.released_operation_ids)
            if any(
                operation_id not in state.operations
                or state.operations[operation_id].intent.task_id != task_id
                or not state.operations[operation_id].intent.is_repair_attempt
                for operation_id in repair_ids
            ):
                return False
            for reference in task.supporting_evidence_refs:
                evidence = state.evidence.get(reference.evidence_id)
                if evidence is None or evidence.subject.task_id != task_id or evidence.subject.candidate_id != reference.candidate_id:
                    return False
        if set(state.memberships) != set(state.tasks):
            return False
        for candidate in state.candidates.values():
            task = state.tasks.get(candidate.task_id)
            if task is None or not _candidate_matches_task(candidate, task):
                return False
            if any(
                parent_id not in state.candidates
                or state.candidates[parent_id].task_id != candidate.task_id
                for parent_id in candidate.parent_candidate_ids
            ):
                return False
            if candidate.creation_operation_id is not None:
                operation = state.operations.get(candidate.creation_operation_id)
                if operation is None or operation.intent.task_id != candidate.task_id:
                    return False
        if _candidate_cycle(state.candidates):
            return False
        for operation in state.operations.values():
            task = state.tasks.get(operation.intent.task_id)
            if task is None or not _intent_matches_task(operation, task):
                return False
            for evidence_id in operation.intent.required_evidence_ids:
                evidence = state.evidence.get(evidence_id)
                if evidence is None or evidence.subject.task_id != task.task_id:
                    return False
                if operation.intent.candidate_id is not None and evidence.subject.candidate_id != operation.intent.candidate_id:
                    return False
        evidence_memberships: dict = {}
        for history in state.histories.values():
            for evidence_id in history.evidence_ids:
                if evidence_id in evidence_memberships:
                    return False
                evidence_memberships[evidence_id] = history.effective_subject.subject_id
        if set(evidence_memberships) != set(state.evidence):
            return False
        for evidence_id, evidence in state.evidence.items():
            task = state.tasks.get(evidence.subject.task_id)
            operation = state.operations.get(evidence.payload.operation_id)
            attempt = state.attempts.get(evidence.payload.operation_id)
            if (
                task is None or operation is None or attempt is None
                or evidence.subject.contract_id != task.contract_id
                or evidence.subject.contract_raw_sha256 != task.contract_raw_sha256
                or evidence.subject.authorization_id != task.authorization_id
                or evidence.subject.task_admission_event_id != task.admission_event_id
                or evidence.subject.target_registration_id != task.target_registration_id
                or operation.intent.task_id != task.task_id
                or attempt.effective_subject.subject_id != evidence.payload.effective_subject_id
                or attempt.invocation_id != evidence.payload.invocation_id
                or attempt.slot_id != evidence.payload.slot_id
                or attempt.canonical_request_id != evidence.payload.canonical_request_id
                or evidence_memberships[evidence_id] != evidence.payload.effective_subject_id
            ):
                return False
        for binding in state.attempts.values():
            operation = state.operations.get(binding.operation_id)
            membership = state.memberships.get(binding.effective_subject.task_id)
            if (
                operation is None or membership is None
                or binding.operation_id not in membership.operation_ids
                or not _review_binding_matches_operation(binding, operation)
            ):
                return False
        for history in state.histories.values():
            subject = history.effective_subject
            task = state.tasks.get(subject.task_id)
            candidate = state.candidates.get(subject.candidate_id)
            resolved = self._resolved_targets.get(subject.target_registration_id)
            if (
                task is None or candidate is None or resolved is None
                or not _candidate_matches_task(candidate, task)
                or subject.repository_id != resolved.registration.repository_id
                or subject.contract_id != task.contract_id
                or subject.contract_raw_sha256 != task.contract_raw_sha256
                or subject.authorization_id != task.authorization_id
                or subject.task_admission_event_id != task.admission_event_id
                or subject.target_registration_id != task.target_registration_id
            ):
                return False
            for evidence_id in history.evidence_ids:
                evidence = state.evidence.get(evidence_id)
                if evidence is None or not _evidence_matches_subject(evidence, history.effective_subject):
                    return False
        for relation in state.supersessions.values():
            earlier = state.evidence.get(relation.earlier_evidence_id)
            later = state.evidence.get(relation.later_evidence_id)
            if (
                earlier is None or later is None
                or earlier.payload.effective_subject_id != relation.subject_id
                or later.payload.effective_subject_id != relation.subject_id
            ):
                return False
        return True

    def read_task_working_set(self, task_id: TaskId) -> CanonicalTaskWorkingSet | None:
        if type(task_id) is not TaskId:
            raise TypeError("exact TaskId required")
        with self._lock:
            task = self._state.tasks.get(task_id)
            if task is None:
                return None
            membership = self._state.memberships[task_id]
            return CanonicalTaskWorkingSet(
                CanonicalStateOccurrenceBinding(BackendGeneration(self._generation)),
                self._state.authorizations[task.authorization_id],
                task,
                self._state.candidates.get(task.current_candidate_id),
                membership,
                tuple(self._state.operations[item] for item in membership.operation_ids),
                tuple(self._state.evidence[item.evidence_id] for item in task.supporting_evidence_refs),
            )

    def read_review_eligibility_snapshot(
        self, subject_id: SemanticReviewEffectiveSubjectId
    ) -> CanonicalReviewEligibilitySnapshot | None:
        if type(subject_id) is not SemanticReviewEffectiveSubjectId:
            raise TypeError("exact SemanticReviewEffectiveSubjectId required")
        with self._lock:
            history = self._state.histories.get(subject_id)
            if history is None:
                return None
            subject = history.effective_subject
            membership = self._state.memberships.get(subject.task_id)
            if membership is None:
                return None
            bindings = tuple(
                self._state.attempts[operation_id]
                for operation_id in membership.operation_ids
                if operation_id in self._state.attempts
                and self._state.attempts[operation_id].effective_subject == subject
            )
            return CanonicalReviewEligibilitySnapshot(
                CanonicalStateOccurrenceBinding(BackendGeneration(self._generation)),
                subject,
                history,
                tuple(self._state.evidence[item] for item in history.evidence_ids),
                membership,
                bindings,
                tuple(self._state.operations[item.operation_id] for item in bindings),
            )


def _candidate_matches_task(candidate: CandidateRecord, task: TaskRecord) -> bool:
    return (
        candidate.task_id == task.task_id
        and candidate.contract_id == task.contract_id
        and candidate.contract_raw_sha256 == task.contract_raw_sha256
        and candidate.authorization_id == task.authorization_id
        and candidate.admission_event_id == task.admission_event_id
        and candidate.target_registration_id == task.target_registration_id
    )


def _intent_matches_task(operation: OperationRecord, task: TaskRecord) -> bool:
    intent = operation.intent
    return (
        intent.task_id == task.task_id
        and intent.contract_id == task.contract_id
        and intent.contract_raw_sha256 == task.contract_raw_sha256
        and intent.authorization_id == task.authorization_id
        and intent.admission_event_id == task.admission_event_id
        and intent.target_registration_id == task.target_registration_id
    )


def _review_binding_matches_operation(binding: ReviewAttemptBindingRecord, operation: OperationRecord) -> bool:
    subject, intent = binding.effective_subject, operation.intent
    return (
        binding.operation_id == intent.operation_id
        and subject.task_id == intent.task_id
        and subject.candidate_id == intent.candidate_id
        and subject.contract_id == intent.contract_id
        and subject.contract_raw_sha256 == intent.contract_raw_sha256
        and subject.authorization_id == intent.authorization_id
        and subject.task_admission_event_id == intent.admission_event_id
        and subject.target_registration_id == intent.target_registration_id
        and subject.policy_epoch_identity == intent.policy_epoch_identity
    )


def _evidence_matches_subject(evidence: EvidenceRecord, subject: SemanticReviewEffectiveSubject) -> bool:
    current = evidence.subject
    return (
        evidence.payload.effective_subject_id == subject.subject_id
        and current.repository_id == subject.repository_id
        and current.task_id == subject.task_id
        and current.candidate_id == subject.candidate_id
        and current.contract_id == subject.contract_id
        and current.contract_raw_sha256 == subject.contract_raw_sha256
        and current.authorization_id == subject.authorization_id
        and current.task_admission_event_id == subject.task_admission_event_id
        and current.target_registration_id == subject.target_registration_id
        and current.policy_epoch_identity == subject.policy_epoch_identity
        and current.base == subject.base
        and current.target_context_id == subject.target_context_id
        and current.requirement_ids == subject.requirement_ids
        and current.required_material_ids == subject.required_material_ids
        and current.required_context_ids == subject.required_context_ids
    )


def _candidate_cycle(candidates: dict) -> bool:
    visiting: set = set()
    visited: set = set()

    def visit(candidate_id) -> bool:
        if candidate_id in visiting:
            return True
        if candidate_id in visited:
            return False
        visiting.add(candidate_id)
        for parent in candidates[candidate_id].parent_candidate_ids:
            if visit(parent):
                return True
        visiting.remove(candidate_id)
        visited.add(candidate_id)
        return False

    return any(visit(candidate_id) for candidate_id in candidates)


class CanonicalRecordKind(Enum):
    AUTHORIZATION = "authorization"
    TASK = "task"
    CANDIDATE = "candidate"
    OPERATION = "operation"
    TASK_OPERATION_MEMBERSHIP = "task_operation_membership"
    REVIEW_ATTEMPT_BINDING = "review_attempt_binding"
    EVIDENCE = "evidence"
    EVIDENCE_HISTORY = "evidence_history"
    SUPERSESSION = "supersession"


def _canonical_value(value):
    if is_dataclass(value):
        return {field.name: _canonical_value(getattr(value, field.name)) for field in fields(value)}
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, bytes):
        return {"bytes_hex": value.hex()}
    if isinstance(value, tuple):
        return [_canonical_value(item) for item in value]
    if isinstance(value, MappingProxyType):
        value = dict(value)
    if isinstance(value, dict):
        return {str(key): _canonical_value(value[key]) for key in sorted(value, key=str)}
    if value is None or type(value) in (str, int, bool):
        return value
    raise TypeError(f"unsupported canonical value type: {type(value).__name__}")


def canonical_json_bytes(value: object) -> bytes:
    payload = {"format": "autodev.canonical-json/v1", "value": _canonical_value(value)}
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def canonical_record_bytes(
    record_kind: CanonicalRecordKind, value: object, schema_version: str = "1"
) -> bytes:
    if type(record_kind) is not CanonicalRecordKind or schema_version != "1":
        raise ValueError("unsupported canonical record kind or schema")
    expected_type = _CANONICAL_RECORD_TYPES[record_kind]
    if type(value) is not expected_type:
        raise TypeError(f"{record_kind.value} requires exact {expected_type.__name__}")
    payload = {
        "format": "autodev.canonical-record/v1",
        "record": _canonical_value(value),
        "record_kind": record_kind.value,
        "schema_version": schema_version,
    }
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


_CANONICAL_RECORD_TYPES = {
    CanonicalRecordKind.AUTHORIZATION: AdmittedAuthorization,
    CanonicalRecordKind.TASK: TaskRecord,
    CanonicalRecordKind.CANDIDATE: CandidateRecord,
    CanonicalRecordKind.OPERATION: OperationRecord,
    CanonicalRecordKind.TASK_OPERATION_MEMBERSHIP: TaskOperationMembershipRecord,
    CanonicalRecordKind.REVIEW_ATTEMPT_BINDING: ReviewAttemptBindingRecord,
    CanonicalRecordKind.EVIDENCE: EvidenceRecord,
    CanonicalRecordKind.EVIDENCE_HISTORY: EvidenceHistoryMembershipRecord,
    CanonicalRecordKind.SUPERSESSION: EvidenceSupersessionRecord,
}


@lru_cache(maxsize=None)
def _resolved_fields(record_type: type) -> tuple[tuple[str, object], ...]:
    hints = get_type_hints(record_type)
    return tuple((field.name, hints[field.name]) for field in fields(record_type))


def _bare_tuple_item_type(owner: type, field_name: str) -> type | None:
    return {
        (EvidenceSubject, "required_material_ids"): MaterialIdentity,
        (EvidenceSubject, "required_context_ids"): TrustedContextId,
        (SemanticEvidencePayload, "requirement_results"): RequirementResult,
    }.get((owner, field_name))


def _decode_canonical_value(value: object, expected: object, *, owner: type | None = None, field_name: str = "") -> object:
    if expected is type(None):
        if value is not None:
            raise TypeError("expected null")
        return None
    origin = get_origin(expected)
    if origin in (UnionType, Union):
        alternatives = get_args(expected)
        for alternative in alternatives:
            try:
                return _decode_canonical_value(value, alternative, owner=owner, field_name=field_name)
            except (AttributeError, KeyError, TypeError, ValueError):
                pass
        raise TypeError("value does not match closed union")
    if origin is tuple or expected is tuple:
        if type(value) is not list:
            raise TypeError("canonical tuple must be encoded as an array")
        arguments = get_args(expected)
        if not arguments:
            item_type = _bare_tuple_item_type(owner, field_name)
            if item_type is None:
                raise TypeError("untyped tuple is not in the closed canonical schema")
            arguments = (item_type, Ellipsis)
        if len(arguments) == 2 and arguments[1] is Ellipsis:
            return tuple(_decode_canonical_value(item, arguments[0]) for item in value)
        if len(value) != len(arguments):
            raise TypeError("canonical fixed tuple has wrong length")
        return tuple(_decode_canonical_value(item, item_type) for item, item_type in zip(value, arguments))
    if expected in (str, int, bool):
        if type(value) is not expected:
            raise TypeError("canonical scalar has wrong exact type")
        return value
    if expected is bytes:
        if type(value) is not dict or set(value) != {"bytes_hex"} or type(value["bytes_hex"]) is not str:
            raise TypeError("canonical bytes have wrong shape")
        decoded = bytes.fromhex(value["bytes_hex"])
        if decoded.hex() != value["bytes_hex"]:
            raise ValueError("canonical bytes are not normalized")
        return decoded
    if isinstance(expected, type) and issubclass(expected, Enum):
        if not any(type(value) is type(member.value) and value == member.value for member in expected):
            raise ValueError("canonical enum value is outside the closed domain")
        return expected(value)
    if isinstance(expected, type) and is_dataclass(expected):
        if type(value) is not dict:
            raise TypeError("canonical nominal record must be an object")
        expected_fields = _resolved_fields(expected)
        if set(value) != {name for name, _ in expected_fields}:
            raise ValueError("canonical nominal record field set mismatch")
        decoded_fields = {
            name: _decode_canonical_value(value[name], annotation, owner=expected, field_name=name)
            for name, annotation in expected_fields
        }
        decoded = object.__new__(expected)
        for name, item in decoded_fields.items():
            object.__setattr__(decoded, name, item)
        post_init = expected.__dict__.get("__post_init__")
        if post_init is not None:
            post_init(decoded)
        return decoded
    raise TypeError("type is not part of the closed canonical schema")


def _identity_parts(record_kind: CanonicalRecordKind, record: object) -> tuple[str, ...]:
    if record_kind is CanonicalRecordKind.AUTHORIZATION:
        return (record.authorization_id.raw_sha256.value,)
    if record_kind is CanonicalRecordKind.TASK:
        return (record.task_id.value,)
    if record_kind is CanonicalRecordKind.CANDIDATE:
        return (record.candidate_id.value,)
    if record_kind is CanonicalRecordKind.OPERATION:
        return (record.intent.operation_id.value,)
    if record_kind is CanonicalRecordKind.TASK_OPERATION_MEMBERSHIP:
        return (record.task_id.value,)
    if record_kind is CanonicalRecordKind.REVIEW_ATTEMPT_BINDING:
        return (record.operation_id.value,)
    if record_kind is CanonicalRecordKind.EVIDENCE:
        return (record.evidence_id.value,)
    if record_kind is CanonicalRecordKind.EVIDENCE_HISTORY:
        return (record.effective_subject.subject_id.value,)
    if record_kind is CanonicalRecordKind.SUPERSESSION:
        return (record.earlier_evidence_id.value, record.later_evidence_id.value)
    raise ValueError("unsupported canonical record kind")


def _logical_identity(record_kind: CanonicalRecordKind, record: object, schema_version: str) -> str:
    if schema_version != "1":
        raise ValueError("unsupported canonical record schema")
    payload = ("autodev.canonical-identity/v1", record_kind.value, *_identity_parts(record_kind, record))
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


def canonical_logical_identity(
    record_kind: CanonicalRecordKind, value: object, schema_version: str = "1"
) -> str:
    if type(record_kind) is not CanonicalRecordKind:
        raise TypeError("exact CanonicalRecordKind required")
    canonical_record_bytes(record_kind, value, schema_version)
    return _logical_identity(record_kind, value, schema_version)


@dataclass(frozen=True, slots=True)
class CanonicalObjectRef:
    record_kind: CanonicalRecordKind
    schema_version: str
    object_digest: RawSha256

    def __post_init__(self) -> None:
        if type(self.record_kind) is not CanonicalRecordKind or type(self.schema_version) is not str or not self.schema_version:
            raise TypeError("canonical object reference has wrong exact type")
        if type(self.object_digest) is not RawSha256:
            raise TypeError("object_digest must be exactly RawSha256")


def canonical_object_ref(record_kind: CanonicalRecordKind, value: object, schema_version: str = "1") -> CanonicalObjectRef:
    return CanonicalObjectRef(
        record_kind,
        schema_version,
        RawSha256(hashlib.sha256(canonical_record_bytes(record_kind, value, schema_version)).hexdigest()),
    )


@dataclass(frozen=True, slots=True)
class CanonicalIndexEntry:
    logical_identity: str
    object_ref: CanonicalObjectRef

    def __post_init__(self) -> None:
        if type(self.logical_identity) is not str or not self.logical_identity or type(self.object_ref) is not CanonicalObjectRef:
            raise TypeError("canonical index entry has wrong exact type")


def _index(values: object, kind: CanonicalRecordKind, name: str) -> tuple:
    _exact_tuple(values, CanonicalIndexEntry, name)
    keys = tuple(item.logical_identity for item in values)
    if keys != tuple(sorted(keys)) or len(set(keys)) != len(keys):
        raise ValueError(f"{name} must be unique and canonically ordered")
    if any(item.object_ref.record_kind is not kind for item in values):
        raise ValueError(f"{name} contains wrong record kind")
    return values


@dataclass(frozen=True, slots=True)
class CanonicalStateRootManifest:
    format_version: str
    predecessor_state_root: GitSha | None
    authorization_index: tuple[CanonicalIndexEntry, ...]
    task_index: tuple[CanonicalIndexEntry, ...]
    candidate_index: tuple[CanonicalIndexEntry, ...]
    operation_index: tuple[CanonicalIndexEntry, ...]
    task_operation_membership_index: tuple[CanonicalIndexEntry, ...]
    review_attempt_binding_index: tuple[CanonicalIndexEntry, ...]
    evidence_index: tuple[CanonicalIndexEntry, ...]
    evidence_history_index: tuple[CanonicalIndexEntry, ...]
    supersession_index: tuple[CanonicalIndexEntry, ...]

    def __post_init__(self) -> None:
        if self.format_version != "1":
            raise ValueError("unsupported canonical root format")
        if self.predecessor_state_root is not None and type(self.predecessor_state_root) is not GitSha:
            raise TypeError("predecessor_state_root has wrong exact type")
        for values, kind, name in (
            (self.authorization_index, CanonicalRecordKind.AUTHORIZATION, "authorization_index"),
            (self.task_index, CanonicalRecordKind.TASK, "task_index"),
            (self.candidate_index, CanonicalRecordKind.CANDIDATE, "candidate_index"),
            (self.operation_index, CanonicalRecordKind.OPERATION, "operation_index"),
            (self.task_operation_membership_index, CanonicalRecordKind.TASK_OPERATION_MEMBERSHIP, "task_operation_membership_index"),
            (self.review_attempt_binding_index, CanonicalRecordKind.REVIEW_ATTEMPT_BINDING, "review_attempt_binding_index"),
            (self.evidence_index, CanonicalRecordKind.EVIDENCE, "evidence_index"),
            (self.evidence_history_index, CanonicalRecordKind.EVIDENCE_HISTORY, "evidence_history_index"),
            (self.supersession_index, CanonicalRecordKind.SUPERSESSION, "supersession_index"),
        ):
            _index(values, kind, name)

    @property
    def indexes(self) -> tuple[tuple[CanonicalIndexEntry, ...], ...]:
        return tuple(getattr(self, name) for name in (
            "authorization_index", "task_index", "candidate_index", "operation_index",
            "task_operation_membership_index", "review_attempt_binding_index",
            "evidence_index", "evidence_history_index", "supersession_index",
        ))


@dataclass(frozen=True, slots=True)
class CanonicalStoredObject:
    object_ref: CanonicalObjectRef
    canonical_bytes: bytes

    def __post_init__(self) -> None:
        if type(self.object_ref) is not CanonicalObjectRef or type(self.canonical_bytes) is not bytes:
            raise TypeError("stored canonical object has wrong exact type")


def validate_canonical_root(
    manifest: CanonicalStateRootManifest,
    objects: tuple[CanonicalStoredObject, ...],
    resolved_targets: tuple[ResolvedTargetRegistration, ...] = (),
) -> bool:
    decoded = _decode_canonical_root_objects(manifest, objects)
    if decoded is None:
        return False
    try:
        validator = InMemoryCanonicalStateBackend(resolved_targets)
        state = _State(
            {record.authorization_id: record for record in decoded[CanonicalRecordKind.AUTHORIZATION]},
            {record.task_id: record for record in decoded[CanonicalRecordKind.TASK]},
            {record.candidate_id: record for record in decoded[CanonicalRecordKind.CANDIDATE]},
            {record.intent.operation_id: record for record in decoded[CanonicalRecordKind.OPERATION]},
            {record.task_id: record for record in decoded[CanonicalRecordKind.TASK_OPERATION_MEMBERSHIP]},
            {record.operation_id: record for record in decoded[CanonicalRecordKind.REVIEW_ATTEMPT_BINDING]},
            {record.evidence_id: record for record in decoded[CanonicalRecordKind.EVIDENCE]},
            {record.effective_subject.subject_id: record for record in decoded[CanonicalRecordKind.EVIDENCE_HISTORY]},
            {_supersession_key(record): record for record in decoded[CanonicalRecordKind.SUPERSESSION]},
        )
        if any(len(namespace) != len(decoded[kind]) for namespace, kind in zip(
            (
                state.authorizations, state.tasks, state.candidates, state.operations,
                state.memberships, state.attempts, state.evidence, state.histories,
                state.supersessions,
            ),
            CanonicalRecordKind,
        )):
            return False
        return validator._valid_graph(state)
    except (AttributeError, KeyError, TypeError, ValueError):
        return False


def validate_canonical_root_object_integrity(
    manifest: CanonicalStateRootManifest,
    objects: tuple[CanonicalStoredObject, ...],
) -> bool:
    """Validate claimed object bytes only; this is not canonical-root proof."""
    return _decode_canonical_root_objects(manifest, objects) is not None


def _decode_canonical_root_objects(
    manifest: CanonicalStateRootManifest,
    objects: tuple[CanonicalStoredObject, ...],
) -> dict[CanonicalRecordKind, tuple[object, ...]] | None:
    if type(manifest) is not CanonicalStateRootManifest:
        raise TypeError("exact CanonicalStateRootManifest required")
    _exact_tuple(objects, CanonicalStoredObject, "objects", unique=False)
    by_ref = {item.object_ref: item for item in objects}
    if len(by_ref) != len(objects):
        return None
    claimed = tuple(entry.object_ref for index in manifest.indexes for entry in index)
    if len(set(claimed)) != len(claimed):
        return None
    decoded_by_kind: dict[CanonicalRecordKind, list[object]] = {
        kind: [] for kind in CanonicalRecordKind
    }
    for entry in (entry for index in manifest.indexes for entry in index):
        reference = entry.object_ref
        stored = by_ref.get(reference)
        if stored is None:
            return None
        decoded = _decode_canonical_record(stored.canonical_bytes)
        if decoded is None:
            return None
        record_kind, schema_version, record = decoded
        if record_kind is not reference.record_kind or schema_version != reference.schema_version:
            return None
        try:
            if entry.logical_identity != _logical_identity(record_kind, record, schema_version):
                return None
        except (KeyError, TypeError, ValueError):
            return None
        digest = RawSha256(hashlib.sha256(stored.canonical_bytes).hexdigest())
        if digest != reference.object_digest:
            return None
        decoded_by_kind[record_kind].append(record)
    return {kind: tuple(records) for kind, records in decoded_by_kind.items()}


def _decode_canonical_record(raw: bytes) -> tuple[CanonicalRecordKind, str, object] | None:
    try:
        text = raw.decode("utf-8", errors="strict")

        def pairs(values):
            result = {}
            for key, value in values:
                if key in result:
                    raise ValueError("duplicate key")
                result[key] = value
            return result

        value = json.loads(text, object_pairs_hook=pairs)
        if (
            type(value) is not dict
            or set(value) != {"format", "record", "record_kind", "schema_version"}
            or value["format"] != "autodev.canonical-record/v1"
            or type(value["record"]) is not dict
            or value["schema_version"] != "1"
        ):
            return None
        if json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8") != raw:
            return None
        record_kind = CanonicalRecordKind(value["record_kind"])
        record = _decode_canonical_value(value["record"], _CANONICAL_RECORD_TYPES[record_kind])
        if canonical_record_bytes(record_kind, record, value["schema_version"]) != raw:
            return None
        return record_kind, value["schema_version"], record
    except (AttributeError, KeyError, UnicodeDecodeError, ValueError, TypeError, json.JSONDecodeError):
        return None


@dataclass(frozen=True, slots=True)
class CanonicalStateCommit:
    state_root: GitSha
    manifest: CanonicalStateRootManifest
    parents: tuple[GitSha, ...]

    def __post_init__(self) -> None:
        if type(self.state_root) is not GitSha or type(self.manifest) is not CanonicalStateRootManifest:
            raise TypeError("canonical commit field has wrong exact type")
        _exact_tuple(self.parents, GitSha, "parents")


def validate_canonical_state_commit(commit: CanonicalStateCommit, expected_prior: GitSha | None) -> bool:
    if type(commit) is not CanonicalStateCommit:
        raise TypeError("exact CanonicalStateCommit required")
    if expected_prior is None:
        return commit.manifest.predecessor_state_root is None and commit.parents == ()
    return (
        type(expected_prior) is GitSha
        and commit.parents == (expected_prior,)
        and commit.manifest.predecessor_state_root == expected_prior
    )


@dataclass(frozen=True, slots=True)
class CanonicalRefUpdateCapability:
    platform_enforced_expected_old_head: bool

    def __post_init__(self) -> None:
        if type(self.platform_enforced_expected_old_head) is not bool:
            raise TypeError("platform CAS capability must be exactly bool")


def evaluate_canonical_ref_update_support(capability: CanonicalRefUpdateCapability) -> CanonicalWriteStatus:
    if type(capability) is not CanonicalRefUpdateCapability:
        raise TypeError("exact CanonicalRefUpdateCapability required")
    return CanonicalWriteStatus.APPLIED if capability.platform_enforced_expected_old_head else CanonicalWriteStatus.UNSUPPORTED


def reconcile_ambiguous_canonical_write(
    *, attempted: CanonicalStateCommit, expected_prior: GitSha,
    current_root: GitSha | None, canonical_history: tuple[CanonicalStateCommit, ...] | None,
) -> CanonicalWriteStatus:
    if not validate_canonical_state_commit(attempted, expected_prior):
        return CanonicalWriteStatus.INDETERMINATE
    if current_root == attempted.state_root:
        return CanonicalWriteStatus.APPLIED
    if canonical_history is None or current_root is None or type(canonical_history) is not tuple:
        return CanonicalWriteStatus.INDETERMINATE
    commits = {item.state_root: item for item in canonical_history if type(item) is CanonicalStateCommit}
    if len(commits) != len(canonical_history) or current_root not in commits:
        return CanonicalWriteStatus.INDETERMINATE
    cursor = current_root
    seen: set[GitSha] = set()
    while cursor in commits and cursor not in seen:
        if cursor == attempted.state_root:
            return CanonicalWriteStatus.APPLIED
        seen.add(cursor)
        commit = commits[cursor]
        if len(commit.parents) != 1 or commit.manifest.predecessor_state_root != commit.parents[0]:
            return CanonicalWriteStatus.INDETERMINATE
        cursor = commit.parents[0]
    if cursor != expected_prior:
        return CanonicalWriteStatus.INDETERMINATE
    # Ordinary commit ancestry cannot prove that an attempted root was never
    # canonical before a ref rewrite.  Without a trusted complete transition
    # proof the only safe result is indeterminate.
    return CanonicalWriteStatus.INDETERMINATE
