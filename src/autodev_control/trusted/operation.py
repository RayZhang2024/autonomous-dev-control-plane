"""Immutable protected-operation intent and lifecycle primitives for G4.

These values are candidate trusted source only.  They neither persist state nor
grant permission to perform an external effect.
"""

from dataclasses import dataclass
from enum import Enum

from .errors import G4Failure, G4FailureCode
from .identity import GitRef, RawSha256
from .manifest import PolicyEpochIdentity
from .scope import AuthorizationId, ContractId, TargetRegistrationId, TaskId


def _logical(value: object) -> None:
    from .identity import LogicalIdentifier

    LogicalIdentifier(value)


@dataclass(frozen=True, slots=True)
class CandidateId:
    value: str

    def __post_init__(self) -> None:
        _logical(self.value)


@dataclass(frozen=True, slots=True)
class EvidenceId:
    value: str

    def __post_init__(self) -> None:
        _logical(self.value)


@dataclass(frozen=True, slots=True)
class OperationId:
    value: str

    def __post_init__(self) -> None:
        _logical(self.value)


@dataclass(frozen=True, slots=True)
class OperationIdempotencyKey:
    value: str

    def __post_init__(self) -> None:
        _logical(self.value)


@dataclass(frozen=True, slots=True)
class OperationMembershipBindingId:
    value: str

    def __post_init__(self) -> None:
        _logical(self.value)


@dataclass(frozen=True, slots=True)
class AuthoritativeStateBindingId:
    value: str

    def __post_init__(self) -> None:
        _logical(self.value)


@dataclass(frozen=True, slots=True)
class AdmissionEventId:
    value: str

    def __post_init__(self) -> None:
        _logical(self.value)


@dataclass(frozen=True, slots=True)
class CompletionRuleSetId:
    value: str

    def __post_init__(self) -> None:
        _logical(self.value)


@dataclass(frozen=True, slots=True)
class CancellationRequestId:
    value: str

    def __post_init__(self) -> None:
        _logical(self.value)


@dataclass(frozen=True, slots=True)
class OperationActionId:
    value: str

    def __post_init__(self) -> None:
        _logical(self.value)


@dataclass(frozen=True, slots=True)
class OperationSubjectId:
    value: str

    def __post_init__(self) -> None:
        _logical(self.value)


@dataclass(frozen=True, slots=True)
class BlockingConditionId:
    value: str

    def __post_init__(self) -> None:
        _logical(self.value)


@dataclass(frozen=True, slots=True)
class AwaitingInputRequirementId:
    value: str

    def __post_init__(self) -> None:
        _logical(self.value)


@dataclass(frozen=True, slots=True)
class DecisionEventId:
    value: str

    def __post_init__(self) -> None:
        _logical(self.value)


OperationRevision = int


def _revision(value: object, name: str = "revision") -> int:
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


class OperationState(Enum):
    RESERVED = "reserved"
    PERFORMING = "performing"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CONFLICT = "conflict"
    INDETERMINATE = "indeterminate"


class OperationEffectClass(Enum):
    NON_PROTECTED_EFFECT = "NON_PROTECTED_EFFECT"
    PROTECTED_OR_AUTHORITATIVE_EFFECT = "PROTECTED_OR_AUTHORITATIVE_EFFECT"


class OperationPurpose(Enum):
    NORMAL = "NORMAL"
    SAFETY_RECONCILIATION = "SAFETY_RECONCILIATION"


class ReconciliationFinding(Enum):
    INTENDED_EFFECT_PROVEN = "INTENDED_EFFECT_PROVEN"
    INTENDED_EFFECT_PROVEN_ABSENT = "INTENDED_EFFECT_PROVEN_ABSENT"
    UNRESOLVED = "UNRESOLVED"


@dataclass(frozen=True, slots=True, init=False)
class TrustedReconciliationFinding:
    finding: ReconciliationFinding

    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("finding must come from a trusted reconciliation boundary")


@dataclass(frozen=True, slots=True)
class IntegrationBound:
    integration_ref: GitRef

    def __post_init__(self) -> None:
        if type(self.integration_ref) is not GitRef:
            raise TypeError("integration_ref must be exactly GitRef")


@dataclass(frozen=True, slots=True)
class NotIntegrationBound:
    pass


IntegrationBinding = IntegrationBound | NotIntegrationBound


@dataclass(frozen=True, slots=True, init=False)
class TrustedOperationClassification:
    effect_class: OperationEffectClass
    purpose: OperationPurpose

    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("classification must come from a trusted boundary")


@dataclass(frozen=True, slots=True, init=False)
class OperationIntent:
    operation_id: OperationId
    idempotency_key: OperationIdempotencyKey
    task_id: TaskId
    action_id: OperationActionId
    subject_id: OperationSubjectId
    effect_class: OperationEffectClass
    purpose: OperationPurpose
    candidate_id: CandidateId | None
    contract_id: ContractId
    contract_raw_sha256: RawSha256
    authorization_id: AuthorizationId
    admission_event_id: AdmissionEventId
    target_registration_id: TargetRegistrationId
    policy_epoch_identity: PolicyEpochIdentity
    authoritative_state_binding_id: AuthoritativeStateBindingId
    required_evidence_ids: tuple[EvidenceId, ...]
    integration_binding: IntegrationBinding
    is_repair_attempt: bool

    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("operation intent must come from a trusted classification boundary")


def construct_trusted_operation_intent(
    *,
    classification: TrustedOperationClassification,
    operation_id: OperationId,
    idempotency_key: OperationIdempotencyKey,
    task_id: TaskId,
    action_id: OperationActionId,
    subject_id: OperationSubjectId,
    candidate_id: CandidateId | None,
    contract_id: ContractId,
    contract_raw_sha256: RawSha256,
    authorization_id: AuthorizationId,
    admission_event_id: AdmissionEventId,
    target_registration_id: TargetRegistrationId,
    policy_epoch_identity: PolicyEpochIdentity,
    authoritative_state_binding_id: AuthoritativeStateBindingId,
    required_evidence_ids: tuple[EvidenceId, ...],
    integration_binding: IntegrationBinding,
    is_repair_attempt: bool = False,
) -> OperationIntent:
    """Consume trusted classification; construction itself grants no authority."""
    exact = (
        (classification, TrustedOperationClassification),
        (operation_id, OperationId),
        (idempotency_key, OperationIdempotencyKey),
        (task_id, TaskId),
        (action_id, OperationActionId),
        (subject_id, OperationSubjectId),
        (contract_id, ContractId),
        (contract_raw_sha256, RawSha256),
        (authorization_id, AuthorizationId),
        (admission_event_id, AdmissionEventId),
        (target_registration_id, TargetRegistrationId),
        (policy_epoch_identity, PolicyEpochIdentity),
        (authoritative_state_binding_id, AuthoritativeStateBindingId),
    )
    if any(type(value) is not expected for value, expected in exact):
        raise TypeError("operation intent identity has wrong exact type")
    if candidate_id is not None and type(candidate_id) is not CandidateId:
        raise TypeError("candidate_id has wrong exact type")
    _unique_exact(required_evidence_ids, EvidenceId, "required_evidence_ids")
    if type(integration_binding) not in (IntegrationBound, NotIntegrationBound):
        raise TypeError("integration binding has wrong exact variant")
    if type(is_repair_attempt) is not bool:
        raise TypeError("is_repair_attempt must be exactly bool")
    result = object.__new__(OperationIntent)
    fields = {
        "operation_id": operation_id,
        "idempotency_key": idempotency_key,
        "task_id": task_id,
        "action_id": action_id,
        "subject_id": subject_id,
        "effect_class": classification.effect_class,
        "purpose": classification.purpose,
        "candidate_id": candidate_id,
        "contract_id": contract_id,
        "contract_raw_sha256": contract_raw_sha256,
        "authorization_id": authorization_id,
        "admission_event_id": admission_event_id,
        "target_registration_id": target_registration_id,
        "policy_epoch_identity": policy_epoch_identity,
        "authoritative_state_binding_id": authoritative_state_binding_id,
        "required_evidence_ids": required_evidence_ids,
        "integration_binding": integration_binding,
        "is_repair_attempt": is_repair_attempt,
    }
    for name, value in fields.items():
        object.__setattr__(result, name, value)
    return result


@dataclass(frozen=True, slots=True)
class OperationRecord:
    intent: OperationIntent
    revision: OperationRevision
    state: OperationState
    reason_code: G4FailureCode | None = None

    def __post_init__(self) -> None:
        if type(self.intent) is not OperationIntent:
            raise TypeError("intent must be exactly OperationIntent")
        _revision(self.revision, "operation revision")
        if type(self.state) is not OperationState:
            raise TypeError("state must be exactly OperationState")
        if self.reason_code is not None and type(self.reason_code) is not G4FailureCode:
            raise TypeError("reason_code must be exact G4FailureCode or None")


@dataclass(frozen=True, slots=True)
class OperationReservationResult:
    operation: OperationRecord | None = None
    replayed: bool = False
    failure: G4Failure | None = None

    def __post_init__(self) -> None:
        if (self.operation is None) == (self.failure is None):
            raise ValueError("result must contain exactly operation or failure")
        if type(self.replayed) is not bool:
            raise TypeError("replayed must be exactly bool")


@dataclass(frozen=True, slots=True)
class OperationRevisionProposal:
    expected_revision: OperationRevision
    proposed: OperationRecord

    def __post_init__(self) -> None:
        _revision(self.expected_revision, "expected operation revision")
        if type(self.proposed) is not OperationRecord:
            raise TypeError("proposed must be exactly OperationRecord")
        if self.proposed.revision != self.expected_revision + 1:
            raise ValueError("proposed operation revision must increment exactly once")


@dataclass(frozen=True, slots=True)
class OperationRevisionResult:
    proposal: OperationRevisionProposal | None = None
    failure: G4Failure | None = None

    def __post_init__(self) -> None:
        if (self.proposal is None) == (self.failure is None):
            raise ValueError("result must contain exactly proposal or failure")

    @property
    def operation(self) -> OperationRecord | None:
        return None if self.proposal is None else self.proposal.proposed


def reserve_operation(
    intent: OperationIntent,
    existing_operations: tuple[OperationRecord, ...],
) -> OperationReservationResult:
    """Create RESERVED@1 or return the exact task-scoped idempotent replay."""
    if type(intent) is not OperationIntent:
        raise TypeError("intent must be exactly OperationIntent")
    _unique_exact(existing_operations, OperationRecord, "existing_operations")
    by_id: dict[OperationId, OperationRecord] = {}
    by_key: dict[tuple[TaskId, OperationIdempotencyKey], OperationRecord] = {}
    for record in existing_operations:
        prior_id = by_id.get(record.intent.operation_id)
        if prior_id is not None:
            raise ValueError("snapshot contains duplicate OperationId")
        key = (record.intent.task_id, record.intent.idempotency_key)
        prior_key = by_key.get(key)
        if prior_key is not None:
            raise ValueError("snapshot contains duplicate task-scoped idempotency key")
        by_id[record.intent.operation_id] = record
        by_key[key] = record
    prior = by_id.get(intent.operation_id)
    if prior is not None:
        if prior.intent != intent:
            return OperationReservationResult(failure=G4Failure(G4FailureCode.OPERATION_ID_REUSE_MISMATCH))
        return OperationReservationResult(operation=prior, replayed=True)
    prior = by_key.get((intent.task_id, intent.idempotency_key))
    if prior is not None:
        return OperationReservationResult(failure=G4Failure(G4FailureCode.IDEMPOTENCY_COLLISION))
    return OperationReservationResult(OperationRecord(intent, 1, OperationState.RESERVED))


_TRANSITIONS = {
    OperationState.RESERVED: frozenset((OperationState.PERFORMING, OperationState.CONFLICT)),
    OperationState.PERFORMING: frozenset(
        (OperationState.SUCCEEDED, OperationState.FAILED, OperationState.INDETERMINATE)
    ),
    OperationState.INDETERMINATE: frozenset(
        (OperationState.INDETERMINATE, OperationState.SUCCEEDED, OperationState.FAILED)
    ),
}


def transition_operation(
    operation: OperationRecord,
    expected_revision: OperationRevision,
    target_state: OperationState,
    *,
    reason_code: G4FailureCode | None = None,
) -> OperationRevisionResult:
    if type(operation) is not OperationRecord or type(target_state) is not OperationState:
        raise TypeError("operation and target state have wrong exact type")
    _revision(expected_revision, "expected operation revision")
    if operation.revision != expected_revision:
        return OperationRevisionResult(failure=G4Failure(G4FailureCode.REVISION_CONFLICT))
    if target_state not in _TRANSITIONS.get(operation.state, frozenset()):
        return OperationRevisionResult(failure=G4Failure(G4FailureCode.INVALID_OPERATION_TRANSITION))
    proposed = OperationRecord(operation.intent, operation.revision + 1, target_state, reason_code)
    return OperationRevisionResult(OperationRevisionProposal(operation.revision, proposed))


def reconcile_operation(
    operation: OperationRecord,
    expected_revision: OperationRevision,
    finding: TrustedReconciliationFinding,
) -> OperationRevisionResult:
    if type(finding) is not TrustedReconciliationFinding:
        raise TypeError("finding must be exactly TrustedReconciliationFinding")
    if operation.state not in (OperationState.PERFORMING, OperationState.INDETERMINATE):
        return OperationRevisionResult(failure=G4Failure(G4FailureCode.RECONCILIATION_REQUIRED))
    target = {
        ReconciliationFinding.INTENDED_EFFECT_PROVEN: OperationState.SUCCEEDED,
        ReconciliationFinding.INTENDED_EFFECT_PROVEN_ABSENT: OperationState.FAILED,
        ReconciliationFinding.UNRESOLVED: OperationState.INDETERMINATE,
    }[finding.finding]
    return transition_operation(operation, expected_revision, target)
