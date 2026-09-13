from dataclasses import FrozenInstanceError, replace

import pytest

from autodev_control.trusted.errors import G4FailureCode
from autodev_control.trusted.identity import OperationStartBindingId, RawSha256
from autodev_control.trusted.manifest import PolicyEpochIdentity, TrustedManifestId
from autodev_control.trusted.operation import (
    AdmissionEventId,
    AuthoritativeStateBindingId,
    CandidateId,
    EvidenceId,
    IntegrationBound,
    NotIntegrationBound,
    OperationActionId,
    OperationEffectClass,
    OperationId,
    OperationIdempotencyKey,
    OperationIntent,
    OperationPurpose,
    OperationRecord,
    OperationState,
    OperationSubjectId,
    ReconciliationFinding,
    TrustedOperationClassification,
    TrustedReconciliationFinding,
    construct_trusted_operation_intent,
    reconcile_operation,
    reserve_operation,
    transition_operation,
)
from autodev_control.trusted.scope import AuthorizationId, ContractId, TargetRegistrationId, TaskId
from autodev_control.trusted.identity import GitRef


RAW = RawSha256("1" * 64)
AUTH = AuthorizationId(RAW)
TARGET = TargetRegistrationId(RAW)
EPOCH = PolicyEpochIdentity(TrustedManifestId(RAW))
START = OperationStartBindingId(RawSha256("9" * 64))


def record(value, revision, state):
    binding = None if state in (OperationState.RESERVED, OperationState.CONFLICT) else START
    return OperationRecord(value, revision, state, start_binding_id=binding)


def _mint(cls, **fields):
    value = object.__new__(cls)
    for name, field_value in fields.items():
        object.__setattr__(value, name, field_value)
    return value


def classification(effect_class, purpose):
    return _mint(
        TrustedOperationClassification,
        effect_class=effect_class,
        purpose=purpose,
    )


def reconciliation_finding(finding):
    return _mint(TrustedReconciliationFinding, finding=finding)


def intent(
    operation="op-1", key="key-1", *, task="task", effect=OperationEffectClass.PROTECTED_OR_AUTHORITATIVE_EFFECT,
    purpose=OperationPurpose.NORMAL, candidate="candidate", integration=False, repair=False,
):
    trusted_classification = classification(effect, purpose)
    return construct_trusted_operation_intent(
        classification=trusted_classification,
        operation_id=OperationId(operation),
        idempotency_key=OperationIdempotencyKey(key),
        task_id=TaskId(task),
        action_id=OperationActionId("action"),
        subject_id=OperationSubjectId("subject"),
        candidate_id=CandidateId(candidate) if candidate else None,
        contract_id=ContractId("contract"),
        contract_raw_sha256=RAW,
        authorization_id=AUTH,
        admission_event_id=AdmissionEventId("admission"),
        target_registration_id=TARGET,
        policy_epoch_identity=EPOCH,
        authoritative_state_binding_id=AuthoritativeStateBindingId("state-binding"),
        required_evidence_ids=(EvidenceId("evidence"),),
        integration_binding=IntegrationBound(GitRef("refs/heads/main")) if integration else NotIntegrationBound(),
        is_repair_attempt=repair,
    )


def test_closed_operation_state_domain():
    assert [(item.name, item.value) for item in OperationState] == [
        ("RESERVED", "reserved"), ("PERFORMING", "performing"),
        ("SUCCEEDED", "succeeded"), ("FAILED", "failed"),
        ("CONFLICT", "conflict"), ("INDETERMINATE", "indeterminate"),
    ]


def test_nominal_operation_id_domains_are_not_interchangeable():
    assert OperationId("same") != CandidateId("same")
    assert OperationId("same") != EvidenceId("same")


def test_direct_classification_and_intent_construction_are_closed():
    with pytest.raises(TypeError):
        TrustedOperationClassification(OperationEffectClass.NON_PROTECTED_EFFECT, OperationPurpose.NORMAL)
    with pytest.raises(TypeError):
        OperationIntent()


def test_intent_requires_duplicate_free_evidence_ids():
    trusted_classification = classification(
        OperationEffectClass.NON_PROTECTED_EFFECT, OperationPurpose.NORMAL
    )
    kwargs = dict(
        classification=trusted_classification, operation_id=OperationId("op"),
        idempotency_key=OperationIdempotencyKey("key"), task_id=TaskId("task"),
        action_id=OperationActionId("action"), subject_id=OperationSubjectId("subject"),
        candidate_id=None, contract_id=ContractId("contract"), contract_raw_sha256=RAW,
        authorization_id=AUTH, admission_event_id=AdmissionEventId("admission"),
        target_registration_id=TARGET, policy_epoch_identity=EPOCH,
        authoritative_state_binding_id=AuthoritativeStateBindingId("binding"),
        required_evidence_ids=(EvidenceId("e"), EvidenceId("e")),
        integration_binding=NotIntegrationBound(),
    )
    with pytest.raises(ValueError):
        construct_trusted_operation_intent(**kwargs)


@pytest.mark.parametrize("revision", [True, False, 0, -1, 1.0])
def test_operation_revision_is_exact_positive_int(revision):
    with pytest.raises((TypeError, ValueError)):
        OperationRecord(intent(), revision, OperationState.RESERVED)


def test_reservation_is_reserved_at_revision_one_and_non_bearer():
    result = reserve_operation(intent(), ())
    assert result.operation == OperationRecord(intent(), 1, OperationState.RESERVED)
    assert result.replayed is False


def test_exact_replay_returns_existing_record_without_duplicate():
    existing = record(intent(), 3, OperationState.FAILED)
    result = reserve_operation(intent(), (existing,))
    assert result.operation is existing
    assert result.replayed is True


def test_operation_id_reuse_with_changed_intent_fails():
    existing = OperationRecord(intent(), 1, OperationState.RESERVED)
    result = reserve_operation(intent(key="another-key"), (existing,))
    assert result.failure.code is G4FailureCode.OPERATION_ID_REUSE_MISMATCH


def test_task_scoped_idempotency_collision_fails():
    existing = OperationRecord(intent(), 1, OperationState.RESERVED)
    result = reserve_operation(intent(operation="op-2"), (existing,))
    assert result.failure.code is G4FailureCode.IDEMPOTENCY_COLLISION


def test_same_key_on_another_task_is_not_a_collision():
    existing = OperationRecord(intent(), 1, OperationState.RESERVED)
    result = reserve_operation(intent(operation="op-2", task="other"), (existing,))
    assert result.operation.state is OperationState.RESERVED


@pytest.mark.parametrize(
    ("source", "target"),
    [
        (OperationState.RESERVED, OperationState.CONFLICT),
        (OperationState.PERFORMING, OperationState.SUCCEEDED),
        (OperationState.PERFORMING, OperationState.FAILED),
        (OperationState.PERFORMING, OperationState.INDETERMINATE),
        (OperationState.INDETERMINATE, OperationState.INDETERMINATE),
        (OperationState.INDETERMINATE, OperationState.SUCCEEDED),
        (OperationState.INDETERMINATE, OperationState.FAILED),
    ],
)
def test_exact_allowed_operation_transitions(source, target):
    result = transition_operation(record(intent(), 4, source), 4, target)
    assert result.operation.state is target
    assert result.operation.revision == 5


@pytest.mark.parametrize("terminal", [OperationState.SUCCEEDED, OperationState.FAILED, OperationState.CONFLICT])
def test_operation_terminal_states_have_no_outgoing_transition(terminal):
    result = transition_operation(record(intent(), 2, terminal), 2, OperationState.PERFORMING)
    assert result.failure.code is G4FailureCode.INVALID_OPERATION_TRANSITION


def test_stale_operation_revision_is_revision_conflict_not_operation_conflict():
    result = transition_operation(OperationRecord(intent(), 2, OperationState.RESERVED), 1, OperationState.PERFORMING)
    assert result.failure.code is G4FailureCode.REVISION_CONFLICT


def test_generic_transition_cannot_start_reserved_operation():
    result = transition_operation(
        OperationRecord(intent(), 7, OperationState.RESERVED), 7, OperationState.PERFORMING
    )
    assert result.failure.code is G4FailureCode.INVALID_OPERATION_TRANSITION


@pytest.mark.parametrize(
    ("finding", "target"),
    [
        (ReconciliationFinding.INTENDED_EFFECT_PROVEN, OperationState.SUCCEEDED),
        (ReconciliationFinding.INTENDED_EFFECT_PROVEN_ABSENT, OperationState.FAILED),
        (ReconciliationFinding.UNRESOLVED, OperationState.INDETERMINATE),
    ],
)
@pytest.mark.parametrize("source", [OperationState.PERFORMING, OperationState.INDETERMINATE])
def test_reconciliation_maps_exact_findings(source, finding, target):
    trusted = reconciliation_finding(finding)
    result = reconcile_operation(record(intent(), 1, source), 1, trusted)
    assert result.operation.state is target


def test_reconciliation_of_reserved_operation_is_rejected():
    finding = reconciliation_finding(ReconciliationFinding.UNRESOLVED)
    result = reconcile_operation(OperationRecord(intent(), 1, OperationState.RESERVED), 1, finding)
    assert result.failure.code is G4FailureCode.RECONCILIATION_REQUIRED


def test_operation_values_are_deeply_immutable_and_copy_isolated():
    source = [EvidenceId("source")]
    value = intent()
    source.append(EvidenceId("later"))
    assert value.required_evidence_ids == (EvidenceId("evidence"),)
    with pytest.raises(FrozenInstanceError):
        value.operation_id = OperationId("changed")
    with pytest.raises(TypeError):
        value.required_evidence_ids[0] = EvidenceId("changed")
    with pytest.raises(FrozenInstanceError):
        OperationRecord(value, 1, OperationState.RESERVED).state = OperationState.SUCCEEDED


def test_new_attempt_after_failure_uses_new_operation_and_key():
    failed = record(intent(), 3, OperationState.FAILED)
    fresh = reserve_operation(intent(operation="op-2", key="key-2"), (failed,))
    assert fresh.operation.state is OperationState.RESERVED


def test_integration_binding_is_explicit_variant():
    assert type(intent(integration=True).integration_binding) is IntegrationBound
    assert type(intent(integration=False).integration_binding) is NotIntegrationBound
