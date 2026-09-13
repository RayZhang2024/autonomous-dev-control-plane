from dataclasses import FrozenInstanceError, replace

import pytest

from autodev_control.trusted.errors import G4FailureCode
from autodev_control.trusted.identity import CandidateMaterializationId, GitSha, OperationStartBindingId, RawSha256
from autodev_control.trusted.manifest import PolicyEpochIdentity, TrustedManifestId
from autodev_control.trusted.operation import (
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
    NotIntegrationBound,
    OperationActionId,
    OperationEffectClass,
    OperationId,
    OperationIdempotencyKey,
    OperationMembershipBindingId,
    OperationPurpose,
    OperationRecord,
    OperationState,
    OperationSubjectId,
    TrustedOperationClassification,
    construct_trusted_operation_intent,
)
from autodev_control.trusted.scope import AuthorizationId, ContractId, TargetRegistrationId, TaskId
from autodev_control.trusted.identity import GitRef
from autodev_control.trusted.state import (
    CancellationStatus,
    CandidateApplicabilityDetermination,
    CandidateRecord,
    CompletionAggregate,
    ConditionStatus,
    EvidenceBindingRef,
    OperationRevisionBinding,
    RepairBudget,
    TaskEvaluationInput,
    TaskOperationSnapshot,
    TaskRecord,
    TaskState,
    _TASK_TRANSITIONS,
    adopt_candidate,
    evaluate_task,
    initial_task_proposal,
    release_repair_attempt as release_repair_attempt_model,
    reserve_repair_attempt as reserve_repair_attempt_model,
    reserve_task_operation,
    revise_supporting_evidence,
    set_cancellation,
    start_operation,
)


RAW = RawSha256("2" * 64)
AUTH = AuthorizationId(RAW)
TARGET = TargetRegistrationId(RAW)
EPOCH = PolicyEpochIdentity(TrustedManifestId(RAW))
TASK_ID = TaskId("task")
CONTRACT = ContractId("contract")
ADMISSION = AdmissionEventId("admission")
MEMBERSHIP = OperationMembershipBindingId("membership")
START = OperationStartBindingId("8" * 64)
MATERIALIZATION = CandidateMaterializationId("6" * 64)


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


def admitted(maximum=2):
    return initial_task_proposal(
        task_id=TASK_ID, contract_id=CONTRACT, contract_raw_sha256=RAW,
        authorization_id=AUTH, admission_event_id=ADMISSION,
        target_registration_id=TARGET, policy_epoch_identity=EPOCH,
        repair_budget=RepairBudget(maximum),
    ).proposed


def candidate(name="candidate", task_id=TASK_ID):
    return CandidateRecord(
        CandidateId(name), task_id, GitSha("a" * 40), CONTRACT, RAW, AUTH,
        ADMISSION, TARGET, EPOCH, MATERIALIZATION, (), None,
    )


def evaluating():
    return replace(admitted(), state=TaskState.EVALUATING, current_candidate_id=CandidateId("candidate"))


def operation(
    name="op", *, state=OperationState.RESERVED,
    effect=OperationEffectClass.PROTECTED_OR_AUTHORITATIVE_EFFECT,
    purpose=OperationPurpose.NORMAL, candidate_id=CandidateId("candidate"), repair=False,
    integration=False,
):
    trusted_classification = classification(effect, purpose)
    intent = construct_trusted_operation_intent(
        classification=trusted_classification, operation_id=OperationId(name),
        idempotency_key=OperationIdempotencyKey(f"key-{name}"), task_id=TASK_ID,
        action_id=OperationActionId("action"), subject_id=OperationSubjectId("subject"),
        candidate_id=candidate_id, contract_id=CONTRACT, contract_raw_sha256=RAW,
        authorization_id=AUTH, admission_event_id=ADMISSION,
        target_registration_id=TARGET, policy_epoch_identity=EPOCH,
        authoritative_state_binding_id=AuthoritativeStateBindingId("authoritative"),
        required_evidence_ids=(),
        integration_binding=IntegrationBound(GitRef("refs/heads/main")) if integration else NotIntegrationBound(),
        is_repair_attempt=repair,
    )
    binding = None if state in (OperationState.RESERVED, OperationState.CONFLICT) else START
    return OperationRecord(intent, 1, state, start_binding_id=binding)


def snapshot(*operations, membership=MEMBERSHIP):
    return TaskOperationSnapshot(TASK_ID, membership, tuple(operations))


def aggregate(task, *, contract=ConditionStatus.UNSATISFIED,
              additional=ConditionStatus.SATISFIED,
              applicability=ConditionStatus.SATISFIED, required=()):
    return _mint(
        CompletionAggregate,
        completion_rule_set_id=CompletionRuleSetId("rules"), task_id=task.task_id,
        contract_id=task.contract_id, contract_raw_sha256=task.contract_raw_sha256,
        authorization_id=task.authorization_id, admission_event_id=task.admission_event_id,
        target_registration_id=task.target_registration_id,
        policy_epoch_identity=task.last_evaluated_policy_epoch_identity,
        candidate_id=task.current_candidate_id, contract_acceptance_status=contract,
        additional_trusted_completion_conditions_status=additional,
        required_protected_operation_ids=required,
        current_applicability_and_authority_status=applicability,
    )


def evaluation(task, operations=(), *, blockers=(), waiting=(), next_id=None,
               contract=ConditionStatus.UNSATISFIED, required=(), expected_membership=MEMBERSHIP):
    snap = snapshot(*operations)
    bindings = tuple(
        OperationRevisionBinding(item.intent.operation_id, item.revision)
        for item in operations
        if item.intent.effect_class is OperationEffectClass.PROTECTED_OR_AUTHORITATIVE_EFFECT
        and (item.state in (OperationState.RESERVED, OperationState.PERFORMING, OperationState.INDETERMINATE)
             or item.intent.operation_id in required)
    )
    return TaskEvaluationInput(
        task.task_id, task.revision, task.contract_id, task.contract_raw_sha256,
        task.authorization_id, task.admission_event_id, task.target_registration_id,
        task.last_evaluated_policy_epoch_identity, task.current_candidate_id,
        tuple(blockers), tuple(waiting), next_id,
        aggregate(task, contract=contract, required=required), snap,
        expected_membership, bindings,
    )


def applicability(task, value):
    return _mint(
        CandidateApplicabilityDetermination,
        decision_event_id=DecisionEventId("decision"), candidate_id=value.candidate_id,
        task_id=value.task_id,
        expected_task_revision=task.revision,
        contract_id=value.contract_id,
        contract_raw_sha256=value.contract_raw_sha256,
        authorization_id=value.authorization_id,
        admission_event_id=value.admission_event_id,
        target_registration_id=value.target_registration_id,
        policy_epoch_identity=value.policy_epoch_identity,
    )


def reserve_repair_attempt(
    task, operation_id, *, expected_task_revision, operations=(),
    membership=MEMBERSHIP, expected_membership=MEMBERSHIP,
):
    return reserve_repair_attempt_model(
        task, operation_id, expected_task_revision=expected_task_revision,
        snapshot=TaskOperationSnapshot(task.task_id, membership, tuple(operations)),
        expected_membership_binding_id=expected_membership,
    )


def release_repair_attempt(
    task, operation_id, *, expected_task_revision, operation=None,
    expected_operation_revision=None, membership=MEMBERSHIP,
    expected_membership=MEMBERSHIP,
):
    operations = () if operation is None else (operation,)
    return release_repair_attempt_model(
        task, operation_id, expected_task_revision=expected_task_revision,
        snapshot=TaskOperationSnapshot(task.task_id, membership, operations),
        expected_membership_binding_id=expected_membership,
        expected_operation_revision=expected_operation_revision,
    )


def test_closed_task_state_domain():
    assert [(item.name, item.value) for item in TaskState] == [
        ("ADMITTED", "admitted"), ("EVALUATING", "evaluating"),
        ("AWAITING_INPUT", "awaiting_input"), ("INTEGRATION_READY", "integration_ready"),
        ("BLOCKED", "blocked"), ("COMPLETED", "completed"), ("CANCELLED", "cancelled"),
    ]


def test_closed_g4_failure_domain_is_exact():
    assert [item.name for item in G4FailureCode] == [
        "IDENTITY_MISMATCH", "REVISION_CONFLICT", "OPERATION_MEMBERSHIP_CONFLICT",
        "TERMINAL_TASK", "INVALID_TASK_TRANSITION", "INCONSISTENT_TASK_EVALUATION",
        "EVIDENCE_BINDING_MISMATCH", "CANDIDATE_DETACHMENT_UNSAFE",
        "REPAIR_BUDGET_EXHAUSTED", "REPAIR_ATTEMPT_REUSE_MISMATCH",
        "REPAIR_ATTEMPT_NOT_RESERVED", "OPERATION_ID_REUSE_MISMATCH",
        "IDEMPOTENCY_COLLISION", "INVALID_OPERATION_TRANSITION",
        "OPERATION_NOT_STARTABLE", "CANCELLATION_BLOCKS_OPERATION_START",
        "RECONCILIATION_REQUIRED", "ACTION_PRECONDITION_CONFLICT",
    ]


def test_exact_frozen_transition_matrix():
    expected = {
        TaskState.ADMITTED: {TaskState.EVALUATING, TaskState.AWAITING_INPUT, TaskState.BLOCKED, TaskState.COMPLETED, TaskState.CANCELLED},
        TaskState.EVALUATING: {TaskState.ADMITTED, TaskState.AWAITING_INPUT, TaskState.INTEGRATION_READY, TaskState.BLOCKED, TaskState.COMPLETED, TaskState.CANCELLED},
        TaskState.AWAITING_INPUT: {TaskState.ADMITTED, TaskState.EVALUATING, TaskState.INTEGRATION_READY, TaskState.BLOCKED, TaskState.COMPLETED, TaskState.CANCELLED},
        TaskState.INTEGRATION_READY: {TaskState.ADMITTED, TaskState.EVALUATING, TaskState.AWAITING_INPUT, TaskState.BLOCKED, TaskState.COMPLETED, TaskState.CANCELLED},
        TaskState.BLOCKED: {TaskState.ADMITTED, TaskState.EVALUATING, TaskState.AWAITING_INPUT, TaskState.INTEGRATION_READY, TaskState.COMPLETED, TaskState.CANCELLED},
    }
    assert {key: set(value) for key, value in _TASK_TRANSITIONS.items()} == expected
    assert TaskState.COMPLETED not in _TASK_TRANSITIONS
    assert TaskState.CANCELLED not in _TASK_TRANSITIONS


@pytest.mark.parametrize("revision", [True, False, 0, -1, 1.0])
def test_task_revision_is_exact_positive_int(revision):
    with pytest.raises((TypeError, ValueError)):
        replace(admitted(), revision=revision)


def test_initial_task_is_expected_absent_admitted_at_one():
    proposal = initial_task_proposal(
        task_id=TASK_ID, contract_id=CONTRACT, contract_raw_sha256=RAW,
        authorization_id=AUTH, admission_event_id=ADMISSION,
        target_registration_id=TARGET, policy_epoch_identity=EPOCH,
        repair_budget=RepairBudget(0),
    )
    assert proposal.expected_absent is True
    assert (proposal.proposed.state, proposal.proposed.revision) == (TaskState.ADMITTED, 1)


def test_same_state_safety_change_increments_revision():
    task = admitted()
    result = revise_supporting_evidence(
        task, (EvidenceBindingRef(EvidenceId("e"), None),), expected_task_revision=1
    )
    assert result.proposal.proposed.state is TaskState.ADMITTED
    assert result.proposal.proposed.revision == 2


def test_stale_task_revision_is_conflict_not_blocked():
    result = reserve_repair_attempt(admitted(), OperationId("repair"), expected_task_revision=2)
    assert result.failure.code is G4FailureCode.REVISION_CONFLICT


@pytest.mark.parametrize("state", [TaskState.COMPLETED, TaskState.CANCELLED])
def test_terminal_task_rejects_later_revision(state):
    status = CancellationStatus.NONE if state is TaskState.COMPLETED else CancellationStatus.AUTHORITATIVE
    request = None if state is TaskState.COMPLETED else CancellationRequestId("cancel")
    task = replace(admitted(), state=state, cancellation_status=status, cancellation_request_id=request)
    result = reserve_repair_attempt(task, OperationId("repair"), expected_task_revision=1)
    assert result.failure.code is G4FailureCode.TERMINAL_TASK


def test_blocker_precedes_waiting():
    task = evaluating()
    result = evaluate_task(task, evaluation(
        task, blockers=(BlockingConditionId("block"),),
        waiting=(AwaitingInputRequirementId("input"),),
    ))
    assert result.proposal.proposed.state is TaskState.BLOCKED


def test_blocker_with_successful_completion_is_inconsistent():
    task = evaluating()
    result = evaluate_task(task, evaluation(
        task, blockers=(BlockingConditionId("block"),), contract=ConditionStatus.SATISFIED,
    ))
    assert result.failure.code is G4FailureCode.INCONSISTENT_TASK_EVALUATION


def test_direct_completion_does_not_require_integration_ready():
    task = evaluating()
    result = evaluate_task(task, evaluation(task, contract=ConditionStatus.SATISFIED))
    assert result.proposal.proposed.state is TaskState.COMPLETED


def test_missing_required_operation_fails_closed():
    task = evaluating()
    result = evaluate_task(task, evaluation(
        task, contract=ConditionStatus.SATISFIED, required=(OperationId("missing"),)
    ))
    assert result.failure.code is G4FailureCode.INCONSISTENT_TASK_EVALUATION


def test_wrong_class_required_operation_fails_closed():
    task = evaluating()
    item = operation(effect=OperationEffectClass.NON_PROTECTED_EFFECT)
    result = evaluate_task(task, evaluation(
        task, (item,), contract=ConditionStatus.SATISFIED, required=(item.intent.operation_id,)
    ))
    assert result.failure.code is G4FailureCode.INCONSISTENT_TASK_EVALUATION


@pytest.mark.parametrize("state", [OperationState.RESERVED, OperationState.FAILED, OperationState.CONFLICT])
def test_non_succeeded_required_operation_prevents_completion(state):
    task = evaluating()
    item = operation(state=state)
    result = evaluate_task(task, evaluation(
        task, (item,), contract=ConditionStatus.SATISFIED, required=(item.intent.operation_id,)
    ))
    assert result.proposal.proposed.state is TaskState.EVALUATING


@pytest.mark.parametrize("state", [OperationState.PERFORMING, OperationState.INDETERMINATE])
def test_unresolved_protected_operation_blocks_completion(state):
    task = evaluating()
    item = operation(state=state)
    result = evaluate_task(task, evaluation(task, (item,), contract=ConditionStatus.SATISFIED))
    assert result.proposal.proposed.state is TaskState.EVALUATING


def test_new_operation_invalidates_stale_completion_membership():
    task = evaluating()
    value = evaluation(task, contract=ConditionStatus.SATISFIED, expected_membership=OperationMembershipBindingId("old"))
    result = evaluate_task(task, value)
    assert result.failure.code is G4FailureCode.OPERATION_MEMBERSHIP_CONFLICT


def test_reserved_operation_start_invalidates_stale_completion_revision():
    task = evaluating()
    item = operation()
    value = evaluation(task, (item,), contract=ConditionStatus.SATISFIED)
    changed = replace(item, revision=2, state=OperationState.PERFORMING, start_binding_id=START)
    value = replace(value, operation_snapshot=snapshot(changed))
    result = evaluate_task(task, value)
    assert result.failure.code is G4FailureCode.REVISION_CONFLICT


def test_operation_success_alone_does_not_imply_completion():
    task = evaluating()
    item = operation(state=OperationState.SUCCEEDED)
    result = evaluate_task(task, evaluation(task, (item,), required=(item.intent.operation_id,)))
    assert result.proposal.proposed.state is TaskState.EVALUATING


def test_requested_cancellation_withholds_completion_without_forcing_blocked():
    task = evaluating()
    requested = set_cancellation(
        task, CancellationStatus.REQUESTED, CancellationRequestId("cancel"), expected_task_revision=1
    ).proposal.proposed
    assert requested.state is TaskState.EVALUATING
    result = evaluate_task(requested, evaluation(requested, contract=ConditionStatus.SATISFIED))
    assert result.proposal.proposed.state is TaskState.EVALUATING
    assert result.proposal.proposed.cancellation_status is CancellationStatus.REQUESTED
    cleared = set_cancellation(
        result.proposal.proposed, CancellationStatus.NONE, None, expected_task_revision=3
    )
    assert cleared.proposal.proposed.cancellation_status is CancellationStatus.NONE


def test_requested_cancellation_preserves_integration_ready_posture_and_next_operation():
    item = operation(integration=True)
    task = replace(
        evaluating(), state=TaskState.INTEGRATION_READY,
        next_integration_operation_id=item.intent.operation_id,
    )
    requested = set_cancellation(
        task, CancellationStatus.REQUESTED, CancellationRequestId("cancel"),
        expected_task_revision=1,
    ).proposal.proposed
    assert requested.state is TaskState.INTEGRATION_READY
    assert requested.next_integration_operation_id == item.intent.operation_id
    evaluated = evaluate_task(
        requested, evaluation(
            requested, (item,), next_id=item.intent.operation_id,
            contract=ConditionStatus.SATISFIED,
        )
    ).proposal.proposed
    assert evaluated.state is TaskState.INTEGRATION_READY
    assert evaluated.next_integration_operation_id == item.intent.operation_id


def test_authoritative_cancellation_is_terminal_when_no_unresolved_effect():
    task = evaluating()
    result = set_cancellation(
        task, CancellationStatus.AUTHORITATIVE, CancellationRequestId("cancel"),
        expected_task_revision=1, snapshot=snapshot(), expected_membership_binding_id=MEMBERSHIP,
    )
    assert result.proposal.proposed.state is TaskState.CANCELLED
    later = evaluate_task(result.proposal.proposed, evaluation(result.proposal.proposed))
    assert later.failure.code is G4FailureCode.TERMINAL_TASK


def test_authoritative_cancellation_retains_posture_for_inflight_effect():
    task = evaluating()
    item = operation(state=OperationState.PERFORMING)
    result = set_cancellation(
        task, CancellationStatus.AUTHORITATIVE, CancellationRequestId("cancel"),
        expected_task_revision=1, snapshot=snapshot(item), expected_membership_binding_id=MEMBERSHIP,
        expected_operation_revisions=(OperationRevisionBinding(item.intent.operation_id, 1),),
    )
    assert result.proposal.proposed.state is TaskState.EVALUATING
    assert result.proposal.proposed.cancellation_status is CancellationStatus.AUTHORITATIVE


def test_authoritative_cancellation_clears_next_integration_operation():
    item = operation(integration=True)
    task = replace(
        evaluating(), state=TaskState.INTEGRATION_READY,
        next_integration_operation_id=item.intent.operation_id,
    )
    result = set_cancellation(
        task, CancellationStatus.AUTHORITATIVE, CancellationRequestId("cancel"),
        expected_task_revision=1, snapshot=snapshot(item),
        expected_membership_binding_id=MEMBERSHIP,
        expected_operation_revisions=(OperationRevisionBinding(item.intent.operation_id, 1),),
    )
    assert result.proposal.proposed.state is TaskState.CANCELLED
    assert result.proposal.proposed.next_integration_operation_id is None


def test_completion_cancellation_race_is_task_revision_safe():
    task = evaluating()
    completion = evaluate_task(task, evaluation(task, contract=ConditionStatus.SATISFIED)).proposal.proposed
    stale_cancel = set_cancellation(
        completion, CancellationStatus.AUTHORITATIVE, CancellationRequestId("cancel"),
        expected_task_revision=task.revision, snapshot=snapshot(), expected_membership_binding_id=MEMBERSHIP,
    )
    assert stale_cancel.failure.code is G4FailureCode.REVISION_CONFLICT


def test_candidate_replacement_drops_old_bound_evidence():
    old = CandidateId("candidate")
    task = replace(evaluating(), supporting_evidence_refs=(
        EvidenceBindingRef(EvidenceId("bound"), old), EvidenceBindingRef(EvidenceId("independent"), None),
    ))
    new = candidate("new")
    result = adopt_candidate(
        task, new, applicability(task, new), expected_task_revision=1,
        snapshot=snapshot(), expected_membership_binding_id=MEMBERSHIP,
        expected_operation_revisions=(),
    )
    assert result.proposal.proposed.supporting_evidence_refs == (EvidenceBindingRef(EvidenceId("independent"), None),)


@pytest.mark.parametrize("state", [OperationState.PERFORMING, OperationState.INDETERMINATE])
def test_old_candidate_inflight_effect_prevents_detachment(state):
    task = evaluating()
    item = operation(state=state)
    new = candidate("new")
    result = adopt_candidate(
        task, new, applicability(task, new), expected_task_revision=1,
        snapshot=snapshot(item), expected_membership_binding_id=MEMBERSHIP,
        expected_operation_revisions=(OperationRevisionBinding(item.intent.operation_id, 1),),
    )
    assert result.failure.code is G4FailureCode.CANDIDATE_DETACHMENT_UNSAFE


def test_reserved_old_candidate_operation_does_not_block_but_is_revision_bound():
    task = evaluating()
    item = operation()
    new = candidate("new")
    result = adopt_candidate(
        task, new, applicability(task, new), expected_task_revision=1,
        snapshot=snapshot(item), expected_membership_binding_id=MEMBERSHIP,
        expected_operation_revisions=(OperationRevisionBinding(item.intent.operation_id, 1),),
    )
    assert result.proposal.proposed.current_candidate_id == new.candidate_id
    started = replace(item, revision=2, state=OperationState.PERFORMING, start_binding_id=START)
    stale = adopt_candidate(
        task, new, applicability(task, new), expected_task_revision=1,
        snapshot=snapshot(started), expected_membership_binding_id=MEMBERSHIP,
        expected_operation_revisions=(OperationRevisionBinding(item.intent.operation_id, 1),),
    )
    assert stale.failure.code is G4FailureCode.REVISION_CONFLICT


def test_new_old_candidate_operation_invalidates_detachment_membership():
    task = evaluating()
    new = candidate("new")
    result = adopt_candidate(
        task, new, applicability(task, new), expected_task_revision=1,
        snapshot=snapshot(), expected_membership_binding_id=OperationMembershipBindingId("old"),
        expected_operation_revisions=(),
    )
    assert result.failure.code is G4FailureCode.OPERATION_MEMBERSHIP_CONFLICT


def test_evidence_identity_conflict_has_structured_failure():
    refs = (EvidenceBindingRef(EvidenceId("same"), None), EvidenceBindingRef(EvidenceId("same"), CandidateId("candidate")))
    result = revise_supporting_evidence(evaluating(), refs, expected_task_revision=1)
    assert result.failure.code is G4FailureCode.EVIDENCE_BINDING_MISMATCH


def test_repair_reservation_is_bounded_and_idempotent():
    task = admitted(maximum=1)
    first = reserve_repair_attempt(task, OperationId("repair"), expected_task_revision=1).proposal.proposed
    replay = reserve_repair_attempt(first, OperationId("repair"), expected_task_revision=2)
    assert replay.task is first and replay.replayed
    exhausted = reserve_repair_attempt(first, OperationId("other"), expected_task_revision=2)
    assert exhausted.failure.code is G4FailureCode.REPAIR_BUDGET_EXHAUSTED


def test_repair_reservation_rejects_operation_id_already_used_outside_budget():
    existing = operation(name="repair", repair=False)
    result = reserve_repair_attempt(
        admitted(), OperationId("repair"), expected_task_revision=1,
        operations=(existing,),
    )
    assert result.failure.code is G4FailureCode.REPAIR_ATTEMPT_REUSE_MISMATCH


def test_repair_reservation_binds_exact_operation_membership():
    result = reserve_repair_attempt(
        admitted(), OperationId("repair"), expected_task_revision=1,
        membership=OperationMembershipBindingId("current"),
        expected_membership=OperationMembershipBindingId("stale"),
    )
    assert result.failure.code is G4FailureCode.OPERATION_MEMBERSHIP_CONFLICT


def test_successful_repair_reservation_carries_membership_precondition():
    result = reserve_repair_attempt(
        admitted(), OperationId("repair"), expected_task_revision=1,
    )
    assert result.proposal.expected_membership_binding_id == MEMBERSHIP


def test_released_repair_id_is_historical_and_cannot_create_operation():
    task = reserve_repair_attempt(admitted(), OperationId("repair"), expected_task_revision=1).proposal.proposed
    released = release_repair_attempt(task, OperationId("repair"), expected_task_revision=2).proposal.proposed
    replay = reserve_repair_attempt(released, OperationId("repair"), expected_task_revision=3)
    assert replay.task is released and replay.replayed
    item = operation(name="repair", repair=True)
    create = reserve_task_operation(
        released, item.intent, snapshot(), expected_task_revision=3,
        expected_membership_binding_id=MEMBERSHIP,
    )
    assert create.failure.code is G4FailureCode.REPAIR_ATTEMPT_NOT_RESERVED


def test_absent_operation_release_is_membership_bound():
    task = reserve_repair_attempt(
        admitted(), OperationId("repair"), expected_task_revision=1,
    ).proposal.proposed
    result = release_repair_attempt(
        task, OperationId("repair"), expected_task_revision=2,
    )
    assert result.proposal.expected_membership_binding_id == MEMBERSHIP
    assert result.proposal.expected_operation_revisions == ()


def test_absent_operation_release_rejects_stale_membership():
    task = reserve_repair_attempt(
        admitted(), OperationId("repair"), expected_task_revision=1,
    ).proposal.proposed
    result = release_repair_attempt(
        task, OperationId("repair"), expected_task_revision=2,
        membership=OperationMembershipBindingId("current"),
        expected_membership=OperationMembershipBindingId("stale"),
    )
    assert result.failure.code is G4FailureCode.OPERATION_MEMBERSHIP_CONFLICT


def test_existing_reserved_operation_release_binds_membership_and_revision():
    task = reserve_repair_attempt(
        admitted(), OperationId("repair"), expected_task_revision=1,
    ).proposal.proposed
    item = operation(name="repair", repair=True)
    result = release_repair_attempt(
        task, OperationId("repair"), expected_task_revision=2,
        operation=item, expected_operation_revision=1,
    )
    assert result.proposal.expected_membership_binding_id == MEMBERSHIP
    assert result.proposal.expected_operation_revisions == (
        OperationRevisionBinding(OperationId("repair"), 1),
    )


def test_repair_operation_creation_requires_current_reservation():
    item = operation(name="repair", repair=True)
    result = reserve_task_operation(
        admitted(), item.intent, snapshot(), expected_task_revision=1,
        expected_membership_binding_id=MEMBERSHIP,
    )
    assert result.failure.code is G4FailureCode.REPAIR_ATTEMPT_NOT_RESERVED


def test_operation_creation_proposal_binds_task_and_membership_preconditions():
    item = operation(name="normal", repair=False)
    result = reserve_task_operation(
        evaluating(), item.intent, snapshot(), expected_task_revision=1,
        expected_membership_binding_id=MEMBERSHIP,
    )
    proposal = result.operation_create_proposal
    assert proposal.expected_absent is True
    assert proposal.expected_task_revision == 1
    assert proposal.expected_membership_binding_id == MEMBERSHIP
    assert (proposal.proposed.revision, proposal.proposed.state) == (1, OperationState.RESERVED)


def test_release_requires_absent_or_reserved_operation():
    task = reserve_repair_attempt(admitted(), OperationId("repair"), expected_task_revision=1).proposal.proposed
    item = operation(name="repair", repair=True, state=OperationState.PERFORMING)
    result = release_repair_attempt(
        task, OperationId("repair"), expected_task_revision=2,
        operation=item, expected_operation_revision=1,
    )
    assert result.failure.code is G4FailureCode.REPAIR_ATTEMPT_REUSE_MISMATCH


def test_repair_start_atomically_consumes_budget_and_enters_performing():
    task = reserve_repair_attempt(evaluating(), OperationId("repair"), expected_task_revision=1).proposal.proposed
    item = operation(name="repair", repair=True)
    result = start_operation(
        task, item, expected_task_revision=2, expected_operation_revision=1,
        expected_cancellation_status=CancellationStatus.NONE, operation_start_binding_id=START,
    )
    assert result.operation.state is OperationState.PERFORMING
    assert result.task.revision == 3
    assert result.task.repair_budget.reserved_operation_ids == ()
    assert result.task.repair_budget.consumed_operation_ids == (OperationId("repair"),)
    assert result.operation_start_proposal.expected_task_revision == 2
    assert result.operation_start_proposal.expected_operation_revision == 1
    assert result.operation_start_proposal.proposed_task is result.task


def test_release_start_race_is_revision_safe():
    task = reserve_repair_attempt(evaluating(), OperationId("repair"), expected_task_revision=1).proposal.proposed
    item = operation(name="repair", repair=True)
    released = release_repair_attempt(
        task, OperationId("repair"), expected_task_revision=2,
        operation=item, expected_operation_revision=1,
    ).proposal.proposed
    stale_start = start_operation(
        released, item, expected_task_revision=2, expected_operation_revision=1,
        expected_cancellation_status=CancellationStatus.NONE, operation_start_binding_id=START,
    )
    assert stale_start.failure.code is G4FailureCode.REVISION_CONFLICT


def test_start_release_race_leaves_attempt_consumed():
    task = reserve_repair_attempt(evaluating(), OperationId("repair"), expected_task_revision=1).proposal.proposed
    item = operation(name="repair", repair=True)
    started = start_operation(
        task, item, expected_task_revision=2, expected_operation_revision=1,
        expected_cancellation_status=CancellationStatus.NONE, operation_start_binding_id=START,
    )
    late_release = release_repair_attempt(
        started.task, OperationId("repair"), expected_task_revision=3,
        operation=started.operation, expected_operation_revision=2,
    )
    assert late_release.failure.code is G4FailureCode.REPAIR_ATTEMPT_NOT_RESERVED


def test_authoritative_cancellation_blocks_normal_protected_start_and_repair():
    task = set_cancellation(
        evaluating(), CancellationStatus.AUTHORITATIVE, CancellationRequestId("cancel"),
        expected_task_revision=1, snapshot=snapshot(), expected_membership_binding_id=MEMBERSHIP,
    ).proposal.proposed
    normal = start_operation(
        task, operation(), expected_task_revision=2, expected_operation_revision=1,
        expected_cancellation_status=CancellationStatus.AUTHORITATIVE, operation_start_binding_id=START,
    )
    assert normal.failure.code is G4FailureCode.CANCELLATION_BLOCKS_OPERATION_START
    repair = reserve_repair_attempt(task, OperationId("repair"), expected_task_revision=2)
    assert repair.failure.code is G4FailureCode.TERMINAL_TASK


def test_authoritative_nonterminal_cancellation_blocks_normal_but_not_self_authorizes_reconciliation():
    inflight = operation(name="inflight", state=OperationState.PERFORMING)
    task = set_cancellation(
        evaluating(), CancellationStatus.AUTHORITATIVE, CancellationRequestId("cancel"),
        expected_task_revision=1, snapshot=snapshot(inflight), expected_membership_binding_id=MEMBERSHIP,
        expected_operation_revisions=(OperationRevisionBinding(OperationId("inflight"), 1),),
    ).proposal.proposed
    result = start_operation(
        task, operation(name="new"), expected_task_revision=2, expected_operation_revision=1,
        expected_cancellation_status=CancellationStatus.AUTHORITATIVE, operation_start_binding_id=START,
    )
    assert result.failure.code is G4FailureCode.CANCELLATION_BLOCKS_OPERATION_START


def test_candidate_bound_start_fails_after_candidate_change():
    result = start_operation(
        replace(evaluating(), current_candidate_id=CandidateId("new")), operation(),
        expected_task_revision=1, expected_operation_revision=1,
        expected_cancellation_status=CancellationStatus.NONE, operation_start_binding_id=START,
    )
    assert result.failure.code is G4FailureCode.OPERATION_NOT_STARTABLE


def test_integration_bound_start_requires_exact_ready_next_operation():
    item = operation(integration=True)
    wrong = start_operation(
        evaluating(), item, expected_task_revision=1, expected_operation_revision=1,
        expected_cancellation_status=CancellationStatus.NONE, operation_start_binding_id=START,
    )
    assert wrong.failure.code is G4FailureCode.OPERATION_NOT_STARTABLE
    ready = replace(
        evaluating(), state=TaskState.INTEGRATION_READY,
        next_integration_operation_id=item.intent.operation_id,
    )
    allowed = start_operation(
        ready, item, expected_task_revision=1, expected_operation_revision=1,
        expected_cancellation_status=CancellationStatus.NONE, operation_start_binding_id=START,
    )
    assert allowed.operation.state is OperationState.PERFORMING
    assert allowed.operation.revision == 2


def test_nonterminal_authoritative_cancellation_blocks_repair_start():
    repair_id = OperationId("repair")
    task = reserve_repair_attempt(evaluating(), repair_id, expected_task_revision=1).proposal.proposed
    inflight = operation(name="inflight", state=OperationState.PERFORMING)
    task = set_cancellation(
        task, CancellationStatus.AUTHORITATIVE, CancellationRequestId("cancel"),
        expected_task_revision=2, snapshot=snapshot(inflight), expected_membership_binding_id=MEMBERSHIP,
        expected_operation_revisions=(OperationRevisionBinding(inflight.intent.operation_id, 1),),
    ).proposal.proposed
    result = start_operation(
        task, operation(name="repair", repair=True), expected_task_revision=3,
        expected_operation_revision=1,
        expected_cancellation_status=CancellationStatus.AUTHORITATIVE, operation_start_binding_id=START,
    )
    assert result.failure.code is G4FailureCode.CANCELLATION_BLOCKS_OPERATION_START


def test_task_snapshot_rejects_wrong_task_and_duplicate_operation_ids():
    wrong = replace(operation(), intent=construct_trusted_operation_intent(
        classification=classification(OperationEffectClass.NON_PROTECTED_EFFECT, OperationPurpose.NORMAL),
        operation_id=OperationId("wrong"), idempotency_key=OperationIdempotencyKey("wrong"),
        task_id=TaskId("other"), action_id=OperationActionId("a"), subject_id=OperationSubjectId("s"),
        candidate_id=None, contract_id=CONTRACT, contract_raw_sha256=RAW, authorization_id=AUTH,
        admission_event_id=ADMISSION, target_registration_id=TARGET, policy_epoch_identity=EPOCH,
        authoritative_state_binding_id=AuthoritativeStateBindingId("b"), required_evidence_ids=(),
        integration_binding=NotIntegrationBound(),
    ))
    with pytest.raises(ValueError):
        snapshot(wrong)
    with pytest.raises(ValueError):
        snapshot(operation(), operation())


def test_deep_immutability_of_task_candidate_budget_snapshot_and_nested_values():
    task = evaluating()
    value = candidate()
    snap = snapshot(operation())
    with pytest.raises(FrozenInstanceError):
        task.state = TaskState.COMPLETED
    with pytest.raises(FrozenInstanceError):
        value.base = GitSha("b" * 40)
    with pytest.raises(FrozenInstanceError):
        task.repair_budget.maximum_attempts = 9
    with pytest.raises(TypeError):
        snap.operations[0] = operation("other")
    with pytest.raises(FrozenInstanceError):
        snap.operations[0].intent.candidate_id = CandidateId("other")


def test_private_aggregate_and_applicability_construction_is_closed():
    with pytest.raises(TypeError):
        CompletionAggregate()
    with pytest.raises(TypeError):
        CandidateApplicabilityDetermination()


def test_g4_objects_make_no_persistence_or_authority_claim():
    task = admitted()
    item = operation()
    assert not hasattr(task, "persisted")
    assert not hasattr(item, "authorized")
    assert not hasattr(item, "execute")
