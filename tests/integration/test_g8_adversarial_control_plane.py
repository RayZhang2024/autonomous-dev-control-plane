"""G8 v0.2 adversarial integrations over the assembled G1--G7 fixtures.

Each test owns fresh fixture state.  Helpers are deliberately imported from the
lower-layer test fixtures: they construct the same G1--G7 candidate runtime,
not a parallel test authority path.
"""

from dataclasses import replace
import json

import pytest

from autodev_control.trusted.authorization import (
    OrdinaryRootProtectionState,
    admit_direct_authorization,
    load_candidate_authorization_proposal,
)
from autodev_control.trusted.backend import (
    CanonicalTransaction,
    CanonicalWriteStatus,
    CreateAuthorization,
    CreateCandidate,
    CreateEvidenceHistory,
    CreateSemanticReviewOperationAndBinding,
    CreateTaskAndInitialOperationMembership,
    ReplaceOperation,
    ReplaceTask,
    ResolvedTargetRegistration,
    ReviewAttemptBindingRecord,
)
from autodev_control.trusted.decision import Decision
from autodev_control.trusted.errors import (
    AuthorizationAdmissionReasonCode,
    AuthorizationProposalFailureCode,
)
from autodev_control.trusted.errors import G4FailureCode
from autodev_control.trusted.evidence import (
    EvidenceApplicabilityDecision,
    EvidenceApplicabilityReason,
    evaluate_evidence_applicability,
    SemanticVerdict,
)
from autodev_control.trusted.gates import (
    ActionTargetFence,
    ControlStateGate,
    GateResultCode,
    MergeGate,
    ProtectedEffectSubject,
    SemanticEvidenceCommand,
    TargetPublicationGate,
    TaskEvaluationCommand,
)
from autodev_control.trusted.identity import (
    CandidateMaterializationId,
    GitSha,
    ImmutableConfigId,
    OperationStartBindingId,
    RawSha256,
)
from autodev_control.trusted.materialization import (
    MutationKind,
    build_candidate_materialization,
)
from autodev_control.trusted.operation import (
    AuthoritativeStateBindingId,
    NotIntegrationBound,
    OperationActionId,
    OperationEffectClass,
    OperationId,
    OperationIdempotencyKey,
    OperationPurpose,
    OperationRecord,
    OperationState,
    OperationSubjectId,
    CandidateId,
    _compose_trusted_operation_classification,
    construct_trusted_operation_intent,
)
from autodev_control.trusted.scope import (
    ChangeType,
    ContractId,
    MutationScope,
    MutationScopeRule,
    RepositorySelector,
    TaskCapability,
    TaskId,
)
from autodev_control.trusted.state import (
    RepairBudget,
    CandidateRecord,
    TaskRecord,
)
from autodev_control.trusted.state import (
    CancellationRequestId, CancellationStatus, ConditionStatus, TaskState,
)

from tests.trusted import test_authorization as authorization_fixture
from tests.trusted import test_evidence as evidence_fixture
from tests.trusted import test_gates as gates_fixture


def _operation(runtime, operation_id):
    return next(
        item for item in runtime.backend.read_task_working_set(gates_fixture.TASK).operations
        if item.intent.operation_id == operation_id
    )


def _publication_setup(name="g8-publication", *, target=None):
    runtime = gates_fixture.runtime(target)
    gates_fixture.initialize_task(runtime)
    materialization = gates_fixture.materialize(runtime)
    gates_fixture.adopt_materialization(runtime, materialization)
    operation = gates_fixture.reserve_protected(runtime, name, materialization.candidate_id)
    fence = ActionTargetFence(
        gates_fixture.REPO, materialization.candidate_branch, None,
        runtime.platform.snapshot().generation,
    )
    return runtime, materialization, operation, fence


def _evaluate(runtime, context, *, blockers=()):
    """Use the public G6/G4 evaluation path for one exact trusted context."""
    runtime.register_completion_evaluation_context(context)
    return ControlStateGate(runtime).commit(
        runtime.boundary.evaluate_task(TaskEvaluationCommand(
            gates_fixture.TASK, context.context_id, blockers, (), None,
        )), gates_fixture.independent_lease(runtime),
    )


def _persist_admitted_evidence_through_g5_boundary():
    """Bootstrap canonical eligibility, then admit raw APPROVED evidence publicly."""
    template = evidence_fixture.fixture()
    subject = template.effective_subject
    target_fields = {
        field: getattr(gates_fixture.registration(), field)
        for field in gates_fixture.AdmittedTargetRegistration.__dataclass_fields__
    }
    target_fields.update(
        target_registration_id=subject.target_registration_id,
        policy_epoch_identity=subject.policy_epoch_identity,
    )
    target = gates_fixture.mint(gates_fixture.AdmittedTargetRegistration, **target_fields)
    resolved = gates_fixture.mint(
        ResolvedTargetRegistration,
        registration=target, target_registration_id=subject.target_registration_id,
        root_config_id=ImmutableConfigId("g8-evidence-target-root"),
        policy_epoch_identity=subject.policy_epoch_identity,
    )
    template_runtime = gates_fixture.runtime()
    runtime = gates_fixture.FixtureProtectedGateRuntime(
        template_runtime.binding,
        gates_fixture.InMemoryCanonicalStateBackend((resolved,)),
        gates_fixture.FixtureGitPlatform(), gates_fixture.FixtureGateAudit(),
    )
    authorization_fields = {
        field: getattr(gates_fixture.authorization(), field)
        for field in gates_fixture.AdmittedAuthorization.__dataclass_fields__
    }
    authorization_fields.update(
        authorization_id=subject.authorization_id,
        task_id=subject.task_id, contract_id=subject.contract_id,
        contract_raw_sha256=subject.contract_raw_sha256,
        target_registration_id=subject.target_registration_id,
        policy_epoch_identity=subject.policy_epoch_identity,
    )
    authorization = gates_fixture.mint(
        gates_fixture.AdmittedAuthorization, **authorization_fields,
    )
    task = TaskRecord(
        subject.task_id, 1, TaskState.ADMITTED,
        subject.contract_id, subject.contract_raw_sha256,
        subject.authorization_id, subject.task_admission_event_id,
        subject.target_registration_id, subject.policy_epoch_identity,
        None, None, (), RepairBudget(0),
    )
    adopted_task = TaskRecord(
        subject.task_id, 2, TaskState.EVALUATING,
        subject.contract_id, subject.contract_raw_sha256,
        subject.authorization_id, subject.task_admission_event_id,
        subject.target_registration_id, subject.policy_epoch_identity,
        subject.candidate_id, None, (), RepairBudget(0),
    )
    candidate = CandidateRecord(
        subject.candidate_id, subject.task_id, subject.base,
        subject.contract_id, subject.contract_raw_sha256,
        subject.authorization_id, subject.task_admission_event_id,
        subject.target_registration_id, subject.policy_epoch_identity,
        CandidateMaterializationId(RawSha256("a" * 64)), (),
    )
    intent = construct_trusted_operation_intent(
        classification=_compose_trusted_operation_classification(
            OperationEffectClass.NON_PROTECTED_EFFECT, OperationPurpose.NORMAL,
        ),
        operation_id=template.operation.intent.operation_id,
        idempotency_key=OperationIdempotencyKey("g8-semantic-review"),
        task_id=subject.task_id,
        action_id=OperationActionId("g8-semantic-review"),
        subject_id=OperationSubjectId("g8-semantic-review"),
        candidate_id=subject.candidate_id,
        contract_id=subject.contract_id,
        contract_raw_sha256=subject.contract_raw_sha256,
        authorization_id=subject.authorization_id,
        admission_event_id=subject.task_admission_event_id,
        target_registration_id=subject.target_registration_id,
        policy_epoch_identity=subject.policy_epoch_identity,
        authoritative_state_binding_id=AuthoritativeStateBindingId("g8-evidence"),
        required_evidence_ids=(), integration_binding=NotIntegrationBound(),
    )
    assert runtime.backend.apply(CanonicalTransaction(
        runtime.backend.occurrence, (), (
            CreateAuthorization(authorization),
            CreateTaskAndInitialOperationMembership(task),
            CreateCandidate(candidate),
            CreateEvidenceHistory(subject),
            ReplaceTask(1, adopted_task),
        ),
    )).status is CanonicalWriteStatus.APPLIED
    reserved = OperationRecord(intent, 1, OperationState.RESERVED)
    attempt = ReviewAttemptBindingRecord(
        subject, template.invocation.invocation_id, template.slot.slot_id,
        reserved.intent.operation_id, template.invocation.canonical_request_id,
    )
    working = runtime.backend.read_task_working_set(subject.task_id)
    assert runtime.backend.apply(CanonicalTransaction(
        runtime.backend.occurrence, (), (
            CreateSemanticReviewOperationAndBinding(
                reserved, attempt, working.task.revision,
                working.task_operation_membership.membership_binding_id,
            ),
        ),
    )).status is CanonicalWriteStatus.APPLIED
    succeeded = OperationRecord(
        intent, 2, OperationState.SUCCEEDED,
        start_binding_id=OperationStartBindingId(RawSha256("7" * 64)),
    )
    assert runtime.backend.apply(CanonicalTransaction(
        runtime.backend.occurrence, (), (ReplaceOperation(1, succeeded),),
    )).status is CanonicalWriteStatus.APPLIED
    context_id = ImmutableConfigId("g8-approved-evidence")
    runtime.register_semantic_evidence_context(context_id, template)
    request = runtime.boundary.admit_semantic_evidence(
        SemanticEvidenceCommand(context_id, template.raw_response),
    )
    assert ControlStateGate(runtime).commit(
        request, gates_fixture.independent_lease(runtime),
    ).code is GateResultCode.COMMITTED
    snapshot = runtime.backend.read_review_eligibility_snapshot(subject.subject_id)
    assert len(snapshot.canonical_evidence_records) == 1
    return runtime, snapshot.canonical_evidence_records[0]


def test_g8_01_admitted_evidence_with_stale_base_is_not_current_proof():
    admitted = evidence_fixture.admit_semantic_review(
        evidence_fixture.fixture()
    ).proposed_evidence_record
    current = replace(admitted.subject, base=GitSha("b" * 40))
    result = evaluate_evidence_applicability(admitted, current)
    assert (result.decision, result.reason) == (
        EvidenceApplicabilityDecision.STALE,
        EvidenceApplicabilityReason.BASE_CHANGED,
    )
    assert result.decision is not EvidenceApplicabilityDecision.APPLICABLE


def test_g8_02_public_control_boundary_rejects_transferred_authorization():
    runtime = gates_fixture.runtime()
    gates_fixture.initialize_task(runtime)
    request = runtime.boundary.create_task(
        task_id=TaskId("g8-other-task"),
        contract_id=ContractId("g8-other-contract"),
        contract_raw_sha256=RawSha256("9" * 64),
        authorization_id=gates_fixture.AUTH,
        admission_event_id=gates_fixture.ADMISSION,
        target_registration_id=gates_fixture.TARGET,
        policy_epoch_identity=gates_fixture.EPOCH,
        repair_budget=RepairBudget(1),
    )
    assert ControlStateGate(runtime).commit(
        request, gates_fixture.independent_lease(runtime),
    ).code is GateResultCode.REJECTED
    assert runtime.backend.read_task_working_set(TaskId("g8-other-task")) is None


def test_g8_03_tree_derived_out_of_scope_addition_cannot_start_publication():
    modify_only = MutationScope((MutationScopeRule(
        RepositorySelector(), (ChangeType.MODIFY,),
    ),))
    target_fields = {
        field: getattr(gates_fixture.registration(), field)
        for field in gates_fixture.AdmittedTargetRegistration.__dataclass_fields__
    }
    target_fields["ordinary_allowed_scope"] = modify_only
    target = gates_fixture.mint(gates_fixture.AdmittedTargetRegistration, **target_fields)
    runtime, materialization, operation, fence = _publication_setup(
        "g8-scope-escape", target=target,
    )
    assert materialization.inventory.mutations[0].kind is MutationKind.ADDED
    with pytest.raises(ValueError):
        gates_fixture.start_protected(
            runtime, operation,
            ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
            fence, materialization, target=target,
        )
    assert runtime.platform.marker(
        operation.intent.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION.value,
    ) is None
    assert _operation(runtime, operation.intent.operation_id).state is OperationState.CONFLICT


def test_g8_04_root_overlap_and_missing_context_use_frozen_admission_reasons():
    target = authorization_fixture.admitted_target()
    proposal = authorization_fixture.load_proposal(target.target_registration_id)
    contract, policy, approval, issuer, root = authorization_fixture.direct_contexts(
        proposal, target,
    )
    protected = authorization_fixture._ordinary_root_context_for_test(
        policy_epoch_identity=policy.policy_epoch_identity,
        repository_id=target.repository_id,
        state=OrdinaryRootProtectionState.ROOT_PROTECTED_MUTATION_SCOPE,
        root_protected_mutation_scope=authorization_fixture.proposal_scope(),
    )
    overlap = admit_direct_authorization(
        proposal, target, contract, policy, approval, issuer, protected,
    )
    unavailable = admit_direct_authorization(
        proposal, target, contract, policy, approval, issuer, None,
    )
    assert overlap.decision is Decision.DENY
    assert overlap.reason_code is AuthorizationAdmissionReasonCode.ROOT_SCOPE_OVERLAP
    assert overlap.admitted_authorization is None
    assert unavailable.decision is Decision.ESCALATE
    assert unavailable.reason_code is AuthorizationAdmissionReasonCode.ROOT_CONTEXT_UNAVAILABLE
    assert unavailable.admitted_authorization is None


def test_g8_05_target_movement_before_start_conflicts_without_effect():
    runtime, materialization, operation, fence = _publication_setup("g8-stale-target")
    runtime.platform.seed_ref(
        gates_fixture.REPO, materialization.candidate_branch, GitSha("d" * 40),
    )
    result = gates_fixture.start_protected(
        runtime, operation,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
        fence, materialization,
    )
    assert result.code is GateResultCode.ACTION_PRECONDITION_CONFLICT
    stored = _operation(runtime, operation.intent.operation_id)
    assert stored.state is OperationState.CONFLICT
    assert stored.start_binding_id is None
    assert runtime.platform.marker(
        operation.intent.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION.value,
    ) is None


def test_g8_06_admitted_approved_evidence_cannot_override_a_deterministic_conflict():
    """G5 persists APPROVED evidence; G7's independent target fence still wins."""
    _, evidence = _persist_admitted_evidence_through_g5_boundary()
    assert evidence.payload.aggregate is SemanticVerdict.APPROVED
    runtime, materialization, operation, fence = _publication_setup("g8-evidence-conflict")
    runtime.platform.seed_ref(
        gates_fixture.REPO, materialization.candidate_branch, GitSha("d" * 40),
    )
    result = gates_fixture.start_protected(
        runtime, operation,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
        fence, materialization,
    )
    assert result.code is GateResultCode.ACTION_PRECONDITION_CONFLICT
    assert _operation(runtime, operation.intent.operation_id).state is OperationState.CONFLICT
    assert runtime.platform.marker(
        operation.intent.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION.value,
    ) is None


def test_g8_07_admitted_approval_is_not_merge_or_completion_authority():
    """A canonical APPROVED review cannot start an unproven merge or complete work."""
    _, evidence = _persist_admitted_evidence_through_g5_boundary()
    assert evidence.payload.aggregate is SemanticVerdict.APPROVED
    runtime, materialization, operation, _ = _publication_setup("g8-evidence-merge")
    with pytest.raises(ValueError):
        gates_fixture.start_protected(
            runtime, operation, ProtectedEffectSubject.FAST_FORWARD_MERGE,
            ActionTargetFence(
                gates_fixture.REPO, gates_fixture.REF, materialization.base,
                runtime.platform.snapshot().generation,
            ), materialization,
        )
    assert _operation(runtime, operation.intent.operation_id).state is OperationState.CONFLICT
    assert runtime.platform.marker(
        operation.intent.operation_id,
        ProtectedEffectSubject.FAST_FORWARD_MERGE.value,
    ) is None
    context = gates_fixture.completion_context(
        runtime, "g8-evidence-required-merge",
        contract=ConditionStatus.SATISFIED,
        additional=ConditionStatus.SATISFIED,
        applicability=ConditionStatus.SATISFIED,
        required=(operation.intent.operation_id,),
    )
    assert _evaluate(runtime, context).code is GateResultCode.COMMITTED
    assert runtime.backend.read_task_working_set(gates_fixture.TASK).task.state is not TaskState.COMPLETED


def test_g8_08_exact_replay_never_duplicates_effect_or_lends_marker_to_other_operation():
    runtime, materialization, operation, fence = _publication_setup("g8-replay")
    started = gates_fixture.start_protected(
        runtime, operation,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
        fence, materialization,
    )
    assert TargetPublicationGate(runtime).perform(
        started.continuation,
    ).code is GateResultCode.EFFECT_SUCCEEDED
    assert runtime.reconcile_recovered_effect(
        gates_fixture.TASK, operation.intent.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
    ).code is GateResultCode.EFFECT_SUCCEEDED
    assert TargetPublicationGate(runtime).perform(
        started.continuation,
    ).code is GateResultCode.LEASE_CONSUMED
    marker = runtime.platform.marker(
        operation.intent.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION.value,
    )
    assert marker is not None
    other = gates_fixture.reserve_protected(runtime, "g8-replay-other", materialization.candidate_id)
    assert runtime.platform.marker(
        other.intent.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION.value,
    ) is None
    assert len(runtime.platform._markers) == 1


def test_g8_09_recovery_requires_durable_marker_and_never_replays():
    runtime, materialization, operation, fence = _publication_setup("g8-recovery")
    started = gates_fixture.start_protected(
        runtime, operation,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
        fence, materialization,
    )
    restarted = runtime.restart()
    assert restarted.reconcile_recovered_effect(
        gates_fixture.TASK, operation.intent.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
    ).code is GateResultCode.EFFECT_FAILED
    assert restarted.platform.prepared_effect_state(
        operation.intent.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION.value,
    ) == "RELEASED"
    assert _operation(restarted, operation.intent.operation_id).state is OperationState.FAILED
    assert restarted.platform.marker(
        operation.intent.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION.value,
    ) is None
    assert started.continuation.target_fence_token.active is False


def test_g8_09b_consumed_exact_marker_reconciles_succeeded_without_replay():
    runtime, materialization, operation, fence = _publication_setup("g8-recovery-marker")
    started = gates_fixture.start_protected(
        runtime, operation,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
        fence, materialization,
    )
    assert TargetPublicationGate(runtime).perform(
        started.continuation,
    ).code is GateResultCode.EFFECT_SUCCEEDED
    marker = runtime.platform.marker(
        operation.intent.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION.value,
    )
    assert marker is not None
    restarted = runtime.restart()
    assert restarted.reconcile_recovered_effect(
        gates_fixture.TASK, operation.intent.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
    ).code is GateResultCode.EFFECT_SUCCEEDED
    assert _operation(restarted, operation.intent.operation_id).state is OperationState.SUCCEEDED
    assert restarted.platform.marker(
        operation.intent.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION.value,
    ) == marker


def test_g8_09c_contradictory_marker_postcondition_is_indeterminate():
    runtime, materialization, operation, fence = _publication_setup("g8-recovery-contradiction")
    started = gates_fixture.start_protected(
        runtime, operation,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
        fence, materialization,
    )
    assert TargetPublicationGate(runtime).perform(
        started.continuation,
    ).code is GateResultCode.EFFECT_SUCCEEDED
    runtime.platform.seed_ref(
        gates_fixture.REPO, materialization.candidate_branch, GitSha("d" * 40),
    )
    restarted = runtime.restart()
    assert restarted.reconcile_recovered_effect(
        gates_fixture.TASK, operation.intent.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
    ).code is GateResultCode.INDETERMINATE
    assert _operation(restarted, operation.intent.operation_id).state is OperationState.INDETERMINATE


def test_g8_10a_authoritative_cancellation_first_blocks_protected_start():
    runtime, materialization, operation, fence = _publication_setup("g8-cancel-first")
    cancellation = runtime.boundary.set_cancellation(
        gates_fixture.TASK, CancellationStatus.AUTHORITATIVE,
        CancellationRequestId("g8-cancel"),
    )
    assert ControlStateGate(runtime).commit(
        cancellation, gates_fixture.independent_lease(runtime),
    ).code is GateResultCode.COMMITTED
    task = runtime.backend.read_task_working_set(gates_fixture.TASK).task
    assert task.cancellation_status is CancellationStatus.AUTHORITATIVE
    assert task.state is TaskState.CANCELLED
    result = gates_fixture.start_protected(
        runtime, operation,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
        fence, materialization,
    )
    assert result.failure_code is G4FailureCode.CANCELLATION_BLOCKS_OPERATION_START
    stored = _operation(runtime, operation.intent.operation_id)
    assert stored.state is OperationState.RESERVED
    assert stored.start_binding_id is None
    assert runtime.platform.marker(
        operation.intent.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION.value,
    ) is None


def test_g8_10b_started_operation_survives_authoritative_cancellation_until_recovery():
    runtime, materialization, operation, fence = _publication_setup("g8-start-first")
    started = gates_fixture.start_protected(
        runtime, operation,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
        fence, materialization,
    )
    performing = _operation(runtime, operation.intent.operation_id)
    assert performing.state is OperationState.PERFORMING
    cancellation = runtime.boundary.set_cancellation(
        gates_fixture.TASK, CancellationStatus.AUTHORITATIVE,
        CancellationRequestId("g8-cancel-after-start"),
    )
    assert ControlStateGate(runtime).commit(
        cancellation, gates_fixture.independent_lease(runtime),
    ).code is GateResultCode.COMMITTED
    task = runtime.backend.read_task_working_set(gates_fixture.TASK).task
    assert task.cancellation_status is CancellationStatus.AUTHORITATIVE
    assert task.next_integration_operation_id is None
    stored = _operation(runtime, operation.intent.operation_id)
    assert stored.state is OperationState.PERFORMING
    assert stored.start_binding_id == performing.start_binding_id
    assert started.continuation is not None


def test_g8_11_public_evaluation_boundary_can_represent_all_frozen_completion_inputs():
    """The root-managed context supplies all frozen completion facts exactly."""
    runtime, materialization, operation, fence = _publication_setup("g8-completion")
    started = gates_fixture.start_protected(
        runtime, operation,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
        fence, materialization,
    )
    assert TargetPublicationGate(runtime).perform(
        started.continuation,
    ).code is GateResultCode.EFFECT_SUCCEEDED
    assert runtime.reconcile_recovered_effect(
        gates_fixture.TASK, operation.intent.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
    ).code is GateResultCode.EFFECT_SUCCEEDED
    context = gates_fixture.completion_context(
        runtime, "g8-completion-positive",
        contract=ConditionStatus.SATISFIED,
        additional=ConditionStatus.SATISFIED,
        applicability=ConditionStatus.SATISFIED,
        required=(),
    )
    runtime.register_completion_evaluation_context(context)
    assert ControlStateGate(runtime).commit(
        runtime.boundary.evaluate_task(TaskEvaluationCommand(
            gates_fixture.TASK, context.context_id, (), (), None,
        )), gates_fixture.independent_lease(runtime),
    ).code is GateResultCode.COMMITTED
    assert runtime.backend.read_task_working_set(gates_fixture.TASK).task.state is TaskState.COMPLETED

    for name, contract, additional, applicability in (
        ("contract", ConditionStatus.UNSATISFIED, ConditionStatus.SATISFIED, ConditionStatus.SATISFIED),
        ("additional", ConditionStatus.SATISFIED, ConditionStatus.UNSATISFIED, ConditionStatus.SATISFIED),
        ("applicability", ConditionStatus.SATISFIED, ConditionStatus.SATISFIED, ConditionStatus.UNSATISFIED),
    ):
        negative = gates_fixture.runtime()
        gates_fixture.initialize_task(negative)
        negative_context = gates_fixture.completion_context(
            negative, "g8-completion-" + name,
            contract=contract, additional=additional, applicability=applicability,
        )
        negative.register_completion_evaluation_context(negative_context)
        blockers = (
            (gates_fixture.BlockingConditionId("g8-not-applicable"),)
            if applicability is ConditionStatus.UNSATISFIED else ()
        )
        assert ControlStateGate(negative).commit(
            negative.boundary.evaluate_task(TaskEvaluationCommand(
                gates_fixture.TASK, negative_context.context_id, blockers, (), None,
            )), gates_fixture.independent_lease(negative),
        ).code is GateResultCode.COMMITTED
        assert negative.backend.read_task_working_set(gates_fixture.TASK).task.state is not TaskState.COMPLETED


def test_g8_11_required_operation_not_succeeded_cannot_complete():
    runtime, materialization, operation, _ = _publication_setup("g8-required-not-succeeded")
    context = gates_fixture.completion_context(
        runtime, "g8-required-not-succeeded-context",
        contract=ConditionStatus.SATISFIED,
        additional=ConditionStatus.SATISFIED,
        applicability=ConditionStatus.SATISFIED,
        required=(operation.intent.operation_id,),
    )
    assert _evaluate(runtime, context).code is GateResultCode.COMMITTED
    assert _operation(runtime, operation.intent.operation_id).state is OperationState.RESERVED
    assert runtime.backend.read_task_working_set(gates_fixture.TASK).task.state is not TaskState.COMPLETED


def test_g8_11_unresolved_performing_operation_cannot_complete():
    runtime, materialization, operation, fence = _publication_setup("g8-performing")
    started = gates_fixture.start_protected(
        runtime, operation, ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
        fence, materialization,
    )
    context = gates_fixture.completion_context(
        runtime, "g8-performing-context",
        contract=ConditionStatus.SATISFIED,
        additional=ConditionStatus.SATISFIED,
        applicability=ConditionStatus.SATISFIED,
        required=(operation.intent.operation_id,),
    )
    assert _evaluate(runtime, context).code is GateResultCode.COMMITTED
    assert _operation(runtime, operation.intent.operation_id).state is OperationState.PERFORMING
    assert started.continuation is not None
    assert runtime.backend.read_task_working_set(gates_fixture.TASK).task.state is not TaskState.COMPLETED


def test_g8_11_unresolved_indeterminate_operation_cannot_complete():
    runtime, materialization, operation, fence = _publication_setup("g8-indeterminate")
    started = gates_fixture.start_protected(
        runtime, operation, ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
        fence, materialization,
    )
    assert TargetPublicationGate(runtime).perform(started.continuation).code is GateResultCode.EFFECT_SUCCEEDED
    runtime.platform.seed_ref(
        gates_fixture.REPO, materialization.candidate_branch, GitSha("d" * 40),
    )
    restarted = runtime.restart()
    assert restarted.reconcile_recovered_effect(
        gates_fixture.TASK, operation.intent.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
    ).code is GateResultCode.INDETERMINATE
    context = gates_fixture.completion_context(
        restarted, "g8-indeterminate-context",
        contract=ConditionStatus.SATISFIED,
        additional=ConditionStatus.SATISFIED,
        applicability=ConditionStatus.SATISFIED,
        required=(operation.intent.operation_id,),
    )
    assert _evaluate(restarted, context).code is GateResultCode.COMMITTED
    assert _operation(restarted, operation.intent.operation_id).state is OperationState.INDETERMINATE
    assert restarted.backend.read_task_working_set(gates_fixture.TASK).task.state is not TaskState.COMPLETED


def test_g8_11_authoritative_cancellation_cannot_complete():
    runtime = gates_fixture.runtime()
    gates_fixture.initialize_task(runtime)
    cancellation = runtime.boundary.set_cancellation(
        gates_fixture.TASK, CancellationStatus.AUTHORITATIVE,
        CancellationRequestId("g8-completion-cancel"),
    )
    assert ControlStateGate(runtime).commit(
        cancellation, gates_fixture.independent_lease(runtime),
    ).code is GateResultCode.COMMITTED
    context = gates_fixture.completion_context(
        runtime, "g8-cancelled-context",
        contract=ConditionStatus.SATISFIED,
        additional=ConditionStatus.SATISFIED,
        applicability=ConditionStatus.SATISFIED,
    )
    with pytest.raises(ValueError, match="TERMINAL_TASK"):
        _evaluate(runtime, context)
    task = runtime.backend.read_task_working_set(gates_fixture.TASK).task
    assert task.cancellation_status is CancellationStatus.AUTHORITATIVE
    assert task.state is not TaskState.COMPLETED


def test_g8_13_external_merge_like_state_without_marker_never_recovers_succeeded():
    """An untrusted fast-forward cannot substitute for this merge's marker."""
    runtime, materialization, _, _ = _publication_setup("g8-merge-publication")
    publish = next(iter(runtime.backend.read_task_working_set(gates_fixture.TASK).operations))
    publish_started = gates_fixture.start_protected(
        runtime, publish, ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
        ActionTargetFence(
            gates_fixture.REPO, materialization.candidate_branch, None,
            runtime.platform.snapshot().generation,
        ), materialization,
    )
    assert TargetPublicationGate(runtime).perform(publish_started.continuation).code is GateResultCode.EFFECT_SUCCEEDED
    create_pr = gates_fixture.reserve_protected(
        runtime, "g8-merge-pr", materialization.candidate_id,
    )
    pr_started = gates_fixture.start_protected(
        runtime, create_pr, ProtectedEffectSubject.PULL_REQUEST_CREATION,
        ActionTargetFence(
            gates_fixture.REPO, materialization.candidate_branch,
            materialization.commit, runtime.platform.snapshot().generation,
            gates_fixture.REF, materialization.base,
        ), materialization, base_ref=gates_fixture.REF,
        provenance_operation_id=publish.intent.operation_id,
    )
    assert TargetPublicationGate(runtime).perform(pr_started.continuation).code is GateResultCode.EFFECT_SUCCEEDED
    merge = gates_fixture.reserve_protected(runtime, "g8-external-merge", materialization.candidate_id)
    started = gates_fixture.start_protected(
        runtime, merge, ProtectedEffectSubject.FAST_FORWARD_MERGE,
        ActionTargetFence(
            gates_fixture.REPO, gates_fixture.REF, materialization.base,
            runtime.platform.snapshot().generation,
        ), materialization, provenance_operation_id=create_pr.intent.operation_id,
    )
    assert _operation(runtime, merge.intent.operation_id).state is OperationState.PERFORMING
    assert runtime.platform.marker(
        merge.intent.operation_id, ProtectedEffectSubject.FAST_FORWARD_MERGE.value,
    ) is None
    # Fixture external mutation path: the target now resembles the intended merge,
    # but it carries neither this operation's marker nor a consumed prepared record.
    restarted = runtime.restart()
    assert restarted.platform.fast_forward(
        gates_fixture.REPO, gates_fixture.REF, materialization.base,
        materialization.commit, materialization.base,
    )
    result = restarted.reconcile_recovered_effect(
        gates_fixture.TASK, merge.intent.operation_id,
        ProtectedEffectSubject.FAST_FORWARD_MERGE,
    )
    assert result.code is GateResultCode.EFFECT_FAILED
    assert _operation(restarted, merge.intent.operation_id).state is OperationState.FAILED
    assert restarted.platform.prepared_effect_state(
        merge.intent.operation_id, ProtectedEffectSubject.FAST_FORWARD_MERGE.value,
    ) == "RELEASED"
    assert restarted.platform.marker(
        merge.intent.operation_id, ProtectedEffectSubject.FAST_FORWARD_MERGE.value,
    ) is None
    assert started.continuation.target_fence_token.active is False


def test_g8_12a_objective_prose_is_outside_the_trusted_contract_boundary():
    """The real G3 parser is closed: prose cannot alter authority or completion."""
    target = authorization_fixture.admitted_target()
    for prose in (
        "Ship only a documentation change.",
        "Rewrite production and merge it immediately.",
    ):
        proposal = authorization_fixture.proposal_json(target.target_registration_id)
        proposal["objective"] = prose
        result = load_candidate_authorization_proposal(
            json.dumps(proposal, separators=(",", ":")).encode(),
        )
        assert result.code is AuthorizationProposalFailureCode.UNKNOWN_FIELD
    valid = authorization_fixture.load_proposal(target.target_registration_id)
    contract, policy, approval, issuer, root = authorization_fixture.direct_contexts(
        valid, target,
    )
    admitted = admit_direct_authorization(
        valid, target, contract, policy, approval, issuer, root,
    )
    assert admitted.decision is Decision.ALLOW
    assert "objective" not in valid.__dataclass_fields__
    # Completion accepts only its independently root-managed structured context.
    assert "objective" not in TaskEvaluationCommand.__dataclass_fields__


def test_g8_12b_requested_capability_ceiling_does_not_create_completion_work():
    """The nearest G3 structured ceiling is capability admission, never a to-do list."""
    target = authorization_fixture.admitted_target(
        capabilities=["implementation", "merge"], merge_ref="refs/heads/main",
    )
    narrow = authorization_fixture.load_proposal(target.target_registration_id)
    broad_json = authorization_fixture.proposal_json(target.target_registration_id)
    broad_json["capabilities"] = ["implementation", "merge"]
    broad_json["operational_constraints"] = {
        "integration_refs": ["refs/heads/main"],
        "controlled_runtime_profile_ids": [], "repair_max_attempts": 0,
    }
    broad = load_candidate_authorization_proposal(
        json.dumps(broad_json, separators=(",", ":")).encode(),
    )
    assert type(broad) is type(narrow)
    narrow_context = authorization_fixture.direct_contexts(narrow, target)
    broad_context = authorization_fixture.direct_contexts(broad, target)
    narrow_admission = admit_direct_authorization(
        narrow, target, *narrow_context,
    )
    broad_admission = admit_direct_authorization(
        broad, target, *broad_context,
    )
    assert narrow_admission.decision is broad_admission.decision is Decision.ALLOW
    assert TaskCapability.MERGE not in narrow_admission.admitted_authorization.authorized_capabilities
    assert TaskCapability.MERGE in broad_admission.admitted_authorization.authorized_capabilities
    # Completion requirements remain explicit root-managed data, not inferred
    # from the broader G3 ceiling or from any order among requested capabilities.
    narrow_runtime = gates_fixture.runtime()
    broad_runtime = gates_fixture.runtime()
    gates_fixture.initialize_task(narrow_runtime)
    gates_fixture.initialize_task(broad_runtime)
    narrow_completion = gates_fixture.completion_context(
        narrow_runtime, "g8-narrow-ceiling-completion",
        contract=ConditionStatus.SATISFIED,
        additional=ConditionStatus.SATISFIED,
        applicability=ConditionStatus.SATISFIED,
    )
    broad_completion = gates_fixture.completion_context(
        broad_runtime, "g8-broad-ceiling-completion",
        contract=ConditionStatus.SATISFIED,
        additional=ConditionStatus.SATISFIED,
        applicability=ConditionStatus.SATISFIED,
    )
    assert narrow_completion.required_protected_operation_ids == ()
    assert broad_completion.required_protected_operation_ids == ()
    assert _evaluate(narrow_runtime, narrow_completion).code is GateResultCode.COMMITTED
    assert _evaluate(broad_runtime, broad_completion).code is GateResultCode.COMMITTED
    assert narrow_runtime.backend.read_task_working_set(gates_fixture.TASK).task.state is TaskState.COMPLETED
    assert broad_runtime.backend.read_task_working_set(gates_fixture.TASK).task.state is TaskState.COMPLETED


def test_g8_14_admitted_evidence_for_old_candidate_is_stale_for_replacement():
    runtime = gates_fixture.runtime()
    gates_fixture.initialize_task(runtime)
    original = gates_fixture.materialize(runtime)
    gates_fixture.adopt_materialization(runtime, original)
    replacement = build_candidate_materialization(
        repository_id=original.repository_id, task_id=original.task_id,
        candidate_id=CandidateId("g8-replacement-candidate"),
        contract_id=original.contract_id,
        contract_raw_sha256=original.contract_raw_sha256,
        authorization_id=original.authorization_id,
        target_registration_id=original.target_registration_id,
        policy_epoch_identity=original.policy_epoch_identity,
        base=original.base, base_tree_id=original.base_tree,
        commit=original.commit, result_tree_id=original.result_tree,
        parent_commits=original.parent_commits, base_tree=(),
        candidate_tree=(gates_fixture.GitTreeEntry(
            gates_fixture.CanonicalGitPath("src/new.py"),
            gates_fixture.GitObjectKind.BLOB, "100644", GitSha("c" * 40),
        ),), materialization_profile_id=original.materialization_profile_id,
    )
    assert ControlStateGate(runtime).commit(
        runtime.boundary.create_candidate_and_adopt(
            task_id=gates_fixture.TASK, materialization=replacement,
            admission_event_id=gates_fixture.ADMISSION,
            decision_event_id=gates_fixture.DecisionEventId("g8-candidate-replacement"),
            parent_candidate_ids=(original.candidate_id,),
        ), gates_fixture.independent_lease(runtime),
    ).code is GateResultCode.COMMITTED
    assert runtime.backend.read_task_working_set(gates_fixture.TASK).task.current_candidate_id == replacement.candidate_id
    admitted = evidence_fixture.admit_semantic_review(
        evidence_fixture.fixture()
    ).proposed_evidence_record
    # The original evidence subject uses the fixture's original CandidateId;
    # apply the actual replacement candidate selected by the G4 lifecycle.
    current = replace(admitted.subject, candidate_id=replacement.candidate_id)
    result = evaluate_evidence_applicability(admitted, current)
    assert (result.decision, result.reason) == (
        EvidenceApplicabilityDecision.STALE,
        EvidenceApplicabilityReason.CANDIDATE_CHANGED,
    )
    assert result.decision is not EvidenceApplicabilityDecision.APPLICABLE
