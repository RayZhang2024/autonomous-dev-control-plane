from dataclasses import FrozenInstanceError, fields, replace
import hashlib
import json

import pytest

from autodev_control.trusted.authorization import (
    AdmittedAuthorization, AuthorizationOperationalConstraints, DelegationAllowance,
    DirectAuthoritySource,
)
from autodev_control.trusted.backend import *
from autodev_control.trusted.evidence import (
    EvidenceClass, EvidenceRecord, EvidenceSubject, SemanticEvidencePayload,
    EvidenceSupersessionRecord, TrustedAdmittedEvidenceRecord,
    TrustedSupersessionAuthorization, build_evidence_supersession_record,
)
from autodev_control.trusted.identity import GitRef, GitSha, ImmutableConfigId, RawSha256
from autodev_control.trusted.manifest import PolicyEpochIdentity, TrustedManifestId
from autodev_control.trusted.operation import (
    AdmissionEventId, AuthoritativeStateBindingId, EvidenceId, IntegrationBound,
    NotIntegrationBound, OperationActionId, OperationEffectClass, OperationId,
    OperationIdempotencyKey, OperationPurpose, OperationRecord, OperationState,
    OperationSubjectId, TrustedOperationClassification,
    construct_trusted_operation_intent,
)
from autodev_control.trusted.review import *
from autodev_control.trusted.scope import (
    AuthenticationEventId, AuthorizationId, AuthorizationKind, ContractId,
    GitHubRepositoryId, HumanPrincipalId, MutationScope, RiskTier, TargetRegistrationId,
    TaskCapability, TaskId,
)
from autodev_control.trusted.state import (
    CandidateRecord, EvidenceBindingRef, RepairBudget, TaskRecord, TaskState,
    initial_task_proposal,
)
from autodev_control.trusted.target_registration import AdmittedTargetRegistration


RAW = RawSha256("6" * 64)
AUTH = AuthorizationId(RAW)
TARGET = TargetRegistrationId(RAW)
TASK = TaskId("task")
CONTRACT = ContractId("contract")
ADMISSION = AdmissionEventId("admission")
EPOCH = PolicyEpochIdentity(TrustedManifestId(RAW))
REPOSITORY = GitHubRepositoryId("123")
BASE = GitSha("a" * 40)


def mint(cls, **values):
    result = object.__new__(cls)
    for name, value in values.items():
        object.__setattr__(result, name, value)
    return result


def admitted_authorization(*, epoch=EPOCH, task_id=TASK):
    empty_ops = AuthorizationOperationalConstraints((), (), 0)
    return mint(
        AdmittedAuthorization,
        authorization_id=AUTH,
        kind=AuthorizationKind.DIRECT_HUMAN,
        authority_source=DirectAuthoritySource(HumanPrincipalId("human"), AuthenticationEventId("auth-event")),
        ancestry=(),
        task_id=task_id,
        contract_id=CONTRACT,
        contract_raw_sha256=RAW,
        target_registration_id=TARGET,
        authorized_capabilities=(TaskCapability.IMPLEMENTATION,),
        authorized_mutation_scope=MutationScope(()),
        authorized_operational_constraints=empty_ops,
        effective_authoritative_risk=RiskTier.ROUTINE,
        authorization_risk_ceiling=RiskTier.ROUTINE,
        delegation=DelegationAllowance(0, (), MutationScope(()), empty_ops, None),
        policy_epoch_identity=epoch,
    )


def resolved_target():
    registration = mint(
        AdmittedTargetRegistration,
        target_registration_id=TARGET,
        repository_id=REPOSITORY,
        policy_epoch_identity=EPOCH,
    )
    return mint(
        ResolvedTargetRegistration,
        registration=registration,
        target_registration_id=TARGET,
        root_config_id=ImmutableConfigId("root-target-config"),
        policy_epoch_identity=EPOCH,
    )


def backend():
    return InMemoryCanonicalStateBackend((resolved_target(),))


def task(*, epoch=EPOCH):
    return initial_task_proposal(
        task_id=TASK, contract_id=CONTRACT, contract_raw_sha256=RAW,
        authorization_id=AUTH, admission_event_id=ADMISSION,
        target_registration_id=TARGET, policy_epoch_identity=epoch,
        repair_budget=RepairBudget(2),
    ).proposed


def classification(effect=OperationEffectClass.PROTECTED_OR_AUTHORITATIVE_EFFECT, purpose=OperationPurpose.NORMAL):
    return mint(TrustedOperationClassification, effect_class=effect, purpose=purpose)


def operation(name="operation", *, candidate_id=None, evidence=(), repair=False, state=OperationState.RESERVED, integration=False):
    intent = construct_trusted_operation_intent(
        classification=classification(), operation_id=OperationId(name),
        idempotency_key=OperationIdempotencyKey(f"key-{name}"), task_id=TASK,
        action_id=OperationActionId("action"), subject_id=OperationSubjectId("subject"),
        candidate_id=candidate_id, contract_id=CONTRACT, contract_raw_sha256=RAW,
        authorization_id=AUTH, admission_event_id=ADMISSION,
        target_registration_id=TARGET, policy_epoch_identity=EPOCH,
        authoritative_state_binding_id=AuthoritativeStateBindingId("state-binding"),
        required_evidence_ids=tuple(evidence),
        integration_binding=IntegrationBound(GitRef("refs/heads/main")) if integration else NotIntegrationBound(),
        is_repair_attempt=repair,
    )
    return OperationRecord(intent, 1, state)


def effective_subject(subject_id="subject"):
    return mint(
        SemanticReviewEffectiveSubject,
        subject_id=SemanticReviewEffectiveSubjectId(subject_id), repository_id=REPOSITORY,
        task_id=TASK, candidate_id=CandidateId("candidate"), contract_id=CONTRACT,
        contract_raw_sha256=RAW, authorization_id=AUTH,
        task_admission_event_id=ADMISSION, target_registration_id=TARGET,
        policy_epoch_identity=EPOCH, base=BASE, target_context_id=TargetContextId("target"),
        pr_id=PullRequestIdentity("pr"), requirement_ids=(), required_material_ids=(),
        required_context_ids=(), composition_rule_id=CompositionRuleId("composition"),
    )


def evidence(subject=None, evidence_id="evidence"):
    subject = subject or effective_subject()
    invocation = ReviewInvocationId("invocation")
    slot = ReviewSlotId("slot")
    evidence_subject = EvidenceSubject(
        REPOSITORY, TASK, CONTRACT, RAW, ADMISSION, AUTH, TARGET, EPOCH,
        subject.candidate_id, BASE, subject.target_context_id, subject.pr_id,
        (), (), (), invocation, slot, ReviewerProfileId("profile"),
        ImmutableConfigId("profile-config"), ImmutableConfigId("schema"),
    )
    payload = SemanticEvidencePayload(
        subject.subject_id, slot, invocation, ReviewEnvelopeId("envelope"),
        ReviewInputManifestId("manifest"), ReviewerProfileId("profile"),
        ImmutableConfigId("profile-config"), ReviewerServiceId("service"),
        OperationId("review-operation"), CanonicalRequestId("request"),
        RawReviewResponseId("response"), (), (), SemanticVerdict.APPROVED,
        ImmutableConfigId("schema"),
    )
    return EvidenceRecord(
        EvidenceId(evidence_id), EvidenceClass.SEMANTIC_REVIEW, evidence_subject,
        EvidenceProducerEventId("producer"), RawReviewResponseId("response"), RAW,
        EvidenceAdmissionEventId("evidence-admission"), payload,
    )


def apply(store, *mutations, conditions=()):
    return store.apply(CanonicalTransaction(store.occurrence, tuple(conditions), tuple(mutations)))


def initialized_backend(*, task_epoch=EPOCH):
    store = backend()
    result = apply(store, CreateAuthorization(admitted_authorization()), CreateTaskAndInitialOperationMembership(task(epoch=task_epoch)))
    assert result.status is CanonicalWriteStatus.APPLIED
    return store


def adopt_canonical_candidate(store):
    candidate = CandidateRecord(CandidateId("candidate"), TASK, BASE, CONTRACT, RAW, AUTH, ADMISSION, TARGET, EPOCH, ())
    evaluating = replace(task(), revision=2, state=TaskState.EVALUATING, current_candidate_id=candidate.candidate_id)
    assert apply(store, ReplaceTask(1, evaluating), CreateCandidate(candidate)).status is CanonicalWriteStatus.APPLIED
    return candidate


def review_ready_backend():
    store = initialized_backend()
    adopt_canonical_candidate(store)
    subject = effective_subject()
    assert apply(store, CreateEvidenceHistory(subject)).status is CanonicalWriteStatus.APPLIED
    membership = store.read_task_working_set(TASK).task_operation_membership
    review_operation = operation("review-operation", candidate_id=subject.candidate_id)
    review_binding = ReviewAttemptBindingRecord(
        subject, ReviewInvocationId("invocation"), ReviewSlotId("slot"),
        review_operation.intent.operation_id, CanonicalRequestId("request"),
    )
    assert apply(
        store,
        CreateSemanticReviewOperationAndBinding(
            review_operation, review_binding, 2, membership.membership_binding_id
        ),
    ).status is CanonicalWriteStatus.APPLIED
    return store, subject


def insert_evidence(store, subject, value):
    history = store.read_review_eligibility_snapshot(subject.subject_id).evidence_history_membership
    record = evidence(subject, value)
    assert apply(
        store,
        CreateEvidenceAndAdvanceHistory(subject, history.membership_binding_id, record),
    ).status is CanonicalWriteStatus.APPLIED
    return record


def test_authorization_create_idempotency_collision_and_generation_rules():
    store = backend()
    before = store.occurrence
    created = apply(store, CreateAuthorization(admitted_authorization()))
    assert created.status is CanonicalWriteStatus.APPLIED
    assert created.canonical_state_occurrence_binding.backend_generation.value == before.backend_generation.value + 1
    assert apply(store, CreateAuthorization(admitted_authorization())).status is CanonicalWriteStatus.ALREADY_PRESENT
    assert store.occurrence == created.canonical_state_occurrence_binding
    conflicting = admitted_authorization(task_id=TaskId("other-task"))
    assert apply(store, CreateAuthorization(conflicting)).status is CanonicalWriteStatus.IDENTITY_CONFLICT
    assert store.occurrence == created.canonical_state_occurrence_binding


def test_task_and_authorization_can_be_mutually_created_in_one_final_graph_transaction():
    store = backend()
    result = apply(store, CreateTaskAndInitialOperationMembership(task()), CreateAuthorization(admitted_authorization()))
    assert result.status is CanonicalWriteStatus.APPLIED
    working = store.read_task_working_set(TASK)
    assert working.task.state is TaskState.ADMITTED
    assert working.task_operation_membership.membership_revision == 1
    assert working.task_operation_membership.operation_ids == ()


def test_task_requires_matching_authorization_and_failed_transaction_publishes_nothing():
    store = backend()
    before = store.occurrence
    assert apply(store, CreateTaskAndInitialOperationMembership(task())).status is CanonicalWriteStatus.INVALID_TRANSACTION
    assert store.occurrence == before
    assert store.read_task_working_set(TASK) is None


def test_task_evaluation_epoch_may_differ_from_authorization_admission_epoch():
    later = PolicyEpochIdentity(TrustedManifestId(RawSha256("7" * 64)))
    store = initialized_backend(task_epoch=later)
    working = store.read_task_working_set(TASK)
    assert working.authorization.policy_epoch_identity == EPOCH
    assert working.task.last_evaluated_policy_epoch_identity == later


def test_operation_create_advances_membership_once_and_content_update_does_not():
    store = initialized_backend()
    before = store.read_task_working_set(TASK)
    op = operation()
    result = apply(store, CreateOperationAndAdvanceMembership(op, 1, before.task_operation_membership.membership_binding_id))
    assert result.status is CanonicalWriteStatus.APPLIED
    after_create = store.read_task_working_set(TASK)
    assert after_create.task_operation_membership.membership_revision == 2
    updated = replace(op, revision=2, state=OperationState.PERFORMING)
    assert apply(store, ReplaceOperation(1, updated)).status is CanonicalWriteStatus.APPLIED
    after_update = store.read_task_working_set(TASK)
    assert after_update.task_operation_membership == after_create.task_operation_membership
    assert after_update.task_operation_snapshot().operations == (updated,)


def test_membership_cannot_omit_any_existing_same_task_operation():
    store = initialized_backend()
    initial = store.read_task_working_set(TASK).task_operation_membership
    op = operation()
    assert apply(store, CreateOperationAndAdvanceMembership(op, 1, initial.membership_binding_id)).status is CanonicalWriteStatus.APPLIED
    with_op = store.read_task_working_set(TASK).task_operation_membership
    assert apply(store, ReplaceTaskOperationMembership(TASK, with_op.membership_binding_id, ())).status is CanonicalWriteStatus.INVALID_TRANSACTION
    returned = store.read_task_working_set(TASK)
    assert returned.task_operation_membership == with_op
    assert returned.task_operation_membership.operation_ids == (op.intent.operation_id,)
    assert returned.operations == (op,)


def test_candidate_and_current_candidate_closure_and_same_transaction_reference():
    store = initialized_backend()
    candidate = CandidateRecord(CandidateId("candidate"), TASK, BASE, CONTRACT, RAW, AUTH, ADMISSION, TARGET, EPOCH, ())
    evaluating = replace(task(), revision=2, state=TaskState.EVALUATING, current_candidate_id=candidate.candidate_id)
    assert apply(store, ReplaceTask(1, evaluating), CreateCandidate(candidate)).status is CanonicalWriteStatus.APPLIED
    assert store.read_task_working_set(TASK).candidate == candidate

    bad = CandidateRecord(CandidateId("bad"), TASK, BASE, ContractId("other"), RAW, AUTH, ADMISSION, TARGET, EPOCH, ())
    assert apply(store, CreateCandidate(bad)).status is CanonicalWriteStatus.INVALID_TRANSACTION


def test_candidate_parent_and_creation_operation_must_resolve():
    store = initialized_backend()
    child = CandidateRecord(CandidateId("child"), TASK, BASE, CONTRACT, RAW, AUTH, ADMISSION, TARGET, EPOCH, (CandidateId("missing"),), OperationId("missing"))
    assert apply(store, CreateCandidate(child)).status is CanonicalWriteStatus.INVALID_TRANSACTION


def test_candidate_parent_and_creation_operation_can_resolve_in_complete_same_transaction_graph():
    store = initialized_backend()
    membership = store.read_task_working_set(TASK).task_operation_membership
    creation = operation("candidate-creation")
    parent = CandidateRecord(CandidateId("parent"), TASK, BASE, CONTRACT, RAW, AUTH, ADMISSION, TARGET, EPOCH, ())
    child = CandidateRecord(CandidateId("child"), TASK, BASE, CONTRACT, RAW, AUTH, ADMISSION, TARGET, EPOCH, (parent.candidate_id,), creation.intent.operation_id)
    assert apply(
        store,
        CreateCandidate(child),
        CreateOperationAndAdvanceMembership(creation, 1, membership.membership_binding_id),
        CreateCandidate(parent),
    ).status is CanonicalWriteStatus.APPLIED


def test_next_integration_and_repair_budget_references_fail_closed_when_dangling():
    store = initialized_backend()
    next_task = replace(task(), revision=2, state=TaskState.INTEGRATION_READY, next_integration_operation_id=OperationId("missing"))
    assert apply(store, ReplaceTask(1, next_task)).status is CanonicalWriteStatus.INVALID_TRANSACTION
    repair_task = replace(task(), revision=2, repair_budget=RepairBudget(2, (OperationId("missing"),), (), ()))
    assert apply(store, ReplaceTask(1, repair_task)).status is CanonicalWriteStatus.INVALID_TRANSACTION


def test_next_integration_and_repair_references_may_be_created_atomically_with_operations():
    integration_store = initialized_backend()
    membership = integration_store.read_task_working_set(TASK).task_operation_membership
    integration = operation("integration", integration=True)
    ready = replace(task(), revision=2, state=TaskState.INTEGRATION_READY, next_integration_operation_id=integration.intent.operation_id)
    assert apply(
        integration_store,
        CreateOperationAndAdvanceMembership(integration, 1, membership.membership_binding_id),
        ReplaceTask(1, ready),
    ).status is CanonicalWriteStatus.APPLIED

    repair_store = initialized_backend()
    membership = repair_store.read_task_working_set(TASK).task_operation_membership
    repair = operation("repair", repair=True)
    reserved = replace(task(), revision=2, repair_budget=RepairBudget(2, (repair.intent.operation_id,), (), ()))
    assert apply(
        repair_store,
        CreateOperationAndAdvanceMembership(repair, 1, membership.membership_binding_id),
        ReplaceTask(1, reserved),
    ).status is CanonicalWriteStatus.APPLIED


def test_operation_required_evidence_must_resolve_and_match_task_candidate():
    store = initialized_backend()
    membership = store.read_task_working_set(TASK).task_operation_membership
    op = operation(evidence=(EvidenceId("missing"),))
    assert apply(store, CreateOperationAndAdvanceMembership(op, 1, membership.membership_binding_id)).status is CanonicalWriteStatus.INVALID_TRANSACTION


def test_supporting_and_operation_required_evidence_resolve_to_exact_canonical_record():
    store, subject = review_ready_backend()
    record = insert_evidence(store, subject, "evidence")
    current = store.read_task_working_set(TASK).task
    supported = replace(
        current, revision=current.revision + 1,
        supporting_evidence_refs=(EvidenceBindingRef(record.evidence_id, subject.candidate_id),),
    )
    assert apply(store, ReplaceTask(current.revision, supported)).status is CanonicalWriteStatus.APPLIED
    membership = store.read_task_working_set(TASK).task_operation_membership
    dependent = operation("dependent", candidate_id=subject.candidate_id, evidence=(record.evidence_id,))
    assert apply(
        store,
        CreateOperationAndAdvanceMembership(dependent, supported.revision, membership.membership_binding_id),
    ).status is CanonicalWriteStatus.APPLIED
    working = store.read_task_working_set(TASK)
    assert working.supporting_evidence == (record,)


def test_empty_evidence_history_identity_collision_and_h0_race():
    store = initialized_backend()
    adopt_canonical_candidate(store)
    subject = effective_subject()
    assert apply(store, CreateEvidenceHistory(subject)).status is CanonicalWriteStatus.APPLIED
    snapshot = store.read_review_eligibility_snapshot(subject.subject_id)
    assert snapshot.evidence_history_membership.membership_revision == 1
    assert snapshot.evidence_history_membership.evidence_ids == ()
    changed_subject = effective_subject()
    object.__setattr__(changed_subject, "base", GitSha("b" * 40))
    assert apply(store, CreateEvidenceHistory(changed_subject)).status is CanonicalWriteStatus.IDENTITY_CONFLICT

    h0 = snapshot.evidence_history_membership.membership_binding_id
    membership = store.read_task_working_set(TASK).task_operation_membership
    review_operation = operation("review-operation", candidate_id=subject.candidate_id)
    review_binding = ReviewAttemptBindingRecord(
        subject, ReviewInvocationId("invocation"), ReviewSlotId("slot"),
        review_operation.intent.operation_id, CanonicalRequestId("request"),
    )
    assert apply(
        store,
        CreateSemanticReviewOperationAndBinding(
            review_operation, review_binding, 2, membership.membership_binding_id
        ),
    ).status is CanonicalWriteStatus.APPLIED
    snapshot = store.read_review_eligibility_snapshot(subject.subject_id)
    h0 = snapshot.evidence_history_membership.membership_binding_id
    first = evidence(subject)
    tx1 = CanonicalTransaction(store.occurrence, (), (CreateEvidenceAndAdvanceHistory(subject, h0, first),))
    tx2 = CanonicalTransaction(store.occurrence, (), (CreateEvidenceAndAdvanceHistory(subject, h0, evidence(subject, "other")),))
    assert store.apply(tx1).status is CanonicalWriteStatus.APPLIED
    assert store.apply(tx2).status is CanonicalWriteStatus.CAS_CONFLICT


def test_semantic_review_operation_membership_and_binding_are_atomic_and_coherent():
    store = initialized_backend()
    adopt_canonical_candidate(store)
    subject = effective_subject()
    assert apply(store, CreateEvidenceHistory(subject)).status is CanonicalWriteStatus.APPLIED
    membership = store.read_task_working_set(TASK).task_operation_membership
    op = operation("review-operation", candidate_id=subject.candidate_id)
    binding = ReviewAttemptBindingRecord(subject, ReviewInvocationId("invocation"), ReviewSlotId("slot"), op.intent.operation_id, CanonicalRequestId("request"))
    result = apply(store, CreateSemanticReviewOperationAndBinding(op, binding, 2, membership.membership_binding_id))
    assert result.status is CanonicalWriteStatus.APPLIED
    snapshot = store.read_review_eligibility_snapshot(subject.subject_id)
    assert snapshot.review_attempt_bindings == (binding,)
    assert snapshot.review_attempt_operations == (op,)
    assert snapshot.g5_evidence_snapshot().canonical_state_occurrence_binding == snapshot.g5_attempt_snapshot().canonical_state_occurrence_binding


def test_review_binding_shared_context_mismatch_is_rejected_atomically():
    store = initialized_backend()
    adopt_canonical_candidate(store)
    subject = effective_subject()
    membership = store.read_task_working_set(TASK).task_operation_membership
    op = operation("review-operation", candidate_id=subject.candidate_id)
    bad_subject = effective_subject()
    object.__setattr__(bad_subject, "authorization_id", AuthorizationId(RawSha256("8" * 64)))
    binding = ReviewAttemptBindingRecord(bad_subject, ReviewInvocationId("invocation"), ReviewSlotId("slot"), op.intent.operation_id, CanonicalRequestId("request"))
    before = store.occurrence
    assert apply(store, CreateSemanticReviewOperationAndBinding(op, binding, 2, membership.membership_binding_id)).status is CanonicalWriteStatus.INVALID_TRANSACTION
    assert store.occurrence == before
    assert store.read_task_working_set(TASK).operations == ()


def test_supersession_requires_preexisting_canonical_evidence_and_preserves_both_records():
    store, subject = review_ready_backend()
    early = insert_evidence(store, subject, "early")
    late = insert_evidence(store, subject, "late")
    history = store.read_review_eligibility_snapshot(subject.subject_id).evidence_history_membership
    early_admitted = mint(TrustedAdmittedEvidenceRecord, record=early, membership_binding=history.membership_binding_id)
    late_admitted = mint(TrustedAdmittedEvidenceRecord, record=late, membership_binding=history.membership_binding_id)
    authorization = mint(
        TrustedSupersessionAuthorization,
        decision_id=SupersessionDecisionId("decision"), subject_id=subject.subject_id,
        policy_epoch_identity=subject.policy_epoch_identity,
        earlier_evidence_id=early.evidence_id, later_evidence_id=late.evidence_id,
        authorized_reason=SupersessionReason.AUTHORIZED_ADJUDICATION,
    )
    relation = build_evidence_supersession_record(early_admitted, late_admitted, authorization)
    assert apply(store, CreateSupersession(relation)).status is CanonicalWriteStatus.APPLIED
    snapshot = store.read_review_eligibility_snapshot(subject.subject_id)
    assert snapshot.canonical_evidence_records == (early, late)

    missing = mint(
        EvidenceSupersessionRecord,
        earlier_evidence_id=EvidenceId("missing"), later_evidence_id=late.evidence_id,
        subject_id=subject.subject_id, policy_epoch_identity=subject.policy_epoch_identity,
        authorized_reason=SupersessionReason.AUTHORIZED_ADJUDICATION,
        decision_id=SupersessionDecisionId("other"), authorization=authorization,
    )
    assert apply(store, CreateSupersession(missing)).status is CanonicalWriteStatus.INVALID_TRANSACTION


def test_coherent_working_set_is_immutable_and_contains_complete_membership():
    store = initialized_backend()
    membership = store.read_task_working_set(TASK).task_operation_membership
    op = operation()
    assert apply(store, CreateOperationAndAdvanceMembership(op, 1, membership.membership_binding_id)).status is CanonicalWriteStatus.APPLIED
    working = store.read_task_working_set(TASK)
    assert working.operations == (op,)
    with pytest.raises(FrozenInstanceError):
        working.operations = ()
    with pytest.raises(TypeError):
        store._state.tasks[TaskId("other")] = task()
    with pytest.raises(AttributeError):
        store._state = None
    assert not hasattr(store, "force_write") and not hasattr(store, "put_any_record")


def canonical_root_for(*typed_records):
    grouped = {kind: [] for kind in CanonicalRecordKind}
    stored = []
    for kind, record in typed_records:
        reference = canonical_object_ref(kind, record)
        grouped[kind].append(CanonicalIndexEntry(canonical_logical_identity(kind, record), reference))
        stored.append(CanonicalStoredObject(reference, canonical_record_bytes(kind, record)))
    indexes = tuple(tuple(sorted(grouped[kind], key=lambda item: item.logical_identity)) for kind in CanonicalRecordKind)
    return CanonicalStateRootManifest("1", None, *indexes), tuple(stored)


def test_root_digest_indexes_and_unrelated_staging_objects():
    payload = task()
    with pytest.raises(TypeError):
        canonical_object_ref(CanonicalRecordKind.TASK, ("caller-label",))
    with pytest.raises(ValueError):
        canonical_object_ref(CanonicalRecordKind.TASK, payload, "2")
    reference = canonical_object_ref(CanonicalRecordKind.TASK, payload)
    entry = CanonicalIndexEntry(canonical_logical_identity(CanonicalRecordKind.TASK, payload), reference)
    manifest = CanonicalStateRootManifest("1", None, (), (entry,), (), (), (), (), (), (), ())
    stored = CanonicalStoredObject(reference, canonical_record_bytes(CanonicalRecordKind.TASK, payload))
    extra_payload = replace(payload, task_id=TaskId("staging"))
    extra_ref = canonical_object_ref(CanonicalRecordKind.TASK, extra_payload)
    extra = CanonicalStoredObject(extra_ref, canonical_record_bytes(CanonicalRecordKind.TASK, extra_payload))
    assert validate_canonical_root_object_integrity(manifest, (stored, extra))
    assert not validate_canonical_root(manifest, (stored, extra), (resolved_target(),))
    assert not validate_canonical_root(manifest, ())
    corrupt = CanonicalStoredObject(reference, b"different")
    assert not validate_canonical_root(manifest, (corrupt,))
    wrong_identity = CanonicalStateRootManifest(
        "1", None, (), (CanonicalIndexEntry("wrong-task", reference),), (), (), (), (), (), (), ()
    )
    assert not validate_canonical_root(wrong_identity, (stored,))
    arbitrary = b'{"format":"autodev.canonical-record/v1", "record":{},"record_kind":"task","schema_version":"1"}'
    arbitrary_ref = CanonicalObjectRef(CanonicalRecordKind.TASK, "1", RawSha256(hashlib.sha256(arbitrary).hexdigest()))
    arbitrary_manifest = CanonicalStateRootManifest(
        "1", None, (), (CanonicalIndexEntry("task", arbitrary_ref),), (), (), (), (), (), (), ()
    )
    assert not validate_canonical_root(arbitrary_manifest, (CanonicalStoredObject(arbitrary_ref, arbitrary),))


def test_root_rejects_incomplete_or_structurally_forged_typed_records():
    valid = task()
    valid_record = json.loads(canonical_record_bytes(CanonicalRecordKind.TASK, valid))["record"]
    logical_identity = canonical_logical_identity(CanonicalRecordKind.TASK, valid)

    def rejected(record, *, wrapper_kind="task", ref_kind=CanonicalRecordKind.TASK, schema="1"):
        wrapper = {
            "format": "autodev.canonical-record/v1", "record": record,
            "record_kind": wrapper_kind, "schema_version": schema,
        }
        raw = json.dumps(wrapper, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
        reference = CanonicalObjectRef(ref_kind, schema, RawSha256(hashlib.sha256(raw).hexdigest()))
        entry = CanonicalIndexEntry(logical_identity, reference)
        indexes = [(), (), (), (), (), (), (), (), ()]
        indexes[1 if ref_kind is CanonicalRecordKind.TASK else 2] = (entry,)
        manifest = CanonicalStateRootManifest("1", None, *indexes)
        assert not validate_canonical_root(manifest, (CanonicalStoredObject(reference, raw),))

    rejected({"task_id": valid_record["task_id"]})
    missing = dict(valid_record)
    missing.pop("contract_id")
    rejected(missing)
    extra = dict(valid_record, caller_label="task")
    rejected(extra)
    wrong_identity_shape = dict(valid_record, task_id=TASK.value)
    rejected(wrong_identity_shape)
    wrong_scalar = dict(valid_record, revision=True)
    rejected(wrong_scalar)
    rejected(valid_record, wrapper_kind="candidate", ref_kind=CanonicalRecordKind.CANDIDATE)
    rejected(valid_record, schema="2")


def test_root_accepts_complete_exact_schema_for_every_supported_v1_record_kind():
    subject = effective_subject()
    op = operation(candidate_id=subject.candidate_id)
    admitted_evidence = evidence(subject)
    earlier, later = EvidenceId("earlier"), EvidenceId("later")
    supersession_authorization = mint(
        TrustedSupersessionAuthorization,
        decision_id=SupersessionDecisionId("decision"), subject_id=subject.subject_id,
        policy_epoch_identity=EPOCH, earlier_evidence_id=earlier,
        later_evidence_id=later,
        authorized_reason=SupersessionReason.AUTHORIZED_ADJUDICATION,
    )
    records = (
        admitted_authorization(),
        task(),
        CandidateRecord(subject.candidate_id, TASK, BASE, CONTRACT, RAW, AUTH, ADMISSION, TARGET, EPOCH, ()),
        op,
        TaskOperationMembershipRecord(TASK, 1, OperationMembershipBindingId("membership"), (op.intent.operation_id,)),
        ReviewAttemptBindingRecord(
            subject, ReviewInvocationId("invocation"), ReviewSlotId("slot"),
            op.intent.operation_id, CanonicalRequestId("request"),
        ),
        admitted_evidence,
        EvidenceHistoryMembershipRecord(
            subject, 1, EvidenceHistoryMembershipBindingId("history"), (admitted_evidence.evidence_id,),
        ),
        mint(
            EvidenceSupersessionRecord, earlier_evidence_id=earlier, later_evidence_id=later,
            subject_id=subject.subject_id, policy_epoch_identity=EPOCH,
            authorized_reason=SupersessionReason.AUTHORIZED_ADJUDICATION,
            decision_id=SupersessionDecisionId("decision"), authorization=supersession_authorization,
        ),
    )
    indexes, stored = [], []
    for kind, record in zip(CanonicalRecordKind, records):
        reference = canonical_object_ref(kind, record)
        indexes.append((CanonicalIndexEntry(canonical_logical_identity(kind, record), reference),))
        stored.append(CanonicalStoredObject(reference, canonical_record_bytes(kind, record)))
    manifest = CanonicalStateRootManifest("1", None, *indexes)
    assert validate_canonical_root_object_integrity(manifest, tuple(stored))
    assert not validate_canonical_root(manifest, tuple(stored), (resolved_target(),))


def test_complete_coherent_reconstructed_root_passes_graph_closure():
    membership = TaskOperationMembershipRecord(TASK, 1, OperationMembershipBindingId("membership"), ())
    manifest, objects = canonical_root_for(
        (CanonicalRecordKind.AUTHORIZATION, admitted_authorization()),
        (CanonicalRecordKind.TASK, task()),
        (CanonicalRecordKind.TASK_OPERATION_MEMBERSHIP, membership),
    )
    assert not validate_canonical_root(manifest, objects)
    assert validate_canonical_root(manifest, objects, (resolved_target(),))


def test_root_rejects_dangling_task_candidate_and_operation_references():
    authorization = admitted_authorization()
    base_task = task()
    empty_membership = TaskOperationMembershipRecord(TASK, 1, OperationMembershipBindingId("membership"), ())

    def rejected(*records):
        manifest, objects = canonical_root_for(*records)
        assert validate_canonical_root_object_integrity(manifest, objects)
        assert not validate_canonical_root(manifest, objects, (resolved_target(),))

    rejected(
        (CanonicalRecordKind.TASK, base_task),
        (CanonicalRecordKind.TASK_OPERATION_MEMBERSHIP, empty_membership),
    )
    rejected(
        (CanonicalRecordKind.AUTHORIZATION, authorization),
        (CanonicalRecordKind.TASK, base_task),
    )
    rejected(
        (CanonicalRecordKind.AUTHORIZATION, authorization),
        (CanonicalRecordKind.TASK, replace(
            base_task, revision=2, state=TaskState.EVALUATING,
            current_candidate_id=CandidateId("missing"),
        )),
        (CanonicalRecordKind.TASK_OPERATION_MEMBERSHIP, empty_membership),
    )
    rejected(
        (CanonicalRecordKind.AUTHORIZATION, authorization),
        (CanonicalRecordKind.TASK, replace(
            base_task, revision=2, state=TaskState.INTEGRATION_READY,
            next_integration_operation_id=OperationId("missing"),
        )),
        (CanonicalRecordKind.TASK_OPERATION_MEMBERSHIP, empty_membership),
    )
    parent_missing = CandidateRecord(
        CandidateId("candidate"), TASK, BASE, CONTRACT, RAW, AUTH, ADMISSION, TARGET, EPOCH,
        (CandidateId("missing-parent"),),
    )
    rejected(
        (CanonicalRecordKind.AUTHORIZATION, authorization),
        (CanonicalRecordKind.TASK, base_task),
        (CanonicalRecordKind.CANDIDATE, parent_missing),
        (CanonicalRecordKind.TASK_OPERATION_MEMBERSHIP, empty_membership),
    )
    creation_missing = CandidateRecord(
        CandidateId("candidate"), TASK, BASE, CONTRACT, RAW, AUTH, ADMISSION, TARGET, EPOCH,
        (), OperationId("missing-creation"),
    )
    rejected(
        (CanonicalRecordKind.AUTHORIZATION, authorization),
        (CanonicalRecordKind.TASK, base_task),
        (CanonicalRecordKind.CANDIDATE, creation_missing),
        (CanonicalRecordKind.TASK_OPERATION_MEMBERSHIP, empty_membership),
    )
    evidence_missing = operation(evidence=(EvidenceId("missing-evidence"),))
    evidence_membership = TaskOperationMembershipRecord(
        TASK, 1, OperationMembershipBindingId("membership"), (evidence_missing.intent.operation_id,),
    )
    rejected(
        (CanonicalRecordKind.AUTHORIZATION, authorization),
        (CanonicalRecordKind.TASK, base_task),
        (CanonicalRecordKind.OPERATION, evidence_missing),
        (CanonicalRecordKind.TASK_OPERATION_MEMBERSHIP, evidence_membership),
    )


def test_root_rejects_incomplete_operation_membership_and_review_binding_closure():
    authorization, base_task, op = admitted_authorization(), task(), operation()
    empty_membership = TaskOperationMembershipRecord(TASK, 1, OperationMembershipBindingId("empty"), ())
    manifest, objects = canonical_root_for(
        (CanonicalRecordKind.AUTHORIZATION, authorization),
        (CanonicalRecordKind.TASK, base_task),
        (CanonicalRecordKind.OPERATION, op),
        (CanonicalRecordKind.TASK_OPERATION_MEMBERSHIP, empty_membership),
    )
    assert not validate_canonical_root(manifest, objects, (resolved_target(),))

    wrong_task_intent = mint(
        type(op.intent),
        **{
            field.name: TaskId("other-task") if field.name == "task_id" else getattr(op.intent, field.name)
            for field in fields(op.intent)
        },
    )
    wrong_task_operation = OperationRecord(wrong_task_intent, 1, OperationState.RESERVED)
    wrong_membership = TaskOperationMembershipRecord(
        TASK, 1, OperationMembershipBindingId("wrong"), (wrong_task_operation.intent.operation_id,),
    )
    manifest, objects = canonical_root_for(
        (CanonicalRecordKind.AUTHORIZATION, authorization),
        (CanonicalRecordKind.TASK, base_task),
        (CanonicalRecordKind.OPERATION, wrong_task_operation),
        (CanonicalRecordKind.TASK_OPERATION_MEMBERSHIP, wrong_membership),
    )
    assert not validate_canonical_root(manifest, objects, (resolved_target(),))

    binding = ReviewAttemptBindingRecord(
        effective_subject(), ReviewInvocationId("invocation"), ReviewSlotId("slot"),
        OperationId("missing-operation"), CanonicalRequestId("request"),
    )
    manifest, objects = canonical_root_for(
        (CanonicalRecordKind.AUTHORIZATION, authorization),
        (CanonicalRecordKind.TASK, base_task),
        (CanonicalRecordKind.TASK_OPERATION_MEMBERSHIP, empty_membership),
        (CanonicalRecordKind.REVIEW_ATTEMPT_BINDING, binding),
    )
    assert not validate_canonical_root(manifest, objects, (resolved_target(),))

    membership = TaskOperationMembershipRecord(
        TASK, 1, OperationMembershipBindingId("operation"), (op.intent.operation_id,),
    )
    mismatched_binding = replace(binding, operation_id=op.intent.operation_id)
    manifest, objects = canonical_root_for(
        (CanonicalRecordKind.AUTHORIZATION, authorization),
        (CanonicalRecordKind.TASK, base_task),
        (CanonicalRecordKind.OPERATION, op),
        (CanonicalRecordKind.TASK_OPERATION_MEMBERSHIP, membership),
        (CanonicalRecordKind.REVIEW_ATTEMPT_BINDING, mismatched_binding),
    )
    assert not validate_canonical_root(manifest, objects, (resolved_target(),))


def test_root_rejects_incomplete_evidence_history_and_supersession_closure():
    authorization, base_task = admitted_authorization(), task()
    subject = effective_subject()
    candidate = CandidateRecord(subject.candidate_id, TASK, BASE, CONTRACT, RAW, AUTH, ADMISSION, TARGET, EPOCH, ())
    empty_membership = TaskOperationMembershipRecord(TASK, 1, OperationMembershipBindingId("empty"), ())
    history_with_missing = EvidenceHistoryMembershipRecord(
        subject, 1, EvidenceHistoryMembershipBindingId("history"), (EvidenceId("missing"),),
    )
    manifest, objects = canonical_root_for(
        (CanonicalRecordKind.AUTHORIZATION, authorization),
        (CanonicalRecordKind.TASK, base_task),
        (CanonicalRecordKind.CANDIDATE, candidate),
        (CanonicalRecordKind.TASK_OPERATION_MEMBERSHIP, empty_membership),
        (CanonicalRecordKind.EVIDENCE_HISTORY, history_with_missing),
    )
    assert not validate_canonical_root(manifest, objects, (resolved_target(),))

    admitted_evidence = evidence(subject)
    review_operation = operation("review-operation", candidate_id=subject.candidate_id)
    membership = TaskOperationMembershipRecord(
        TASK, 1, OperationMembershipBindingId("review"), (review_operation.intent.operation_id,),
    )
    binding = ReviewAttemptBindingRecord(
        subject, admitted_evidence.payload.invocation_id, admitted_evidence.payload.slot_id,
        review_operation.intent.operation_id, admitted_evidence.payload.canonical_request_id,
    )
    empty_history = EvidenceHistoryMembershipRecord(
        subject, 1, EvidenceHistoryMembershipBindingId("history"), (),
    )
    manifest, objects = canonical_root_for(
        (CanonicalRecordKind.AUTHORIZATION, authorization),
        (CanonicalRecordKind.TASK, base_task),
        (CanonicalRecordKind.CANDIDATE, candidate),
        (CanonicalRecordKind.OPERATION, review_operation),
        (CanonicalRecordKind.TASK_OPERATION_MEMBERSHIP, membership),
        (CanonicalRecordKind.REVIEW_ATTEMPT_BINDING, binding),
        (CanonicalRecordKind.EVIDENCE, admitted_evidence),
        (CanonicalRecordKind.EVIDENCE_HISTORY, empty_history),
    )
    assert not validate_canonical_root(manifest, objects, (resolved_target(),))

    earlier, later = EvidenceId("missing-earlier"), EvidenceId("missing-later")
    supersession_authorization = mint(
        TrustedSupersessionAuthorization,
        decision_id=SupersessionDecisionId("decision"), subject_id=subject.subject_id,
        policy_epoch_identity=EPOCH, earlier_evidence_id=earlier,
        later_evidence_id=later, authorized_reason=SupersessionReason.AUTHORIZED_ADJUDICATION,
    )
    supersession = mint(
        EvidenceSupersessionRecord, earlier_evidence_id=earlier, later_evidence_id=later,
        subject_id=subject.subject_id, policy_epoch_identity=EPOCH,
        authorized_reason=SupersessionReason.AUTHORIZED_ADJUDICATION,
        decision_id=SupersessionDecisionId("decision"), authorization=supersession_authorization,
    )
    manifest, objects = canonical_root_for(
        (CanonicalRecordKind.AUTHORIZATION, authorization),
        (CanonicalRecordKind.TASK, base_task),
        (CanonicalRecordKind.TASK_OPERATION_MEMBERSHIP, empty_membership),
        (CanonicalRecordKind.SUPERSESSION, supersession),
    )
    assert not validate_canonical_root(manifest, objects, (resolved_target(),))


@pytest.mark.parametrize("revision", [True, False, 1.0, "1", 0, -1])
def test_all_revision_inputs_require_exact_positive_integers(revision):
    op = operation()
    subject = effective_subject()
    binding = ReviewAttemptBindingRecord(
        subject, ReviewInvocationId("invocation"), ReviewSlotId("slot"),
        op.intent.operation_id, CanonicalRequestId("request"),
    )
    membership = OperationMembershipBindingId("membership")
    constructors = (
        lambda: TaskRevisionEquals(TASK, revision),
        lambda: OperationRevisionEquals(op.intent.operation_id, revision),
        lambda: ReplaceTask(revision, task()),
        lambda: ReplaceOperation(revision, op),
        lambda: CreateOperationAndAdvanceMembership(op, revision, membership),
        lambda: CreateSemanticReviewOperationAndBinding(op, binding, revision, membership),
    )
    for constructor in constructors:
        with pytest.raises((TypeError, ValueError)):
            constructor()


def test_generic_record_conditions_use_closed_namespace_identity_and_record_types():
    with pytest.raises((TypeError, ValueError)):
        RecordAbsent(CanonicalNamespace.TASK, OperationId("task"))
    with pytest.raises((TypeError, ValueError)):
        RecordPresent(CanonicalNamespace.OPERATION, TASK)
    with pytest.raises((TypeError, ValueError)):
        ExactRecordEquals(CanonicalNamespace.TASK, TASK, operation())
    with pytest.raises(ValueError):
        ExactRecordEquals(CanonicalNamespace.TASK, TaskId("other"), task())
    assert ExactRecordEquals(CanonicalNamespace.TASK, TASK, task()).record == task()


def test_apply_rejects_forged_malformed_inputs_without_publishing_partial_state():
    store = initialized_backend()
    before_occurrence = store.occurrence
    before_working = store.read_task_working_set(TASK)
    forged_values = (
        mint(ReplaceTask, expected_revision=True, task=replace(task(), revision=2)),
        mint(CreateCandidate, candidate=task()),
        mint(RecordAbsent, namespace=CanonicalNamespace.TASK, identity=OperationId("task")),
    )
    for forged in forged_values:
        conditions = (forged,) if type(forged) is RecordAbsent else ()
        mutations = () if conditions else (forged,)
        transaction = mint(
            CanonicalTransaction, expected_state_occurrence=store.occurrence,
            conditions=conditions, mutations=mutations,
        )
        result = store.apply(transaction)
        assert result.status is CanonicalWriteStatus.INVALID_TRANSACTION
        assert store.occurrence == before_occurrence
        assert store.read_task_working_set(TASK) == before_working


def test_single_predecessor_commit_and_platform_cas_contract():
    empty = CanonicalStateRootManifest("1", GitSha("a" * 40), (), (), (), (), (), (), (), (), ())
    valid = CanonicalStateCommit(GitSha("b" * 40), empty, (GitSha("a" * 40),))
    assert validate_canonical_state_commit(valid, GitSha("a" * 40))
    merge = CanonicalStateCommit(GitSha("c" * 40), empty, (GitSha("a" * 40), GitSha("d" * 40)))
    assert not validate_canonical_state_commit(merge, GitSha("a" * 40))
    assert evaluate_canonical_ref_update_support(CanonicalRefUpdateCapability(False)) is CanonicalWriteStatus.UNSUPPORTED
    assert evaluate_canonical_ref_update_support(CanonicalRefUpdateCapability(True)) is CanonicalWriteStatus.APPLIED


def test_ambiguous_write_reconciliation_current_historical_competing_and_unknown():
    s0, s1, s2, other = (GitSha(char * 40) for char in "abcd")
    m1 = CanonicalStateRootManifest("1", s0, (), (), (), (), (), (), (), (), ())
    attempted = CanonicalStateCommit(s1, m1, (s0,))
    m2 = CanonicalStateRootManifest("1", s1, (), (), (), (), (), (), (), (), ())
    later = CanonicalStateCommit(s2, m2, (s1,))
    assert reconcile_ambiguous_canonical_write(attempted=attempted, expected_prior=s0, current_root=s1, canonical_history=()) is CanonicalWriteStatus.APPLIED
    assert reconcile_ambiguous_canonical_write(attempted=attempted, expected_prior=s0, current_root=s2, canonical_history=(attempted, later)) is CanonicalWriteStatus.APPLIED
    competing_manifest = CanonicalStateRootManifest("1", s0, (), (), (), (), (), (), (), (), ())
    competing = CanonicalStateCommit(other, competing_manifest, (s0,))
    assert reconcile_ambiguous_canonical_write(attempted=attempted, expected_prior=s0, current_root=other, canonical_history=(competing,)) is CanonicalWriteStatus.INDETERMINATE
    assert reconcile_ambiguous_canonical_write(attempted=attempted, expected_prior=s0, current_root=other, canonical_history=None) is CanonicalWriteStatus.INDETERMINATE
