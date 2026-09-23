"""Issue #29 G5 currentness, composition consumption, and G6 snapshot tests."""

from dataclasses import replace
import json

import pytest

from autodev_control.trusted.backend import (
    CanonicalStateOccurrenceBinding, CreateCandidateWithMaterialization,
    CreateEvidenceAndAdvanceHistory, CreateEvidenceHistory, CreateSupersession,
    CreateSemanticReviewOperationAndBinding, ReplaceTask, ReviewAttemptBindingRecord,
)
from autodev_control.trusted.current_semantic_review import (
    build_current_semantic_evidence_subject, resolve_current_semantic_review,
)
from autodev_control.trusted.evidence import (
    EvidenceClass, SemanticEvidenceCurrentnessStatus, SemanticReviewEvidenceBinding,
    TrustedAdmittedEvidenceRecord, TrustedSupersessionAuthorization,
    build_evidence_supersession_record,
    consume_current_semantic_evidence,
)
from autodev_control.trusted.identity import RawSha256, SemanticEvaluatorObligationId
from autodev_control.trusted.operation import EvidenceId
from autodev_control.trusted.review import (
    CanonicalRequestId, EvidenceHistoryMembershipBindingId, ReviewInvocationId,
    SupersessionDecisionId, SupersessionReason,
)
from autodev_control.trusted.state import ConditionStatus
from tests.trusted.test_backend import apply, mint, operation
from tests.trusted.test_current_semantic_review import (
    _canonical_backend_with_candidate, _candidate,
    _current_applicability_context, _materialization,
    _resolved_product, _semantic_config_bytes, _semantic_contract, _trusted_reader,
)


def _resolved_backend_with_current_evidence(
    evidence_id="current-evidence", verdict_name="approved", *,
    contract=None, config_bytes=None, resolved_target=None,
):
    config_bytes = _semantic_config_bytes() if config_bytes is None else config_bytes
    resolution, contract, materialization = _resolved_product(
        contract=contract, config_bytes=config_bytes,
    )
    candidate = _candidate(materialization, contract=contract)
    store = _canonical_backend_with_candidate(
        contract, candidate, materialization, resolved_target=resolved_target,
    )
    outcome = resolution.obligation_outcomes[0]
    subject = outcome.effective_subject
    assert apply(store, CreateEvidenceHistory(subject)).status.name == "APPLIED"
    slot = outcome.trusted_evaluator_resolution.review_slots[0]
    invocation = ReviewInvocationId("current-invocation")
    working = store.read_task_working_set(subject.task_id)
    review_operation = operation(
        "semantic-evidence-op", candidate_id=subject.candidate_id,
    )
    intent_fields = {name: getattr(review_operation.intent, name)
                     for name in review_operation.intent.__dataclass_fields__}
    intent_fields.update(
        contract_id=subject.contract_id,
        contract_raw_sha256=subject.contract_raw_sha256,
        authorization_id=subject.authorization_id,
        admission_event_id=subject.task_admission_event_id,
        target_registration_id=subject.target_registration_id,
        policy_epoch_identity=subject.policy_epoch_identity,
    )
    review_intent = mint(type(review_operation.intent), **intent_fields)
    review_operation = replace(review_operation, intent=review_intent)
    attempt = ReviewAttemptBindingRecord(
        subject, invocation, slot.slot_id, review_operation.intent.operation_id,
        __import__("autodev_control.trusted.review", fromlist=["CanonicalRequestId"])
        .CanonicalRequestId("request"),
    )
    assert apply(store, CreateSemanticReviewOperationAndBinding(
        review_operation, attempt, working.task.revision,
        working.task_operation_membership.membership_binding_id,
    )).status.name == "APPLIED"
    from autodev_control.trusted.current_semantic_review import build_current_semantic_evidence_subject
    current_subject = build_current_semantic_evidence_subject(
        outcome.resolved_obligation, slot, invocation,
    )
    from tests.trusted.test_evidence import admit_semantic_review, fixture, verdict
    raw = verdict(
        verdict_name,
        overall="approved" if verdict_name == "approved" else verdict_name,
        unable="other" if verdict_name == "unable_to_determine" else None,
    )
    admitted = admit_semantic_review(fixture(raw=raw)).proposed_evidence_record
    payload = replace(
        admitted.payload,
        effective_subject_id=subject.subject_id,
        slot_id=slot.slot_id,
        invocation_id=invocation,
        profile_id=slot.profile.profile_id,
        profile_config_id=slot.profile.config_id,
        service_id=slot.profile.service_id,
        verdict_schema_id=slot.profile.verdict_schema_id,
        operation_id=review_operation.intent.operation_id,
        requirement_results=tuple(replace(
            item, requirement_id=subject.requirement_ids[0]
        ) for item in admitted.payload.requirement_results),
        aggregate=admitted.payload.aggregate,
    )
    record = replace(
        admitted, evidence_id=EvidenceId(evidence_id), subject=current_subject,
        payload=payload,
    )
    history = store.read_review_eligibility_snapshot(subject.subject_id).evidence_history_membership
    assert apply(store, CreateEvidenceAndAdvanceHistory(
        subject, history.membership_binding_id, record,
    )).status.name == "APPLIED"
    inputs = store.read_current_semantic_review_inputs(subject.task_id)
    context = __import__(
        "tests.trusted.test_current_semantic_review", fromlist=["_current_applicability_context"]
    )._current_applicability_context(contract)
    result = resolve_current_semantic_review(
        inputs, applicability_context=context,
        byte_reader=__import__(
            "tests.trusted.test_current_semantic_review", fromlist=["_trusted_reader"]
        )._trusted_reader(contract, config_bytes),
        semantic_context_source=None,
    )
    assert result.status.name == "RESOLVED"
    return store, result, record, subject


def _append_superseding_approved_evidence(store, resolution, earlier, effective_subject):
    outcome = resolution.obligation_outcomes[0]
    slot = outcome.trusted_evaluator_resolution.review_slots[0]
    later_invocation = ReviewInvocationId("later-current-invocation")
    later_subject = build_current_semantic_evidence_subject(
        outcome.resolved_obligation, slot, later_invocation,
    )
    operation_id = type(earlier.payload.operation_id)("later-semantic-evidence-op")
    working = store.read_task_working_set(effective_subject.task_id)
    later_operation = operation(
        operation_id.value, candidate_id=effective_subject.candidate_id,
    )
    intent_values = {
        name: getattr(later_operation.intent, name)
        for name in later_operation.intent.__dataclass_fields__
    }
    intent_values.update(
        contract_id=effective_subject.contract_id,
        contract_raw_sha256=effective_subject.contract_raw_sha256,
        authorization_id=effective_subject.authorization_id,
        admission_event_id=effective_subject.task_admission_event_id,
        target_registration_id=effective_subject.target_registration_id,
        policy_epoch_identity=effective_subject.policy_epoch_identity,
    )
    later_operation = replace(later_operation, intent=mint(type(later_operation.intent), **intent_values))
    request_id = CanonicalRequestId("later-canonical-request")
    attempt = ReviewAttemptBindingRecord(
        effective_subject, later_invocation, slot.slot_id, operation_id, request_id,
    )
    assert apply(store, CreateSemanticReviewOperationAndBinding(
        later_operation, attempt, working.task.revision,
        working.task_operation_membership.membership_binding_id,
    )).status.name == "APPLIED"
    later = replace(
        earlier, evidence_id=EvidenceId("later-approved-evidence"),
        subject=later_subject,
        payload=replace(
            earlier.payload, invocation_id=later_invocation,
            operation_id=operation_id, canonical_request_id=request_id,
        ),
    )
    history = store.read_review_eligibility_snapshot(effective_subject.subject_id)
    assert history is not None
    assert apply(store, CreateEvidenceAndAdvanceHistory(
        effective_subject, history.evidence_history_membership.membership_binding_id,
        later,
    )).status.name == "APPLIED"
    authorization = mint(
        TrustedSupersessionAuthorization,
        decision_id=SupersessionDecisionId("trusted-supersession-decision"),
        subject_id=effective_subject.subject_id,
        policy_epoch_identity=effective_subject.policy_epoch_identity,
        earlier_evidence_id=earlier.evidence_id,
        later_evidence_id=later.evidence_id,
        authorized_reason=SupersessionReason.AUTHORIZED_ADJUDICATION,
    )
    relation = build_evidence_supersession_record(
        mint(TrustedAdmittedEvidenceRecord, record=earlier,
             membership_binding=EvidenceHistoryMembershipBindingId("earlier")),
        mint(TrustedAdmittedEvidenceRecord, record=later,
             membership_binding=EvidenceHistoryMembershipBindingId("later")),
        authorization,
    )
    assert apply(store, CreateSupersession(relation)).status.name == "APPLIED"
    return later


def _two_required_slot_config_bytes():
    value = json.loads(_semantic_config_bytes())
    second = json.loads(json.dumps(value["review_slots"][0]))
    second["slot_id"] = "slot-b"
    second["independence_binding_sha256"] = "b" * 64
    second["profile"].update(
        profile_id="profile-b", service_id="service-b",
        verdict_schema_id="schema-b", rereview_policy_id="rereview-b",
        disclosure_policy_id="disclosure-b",
    )
    value["review_slots"].append(second)
    value["composition"] = {
        "composition_rule_id": "composition-two-slots",
        "mode": "ALL_REQUIRED_INVOCATIONS",
        "required_slot_ids": ["slot-a", "slot-b"],
    }
    return json.dumps(value, separators=(",", ":")).encode()


def _append_second_slot_approved_evidence(store, resolution, first, effective_subject):
    outcome = resolution.obligation_outcomes[0]
    slot = outcome.trusted_evaluator_resolution.review_slots[1]
    invocation = ReviewInvocationId("second-slot-current-invocation")
    subject = build_current_semantic_evidence_subject(
        outcome.resolved_obligation, slot, invocation,
    )
    operation_id = type(first.payload.operation_id)("second-slot-semantic-evidence-op")
    working = store.read_task_working_set(effective_subject.task_id)
    review_operation = operation(
        operation_id.value, candidate_id=effective_subject.candidate_id,
    )
    intent_values = {
        name: getattr(review_operation.intent, name)
        for name in review_operation.intent.__dataclass_fields__
    }
    intent_values.update(
        contract_id=effective_subject.contract_id,
        contract_raw_sha256=effective_subject.contract_raw_sha256,
        authorization_id=effective_subject.authorization_id,
        admission_event_id=effective_subject.task_admission_event_id,
        target_registration_id=effective_subject.target_registration_id,
        policy_epoch_identity=effective_subject.policy_epoch_identity,
    )
    review_operation = replace(
        review_operation, intent=mint(type(review_operation.intent), **intent_values),
    )
    request_id = CanonicalRequestId("second-slot-canonical-request")
    attempt = ReviewAttemptBindingRecord(
        effective_subject, invocation, slot.slot_id, operation_id, request_id,
    )
    assert apply(store, CreateSemanticReviewOperationAndBinding(
        review_operation, attempt, working.task.revision,
        working.task_operation_membership.membership_binding_id,
    )).status.name == "APPLIED"
    second = replace(
        first, evidence_id=EvidenceId("second-slot-approved-evidence"),
        subject=subject,
        payload=replace(
            first.payload, invocation_id=invocation, slot_id=slot.slot_id,
            profile_id=slot.profile.profile_id,
            profile_config_id=slot.profile.config_id,
            service_id=slot.profile.service_id,
            verdict_schema_id=slot.profile.verdict_schema_id,
            operation_id=operation_id, canonical_request_id=request_id,
        ),
    )
    history = store.read_review_eligibility_snapshot(effective_subject.subject_id)
    assert history is not None
    assert apply(store, CreateEvidenceAndAdvanceHistory(
        effective_subject,
        history.evidence_history_membership.membership_binding_id,
        second,
    )).status.name == "APPLIED"
    return second


def test_g6_semantic_snapshot_returns_complete_history_and_exact_missing_lookup():
    store, resolution, record, subject = _resolved_backend_with_current_evidence()
    occurrence = store.occurrence
    snapshot = store.read_semantic_consumption_snapshot(
        subject.task_id, occurrence, (subject.subject_id,),
        (record.evidence_id, EvidenceId("not-found")),
    )
    assert snapshot is not None
    assert snapshot.canonical_state_occurrence_binding == occurrence
    assert tuple(item.subject_id for item in snapshot.histories) == (subject.subject_id,)
    assert tuple(item.evidence_id for item in snapshot.histories[0].records) == (
        record.evidence_id,
    )
    assert tuple(item.record for item in snapshot.requested_evidence) == (
        record, None,
    )
    result = consume_current_semantic_evidence(
        resolution, snapshot, (record.evidence_id, EvidenceId("not-found")),
        current_contract=store.read_contract(subject.contract_id),
    )
    assert result.contract_status is ConditionStatus.SATISFIED
    assert result.obligation_results[0].status is ConditionStatus.SATISFIED
    assert result.obligation_results[0].progression_support_evidence_ids == (
        record.evidence_id,
    )
    assert tuple(item.status for item in result.evidence_currentness) == (
        SemanticEvidenceCurrentnessStatus.CURRENT,
        SemanticEvidenceCurrentnessStatus.NOT_FOUND,
    )


def _append_canonical_nonsemantic_evidence(store, resolution, record):
    subject = resolution.obligation_outcomes[0].effective_subject
    outcome = resolution.obligation_outcomes[0]
    slot = outcome.trusted_evaluator_resolution.review_slots[0]
    effective = mint(
        type(subject),
        **{
            **{name: getattr(subject, name) for name in subject.__dataclass_fields__},
            "subject_id": type(subject.subject_id)("nonsemantic-history-subject"),
        },
    )
    invocation = ReviewInvocationId("nonsemantic-invocation")
    review_operation = operation(
        "nonsemantic-canonical-evidence-op", candidate_id=subject.candidate_id,
    )
    intent_fields = {
        name: getattr(review_operation.intent, name)
        for name in review_operation.intent.__dataclass_fields__
    }
    intent_fields.update(
        contract_id=subject.contract_id,
        contract_raw_sha256=subject.contract_raw_sha256,
        authorization_id=subject.authorization_id,
        admission_event_id=subject.task_admission_event_id,
        target_registration_id=subject.target_registration_id,
        policy_epoch_identity=subject.policy_epoch_identity,
    )
    review_operation = replace(
        review_operation, intent=mint(type(review_operation.intent), **intent_fields),
    )
    request_id = CanonicalRequestId("nonsemantic-request")
    attempt = ReviewAttemptBindingRecord(
        effective, invocation, slot.slot_id, review_operation.intent.operation_id,
        request_id,
    )
    working = store.read_task_working_set(subject.task_id)
    assert apply(store, CreateEvidenceHistory(effective)).status.name == "APPLIED"
    assert apply(store, CreateSemanticReviewOperationAndBinding(
        review_operation, attempt, working.task.revision,
        working.task_operation_membership.membership_binding_id,
    )).status.name == "APPLIED"
    evidence_subject = replace(
        record.subject,
        invocation_id=invocation,
        semantic_review_binding=None,
    )
    nonsemantic = replace(
        record, evidence_id=EvidenceId("canonical-deterministic-evidence"),
        evidence_class=EvidenceClass.DETERMINISTIC,
        subject=evidence_subject,
        payload=replace(
            record.payload, effective_subject_id=effective.subject_id,
            invocation_id=invocation, operation_id=review_operation.intent.operation_id,
            canonical_request_id=request_id,
        ),
    )
    history = store.read_review_eligibility_snapshot(effective.subject_id)
    assert history is not None
    assert apply(store, CreateEvidenceAndAdvanceHistory(
        effective, history.evidence_history_membership.membership_binding_id,
        nonsemantic,
    )).status.name == "APPLIED"
    return nonsemantic


@pytest.mark.parametrize("unresolved_state", ("not_applicable", "indeterminate"))
def test_unresolved_semantic_resolution_preserves_structural_evidence_classification(
    unresolved_state,
):
    store, initial_resolution, record, subject = _resolved_backend_with_current_evidence()
    nonsemantic = _append_canonical_nonsemantic_evidence(
        store, initial_resolution, record,
    )
    contract = store.read_contract(subject.contract_id)
    inputs = store.read_current_semantic_review_inputs(subject.task_id)
    context = _current_applicability_context(contract)
    reader = _trusted_reader(contract, _semantic_config_bytes())
    if unresolved_state == "not_applicable":
        moved_base = mint(
            type(context.base_observation),
            **{
                **{name: getattr(context.base_observation, name)
                   for name in context.base_observation.__dataclass_fields__},
                "sha": type(contract.base_sha)("d" * 40),
            },
        )
        context = mint(
            type(context),
            **{
                **{name: getattr(context, name) for name in context.__dataclass_fields__},
                "base_observation": moved_base,
            },
        )
    else:
        reader = None
    resolution = resolve_current_semantic_review(
        inputs, applicability_context=context, byte_reader=reader,
        semantic_context_source=None,
    )
    assert resolution.status.name == (
        "NOT_APPLICABLE" if unresolved_state == "not_applicable" else "INDETERMINATE"
    )
    current_subject_ids = tuple(
        item.effective_subject.subject_id for item in resolution.obligation_outcomes
        if resolution.status.name == "RESOLVED" and item.effective_subject is not None
    )
    missing_id = EvidenceId("absent-under-unresolved-review")
    snapshot = store.read_semantic_consumption_snapshot(
        subject.task_id, inputs.canonical_state_occurrence_binding, current_subject_ids,
        (nonsemantic.evidence_id, missing_id),
    )
    assert snapshot is not None
    result = consume_current_semantic_evidence(
        resolution, snapshot, (nonsemantic.evidence_id, missing_id),
        current_contract=contract,
    )
    assert tuple(item.status for item in result.evidence_currentness) == (
        SemanticEvidenceCurrentnessStatus.NOT_SEMANTIC,
        SemanticEvidenceCurrentnessStatus.NOT_FOUND,
    )
    assert tuple(item.reason.name for item in result.evidence_currentness) == (
        "NOT_SEMANTIC", "NOT_FOUND",
    )


def test_two_evaluator_obligations_remain_independent_for_contract_aggregate_and_support():
    config_bytes = _semantic_config_bytes()
    contract, _, _ = _semantic_contract(
        config_bytes=config_bytes, extra_evaluation_ids=("evaluation-two",),
    )
    store, resolution, first_record, _ = _resolved_backend_with_current_evidence(
        contract=contract, config_bytes=config_bytes,
    )
    assert len(resolution.obligation_outcomes) == 2
    assert resolution.obligation_outcomes[0].obligation_id != resolution.obligation_outcomes[1].obligation_id
    subject_ids = tuple(
        item.effective_subject.subject_id for item in resolution.obligation_outcomes
    )
    snapshot = store.read_semantic_consumption_snapshot(
        first_record.subject.task_id, resolution.occurrence, subject_ids,
        (first_record.evidence_id,),
    )
    assert snapshot is not None
    result = consume_current_semantic_evidence(
        resolution, snapshot, (first_record.evidence_id,), current_contract=contract,
    )
    assert tuple(item.status for item in result.obligation_results) == (
        ConditionStatus.SATISFIED, ConditionStatus.UNSATISFIED,
    )
    assert result.obligation_results[0].progression_support_evidence_ids == (
        first_record.evidence_id,
    )
    assert result.obligation_results[1].progression_support_evidence_ids == ()
    assert result.contract_status is ConditionStatus.UNSATISFIED


@pytest.mark.parametrize(("verdict_name", "expected"), [
    ("changes_required", ConditionStatus.UNSATISFIED),
    ("unable_to_determine", ConditionStatus.INDETERMINATE),
])
def test_negative_or_indeterminate_semantics_never_provide_progression_support(
    verdict_name, expected,
):
    store, resolution, record, subject = _resolved_backend_with_current_evidence(
        verdict_name=verdict_name,
    )
    snapshot = store.read_semantic_consumption_snapshot(
        subject.task_id, store.occurrence, (subject.subject_id,),
        (record.evidence_id,),
    )
    result = consume_current_semantic_evidence(
        resolution, snapshot, (record.evidence_id,),
        current_contract=store.read_contract(subject.contract_id),
    )
    assert result.contract_status is expected
    assert result.obligation_results[0].status is expected
    assert result.obligation_results[0].progression_support_evidence_ids == ()
    # Freshness is orthogonal to approval: a current negative record can be
    # suitable for a non-forward operation without becoming support.
    assert result.evidence_currentness[0].status is SemanticEvidenceCurrentnessStatus.CURRENT


def test_g6_semantic_snapshot_rejects_occurrence_movement_and_favorable_subset():
    store, resolution, record, subject = _resolved_backend_with_current_evidence()
    old = store.occurrence
    # G5 refuses a subset that does not equal the complete #32 RESOLVED view.
    subset = store.read_semantic_consumption_snapshot(
        subject.task_id, old, (), (record.evidence_id,),
    )
    assert subset is not None
    rejected = consume_current_semantic_evidence(
        resolution, subset, (record.evidence_id,),
        current_contract=store.read_contract(subject.contract_id),
    )
    assert rejected.contract_status is ConditionStatus.INDETERMINATE
    assert rejected.obligation_results == ()
    # The facts boundary is fenced before touching any returned evidence.
    second_fields = {name: getattr(subject, name) for name in subject.__dataclass_fields__}
    second_fields["subject_id"] = type(subject.subject_id)("another-current-subject")
    second = mint(type(subject), **second_fields)
    assert apply(store, CreateEvidenceHistory(second)).status.name == "APPLIED"
    assert store.read_semantic_consumption_snapshot(
        subject.task_id, old, (subject.subject_id,), (record.evidence_id,),
    ) is None


def test_resolved_obligation_with_exact_absent_history_is_unsatisfied():
    _, contract, materialization = _resolved_product()
    candidate = _candidate(materialization, contract=contract)
    store = _canonical_backend_with_candidate(contract, candidate, materialization)
    inputs = store.read_current_semantic_review_inputs(candidate.task_id)
    assert inputs is not None
    resolution = resolve_current_semantic_review(
        inputs,
        applicability_context=_current_applicability_context(contract),
        byte_reader=_trusted_reader(contract, _semantic_config_bytes()),
        semantic_context_source=None,
    )
    assert resolution.status.name == "RESOLVED"
    subject_id = resolution.obligation_outcomes[0].effective_subject.subject_id
    snapshot = store.read_semantic_consumption_snapshot(
        candidate.task_id, inputs.canonical_state_occurrence_binding,
        (subject_id,), (),
    )
    assert snapshot is not None
    assert snapshot.histories[0].history is None
    result = consume_current_semantic_evidence(
        resolution, snapshot, (), current_contract=contract,
    )
    assert result.contract_status is ConditionStatus.UNSATISFIED
    assert len(result.obligation_results) == 1
    assert result.obligation_results[0].status is ConditionStatus.UNSATISFIED
    assert result.obligation_results[0].composition_result is None
    assert result.obligation_results[0].progression_support_evidence_ids == ()


def test_complete_approved_multislot_composition_exposes_exact_ordered_support():
    config_bytes = _two_required_slot_config_bytes()
    contract, _, _ = _semantic_contract(config_bytes=config_bytes)
    store, resolution, first, subject = _resolved_backend_with_current_evidence(
        contract=contract, config_bytes=config_bytes,
    )
    second = _append_second_slot_approved_evidence(
        store, resolution, first, subject,
    )
    inputs = store.read_current_semantic_review_inputs(subject.task_id)
    resolution = resolve_current_semantic_review(
        inputs,
        applicability_context=_current_applicability_context(contract),
        byte_reader=_trusted_reader(contract, config_bytes),
        semantic_context_source=None,
    )
    slots = resolution.obligation_outcomes[0].resolved_obligation.assignment.composition_rule.required_slots
    snapshot = store.read_semantic_consumption_snapshot(
        subject.task_id, store.occurrence, (subject.subject_id,),
        (first.evidence_id, second.evidence_id),
    )
    result = consume_current_semantic_evidence(
        resolution, snapshot, (first.evidence_id, second.evidence_id),
        current_contract=contract,
    )
    obligation = result.obligation_results[0]
    assert tuple(item.slot_id for item in slots) == tuple(
        item.payload.slot_id for item in (first, second)
    )
    assert obligation.status is ConditionStatus.SATISFIED
    assert obligation.progression_support_evidence_ids == (
        first.evidence_id, second.evidence_id,
    )
    assert tuple(item.status for item in result.evidence_currentness) == (
        SemanticEvidenceCurrentnessStatus.CURRENT,
        SemanticEvidenceCurrentnessStatus.CURRENT,
    )


def test_partial_multislot_history_is_unsatisfied_without_progression_support():
    config_bytes = _two_required_slot_config_bytes()
    contract, _, _ = _semantic_contract(config_bytes=config_bytes)
    store, resolution, _, subject = _resolved_backend_with_current_evidence(
        contract=contract, config_bytes=config_bytes,
    )
    snapshot = store.read_semantic_consumption_snapshot(
        subject.task_id, store.occurrence, (subject.subject_id,), (),
    )
    result = consume_current_semantic_evidence(
        resolution, snapshot, (), current_contract=contract,
    )
    obligation = result.obligation_results[0]
    assert obligation.composition_result.reason.name == "REQUIRED_SLOT_MISSING"
    assert obligation.status is ConditionStatus.UNSATISFIED
    assert obligation.progression_support_evidence_ids == ()


def test_conflicting_applicable_evidence_is_indeterminate_without_progression_support():
    from autodev_control.trusted.evidence import SemanticVerdict

    store, resolution, approved, effective_subject = _resolved_backend_with_current_evidence()
    outcome = resolution.obligation_outcomes[0]
    slot = outcome.trusted_evaluator_resolution.review_slots[0]
    invocation = ReviewInvocationId("conflicting-current-invocation")
    subject = build_current_semantic_evidence_subject(
        outcome.resolved_obligation, slot, invocation,
    )
    working = store.read_task_working_set(effective_subject.task_id)
    operation_id = type(approved.payload.operation_id)("conflicting-semantic-op")
    review_operation = operation(
        operation_id.value, candidate_id=effective_subject.candidate_id,
    )
    intent_values = {
        name: getattr(review_operation.intent, name)
        for name in review_operation.intent.__dataclass_fields__
    }
    intent_values.update(
        contract_id=effective_subject.contract_id,
        contract_raw_sha256=effective_subject.contract_raw_sha256,
        authorization_id=effective_subject.authorization_id,
        admission_event_id=effective_subject.task_admission_event_id,
        target_registration_id=effective_subject.target_registration_id,
        policy_epoch_identity=effective_subject.policy_epoch_identity,
    )
    review_operation = replace(
        review_operation, intent=mint(type(review_operation.intent), **intent_values),
    )
    request_id = CanonicalRequestId("conflicting-semantic-request")
    attempt = ReviewAttemptBindingRecord(
        effective_subject, invocation, slot.slot_id, operation_id, request_id,
    )
    assert apply(store, CreateSemanticReviewOperationAndBinding(
        review_operation, attempt, working.task.revision,
        working.task_operation_membership.membership_binding_id,
    )).status.name == "APPLIED"
    negative_result = replace(
        approved.payload.requirement_results[0],
        verdict=SemanticVerdict.CHANGES_REQUIRED,
        unable_reason_code=None,
    )
    conflicting = replace(
        approved,
        evidence_id=EvidenceId("conflicting-semantic-evidence"),
        subject=subject,
        payload=replace(
            approved.payload,
            invocation_id=invocation,
            operation_id=operation_id,
            canonical_request_id=request_id,
            requirement_results=(negative_result,),
            aggregate=SemanticVerdict.CHANGES_REQUIRED,
        ),
    )
    history = store.read_review_eligibility_snapshot(effective_subject.subject_id)
    assert history is not None
    assert apply(store, CreateEvidenceAndAdvanceHistory(
        effective_subject,
        history.evidence_history_membership.membership_binding_id,
        conflicting,
    )).status.name == "APPLIED"

    current_inputs = store.read_current_semantic_review_inputs(effective_subject.task_id)
    current_resolution = resolve_current_semantic_review(
        current_inputs,
        applicability_context=_current_applicability_context(
            store.read_contract(effective_subject.contract_id),
        ),
        byte_reader=_trusted_reader(
            store.read_contract(effective_subject.contract_id),
            _semantic_config_bytes(),
        ),
        semantic_context_source=None,
    )
    snapshot = store.read_semantic_consumption_snapshot(
        effective_subject.task_id,
        current_inputs.canonical_state_occurrence_binding,
        (effective_subject.subject_id,),
        (approved.evidence_id, conflicting.evidence_id),
    )
    consumed = consume_current_semantic_evidence(
        current_resolution, snapshot,
        (approved.evidence_id, conflicting.evidence_id),
        current_contract=store.read_contract(effective_subject.contract_id),
    )
    obligation = consumed.obligation_results[0]
    assert obligation.composition_result.reason.name == "CONFLICTING_APPLICABLE_EVIDENCE"
    assert obligation.status is ConditionStatus.INDETERMINATE
    assert obligation.progression_support_evidence_ids == ()
    assert consumed.contract_status is ConditionStatus.INDETERMINATE


def test_current_contract_schema_epoch_mismatch_is_stale_with_exact_g1_diagnostic():
    store, _, record, subject = _resolved_backend_with_current_evidence()
    contract = store.read_contract(subject.contract_id)
    inputs = store.read_current_semantic_review_inputs(subject.task_id)
    assert inputs is not None
    context = _current_applicability_context(contract)
    old_epoch = replace(
        context.schema_binding.policy_epoch_identity,
        manifest_id=type(context.schema_binding.policy_epoch_identity.manifest_id)(
            type(context.schema_binding.policy_epoch_identity.manifest_id.raw_sha256)("d" * 64)
        ),
    )
    stale_schema_binding = mint(
        type(context.schema_binding),
        **{
            **{name: getattr(context.schema_binding, name)
               for name in context.schema_binding.__dataclass_fields__},
            "policy_epoch_identity": old_epoch,
        },
    )
    stale_context = mint(
        type(context),
        **{
            **{name: getattr(context, name) for name in context.__dataclass_fields__},
            "schema_binding": stale_schema_binding,
        },
    )
    resolution = resolve_current_semantic_review(
        inputs, applicability_context=stale_context,
        byte_reader=_trusted_reader(contract, _semantic_config_bytes()),
        semantic_context_source=None,
    )
    assert resolution.status.name == "NOT_APPLICABLE"
    assert resolution.applicability_code is not None
    snapshot = store.read_semantic_consumption_snapshot(
        subject.task_id, inputs.canonical_state_occurrence_binding, (),
        (record.evidence_id,),
    )
    assert snapshot is not None
    result = consume_current_semantic_evidence(
        resolution, snapshot, (record.evidence_id,),
        current_contract=contract,
    )
    assert result.contract_status is ConditionStatus.INDETERMINATE
    currentness = result.evidence_currentness[0]
    assert currentness.status is SemanticEvidenceCurrentnessStatus.STALE
    assert currentness.applicability_code is resolution.applicability_code


def test_current_contract_base_observation_movement_is_stale_with_exact_g1_diagnostic():
    store, _, record, subject = _resolved_backend_with_current_evidence()
    contract = store.read_contract(subject.contract_id)
    context = _current_applicability_context(contract)
    moved_base = mint(
        type(context.base_observation),
        **{
            **{name: getattr(context.base_observation, name)
               for name in context.base_observation.__dataclass_fields__},
            "sha": type(contract.base_sha)("d" * 40),
        },
    )
    moved_context = mint(
        type(context),
        **{
            **{name: getattr(context, name) for name in context.__dataclass_fields__},
            "base_observation": moved_base,
        },
    )
    inputs = store.read_current_semantic_review_inputs(subject.task_id)
    resolution = resolve_current_semantic_review(
        inputs, applicability_context=moved_context,
        byte_reader=_trusted_reader(contract, _semantic_config_bytes()),
        semantic_context_source=None,
    )
    assert resolution.status.name == "NOT_APPLICABLE"
    snapshot = store.read_semantic_consumption_snapshot(
        subject.task_id, inputs.canonical_state_occurrence_binding,
        (), (record.evidence_id,),
    )
    result = consume_current_semantic_evidence(
        resolution, snapshot, (record.evidence_id,), current_contract=contract,
    )
    currentness = result.evidence_currentness[0]
    assert currentness.status is SemanticEvidenceCurrentnessStatus.STALE
    assert resolution.applicability_code is not None
    assert currentness.applicability_code is resolution.applicability_code
    assert result.obligation_results == ()


@pytest.mark.parametrize(("dimension", "expected_reason"), [
    ("target", "TARGET_CONTEXT_CHANGED"),
    ("pr", "PULL_REQUEST_CHANGED"),
])
def test_current_target_or_pr_context_movement_makes_exact_evidence_stale(
    monkeypatch, dimension, expected_reason,
):
    import autodev_control.trusted.current_semantic_review as resolver_module
    from tests.trusted.test_current_semantic_review import _pr_success, _target_success

    config_bytes = _semantic_config_bytes(
        target="REQUIRED" if dimension == "target" else "NOT_APPLICABLE",
        pr="REQUIRED" if dimension == "pr" else "NOT_APPLICABLE",
    )
    contract, _, _ = _semantic_contract(config_bytes=config_bytes)
    if dimension == "target":
        monkeypatch.setattr(
            resolver_module, "resolve_current_semantic_target_context",
            lambda *_: _target_success(),
        )
        monkeypatch.setattr(
            resolver_module, "resolve_current_semantic_pull_request_context",
            lambda *_: pytest.fail("PR context is not required for target-only evidence"),
        )
    else:
        monkeypatch.setattr(
            resolver_module, "resolve_current_semantic_target_context",
            lambda *_: pytest.fail("target context is not required for PR-only evidence"),
        )
        monkeypatch.setattr(
            resolver_module, "resolve_current_semantic_pull_request_context",
            lambda *_: _pr_success(),
        )
    store, _, record, historical_subject = _resolved_backend_with_current_evidence(
        contract=contract, config_bytes=config_bytes,
    )

    if dimension == "target":
        monkeypatch.setattr(
            resolver_module, "resolve_current_semantic_target_context",
            lambda *_: replace(_target_success(), target_context_id=type(
                _target_success().target_context_id,
            )("target-context-moved")),
        )
    else:
        monkeypatch.setattr(
            resolver_module, "resolve_current_semantic_pull_request_context",
            lambda *_: replace(_pr_success(), pull_request_identity=type(
                _pr_success().pull_request_identity,
            )("pr-context-moved")),
        )

    current_contract = store.read_contract(historical_subject.contract_id)
    current_inputs = store.read_current_semantic_review_inputs(historical_subject.task_id)
    current_resolution = resolver_module.resolve_current_semantic_review(
        current_inputs,
        applicability_context=_current_applicability_context(current_contract),
        byte_reader=_trusted_reader(current_contract, config_bytes),
        semantic_context_source=None,
    )
    complete_current_subject_ids = tuple(
        outcome.effective_subject.subject_id
        for outcome in current_resolution.obligation_outcomes
    )
    snapshot = store.read_semantic_consumption_snapshot(
        historical_subject.task_id,
        current_inputs.canonical_state_occurrence_binding,
        complete_current_subject_ids,
        (record.evidence_id,),
    )
    result = consume_current_semantic_evidence(
        current_resolution, snapshot, (record.evidence_id,),
        current_contract=current_contract,
    )
    exact = result.evidence_currentness[0]
    assert exact.status is SemanticEvidenceCurrentnessStatus.STALE
    assert exact.applicability_reason.name == expected_reason
    assert record.subject.target_context_id == (
        historical_subject.target_context_id if dimension == "target" else None
    )
    assert record.subject.pr_id == (
        historical_subject.pr_id if dimension == "pr" else None
    )


def test_exact_prior_candidate_semantic_evidence_is_stale_after_current_materialization_moves():
    store, _, record, subject = _resolved_backend_with_current_evidence()
    moved_materialization = _materialization(
        type(subject.candidate_id)("moved-candidate"),
        variant="moved",
        contract_raw=subject.contract_raw_sha256,
    )
    moved_candidate = _candidate(
        moved_materialization, candidate_id=type(subject.candidate_id)("moved-candidate"),
        contract=store.read_contract(subject.contract_id),
    )
    assert apply(store, CreateCandidateWithMaterialization(
        moved_candidate, moved_materialization,
    )).status.name == "APPLIED"
    working = store.read_task_working_set(subject.task_id)
    moved_task = replace(
        working.task, revision=working.task.revision + 1,
        current_candidate_id=moved_candidate.candidate_id,
    )
    assert apply(store, ReplaceTask(working.task.revision, moved_task)).status.name == "APPLIED"
    current_inputs = store.read_current_semantic_review_inputs(subject.task_id)
    current_contract = store.read_contract(subject.contract_id)
    resolution = resolve_current_semantic_review(
        current_inputs,
        applicability_context=_current_applicability_context(current_contract),
        byte_reader=_trusted_reader(current_contract, _semantic_config_bytes()),
        semantic_context_source=None,
    )
    assert resolution.status.name == "RESOLVED"
    current_subject_ids = tuple(
        item.effective_subject.subject_id for item in resolution.obligation_outcomes
        if item.effective_subject is not None
    )
    snapshot = store.read_semantic_consumption_snapshot(
        subject.task_id, current_inputs.canonical_state_occurrence_binding,
        current_subject_ids, (record.evidence_id,),
    )
    assert snapshot is not None
    result = consume_current_semantic_evidence(
        resolution, snapshot, (record.evidence_id,), current_contract=current_contract,
    )
    assert result.evidence_currentness[0].status is SemanticEvidenceCurrentnessStatus.STALE
    assert result.evidence_currentness[0].applicability_reason.name == "CANDIDATE_CHANGED"


def test_same_contract_unmatched_historical_obligation_is_indeterminate_not_stale():
    store, _, record, effective_subject = _resolved_backend_with_current_evidence()
    current_binding = record.subject.semantic_review_binding
    assert current_binding is not None
    inconsistent_subject = replace(
        record.subject,
        semantic_review_binding=SemanticReviewEvidenceBinding(
            SemanticEvaluatorObligationId(RawSha256("f" * 64)),
            current_binding.candidate_materialization_id,
        ),
    )
    inconsistent_record = replace(
        record, evidence_id=EvidenceId("same-contract-wrong-obligation"),
        subject=inconsistent_subject,
    )
    history = store.read_review_eligibility_snapshot(effective_subject.subject_id)
    assert history is not None
    assert apply(store, CreateEvidenceAndAdvanceHistory(
        effective_subject, history.evidence_history_membership.membership_binding_id,
        inconsistent_record,
    )).status.name == "APPLIED"
    contract = store.read_contract(effective_subject.contract_id)
    inputs = store.read_current_semantic_review_inputs(effective_subject.task_id)
    resolution = resolve_current_semantic_review(
        inputs, applicability_context=_current_applicability_context(contract),
        byte_reader=_trusted_reader(contract, _semantic_config_bytes()),
        semantic_context_source=None,
    )
    current_subject_ids = tuple(
        item.effective_subject.subject_id for item in resolution.obligation_outcomes
        if item.effective_subject is not None
    )
    snapshot = store.read_semantic_consumption_snapshot(
        effective_subject.task_id, inputs.canonical_state_occurrence_binding,
        current_subject_ids, (inconsistent_record.evidence_id,),
    )
    assert snapshot is not None
    result = consume_current_semantic_evidence(
        resolution, snapshot, (inconsistent_record.evidence_id,),
        current_contract=contract,
    )
    currentness = result.evidence_currentness[0]
    assert currentness.status is SemanticEvidenceCurrentnessStatus.INDETERMINATE
    assert currentness.reason.name == "OBLIGATION_MISMATCH"


@pytest.mark.parametrize("valid_supersession", (True, False))
def test_current_consumer_uses_only_valid_supersession_for_support(valid_supersession):
    store, resolution, earlier, effective_subject = _resolved_backend_with_current_evidence()
    outcome = resolution.obligation_outcomes[0]
    slot = outcome.trusted_evaluator_resolution.review_slots[0]
    later_invocation = ReviewInvocationId("later-current-invocation")
    later_subject = build_current_semantic_evidence_subject(
        outcome.resolved_obligation, slot, later_invocation,
    )
    operation_id = type(earlier.payload.operation_id)("later-semantic-evidence-op")
    working = store.read_task_working_set(effective_subject.task_id)
    later_operation = operation(
        operation_id.value, candidate_id=effective_subject.candidate_id,
    )
    intent_values = {
        name: getattr(later_operation.intent, name)
        for name in later_operation.intent.__dataclass_fields__
    }
    intent_values.update(
        contract_id=effective_subject.contract_id,
        contract_raw_sha256=effective_subject.contract_raw_sha256,
        authorization_id=effective_subject.authorization_id,
        admission_event_id=effective_subject.task_admission_event_id,
        target_registration_id=effective_subject.target_registration_id,
        policy_epoch_identity=effective_subject.policy_epoch_identity,
    )
    later_operation = replace(later_operation, intent=mint(type(later_operation.intent), **intent_values))
    request_id = CanonicalRequestId("later-canonical-request")
    attempt = ReviewAttemptBindingRecord(
        effective_subject, later_invocation, slot.slot_id, operation_id, request_id,
    )
    assert apply(store, CreateSemanticReviewOperationAndBinding(
        later_operation, attempt, working.task.revision,
        working.task_operation_membership.membership_binding_id,
    )).status.name == "APPLIED"
    later = replace(
        earlier, evidence_id=EvidenceId("later-approved-evidence"),
        subject=later_subject,
        payload=replace(
            earlier.payload, invocation_id=later_invocation,
            operation_id=operation_id, canonical_request_id=request_id,
        ),
    )
    history = store.read_review_eligibility_snapshot(effective_subject.subject_id)
    assert history is not None
    assert apply(store, CreateEvidenceAndAdvanceHistory(
        effective_subject, history.evidence_history_membership.membership_binding_id,
        later,
    )).status.name == "APPLIED"
    authorization = mint(
        TrustedSupersessionAuthorization,
        decision_id=SupersessionDecisionId("trusted-supersession-decision"),
        subject_id=effective_subject.subject_id,
        policy_epoch_identity=effective_subject.policy_epoch_identity,
        earlier_evidence_id=earlier.evidence_id,
        later_evidence_id=later.evidence_id,
        authorized_reason=SupersessionReason.AUTHORIZED_ADJUDICATION,
    )
    relation = build_evidence_supersession_record(
        mint(TrustedAdmittedEvidenceRecord, record=earlier,
             membership_binding=EvidenceHistoryMembershipBindingId("earlier")),
        mint(TrustedAdmittedEvidenceRecord, record=later,
             membership_binding=EvidenceHistoryMembershipBindingId("later")),
        authorization,
    )
    if valid_supersession:
        assert apply(store, CreateSupersession(relation)).status.name == "APPLIED"
    contract = store.read_contract(effective_subject.contract_id)
    inputs = store.read_current_semantic_review_inputs(effective_subject.task_id)
    resolution = resolve_current_semantic_review(
        inputs, applicability_context=_current_applicability_context(contract),
        byte_reader=_trusted_reader(contract, _semantic_config_bytes()),
        semantic_context_source=None,
    )
    snapshot = store.read_semantic_consumption_snapshot(
        effective_subject.task_id, inputs.canonical_state_occurrence_binding,
        (effective_subject.subject_id,), (earlier.evidence_id, later.evidence_id),
    )
    assert snapshot is not None
    result = consume_current_semantic_evidence(
        resolution, snapshot, (earlier.evidence_id, later.evidence_id),
        current_contract=contract,
    )
    if valid_supersession:
        assert result.contract_status is ConditionStatus.SATISFIED
        assert result.evidence_currentness[0].status is SemanticEvidenceCurrentnessStatus.STALE
        assert result.evidence_currentness[0].reason.name == "SUPERSEDED"
        assert result.evidence_currentness[1].status is SemanticEvidenceCurrentnessStatus.CURRENT
        assert result.obligation_results[0].progression_support_evidence_ids == (
            later.evidence_id,
        )
    else:
        assert result.contract_status is ConditionStatus.INDETERMINATE
        assert result.evidence_currentness[0].status is SemanticEvidenceCurrentnessStatus.INDETERMINATE
        assert result.evidence_currentness[1].status is SemanticEvidenceCurrentnessStatus.INDETERMINATE
        assert result.obligation_results[0].progression_support_evidence_ids == ()
