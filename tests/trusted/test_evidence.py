import hashlib
import json
from dataclasses import FrozenInstanceError, replace

import pytest

from autodev_control.trusted.evidence import *
from autodev_control.trusted.identity import GitSha, ImmutableConfigId, RawSha256
from autodev_control.trusted.manifest import PolicyEpochIdentity, TrustedManifestId
from autodev_control.trusted.operation import AdmissionEventId, CandidateId, EvidenceId, OperationId, OperationIntent, OperationRecord, OperationState
from autodev_control.trusted.parsing import ParseLimits
from autodev_control.trusted.review import *
from autodev_control.trusted.scope import AuthorizationId, ContractId, GitHubRepositoryId, TargetRegistrationId, TaskId

RAW = RawSha256("5" * 64)
EPOCH = PolicyEpochIdentity(TrustedManifestId(RAW))


def mint(cls, **fields):
    value = object.__new__(cls)
    for name, field in fields.items():
        object.__setattr__(value, name, field)
    return value


def verdict(verdict_value="approved", duplicate=False, overall=None, unable=None):
    result = {"requirement_id": "r1", "verdict": verdict_value, "rationale": "human prose", "finding_ids": []}
    if unable:
        result["unable_reason_code"] = unable
    results = [result, dict(result)] if duplicate else [result]
    body = {"schema_version": "1.0", "review_invocation_id": "inv", "requirement_results": results, "findings": []}
    if overall is not None:
        body["overall_verdict"] = overall
    return json.dumps(body, separators=(",", ":")).encode()


def fixture(raw=None, operation_state=OperationState.SUCCEEDED, disclosure=DisclosureApplicability.NOT_APPLICABLE):
    raw = verdict() if raw is None else raw
    profile = ReviewerProfileBinding(ReviewerProfileId("profile"), ImmutableConfigId("profile-config"), ReviewerServiceId("service"), ImmutableConfigId("schema"), ParseLimits(100000, 20), ToolMode.NO_TOOLS)
    slot = ReviewSlot(ReviewSlotId("slot"), profile, RAW)
    composition = SemanticReviewCompositionRule(CompositionRuleId("composition"), CompositionMode.SINGLE_REQUIRED_INVOCATION, (slot,))
    effective = mint(
        SemanticReviewEffectiveSubject, subject_id=SemanticReviewEffectiveSubjectId("subject"), repository_id=GitHubRepositoryId("1"),
        task_id=TaskId("task"), candidate_id=CandidateId("candidate"), contract_id=ContractId("contract"),
        contract_raw_sha256=RAW, authorization_id=AuthorizationId(RAW), task_admission_event_id=AdmissionEventId("task-admission"),
        target_registration_id=TargetRegistrationId(RAW), policy_epoch_identity=EPOCH, base=GitSha("a" * 40),
        target_context_id=TargetContextId("target"), requirement_ids=(SemanticRequirementId("r1"),),
        required_material_ids=(MaterialIdentity("m"),), required_context_ids=(TrustedContextId("c"),),
        composition_rule_id=composition.composition_rule_id,
    )
    subject = EvidenceSubject(
        effective.repository_id, effective.task_id, effective.contract_id, RAW,
        effective.task_admission_event_id, effective.authorization_id, effective.target_registration_id,
        EPOCH, effective.candidate_id, effective.base, effective.target_context_id,
        effective.requirement_ids, ReviewInvocationId("inv"), slot.slot_id,
        profile.profile_id, profile.config_id, profile.verdict_schema_id,
    )
    manifest = ReviewInputManifest(ReviewInputManifestId("manifest"), subject.invocation_id, CanonicalRequestId("request"), effective.subject_id, slot.slot_id, profile.profile_id, profile.config_id, effective.required_material_ids, effective.required_context_ids)
    envelope = TrustedReviewEnvelope(ReviewEnvelopeId("envelope"), subject.invocation_id, CanonicalRequestId("request"), AssignmentIdentity("assignment"), effective.subject_id, slot.slot_id, profile, (), manifest)
    invocation = mint(
        TrustedReviewInvocationRecord, invocation_id=subject.invocation_id, envelope_id=envelope.envelope_id,
        manifest_id=manifest.manifest_id, slot_id=slot.slot_id, profile=profile,
        canonical_request_id=CanonicalRequestId("request"), submission_event_id=SubmissionEventId("submit"),
        raw_response_id=RawReviewResponseId("response"), raw_response_sha256=RawSha256(hashlib.sha256(raw).hexdigest()),
        subject=effective,
    )
    intent = mint(OperationIntent, operation_id=OperationId("operation"), task_id=subject.task_id, candidate_id=subject.candidate_id)
    operation = OperationRecord(intent, 2, operation_state)
    binding = mint(
        TrustedReviewOperationBinding, invocation_id=subject.invocation_id, slot_id=slot.slot_id,
        operation_id=intent.operation_id, canonical_request_id=CanonicalRequestId("request"),
        task_id=subject.task_id, candidate_id=subject.candidate_id, role=ReviewOperationRole.SEMANTIC_REVIEW,
    )
    disclosure_requirement = mint(
        TrustedDisclosureRequirement, applicability=disclosure, invocation_id=subject.invocation_id,
        slot_id=slot.slot_id, profile_id=profile.profile_id, service_id=profile.service_id,
        canonical_request_id=CanonicalRequestId("request"),
    )
    history = mint(TrustedEffectiveSubjectEvidenceSnapshot, subject=effective, membership_binding=EvidenceHistoryMembershipBindingId("H0"), admitted_bindings=())
    attempt = ReviewSlotAttempt(subject.invocation_id, slot.slot_id, intent.operation_id, operation_state, CanonicalRequestId("request"))
    attempts = mint(TrustedReviewSlotAttemptSnapshot, subject=effective, operation_membership_binding_id=__import__('autodev_control.trusted.operation', fromlist=['OperationMembershipBindingId']).OperationMembershipBindingId("O0"), attempts=(attempt,))
    request = SemanticEvidenceAdmissionRequest(
        raw, ParseLimits(100000, 20), mint(TrustedVerdictSchemaContext, schema_id=profile.verdict_schema_id, version="1.0"),
        profile.verdict_schema_id, subject, effective, slot, composition, envelope, invocation, binding,
        operation, disclosure_requirement, None, mint(TrustedCurrentEvidenceContext, subject=subject),
        history, attempts, EvidenceRecordProposalIdentity(EvidenceId("evidence"), EvidenceAdmissionEventId("evidence-admission"), EvidenceProducerEventId("producer")),
    )
    return request


def test_admits_approved_and_carries_exact_history_cas_binding():
    result = admit_semantic_review(fixture())
    assert result.decision is EvidenceAdmissionDecision.ADMIT
    assert result.expected_evidence_history_membership_binding == EvidenceHistoryMembershipBindingId("H0")
    assert result.proposed_evidence_record.payload.aggregate is SemanticVerdict.APPROVED


def test_succeeded_changes_required_is_valid_admitted_failure_evidence():
    result = admit_semantic_review(fixture(verdict("changes_required", overall="changes_required")))
    assert result.decision is EvidenceAdmissionDecision.ADMIT
    assert result.proposed_evidence_record.payload.aggregate is SemanticVerdict.CHANGES_REQUIRED


def test_operation_success_is_required_but_does_not_imply_approval():
    assert admit_semantic_review(fixture(operation_state=OperationState.PERFORMING)).reason_code is EvidenceAdmissionReasonCode.OPERATION_NOT_SUCCEEDED


def test_duplicate_requirement_result_precedes_set_equality():
    result = admit_semantic_review(fixture(verdict(duplicate=True)))
    assert result.reason_code is EvidenceAdmissionReasonCode.DUPLICATE_REQUIREMENT_RESULT


def test_unavailable_and_unsupported_schema_are_distinct():
    request = fixture()
    assert admit_semantic_review(replace(request, schema_context=None)).reason_code is EvidenceAdmissionReasonCode.SCHEMA_CONTEXT_UNAVAILABLE
    unsupported = mint(TrustedVerdictSchemaContext, schema_id=ImmutableConfigId("other"), version="2.0")
    assert admit_semantic_review(replace(request, schema_context=unsupported)).reason_code is EvidenceAdmissionReasonCode.UNSUPPORTED_VERDICT_SCHEMA


def test_finite_limits_precede_raw_parse_and_schema():
    assert admit_semantic_review(replace(fixture(), parse_limits=None, raw_response=b"bad")).reason_code is EvidenceAdmissionReasonCode.RAW_LIMIT_CONTEXT_UNAVAILABLE


def test_disclosure_required_unavailable_escalates_and_contradiction_denies():
    required = fixture(disclosure=DisclosureApplicability.REQUIRED)
    result = admit_semantic_review(required)
    assert (result.decision, result.reason_code) == (EvidenceAdmissionDecision.ESCALATE, EvidenceAdmissionReasonCode.DISCLOSURE_CONTEXT_UNAVAILABLE)
    contradiction = replace(fixture(), disclosure_authorization=mint(TrustedDisclosureAuthorizationBinding))
    assert admit_semantic_review(contradiction).reason_code is EvidenceAdmissionReasonCode.DISCLOSURE_BINDING_MISMATCH


def test_original_mismatch_precedes_current_staleness():
    request = fixture()
    bad_effective = mint(SemanticReviewEffectiveSubject, **{name: getattr(request.effective_subject, name) for name in request.effective_subject.__dataclass_fields__})
    object.__setattr__(bad_effective, "candidate_id", CandidateId("other"))
    bad_invocation = mint(TrustedReviewInvocationRecord, **{name: getattr(request.invocation, name) for name in request.invocation.__dataclass_fields__})
    object.__setattr__(bad_invocation, "subject", bad_effective)
    assert admit_semantic_review(replace(request, invocation=bad_invocation)).reason_code is EvidenceAdmissionReasonCode.SUBJECT_BINDING_MISMATCH
    moved = replace(request.subject, candidate_id=CandidateId("current-c2"))
    stale = replace(request, current_context=mint(TrustedCurrentEvidenceContext, subject=moved))
    assert admit_semantic_review(stale).reason_code is EvidenceAdmissionReasonCode.ADMISSION_CONTEXT_STALE


@pytest.mark.parametrize(("field", "reason"), [
    ("candidate_id", EvidenceApplicabilityReason.CANDIDATE_CHANGED),
    ("base", EvidenceApplicabilityReason.BASE_CHANGED),
    ("slot_id", EvidenceApplicabilityReason.REVIEW_SLOT_CHANGED),
    ("profile_id", EvidenceApplicabilityReason.REVIEWER_PROFILE_CHANGED),
    ("profile_config_id", EvidenceApplicabilityReason.REVIEWER_PROFILE_CONFIG_CHANGED),
])
def test_post_admission_applicability_is_exact(field, reason):
    record = admit_semantic_review(fixture()).proposed_evidence_record
    replacements = {"candidate_id": CandidateId("new"), "base": GitSha("b" * 40), "slot_id": ReviewSlotId("new"), "profile_id": ReviewerProfileId("new"), "profile_config_id": ImmutableConfigId("new")}
    current = replace(record.subject, **{field: replacements[field]})
    result = evaluate_evidence_applicability(record, current)
    assert (result.decision, result.reason) == (EvidenceApplicabilityDecision.STALE, reason)


def test_aggregate_precedence_is_unable_then_changes_then_approved():
    approved = mint(RequirementResult, verdict=SemanticVerdict.APPROVED)
    changed = mint(RequirementResult, verdict=SemanticVerdict.CHANGES_REQUIRED)
    unable = mint(RequirementResult, verdict=SemanticVerdict.UNABLE_TO_DETERMINE)
    assert recompute_semantic_aggregate((approved, changed, unable)) is SemanticVerdict.UNABLE_TO_DETERMINE
    assert recompute_semantic_aggregate((approved, changed)) is SemanticVerdict.CHANGES_REQUIRED
    assert recompute_semantic_aggregate((approved,)) is SemanticVerdict.APPROVED


def test_task_and_evidence_admission_event_ids_are_distinct_and_values_non_bearer():
    assert AdmissionEventId("same") != EvidenceAdmissionEventId("same")
    record = admit_semantic_review(fixture()).proposed_evidence_record
    assert not hasattr(record, "persist") and not hasattr(record.evidence_id, "authority")
    with pytest.raises(FrozenInstanceError):
        record.evidence_id = EvidenceId("other")


def test_production_evidence_module_exposes_no_fixture_minting_helper():
    module = __import__("autodev_control.trusted.evidence", fromlist=["*"])
    assert not any(name.endswith("for_test") for name in vars(module))
