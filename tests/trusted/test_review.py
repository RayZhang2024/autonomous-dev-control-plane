import json
from dataclasses import FrozenInstanceError, replace

import pytest

from autodev_control.trusted.evidence import EvidenceSubject
from autodev_control.trusted.identity import GitSha, ImmutableConfigId, RawSha256
from autodev_control.trusted.manifest import PolicyEpochIdentity, TrustedManifestId
from autodev_control.trusted.operation import AdmissionEventId, CandidateId, EvidenceId, OperationId, OperationMembershipBindingId, OperationState
from autodev_control.trusted.parsing import ParseLimits
from autodev_control.trusted.review import *
from autodev_control.trusted.scope import AuthorizationId, ContractId, GitHubRepositoryId, TargetRegistrationId, TaskId

RAW = RawSha256("3" * 64)
EPOCH = PolicyEpochIdentity(TrustedManifestId(RAW))


def mint(cls, **fields):
    value = object.__new__(cls)
    for name, field in fields.items():
        object.__setattr__(value, name, field)
    return value


def raw_verdict(**changes):
    value = {
        "schema_version": "1.0", "review_invocation_id": "inv",
        "requirement_results": [{"requirement_id": "r1", "verdict": "approved", "rationale": "ok", "finding_ids": []}],
        "findings": [], "overall_verdict": "approved",
    }
    value.update(changes)
    return json.dumps(value, separators=(",", ":")).encode()


def profile(name="profile"):
    return ReviewerProfileBinding(
        ReviewerProfileId(name), ImmutableConfigId(f"{name}-config"), ReviewerServiceId("service"),
        ImmutableConfigId("schema"), ParseLimits(100000, 20), ToolMode.NO_TOOLS,
        (ReviewerServiceConstraintId("service-constraint"),),
        (ProviderMetadataRequirementId("provider-metadata"),),
        ImmutableConfigId("rereview-policy"), ImmutableConfigId("disclosure-policy"),
    )


def subject():
    return mint(
        SemanticReviewEffectiveSubject, subject_id=SemanticReviewEffectiveSubjectId("subject"),
        repository_id=GitHubRepositoryId("1"), task_id=TaskId("task"), candidate_id=CandidateId("candidate"),
        contract_id=ContractId("contract"), contract_raw_sha256=RAW, authorization_id=AuthorizationId(RAW),
        task_admission_event_id=AdmissionEventId("task-admission"), target_registration_id=TargetRegistrationId(RAW),
        policy_epoch_identity=EPOCH, base=GitSha("a" * 40), target_context_id=TargetContextId("target"), pr_id=PullRequestIdentity("pr"),
        requirement_ids=(SemanticRequirementId("r1"),), required_material_ids=(MaterialIdentity("m1"),),
        required_context_ids=(TrustedContextId("c1"),), composition_rule_id=CompositionRuleId("composition"),
    )


def composition(*slots):
    return SemanticReviewCompositionRule(CompositionRuleId("composition"), CompositionMode.ALL_REQUIRED_INVOCATIONS, tuple(slots))


def histories(subj, evidence=(), attempts=(), membership="operations"):
    history = mint(TrustedEffectiveSubjectEvidenceSnapshot, subject=subj, membership_binding=EvidenceHistoryMembershipBindingId("history"), admitted_bindings=tuple(evidence))
    attempt = mint(TrustedReviewSlotAttemptSnapshot, subject=subj, operation_membership_binding_id=OperationMembershipBindingId(membership), attempts=tuple(attempts))
    return history, attempt


def test_closed_schema_accepts_valid_v1_and_is_deeply_immutable():
    result = validate_review_verdict_v1(raw_verdict(), ParseLimits(100000, 20))
    assert result.reason is VerdictValidationReason.VALID
    assert result.verdict.overall_verdict is SemanticVerdict.APPROVED
    with pytest.raises(TypeError):
        result.verdict.requirement_results[0] = None


@pytest.mark.parametrize("mutation", [
    {"schema_version": "2.0"}, {"extra": True}, {"requirement_results": []},
    {"findings": [{}]}, {"reviewer_summary": ""}, {"review_invocation_id": ""},
])
def test_closed_schema_rejects_structural_violations(mutation):
    assert validate_review_verdict_v1(raw_verdict(**mutation), ParseLimits(100000, 20)).reason is VerdictValidationReason.SCHEMA_VALIDATION_FAILED


@pytest.mark.parametrize("mutation", [
    {"reviewer_summary": None},
    {"requirement_results": [{"requirement_id": "r1", "verdict": "approved", "rationale": "ok", "finding_ids": [], "unable_reason_code": None}]},
    {"findings": [{"finding_id": "f", "kind": "advisory_observation", "requirement_ids": [], "summary": "s", "rationale": "r", "suggested_remediation": None}]},
    {"findings": [{"finding_id": "f", "kind": "advisory_observation", "requirement_ids": [], "summary": "s", "rationale": "r", "locations": [{"path": "x", "content_id": None}]}]},
    {"findings": [{"finding_id": "f", "kind": "advisory_observation", "requirement_ids": [], "summary": "s", "rationale": "r", "locations": [{"path": "x", "line_start": None}]}]},
    {"findings": [{"finding_id": "f", "kind": "advisory_observation", "requirement_ids": [], "summary": "s", "rationale": "r", "locations": [{"path": "x", "line_end": None}]}]},
])
def test_optional_schema_properties_reject_explicit_null(mutation):
    assert validate_review_verdict_v1(raw_verdict(**mutation), ParseLimits(100000, 20)).reason is VerdictValidationReason.SCHEMA_VALIDATION_FAILED


def test_optional_schema_properties_accept_absence():
    finding = {"finding_id": "f", "kind": "advisory_observation", "requirement_ids": [], "summary": "s", "rationale": "r", "locations": [{"path": "x"}]}
    assert validate_review_verdict_v1(raw_verdict(findings=[finding]), ParseLimits(100000, 20)).reason is VerdictValidationReason.VALID


def test_strict_parser_and_raw_ceiling_are_distinct():
    assert validate_review_verdict_v1(b'{"a":1,"a":2}', ParseLimits(1000, 10)).reason is VerdictValidationReason.RAW_RESPONSE_PARSE_FAILED
    assert validate_review_verdict_v1(raw_verdict(), ParseLimits(5, 10)).reason is VerdictValidationReason.RAW_RESPONSE_TOO_LARGE
    long = raw_verdict(reviewer_summary="x" * 16385)
    assert validate_review_verdict_v1(long, ParseLimits(len(long), 20)).reason is VerdictValidationReason.SCHEMA_VALIDATION_FAILED


def test_unable_reason_condition_and_location_shape():
    unable = {"requirement_id": "r1", "verdict": "unable_to_determine", "rationale": "why", "finding_ids": []}
    assert validate_review_verdict_v1(raw_verdict(requirement_results=[unable]), ParseLimits(100000, 20)).reason is VerdictValidationReason.SCHEMA_VALIDATION_FAILED
    unable["unable_reason_code"] = "other"
    assert validate_review_verdict_v1(raw_verdict(requirement_results=[unable], overall_verdict="unable_to_determine"), ParseLimits(100000, 20)).reason is VerdictValidationReason.VALID


def test_schema_integer_locations_accept_integers_and_reject_nonintegers():
    finding = {"finding_id": "f", "kind": "advisory_observation", "requirement_ids": [], "summary": "s", "rationale": "r", "locations": [{"path": "a.py", "line_start": 1, "line_end": 2}]}
    assert validate_review_verdict_v1(raw_verdict(findings=[finding]), ParseLimits(100000, 20)).reason is VerdictValidationReason.VALID
    finding["locations"][0]["line_start"] = 1.5
    assert validate_review_verdict_v1(raw_verdict(findings=[finding]), ParseLimits(100000, 20)).reason is VerdictValidationReason.SCHEMA_VALIDATION_FAILED


def test_trusted_provenance_and_assignment_constructors_are_closed():
    for cls in (SemanticReviewAssignment, SemanticReviewEffectiveSubject, TrustedEffectiveSubjectEvidenceSnapshot, TrustedReviewSlotAttemptSnapshot, TrustedReviewInvocationRecord, TrustedReviewOperationBinding, TrustedDisclosureRequirement, TrustedDisclosureAuthorizationBinding):
        with pytest.raises(TypeError):
            cls()
    assert not any(name.endswith("for_test") for name in vars(__import__("autodev_control.trusted.review", fromlist=["*"])))


@pytest.mark.parametrize("state", [OperationState.RESERVED, OperationState.PERFORMING, OperationState.INDETERMINATE, OperationState.SUCCEEDED])
def test_same_slot_active_or_unadmitted_attempt_blocks(state):
    subj, slot = subject(), ReviewSlot(ReviewSlotId("a"), profile(), RAW)
    attempt = ReviewSlotAttempt(ReviewInvocationId("inv"), slot.slot_id, OperationId("op"), state, CanonicalRequestId("request"))
    history, attempts = histories(subj, attempts=(attempt,))
    result = evaluate_review_invocation_eligibility(subj, slot, composition(slot), history, attempts)
    assert result.decision is EligibilityDecision.NOT_ELIGIBLE
    assert result.expected_operation_membership_binding == OperationMembershipBindingId("operations")


@pytest.mark.parametrize("state", [OperationState.FAILED, OperationState.CONFLICT])
def test_terminal_attempt_requires_separate_retry_authority(state):
    subj, slot = subject(), ReviewSlot(ReviewSlotId("a"), profile(), RAW)
    attempt = ReviewSlotAttempt(ReviewInvocationId("inv"), slot.slot_id, OperationId("op"), state, CanonicalRequestId("request"))
    history, attempts = histories(subj, attempts=(attempt,))
    denied = evaluate_review_invocation_eligibility(subj, slot, composition(slot), history, attempts)
    assert denied.reason is EligibilityReason.RETRY_AUTHORIZATION_REQUIRED
    auth = mint(TrustedOperationalRetryAuthorization, subject_id=subj.subject_id, slot_id=slot.slot_id, prior_operation_id=attempt.operation_id)
    assert evaluate_review_invocation_eligibility(subj, slot, composition(slot), history, attempts, operational_retry_authorization=auth).decision is EligibilityDecision.ELIGIBLE


def test_independent_slot_b_remains_eligible_after_slot_a_evidence():
    subj = subject()
    slot_a, slot_b = ReviewSlot(ReviewSlotId("a"), profile("a"), RAW), ReviewSlot(ReviewSlotId("b"), profile("b"), RawSha256("4" * 64))
    evidence = AdmittedSemanticEvidenceBinding(EvidenceId("e"), ReviewInvocationId("inv"), slot_a.slot_id, True)
    history, attempts = histories(subj, evidence=(evidence,))
    assert evaluate_review_invocation_eligibility(subj, slot_b, composition(slot_a, slot_b), history, attempts).decision is EligibilityDecision.ELIGIBLE


def test_profile_cycling_cannot_manufacture_slot_and_history_unavailable_is_indeterminate():
    subj, required = subject(), ReviewSlot(ReviewSlotId("a"), profile("a"), RAW)
    changed = ReviewSlot(required.slot_id, profile("other"), RAW)
    history, attempts = histories(subj)
    assert evaluate_review_invocation_eligibility(subj, changed, composition(required), history, attempts).reason is EligibilityReason.SLOT_PROFILE_MISMATCH
    assert evaluate_review_invocation_eligibility(subj, required, composition(required), None, attempts).decision is EligibilityDecision.INDETERMINATE


def test_ordinary_g5_values_reject_mutable_nested_containers():
    with pytest.raises(TypeError):
        ReviewerProfileBinding(
            ReviewerProfileId("p"), ImmutableConfigId("pc"), ReviewerServiceId("s"), ImmutableConfigId("schema"),
            ParseLimits(10, 2), ToolMode.NO_TOOLS, [], (), ImmutableConfigId("rr"), ImmutableConfigId("dp"),
        )
    with pytest.raises(TypeError):
        SemanticReviewCompositionRule(CompositionRuleId("c"), CompositionMode.ALL_REQUIRED_INVOCATIONS, [])
    with pytest.raises(TypeError):
        RequirementMaterialAssignment(SemanticRequirementId("r"), [], (), ())


@pytest.mark.parametrize("mode", [
    CompositionMode.SINGLE_REQUIRED_INVOCATION,
    CompositionMode.ALL_REQUIRED_INVOCATIONS,
    CompositionMode.EXACT_REQUIRED_INVOCATION_SET,
])
def test_every_supported_semantic_composition_requires_a_nonempty_exact_slot_tuple(mode):
    with pytest.raises(ValueError):
        SemanticReviewCompositionRule(CompositionRuleId("composition"), mode, ())


def test_envelope_binds_exact_assignment_context_and_representation_rules():
    subj, prof = subject(), profile()
    slot = ReviewSlot(ReviewSlotId("a"), prof, RAW)
    rule = SemanticReviewCompositionRule(CompositionRuleId("composition"), CompositionMode.SINGLE_REQUIRED_INVOCATION, (slot,))
    assignment = mint(
        SemanticReviewAssignment, assignment_id=AssignmentIdentity("assignment"), repository_id=subj.repository_id,
        task_id=subj.task_id, contract_id=subj.contract_id, contract_raw_sha256=subj.contract_raw_sha256,
        target_registration_id=subj.target_registration_id, policy_epoch_identity=subj.policy_epoch_identity,
        candidate_id=subj.candidate_id, requirements=(SemanticRequirement(SemanticRequirementId("r1"), RAW),),
        material_assignments=(RequirementMaterialAssignment(SemanticRequirementId("r1"), (MaterialIdentity("m1"),), (TrustedContextId("c1"),), (RepresentationIdentity("rep-rule"),)),),
        required_context_ids=(TrustedContextId("c1"),), composition_rule=rule,
        partition_rule=ReviewPartitionRule.SINGLE_REVIEW_PACKAGE,
    )
    evidence_subject = EvidenceSubject(
        repository_id=subj.repository_id, task_id=subj.task_id,
        candidate_id=subj.candidate_id, contract_id=subj.contract_id, contract_raw_sha256=subj.contract_raw_sha256,
        authorization_id=subj.authorization_id, task_admission_event_id=subj.task_admission_event_id,
        target_registration_id=subj.target_registration_id, policy_epoch_identity=subj.policy_epoch_identity,
        base=subj.base, target_context_id=subj.target_context_id, pr_id=subj.pr_id, requirement_ids=subj.requirement_ids,
        required_material_ids=subj.required_material_ids, required_context_ids=subj.required_context_ids,
        invocation_id=ReviewInvocationId("inv"),
        slot_id=slot.slot_id, profile_id=prof.profile_id, profile_config_id=prof.config_id,
        verdict_schema_id=prof.verdict_schema_id,
    )
    changed = MaterialBinding(MaterialIdentity("m1"), subj.repository_id, MaterialKind.CHANGED_CONTENT, "a.py", "sha", subj.candidate_id, subj.base, classification_id=MaterialClassificationId("source"))
    context = MaterialBinding(MaterialIdentity("context-material"), subj.repository_id, MaterialKind.TRUSTED_CONTEXT, "policy", "sha", None, subj.base, trusted_context_id=TrustedContextId("c1"), classification_id=MaterialClassificationId("policy"))
    built = build_trusted_review_envelope(
        assignment=assignment, subject=subj, slot=slot, changed_inventory=(changed,), trusted_context_inventory=(context,),
        invocation_id=ReviewInvocationId("inv"), envelope_id=ReviewEnvelopeId("env"),
        manifest_id=ReviewInputManifestId("manifest"), canonical_request_id=CanonicalRequestId("request"),
        evidence_subject=evidence_subject,
    )
    assert built.reason is EnvelopeReason.BUILT
    assert built.envelope.input_manifest.trusted_context_ids == (TrustedContextId("c1"),)
    assert built.envelope.input_manifest.evidence_subject is evidence_subject

    for changed_binding in (
        replace(changed, candidate_id=CandidateId("other-candidate")),
        replace(changed, base=GitSha("b" * 40)),
    ):
        identity_denied = build_trusted_review_envelope(
            assignment=assignment, subject=subj, slot=slot,
            changed_inventory=(changed_binding,), trusted_context_inventory=(context,),
            invocation_id=ReviewInvocationId("inv"), envelope_id=ReviewEnvelopeId("env"),
            manifest_id=ReviewInputManifestId("manifest"),
            canonical_request_id=CanonicalRequestId("request"),
            evidence_subject=evidence_subject,
        )
        assert identity_denied.reason is EnvelopeReason.IDENTITY_MISMATCH

    for context_binding in (
        replace(context, candidate_id=CandidateId("candidate-context-is-not-applicable")),
        replace(context, base=GitSha("b" * 40)),
    ):
        context_denied = build_trusted_review_envelope(
            assignment=assignment, subject=subj, slot=slot,
            changed_inventory=(changed,), trusted_context_inventory=(context_binding,),
            invocation_id=ReviewInvocationId("inv"), envelope_id=ReviewEnvelopeId("env"),
            manifest_id=ReviewInputManifestId("manifest"),
            canonical_request_id=CanonicalRequestId("request"),
            evidence_subject=evidence_subject,
        )
        assert context_denied.reason is EnvelopeReason.IDENTITY_MISMATCH

    supplemental = MaterialBinding(
        MaterialIdentity("supplemental"), subj.repository_id,
        MaterialKind.SUPPLEMENTAL_UNTRUSTED_CONTEXT, "notes", "notes-sha",
        None, subj.base,
    )
    for supplemental_binding in (
        replace(supplemental, candidate_id=CandidateId("candidate-context-is-not-applicable")),
        replace(supplemental, base=GitSha("b" * 40)),
    ):
        supplemental_denied = build_trusted_review_envelope(
            assignment=assignment, subject=subj, slot=slot,
            changed_inventory=(changed,), trusted_context_inventory=(context,),
            supplemental_context_inventory=(supplemental_binding,),
            invocation_id=ReviewInvocationId("inv"), envelope_id=ReviewEnvelopeId("env"),
            manifest_id=ReviewInputManifestId("manifest"),
            canonical_request_id=CanonicalRequestId("request"),
            evidence_subject=evidence_subject,
        )
        assert supplemental_denied.reason is EnvelopeReason.IDENTITY_MISMATCH

    transformed = MaterialBinding(MaterialIdentity("rendered"), subj.repository_id, MaterialKind.TRANSFORMED_REPRESENTATION, "render", "sha", subj.candidate_id, subj.base, RepresentationIdentity("not-permitted"), represented_material_id=MaterialIdentity("m1"))
    denied = build_trusted_review_envelope(
        assignment=assignment, subject=subj, slot=slot, changed_inventory=(changed,), trusted_context_inventory=(context,),
        representation_inventory=(transformed,), invocation_id=ReviewInvocationId("inv"), envelope_id=ReviewEnvelopeId("env"),
        manifest_id=ReviewInputManifestId("manifest"), canonical_request_id=CanonicalRequestId("request"), evidence_subject=evidence_subject,
    )
    assert denied.reason is EnvelopeReason.MATERIAL_COVERAGE_MISMATCH
