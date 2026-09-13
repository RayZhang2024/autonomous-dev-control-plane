import hashlib
import json
from dataclasses import FrozenInstanceError, replace

import pytest

from autodev_control.trusted.backend import BackendGeneration, CanonicalStateOccurrenceBinding
from autodev_control.trusted.evidence import *
from autodev_control.trusted.identity import GitSha, ImmutableConfigId, RawSha256
from autodev_control.trusted.manifest import PolicyEpochIdentity, TrustedManifestId
from autodev_control.trusted.operation import AdmissionEventId, CandidateId, EvidenceId, OperationId, OperationIntent, OperationRecord, OperationState
from autodev_control.trusted.parsing import ParseLimits
from autodev_control.trusted.review import *
from autodev_control.trusted.scope import AuthorizationId, ContractId, GitHubRepositoryId, TargetRegistrationId, TaskId

RAW = RawSha256("5" * 64)
EPOCH = PolicyEpochIdentity(TrustedManifestId(RAW))
OCCURRENCE = CanonicalStateOccurrenceBinding(BackendGeneration(1))


def mint(cls, **fields):
    value = object.__new__(cls)
    for name, field in fields.items():
        object.__setattr__(value, name, field)
    return value


def minted_copy(value, **changes):
    fields = {name: getattr(value, name) for name in value.__dataclass_fields__}
    fields.update(changes)
    return mint(type(value), **fields)


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
    profile = ReviewerProfileBinding(
        ReviewerProfileId("profile"), ImmutableConfigId("profile-config"), ReviewerServiceId("service"),
        ImmutableConfigId("schema"), ParseLimits(100000, 20), ToolMode.NO_TOOLS,
        (ReviewerServiceConstraintId("service-constraint"),),
        (ProviderMetadataRequirementId("provider-metadata"),),
        ImmutableConfigId("rereview-policy"), ImmutableConfigId("disclosure-policy"),
    )
    slot = ReviewSlot(ReviewSlotId("slot"), profile, RAW)
    composition = SemanticReviewCompositionRule(CompositionRuleId("composition"), CompositionMode.SINGLE_REQUIRED_INVOCATION, (slot,))
    effective = mint(
        SemanticReviewEffectiveSubject, subject_id=SemanticReviewEffectiveSubjectId("subject"), repository_id=GitHubRepositoryId("1"),
        task_id=TaskId("task"), candidate_id=CandidateId("candidate"), contract_id=ContractId("contract"),
        contract_raw_sha256=RAW, authorization_id=AuthorizationId(RAW), task_admission_event_id=AdmissionEventId("task-admission"),
        target_registration_id=TargetRegistrationId(RAW), policy_epoch_identity=EPOCH, base=GitSha("a" * 40),
        target_context_id=TargetContextId("target"), pr_id=PullRequestIdentity("pr"), requirement_ids=(SemanticRequirementId("r1"),),
        required_material_ids=(MaterialIdentity("m"),), required_context_ids=(TrustedContextId("c"),),
        composition_rule_id=composition.composition_rule_id,
    )
    subject = EvidenceSubject(
        effective.repository_id, effective.task_id, effective.contract_id, RAW,
        effective.task_admission_event_id, effective.authorization_id, effective.target_registration_id,
        EPOCH, effective.candidate_id, effective.base, effective.target_context_id, effective.pr_id,
        effective.requirement_ids, effective.required_material_ids, effective.required_context_ids,
        ReviewInvocationId("inv"), slot.slot_id,
        profile.profile_id, profile.config_id, profile.verdict_schema_id,
    )
    assignment = mint(
        SemanticReviewAssignment, assignment_id=AssignmentIdentity("assignment"), repository_id=subject.repository_id,
        task_id=subject.task_id, contract_id=subject.contract_id, contract_raw_sha256=subject.contract_raw_sha256,
        target_registration_id=subject.target_registration_id, policy_epoch_identity=subject.policy_epoch_identity,
        candidate_id=subject.candidate_id, requirements=(SemanticRequirement(SemanticRequirementId("r1"), RAW),),
        material_assignments=(RequirementMaterialAssignment(SemanticRequirementId("r1"), subject.required_material_ids, subject.required_context_ids, ()),),
        required_context_ids=subject.required_context_ids, composition_rule=composition,
        partition_rule=ReviewPartitionRule.SINGLE_REVIEW_PACKAGE,
    )
    manifest = ReviewInputManifest(
        ReviewInputManifestId("manifest"), subject.invocation_id, CanonicalRequestId("request"),
        effective.subject_id, slot.slot_id, profile.profile_id, profile.config_id,
        profile.service_id, AssignmentIdentity("assignment"), subject, effective.requirement_ids,
        effective.required_material_ids, (), (), effective.required_context_ids, (), profile.verdict_schema_id,
    )
    changed_material = MaterialBinding(
        effective.required_material_ids[0], subject.repository_id, MaterialKind.CHANGED_CONTENT,
        "src/a.py", "content", subject.candidate_id, subject.base,
    )
    trusted_context = MaterialBinding(
        MaterialIdentity("context-material"), subject.repository_id, MaterialKind.TRUSTED_CONTEXT,
        "policy", "context-content", None, subject.base, trusted_context_id=effective.required_context_ids[0],
    )
    envelope = TrustedReviewEnvelope(
        ReviewEnvelopeId("envelope"), subject.invocation_id, CanonicalRequestId("request"),
        AssignmentIdentity("assignment"), effective.subject_id, slot.slot_id, profile,
        effective, subject, effective.requirement_ids, (changed_material, trusted_context), (), manifest,
    )
    invocation = mint(
        TrustedReviewInvocationRecord, invocation_id=subject.invocation_id, envelope_id=envelope.envelope_id,
        manifest_id=manifest.manifest_id, assignment_id=assignment.assignment_id,
        slot_id=slot.slot_id, profile=profile,
        canonical_request_id=CanonicalRequestId("request"), submission_event_id=SubmissionEventId("submit"),
        raw_response_id=RawReviewResponseId("response"), raw_response_sha256=RawSha256(hashlib.sha256(raw).hexdigest()),
        verdict_schema_id=profile.verdict_schema_id, required_material_ids=subject.required_material_ids,
        representation_ids=(),
        required_context_ids=subject.required_context_ids, supplemental_context_ids=(),
        observed_provider_metadata_requirement_ids=profile.provider_metadata_requirement_ids,
        subject=effective,
    )
    intent = mint(
        OperationIntent, operation_id=OperationId("operation"), task_id=subject.task_id,
        candidate_id=subject.candidate_id, contract_id=subject.contract_id,
        contract_raw_sha256=subject.contract_raw_sha256, authorization_id=subject.authorization_id,
        admission_event_id=subject.task_admission_event_id, target_registration_id=subject.target_registration_id,
        policy_epoch_identity=subject.policy_epoch_identity,
    )
    operation = OperationRecord(intent, 2, operation_state)
    binding = mint(
        TrustedReviewOperationBinding, invocation_id=subject.invocation_id, slot_id=slot.slot_id,
        operation_id=intent.operation_id, operation_revision=operation.revision,
        canonical_request_id=CanonicalRequestId("request"),
        task_id=subject.task_id, candidate_id=subject.candidate_id, contract_id=subject.contract_id,
        contract_raw_sha256=subject.contract_raw_sha256, authorization_id=subject.authorization_id,
        task_admission_event_id=subject.task_admission_event_id,
        target_registration_id=subject.target_registration_id, policy_epoch_identity=subject.policy_epoch_identity,
        role=ReviewOperationRole.SEMANTIC_REVIEW,
    )
    disclosure_requirement = mint(
        TrustedDisclosureRequirement, applicability=disclosure, invocation_id=subject.invocation_id,
        slot_id=slot.slot_id, profile_id=profile.profile_id, service_id=profile.service_id,
        canonical_request_id=CanonicalRequestId("request"), disclosed_resources=(),
    )
    history = mint(TrustedEffectiveSubjectEvidenceSnapshot, canonical_state_occurrence_binding=OCCURRENCE, subject=effective, membership_binding=EvidenceHistoryMembershipBindingId("H0"), admitted_bindings=())
    attempt = ReviewSlotAttempt(subject.invocation_id, slot.slot_id, intent.operation_id, operation_state, CanonicalRequestId("request"))
    attempts = mint(TrustedReviewSlotAttemptSnapshot, canonical_state_occurrence_binding=OCCURRENCE, subject=effective, operation_membership_binding_id=__import__('autodev_control.trusted.operation', fromlist=['OperationMembershipBindingId']).OperationMembershipBindingId("O0"), attempts=(attempt,))
    request = SemanticEvidenceAdmissionRequest(
        raw, ParseLimits(100000, 20), mint(TrustedVerdictSchemaContext, schema_id=profile.verdict_schema_id, version="1.0"),
        profile.verdict_schema_id, subject, effective, slot, composition, envelope, invocation, binding,
        operation, disclosure_requirement, None, mint(TrustedCurrentEvidenceContext, subject=subject),
        history, attempts, EvidenceRecordProposalIdentity(EvidenceId("evidence"), EvidenceAdmissionEventId("evidence-admission"), EvidenceProducerEventId("producer")),
        mint(TrustedReviewProfileAdmissionContext, baseline_config_id=ImmutableConfigId("baseline-parser"),
             policy_epoch_identity=subject.policy_epoch_identity, profile_id=profile.profile_id, profile_config_id=profile.config_id,
             baseline_limits=ParseLimits(200000, 30), active_policy_limits=ParseLimits(150000, 25), profile_limits=profile.raw_limits),
        invocation.raw_response_id, None, None, assignment,
    )
    return request


def disclosed_resource(material):
    return DisclosedResourceBinding(
        material.material_id, material.repository_id, material.kind, material.classification_id,
        material.path_or_resource, material.content_or_deletion_identity,
        material.candidate_id, material.base,
        material.trusted_context_id, material.representation_id, material.represented_material_id,
    )


def with_disclosure_package(request, materials, supplemental=()):
    changed_ids = tuple(item.material_id for item in materials if item.kind in (MaterialKind.CHANGED_CONTENT, MaterialKind.DELETION))
    representations = tuple(item for item in materials if item.kind is MaterialKind.TRANSFORMED_REPRESENTATION)
    context_ids = tuple(item.trusted_context_id for item in materials if item.kind is MaterialKind.TRUSTED_CONTEXT)
    manifest = replace(
        request.envelope.input_manifest, changed_material_ids=changed_ids,
        representation_ids=tuple(item.representation_id for item in representations),
        represented_material_ids=tuple(item.represented_material_id for item in representations),
        trusted_context_ids=context_ids, supplemental_context_ids=tuple(item.material_id for item in supplemental),
    )
    envelope = replace(request.envelope, materials=tuple(materials), supplemental_context=tuple(supplemental), input_manifest=manifest)
    invocation = minted_copy(
        request.invocation, required_material_ids=changed_ids,
        representation_ids=manifest.representation_ids, required_context_ids=context_ids,
        supplemental_context_ids=manifest.supplemental_context_ids,
    )
    resources = tuple(disclosed_resource(item) for item in (*materials, *supplemental))
    requirement = minted_copy(request.disclosure_requirement, disclosed_resources=resources)
    authorization = mint(
        TrustedDisclosureAuthorizationBinding, target_registration_id=request.subject.target_registration_id,
        repository_id=request.subject.repository_id, authorization_id=request.subject.authorization_id,
        policy_epoch_identity=request.subject.policy_epoch_identity, profile_id=request.subject.profile_id,
        service_id=request.slot.profile.service_id, canonical_request_id=request.invocation.canonical_request_id,
        decision_id=DisclosureDecisionId("decision"), permitted_resources=resources,
    )
    return replace(
        request, envelope=envelope, invocation=invocation,
        disclosure_requirement=requirement, disclosure_authorization=authorization,
    )


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


def test_operation_binding_includes_exact_revision_and_full_g4_context():
    request = fixture()
    bad = minted_copy(request.operation_binding, operation_revision=99)
    assert admit_semantic_review(replace(request, operation_binding=bad)).reason_code is EvidenceAdmissionReasonCode.OPERATION_BINDING_MISMATCH


def test_mixed_canonical_occurrences_fail_evidence_admission_closed():
    request = fixture()
    attempts = minted_copy(
        request.slot_attempt_history,
        canonical_state_occurrence_binding=CanonicalStateOccurrenceBinding(BackendGeneration(2)),
    )
    result = admit_semantic_review(replace(request, slot_attempt_history=attempts))
    assert result.reason_code is EvidenceAdmissionReasonCode.REVIEW_SLOT_ATTEMPT_CONFLICT


def test_duplicate_requirement_result_precedes_set_equality():
    result = admit_semantic_review(fixture(verdict(duplicate=True)))
    assert result.reason_code is EvidenceAdmissionReasonCode.DUPLICATE_REQUIREMENT_RESULT


def test_unavailable_and_unsupported_schema_are_distinct():
    request = fixture()
    assert admit_semantic_review(replace(request, schema_context=None)).reason_code is EvidenceAdmissionReasonCode.SCHEMA_CONTEXT_UNAVAILABLE
    unsupported = mint(TrustedVerdictSchemaContext, schema_id=ImmutableConfigId("other"), version="2.0")
    assert admit_semantic_review(replace(request, schema_context=unsupported)).reason_code is EvidenceAdmissionReasonCode.UNSUPPORTED_VERDICT_SCHEMA


def test_finite_limits_precede_raw_parse_and_schema():
    assert admit_semantic_review(replace(fixture(), profile_admission_context=None, raw_response=b"bad")).reason_code is EvidenceAdmissionReasonCode.RAW_LIMIT_CONTEXT_UNAVAILABLE


def test_untrusted_more_permissive_parse_limit_cannot_bypass_profile_limit():
    request = fixture()
    raw = verdict()
    context = mint(
        TrustedReviewProfileAdmissionContext, baseline_config_id=ImmutableConfigId("baseline-parser"),
        policy_epoch_identity=request.subject.policy_epoch_identity, profile_id=request.subject.profile_id,
        profile_config_id=request.subject.profile_config_id,
        baseline_limits=ParseLimits(100000, 30), active_policy_limits=ParseLimits(100000, 30),
        profile_limits=ParseLimits(len(raw) - 1, 20),
    )
    result = admit_semantic_review(replace(request, raw_response=raw, parse_limits=ParseLimits(100000, 30), profile_admission_context=context))
    assert result.reason_code is EvidenceAdmissionReasonCode.RAW_RESPONSE_TOO_LARGE


def test_raw_response_identity_and_digest_are_exact():
    request = fixture()
    assert admit_semantic_review(replace(request, raw_response_id=RawReviewResponseId("other"))).reason_code is EvidenceAdmissionReasonCode.RESPONSE_BINDING_MISMATCH
    invocation = minted_copy(request.invocation, raw_response_sha256=RawSha256("9" * 64))
    assert admit_semantic_review(replace(request, invocation=invocation)).reason_code is EvidenceAdmissionReasonCode.RESPONSE_BINDING_MISMATCH


def test_envelope_manifest_and_assignment_bindings_are_exact():
    request = fixture()
    assert admit_semantic_review(replace(request, envelope=replace(request.envelope, envelope_id=ReviewEnvelopeId("other")))).reason_code is EvidenceAdmissionReasonCode.REQUEST_BINDING_MISMATCH
    bad_manifest = replace(request.envelope.input_manifest, manifest_id=ReviewInputManifestId("other"))
    assert admit_semantic_review(replace(request, envelope=replace(request.envelope, input_manifest=bad_manifest))).reason_code is EvidenceAdmissionReasonCode.REQUEST_BINDING_MISMATCH
    for field, value in (
        ("contract_id", ContractId("other")), ("contract_raw_sha256", RawSha256("8" * 64)),
        ("target_registration_id", TargetRegistrationId(RawSha256("7" * 64))),
        ("policy_epoch_identity", PolicyEpochIdentity(TrustedManifestId(RawSha256("6" * 64)))),
        ("requirements", (SemanticRequirement(SemanticRequirementId("other"), RAW),)),
    ):
        bad_assignment = minted_copy(request.assignment, **{field: value})
        assert admit_semantic_review(replace(request, assignment=bad_assignment)).reason_code is EvidenceAdmissionReasonCode.REQUEST_BINDING_MISMATCH


@pytest.mark.parametrize("change", [
    {"candidate_id": CandidateId("other-candidate")},
    {"base": GitSha("b" * 40)},
])
def test_admission_rejects_material_candidate_or_base_drift_with_stable_material_identity(change):
    request = fixture()
    original = request.envelope.materials[0]
    changed = replace(original, **change)
    envelope = replace(request.envelope, materials=(changed, *request.envelope.materials[1:]))
    classified = replace(original, classification_id=MaterialClassificationId("source"))
    assert changed.material_id == original.material_id
    assert disclosed_resource(replace(classified, **change)) != disclosed_resource(classified)
    assert admit_semantic_review(replace(request, envelope=envelope)).reason_code is EvidenceAdmissionReasonCode.REQUEST_BINDING_MISMATCH


@pytest.mark.parametrize(("field", "value"), [
    ("contract_id", ContractId("other")),
    ("contract_raw_sha256", RawSha256("8" * 64)),
    ("target_registration_id", TargetRegistrationId(RawSha256("7" * 64))),
    ("policy_epoch_identity", PolicyEpochIdentity(TrustedManifestId(RawSha256("6" * 64)))),
    ("requirement_ids", (SemanticRequirementId("other"),)),
])
def test_effective_subject_mismatch_is_denied_before_request_package(field, value):
    request = fixture()
    effective = minted_copy(request.effective_subject, **{field: value})
    assert admit_semantic_review(replace(request, effective_subject=effective)).reason_code is EvidenceAdmissionReasonCode.SUBJECT_BINDING_MISMATCH


@pytest.mark.parametrize(("field", "value"), [
    ("repository_id", GitHubRepositoryId("2")),
    ("base", GitSha("b" * 40)),
    ("target_context_id", TargetContextId("other-target")),
    ("pr_id", PullRequestIdentity("other-pr")),
    ("required_material_ids", (MaterialIdentity("other-material"),)),
    ("required_context_ids", (TrustedContextId("other-context"),)),
])
def test_effective_and_evidence_subject_common_context_must_match(field, value):
    request = fixture()
    changed_subject = replace(request.subject, **{field: value})
    assert admit_semantic_review(replace(request, subject=changed_subject)).reason_code is EvidenceAdmissionReasonCode.SUBJECT_BINDING_MISMATCH


def test_schema_identity_is_cross_checked_across_complete_package():
    request = fixture()
    bad_manifest = replace(request.envelope.input_manifest, verdict_schema_id=ImmutableConfigId("other"))
    assert admit_semantic_review(replace(request, envelope=replace(request.envelope, input_manifest=bad_manifest))).reason_code is EvidenceAdmissionReasonCode.REQUEST_BINDING_MISMATCH
    assert admit_semantic_review(replace(request, subject=replace(request.subject, verdict_schema_id=ImmutableConfigId("other")))).reason_code is EvidenceAdmissionReasonCode.PROFILE_BINDING_MISMATCH


def test_disclosure_required_unavailable_escalates_and_contradiction_denies():
    required = fixture(disclosure=DisclosureApplicability.REQUIRED)
    result = admit_semantic_review(required)
    assert (result.decision, result.reason_code) == (EvidenceAdmissionDecision.ESCALATE, EvidenceAdmissionReasonCode.DISCLOSURE_CONTEXT_UNAVAILABLE)
    contradiction = replace(fixture(), disclosure_authorization=mint(TrustedDisclosureAuthorizationBinding))
    assert admit_semantic_review(contradiction).reason_code is EvidenceAdmissionReasonCode.DISCLOSURE_BINDING_MISMATCH


def test_disclosure_requirement_and_authorization_bind_every_identity():
    request = fixture(disclosure=DisclosureApplicability.REQUIRED)
    requirement = request.disclosure_requirement
    for field, value in (
        ("invocation_id", ReviewInvocationId("other")), ("slot_id", ReviewSlotId("other")),
        ("profile_id", ReviewerProfileId("other")), ("canonical_request_id", CanonicalRequestId("other")),
    ):
        assert admit_semantic_review(replace(request, disclosure_requirement=minted_copy(requirement, **{field: value}))).reason_code is EvidenceAdmissionReasonCode.DISCLOSURE_BINDING_MISMATCH
    classified = tuple(replace(item, classification_id=MaterialClassificationId(f"class-{index}")) for index, item in enumerate(request.envelope.materials))
    exact = with_disclosure_package(request, classified)
    assert admit_semantic_review(exact).decision is EvidenceAdmissionDecision.ADMIT
    wrong_repo = minted_copy(exact.disclosure_authorization, repository_id=GitHubRepositoryId("2"))
    assert admit_semantic_review(replace(exact, disclosure_authorization=wrong_repo)).reason_code is EvidenceAdmissionReasonCode.DISCLOSURE_BINDING_MISMATCH
    first = exact.disclosure_authorization.permitted_resources[0]
    wrong_resource = replace(first, material_id=MaterialIdentity("package-b-material"))
    wrong_package = minted_copy(exact.disclosure_authorization, permitted_resources=(wrong_resource, *exact.disclosure_authorization.permitted_resources[1:]))
    assert admit_semantic_review(replace(exact, disclosure_authorization=wrong_package)).reason_code is EvidenceAdmissionReasonCode.DISCLOSURE_BINDING_MISMATCH


@pytest.mark.parametrize("change", [
    {"path_or_resource": "renamed.py"},
    {"content_or_deletion_identity": "different-content"},
])
def test_disclosure_authorization_cannot_be_reused_after_exact_resource_drift(change):
    request = fixture(disclosure=DisclosureApplicability.REQUIRED)
    classified = tuple(
        replace(item, classification_id=MaterialClassificationId(f"class-{index}"))
        for index, item in enumerate(request.envelope.materials)
    )
    exact = with_disclosure_package(request, classified)
    changed = replace(exact.envelope.materials[0], **change)
    assert changed.material_id == exact.envelope.materials[0].material_id
    changed_envelope = replace(exact.envelope, materials=(changed, *exact.envelope.materials[1:]))
    assert admit_semantic_review(replace(exact, envelope=changed_envelope)).reason_code is EvidenceAdmissionReasonCode.DISCLOSURE_BINDING_MISMATCH


def test_exact_unchanged_disclosed_resource_package_remains_permitted():
    request = fixture(disclosure=DisclosureApplicability.REQUIRED)
    classified = tuple(
        replace(item, classification_id=MaterialClassificationId(f"class-{index}"))
        for index, item in enumerate(request.envelope.materials)
    )
    exact = with_disclosure_package(request, classified)
    assert admit_semantic_review(exact).decision is EvidenceAdmissionDecision.ADMIT


def test_required_disclosure_covers_supplemental_and_transformed_resources():
    request = fixture(disclosure=DisclosureApplicability.REQUIRED)
    classified = tuple(replace(item, classification_id=MaterialClassificationId(f"class-{index}")) for index, item in enumerate(request.envelope.materials))
    supplemental = MaterialBinding(
        MaterialIdentity("supplemental"), request.subject.repository_id,
        MaterialKind.SUPPLEMENTAL_UNTRUSTED_CONTEXT, "notes", "notes-content", None,
        request.subject.base, classification_id=MaterialClassificationId("supplemental-class"),
    )
    transformed = MaterialBinding(
        MaterialIdentity("rendered"), request.subject.repository_id,
        MaterialKind.TRANSFORMED_REPRESENTATION, "render", "render-content",
        request.subject.candidate_id, request.subject.base, RepresentationIdentity("render-rule"),
        represented_material_id=request.subject.required_material_ids[0],
        classification_id=MaterialClassificationId("render-class"),
    )
    material_assignment = replace(
        request.assignment.material_assignments[0],
        permitted_representation_ids=(RepresentationIdentity("render-rule"),),
    )
    request = replace(request, assignment=minted_copy(request.assignment, material_assignments=(material_assignment,)))
    exact = with_disclosure_package(request, (*classified, transformed), (supplemental,))
    assert admit_semantic_review(exact).decision is EvidenceAdmissionDecision.ADMIT
    omitted_supplemental = minted_copy(exact.disclosure_authorization, permitted_resources=exact.disclosure_authorization.permitted_resources[:-1])
    assert admit_semantic_review(replace(exact, disclosure_authorization=omitted_supplemental)).reason_code is EvidenceAdmissionReasonCode.DISCLOSURE_BINDING_MISMATCH
    omitted_transformed = minted_copy(exact.disclosure_authorization, permitted_resources=tuple(item for item in exact.disclosure_authorization.permitted_resources if item.kind is not MaterialKind.TRANSFORMED_REPRESENTATION))
    assert admit_semantic_review(replace(exact, disclosure_authorization=omitted_transformed)).reason_code is EvidenceAdmissionReasonCode.DISCLOSURE_BINDING_MISMATCH


def test_required_disclosure_rejects_any_unclassified_resource():
    request = fixture(disclosure=DisclosureApplicability.REQUIRED)
    authorization = mint(
        TrustedDisclosureAuthorizationBinding, target_registration_id=request.subject.target_registration_id,
        repository_id=request.subject.repository_id, authorization_id=request.subject.authorization_id,
        policy_epoch_identity=request.subject.policy_epoch_identity, profile_id=request.subject.profile_id,
        service_id=request.slot.profile.service_id, canonical_request_id=request.invocation.canonical_request_id,
        decision_id=DisclosureDecisionId("decision"), permitted_resources=(),
    )
    assert admit_semantic_review(replace(request, disclosure_authorization=authorization)).reason_code is EvidenceAdmissionReasonCode.DISCLOSURE_BINDING_MISMATCH


def test_subject_echo_pr_identity_is_exact():
    body = json.loads(verdict())
    body["subject_echo"] = {"repository_id": "1", "task_id": "task", "contract_id": "contract", "candidate_id": "candidate", "pr_id": "other"}
    raw = json.dumps(body, separators=(",", ":")).encode()
    request = fixture(raw=raw)
    assert admit_semantic_review(request).reason_code is EvidenceAdmissionReasonCode.SUBJECT_ECHO_MISMATCH


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


def test_admission_revalidates_rereview_retry_and_exact_snapshot_subjects():
    request = fixture()
    existing = AdmittedSemanticEvidenceBinding(EvidenceId("earlier"), ReviewInvocationId("earlier-inv"), request.slot.slot_id, True)
    history = minted_copy(request.evidence_history, admitted_bindings=(existing,))
    assert admit_semantic_review(replace(request, evidence_history=history)).reason_code is EvidenceAdmissionReasonCode.REREVIEW_NOT_PERMITTED
    rereview = mint(TrustedReReviewAuthorization, authorization_id=ReReviewAuthorizationId("rr"), subject_id=request.effective_subject.subject_id, slot_id=request.slot.slot_id, reason=ReReviewReason.AUTHORIZED_ADJUDICATION)
    assert admit_semantic_review(replace(request, evidence_history=history, rereview_authorization=rereview)).decision is EvidenceAdmissionDecision.ADMIT

    prior = ReviewSlotAttempt(ReviewInvocationId("prior"), request.slot.slot_id, OperationId("prior-op"), OperationState.FAILED, CanonicalRequestId("prior-request"))
    attempts = minted_copy(request.slot_attempt_history, attempts=(prior, *request.slot_attempt_history.attempts))
    assert admit_semantic_review(replace(request, slot_attempt_history=attempts)).reason_code is EvidenceAdmissionReasonCode.REVIEW_SLOT_ATTEMPT_CONFLICT
    retry = mint(TrustedOperationalRetryAuthorization, subject_id=request.effective_subject.subject_id, slot_id=request.slot.slot_id, prior_operation_id=prior.operation_id)
    assert admit_semantic_review(replace(request, slot_attempt_history=attempts, operational_retry_authorization=retry)).decision is EvidenceAdmissionDecision.ADMIT

    other_subject = minted_copy(request.effective_subject, candidate_id=CandidateId("other"))
    assert admit_semantic_review(replace(request, evidence_history=minted_copy(request.evidence_history, subject=other_subject))).reason_code is EvidenceAdmissionReasonCode.REREVIEW_NOT_PERMITTED
    assert admit_semantic_review(replace(request, slot_attempt_history=minted_copy(request.slot_attempt_history, subject=other_subject))).reason_code is EvidenceAdmissionReasonCode.REVIEW_SLOT_ATTEMPT_CONFLICT
    assert admit_semantic_review(replace(request, slot_attempt_history=minted_copy(request.slot_attempt_history, attempts=()))).reason_code is EvidenceAdmissionReasonCode.REVIEW_SLOT_ATTEMPT_CONFLICT


@pytest.mark.parametrize(("field", "reason"), [
    ("candidate_id", EvidenceApplicabilityReason.CANDIDATE_CHANGED),
    ("base", EvidenceApplicabilityReason.BASE_CHANGED),
    ("slot_id", EvidenceApplicabilityReason.REVIEW_SLOT_CHANGED),
    ("profile_id", EvidenceApplicabilityReason.REVIEWER_PROFILE_CHANGED),
    ("profile_config_id", EvidenceApplicabilityReason.REVIEWER_PROFILE_CONFIG_CHANGED),
    ("required_material_ids", EvidenceApplicabilityReason.REQUIRED_MATERIAL_CHANGED),
    ("required_context_ids", EvidenceApplicabilityReason.REQUIRED_CONTEXT_CHANGED),
])
def test_post_admission_applicability_is_exact(field, reason):
    record = admit_semantic_review(fixture()).proposed_evidence_record
    replacements = {"candidate_id": CandidateId("new"), "base": GitSha("b" * 40), "slot_id": ReviewSlotId("new"), "profile_id": ReviewerProfileId("new"), "profile_config_id": ImmutableConfigId("new"), "required_material_ids": (MaterialIdentity("new"),), "required_context_ids": (TrustedContextId("new"),)}
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


def test_semantic_status_composition_conflict_and_structured_supersession():
    request = fixture()
    approved = admit_semantic_review(request).proposed_evidence_record
    assert semantic_status_for_verdict(SemanticVerdict.APPROVED) is __import__('autodev_control.trusted.state', fromlist=['ConditionStatus']).ConditionStatus.SATISFIED
    changed_request = fixture(raw=verdict("changes_required", overall="changes_required"))
    changed = replace(admit_semantic_review(changed_request).proposed_evidence_record, evidence_id=EvidenceId("later"))
    context = mint(TrustedSemanticCompositionContext, effective_subject=request.effective_subject, composition_rule=request.composition_rule)
    snapshot = mint(
        TrustedCanonicalSemanticEvidenceSnapshot, effective_subject=request.effective_subject,
        membership_binding=EvidenceHistoryMembershipBindingId("canonical-H"),
        complete_admitted_records=(approved, changed),
    )
    with pytest.raises(TypeError):
        compose_semantic_evidence((approved,), context)
    with pytest.raises(TypeError):
        TrustedCanonicalSemanticEvidenceSnapshot(request.effective_subject, EvidenceHistoryMembershipBindingId("H"), (approved,))
    with pytest.raises(TypeError):
        replace(snapshot, complete_admitted_records=(approved,))
    conflict = compose_semantic_evidence(snapshot, context)
    assert conflict.reason is SemanticCompositionReason.CONFLICTING_APPLICABLE_EVIDENCE
    assert conflict.evidence_history_membership_binding == EvidenceHistoryMembershipBindingId("canonical-H")

    early = mint(TrustedAdmittedEvidenceRecord, record=approved, membership_binding=EvidenceHistoryMembershipBindingId("H1"))
    late = mint(TrustedAdmittedEvidenceRecord, record=changed, membership_binding=EvidenceHistoryMembershipBindingId("H2"))
    authorization = mint(
        TrustedSupersessionAuthorization, decision_id=SupersessionDecisionId("decision"),
        subject_id=approved.payload.effective_subject_id, policy_epoch_identity=approved.subject.policy_epoch_identity,
        earlier_evidence_id=approved.evidence_id, later_evidence_id=changed.evidence_id,
        authorized_reason=SupersessionReason.AUTHORIZED_ADJUDICATION,
    )
    relation = build_evidence_supersession_record(early, late, authorization)
    composed = compose_semantic_evidence(snapshot, context, (relation,))
    assert composed.reason is SemanticCompositionReason.COMPOSED
    assert composed.requirement_statuses[0].status.name == "UNSATISFIED"
    assert approved.payload.aggregate is SemanticVerdict.APPROVED

    omitted_later = mint(
        TrustedCanonicalSemanticEvidenceSnapshot, effective_subject=request.effective_subject,
        membership_binding=EvidenceHistoryMembershipBindingId("canonical-H2"),
        complete_admitted_records=(approved,),
    )
    assert compose_semantic_evidence(omitted_later, context, (relation,)).reason is SemanticCompositionReason.CONFLICTING_APPLICABLE_EVIDENCE


@pytest.mark.parametrize("mode", [
    CompositionMode.ALL_REQUIRED_INVOCATIONS,
    CompositionMode.EXACT_REQUIRED_INVOCATION_SET,
])
def test_malformed_zero_slot_composition_fails_closed_for_nonempty_requirements(mode):
    request = fixture()
    malformed_rule = mint(
        SemanticReviewCompositionRule,
        composition_rule_id=request.effective_subject.composition_rule_id,
        mode=mode,
        required_slots=(),
    )
    context = mint(
        TrustedSemanticCompositionContext,
        effective_subject=request.effective_subject,
        composition_rule=malformed_rule,
    )
    snapshot = mint(
        TrustedCanonicalSemanticEvidenceSnapshot,
        effective_subject=request.effective_subject,
        membership_binding=EvidenceHistoryMembershipBindingId("zero-slot-H"),
        complete_admitted_records=(),
    )
    result = compose_semantic_evidence(snapshot, context)
    assert request.effective_subject.requirement_ids
    assert result.reason is SemanticCompositionReason.INVALID_COMPOSITION_RULE
    assert result.requirement_statuses == ()


def second_slot_record(record, slot, verdict_value):
    unable = UnableReasonCode.OTHER if verdict_value is SemanticVerdict.UNABLE_TO_DETERMINE else None
    result = replace(record.payload.requirement_results[0], verdict=verdict_value, unable_reason_code=unable)
    subject = replace(
        record.subject, invocation_id=ReviewInvocationId(f"inv-{slot.slot_id.value}"), slot_id=slot.slot_id,
        profile_id=slot.profile.profile_id, profile_config_id=slot.profile.config_id,
        verdict_schema_id=slot.profile.verdict_schema_id,
    )
    payload = replace(
        record.payload, slot_id=slot.slot_id, invocation_id=subject.invocation_id,
        profile_id=slot.profile.profile_id, profile_config_id=slot.profile.config_id,
        service_id=slot.profile.service_id, verdict_schema_id=slot.profile.verdict_schema_id,
        requirement_results=(result,), aggregate=verdict_value,
    )
    return replace(record, evidence_id=EvidenceId(f"evidence-{slot.slot_id.value}-{verdict_value.value}"), subject=subject, payload=payload)


@pytest.mark.parametrize(("slot_b_verdict", "expected"), [
    (SemanticVerdict.APPROVED, "SATISFIED"),
    (SemanticVerdict.CHANGES_REQUIRED, "UNSATISFIED"),
    (SemanticVerdict.UNABLE_TO_DETERMINE, "INDETERMINATE"),
])
def test_two_slot_composition_uses_common_subject_and_exact_per_slot_profile(slot_b_verdict, expected):
    request = fixture()
    slot_a = request.slot
    profile_b = replace(
        slot_a.profile, profile_id=ReviewerProfileId("profile-b"),
        config_id=ImmutableConfigId("profile-b-config"), service_id=ReviewerServiceId("service-b"),
    )
    slot_b = ReviewSlot(ReviewSlotId("slot-b"), profile_b, RawSha256("4" * 64))
    rule = SemanticReviewCompositionRule(
        request.composition_rule.composition_rule_id, CompositionMode.ALL_REQUIRED_INVOCATIONS,
        (slot_a, slot_b),
    )
    approved_a = admit_semantic_review(request).proposed_evidence_record
    record_b = second_slot_record(approved_a, slot_b, slot_b_verdict)
    context = mint(TrustedSemanticCompositionContext, effective_subject=request.effective_subject, composition_rule=rule)
    snapshot = mint(
        TrustedCanonicalSemanticEvidenceSnapshot, effective_subject=request.effective_subject,
        membership_binding=EvidenceHistoryMembershipBindingId("two-slot-H"),
        complete_admitted_records=(approved_a, record_b),
    )
    result = compose_semantic_evidence(snapshot, context)
    assert result.reason is SemanticCompositionReason.COMPOSED
    assert result.requirement_statuses[0].status.name == expected

    changed_profile_b = replace(profile_b, config_id=ImmutableConfigId("profile-b-new-config"))
    changed_rule = SemanticReviewCompositionRule(rule.composition_rule_id, rule.mode, (slot_a, replace(slot_b, profile=changed_profile_b)))
    changed_context = mint(TrustedSemanticCompositionContext, effective_subject=request.effective_subject, composition_rule=changed_rule)
    assert compose_semantic_evidence(snapshot, changed_context).reason is SemanticCompositionReason.REQUIRED_SLOT_MISSING


@pytest.mark.parametrize(("verdict_value", "status"), [
    (SemanticVerdict.APPROVED, "SATISFIED"),
    (SemanticVerdict.CHANGES_REQUIRED, "UNSATISFIED"),
    (SemanticVerdict.UNABLE_TO_DETERMINE, "INDETERMINATE"),
])
def test_per_requirement_semantic_status_is_closed(verdict_value, status):
    assert semantic_status_for_verdict(verdict_value).name == status


def test_g5_public_value_constructors_reject_mutable_nested_inputs():
    request = fixture()
    with pytest.raises(TypeError):
        replace(request.subject, required_context_ids=[])
    with pytest.raises(TypeError):
        replace(request.envelope.input_manifest, supplemental_context_ids=[])
    with pytest.raises(TypeError):
        replace(admit_semantic_review(request).proposed_evidence_record.payload, findings=[])


def test_production_evidence_module_exposes_no_fixture_minting_helper():
    module = __import__("autodev_control.trusted.evidence", fromlist=["*"])
    assert not any(name.endswith("for_test") for name in vars(module))
