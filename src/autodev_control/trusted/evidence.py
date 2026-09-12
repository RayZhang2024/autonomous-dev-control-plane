"""Provenance-bound Evidence Admission and applicability for G5.

Admission results are conditional non-bearer proposals.  This module neither
persists evidence nor calls reviewers, providers, GitHub, or protected effects.
"""

from dataclasses import dataclass
from enum import Enum

from .identity import GitSha, ImmutableConfigId, RawSha256
from .manifest import PolicyEpochIdentity
from .operation import AdmissionEventId, CandidateId, EvidenceId, OperationId, OperationRecord, OperationState
from .parsing import ParseLimits
from .review import (
    CanonicalRequestId, CompositionMode, DisclosureApplicability,
    EvidenceAdmissionEventId, EvidenceHistoryMembershipBindingId,
    EvidenceProducerEventId, FindingKind, RawReviewResponseId,
    RawSemanticVerdict, ReviewEnvelopeId, ReviewFinding, ReviewInputManifestId,
    ReviewInvocationId, ReviewerProfileBinding, ReviewerProfileId, ReviewerServiceId,
    ReviewOperationRole,
    ReviewSlot, ReviewSlotId, SemanticRequirementId, SemanticReviewCompositionRule,
    SemanticReviewEffectiveSubject, SemanticReviewEffectiveSubjectId, SemanticVerdict,
    TargetContextId, TrustedDisclosureAuthorizationBinding, TrustedDisclosureRequirement,
    TrustedEffectiveSubjectEvidenceSnapshot, TrustedReviewEnvelope,
    TrustedReviewInvocationRecord, TrustedReviewOperationBinding,
    TrustedReviewSlotAttemptSnapshot, UnableReasonCode, VerdictValidationReason,
    evaluate_review_invocation_eligibility, validate_review_verdict_v1,
)
from .scope import AuthorizationId, ContractId, GitHubRepositoryId, TargetRegistrationId, TaskId


class EvidenceClass(Enum):
    DETERMINISTIC = "DETERMINISTIC"
    SEMANTIC_REVIEW = "SEMANTIC_REVIEW"
    CONTROLLED_RUNTIME = "CONTROLLED_RUNTIME"
    EXTERNAL_OBSERVATION = "EXTERNAL_OBSERVATION"
    HUMAN_APPROVAL = "HUMAN_APPROVAL"


class EvidenceAdmissionDecision(Enum):
    ADMIT = "ADMIT"
    DENY = "DENY"
    ESCALATE = "ESCALATE"


class EvidenceAdmissionReasonCode(Enum):
    ADMITTED = "ADMITTED"
    ADMISSION_CONTEXT_UNAVAILABLE = "ADMISSION_CONTEXT_UNAVAILABLE"
    RAW_LIMIT_CONTEXT_UNAVAILABLE = "RAW_LIMIT_CONTEXT_UNAVAILABLE"
    SCHEMA_CONTEXT_UNAVAILABLE = "SCHEMA_CONTEXT_UNAVAILABLE"
    PROFILE_CONTEXT_UNAVAILABLE = "PROFILE_CONTEXT_UNAVAILABLE"
    PROVENANCE_CONTEXT_UNAVAILABLE = "PROVENANCE_CONTEXT_UNAVAILABLE"
    OPERATION_CONTEXT_UNAVAILABLE = "OPERATION_CONTEXT_UNAVAILABLE"
    DISCLOSURE_CONTEXT_UNAVAILABLE = "DISCLOSURE_CONTEXT_UNAVAILABLE"
    FRESHNESS_CONTEXT_UNAVAILABLE = "FRESHNESS_CONTEXT_UNAVAILABLE"
    REREVIEW_CONTEXT_UNAVAILABLE = "REREVIEW_CONTEXT_UNAVAILABLE"
    SLOT_ATTEMPT_CONTEXT_UNAVAILABLE = "SLOT_ATTEMPT_CONTEXT_UNAVAILABLE"
    RAW_RESPONSE_TOO_LARGE = "RAW_RESPONSE_TOO_LARGE"
    RAW_RESPONSE_PARSE_FAILED = "RAW_RESPONSE_PARSE_FAILED"
    UNSUPPORTED_VERDICT_SCHEMA = "UNSUPPORTED_VERDICT_SCHEMA"
    SCHEMA_VALIDATION_FAILED = "SCHEMA_VALIDATION_FAILED"
    INVOCATION_BINDING_MISMATCH = "INVOCATION_BINDING_MISMATCH"
    SUBJECT_BINDING_MISMATCH = "SUBJECT_BINDING_MISMATCH"
    SUBJECT_ECHO_MISMATCH = "SUBJECT_ECHO_MISMATCH"
    PROFILE_BINDING_MISMATCH = "PROFILE_BINDING_MISMATCH"
    REQUEST_BINDING_MISMATCH = "REQUEST_BINDING_MISMATCH"
    RESPONSE_BINDING_MISMATCH = "RESPONSE_BINDING_MISMATCH"
    OPERATION_BINDING_MISMATCH = "OPERATION_BINDING_MISMATCH"
    OPERATION_NOT_SUCCEEDED = "OPERATION_NOT_SUCCEEDED"
    DISCLOSURE_BINDING_MISMATCH = "DISCLOSURE_BINDING_MISMATCH"
    DUPLICATE_REQUIREMENT_RESULT = "DUPLICATE_REQUIREMENT_RESULT"
    REQUIREMENT_SET_MISMATCH = "REQUIREMENT_SET_MISMATCH"
    FINDING_ID_DUPLICATE = "FINDING_ID_DUPLICATE"
    FINDING_REFERENCE_INVALID = "FINDING_REFERENCE_INVALID"
    FINDING_RELATION_INVALID = "FINDING_RELATION_INVALID"
    LOCATION_INVALID = "LOCATION_INVALID"
    UNABLE_REASON_INVALID = "UNABLE_REASON_INVALID"
    OVERALL_VERDICT_MISMATCH = "OVERALL_VERDICT_MISMATCH"
    CONTRACT_BINDING_MISMATCH = "CONTRACT_BINDING_MISMATCH"
    AUTHORIZATION_BINDING_MISMATCH = "AUTHORIZATION_BINDING_MISMATCH"
    TASK_ADMISSION_EVENT_BINDING_MISMATCH = "TASK_ADMISSION_EVENT_BINDING_MISMATCH"
    TARGET_BINDING_MISMATCH = "TARGET_BINDING_MISMATCH"
    POLICY_EPOCH_MISMATCH = "POLICY_EPOCH_MISMATCH"
    CANDIDATE_CONTEXT_MISMATCH = "CANDIDATE_CONTEXT_MISMATCH"
    ADMISSION_CONTEXT_STALE = "ADMISSION_CONTEXT_STALE"
    REVIEW_SLOT_ATTEMPT_CONFLICT = "REVIEW_SLOT_ATTEMPT_CONFLICT"
    REREVIEW_NOT_PERMITTED = "REREVIEW_NOT_PERMITTED"
    EVIDENCE_PROPOSAL_IDENTITY_INVALID = "EVIDENCE_PROPOSAL_IDENTITY_INVALID"
    UNSUPPORTED_REVIEW_PARTITIONING = "UNSUPPORTED_REVIEW_PARTITIONING"


@dataclass(frozen=True, slots=True)
class EvidenceSubject:
    repository_id: GitHubRepositoryId
    task_id: TaskId
    contract_id: ContractId
    contract_raw_sha256: RawSha256
    task_admission_event_id: AdmissionEventId
    authorization_id: AuthorizationId
    target_registration_id: TargetRegistrationId
    policy_epoch_identity: PolicyEpochIdentity
    candidate_id: CandidateId
    base: GitSha
    target_context_id: TargetContextId | None
    requirement_ids: tuple[SemanticRequirementId, ...]
    invocation_id: ReviewInvocationId
    slot_id: ReviewSlotId
    profile_id: ReviewerProfileId
    profile_config_id: ImmutableConfigId
    verdict_schema_id: ImmutableConfigId


@dataclass(frozen=True, slots=True)
class EvidenceRecordProposalIdentity:
    proposed_evidence_id: EvidenceId
    proposed_evidence_admission_event_id: EvidenceAdmissionEventId
    evidence_producer_event_id: EvidenceProducerEventId


@dataclass(frozen=True, slots=True)
class SemanticEvidencePayload:
    effective_subject_id: SemanticReviewEffectiveSubjectId
    slot_id: ReviewSlotId
    invocation_id: ReviewInvocationId
    envelope_id: ReviewEnvelopeId
    manifest_id: ReviewInputManifestId
    profile_id: ReviewerProfileId
    profile_config_id: ImmutableConfigId
    service_id: ReviewerServiceId
    operation_id: OperationId
    canonical_request_id: CanonicalRequestId
    raw_response_id: RawReviewResponseId
    requirement_results: tuple
    findings: tuple[ReviewFinding, ...]
    aggregate: SemanticVerdict
    verdict_schema_id: ImmutableConfigId


@dataclass(frozen=True, slots=True)
class EvidenceRecord:
    evidence_id: EvidenceId
    evidence_class: EvidenceClass
    subject: EvidenceSubject
    producer_event_id: EvidenceProducerEventId
    raw_response_id: RawReviewResponseId
    raw_response_sha256: RawSha256
    evidence_admission_event_id: EvidenceAdmissionEventId
    payload: SemanticEvidencePayload


@dataclass(frozen=True, slots=True, init=False)
class TrustedVerdictSchemaContext:
    schema_id: ImmutableConfigId
    version: str
    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("schema context must come from trusted configuration")


@dataclass(frozen=True, slots=True, init=False)
class TrustedCurrentEvidenceContext:
    subject: EvidenceSubject
    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("current context must come from trusted state")


@dataclass(frozen=True, slots=True)
class SemanticEvidenceAdmissionRequest:
    raw_response: bytes
    parse_limits: ParseLimits | None
    schema_context: TrustedVerdictSchemaContext | None
    expected_schema_id: ImmutableConfigId
    subject: EvidenceSubject
    effective_subject: SemanticReviewEffectiveSubject
    slot: ReviewSlot
    composition_rule: SemanticReviewCompositionRule
    envelope: TrustedReviewEnvelope
    invocation: TrustedReviewInvocationRecord | None
    operation_binding: TrustedReviewOperationBinding | None
    operation: OperationRecord | None
    disclosure_requirement: TrustedDisclosureRequirement | None
    disclosure_authorization: TrustedDisclosureAuthorizationBinding | None
    current_context: TrustedCurrentEvidenceContext | None
    evidence_history: TrustedEffectiveSubjectEvidenceSnapshot | None
    slot_attempt_history: TrustedReviewSlotAttemptSnapshot | None
    proposal_identity: EvidenceRecordProposalIdentity


@dataclass(frozen=True, slots=True)
class EvidenceAdmissionResult:
    decision: EvidenceAdmissionDecision
    reason_code: EvidenceAdmissionReasonCode
    proposed_evidence_record: EvidenceRecord | None = None
    expected_evidence_history_membership_binding: EvidenceHistoryMembershipBindingId | None = None


def _result(reason: EvidenceAdmissionReasonCode, *, record=None, history=None) -> EvidenceAdmissionResult:
    if reason is EvidenceAdmissionReasonCode.ADMITTED:
        return EvidenceAdmissionResult(EvidenceAdmissionDecision.ADMIT, reason, record, history)
    escalations = {
        EvidenceAdmissionReasonCode.ADMISSION_CONTEXT_UNAVAILABLE,
        EvidenceAdmissionReasonCode.RAW_LIMIT_CONTEXT_UNAVAILABLE,
        EvidenceAdmissionReasonCode.SCHEMA_CONTEXT_UNAVAILABLE,
        EvidenceAdmissionReasonCode.PROFILE_CONTEXT_UNAVAILABLE,
        EvidenceAdmissionReasonCode.PROVENANCE_CONTEXT_UNAVAILABLE,
        EvidenceAdmissionReasonCode.OPERATION_CONTEXT_UNAVAILABLE,
        EvidenceAdmissionReasonCode.DISCLOSURE_CONTEXT_UNAVAILABLE,
        EvidenceAdmissionReasonCode.FRESHNESS_CONTEXT_UNAVAILABLE,
        EvidenceAdmissionReasonCode.REREVIEW_CONTEXT_UNAVAILABLE,
        EvidenceAdmissionReasonCode.SLOT_ATTEMPT_CONTEXT_UNAVAILABLE,
    }
    decision = EvidenceAdmissionDecision.ESCALATE if reason in escalations else EvidenceAdmissionDecision.DENY
    return EvidenceAdmissionResult(decision, reason)


def recompute_semantic_aggregate(results: tuple) -> SemanticVerdict:
    if any(item.verdict is SemanticVerdict.UNABLE_TO_DETERMINE for item in results):
        return SemanticVerdict.UNABLE_TO_DETERMINE
    if any(item.verdict is SemanticVerdict.CHANGES_REQUIRED for item in results):
        return SemanticVerdict.CHANGES_REQUIRED
    return SemanticVerdict.APPROVED


def _echo_matches(echo, subject: EvidenceSubject) -> bool:
    if echo is None:
        return True
    checks = (
        echo.repository_id == subject.repository_id.value,
        echo.task_id == subject.task_id.value,
        echo.contract_id == subject.contract_id.value,
        echo.candidate_id == subject.candidate_id.value,
    )
    optional = (
        (echo.target_registration_id, subject.target_registration_id.raw_sha256.value),
        (echo.active_policy_id, subject.policy_epoch_identity.manifest_id.raw_sha256.value),
        (echo.base_id, subject.base.value),
        (echo.target_context_id, None if subject.target_context_id is None else subject.target_context_id.value),
    )
    return all(checks) and all(value is None or value == expected for value, expected in optional)


def _verdict_semantics(verdict: RawSemanticVerdict, subject: EvidenceSubject, tool_mode) -> EvidenceAdmissionReasonCode | None:
    ids = tuple(item.requirement_id for item in verdict.requirement_results)
    if len(set(ids)) != len(ids):
        return EvidenceAdmissionReasonCode.DUPLICATE_REQUIREMENT_RESULT
    if set(ids) != set(subject.requirement_ids):
        return EvidenceAdmissionReasonCode.REQUIREMENT_SET_MISMATCH
    finding_ids = tuple(item.finding_id for item in verdict.findings)
    if len(set(finding_ids)) != len(finding_ids):
        return EvidenceAdmissionReasonCode.FINDING_ID_DUPLICATE
    findings = {item.finding_id: item for item in verdict.findings}
    results = {item.requirement_id: item for item in verdict.requirement_results}
    for result in verdict.requirement_results:
        if any(fid not in findings or findings[fid].kind is not FindingKind.REQUIREMENT_ISSUE for fid in result.finding_ids):
            return EvidenceAdmissionReasonCode.FINDING_REFERENCE_INVALID
    if any(rid not in results for finding in verdict.findings for rid in finding.requirement_ids):
        return EvidenceAdmissionReasonCode.FINDING_REFERENCE_INVALID
    for finding in verdict.findings:
        if finding.kind is FindingKind.REQUIREMENT_ISSUE:
            for rid in finding.requirement_ids:
                result = results[rid]
                if result.verdict is not SemanticVerdict.CHANGES_REQUIRED or finding.finding_id not in result.finding_ids:
                    return EvidenceAdmissionReasonCode.FINDING_RELATION_INVALID
    for result in verdict.requirement_results:
        for fid in result.finding_ids:
            if result.requirement_id not in findings[fid].requirement_ids or result.verdict is not SemanticVerdict.CHANGES_REQUIRED:
                return EvidenceAdmissionReasonCode.FINDING_RELATION_INVALID
    if any(location.line_end is not None and location.line_start is not None and location.line_end < location.line_start for finding in verdict.findings for location in finding.locations):
        return EvidenceAdmissionReasonCode.LOCATION_INVALID
    if any(item.unable_reason_code is UnableReasonCode.PERMITTED_TOOL_FAILURE for item in verdict.requirement_results) and tool_mode.value == "NO_TOOLS":
        return EvidenceAdmissionReasonCode.UNABLE_REASON_INVALID
    aggregate = recompute_semantic_aggregate(verdict.requirement_results)
    if verdict.overall_verdict is not None and verdict.overall_verdict is not aggregate:
        return EvidenceAdmissionReasonCode.OVERALL_VERDICT_MISMATCH
    return None


def admit_semantic_review(request: SemanticEvidenceAdmissionRequest | None) -> EvidenceAdmissionResult:
    # The order below is the frozen Issue #14 stages 1 through 29.
    if request is None:
        return _result(EvidenceAdmissionReasonCode.ADMISSION_CONTEXT_UNAVAILABLE)
    if request.parse_limits is None:
        return _result(EvidenceAdmissionReasonCode.RAW_LIMIT_CONTEXT_UNAVAILABLE)
    parsed = validate_review_verdict_v1(request.raw_response, request.parse_limits)
    if parsed.reason is VerdictValidationReason.RAW_RESPONSE_TOO_LARGE:
        return _result(EvidenceAdmissionReasonCode.RAW_RESPONSE_TOO_LARGE)
    if parsed.reason is VerdictValidationReason.RAW_RESPONSE_PARSE_FAILED:
        return _result(EvidenceAdmissionReasonCode.RAW_RESPONSE_PARSE_FAILED)
    if request.schema_context is None:
        return _result(EvidenceAdmissionReasonCode.SCHEMA_CONTEXT_UNAVAILABLE)
    if request.schema_context.version != "1.0" or request.schema_context.schema_id != request.expected_schema_id:
        return _result(EvidenceAdmissionReasonCode.UNSUPPORTED_VERDICT_SCHEMA)
    if parsed.reason is not VerdictValidationReason.VALID:
        return _result(EvidenceAdmissionReasonCode.SCHEMA_VALIDATION_FAILED)
    verdict = parsed.verdict
    if verdict.review_invocation_id != request.subject.invocation_id:
        return _result(EvidenceAdmissionReasonCode.INVOCATION_BINDING_MISMATCH)
    invocation = request.invocation
    if invocation is None:
        return _result(EvidenceAdmissionReasonCode.PROVENANCE_CONTEXT_UNAVAILABLE)
    if invocation.subject != request.effective_subject:
        return _result(EvidenceAdmissionReasonCode.SUBJECT_BINDING_MISMATCH)
    if not _echo_matches(verdict.subject_echo, request.subject):
        return _result(EvidenceAdmissionReasonCode.SUBJECT_ECHO_MISMATCH)
    if invocation.profile != request.slot.profile or request.subject.profile_id != request.slot.profile.profile_id or request.subject.profile_config_id != request.slot.profile.config_id:
        return _result(EvidenceAdmissionReasonCode.PROFILE_BINDING_MISMATCH)
    if (request.envelope.invocation_id, request.envelope.slot_id, request.envelope.canonical_request_id) != (invocation.invocation_id, request.slot.slot_id, invocation.canonical_request_id):
        return _result(EvidenceAdmissionReasonCode.REQUEST_BINDING_MISMATCH)
    if invocation.raw_response_sha256 != verdict.source_document.raw_sha256 or invocation.raw_response_id != request.subject.invocation_id and False:
        return _result(EvidenceAdmissionReasonCode.RESPONSE_BINDING_MISMATCH)
    binding = request.operation_binding
    if binding is None or request.operation is None:
        return _result(EvidenceAdmissionReasonCode.OPERATION_CONTEXT_UNAVAILABLE)
    if binding.role is not ReviewOperationRole.SEMANTIC_REVIEW or (binding.invocation_id, binding.slot_id, binding.operation_id, binding.canonical_request_id, binding.task_id, binding.candidate_id) != (invocation.invocation_id, request.slot.slot_id, request.operation.intent.operation_id, invocation.canonical_request_id, request.subject.task_id, request.subject.candidate_id):
        return _result(EvidenceAdmissionReasonCode.OPERATION_BINDING_MISMATCH)
    if request.operation.state is not OperationState.SUCCEEDED:
        return _result(EvidenceAdmissionReasonCode.OPERATION_NOT_SUCCEEDED)
    disclosure = request.disclosure_requirement
    if disclosure is None:
        return _result(EvidenceAdmissionReasonCode.DISCLOSURE_CONTEXT_UNAVAILABLE)
    if disclosure.applicability is DisclosureApplicability.REQUIRED:
        if request.disclosure_authorization is None:
            return _result(EvidenceAdmissionReasonCode.DISCLOSURE_CONTEXT_UNAVAILABLE)
        auth = request.disclosure_authorization
        if (auth.target_registration_id, auth.authorization_id, auth.policy_epoch_identity, auth.profile_id, auth.service_id, auth.canonical_request_id) != (request.subject.target_registration_id, request.subject.authorization_id, request.subject.policy_epoch_identity, request.subject.profile_id, request.slot.profile.service_id, invocation.canonical_request_id):
            return _result(EvidenceAdmissionReasonCode.DISCLOSURE_BINDING_MISMATCH)
    elif request.disclosure_authorization is not None:
        return _result(EvidenceAdmissionReasonCode.DISCLOSURE_BINDING_MISMATCH)
    semantic_problem = _verdict_semantics(verdict, request.subject, request.slot.profile.tool_mode)
    if semantic_problem is not None:
        return _result(semantic_problem)
    # Stages 23 and 24: coherent originals first, current movement second.
    original = invocation.subject
    if original.contract_id != request.subject.contract_id or original.contract_raw_sha256 != request.subject.contract_raw_sha256:
        return _result(EvidenceAdmissionReasonCode.CONTRACT_BINDING_MISMATCH)
    if original.authorization_id != request.subject.authorization_id:
        return _result(EvidenceAdmissionReasonCode.AUTHORIZATION_BINDING_MISMATCH)
    if original.task_admission_event_id != request.subject.task_admission_event_id:
        return _result(EvidenceAdmissionReasonCode.TASK_ADMISSION_EVENT_BINDING_MISMATCH)
    if original.target_registration_id != request.subject.target_registration_id:
        return _result(EvidenceAdmissionReasonCode.TARGET_BINDING_MISMATCH)
    if original.policy_epoch_identity != request.subject.policy_epoch_identity:
        return _result(EvidenceAdmissionReasonCode.POLICY_EPOCH_MISMATCH)
    if original.candidate_id != request.subject.candidate_id:
        return _result(EvidenceAdmissionReasonCode.CANDIDATE_CONTEXT_MISMATCH)
    if request.current_context is None:
        return _result(EvidenceAdmissionReasonCode.FRESHNESS_CONTEXT_UNAVAILABLE)
    if request.current_context.subject != request.subject:
        return _result(EvidenceAdmissionReasonCode.ADMISSION_CONTEXT_STALE)
    if request.evidence_history is None:
        return _result(EvidenceAdmissionReasonCode.REREVIEW_CONTEXT_UNAVAILABLE)
    if request.slot_attempt_history is None:
        return _result(EvidenceAdmissionReasonCode.SLOT_ATTEMPT_CONTEXT_UNAVAILABLE)
    eligibility = evaluate_review_invocation_eligibility(
        request.effective_subject, request.slot, request.composition_rule,
        request.evidence_history, request.slot_attempt_history,
    )
    # The completing SUCCEEDED attempt is expected; another attempt/evidence is not.
    other_attempts = tuple(a for a in request.slot_attempt_history.attempts if a.operation_id != binding.operation_id and a.slot_id == request.slot.slot_id)
    existing = tuple(e for e in request.evidence_history.admitted_bindings if e.slot_id == request.slot.slot_id and e.substantive)
    if other_attempts:
        return _result(EvidenceAdmissionReasonCode.REVIEW_SLOT_ATTEMPT_CONFLICT)
    if existing:
        return _result(EvidenceAdmissionReasonCode.REREVIEW_NOT_PERMITTED)
    identity = request.proposal_identity
    if type(identity.proposed_evidence_id) is not EvidenceId or type(identity.proposed_evidence_admission_event_id) is not EvidenceAdmissionEventId or type(identity.evidence_producer_event_id) is not EvidenceProducerEventId:
        return _result(EvidenceAdmissionReasonCode.EVIDENCE_PROPOSAL_IDENTITY_INVALID)
    aggregate = recompute_semantic_aggregate(verdict.requirement_results)
    payload = SemanticEvidencePayload(
        request.effective_subject.subject_id, request.slot.slot_id, invocation.invocation_id,
        invocation.envelope_id, invocation.manifest_id, request.slot.profile.profile_id,
        request.slot.profile.config_id, request.slot.profile.service_id, binding.operation_id,
        invocation.canonical_request_id, invocation.raw_response_id,
        verdict.requirement_results, verdict.findings, aggregate, request.expected_schema_id,
    )
    record = EvidenceRecord(
        identity.proposed_evidence_id, EvidenceClass.SEMANTIC_REVIEW, request.subject,
        identity.evidence_producer_event_id, invocation.raw_response_id,
        verdict.source_document.raw_sha256, identity.proposed_evidence_admission_event_id, payload,
    )
    return _result(EvidenceAdmissionReasonCode.ADMITTED, record=record, history=request.evidence_history.membership_binding)


class EvidenceApplicabilityDecision(Enum):
    APPLICABLE = "APPLICABLE"
    STALE = "STALE"
    INDETERMINATE = "INDETERMINATE"


class EvidenceApplicabilityReason(Enum):
    APPLICABLE = "APPLICABLE"
    CONTEXT_UNAVAILABLE = "CONTEXT_UNAVAILABLE"
    CANDIDATE_CHANGED = "CANDIDATE_CHANGED"
    BASE_CHANGED = "BASE_CHANGED"
    TARGET_CONTEXT_CHANGED = "TARGET_CONTEXT_CHANGED"
    CONTRACT_CHANGED = "CONTRACT_CHANGED"
    AUTHORIZATION_CHANGED = "AUTHORIZATION_CHANGED"
    TASK_ADMISSION_EVENT_CHANGED = "TASK_ADMISSION_EVENT_CHANGED"
    TARGET_REGISTRATION_CHANGED = "TARGET_REGISTRATION_CHANGED"
    POLICY_EPOCH_CHANGED = "POLICY_EPOCH_CHANGED"
    REQUIREMENT_SET_CHANGED = "REQUIREMENT_SET_CHANGED"
    REVIEW_SLOT_CHANGED = "REVIEW_SLOT_CHANGED"
    REVIEWER_PROFILE_CHANGED = "REVIEWER_PROFILE_CHANGED"
    REVIEWER_PROFILE_CONFIG_CHANGED = "REVIEWER_PROFILE_CONFIG_CHANGED"
    UNSUPPORTED_CONTINUATION_RULE = "UNSUPPORTED_CONTINUATION_RULE"


@dataclass(frozen=True, slots=True)
class EvidenceApplicabilityResult:
    decision: EvidenceApplicabilityDecision
    reason: EvidenceApplicabilityReason


def evaluate_evidence_applicability(record: EvidenceRecord, current: EvidenceSubject | None) -> EvidenceApplicabilityResult:
    if current is None:
        return EvidenceApplicabilityResult(EvidenceApplicabilityDecision.INDETERMINATE, EvidenceApplicabilityReason.CONTEXT_UNAVAILABLE)
    fields = (
        ("candidate_id", EvidenceApplicabilityReason.CANDIDATE_CHANGED),
        ("base", EvidenceApplicabilityReason.BASE_CHANGED),
        ("target_context_id", EvidenceApplicabilityReason.TARGET_CONTEXT_CHANGED),
        ("contract_id", EvidenceApplicabilityReason.CONTRACT_CHANGED),
        ("contract_raw_sha256", EvidenceApplicabilityReason.CONTRACT_CHANGED),
        ("authorization_id", EvidenceApplicabilityReason.AUTHORIZATION_CHANGED),
        ("task_admission_event_id", EvidenceApplicabilityReason.TASK_ADMISSION_EVENT_CHANGED),
        ("target_registration_id", EvidenceApplicabilityReason.TARGET_REGISTRATION_CHANGED),
        ("policy_epoch_identity", EvidenceApplicabilityReason.POLICY_EPOCH_CHANGED),
        ("requirement_ids", EvidenceApplicabilityReason.REQUIREMENT_SET_CHANGED),
        ("slot_id", EvidenceApplicabilityReason.REVIEW_SLOT_CHANGED),
        ("profile_id", EvidenceApplicabilityReason.REVIEWER_PROFILE_CHANGED),
        ("profile_config_id", EvidenceApplicabilityReason.REVIEWER_PROFILE_CONFIG_CHANGED),
    )
    for name, reason in fields:
        if getattr(record.subject, name) != getattr(current, name):
            return EvidenceApplicabilityResult(EvidenceApplicabilityDecision.STALE, reason)
    return EvidenceApplicabilityResult(EvidenceApplicabilityDecision.APPLICABLE, EvidenceApplicabilityReason.APPLICABLE)


@dataclass(frozen=True, slots=True, init=False)
class TrustedSupersessionAuthorization:
    decision_id: object
    subject_id: SemanticReviewEffectiveSubjectId
    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("supersession authorization must come from trusted policy boundary")


@dataclass(frozen=True, slots=True)
class EvidenceSupersessionRecord:
    earlier_evidence_id: EvidenceId
    later_evidence_id: EvidenceId
    subject_id: SemanticReviewEffectiveSubjectId
    authorization: TrustedSupersessionAuthorization
    authorized_reason: str
