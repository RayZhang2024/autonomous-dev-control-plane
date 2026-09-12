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
    RawSemanticVerdict, ReReviewReason, ReviewEnvelopeId, ReviewFinding, ReviewInputManifestId,
    ReviewPartitionRule,
    ReviewInvocationId, ReviewerProfileBinding, ReviewerProfileId, ReviewerServiceId,
    MaterialClassificationId, PullRequestIdentity, ReviewOperationRole, SupersessionDecisionId,
    SupersessionReason,
    ReviewSlot, ReviewSlotId, SemanticRequirementId, SemanticReviewCompositionRule,
    SemanticReviewAssignment, SemanticReviewEffectiveSubject, SemanticReviewEffectiveSubjectId, SemanticVerdict,
    TargetContextId, TrustedDisclosureAuthorizationBinding, TrustedDisclosureRequirement,
    TrustedEffectiveSubjectEvidenceSnapshot, TrustedReviewEnvelope,
    TrustedReviewInvocationRecord, TrustedReviewOperationBinding,
    TrustedOperationalRetryAuthorization, TrustedReReviewAuthorization,
    TrustedReviewProfileAdmissionContext, TrustedReviewSlotAttemptSnapshot,
    UnableReasonCode, VerdictValidationReason, effective_review_parse_limits,
    evaluate_review_invocation_eligibility, validate_review_verdict_v1,
)
from .scope import AuthorizationId, ContractId, GitHubRepositoryId, TargetRegistrationId, TaskId
from .state import ConditionStatus


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
    pr_id: PullRequestIdentity | None
    requirement_ids: tuple[SemanticRequirementId, ...]
    required_material_ids: tuple
    required_context_ids: tuple
    invocation_id: ReviewInvocationId
    slot_id: ReviewSlotId
    profile_id: ReviewerProfileId
    profile_config_id: ImmutableConfigId
    verdict_schema_id: ImmutableConfigId

    def __post_init__(self) -> None:
        from .review import MaterialIdentity, TrustedContextId
        exact = (
            (self.repository_id, GitHubRepositoryId), (self.task_id, TaskId),
            (self.contract_id, ContractId), (self.contract_raw_sha256, RawSha256),
            (self.task_admission_event_id, AdmissionEventId), (self.authorization_id, AuthorizationId),
            (self.target_registration_id, TargetRegistrationId), (self.policy_epoch_identity, PolicyEpochIdentity),
            (self.candidate_id, CandidateId), (self.base, GitSha), (self.invocation_id, ReviewInvocationId),
            (self.slot_id, ReviewSlotId), (self.profile_id, ReviewerProfileId),
            (self.profile_config_id, ImmutableConfigId), (self.verdict_schema_id, ImmutableConfigId),
        )
        if any(type(value) is not expected for value, expected in exact):
            raise TypeError("evidence subject field has wrong exact type")
        if self.target_context_id is not None and type(self.target_context_id) is not TargetContextId:
            raise TypeError("target_context_id has wrong exact type")
        if self.pr_id is not None and type(self.pr_id) is not PullRequestIdentity:
            raise TypeError("pr_id has wrong exact type")
        for values, expected, name in (
            (self.requirement_ids, SemanticRequirementId, "requirement_ids"),
            (self.required_material_ids, MaterialIdentity, "required_material_ids"),
            (self.required_context_ids, TrustedContextId, "required_context_ids"),
        ):
            if type(values) is not tuple or any(type(item) is not expected for item in values) or len(set(values)) != len(values):
                raise TypeError(f"{name} must be an exact duplicate-free tuple")


@dataclass(frozen=True, slots=True)
class EvidenceRecordProposalIdentity:
    proposed_evidence_id: EvidenceId
    proposed_evidence_admission_event_id: EvidenceAdmissionEventId
    evidence_producer_event_id: EvidenceProducerEventId

    def __post_init__(self) -> None:
        if type(self.proposed_evidence_id) is not EvidenceId or type(self.proposed_evidence_admission_event_id) is not EvidenceAdmissionEventId or type(self.evidence_producer_event_id) is not EvidenceProducerEventId:
            raise TypeError("proposal identity field has wrong exact type")


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

    def __post_init__(self) -> None:
        from .review import RequirementResult
        exact = (
            (self.effective_subject_id, SemanticReviewEffectiveSubjectId), (self.slot_id, ReviewSlotId),
            (self.invocation_id, ReviewInvocationId), (self.envelope_id, ReviewEnvelopeId),
            (self.manifest_id, ReviewInputManifestId), (self.profile_id, ReviewerProfileId),
            (self.profile_config_id, ImmutableConfigId), (self.service_id, ReviewerServiceId),
            (self.operation_id, OperationId), (self.canonical_request_id, CanonicalRequestId),
            (self.raw_response_id, RawReviewResponseId), (self.aggregate, SemanticVerdict),
            (self.verdict_schema_id, ImmutableConfigId),
        )
        if any(type(value) is not expected for value, expected in exact):
            raise TypeError("semantic payload field has wrong exact type")
        if type(self.requirement_results) is not tuple or any(type(item) is not RequirementResult for item in self.requirement_results):
            raise TypeError("requirement_results must be an exact immutable tuple")
        if type(self.findings) is not tuple or any(type(item) is not ReviewFinding for item in self.findings):
            raise TypeError("findings must be an exact immutable tuple")


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

    def __post_init__(self) -> None:
        exact = ((self.evidence_id, EvidenceId), (self.evidence_class, EvidenceClass),
                 (self.subject, EvidenceSubject), (self.producer_event_id, EvidenceProducerEventId),
                 (self.raw_response_id, RawReviewResponseId), (self.raw_response_sha256, RawSha256),
                 (self.evidence_admission_event_id, EvidenceAdmissionEventId),
                 (self.payload, SemanticEvidencePayload))
        if any(type(value) is not expected for value, expected in exact):
            raise TypeError("evidence record field has wrong exact type")


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
    profile_admission_context: TrustedReviewProfileAdmissionContext | None = None
    raw_response_id: RawReviewResponseId | None = None
    rereview_authorization: TrustedReReviewAuthorization | None = None
    operational_retry_authorization: TrustedOperationalRetryAuthorization | None = None
    assignment: SemanticReviewAssignment | None = None


@dataclass(frozen=True, slots=True)
class EvidenceAdmissionResult:
    decision: EvidenceAdmissionDecision
    reason_code: EvidenceAdmissionReasonCode
    proposed_evidence_record: EvidenceRecord | None = None
    expected_evidence_history_membership_binding: EvidenceHistoryMembershipBindingId | None = None

    def __post_init__(self) -> None:
        if type(self.decision) is not EvidenceAdmissionDecision or type(self.reason_code) is not EvidenceAdmissionReasonCode:
            raise TypeError("admission result has wrong exact type")
        if self.proposed_evidence_record is not None and type(self.proposed_evidence_record) is not EvidenceRecord:
            raise TypeError("invalid proposed evidence record")
        if self.expected_evidence_history_membership_binding is not None and type(self.expected_evidence_history_membership_binding) is not EvidenceHistoryMembershipBindingId:
            raise TypeError("invalid evidence history binding")


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
        (echo.pr_id, None if subject.pr_id is None else subject.pr_id.value),
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
    if request.profile_admission_context is None:
        return _result(EvidenceAdmissionReasonCode.RAW_LIMIT_CONTEXT_UNAVAILABLE)
    try:
        effective_limits = effective_review_parse_limits(request.profile_admission_context)
    except (TypeError, ValueError):
        return _result(EvidenceAdmissionReasonCode.RAW_LIMIT_CONTEXT_UNAVAILABLE)
    # The caller's requested limits are deliberately not authoritative.  The
    # exact strictest trusted limit is the one actually passed to the parser.
    parsed = validate_review_verdict_v1(request.raw_response, effective_limits)
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
    profile_context = request.profile_admission_context
    if (
        invocation.profile != request.slot.profile
        or request.subject.profile_id != request.slot.profile.profile_id
        or request.subject.profile_config_id != request.slot.profile.config_id
        or profile_context.profile_id != request.slot.profile.profile_id
        or profile_context.profile_config_id != request.slot.profile.config_id
        or type(profile_context.baseline_config_id) is not ImmutableConfigId
        or profile_context.policy_epoch_identity != request.subject.policy_epoch_identity
        or profile_context.profile_limits != request.slot.profile.raw_limits
        or request.subject.verdict_schema_id != request.slot.profile.verdict_schema_id
        or request.expected_schema_id != request.slot.profile.verdict_schema_id
    ):
        return _result(EvidenceAdmissionReasonCode.PROFILE_BINDING_MISMATCH)
    manifest = request.envelope.input_manifest
    assignment = request.assignment
    if assignment is None:
        return _result(EvidenceAdmissionReasonCode.REQUEST_BINDING_MISMATCH)
    if assignment.partition_rule is not ReviewPartitionRule.SINGLE_REVIEW_PACKAGE:
        return _result(EvidenceAdmissionReasonCode.UNSUPPORTED_REVIEW_PARTITIONING)
    assignment_requirements = tuple(item.requirement_id for item in assignment.requirements)
    request_package = (
        request.envelope.invocation_id == invocation.invocation_id,
        request.envelope.envelope_id == invocation.envelope_id,
        request.envelope.slot_id == invocation.slot_id == request.slot.slot_id,
        request.envelope.canonical_request_id == invocation.canonical_request_id,
        request.envelope.assignment_id == assignment.assignment_id,
        invocation.assignment_id == assignment.assignment_id,
        request.envelope.subject_id == request.effective_subject.subject_id,
        request.envelope.effective_subject == request.effective_subject,
        request.envelope.evidence_subject == request.subject,
        request.envelope.profile == request.slot.profile,
        request.envelope.requirement_ids == request.effective_subject.requirement_ids == request.subject.requirement_ids,
        manifest.manifest_id == invocation.manifest_id,
        manifest.invocation_id == invocation.invocation_id,
        manifest.canonical_request_id == invocation.canonical_request_id,
        manifest.assignment_id == request.envelope.assignment_id,
        manifest.subject_id == request.effective_subject.subject_id,
        manifest.evidence_subject == request.subject,
        manifest.slot_id == request.slot.slot_id,
        manifest.profile_id == request.slot.profile.profile_id,
        manifest.profile_config_id == request.slot.profile.config_id,
        manifest.reviewer_service_id == request.slot.profile.service_id,
        manifest.verdict_schema_id == request.expected_schema_id,
        invocation.verdict_schema_id == request.expected_schema_id,
        manifest.requirement_ids == request.subject.requirement_ids,
        manifest.changed_material_ids == request.subject.required_material_ids,
        manifest.trusted_context_ids == request.subject.required_context_ids,
        invocation.required_material_ids == manifest.changed_material_ids,
        invocation.representation_ids == manifest.representation_ids,
        invocation.required_context_ids == manifest.trusted_context_ids,
        invocation.supplemental_context_ids == manifest.supplemental_context_ids,
        invocation.observed_provider_metadata_requirement_ids == request.slot.profile.provider_metadata_requirement_ids,
        manifest.supplemental_context_ids == tuple(item.material_id for item in request.envelope.supplemental_context),
        manifest.changed_material_ids == tuple(
            item.material_id for item in request.envelope.materials
            if item.kind.value in ("CHANGED_CONTENT", "DELETION")
        ),
        manifest.representation_ids == tuple(
            item.representation_id for item in request.envelope.materials
            if item.kind.value == "TRANSFORMED_REPRESENTATION"
        ),
        manifest.represented_material_ids == tuple(
            item.represented_material_id for item in request.envelope.materials
            if item.kind.value == "TRANSFORMED_REPRESENTATION"
        ),
        manifest.trusted_context_ids == tuple(
            item.trusted_context_id for item in request.envelope.materials
            if item.kind.value == "TRUSTED_CONTEXT"
        ),
        assignment.repository_id == request.subject.repository_id,
        assignment.task_id == request.subject.task_id,
        assignment.candidate_id == request.subject.candidate_id,
        assignment.contract_id == request.subject.contract_id,
        assignment.contract_raw_sha256 == request.subject.contract_raw_sha256,
        assignment.target_registration_id == request.subject.target_registration_id,
        assignment.policy_epoch_identity == request.subject.policy_epoch_identity,
        assignment_requirements == request.subject.requirement_ids,
        assignment.composition_rule == request.composition_rule,
        assignment.composition_rule.composition_rule_id == request.effective_subject.composition_rule_id,
        any(item == request.slot for item in request.composition_rule.required_slots),
    )
    if not all(request_package):
        return _result(EvidenceAdmissionReasonCode.REQUEST_BINDING_MISMATCH)
    if (
        request.raw_response_id is None
        or request.raw_response_id != invocation.raw_response_id
        or invocation.raw_response_sha256 != verdict.source_document.raw_sha256
    ):
        return _result(EvidenceAdmissionReasonCode.RESPONSE_BINDING_MISMATCH)
    binding = request.operation_binding
    if binding is None or request.operation is None:
        return _result(EvidenceAdmissionReasonCode.OPERATION_CONTEXT_UNAVAILABLE)
    operation_context = (
        binding.invocation_id, binding.slot_id, binding.operation_id, binding.operation_revision, binding.canonical_request_id,
        binding.task_id, binding.candidate_id, binding.contract_id, binding.contract_raw_sha256,
        binding.authorization_id, binding.task_admission_event_id,
        binding.target_registration_id, binding.policy_epoch_identity,
    )
    expected_operation_context = (
        invocation.invocation_id, request.slot.slot_id, request.operation.intent.operation_id, request.operation.revision,
        invocation.canonical_request_id, request.subject.task_id, request.subject.candidate_id,
        request.subject.contract_id, request.subject.contract_raw_sha256,
        request.subject.authorization_id, request.subject.task_admission_event_id,
        request.subject.target_registration_id, request.subject.policy_epoch_identity,
    )
    intent = request.operation.intent
    exact_intent = (
        intent.operation_id == binding.operation_id and intent.task_id == request.subject.task_id
        and intent.candidate_id == request.subject.candidate_id
        and intent.contract_id == request.subject.contract_id
        and intent.contract_raw_sha256 == request.subject.contract_raw_sha256
        and intent.authorization_id == request.subject.authorization_id
        and intent.admission_event_id == request.subject.task_admission_event_id
        and intent.target_registration_id == request.subject.target_registration_id
        and intent.policy_epoch_identity == request.subject.policy_epoch_identity
    )
    if binding.role is not ReviewOperationRole.SEMANTIC_REVIEW or operation_context != expected_operation_context or not exact_intent:
        return _result(EvidenceAdmissionReasonCode.OPERATION_BINDING_MISMATCH)
    if request.operation.state is not OperationState.SUCCEEDED:
        return _result(EvidenceAdmissionReasonCode.OPERATION_NOT_SUCCEEDED)
    disclosure = request.disclosure_requirement
    if disclosure is None:
        return _result(EvidenceAdmissionReasonCode.DISCLOSURE_CONTEXT_UNAVAILABLE)
    expected_disclosure = (
        invocation.invocation_id, request.slot.slot_id, request.slot.profile.profile_id,
        request.slot.profile.service_id, invocation.canonical_request_id,
    )
    if (disclosure.invocation_id, disclosure.slot_id, disclosure.profile_id, disclosure.service_id, disclosure.canonical_request_id) != expected_disclosure:
        return _result(EvidenceAdmissionReasonCode.DISCLOSURE_BINDING_MISMATCH)
    material_classifications = tuple(
        item.classification_id for item in request.envelope.materials if item.classification_id is not None
    )
    if disclosure.disclosed_classifications != material_classifications:
        return _result(EvidenceAdmissionReasonCode.DISCLOSURE_BINDING_MISMATCH)
    if disclosure.applicability is DisclosureApplicability.REQUIRED:
        if request.disclosure_authorization is None:
            return _result(EvidenceAdmissionReasonCode.DISCLOSURE_CONTEXT_UNAVAILABLE)
        auth = request.disclosure_authorization
        if (auth.target_registration_id, auth.repository_id, auth.authorization_id, auth.policy_epoch_identity, auth.profile_id, auth.service_id, auth.canonical_request_id, auth.permitted_classifications) != (request.subject.target_registration_id, request.subject.repository_id, request.subject.authorization_id, request.subject.policy_epoch_identity, request.subject.profile_id, request.slot.profile.service_id, invocation.canonical_request_id, disclosure.disclosed_classifications):
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
    if request.evidence_history.subject != request.effective_subject:
        return _result(EvidenceAdmissionReasonCode.REREVIEW_NOT_PERMITTED)
    if request.slot_attempt_history is None:
        return _result(EvidenceAdmissionReasonCode.SLOT_ATTEMPT_CONTEXT_UNAVAILABLE)
    if request.slot_attempt_history.subject != request.effective_subject:
        return _result(EvidenceAdmissionReasonCode.REVIEW_SLOT_ATTEMPT_CONFLICT)
    current_key = (invocation.invocation_id, request.slot.slot_id, binding.operation_id, OperationState.SUCCEEDED, invocation.canonical_request_id)
    current_attempts = tuple(
        item for item in request.slot_attempt_history.attempts
        if (item.invocation_id, item.slot_id, item.operation_id, item.operation_state, item.canonical_request_id) == current_key
    )
    if len(current_attempts) != 1:
        return _result(EvidenceAdmissionReasonCode.REVIEW_SLOT_ATTEMPT_CONFLICT)
    prior_attempts = tuple(item for item in request.slot_attempt_history.attempts if item is not current_attempts[0])
    existing = tuple(item for item in request.evidence_history.admitted_bindings if item.slot_id == request.slot.slot_id and item.substantive)
    if existing:
        rereview = request.rereview_authorization
        if (
            rereview is None
            or rereview.subject_id != request.effective_subject.subject_id
            or rereview.slot_id != request.slot.slot_id
            or type(rereview.reason) is not ReReviewReason
        ):
            return _result(EvidenceAdmissionReasonCode.REREVIEW_NOT_PERMITTED)
    terminal = tuple(item for item in prior_attempts if item.slot_id == request.slot.slot_id and item.operation_state in (OperationState.FAILED, OperationState.CONFLICT))
    if terminal:
        retry = request.operational_retry_authorization
        if (
            len(terminal) != 1 or retry is None
            or retry.subject_id != request.effective_subject.subject_id
            or retry.slot_id != request.slot.slot_id
            or retry.prior_operation_id != terminal[0].operation_id
        ):
            return _result(EvidenceAdmissionReasonCode.REVIEW_SLOT_ATTEMPT_CONFLICT)
    derived_attempt_snapshot = object.__new__(TrustedReviewSlotAttemptSnapshot)
    object.__setattr__(derived_attempt_snapshot, "subject", request.slot_attempt_history.subject)
    object.__setattr__(derived_attempt_snapshot, "operation_membership_binding_id", request.slot_attempt_history.operation_membership_binding_id)
    object.__setattr__(derived_attempt_snapshot, "attempts", prior_attempts)
    eligibility = evaluate_review_invocation_eligibility(
        request.effective_subject, request.slot, request.composition_rule,
        request.evidence_history, derived_attempt_snapshot,
        request.rereview_authorization, request.operational_retry_authorization,
    )
    if eligibility.decision.value != "ELIGIBLE":
        if any(item.slot_id == request.slot.slot_id and item.substantive for item in request.evidence_history.admitted_bindings):
            return _result(EvidenceAdmissionReasonCode.REREVIEW_NOT_PERMITTED)
        return _result(EvidenceAdmissionReasonCode.REVIEW_SLOT_ATTEMPT_CONFLICT)
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
    PULL_REQUEST_CHANGED = "PULL_REQUEST_CHANGED"
    CONTRACT_CHANGED = "CONTRACT_CHANGED"
    AUTHORIZATION_CHANGED = "AUTHORIZATION_CHANGED"
    TASK_ADMISSION_EVENT_CHANGED = "TASK_ADMISSION_EVENT_CHANGED"
    TARGET_REGISTRATION_CHANGED = "TARGET_REGISTRATION_CHANGED"
    POLICY_EPOCH_CHANGED = "POLICY_EPOCH_CHANGED"
    REQUIREMENT_SET_CHANGED = "REQUIREMENT_SET_CHANGED"
    REQUIRED_MATERIAL_CHANGED = "REQUIRED_MATERIAL_CHANGED"
    REQUIRED_CONTEXT_CHANGED = "REQUIRED_CONTEXT_CHANGED"
    REVIEW_SLOT_CHANGED = "REVIEW_SLOT_CHANGED"
    REVIEWER_PROFILE_CHANGED = "REVIEWER_PROFILE_CHANGED"
    REVIEWER_PROFILE_CONFIG_CHANGED = "REVIEWER_PROFILE_CONFIG_CHANGED"
    VERDICT_SCHEMA_CHANGED = "VERDICT_SCHEMA_CHANGED"
    UNSUPPORTED_CONTINUATION_RULE = "UNSUPPORTED_CONTINUATION_RULE"


@dataclass(frozen=True, slots=True)
class EvidenceApplicabilityResult:
    decision: EvidenceApplicabilityDecision
    reason: EvidenceApplicabilityReason

    def __post_init__(self) -> None:
        if type(self.decision) is not EvidenceApplicabilityDecision or type(self.reason) is not EvidenceApplicabilityReason:
            raise TypeError("applicability result has wrong exact type")


def evaluate_evidence_applicability(record: EvidenceRecord, current: EvidenceSubject | None) -> EvidenceApplicabilityResult:
    if current is None:
        return EvidenceApplicabilityResult(EvidenceApplicabilityDecision.INDETERMINATE, EvidenceApplicabilityReason.CONTEXT_UNAVAILABLE)
    fields = (
        ("candidate_id", EvidenceApplicabilityReason.CANDIDATE_CHANGED),
        ("base", EvidenceApplicabilityReason.BASE_CHANGED),
        ("target_context_id", EvidenceApplicabilityReason.TARGET_CONTEXT_CHANGED),
        ("pr_id", EvidenceApplicabilityReason.PULL_REQUEST_CHANGED),
        ("contract_id", EvidenceApplicabilityReason.CONTRACT_CHANGED),
        ("contract_raw_sha256", EvidenceApplicabilityReason.CONTRACT_CHANGED),
        ("authorization_id", EvidenceApplicabilityReason.AUTHORIZATION_CHANGED),
        ("task_admission_event_id", EvidenceApplicabilityReason.TASK_ADMISSION_EVENT_CHANGED),
        ("target_registration_id", EvidenceApplicabilityReason.TARGET_REGISTRATION_CHANGED),
        ("policy_epoch_identity", EvidenceApplicabilityReason.POLICY_EPOCH_CHANGED),
        ("requirement_ids", EvidenceApplicabilityReason.REQUIREMENT_SET_CHANGED),
        ("required_material_ids", EvidenceApplicabilityReason.REQUIRED_MATERIAL_CHANGED),
        ("required_context_ids", EvidenceApplicabilityReason.REQUIRED_CONTEXT_CHANGED),
        ("slot_id", EvidenceApplicabilityReason.REVIEW_SLOT_CHANGED),
        ("profile_id", EvidenceApplicabilityReason.REVIEWER_PROFILE_CHANGED),
        ("profile_config_id", EvidenceApplicabilityReason.REVIEWER_PROFILE_CONFIG_CHANGED),
        ("verdict_schema_id", EvidenceApplicabilityReason.VERDICT_SCHEMA_CHANGED),
    )
    for name, reason in fields:
        if getattr(record.subject, name) != getattr(current, name):
            return EvidenceApplicabilityResult(EvidenceApplicabilityDecision.STALE, reason)
    return EvidenceApplicabilityResult(EvidenceApplicabilityDecision.APPLICABLE, EvidenceApplicabilityReason.APPLICABLE)


@dataclass(frozen=True, slots=True, init=False)
class TrustedSupersessionAuthorization:
    decision_id: SupersessionDecisionId
    subject_id: SemanticReviewEffectiveSubjectId
    policy_epoch_identity: PolicyEpochIdentity
    earlier_evidence_id: EvidenceId
    later_evidence_id: EvidenceId
    authorized_reason: SupersessionReason

    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("supersession authorization must come from trusted policy boundary")


@dataclass(frozen=True, slots=True, init=False)
class TrustedAdmittedEvidenceRecord:
    record: EvidenceRecord
    membership_binding: EvidenceHistoryMembershipBindingId

    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("admitted evidence must come from canonical state boundary")


@dataclass(frozen=True, slots=True, init=False)
class EvidenceSupersessionRecord:
    earlier_evidence_id: EvidenceId
    later_evidence_id: EvidenceId
    subject_id: SemanticReviewEffectiveSubjectId
    policy_epoch_identity: PolicyEpochIdentity
    authorized_reason: SupersessionReason
    decision_id: SupersessionDecisionId
    authorization: TrustedSupersessionAuthorization

    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("use build_evidence_supersession_record")


def build_evidence_supersession_record(
    earlier: TrustedAdmittedEvidenceRecord,
    later: TrustedAdmittedEvidenceRecord,
    authorization: TrustedSupersessionAuthorization,
) -> EvidenceSupersessionRecord:
    if type(earlier) is not TrustedAdmittedEvidenceRecord or type(later) is not TrustedAdmittedEvidenceRecord:
        raise TypeError("both evidence records must be trusted admitted records")
    if type(authorization) is not TrustedSupersessionAuthorization:
        raise TypeError("trusted supersession authorization required")
    early, late = earlier.record, later.record
    if type(early) is not EvidenceRecord or type(late) is not EvidenceRecord:
        raise TypeError("invalid admitted evidence binding")
    if early.evidence_id == late.evidence_id:
        raise ValueError("supersession requires distinct evidence identities")
    if early.payload.effective_subject_id != late.payload.effective_subject_id:
        raise ValueError("initial supersession requires exact effective subject")
    expected = (
        authorization.earlier_evidence_id == early.evidence_id,
        authorization.later_evidence_id == late.evidence_id,
        authorization.subject_id == early.payload.effective_subject_id,
        authorization.policy_epoch_identity == early.subject.policy_epoch_identity == late.subject.policy_epoch_identity,
        type(authorization.authorized_reason) is SupersessionReason,
        type(authorization.decision_id) is SupersessionDecisionId,
    )
    if not all(expected):
        raise ValueError("supersession authorization binding mismatch")
    result = object.__new__(EvidenceSupersessionRecord)
    values = {
        "earlier_evidence_id": early.evidence_id, "later_evidence_id": late.evidence_id,
        "subject_id": authorization.subject_id, "policy_epoch_identity": authorization.policy_epoch_identity,
        "authorized_reason": authorization.authorized_reason, "decision_id": authorization.decision_id,
        "authorization": authorization,
    }
    for name, value in values.items():
        object.__setattr__(result, name, value)
    return result


@dataclass(frozen=True, slots=True)
class SemanticRequirementStatus:
    requirement_id: SemanticRequirementId
    status: ConditionStatus

    def __post_init__(self) -> None:
        if type(self.requirement_id) is not SemanticRequirementId or type(self.status) is not ConditionStatus:
            raise TypeError("semantic requirement status has wrong exact type")


class SemanticCompositionReason(Enum):
    COMPOSED = "COMPOSED"
    REQUIRED_SLOT_MISSING = "REQUIRED_SLOT_MISSING"
    CONFLICTING_APPLICABLE_EVIDENCE = "CONFLICTING_APPLICABLE_EVIDENCE"


@dataclass(frozen=True, slots=True)
class SemanticCompositionResult:
    reason: SemanticCompositionReason
    requirement_statuses: tuple[SemanticRequirementStatus, ...]

    def __post_init__(self) -> None:
        if type(self.reason) is not SemanticCompositionReason:
            raise TypeError("composition reason has wrong exact type")
        if type(self.requirement_statuses) is not tuple or any(type(item) is not SemanticRequirementStatus for item in self.requirement_statuses):
            raise TypeError("requirement_statuses must be an exact immutable tuple")


def semantic_status_for_verdict(verdict: SemanticVerdict) -> ConditionStatus:
    if type(verdict) is not SemanticVerdict:
        raise TypeError("exact SemanticVerdict required")
    return {
        SemanticVerdict.APPROVED: ConditionStatus.SATISFIED,
        SemanticVerdict.CHANGES_REQUIRED: ConditionStatus.UNSATISFIED,
        SemanticVerdict.UNABLE_TO_DETERMINE: ConditionStatus.INDETERMINATE,
    }[verdict]


def compose_semantic_evidence(
    records: tuple[EvidenceRecord, ...], current: EvidenceSubject,
    composition_rule: SemanticReviewCompositionRule,
    supersessions: tuple[EvidenceSupersessionRecord, ...] = (),
) -> SemanticCompositionResult:
    if type(records) is not tuple or any(type(item) is not EvidenceRecord for item in records):
        raise TypeError("records must be an exact immutable tuple")
    if type(supersessions) is not tuple or any(type(item) is not EvidenceSupersessionRecord for item in supersessions):
        raise TypeError("supersessions must be an exact immutable tuple")
    superseded = frozenset(item.earlier_evidence_id for item in supersessions)
    applicable = tuple(
        item for item in records
        if item.evidence_id not in superseded
        and item.evidence_class is EvidenceClass.SEMANTIC_REVIEW
        and evaluate_evidence_applicability(item, current).decision is EvidenceApplicabilityDecision.APPLICABLE
    )
    required_slots = tuple(slot.slot_id for slot in composition_rule.required_slots)
    grouped = {slot_id: tuple(item for item in applicable if item.payload.slot_id == slot_id) for slot_id in required_slots}
    if any(len(items) > 1 for items in grouped.values()):
        return SemanticCompositionResult(SemanticCompositionReason.CONFLICTING_APPLICABLE_EVIDENCE, ())
    if any(len(items) != 1 for items in grouped.values()):
        return SemanticCompositionResult(SemanticCompositionReason.REQUIRED_SLOT_MISSING, ())
    vectors = tuple(grouped[slot_id][0].payload.requirement_results for slot_id in required_slots)
    statuses: list[SemanticRequirementStatus] = []
    for requirement_id in current.requirement_ids:
        verdicts = tuple(next(item.verdict for item in vector if item.requirement_id == requirement_id) for vector in vectors)
        if any(item is SemanticVerdict.UNABLE_TO_DETERMINE for item in verdicts):
            status = ConditionStatus.INDETERMINATE
        elif any(item is SemanticVerdict.CHANGES_REQUIRED for item in verdicts):
            status = ConditionStatus.UNSATISFIED
        else:
            status = ConditionStatus.SATISFIED
        statuses.append(SemanticRequirementStatus(requirement_id, status))
    return SemanticCompositionResult(SemanticCompositionReason.COMPOSED, tuple(statuses))
