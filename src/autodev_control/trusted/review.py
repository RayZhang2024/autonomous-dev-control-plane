"""Deterministic semantic-review structures and verdict validation for G5.

Objects produced here are non-bearer candidate values.  The module performs no
review invocation, disclosure, persistence, provider access, or external effect.
"""

from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType

from .identity import GitSha, ImmutableConfigId, LogicalIdentifier, RawSha256
from .manifest import PolicyEpochIdentity
from .operation import (
    AdmissionEventId, CandidateId, EvidenceId, OperationId,
    OperationMembershipBindingId, OperationRecord, OperationState,
)
from .parsing import ParseFailure, ParseFailureCode, ParseLimits, ParsedJsonDocument, parse_trusted_json
from .scope import AuthorizationId, ContractId, GitHubRepositoryId, TargetRegistrationId, TaskId


def _identity_type(name: str):
    def post(self) -> None:
        LogicalIdentifier(self.value)
    return dataclass(frozen=True, slots=True)(type(name, (), {"__annotations__": {"value": str}, "__post_init__": post}))


ReviewInvocationId = _identity_type("ReviewInvocationId")
ReviewEnvelopeId = _identity_type("ReviewEnvelopeId")
ReviewInputManifestId = _identity_type("ReviewInputManifestId")
ReviewerProfileId = _identity_type("ReviewerProfileId")
ReviewerServiceId = _identity_type("ReviewerServiceId")
ReviewSlotId = _identity_type("ReviewSlotId")
SemanticRequirementId = _identity_type("SemanticRequirementId")
FindingId = _identity_type("FindingId")
ReviewPartitionId = _identity_type("ReviewPartitionId")
CanonicalRequestId = _identity_type("CanonicalRequestId")
SubmissionEventId = _identity_type("SubmissionEventId")
RawReviewResponseId = _identity_type("RawReviewResponseId")
EvidenceAdmissionEventId = _identity_type("EvidenceAdmissionEventId")
EvidenceProducerEventId = _identity_type("EvidenceProducerEventId")
SupersessionDecisionId = _identity_type("SupersessionDecisionId")
ReReviewAuthorizationId = _identity_type("ReReviewAuthorizationId")
PullRequestIdentity = _identity_type("PullRequestIdentity")
TargetContextId = _identity_type("TargetContextId")
MaterialIdentity = _identity_type("MaterialIdentity")
RepresentationIdentity = _identity_type("RepresentationIdentity")
SemanticReviewEffectiveSubjectId = _identity_type("SemanticReviewEffectiveSubjectId")
AssignmentIdentity = _identity_type("AssignmentIdentity")
DisclosureDecisionId = _identity_type("DisclosureDecisionId")
EvidenceHistoryMembershipBindingId = _identity_type("EvidenceHistoryMembershipBindingId")
CompositionRuleId = _identity_type("CompositionRuleId")
TrustedContextId = _identity_type("TrustedContextId")


def _tuple(values: object, item_type: type, name: str, *, unique: bool = True) -> tuple:
    if type(values) is not tuple:
        raise TypeError(f"{name} must be exactly tuple")
    seen: set[object] = set()
    for item in values:
        if type(item) is not item_type:
            raise TypeError(f"{name} item has wrong exact type")
        if unique and item in seen:
            raise ValueError(f"duplicate {name} identity")
        seen.add(item)
    return values


class SemanticVerdict(Enum):
    APPROVED = "approved"
    CHANGES_REQUIRED = "changes_required"
    UNABLE_TO_DETERMINE = "unable_to_determine"


class UnableReasonCode(Enum):
    MISSING_REQUIRED_MATERIAL = "missing_required_material"
    UNSUPPORTED_MATERIAL = "unsupported_material"
    INSUFFICIENT_CONTEXT = "insufficient_context"
    AMBIGUOUS_REQUIREMENT = "ambiguous_requirement"
    CONFLICTING_CONTEXT = "conflicting_context"
    CONTEXT_LIMIT = "context_limit"
    REVIEWER_CAPABILITY_LIMIT = "reviewer_capability_limit"
    PERMITTED_TOOL_FAILURE = "permitted_tool_failure"
    OTHER = "other"


class FindingKind(Enum):
    REQUIREMENT_ISSUE = "requirement_issue"
    ADVISORY_OBSERVATION = "advisory_observation"


class ToolMode(Enum):
    NO_TOOLS = "NO_TOOLS"
    PERMITTED_TOOLS = "PERMITTED_TOOLS"


class ReviewPartitionRule(Enum):
    SINGLE_REVIEW_PACKAGE = "SingleReviewPackage"


class CompositionMode(Enum):
    SINGLE_REQUIRED_INVOCATION = "SINGLE_REQUIRED_INVOCATION"
    ALL_REQUIRED_INVOCATIONS = "ALL_REQUIRED_INVOCATIONS"
    EXACT_REQUIRED_INVOCATION_SET = "EXACT_REQUIRED_INVOCATION_SET"


class ReviewOperationRole(Enum):
    SEMANTIC_REVIEW = "SEMANTIC_REVIEW"


class DisclosureApplicability(Enum):
    NOT_APPLICABLE = "NOT_APPLICABLE"
    REQUIRED = "REQUIRED"


class ReReviewReason(Enum):
    AUTHORIZED_ADJUDICATION = "AUTHORIZED_ADJUDICATION"
    POLICY_DEFINED_REREVIEW = "POLICY_DEFINED_REREVIEW"


class MaterialKind(Enum):
    CHANGED_CONTENT = "CHANGED_CONTENT"
    DELETION = "DELETION"
    TRUSTED_CONTEXT = "TRUSTED_CONTEXT"
    TRANSFORMED_REPRESENTATION = "TRANSFORMED_REPRESENTATION"
    SUPPLEMENTAL_UNTRUSTED_CONTEXT = "SUPPLEMENTAL_UNTRUSTED_CONTEXT"


class VerdictValidationReason(Enum):
    VALID = "VALID"
    RAW_RESPONSE_TOO_LARGE = "RAW_RESPONSE_TOO_LARGE"
    RAW_RESPONSE_PARSE_FAILED = "RAW_RESPONSE_PARSE_FAILED"
    SCHEMA_VALIDATION_FAILED = "SCHEMA_VALIDATION_FAILED"


@dataclass(frozen=True, slots=True)
class ReviewLocation:
    path: str
    content_id: str | None
    line_start: int | None
    line_end: int | None


@dataclass(frozen=True, slots=True)
class RequirementResult:
    requirement_id: SemanticRequirementId
    verdict: SemanticVerdict
    rationale: str
    finding_ids: tuple[FindingId, ...]
    unable_reason_code: UnableReasonCode | None


@dataclass(frozen=True, slots=True)
class ReviewFinding:
    finding_id: FindingId
    kind: FindingKind
    requirement_ids: tuple[SemanticRequirementId, ...]
    summary: str
    rationale: str
    locations: tuple[ReviewLocation, ...]
    suggested_remediation: str | None


@dataclass(frozen=True, slots=True)
class SubjectEcho:
    repository_id: str
    task_id: str
    contract_id: str
    candidate_id: str
    target_registration_id: str | None = None
    active_policy_id: str | None = None
    base_id: str | None = None
    target_context_id: str | None = None
    pr_id: str | None = None


@dataclass(frozen=True, slots=True)
class RawSemanticVerdict:
    source_document: ParsedJsonDocument
    review_invocation_id: ReviewInvocationId
    subject_echo: SubjectEcho | None
    requirement_results: tuple[RequirementResult, ...]
    findings: tuple[ReviewFinding, ...]
    overall_verdict: SemanticVerdict | None
    reviewer_summary: str | None


@dataclass(frozen=True, slots=True)
class VerdictValidationResult:
    reason: VerdictValidationReason
    verdict: RawSemanticVerdict | None = None
    parse_failure: ParseFailure | None = None


def _fields(value: object, required: tuple[str, ...], optional: tuple[str, ...] = ()) -> bool:
    if type(value) is not MappingProxyType:
        return False
    keys = tuple(value.keys())
    allowed = frozenset((*required, *optional))
    return all(name in value for name in required) and all(name in allowed for name in keys)


def _string(value: object, maximum: int) -> bool:
    return type(value) is str and 1 <= len(value) <= maximum


def _identifier(value: object) -> bool:
    return _string(value, 512)


def _enum(enum_type: type[Enum], value: object):
    if type(value) is not str:
        raise ValueError
    return enum_type(value)


def _subject_echo(value: object) -> SubjectEcho:
    required = ("repository_id", "task_id", "contract_id", "candidate_id")
    optional = ("target_registration_id", "active_policy_id", "base_id", "target_context_id", "pr_id")
    if not _fields(value, required, optional) or any(not _identifier(value[name]) for name in (*required, *(n for n in optional if n in value))):
        raise ValueError
    return SubjectEcho(*(value[name] for name in required), *(value.get(name) for name in optional))


def _location(value: object) -> ReviewLocation:
    if not _fields(value, ("path",), ("content_id", "line_start", "line_end")) or not _string(value["path"], 4096):
        raise ValueError
    content = value.get("content_id")
    start, end = value.get("line_start"), value.get("line_end")
    if content is not None and not _identifier(content):
        raise ValueError
    if start is not None and (type(start) is not int or start < 1):
        raise ValueError
    if end is not None and (type(end) is not int or end < 1):
        raise ValueError
    if end is not None and start is None:
        raise ValueError
    return ReviewLocation(value["path"], content, start, end)


def _requirement_result(value: object) -> RequirementResult:
    required = ("requirement_id", "verdict", "rationale", "finding_ids")
    if not _fields(value, required, ("unable_reason_code",)):
        raise ValueError
    if not _identifier(value["requirement_id"]) or not _string(value["rationale"], 16384):
        raise ValueError
    verdict = _enum(SemanticVerdict, value["verdict"])
    refs = value["finding_ids"]
    if type(refs) is not tuple or len(refs) > 256 or any(not _identifier(item) for item in refs) or len(set(refs)) != len(refs):
        raise ValueError
    unable = value.get("unable_reason_code")
    if verdict is SemanticVerdict.UNABLE_TO_DETERMINE:
        unable = _enum(UnableReasonCode, unable)
    elif unable is not None:
        raise ValueError
    return RequirementResult(
        SemanticRequirementId(value["requirement_id"]), verdict, value["rationale"],
        tuple(FindingId(item) for item in refs), unable,
    )


def _finding(value: object) -> ReviewFinding:
    required = ("finding_id", "kind", "requirement_ids", "summary", "rationale")
    optional = ("locations", "suggested_remediation")
    if not _fields(value, required, optional):
        raise ValueError
    if not _identifier(value["finding_id"]) or not _string(value["summary"], 4096) or not _string(value["rationale"], 16384):
        raise ValueError
    kind = _enum(FindingKind, value["kind"])
    requirements = value["requirement_ids"]
    if type(requirements) is not tuple or len(requirements) > 256 or any(not _identifier(item) for item in requirements) or len(set(requirements)) != len(requirements):
        raise ValueError
    if kind is FindingKind.REQUIREMENT_ISSUE and not requirements:
        raise ValueError
    locations = value.get("locations", ())
    if type(locations) is not tuple or len(locations) > 256:
        raise ValueError
    remediation = value.get("suggested_remediation")
    if remediation is not None and not _string(remediation, 16384):
        raise ValueError
    return ReviewFinding(
        FindingId(value["finding_id"]), kind,
        tuple(SemanticRequirementId(item) for item in requirements),
        value["summary"], value["rationale"], tuple(_location(item) for item in locations), remediation,
    )


def validate_review_verdict_v1(raw: object, limits: object) -> VerdictValidationResult:
    if type(limits) is not ParseLimits:
        return VerdictValidationResult(VerdictValidationReason.RAW_RESPONSE_PARSE_FAILED)
    parsed = parse_trusted_json(raw, limits)
    if type(parsed) is ParseFailure:
        reason = (
            VerdictValidationReason.RAW_RESPONSE_TOO_LARGE
            if parsed.code is ParseFailureCode.BYTE_LIMIT_EXCEEDED
            else VerdictValidationReason.RAW_RESPONSE_PARSE_FAILED
        )
        return VerdictValidationResult(reason, parse_failure=parsed)
    value = parsed.value
    required = ("schema_version", "review_invocation_id", "requirement_results", "findings")
    optional = ("subject_echo", "overall_verdict", "reviewer_summary")
    try:
        if not _fields(value, required, optional) or value["schema_version"] != "1.0" or not _identifier(value["review_invocation_id"]):
            raise ValueError
        results, findings = value["requirement_results"], value["findings"]
        if type(results) is not tuple or not 1 <= len(results) <= 1024 or type(findings) is not tuple or len(findings) > 1024:
            raise ValueError
        echo = _subject_echo(value["subject_echo"]) if "subject_echo" in value else None
        overall = _enum(SemanticVerdict, value["overall_verdict"]) if "overall_verdict" in value else None
        summary = value.get("reviewer_summary")
        if summary is not None and not _string(summary, 16384):
            raise ValueError
        verdict = RawSemanticVerdict(
            parsed, ReviewInvocationId(value["review_invocation_id"]), echo,
            tuple(_requirement_result(item) for item in results),
            tuple(_finding(item) for item in findings), overall, summary,
        )
    except (TypeError, ValueError):
        return VerdictValidationResult(VerdictValidationReason.SCHEMA_VALIDATION_FAILED)
    return VerdictValidationResult(VerdictValidationReason.VALID, verdict)


@dataclass(frozen=True, slots=True)
class ReviewerProfileBinding:
    profile_id: ReviewerProfileId
    config_id: ImmutableConfigId
    service_id: ReviewerServiceId
    verdict_schema_id: ImmutableConfigId
    raw_limits: ParseLimits
    tool_mode: ToolMode


@dataclass(frozen=True, slots=True)
class SemanticRequirement:
    requirement_id: SemanticRequirementId
    statement_binding: RawSha256


@dataclass(frozen=True, slots=True)
class RequirementMaterialAssignment:
    requirement_id: SemanticRequirementId
    required_material_ids: tuple[MaterialIdentity, ...]
    required_context_ids: tuple[TrustedContextId, ...]
    permitted_representation_ids: tuple[RepresentationIdentity, ...]


@dataclass(frozen=True, slots=True)
class MaterialBinding:
    material_id: MaterialIdentity
    repository_id: GitHubRepositoryId
    kind: MaterialKind
    path_or_resource: str
    content_or_deletion_identity: str
    candidate_id: CandidateId | None
    base: GitSha | None
    representation_id: RepresentationIdentity | None = None


@dataclass(frozen=True, slots=True)
class ReviewSlot:
    slot_id: ReviewSlotId
    profile: ReviewerProfileBinding
    independence_binding: RawSha256


@dataclass(frozen=True, slots=True)
class SemanticReviewCompositionRule:
    composition_rule_id: CompositionRuleId
    mode: CompositionMode
    required_slots: tuple[ReviewSlot, ...]

    def __post_init__(self) -> None:
        _tuple(self.required_slots, ReviewSlot, "required_slots")
        if len({slot.slot_id for slot in self.required_slots}) != len(self.required_slots):
            raise ValueError("duplicate required slot")
        if self.mode is CompositionMode.SINGLE_REQUIRED_INVOCATION and len(self.required_slots) != 1:
            raise ValueError("single mode requires exactly one slot")


@dataclass(frozen=True, slots=True, init=False)
class SemanticReviewAssignment:
    assignment_id: AssignmentIdentity
    task_id: TaskId
    contract_id: ContractId
    contract_raw_sha256: RawSha256
    target_registration_id: TargetRegistrationId
    policy_epoch_identity: PolicyEpochIdentity
    candidate_id: CandidateId
    requirements: tuple[SemanticRequirement, ...]
    material_assignments: tuple[RequirementMaterialAssignment, ...]
    required_context_ids: tuple[TrustedContextId, ...]
    composition_rule: SemanticReviewCompositionRule
    partition_rule: ReviewPartitionRule

    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("assignment must come from trusted contract/policy composition")


@dataclass(frozen=True, slots=True, init=False)
class SemanticReviewEffectiveSubject:
    subject_id: SemanticReviewEffectiveSubjectId
    repository_id: GitHubRepositoryId
    task_id: TaskId
    candidate_id: CandidateId
    contract_id: ContractId
    contract_raw_sha256: RawSha256
    authorization_id: AuthorizationId
    task_admission_event_id: AdmissionEventId
    target_registration_id: TargetRegistrationId
    policy_epoch_identity: PolicyEpochIdentity
    base: GitSha
    target_context_id: TargetContextId | None
    requirement_ids: tuple[SemanticRequirementId, ...]
    required_material_ids: tuple[MaterialIdentity, ...]
    required_context_ids: tuple[TrustedContextId, ...]
    composition_rule_id: CompositionRuleId

    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("effective subject must come from trusted composition")


@dataclass(frozen=True, slots=True)
class ReviewInputManifest:
    manifest_id: ReviewInputManifestId
    invocation_id: ReviewInvocationId
    canonical_request_id: CanonicalRequestId
    subject_id: SemanticReviewEffectiveSubjectId
    slot_id: ReviewSlotId
    profile_id: ReviewerProfileId
    profile_config_id: ImmutableConfigId
    changed_material_ids: tuple[MaterialIdentity, ...]
    trusted_context_ids: tuple[TrustedContextId, ...]


@dataclass(frozen=True, slots=True)
class TrustedReviewEnvelope:
    envelope_id: ReviewEnvelopeId
    invocation_id: ReviewInvocationId
    canonical_request_id: CanonicalRequestId
    assignment_id: AssignmentIdentity
    subject_id: SemanticReviewEffectiveSubjectId
    slot_id: ReviewSlotId
    profile: ReviewerProfileBinding
    materials: tuple[MaterialBinding, ...]
    input_manifest: ReviewInputManifest


class EnvelopeReason(Enum):
    BUILT = "BUILT"
    IDENTITY_MISMATCH = "IDENTITY_MISMATCH"
    MATERIAL_COVERAGE_MISMATCH = "MATERIAL_COVERAGE_MISMATCH"
    UNSUPPORTED_REVIEW_PARTITIONING = "UNSUPPORTED_REVIEW_PARTITIONING"


@dataclass(frozen=True, slots=True)
class EnvelopeBuildResult:
    reason: EnvelopeReason
    envelope: TrustedReviewEnvelope | None = None


def build_trusted_review_envelope(
    *, assignment: SemanticReviewAssignment, subject: SemanticReviewEffectiveSubject,
    slot: ReviewSlot, changed_inventory: tuple[MaterialBinding, ...],
    trusted_context_inventory: tuple[MaterialBinding, ...], invocation_id: ReviewInvocationId,
    envelope_id: ReviewEnvelopeId, manifest_id: ReviewInputManifestId,
    canonical_request_id: CanonicalRequestId,
) -> EnvelopeBuildResult:
    if assignment.partition_rule is not ReviewPartitionRule.SINGLE_REVIEW_PACKAGE:
        return EnvelopeBuildResult(EnvelopeReason.UNSUPPORTED_REVIEW_PARTITIONING)
    if assignment.task_id != subject.task_id or assignment.candidate_id != subject.candidate_id or assignment.composition_rule.composition_rule_id != subject.composition_rule_id:
        return EnvelopeBuildResult(EnvelopeReason.IDENTITY_MISMATCH)
    slots = {item.slot_id: item for item in assignment.composition_rule.required_slots}
    if slots.get(slot.slot_id) != slot:
        return EnvelopeBuildResult(EnvelopeReason.IDENTITY_MISMATCH)
    changed_ids = tuple(item.material_id for item in changed_inventory)
    context_ids = tuple(TrustedContextId(item.material_id.value) for item in trusted_context_inventory)
    if len(set(changed_ids)) != len(changed_ids) or len(set(context_ids)) != len(context_ids):
        return EnvelopeBuildResult(EnvelopeReason.MATERIAL_COVERAGE_MISMATCH)
    assigned_material = tuple(mid for item in assignment.material_assignments for mid in item.required_material_ids)
    assigned_context = tuple(cid for item in assignment.material_assignments for cid in item.required_context_ids)
    if not set(assigned_material).issubset(changed_ids) or not set((*assignment.required_context_ids, *assigned_context)).issubset(context_ids):
        return EnvelopeBuildResult(EnvelopeReason.MATERIAL_COVERAGE_MISMATCH)
    if set(changed_ids) != set(subject.required_material_ids) or set(context_ids) != set(subject.required_context_ids):
        return EnvelopeBuildResult(EnvelopeReason.MATERIAL_COVERAGE_MISMATCH)
    manifest = ReviewInputManifest(
        manifest_id, invocation_id, canonical_request_id, subject.subject_id, slot.slot_id,
        slot.profile.profile_id, slot.profile.config_id, changed_ids, context_ids,
    )
    return EnvelopeBuildResult(EnvelopeReason.BUILT, TrustedReviewEnvelope(
        envelope_id, invocation_id, canonical_request_id, assignment.assignment_id,
        subject.subject_id, slot.slot_id, slot.profile,
        (*changed_inventory, *trusted_context_inventory), manifest,
    ))


@dataclass(frozen=True, slots=True)
class AdmittedSemanticEvidenceBinding:
    evidence_id: EvidenceId
    invocation_id: ReviewInvocationId
    slot_id: ReviewSlotId
    substantive: bool


@dataclass(frozen=True, slots=True, init=False)
class TrustedEffectiveSubjectEvidenceSnapshot:
    subject: SemanticReviewEffectiveSubject
    membership_binding: EvidenceHistoryMembershipBindingId
    admitted_bindings: tuple[AdmittedSemanticEvidenceBinding, ...]
    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("evidence history must come from canonical state boundary")


@dataclass(frozen=True, slots=True)
class ReviewSlotAttempt:
    invocation_id: ReviewInvocationId
    slot_id: ReviewSlotId
    operation_id: OperationId
    operation_state: OperationState
    canonical_request_id: CanonicalRequestId


@dataclass(frozen=True, slots=True, init=False)
class TrustedReviewSlotAttemptSnapshot:
    subject: SemanticReviewEffectiveSubject
    operation_membership_binding_id: OperationMembershipBindingId
    attempts: tuple[ReviewSlotAttempt, ...]
    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("attempt history must come from canonical state boundary")


@dataclass(frozen=True, slots=True, init=False)
class TrustedReReviewAuthorization:
    authorization_id: ReReviewAuthorizationId
    subject_id: SemanticReviewEffectiveSubjectId
    slot_id: ReviewSlotId
    reason: ReReviewReason
    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("re-review authorization must come from trusted policy boundary")


@dataclass(frozen=True, slots=True, init=False)
class TrustedOperationalRetryAuthorization:
    subject_id: SemanticReviewEffectiveSubjectId
    slot_id: ReviewSlotId
    prior_operation_id: OperationId
    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("retry authorization must come from trusted operation/policy boundary")


class EligibilityDecision(Enum):
    ELIGIBLE = "ELIGIBLE"
    NOT_ELIGIBLE = "NOT_ELIGIBLE"
    INDETERMINATE = "INDETERMINATE"


class EligibilityReason(Enum):
    REQUIRED_UNUSED_SLOT = "REQUIRED_UNUSED_SLOT"
    AUTHORIZED_REREVIEW = "AUTHORIZED_REREVIEW"
    AUTHORIZED_OPERATIONAL_RETRY = "AUTHORIZED_OPERATIONAL_RETRY"
    HISTORY_UNAVAILABLE = "HISTORY_UNAVAILABLE"
    COMPOSITION_MISMATCH = "COMPOSITION_MISMATCH"
    SLOT_PROFILE_MISMATCH = "SLOT_PROFILE_MISMATCH"
    SLOT_ATTEMPT_ACTIVE = "SLOT_ATTEMPT_ACTIVE"
    SLOT_ATTEMPT_RECONCILIATION_REQUIRED = "SLOT_ATTEMPT_RECONCILIATION_REQUIRED"
    SLOT_EVIDENCE_EXISTS = "SLOT_EVIDENCE_EXISTS"
    RETRY_AUTHORIZATION_REQUIRED = "RETRY_AUTHORIZATION_REQUIRED"
    AUTHORIZATION_INVALID = "AUTHORIZATION_INVALID"


@dataclass(frozen=True, slots=True)
class ReviewEligibilityResult:
    decision: EligibilityDecision
    reason: EligibilityReason
    expected_operation_membership_binding: OperationMembershipBindingId | None = None


def evaluate_review_invocation_eligibility(
    subject: SemanticReviewEffectiveSubject, slot: ReviewSlot,
    composition_rule: SemanticReviewCompositionRule,
    evidence_history_snapshot: TrustedEffectiveSubjectEvidenceSnapshot | None,
    slot_attempt_snapshot: TrustedReviewSlotAttemptSnapshot | None,
    rereview_authorization: TrustedReReviewAuthorization | None = None,
    operational_retry_authorization: TrustedOperationalRetryAuthorization | None = None,
) -> ReviewEligibilityResult:
    if evidence_history_snapshot is None or slot_attempt_snapshot is None:
        return ReviewEligibilityResult(EligibilityDecision.INDETERMINATE, EligibilityReason.HISTORY_UNAVAILABLE)
    if evidence_history_snapshot.subject != subject or slot_attempt_snapshot.subject != subject:
        return ReviewEligibilityResult(EligibilityDecision.NOT_ELIGIBLE, EligibilityReason.COMPOSITION_MISMATCH)
    required = {item.slot_id: item for item in composition_rule.required_slots}
    if composition_rule.composition_rule_id != subject.composition_rule_id or slot.slot_id not in required:
        return ReviewEligibilityResult(EligibilityDecision.NOT_ELIGIBLE, EligibilityReason.COMPOSITION_MISMATCH)
    if required[slot.slot_id] != slot:
        return ReviewEligibilityResult(EligibilityDecision.NOT_ELIGIBLE, EligibilityReason.SLOT_PROFILE_MISMATCH)
    expected = slot_attempt_snapshot.operation_membership_binding_id
    evidence = tuple(item for item in evidence_history_snapshot.admitted_bindings if item.slot_id == slot.slot_id and item.substantive)
    attempts = tuple(item for item in slot_attempt_snapshot.attempts if item.slot_id == slot.slot_id)
    blocking = tuple(item for item in attempts if item.operation_state in (
        OperationState.RESERVED, OperationState.PERFORMING, OperationState.INDETERMINATE, OperationState.SUCCEEDED,
    ))
    if blocking:
        reason = EligibilityReason.SLOT_ATTEMPT_RECONCILIATION_REQUIRED if any(item.operation_state in (OperationState.PERFORMING, OperationState.INDETERMINATE) for item in blocking) else EligibilityReason.SLOT_ATTEMPT_ACTIVE
        return ReviewEligibilityResult(EligibilityDecision.NOT_ELIGIBLE, reason, expected)
    terminal = tuple(item for item in attempts if item.operation_state in (OperationState.FAILED, OperationState.CONFLICT))
    if terminal:
        latest = terminal[-1]
        if operational_retry_authorization is None:
            return ReviewEligibilityResult(EligibilityDecision.NOT_ELIGIBLE, EligibilityReason.RETRY_AUTHORIZATION_REQUIRED, expected)
        if (operational_retry_authorization.subject_id, operational_retry_authorization.slot_id, operational_retry_authorization.prior_operation_id) != (subject.subject_id, slot.slot_id, latest.operation_id):
            return ReviewEligibilityResult(EligibilityDecision.NOT_ELIGIBLE, EligibilityReason.AUTHORIZATION_INVALID, expected)
        return ReviewEligibilityResult(EligibilityDecision.ELIGIBLE, EligibilityReason.AUTHORIZED_OPERATIONAL_RETRY, expected)
    if evidence:
        if rereview_authorization is None:
            return ReviewEligibilityResult(EligibilityDecision.NOT_ELIGIBLE, EligibilityReason.SLOT_EVIDENCE_EXISTS, expected)
        if (rereview_authorization.subject_id, rereview_authorization.slot_id) != (subject.subject_id, slot.slot_id) or type(rereview_authorization.reason) is not ReReviewReason:
            return ReviewEligibilityResult(EligibilityDecision.NOT_ELIGIBLE, EligibilityReason.AUTHORIZATION_INVALID, expected)
        return ReviewEligibilityResult(EligibilityDecision.ELIGIBLE, EligibilityReason.AUTHORIZED_REREVIEW, expected)
    return ReviewEligibilityResult(EligibilityDecision.ELIGIBLE, EligibilityReason.REQUIRED_UNUSED_SLOT, expected)


@dataclass(frozen=True, slots=True, init=False)
class TrustedReviewInvocationRecord:
    invocation_id: ReviewInvocationId
    envelope_id: ReviewEnvelopeId
    manifest_id: ReviewInputManifestId
    slot_id: ReviewSlotId
    profile: ReviewerProfileBinding
    canonical_request_id: CanonicalRequestId
    submission_event_id: SubmissionEventId
    raw_response_id: RawReviewResponseId
    raw_response_sha256: RawSha256
    subject: SemanticReviewEffectiveSubject
    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("invocation provenance must come from trusted boundary")


@dataclass(frozen=True, slots=True, init=False)
class TrustedReviewOperationBinding:
    invocation_id: ReviewInvocationId
    slot_id: ReviewSlotId
    operation_id: OperationId
    canonical_request_id: CanonicalRequestId
    task_id: TaskId
    candidate_id: CandidateId
    role: ReviewOperationRole
    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("operation correlation must come from trusted boundary")


@dataclass(frozen=True, slots=True, init=False)
class TrustedDisclosureRequirement:
    applicability: DisclosureApplicability
    invocation_id: ReviewInvocationId
    slot_id: ReviewSlotId
    profile_id: ReviewerProfileId
    service_id: ReviewerServiceId
    canonical_request_id: CanonicalRequestId
    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("disclosure requirement must come from trusted boundary")


@dataclass(frozen=True, slots=True, init=False)
class TrustedDisclosureAuthorizationBinding:
    target_registration_id: TargetRegistrationId
    repository_id: GitHubRepositoryId
    authorization_id: AuthorizationId
    policy_epoch_identity: PolicyEpochIdentity
    profile_id: ReviewerProfileId
    service_id: ReviewerServiceId
    canonical_request_id: CanonicalRequestId
    decision_id: DisclosureDecisionId
    permitted_classifications: tuple[str, ...]
    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("disclosure authorization must come from trusted boundary")
