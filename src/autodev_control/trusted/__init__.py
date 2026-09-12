"""Candidate trusted-core primitives. Their construction confers no authority."""

from .authorization import (
    admit_delegated_authorization,
    admit_direct_authorization,
    load_candidate_authorization_proposal,
)
from .manifest import CandidateTrustedManifest, load_candidate_trusted_manifest
from .evidence import (
    EvidenceAdmissionResult,
    EvidenceRecord,
    SemanticCompositionResult,
    TrustedCanonicalSemanticEvidenceSnapshot,
    TrustedSemanticCompositionContext,
    admit_semantic_review,
    build_evidence_supersession_record,
    compose_semantic_evidence,
    evaluate_evidence_applicability,
    semantic_status_for_verdict,
)
from .operation import (
    OperationRecord,
    OperationState,
    construct_trusted_operation_intent,
    reconcile_operation,
    reserve_operation,
    transition_operation,
)
from .parsing import ParseLimits, ParsedJsonDocument, parse_trusted_json
from .resources import resolve_trusted_json_resource, verify_inline_resource_bytes
from .review import (
    RawSemanticVerdict,
    ReviewEligibilityResult,
    TrustedReviewEnvelope,
    build_trusted_review_envelope,
    evaluate_review_invocation_eligibility,
    validate_review_verdict_v1,
)
from .target_registration import admit_target_registration, load_candidate_target_registration
from .state import (
    CandidateRecord,
    CompletionAggregate,
    RepairBudget,
    TaskRecord,
    TaskState,
    adopt_candidate,
    evaluate_task,
    initial_task_proposal,
    reserve_repair_attempt,
    start_operation,
)

__all__ = [
    "CandidateTrustedManifest",
    "EvidenceAdmissionResult",
    "EvidenceRecord",
    "CandidateRecord",
    "CompletionAggregate",
    "OperationRecord",
    "OperationState",
    "ParseLimits",
    "ParsedJsonDocument",
    "RawSemanticVerdict",
    "ReviewEligibilityResult",
    "SemanticCompositionResult",
    "RepairBudget",
    "TaskRecord",
    "TaskState",
    "TrustedReviewEnvelope",
    "TrustedCanonicalSemanticEvidenceSnapshot",
    "TrustedSemanticCompositionContext",
    "adopt_candidate",
    "admit_semantic_review",
    "build_evidence_supersession_record",
    "admit_delegated_authorization",
    "admit_direct_authorization",
    "admit_target_registration",
    "construct_trusted_operation_intent",
    "build_trusted_review_envelope",
    "compose_semantic_evidence",
    "evaluate_evidence_applicability",
    "evaluate_review_invocation_eligibility",
    "evaluate_task",
    "initial_task_proposal",
    "load_candidate_authorization_proposal",
    "load_candidate_target_registration",
    "load_candidate_trusted_manifest",
    "parse_trusted_json",
    "reconcile_operation",
    "reserve_operation",
    "reserve_repair_attempt",
    "resolve_trusted_json_resource",
    "start_operation",
    "semantic_status_for_verdict",
    "transition_operation",
    "validate_review_verdict_v1",
    "verify_inline_resource_bytes",
]
