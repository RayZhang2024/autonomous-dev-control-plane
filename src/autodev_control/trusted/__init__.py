"""Candidate trusted-core primitives. Their construction confers no authority."""

from .authorization import (
    admit_delegated_authorization,
    admit_direct_authorization,
    load_candidate_authorization_proposal,
)
from .manifest import CandidateTrustedManifest, load_candidate_trusted_manifest
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
    "CandidateRecord",
    "CompletionAggregate",
    "OperationRecord",
    "OperationState",
    "ParseLimits",
    "ParsedJsonDocument",
    "RepairBudget",
    "TaskRecord",
    "TaskState",
    "adopt_candidate",
    "admit_delegated_authorization",
    "admit_direct_authorization",
    "admit_target_registration",
    "construct_trusted_operation_intent",
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
    "transition_operation",
    "verify_inline_resource_bytes",
]
