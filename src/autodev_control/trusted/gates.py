"""G7 protected fixture gates.

The gates in this module are a semantic fixture implementation.  They have no
provider, network, credential, workflow, or controlled-runtime integration.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import Enum
import hashlib
import secrets
from threading import RLock

from .audit import (
    AuditAppendStatus, FixtureGateAudit, GateAuditAuthoritativeDependency,
    GateAuditEventPreimage, GateAuditOutcome, build_gate_audit_event,
)
from .backend import (
    AuthorizationExistsAndMatches, CanonicalNamespace, CanonicalTransaction,
    CanonicalStateReadClient,
    CanonicalWriteResult, CanonicalWriteStatus, CreateAuthorization, CreateCandidateWithMaterialization,
    CreateContract, ExactRecordEquals,
    CreateEvidenceAndAdvanceHistory, CreateOperationAndAdvanceMembership,
    CreateTaskAndInitialOperationMembership, EvidenceHistoryMembershipEquals,
    InMemoryCanonicalStateBackend, OperationRevisionEquals, RecordAbsent,
    ReplaceOperation, ReplaceTask, TaskCancellationStatusEquals,
    TaskCurrentCandidateEquals, TaskOperationMembershipEquals, TaskRevisionEquals,
    canonical_json_bytes,
)
from .authorization import (
    AdmittedAuthorization, AuthenticatedHumanAuthorizationApproval,
    AuthorizationKind, AuthorizationPolicyContext, CandidateAuthorizationProposal,
    ContractAuthorityCeiling, DirectIssuerAuthorityEnvelope,
    OrdinaryRootProtectionContext, admit_delegated_authorization,
    admit_direct_authorization,
)
from .contract import (
    CandidateIssueContract, TrustedIssueContractAdmissionContext,
    TrustedIssueContractApplicabilityContext, admit_issue_contract,
    derive_contract_authority_ceiling, evaluate_issue_contract_applicability,
    load_candidate_issue_contract,
)
from .evidence import (
    EvidenceAdmissionDecision, EvidenceClass, SemanticEvidenceAdmissionRequest,
    SemanticEvidenceCurrentnessStatus, consume_current_semantic_evidence,
    admit_semantic_review,
)
from .decision import Decision
from .errors import G4FailureCode
from .fixture_platform import (
    ActiveFixtureRuntimeRegistry, CreatedCandidatePrEffectSubject,
    FastForwardMergeEffectSubject, FixtureFenceToken, FixtureGateRoleFenceClient,
    FixtureStartHeldRecoveryAuthority,
    FixtureGitPlatform,
    ProtectedEffectMarker, ProtectedEffectMarkerPreimage,
    PublishedCandidateRefEffectSubject, build_protected_effect_marker,
)
from .identity import (
    GateRuntimeBindingId, GitRef, GitSha, ImmutableConfigId,
    OperationStartBindingId, PreparedProtectedStartId, RawSha256, RootContextId,
)
from .materialization import (
    AdmittedCandidateMaterialization, CandidateMaterialization,
    CandidateMaterializationAdmissionStatus, FixtureGitObjectStore,
    TrustedCandidateMaterializationContext, admit_candidate_materialization,
    create_admitted_candidate_record,
    inventory_is_authorized,
)
from .operation import (
    AwaitingInputRequirementId,
    AuthoritativeStateBindingId, IntegrationBound, NotIntegrationBound,
    BlockingConditionId, CompletionRuleSetId, EvidenceId,
    OperationActionId, OperationEffectClass, OperationId, OperationIdempotencyKey,
    OperationIntent, OperationPurpose, OperationSubjectId,
    OperationRecord, OperationState, ReconciliationFinding,
    TrustedReconciliationFinding, _compose_trusted_operation_classification,
    construct_trusted_operation_intent,
    derive_operation_start_binding_id_v2 as operation_start_binding_id_v2,
    reconcile_operation as decide_reconciliation, transition_operation,
    CanonicalProtectedStartBinding, StartHeldTargetFenceBinding,
)
from .scope import (
    AuthorizationId, CanonicalBranchRef, ContractId, GitHubRepositoryId,
    MutationScope, ServicePrincipalId, TargetRegistrationId, TaskId,
)
from .state import (
    CancellationRequestId, CancellationStatus, ConditionStatus, EvidenceBindingRef,
    OperationRevisionBinding, RepairBudget, TaskEvaluationInput, TaskState,
    _compose_candidate_applicability, _compose_completion_aggregate,
    adopt_candidate, evaluate_task, initial_task_proposal, reserve_task_operation,
    revise_supporting_evidence, set_cancellation, start_operation as decide_start_operation,
)
from .current_semantic_review import (
    CurrentSemanticReviewResolutionStatus, TrustedSemanticConfigByteReader,
    resolve_current_semantic_review,
)
from .semantic_context import TrustedSemanticContextObservationSource
from .state_reader import AuthoritativeStateDependency, AuthoritativeStateDependencySet
from .manifest import PolicyEpochIdentity
from .operation import AdmissionEventId, CandidateId, DecisionEventId
from .runtime_authority import (
    AuthenticatedCallerContext, AuthenticatedCallerVerifier, ControlStateGateClient,
    ControllerRequestContext,
    MergeGateClient, PublicationGateClient, RuntimeSecurityContext,
    PreparedTargetFenceBinding, ProtectedGateCommand, ProtectedGateRequest,
    TrustedRuntimeRole, PublicationAuthorityClient as PublicationAuthorityContract,
    MergeAuthorityClient as MergeAuthorityContract,
    GateRoleFenceClient as GateRoleFenceContract,
    CanonicalStartReadClient as CanonicalStartReadContract,
    GateAuditClient as GateAuditContract,
    _issue_fixture_caller_context, runtime_context_identity,
    FixtureReadVerifyClient,
)
from .state_reader import (
    AuthoritativeObservationProfile, AuthoritativeStateSnapshot,
    GitHubPullRequestNumber, GitHubStateReader, RegisteredStateFactDescriptor,
    TrustedGitHubReadTransportBinding,
)
from .target_registration import AdmittedTargetRegistration


class TrustedControlCommandKind(Enum):
    ADMIT_CONTRACT = "ADMIT_CONTRACT"
    ADMIT_AUTHORIZATION = "ADMIT_AUTHORIZATION"
    CREATE_TASK = "CREATE_TASK"
    RECORD_CANDIDATE_TRUTH = "RECORD_CANDIDATE_TRUTH"
    ADOPT_CANDIDATE = "ADOPT_CANDIDATE"
    REVISE_SUPPORTING_EVIDENCE = "REVISE_SUPPORTING_EVIDENCE"
    RESERVE_OPERATION = "RESERVE_OPERATION"
    START_OPERATION = "START_OPERATION"
    RESOLVE_TARGET_CONFLICT = "RESOLVE_TARGET_CONFLICT"
    RECONCILE_OPERATION = "RECONCILE_OPERATION"
    EVALUATE_TASK = "EVALUATE_TASK"
    SET_CANCELLATION = "SET_CANCELLATION"
    ADMIT_SEMANTIC_EVIDENCE = "ADMIT_SEMANTIC_EVIDENCE"


class GateResultCode(Enum):
    COMMITTED = "COMMITTED"
    REJECTED = "REJECTED"
    LEASE_INVALID = "LEASE_INVALID"
    LEASE_CONSUMED = "LEASE_CONSUMED"
    ACTION_PRECONDITION_CONFLICT = "ACTION_PRECONDITION_CONFLICT"
    START_COMMITTED = "START_COMMITTED"
    EFFECT_SUCCEEDED = "EFFECT_SUCCEEDED"
    ALREADY_APPLIED = "ALREADY_APPLIED"
    PRECONDITION_CONFLICT = "PRECONDITION_CONFLICT"
    EFFECT_FAILED = "EFFECT_FAILED"
    INDETERMINATE = "INDETERMINATE"
    AUDIT_FAILURE_BEFORE_COMMIT = "AUDIT_FAILURE_BEFORE_COMMIT"
    AUDIT_FAILURE_AFTER_COMMIT = "AUDIT_FAILURE_AFTER_COMMIT"


class TaskSemanticDenialCode(Enum):
    NEXT_INTEGRATION_OPERATION_INVALID = "NEXT_INTEGRATION_OPERATION_INVALID"
    SEMANTIC_CONTRACT_UNSATISFIED = "SEMANTIC_CONTRACT_UNSATISFIED"
    SEMANTIC_CONTEXT_INDETERMINATE = "SEMANTIC_CONTEXT_INDETERMINATE"
    REQUIRED_SEMANTIC_EVIDENCE_NOT_CURRENT = "REQUIRED_SEMANTIC_EVIDENCE_NOT_CURRENT"
    REQUIRED_SEMANTIC_EVIDENCE_NOT_PROGRESSION_SUPPORT = "REQUIRED_SEMANTIC_EVIDENCE_NOT_PROGRESSION_SUPPORT"


class ProtectedStartSemanticDenialCode(Enum):
    REQUIRED_EVIDENCE_NOT_CURRENT = "REQUIRED_EVIDENCE_NOT_CURRENT"
    REQUIRED_EVIDENCE_NOT_VALID_FOR_OPERATION = "REQUIRED_EVIDENCE_NOT_VALID_FOR_OPERATION"
    REQUIRED_EVIDENCE_CONTEXT_INDETERMINATE = "REQUIRED_EVIDENCE_CONTEXT_INDETERMINATE"


class _TaskSemanticDenied(ValueError):
    __slots__ = ("code",)

    def __init__(self, code: TaskSemanticDenialCode) -> None:
        if type(code) is not TaskSemanticDenialCode:
            raise TypeError("semantic task denial requires closed code")
        super().__init__(code.value)
        self.code = code


def _canonical_semantic_dependency_union(
    g1_base_dependency: AuthoritativeStateDependency,
    semantic_dependencies: tuple[AuthoritativeStateDependency, ...],
) -> tuple[AuthoritativeStateDependency, ...] | None:
    """Union exact G1 and #32 dependency facts without repairing either input."""
    if (type(g1_base_dependency) is not AuthoritativeStateDependency
            or type(semantic_dependencies) is not tuple):
        return None
    try:
        # #32 owns canonicalization of its set.  Reject malformed lower-layer
        # input before the one permitted cross-layer exact-duplicate collapse.
        AuthoritativeStateDependencySet(semantic_dependencies)
    except (TypeError, ValueError):
        return None
    by_locator: dict[tuple, AuthoritativeStateDependency] = {}
    for item in (g1_base_dependency, *semantic_dependencies):
        if type(item) is not AuthoritativeStateDependency:
            return None
        previous = by_locator.get(item.locator)
        if previous is not None:
            if previous.expected_binding_id != item.expected_binding_id:
                return None
            continue
        by_locator[item.locator] = item
    canonical = tuple(by_locator[key] for key in sorted(
        by_locator, key=lambda locator: tuple(value.value for value in locator)
    ))
    try:
        AuthoritativeStateDependencySet(canonical)
    except (TypeError, ValueError):
        return None
    return canonical


class ProtectedEffectSubject(Enum):
    CANDIDATE_BRANCH_PUBLICATION = "CANDIDATE_BRANCH_PUBLICATION"
    PULL_REQUEST_CREATION = "PULL_REQUEST_CREATION"
    FAST_FORWARD_MERGE = "FAST_FORWARD_MERGE"


class PreparedProtectedStartState(Enum):
    PREPARED = "PREPARED"
    START_HELD = "START_HELD"
    CONSUMED = "CONSUMED"
    RELEASED = "RELEASED"


@dataclass(frozen=True, slots=True)
class OperationReservationCommand:
    """Closed untrusted request; trusted classification and authority fields are derived."""

    operation_id: OperationId
    idempotency_key: OperationIdempotencyKey
    action_id: OperationActionId
    subject_id: OperationSubjectId
    required_evidence_ids: tuple[EvidenceId, ...]
    integration_binding: IntegrationBound | NotIntegrationBound
    is_repair_attempt: bool = False

    def __post_init__(self) -> None:
        exact = (
            (self.operation_id, OperationId),
            (self.idempotency_key, OperationIdempotencyKey),
            (self.action_id, OperationActionId),
            (self.subject_id, OperationSubjectId),
        )
        if any(type(value) is not expected for value, expected in exact):
            raise TypeError("operation reservation request has wrong exact type")
        if (type(self.required_evidence_ids) is not tuple
                or any(type(item) is not EvidenceId for item in self.required_evidence_ids)
                or len(set(self.required_evidence_ids)) != len(self.required_evidence_ids)):
            raise TypeError("required evidence must be an exact duplicate-free tuple")
        if type(self.integration_binding) not in (IntegrationBound, NotIntegrationBound):
            raise TypeError("integration binding has wrong exact variant")
        if type(self.is_repair_attempt) is not bool:
            raise TypeError("is_repair_attempt must be exactly bool")


@dataclass(frozen=True, slots=True)
class TaskEvaluationCommand:
    """Request-level posture referring to a root-managed completion context."""

    task_id: TaskId
    completion_context_id: ImmutableConfigId
    blocking_condition_ids: tuple[BlockingConditionId, ...]
    awaiting_input_requirement_ids: tuple[AwaitingInputRequirementId, ...]
    next_integration_operation_id: OperationId | None

    def __post_init__(self) -> None:
        if type(self.task_id) is not TaskId or type(self.completion_context_id) is not ImmutableConfigId:
            raise TypeError("task evaluation request has wrong exact identity")
        for values, expected in (
            (self.blocking_condition_ids, BlockingConditionId),
            (self.awaiting_input_requirement_ids, AwaitingInputRequirementId),
        ):
            if (type(values) is not tuple or any(type(item) is not expected for item in values)
                    or len(set(values)) != len(values)):
                raise TypeError("task evaluation collections must be exact duplicate-free tuples")
        if (self.next_integration_operation_id is not None
                and type(self.next_integration_operation_id) is not OperationId):
            raise TypeError("next operation must be exact OperationId or None")


@dataclass(frozen=True, slots=True, init=False)
class TrustedCompletionEvaluationContext:
    """Root-managed exact inputs for the frozen G4 completion predicate."""

    context_id: ImmutableConfigId
    task_id: TaskId
    completion_rule_set_id: CompletionRuleSetId
    contract_id: ContractId
    contract_raw_sha256: RawSha256
    authorization_id: AuthorizationId
    admission_event_id: AdmissionEventId
    target_registration_id: TargetRegistrationId
    policy_epoch_identity: PolicyEpochIdentity
    candidate_id: CandidateId | None
    contract_acceptance_status: ConditionStatus
    additional_trusted_completion_conditions_status: ConditionStatus
    required_protected_operation_ids: tuple[OperationId, ...]
    current_applicability_and_authority_status: ConditionStatus

    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("completion contexts are installed only by root-managed fixture setup")


@dataclass(frozen=True, slots=True)
class SemanticEvidenceCommand:
    """Raw provider response routed to a pre-registered trusted G5 context."""

    admission_context_id: ImmutableConfigId
    raw_response: bytes

    def __post_init__(self) -> None:
        if type(self.admission_context_id) is not ImmutableConfigId:
            raise TypeError("admission context id must be exact ImmutableConfigId")
        if type(self.raw_response) is not bytes:
            raise TypeError("raw response must be exact bytes")


@dataclass(frozen=True, slots=True)
class FixtureRuntimeGeneration:
    value: int

    def __post_init__(self) -> None:
        if type(self.value) is not int or self.value < 1:
            raise ValueError("runtime generation must be positive")


@dataclass(frozen=True, slots=True)
class GateRuntimeBinding:
    root_context_id: RootContextId
    runtime_generation: FixtureRuntimeGeneration
    control_state_principal: ServicePrincipalId
    publication_principal: ServicePrincipalId
    merge_principal: ServicePrincipalId
    runtime_instance_nonce: RawSha256 = field(default_factory=lambda: RawSha256(secrets.token_hex(32)))
    runtime_binding_id: GateRuntimeBindingId = field(init=False)

    def __post_init__(self) -> None:
        values = (self.control_state_principal, self.publication_principal, self.merge_principal)
        if type(self.root_context_id) is not RootContextId or type(self.runtime_generation) is not FixtureRuntimeGeneration:
            raise TypeError("runtime identity has wrong exact type")
        if any(type(item) is not ServicePrincipalId for item in values):
            raise TypeError("gate principal has wrong exact type")
        if len(set(values)) != 3:
            raise ValueError("control, publication, and merge principals must be pairwise distinct")
        if type(self.runtime_instance_nonce) is not RawSha256:
            raise TypeError("runtime instance nonce must be exact RawSha256")
        digest = hashlib.sha256(canonical_json_bytes((
            "autodev.gate-runtime-binding/v1", self.root_context_id,
            self.runtime_generation.value, values, self.runtime_instance_nonce,
        ))).hexdigest()
        object.__setattr__(self, "runtime_binding_id", GateRuntimeBindingId(RawSha256(digest)))


TrustedGateRuntimeBinding = GateRuntimeBinding


class _Capability:
    __slots__ = ("_nonce", "service_identity")

    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("capabilities are minted only by the fixture gate runtime")


class ControlStateCapability(_Capability):
    pass


class TargetPublicationCapability(_Capability):
    pass


class MergeCapability(_Capability):
    pass


def _mint_capability(kind: type[_Capability], nonce: object, service_identity: ServicePrincipalId) -> _Capability:
    value = object.__new__(kind)
    value._nonce = nonce
    value.service_identity = service_identity
    return value


# Compatibility aliases intentionally preserve the one closed lower-layer model.
ControlStateAuthoritativeDependency = AuthoritativeStateDependency
ControlStateAuthoritativeDependencySet = AuthoritativeStateDependencySet
ResolvableStateDependency = AuthoritativeStateDependency
ExactDependencySet = AuthoritativeStateDependencySet


class ExternalStateIndependence:
    __slots__ = ("_nonce",)

    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("external-state independence is a trusted decision result")


class _OneUse:
    __slots__ = ("_owner", "_nonce", "_used")

    def __init__(self, owner: object, nonce: object) -> None:
        self._owner, self._nonce, self._used = owner, nonce, False

    def _consume(self, owner: object, nonce: object) -> bool:
        if self._used or self._owner is not owner or self._nonce is not nonce:
            return False
        self._used = True
        return True

    def __reduce__(self) -> object:
        raise TypeError("ephemeral gate authority cannot be serialized")


class ControlStateCommitLease(_OneUse):
    __slots__ = ("root_context_id", "runtime_generation", "runtime_binding", "dependencies", "capability", "fence_token")

    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("control-state leases are minted only by the active gate")


class PreparedStartCommitLease(_OneUse):
    __slots__ = ("control_lease", "action_target_fence", "prepared_start", "target_capability", "runtime_binding", "authorized_scope", "root_forbidden_scope", "target_fence_token")

    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("prepared-start leases are minted only by the active gate")


class LiveProtectedEffectContinuation(_OneUse):
    __slots__ = ("operation_id", "idempotency_key", "action_id", "intent", "start_binding_id", "prepared_start_id", "subject", "action_target_fence", "integration_binding", "authorized_scope", "root_forbidden_scope", "dependencies", "target_fence_token", "materialization", "target_registration", "base_ref", "provenance_operation_id")

    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("effect continuations are minted only by a freshly audited start")


@dataclass(frozen=True, slots=True)
class ActionTargetFence:
    repository_id: GitHubRepositoryId
    ref: CanonicalBranchRef
    expected_sha: GitSha | None
    platform_generation: int
    base_ref: CanonicalBranchRef | None = None
    base_expected_sha: GitSha | None = None

    def __post_init__(self) -> None:
        if type(self.repository_id) is not GitHubRepositoryId or type(self.ref) is not CanonicalBranchRef:
            raise TypeError("action target identity has wrong exact type")
        if self.expected_sha is not None and type(self.expected_sha) is not GitSha:
            raise TypeError("expected_sha must be exact GitSha or None")
        if type(self.platform_generation) is not int or self.platform_generation < 1:
            raise ValueError("platform generation must be positive")
        if (self.base_ref is None) != (self.base_expected_sha is None):
            raise ValueError("secondary base ref and SHA must be present together")
        if self.base_ref is not None and (
            type(self.base_ref) is not CanonicalBranchRef
            or type(self.base_expected_sha) is not GitSha
        ):
            raise TypeError("secondary base fence has wrong exact type")


@dataclass(frozen=True, slots=True)
class PreparedProtectedStartPreimage:
    format: str
    operation_id: OperationId
    action: ProtectedEffectSubject
    target_fence: ActionTargetFence
    root_context_id: RootContextId
    runtime_generation: FixtureRuntimeGeneration
    runtime_binding_id: GateRuntimeBindingId
    service_identity: ServicePrincipalId
    dependencies: ControlStateAuthoritativeDependencySet
    materialization: CandidateMaterialization
    target_registration: AdmittedTargetRegistration
    base_ref: CanonicalBranchRef | None
    provenance_operation_id: OperationId | None
    authorized_scope: MutationScope
    root_forbidden_scope: MutationScope


class PreparedProtectedStart:
    __slots__ = ("prepared_start_id", "operation", "subject", "fence", "preimage",
                 "prepared_target_fence_binding", "_platform", "_sealed")

    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("prepared protected starts are gate-private")

    @property
    def state(self) -> PreparedProtectedStartState:
        current = self._platform.read_prepared_effect_state(
            self.operation.intent.operation_id, self.subject.value
        )
        if current is None:
            raise RuntimeError("durable prepared record is unavailable")
        return PreparedProtectedStartState(current)

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False):
            raise AttributeError("prepared protected start is immutable")
        object.__setattr__(self, name, value)

    def __reduce__(self) -> object:
        raise TypeError("prepared gate state cannot be serialized")


@dataclass(frozen=True, slots=True, init=False)
class ControlStateCommitRequest:
    command_kind: TrustedControlCommandKind
    transaction: CanonicalTransaction
    required_authoritative_binding_ids: tuple[AuthoritativeStateBindingId, ...]
    required_authoritative_dependencies: tuple[AuthoritativeStateDependency, ...]
    _key: object

    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("commit requests are emitted only by DeterministicTrustedController")

    @property
    def request_format(self) -> str:
        return "autodev.trusted-controller-to-control-state/v1"

    @property
    def declared_t_identity(self) -> RawSha256:
        issuer = self._key
        if type(issuer) is not ControllerRequestContext:
            raise TypeError("closed controller request context is unavailable")
        return runtime_context_identity(issuer.caller)

    @property
    def destination_c_identity(self) -> RawSha256:
        issuer = self._key
        if type(issuer) is not ControllerRequestContext:
            raise TypeError("closed controller request context is unavailable")
        return runtime_context_identity(issuer.destination)

    @property
    def root_context_id(self) -> RootContextId:
        issuer = self._key
        if type(issuer) is not ControllerRequestContext:
            raise TypeError("closed controller request context is unavailable")
        return issuer.caller.root_context_id

    @property
    def runtime_generation(self) -> int:
        issuer = self._key
        if type(issuer) is not ControllerRequestContext:
            raise TypeError("closed controller request context is unavailable")
        return issuer.caller.runtime_generation

    @property
    def replay_identity(self) -> RawSha256:
        required_bindings = getattr(self, "required_authoritative_binding_ids", ())
        required_dependencies = getattr(self, "required_authoritative_dependencies", ())
        return RawSha256(hashlib.sha256(canonical_json_bytes((
            "autodev.trusted-controller-request-replay/v1", self.command_kind,
            self.transaction.expected_state_occurrence,
            self.transaction.conditions, self.transaction.mutations,
            required_bindings, required_dependencies,
        ))).hexdigest())

    @property
    def request_digest(self) -> RawSha256:
        return RawSha256(hashlib.sha256(canonical_json_bytes((
            self.request_format, self.command_kind, self.transaction,
            getattr(self, "required_authoritative_binding_ids", ()),
            getattr(self, "required_authoritative_dependencies", ()),
            self.declared_t_identity, self.destination_c_identity,
            self.root_context_id, self.runtime_generation,
            self.replay_identity,
        ))).hexdigest())


@dataclass(frozen=True, slots=True)
class GateResult:
    code: GateResultCode
    canonical_result: CanonicalWriteResult | None = None
    continuation: LiveProtectedEffectContinuation | None = None
    failure_code: G4FailureCode | None = None
    semantic_denial_code: ProtectedStartSemanticDenialCode | None = None

    def __post_init__(self) -> None:
        if type(self.code) is not GateResultCode:
            raise TypeError("gate result code has wrong exact type")
        if self.canonical_result is not None and type(self.canonical_result) is not CanonicalWriteResult:
            raise TypeError("canonical result has wrong exact type")
        if self.continuation is not None and type(self.continuation) is not LiveProtectedEffectContinuation:
            raise TypeError("continuation has wrong exact type")
        if self.failure_code is not None and type(self.failure_code) is not G4FailureCode:
            raise TypeError("failure code has wrong exact type")
        if (self.semantic_denial_code is not None
                and type(self.semantic_denial_code) is not ProtectedStartSemanticDenialCode):
            raise TypeError("semantic denial code has wrong exact type")
        if self.failure_code is not None and self.semantic_denial_code is not None:
            raise ValueError("G4 failure and semantic denial are mutually exclusive")


class _DeterministicStartDenied(ValueError):
    """Internal transport for an exact G4 start denial through G7 orchestration."""

    __slots__ = ("failure_code",)

    def __init__(self, failure_code: G4FailureCode) -> None:
        if type(failure_code) is not G4FailureCode:
            raise TypeError("start denial requires an exact G4 failure code")
        super().__init__(failure_code.value)
        self.failure_code = failure_code


class DeterministicTrustedController:
    """Closed command-to-proposal boundary; caller G4 objects are never accepted."""

    __slots__ = ("_key", "_backend", "_completion_contexts", "_object_store")

    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("trusted controller is installed only by the active gate runtime")

    def admit_contract(
        self, raw: bytes, context: TrustedIssueContractAdmissionContext | None,
    ) -> ControlStateCommitRequest:
        candidate = load_candidate_issue_contract(raw)
        if type(candidate) is not CandidateIssueContract:
            raise ValueError(candidate.code.value)
        existing = self._backend.read_contract(candidate.contract_id)
        if existing is not None:
            if existing.contract_raw_sha256 != candidate.source_document.raw_sha256:
                raise ValueError(CanonicalWriteStatus.IDENTITY_CONFLICT.value)
            transaction = CanonicalTransaction(
                self._backend.occurrence,
                (ExactRecordEquals(CanonicalNamespace.CONTRACT, candidate.contract_id, existing),),
                (),
            )
            request = object.__new__(ControlStateCommitRequest)
            object.__setattr__(request, "command_kind", TrustedControlCommandKind.ADMIT_CONTRACT)
            object.__setattr__(request, "transaction", transaction)
            object.__setattr__(request, "required_authoritative_binding_ids", ())
            object.__setattr__(request, "_key", self._key)
            return request
        if type(context) is not TrustedIssueContractAdmissionContext:
            raise ValueError("trusted contract admission context is unavailable")
        result = admit_issue_contract(candidate, context)
        if result.proposed_contract is None:
            raise ValueError(result.reason_code.value)
        contract = result.proposed_contract
        transaction = CanonicalTransaction(
            self._backend.occurrence,
            (),
            (CreateContract(contract),),
        )
        request = object.__new__(ControlStateCommitRequest)
        object.__setattr__(request, "command_kind", TrustedControlCommandKind.ADMIT_CONTRACT)
        object.__setattr__(request, "transaction", transaction)
        object.__setattr__(request, "required_authoritative_binding_ids", tuple(dict.fromkeys((
            context.issue_identity.authoritative_state_binding_id,
            context.base_observation.authoritative_state_binding_id,
        ))))
        object.__setattr__(request, "_key", self._key)
        return request

    def admit_authorization(
        self, proposal: CandidateAuthorizationProposal,
        target: AdmittedTargetRegistration | None,
        contract_context: TrustedIssueContractApplicabilityContext,
        policy: AuthorizationPolicyContext | None,
        root: OrdinaryRootProtectionContext | None,
        *, approval: AuthenticatedHumanAuthorizationApproval | None = None,
        issuer: DirectIssuerAuthorityEnvelope | None = None,
    ) -> ControlStateCommitRequest:
        if type(proposal) is not CandidateAuthorizationProposal:
            raise TypeError("exact candidate authorization proposal required")
        contract = self._backend.read_contract(proposal.contract_id)
        if contract is None or contract.contract_raw_sha256 != proposal.contract_raw_sha256:
            raise ValueError("contract is not the exact canonical value")
        applicability = evaluate_issue_contract_applicability(contract, contract_context)
        if applicability.decision is not Decision.ALLOW:
            raise ValueError(applicability.outcome.value)
        ceiling = derive_contract_authority_ceiling(contract)
        resolved = self._backend.read_resolved_target_registration(
            proposal.target_registration_id
        )
        if resolved is None or resolved.registration != target:
            raise ValueError("target registration is not the exact root-resolved value")
        if proposal.kind is AuthorizationKind.DIRECT_HUMAN:
            result = admit_direct_authorization(
                proposal, target, ceiling, policy, approval, issuer, root
            )
        else:
            parent = (
                None if proposal.parent_authorization_id is None
                else self._backend.read_authorization(proposal.parent_authorization_id)
            )
            result = admit_delegated_authorization(
                proposal, target, ceiling, policy, parent, root
            )
        if result.admitted_authorization is None:
            raise ValueError(result.reason_code.value)
        admitted = result.admitted_authorization
        transaction = CanonicalTransaction(
            self._backend.occurrence,
            (RecordAbsent(CanonicalNamespace.AUTHORIZATION, admitted.authorization_id),),
            (CreateAuthorization(admitted),),
        )
        request = object.__new__(ControlStateCommitRequest)
        object.__setattr__(request, "command_kind", TrustedControlCommandKind.ADMIT_AUTHORIZATION)
        object.__setattr__(request, "transaction", transaction)
        object.__setattr__(request, "required_authoritative_binding_ids", ())
        object.__setattr__(request, "_key", self._key)
        return request

    def create_task(
        self, *, task_id: TaskId, contract_id: ContractId,
        contract_raw_sha256: RawSha256, authorization_id: AuthorizationId,
        admission_event_id: AdmissionEventId,
        target_registration_id: TargetRegistrationId,
        policy_epoch_identity: PolicyEpochIdentity, repair_budget: RepairBudget,
    ) -> ControlStateCommitRequest:
        proposal = initial_task_proposal(
            task_id=task_id, contract_id=contract_id,
            contract_raw_sha256=contract_raw_sha256,
            authorization_id=authorization_id, admission_event_id=admission_event_id,
            target_registration_id=target_registration_id,
            policy_epoch_identity=policy_epoch_identity, repair_budget=repair_budget,
        )
        working = self._backend.read_authorization(authorization_id)
        if working is None:
            raise ValueError("authorization is not canonical")
        contract = self._backend.read_contract(contract_id)
        if (
            contract is None or contract.contract_raw_sha256 != contract_raw_sha256
            or contract.task_id != task_id or contract.target_registration_id != target_registration_id
            or working.contract_id != contract_id or working.contract_raw_sha256 != contract_raw_sha256
        ):
            raise ValueError("task requires exact canonical contract and authorization")
        transaction = CanonicalTransaction(
            self._backend.occurrence,
            (
                AuthorizationExistsAndMatches(working),
                ExactRecordEquals(CanonicalNamespace.CONTRACT, contract_id, contract),
                RecordAbsent(CanonicalNamespace.TASK, task_id),
            ),
            (CreateTaskAndInitialOperationMembership(proposal.proposed),),
        )
        request = object.__new__(ControlStateCommitRequest)
        object.__setattr__(request, "command_kind", TrustedControlCommandKind.CREATE_TASK)
        object.__setattr__(request, "transaction", transaction)
        object.__setattr__(request, "required_authoritative_binding_ids", ())
        object.__setattr__(request, "_key", self._key)
        return request

    def create_candidate_and_adopt(self, **_: object) -> ControlStateCommitRequest:
        raise TypeError("combined candidate creation/adoption is unavailable; record then adopt by CandidateId")

    def record_candidate_truth(
        self, *, task_id: TaskId, candidate_id: CandidateId,
        candidate_commit_id: GitSha,
        parent_candidate_ids: tuple[CandidateId, ...] = (),
        creation_operation_id: OperationId | None = None,
    ) -> ControlStateCommitRequest:
        current = self._backend.read_task_working_set(task_id)
        if current is None or self._object_store is None:
            raise ValueError("canonical task or trusted Git-object substrate is unavailable")
        task = current.task
        contract = self._backend.read_contract(task.contract_id)
        if contract is None or contract.contract_raw_sha256 != task.contract_raw_sha256:
            raise ValueError("canonical task contract is unavailable")
        resolved_target = self._backend.read_resolved_target_registration(
            task.target_registration_id
        )
        if (
            resolved_target is None
            or resolved_target.target_registration_id != task.target_registration_id
            or resolved_target.registration.target_registration_id != task.target_registration_id
            or resolved_target.policy_epoch_identity
            != task.last_evaluated_policy_epoch_identity
            or resolved_target.registration.policy_epoch_identity
            != task.last_evaluated_policy_epoch_identity
        ):
            raise ValueError("canonical resolved target registration is unavailable")
        context = object.__new__(TrustedCandidateMaterializationContext)
        for name, value in (
            ("repository_id", resolved_target.registration.repository_id), ("task_id", task.task_id),
            ("contract_id", task.contract_id), ("contract_raw_sha256", task.contract_raw_sha256),
            ("authorization_id", task.authorization_id),
            ("target_registration_id", task.target_registration_id),
            ("policy_epoch_identity", task.last_evaluated_policy_epoch_identity),
            ("base_commit", contract.base_sha),
        ):
            object.__setattr__(context, name, value)
        admission = admit_candidate_materialization(
            store=self._object_store, context=context, candidate_id=candidate_id,
            candidate_commit_id=candidate_commit_id,
        )
        if admission.status is not CandidateMaterializationAdmissionStatus.ADMITTED:
            raise ValueError(admission.reason.value)
        materialization = admission.admitted_materialization
        candidate = create_admitted_candidate_record(
            materialization=materialization, admission_event_id=task.admission_event_id,
            parent_candidate_ids=parent_candidate_ids, creation_operation_id=creation_operation_id,
        )
        transaction = CanonicalTransaction(
            current.canonical_state_occurrence_binding,
            (TaskRevisionEquals(task.task_id, task.revision),),
            (CreateCandidateWithMaterialization(candidate, materialization),),
        )
        request = object.__new__(ControlStateCommitRequest)
        object.__setattr__(request, "command_kind", TrustedControlCommandKind.RECORD_CANDIDATE_TRUTH)
        object.__setattr__(request, "transaction", transaction)
        object.__setattr__(request, "required_authoritative_binding_ids", ())
        object.__setattr__(request, "_key", self._key)
        return request

    def adopt_recorded_candidate(
        self, *, task_id: TaskId, candidate_id: CandidateId,
        decision_event_id: DecisionEventId,
    ) -> ControlStateCommitRequest:
        current = self._backend.read_task_working_set(task_id)
        candidate = self._backend.read_candidate(candidate_id)
        if current is None or candidate is None:
            raise ValueError("canonical task or candidate is unavailable")
        materialization = self._backend.read_candidate_materialization(candidate.materialization_id)
        if materialization is None or (
            candidate.candidate_id != materialization.candidate_id
            or candidate.task_id != materialization.task_id
            or candidate.base != materialization.base_commit
            or candidate.contract_id != materialization.contract_id
            or candidate.contract_raw_sha256 != materialization.contract_raw_sha256
            or candidate.authorization_id != materialization.authorization_id
            or candidate.target_registration_id != materialization.target_registration_id
            or candidate.policy_epoch_identity != materialization.policy_epoch_identity
        ):
            raise ValueError("canonical candidate/materialization continuity is unavailable")
        task = current.task
        determination = _compose_candidate_applicability(task, candidate, decision_event_id)
        result = adopt_candidate(
            task, candidate, determination, expected_task_revision=task.revision,
            snapshot=current.task_operation_snapshot(),
            expected_membership_binding_id=current.task_operation_membership.membership_binding_id,
            expected_operation_revisions=tuple(
                OperationRevisionBinding(item.intent.operation_id, item.revision)
                for item in current.operations if item.intent.candidate_id == task.current_candidate_id
            ),
        )
        if result.proposal is None:
            raise ValueError(result.failure.code.value)
        transaction = CanonicalTransaction(
            current.canonical_state_occurrence_binding,
            (
                TaskRevisionEquals(task.task_id, task.revision),
                TaskOperationMembershipEquals(task.task_id, current.task_operation_membership.membership_binding_id),
                ExactRecordEquals(CanonicalNamespace.CANDIDATE, candidate.candidate_id, candidate),
                ExactRecordEquals(CanonicalNamespace.CANDIDATE_MATERIALIZATION, materialization.materialization_id, materialization),
            ),
            (ReplaceTask(task.revision, result.proposal.proposed),),
        )
        request = object.__new__(ControlStateCommitRequest)
        object.__setattr__(request, "command_kind", TrustedControlCommandKind.ADOPT_CANDIDATE)
        object.__setattr__(request, "transaction", transaction)
        object.__setattr__(request, "required_authoritative_binding_ids", ())
        object.__setattr__(request, "_key", self._key)
        return request

    def revise_supporting_evidence(
        self, task_id: TaskId, refs: tuple[EvidenceBindingRef, ...]
    ) -> ControlStateCommitRequest:
        current = self._backend.read_task_working_set(task_id)
        if current is None:
            raise ValueError("task is not canonical")
        result = revise_supporting_evidence(
            current.task, refs, expected_task_revision=current.task.revision
        )
        if result.proposal is None:
            raise ValueError(result.failure.code.value)
        transaction = CanonicalTransaction(
            current.canonical_state_occurrence_binding,
            (TaskRevisionEquals(task_id, current.task.revision),),
            (ReplaceTask(current.task.revision, result.proposal.proposed),),
        )
        request = object.__new__(ControlStateCommitRequest)
        object.__setattr__(request, "command_kind", TrustedControlCommandKind.REVISE_SUPPORTING_EVIDENCE)
        object.__setattr__(request, "transaction", transaction)
        object.__setattr__(request, "_key", self._key)
        return request

    def reserve_operation(self, task_id: TaskId,
                          command: OperationReservationCommand,
                          authoritative_binding: AuthoritativeStateBindingId) -> ControlStateCommitRequest:
        if type(command) is not OperationReservationCommand:
            raise TypeError("exact OperationReservationCommand required")
        if type(authoritative_binding) is not AuthoritativeStateBindingId:
            raise TypeError("trusted authoritative binding required")
        current = self._backend.read_task_working_set(task_id)
        if current is None:
            raise ValueError("task is not canonical")
        task = current.task
        classification = _compose_trusted_operation_classification(
            OperationEffectClass.PROTECTED_OR_AUTHORITATIVE_EFFECT,
            OperationPurpose.NORMAL,
        )
        intent = construct_trusted_operation_intent(
            classification=classification,
            operation_id=command.operation_id,
            idempotency_key=command.idempotency_key,
            task_id=task.task_id,
            action_id=command.action_id,
            subject_id=command.subject_id,
            candidate_id=task.current_candidate_id,
            contract_id=task.contract_id,
            contract_raw_sha256=task.contract_raw_sha256,
            authorization_id=task.authorization_id,
            admission_event_id=task.admission_event_id,
            target_registration_id=task.target_registration_id,
            policy_epoch_identity=task.last_evaluated_policy_epoch_identity,
            authoritative_state_binding_id=authoritative_binding,
            required_evidence_ids=command.required_evidence_ids,
            integration_binding=command.integration_binding,
            is_repair_attempt=command.is_repair_attempt,
        )
        result = reserve_task_operation(
            current.task, intent, current.task_operation_snapshot(),
            expected_task_revision=current.task.revision,
            expected_membership_binding_id=current.task_operation_membership.membership_binding_id,
        )
        proposal = result.operation_create_proposal
        if proposal is None:
            raise ValueError("operation reservation was not a fresh proposal")
        transaction = CanonicalTransaction(
            current.canonical_state_occurrence_binding,
            (
                TaskRevisionEquals(task_id, current.task.revision),
                TaskOperationMembershipEquals(
                    task_id, current.task_operation_membership.membership_binding_id
                ),
                RecordAbsent(CanonicalNamespace.OPERATION, intent.operation_id),
            ),
            (CreateOperationAndAdvanceMembership(
                proposal.proposed, proposal.expected_task_revision,
                proposal.expected_membership_binding_id,
            ),),
        )
        request = object.__new__(ControlStateCommitRequest)
        object.__setattr__(request, "command_kind", TrustedControlCommandKind.RESERVE_OPERATION)
        object.__setattr__(request, "transaction", transaction)
        object.__setattr__(request, "_key", self._key)
        return request

    def start_operation(
        self, task_id: TaskId, operation_id: OperationId,
        prepared_start: PreparedProtectedStartId | StartHeldTargetFenceBinding,
    ) -> ControlStateCommitRequest:
        current = self._backend.read_task_working_set(task_id)
        if current is None:
            raise ValueError("task is not canonical")
        operation = next(
            (item for item in current.operations if item.intent.operation_id == operation_id), None
        )
        if operation is None:
            raise ValueError("operation is not canonical")
        if type(prepared_start) is PreparedProtectedStartId:
            start_id = operation_start_binding_id(prepared_start)
            companion = None
        elif type(prepared_start) is StartHeldTargetFenceBinding:
            start_id = operation_start_binding_id_v2(prepared_start)
            companion = CanonicalProtectedStartBinding(start_id, prepared_start)
        else:
            raise TypeError("exact prepared identity or F start-held binding required")
        result = decide_start_operation(
            current.task, operation, expected_task_revision=current.task.revision,
            expected_operation_revision=operation.revision,
            expected_cancellation_status=current.task.cancellation_status,
            operation_start_binding_id=start_id,
        )
        proposal = result.operation_start_proposal
        if proposal is None:
            raise _DeterministicStartDenied(result.failure.code)
        conditions = (
            TaskRevisionEquals(task_id, current.task.revision),
            OperationRevisionEquals(operation_id, operation.revision),
            TaskCancellationStatusEquals(task_id, current.task.cancellation_status),
            TaskCurrentCandidateEquals(task_id, current.task.current_candidate_id),
        )
        proposed_operation = proposal.proposed_operation
        if companion is not None:
            proposed_operation = replace(
                proposed_operation,
                canonical_protected_start_binding=companion,
            )
        mutations = (ReplaceOperation(operation.revision, proposed_operation),)
        if proposal.proposed_task is not None:
            mutations = (ReplaceTask(current.task.revision, proposal.proposed_task), *mutations)
        transaction = CanonicalTransaction(
            current.canonical_state_occurrence_binding, conditions, mutations
        )
        request = object.__new__(ControlStateCommitRequest)
        object.__setattr__(request, "command_kind", TrustedControlCommandKind.START_OPERATION)
        object.__setattr__(request, "transaction", transaction)
        object.__setattr__(request, "_key", self._key)
        return request

    def _decide_reconciliation(
        self, task_id: TaskId, operation_id: OperationId,
        finding: TrustedReconciliationFinding,
    ) -> ControlStateCommitRequest:
        current = self._backend.read_task_working_set(task_id)
        if current is None:
            raise ValueError("task is not canonical")
        operation = next(
            (item for item in current.operations if item.intent.operation_id == operation_id), None
        )
        if operation is None:
            raise ValueError("operation is not canonical")
        result = decide_reconciliation(operation, operation.revision, finding)
        if result.proposal is None:
            raise ValueError(result.failure.code.value)
        transaction = CanonicalTransaction(
            current.canonical_state_occurrence_binding,
            (OperationRevisionEquals(operation_id, operation.revision),),
            (ReplaceOperation(operation.revision, result.proposal.proposed),),
        )
        request = object.__new__(ControlStateCommitRequest)
        object.__setattr__(request, "command_kind", TrustedControlCommandKind.RECONCILE_OPERATION)
        object.__setattr__(request, "transaction", transaction)
        object.__setattr__(request, "_key", self._key)
        return request

    def _transition_unstarted_conflict(
        self, task_id: TaskId, operation_id: OperationId,
    ) -> ControlStateCommitRequest:
        current = self._backend.read_task_working_set(task_id)
        if current is None:
            raise ValueError("task is not canonical")
        operation = next(
            (item for item in current.operations if item.intent.operation_id == operation_id), None
        )
        if operation is None:
            raise ValueError("operation is not canonical")
        result = transition_operation(
            operation, operation.revision, OperationState.CONFLICT,
            reason_code=G4FailureCode.ACTION_PRECONDITION_CONFLICT,
        )
        if result.proposal is None:
            raise ValueError(result.failure.code.value)
        transaction = CanonicalTransaction(
            current.canonical_state_occurrence_binding,
            (OperationRevisionEquals(operation_id, operation.revision),),
            (ReplaceOperation(operation.revision, result.proposal.proposed),),
        )
        request = object.__new__(ControlStateCommitRequest)
        object.__setattr__(request, "command_kind", TrustedControlCommandKind.RESOLVE_TARGET_CONFLICT)
        object.__setattr__(request, "transaction", transaction)
        object.__setattr__(request, "_key", self._key)
        return request

    def _transition_started_failed(
        self, task_id: TaskId, operation_id: OperationId,
    ) -> ControlStateCommitRequest:
        current = self._backend.read_task_working_set(task_id)
        if current is None:
            raise ValueError("task is not canonical")
        operation = next(
            (item for item in current.operations if item.intent.operation_id == operation_id), None
        )
        if operation is None:
            raise ValueError("operation is not canonical")
        result = transition_operation(operation, operation.revision, OperationState.FAILED)
        if result.proposal is None:
            raise ValueError(result.failure.code.value)
        transaction = CanonicalTransaction(
            current.canonical_state_occurrence_binding,
            (OperationRevisionEquals(operation_id, operation.revision),),
            (ReplaceOperation(operation.revision, result.proposal.proposed),),
        )
        request = object.__new__(ControlStateCommitRequest)
        object.__setattr__(request, "command_kind", TrustedControlCommandKind.RECONCILE_OPERATION)
        object.__setattr__(request, "transaction", transaction)
        object.__setattr__(request, "_key", self._key)
        return request

    def evaluate_task(self, command: TaskEvaluationCommand) -> ControlStateCommitRequest:
        if type(command) is not TaskEvaluationCommand:
            raise TypeError("exact TaskEvaluationCommand required")
        task_id = command.task_id
        current = self._backend.read_task_working_set(command.task_id)
        if current is None:
            raise ValueError("task is not canonical")
        task = current.task
        context = self._completion_contexts.get(command.completion_context_id)
        if type(context) is not TrustedCompletionEvaluationContext:
            raise ValueError("trusted completion context is unavailable")
        exact = (
            (context.context_id, command.completion_context_id),
            (context.task_id, task.task_id),
            (context.contract_id, task.contract_id),
            (context.contract_raw_sha256, task.contract_raw_sha256),
            (context.authorization_id, task.authorization_id),
            (context.admission_event_id, task.admission_event_id),
            (context.target_registration_id, task.target_registration_id),
            (context.policy_epoch_identity, task.last_evaluated_policy_epoch_identity),
            (context.candidate_id, task.current_candidate_id),
        )
        if any(actual != expected for actual, expected in exact):
            raise ValueError("trusted completion context does not match canonical task")
        if (
            type(context.completion_rule_set_id) is not CompletionRuleSetId
            or type(context.contract_acceptance_status) is not ConditionStatus
            or type(context.additional_trusted_completion_conditions_status) is not ConditionStatus
            or type(context.current_applicability_and_authority_status) is not ConditionStatus
            or type(context.required_protected_operation_ids) is not tuple
            or any(type(item) is not OperationId
                   for item in context.required_protected_operation_ids)
            or len(set(context.required_protected_operation_ids))
            != len(context.required_protected_operation_ids)
        ):
            raise ValueError("trusted completion context is malformed")
        completion = _compose_completion_aggregate(
            task=task, completion_rule_set_id=context.completion_rule_set_id,
            policy_epoch_identity=task.last_evaluated_policy_epoch_identity,
            contract_acceptance_status=context.contract_acceptance_status,
            additional_conditions_status=(
                context.additional_trusted_completion_conditions_status
            ),
            required_operation_ids=context.required_protected_operation_ids,
            applicability_status=context.current_applicability_and_authority_status,
        )
        relevant_ids = set(context.required_protected_operation_ids)
        relevant_ids.update(
            item.intent.operation_id for item in current.operations
            if item.intent.effect_class is OperationEffectClass.PROTECTED_OR_AUTHORITATIVE_EFFECT
            and item.state in (OperationState.RESERVED, OperationState.PERFORMING,
                               OperationState.INDETERMINATE)
        )
        evaluation = TaskEvaluationInput(
            task_id=task.task_id, expected_task_revision=task.revision,
            contract_id=task.contract_id,
            contract_raw_sha256=task.contract_raw_sha256,
            authorization_id=task.authorization_id,
            admission_event_id=task.admission_event_id,
            target_registration_id=task.target_registration_id,
            current_policy_epoch_identity=task.last_evaluated_policy_epoch_identity,
            evaluated_candidate_id=task.current_candidate_id,
            blocking_condition_ids=command.blocking_condition_ids,
            awaiting_input_requirement_ids=command.awaiting_input_requirement_ids,
            next_integration_operation_id=command.next_integration_operation_id,
            completion=completion,
            operation_snapshot=current.task_operation_snapshot(),
            expected_membership_binding_id=current.task_operation_membership.membership_binding_id,
            expected_operation_revisions=tuple(
                OperationRevisionBinding(item.intent.operation_id, item.revision)
                for item in current.operations if item.intent.operation_id in relevant_ids
            ),
        )
        result = evaluate_task(current.task, evaluation)
        if result.proposal is None:
            raise ValueError(result.failure.code.value)
        proposal = result.proposal
        conditions = [TaskRevisionEquals(task_id, current.task.revision)]
        if proposal.expected_membership_binding_id is not None:
            conditions.append(TaskOperationMembershipEquals(
                task_id, proposal.expected_membership_binding_id
            ))
        conditions.extend(OperationRevisionEquals(item.operation_id, item.revision)
                          for item in proposal.expected_operation_revisions)
        transaction = CanonicalTransaction(
            current.canonical_state_occurrence_binding, tuple(conditions),
            (ReplaceTask(current.task.revision, proposal.proposed),),
        )
        request = object.__new__(ControlStateCommitRequest)
        object.__setattr__(request, "command_kind", TrustedControlCommandKind.EVALUATE_TASK)
        object.__setattr__(request, "transaction", transaction)
        object.__setattr__(request, "_key", self._key)
        return request

    def set_cancellation(
        self, task_id: TaskId, status: CancellationStatus,
        request_id: CancellationRequestId | None,
    ) -> ControlStateCommitRequest:
        current = self._backend.read_task_working_set(task_id)
        if current is None:
            raise ValueError("task is not canonical")
        bindings = tuple(
            OperationRevisionBinding(item.intent.operation_id, item.revision)
            for item in current.operations
            if item.state in (
                OperationState.RESERVED, OperationState.PERFORMING,
                OperationState.INDETERMINATE,
            )
        )
        result = set_cancellation(
            current.task, status, request_id,
            expected_task_revision=current.task.revision,
            snapshot=current.task_operation_snapshot(),
            expected_membership_binding_id=current.task_operation_membership.membership_binding_id,
            expected_operation_revisions=bindings,
        )
        if result.proposal is None:
            raise ValueError(result.failure.code.value)
        proposal = result.proposal
        conditions = [TaskRevisionEquals(task_id, current.task.revision)]
        if proposal.expected_membership_binding_id is not None:
            conditions.append(TaskOperationMembershipEquals(
                task_id, proposal.expected_membership_binding_id
            ))
        conditions.extend(OperationRevisionEquals(item.operation_id, item.revision)
                          for item in proposal.expected_operation_revisions)
        transaction = CanonicalTransaction(
            current.canonical_state_occurrence_binding, tuple(conditions),
            (ReplaceTask(current.task.revision, proposal.proposed),),
        )
        request = object.__new__(ControlStateCommitRequest)
        object.__setattr__(request, "command_kind", TrustedControlCommandKind.SET_CANCELLATION)
        object.__setattr__(request, "transaction", transaction)
        object.__setattr__(request, "_key", self._key)
        return request

    def admit_semantic_evidence(
        self, request: SemanticEvidenceAdmissionRequest,
    ) -> ControlStateCommitRequest:
        result = admit_semantic_review(request)
        if (result.decision is not EvidenceAdmissionDecision.ADMIT
                or result.proposed_evidence_record is None
                or result.expected_evidence_history_membership_binding is None):
            raise ValueError(result.reason_code.value)
        subject = request.effective_subject
        snapshot = self._backend.read_review_eligibility_snapshot(subject.subject_id)
        if snapshot is None or snapshot.evidence_history_membership.membership_binding_id != result.expected_evidence_history_membership_binding:
            raise ValueError("canonical evidence history changed")
        transaction = CanonicalTransaction(
            snapshot.canonical_state_occurrence_binding,
            (EvidenceHistoryMembershipEquals(
                subject.subject_id, result.expected_evidence_history_membership_binding
            ),),
            (CreateEvidenceAndAdvanceHistory(
                subject, result.expected_evidence_history_membership_binding,
                result.proposed_evidence_record,
            ),),
        )
        response = object.__new__(ControlStateCommitRequest)
        object.__setattr__(response, "command_kind", TrustedControlCommandKind.ADMIT_SEMANTIC_EVIDENCE)
        object.__setattr__(response, "transaction", transaction)
        object.__setattr__(response, "_key", self._key)
        return response

def _new_controller(key: object, backend: InMemoryCanonicalStateBackend,
                    completion_contexts: dict[ImmutableConfigId, TrustedCompletionEvaluationContext],
                    object_store: FixtureGitObjectStore | None,
                    ) -> DeterministicTrustedController:
    value = object.__new__(DeterministicTrustedController)
    value._key, value._backend, value._completion_contexts, value._object_store = key, backend, completion_contexts, object_store
    return value


class TrustedControllerRuntime:
    """T-side deterministic logic over a read projection and narrow F reads."""

    __slots__ = (
        "controller", "read_state", "f_read_verify", "dependency_profiles",
        "dependency_transports", "contract_contexts", "authorization_contexts",
        "evidence_contexts", "semantic_contexts", "control_state_client",
        "binding", "audit", "publication_gate_client", "merge_gate_client",
    )

    def __init__(
        self, controller: DeterministicTrustedController,
        read_state: CanonicalStateReadClient, f_read_verify: FixtureReadVerifyClient,
        dependency_profiles: dict, dependency_transports: dict,
        contract_contexts: dict, authorization_contexts: dict,
        evidence_contexts: dict, semantic_contexts: dict,
        control_state_client: ControlStateGateClient | None = None,
        binding: GateRuntimeBinding | None = None,
        audit: GateAuditContract | None = None,
    ) -> None:
        if (type(controller) is not DeterministicTrustedController
                or type(read_state) is not CanonicalStateReadClient
                or not isinstance(f_read_verify, FixtureReadVerifyClient)):
            raise TypeError("T runtime requires controller and narrow read projections")
        self.controller, self.read_state, self.f_read_verify = controller, read_state, f_read_verify
        self.dependency_profiles, self.dependency_transports = dependency_profiles, dependency_transports
        self.contract_contexts, self.authorization_contexts = contract_contexts, authorization_contexts
        self.evidence_contexts, self.semantic_contexts = evidence_contexts, semantic_contexts
        if control_state_client is not None and not isinstance(control_state_client, ControlStateGateClient):
            raise TypeError("T runtime requires the narrow authenticated C client")
        self.control_state_client = control_state_client
        if binding is not None and type(binding) is not GateRuntimeBinding:
            raise TypeError("T runtime requires exact immutable root/runtime identity")
        if audit is not None and not isinstance(audit, GateAuditContract):
            raise TypeError("T runtime requires append-only audit interface")
        self.binding, self.audit = binding, audit
        self.publication_gate_client = None
        self.merge_gate_client = None

    def _prepared_start_record(
        self, operation: OperationRecord, subject: ProtectedEffectSubject,
        fence: ActionTargetFence, dependencies: ControlStateAuthoritativeDependencySet,
        materialization: CandidateMaterialization | AdmittedCandidateMaterialization,
        target_registration: AdmittedTargetRegistration,
        base_ref: CanonicalBranchRef | None, provenance_operation_id: OperationId | None,
        authorized_scope: MutationScope, root_forbidden_scope: MutationScope,
    ) -> PreparedProtectedStart:
        service = (self.binding.merge_principal
                   if subject is ProtectedEffectSubject.FAST_FORWARD_MERGE
                   else self.binding.publication_principal)
        preimage = PreparedProtectedStartPreimage(
            "autodev.prepared-protected-start/v1", operation.intent.operation_id,
            subject, fence, self.binding.root_context_id,
            self.binding.runtime_generation, self.binding.runtime_binding_id,
            service, dependencies, materialization, target_registration,
            base_ref, provenance_operation_id, authorized_scope, root_forbidden_scope,
        )
        prepared = object.__new__(PreparedProtectedStart)
        prepared.prepared_start_id = PreparedProtectedStartId(RawSha256(
            hashlib.sha256(canonical_json_bytes(preimage)).hexdigest()
        ))
        prepared.operation, prepared.subject, prepared.fence = operation, subject, fence
        prepared.preimage, prepared._platform = preimage, self.f_read_verify
        prepared.prepared_target_fence_binding = None
        prepared._sealed = False
        return prepared

    def _candidate_action_is_valid(
        self, operation: OperationRecord, subject: ProtectedEffectSubject,
        fence: ActionTargetFence,
        authorized_scope: MutationScope, root_forbidden_scope: MutationScope,
        materialization: CandidateMaterialization | AdmittedCandidateMaterialization,
        target: AdmittedTargetRegistration, base_ref: CanonicalBranchRef | None,
        provenance_operation_id: OperationId | None,
    ) -> bool:
        intent = operation.intent
        resolved = self.read_state.read_resolved_target_registration(
            intent.target_registration_id,
        )
        if (type(operation) is not OperationRecord
                or operation.state is not OperationState.RESERVED
                or type(subject) is not ProtectedEffectSubject
                or type(fence) is not ActionTargetFence
                or type(materialization) not in (
                    CandidateMaterialization, AdmittedCandidateMaterialization,
                )
                or type(target) is not AdmittedTargetRegistration
                or resolved is None or resolved.registration != target
                or materialization.repository_id != fence.repository_id
                or target.repository_id != fence.repository_id
                or materialization.task_id != intent.task_id
                or materialization.candidate_id != intent.candidate_id
                or materialization.contract_id != intent.contract_id
                or materialization.contract_raw_sha256 != intent.contract_raw_sha256
                or materialization.authorization_id != intent.authorization_id
                or materialization.target_registration_id != intent.target_registration_id
                or materialization.policy_epoch_identity != intent.policy_epoch_identity
                or not self.f_read_verify.verify_materialization(materialization)
                or not inventory_is_authorized(
                    materialization.inventory, authorized_scope, root_forbidden_scope,
                )
                or not inventory_is_authorized(
                    materialization.inventory, target.ordinary_allowed_scope,
                    target.ordinary_forbidden_scope,
                )):
            return False
        if subject is ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION:
            return (
                target.target_publication is not None
                and target.target_publication.service_identity == self.binding.publication_principal
                and fence.ref == materialization.candidate_branch
                and fence.expected_sha is None and fence.base_ref is None
                and materialization.candidate_branch not in target.protected_refs
                and (target.merge is None or materialization.candidate_branch
                     not in target.merge.allowed_integration_refs)
                and (not isinstance(intent.integration_binding, IntegrationBound)
                     or GitRef(materialization.candidate_branch.value)
                     != intent.integration_binding.integration_ref)
            )
        if subject is ProtectedEffectSubject.PULL_REQUEST_CREATION:
            marker = (None if provenance_operation_id is None else
                      self.f_read_verify.read_marker(
                          provenance_operation_id,
                          ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION.value,
                      ))
            published = None if marker is None else marker.preimage.effect_subject
            return (
                target.target_publication is not None
                and target.target_publication.service_identity == self.binding.publication_principal
                and target.merge is not None and type(base_ref) is CanonicalBranchRef
                and base_ref in target.merge.allowed_integration_refs
                and fence.ref == materialization.candidate_branch
                and fence.expected_sha == materialization.commit
                and fence.base_ref == base_ref
                and type(published) is PublishedCandidateRefEffectSubject
                and published == PublishedCandidateRefEffectSubject(
                    fence.repository_id, materialization.candidate_branch,
                    GitRef(materialization.candidate_branch.value), materialization.commit,
                )
                and self.f_read_verify.verify_marker_postcondition(marker)
            )
        marker = (None if provenance_operation_id is None else
                  self.f_read_verify.read_marker(
                      provenance_operation_id,
                      ProtectedEffectSubject.PULL_REQUEST_CREATION.value,
                  ))
        created = None if marker is None else marker.preimage.effect_subject
        pr = (None if type(created) is not CreatedCandidatePrEffectSubject else
              self.f_read_verify.read_pull_request(created.pull_request_number))
        return (
            subject is ProtectedEffectSubject.FAST_FORWARD_MERGE
            and target.merge is not None
            and target.merge.service_identity == self.binding.merge_principal
            and fence.ref in target.merge.allowed_integration_refs
            and fence.expected_sha is not None
            and materialization.base == fence.expected_sha
            and type(created) is CreatedCandidatePrEffectSubject
            and created.repository_id == fence.repository_id
            and created.head_ref == GitRef(materialization.candidate_branch.value)
            and created.head_sha == materialization.commit
            and created.base_ref == GitRef(fence.ref.value)
            and created.base_sha == fence.expected_sha
            and pr is not None and not pr.merged
            and self.f_read_verify.verify_marker_postcondition(marker)
        )

    def _protected_start_semantic_denial(
        self, operation: OperationRecord, subject: ProtectedEffectSubject,
        expected_occurrence, dependencies: ControlStateAuthoritativeDependencySet,
    ) -> ProtectedStartSemanticDenialCode | None:
        working = self.read_state.read_task_working_set(operation.intent.task_id)
        if (working is None
                or working.canonical_state_occurrence_binding != expected_occurrence
                or self.read_state.occurrence != expected_occurrence):
            return ProtectedStartSemanticDenialCode.REQUIRED_EVIDENCE_CONTEXT_INDETERMINATE
        canonical = next((item for item in working.operations
                          if item.intent.operation_id == operation.intent.operation_id), None)
        if canonical != operation:
            return ProtectedStartSemanticDenialCode.REQUIRED_EVIDENCE_CONTEXT_INDETERMINATE
        forward = (
            subject is ProtectedEffectSubject.FAST_FORWARD_MERGE
            and type(operation.intent.integration_binding) is IntegrationBound
            and working.task.state is TaskState.INTEGRATION_READY
            and working.task.next_integration_operation_id == operation.intent.operation_id
        )
        if not operation.intent.required_evidence_ids and not forward:
            return None
        semantic_ids: tuple[EvidenceId, ...] = ()
        required = operation.intent.required_evidence_ids
        if required:
            snapshot = self.read_state.read_semantic_consumption_snapshot(
                operation.intent.task_id, expected_occurrence, (), required,
            )
            if (snapshot is None or snapshot.canonical_state_occurrence_binding != expected_occurrence
                    or self.read_state.occurrence != expected_occurrence
                    or tuple(item.evidence_id for item in snapshot.requested_evidence) != required):
                return ProtectedStartSemanticDenialCode.REQUIRED_EVIDENCE_CONTEXT_INDETERMINATE
            if any(item.record is None for item in snapshot.requested_evidence):
                return ProtectedStartSemanticDenialCode.REQUIRED_EVIDENCE_NOT_CURRENT
            semantic_ids = tuple(item.evidence_id for item in snapshot.requested_evidence
                                 if item.record.evidence_class is EvidenceClass.SEMANTIC_REVIEW)
            if not semantic_ids and not forward:
                return None
        semantic = self._resolve_semantic_consumption(
            operation.intent.task_id, semantic_ids, expected_occurrence,
        )
        if (semantic is None or semantic.occurrence != expected_occurrence
                or self.read_state.occurrence != expected_occurrence):
            return ProtectedStartSemanticDenialCode.REQUIRED_EVIDENCE_CONTEXT_INDETERMINATE
        currentness = {item.evidence_id: item for item in semantic.evidence_currentness}
        for evidence_id in semantic_ids:
            result = currentness.get(evidence_id)
            if result is None:
                return ProtectedStartSemanticDenialCode.REQUIRED_EVIDENCE_CONTEXT_INDETERMINATE
            if result.status in (SemanticEvidenceCurrentnessStatus.STALE,
                                 SemanticEvidenceCurrentnessStatus.NOT_FOUND):
                return ProtectedStartSemanticDenialCode.REQUIRED_EVIDENCE_NOT_CURRENT
            if result.status is SemanticEvidenceCurrentnessStatus.INDETERMINATE:
                return ProtectedStartSemanticDenialCode.REQUIRED_EVIDENCE_CONTEXT_INDETERMINATE
        if forward:
            if semantic.contract_status is ConditionStatus.UNSATISFIED:
                return ProtectedStartSemanticDenialCode.REQUIRED_EVIDENCE_NOT_VALID_FOR_OPERATION
            if semantic.contract_status is not ConditionStatus.SATISFIED:
                return ProtectedStartSemanticDenialCode.REQUIRED_EVIDENCE_CONTEXT_INDETERMINATE
            if any(
                currentness[item].status is SemanticEvidenceCurrentnessStatus.CURRENT
                and not any(item in result.progression_support_evidence_ids
                            for result in semantic.obligation_results)
                for item in semantic_ids if item in currentness
            ):
                return ProtectedStartSemanticDenialCode.REQUIRED_EVIDENCE_NOT_VALID_FOR_OPERATION
        if any(item not in dependencies.dependencies
               for item in semantic.authoritative_dependencies):
            return ProtectedStartSemanticDenialCode.REQUIRED_EVIDENCE_CONTEXT_INDETERMINATE
        if (not self._dependencies_fresh_set(dependencies)
                or self.read_state.occurrence != expected_occurrence):
            return ProtectedStartSemanticDenialCode.REQUIRED_EVIDENCE_CONTEXT_INDETERMINATE
        return None

    def start_protected_operation(
        self, operation: OperationRecord, subject: ProtectedEffectSubject,
        fence: ActionTargetFence, dependencies: ControlStateAuthoritativeDependencySet,
        authorized_scope: MutationScope, root_forbidden_scope: MutationScope, *,
        materialization: CandidateMaterialization | AdmittedCandidateMaterialization,
        target_registration: AdmittedTargetRegistration,
        base_ref: CanonicalBranchRef | None = None,
        provenance_operation_id: OperationId | None = None,
    ) -> GateResult:
        """Candidate T orchestration over authenticated P/M/C clients only."""
        if (self.binding is None or self.control_state_client is None
                or type(dependencies) is not ControlStateAuthoritativeDependencySet
                or type(authorized_scope) is not MutationScope
                or type(root_forbidden_scope) is not MutationScope):
            return GateResult(GateResultCode.REJECTED)
        role_client = (self.merge_gate_client
                       if subject is ProtectedEffectSubject.FAST_FORWARD_MERGE
                       else self.publication_gate_client)
        if role_client is None or not self._candidate_action_is_valid(
            operation, subject, fence, authorized_scope, root_forbidden_scope,
            materialization, target_registration, base_ref, provenance_operation_id,
        ):
            return GateResult(GateResultCode.REJECTED)
        working = self.read_state.read_task_working_set(operation.intent.task_id)
        canonical_operation = None if working is None else next((
            item for item in working.operations
            if item.intent.operation_id == operation.intent.operation_id
        ), None)
        if canonical_operation != operation:
            return GateResult(GateResultCode.REJECTED)
        prepared = self._prepared_start_record(
            operation, subject, fence, dependencies, materialization,
            target_registration, base_ref, provenance_operation_id,
            authorized_scope, root_forbidden_scope,
        )
        try:
            decision = self.controller.start_operation(
                operation.intent.task_id, operation.intent.operation_id,
                prepared.prepared_start_id,
            )
        except _DeterministicStartDenied as error:
            return GateResult(GateResultCode.REJECTED, failure_code=error.failure_code)
        except (TypeError, ValueError):
            return GateResult(GateResultCode.REJECTED)
        binding = role_client.prepare_start(prepared)
        if (type(binding) is not PreparedTargetFenceBinding
                or binding.prepared_start_id != prepared.prepared_start_id):
            return GateResult(GateResultCode.REJECTED)
        prepared.prepared_target_fence_binding = binding
        prepared._sealed = True
        semantic_denial = self._protected_start_semantic_denial(
            operation, subject, decision.transaction.expected_state_occurrence,
            dependencies,
        )
        if semantic_denial is not None:
            role_client.abort_start(prepared.prepared_start_id)
            return GateResult(GateResultCode.REJECTED,
                              semantic_denial_code=semantic_denial)
        if (self.f_read_verify.read_ref(fence.repository_id, fence.ref) != fence.expected_sha
                or (fence.base_ref is not None and self.f_read_verify.read_ref(
                    fence.repository_id, fence.base_ref) != fence.base_expected_sha)):
            if role_client.abort_start(prepared.prepared_start_id):
                try:
                    conflict = self.controller._transition_unstarted_conflict(
                        operation.intent.task_id, operation.intent.operation_id,
                    )
                except (TypeError, ValueError):
                    return GateResult(GateResultCode.INDETERMINATE)
                object.__setattr__(conflict, "required_authoritative_dependencies",
                                   dependencies.dependencies)
                result = self.control_state_client.commit_authenticated_request(
                    conflict, dependencies,
                )
                return GateResult(GateResultCode.ACTION_PRECONDITION_CONFLICT,
                                  result.canonical_result,
                                  failure_code=G4FailureCode.ACTION_PRECONDITION_CONFLICT)
            return GateResult(GateResultCode.INDETERMINATE)
        held = role_client.seal_start(prepared.prepared_start_id)
        if (type(held) is not StartHeldTargetFenceBinding
                or held.prepared_start_id != prepared.prepared_start_id):
            return GateResult(GateResultCode.INDETERMINATE)
        try:
            finalized_request = self.controller.start_operation(
                operation.intent.task_id, operation.intent.operation_id, held,
            )
        except (_DeterministicStartDenied, TypeError, ValueError):
            return GateResult(GateResultCode.INDETERMINATE)
        decision_transaction = decision.transaction
        finalized = object.__new__(ControlStateCommitRequest)
        object.__setattr__(finalized, "command_kind", finalized_request.command_kind)
        object.__setattr__(finalized, "_key", finalized_request._key)
        object.__setattr__(finalized, "transaction", CanonicalTransaction(
            decision_transaction.expected_state_occurrence,
            decision_transaction.conditions,
            finalized_request.transaction.mutations,
        ))
        object.__setattr__(finalized, "required_authoritative_dependencies",
                           dependencies.dependencies)
        committed = self.control_state_client.commit_authenticated_request(
            finalized, dependencies,
        )
        if committed.code is not GateResultCode.COMMITTED:
            return GateResult(GateResultCode.INDETERMINATE, committed.canonical_result)
        operation_after = next((
            mutation.operation for mutation in finalized.transaction.mutations
            if type(mutation) is ReplaceOperation
            and mutation.operation.intent.operation_id == operation.intent.operation_id
        ), None)
        if (type(operation_after) is not OperationRecord
                or operation_after.state is not OperationState.PERFORMING
                or operation_after.start_binding_id != operation_start_binding_id_v2(held)):
            return GateResult(GateResultCode.INDETERMINATE, committed.canonical_result)
        audit_dependencies = tuple(GateAuditAuthoritativeDependency(
            item.repository_id, item.observation_profile_id,
            item.transport_config_id, item.expected_binding_id,
        ) for item in dependencies.dependencies)
        start_event = GateAuditEventPreimage(
            "autodev.gate-audit-event/v1", "PROTECTED_START", subject.value,
            GateAuditOutcome.APPLIED, self.binding.root_context_id,
            self.binding.runtime_generation.value, self.binding.runtime_binding_id,
            (self.binding.merge_principal
             if subject is ProtectedEffectSubject.FAST_FORWARD_MERGE
             else self.binding.publication_principal),
            audit_dependencies,
            RawSha256(hashlib.sha256(canonical_json_bytes(dependencies)).hexdigest()),
            decision.transaction.expected_state_occurrence,
            operation_after.intent.operation_id, operation_after.start_binding_id,
            None, prepared.prepared_start_id.raw_sha256, "", "T protected start",
            operation_after.intent.task_id, operation_after.intent.candidate_id,
            operation_after.intent.authorization_id,
            operation_after.intent.target_registration_id,
            operation_after.intent.policy_epoch_identity,
            materialization.materialization_id,
            materialization.inventory.inventory_id,
        )
        if self.audit is not None and self.audit.append_event(
                build_gate_audit_event(start_event)) not in (
                    AuditAppendStatus.APPENDED, AuditAppendStatus.ALREADY_PRESENT):
            # The canonical start is durable, but the held target remains
            # fenced.  No ordinary role releases it; reconciliation is the
            # only subsequent path and may conservatively remain indeterminate.
            self.reconcile_recovered_effect(
                operation_after.intent.task_id, operation_after.intent.operation_id,
                subject,
            )
            return GateResult(GateResultCode.AUDIT_FAILURE_AFTER_COMMIT,
                              committed.canonical_result)
        executed = role_client.execute_started(
            prepared.prepared_start_id, operation_after.start_binding_id,
        )
        if executed.code in (GateResultCode.REJECTED, GateResultCode.LEASE_CONSUMED):
            return GateResult(GateResultCode.INDETERMINATE, committed.canonical_result)
        reconciled = self.reconcile_recovered_effect(
            operation_after.intent.task_id,
            operation_after.intent.operation_id, subject,
        )
        if reconciled.code is GateResultCode.INDETERMINATE:
            return GateResult(GateResultCode.INDETERMINATE, committed.canonical_result)
        return reconciled

    def reconcile_started_effect_absent(self, observation: GateResult) -> GateResult:
        """Turn a P/M absence observation into a T-decided, C-committed transition."""
        continuation = getattr(observation, "continuation", None)
        if (observation.code is not GateResultCode.PRECONDITION_CONFLICT
                or type(continuation) is not LiveProtectedEffectContinuation
                or self.control_state_client is None):
            return GateResult(GateResultCode.INDETERMINATE)
        working = self.read_state.read_task_working_set(continuation.intent.task_id)
        operation = None if working is None else next((
            item for item in working.operations
            if item.intent.operation_id == continuation.operation_id
        ), None)
        companion = None if operation is None else operation.canonical_protected_start_binding
        start = None if type(companion) is not CanonicalProtectedStartBinding else companion.start_held_target_fence_binding
        durable = self.f_read_verify.read_prepared_effect_record(
            continuation.operation_id, continuation.subject.value,
        )
        if (operation is None or operation.intent != continuation.intent
                or operation.state is not OperationState.PERFORMING
                or operation.start_binding_id != continuation.start_binding_id
                or type(companion) is not CanonicalProtectedStartBinding
                or companion.operation_start_binding_id != continuation.start_binding_id
                or type(start) is not StartHeldTargetFenceBinding
                or start.prepared_start_id != continuation.prepared_start_id
                or start.action_class != continuation.subject.value
                or start.operation_id != continuation.operation_id
                or type(durable) is not PreparedProtectedStart
                or durable.prepared_start_id != continuation.prepared_start_id
                or durable.preimage.dependencies != continuation.dependencies
                or self.f_read_verify.read_prepared_effect_state(
                    continuation.operation_id, continuation.subject.value
                ) != "RELEASED"
                or self.f_read_verify.read_marker(
                    continuation.operation_id, continuation.subject.value
                ) is not None
                or not self._dependencies_fresh_set(continuation.dependencies)):
            return GateResult(GateResultCode.INDETERMINATE)
        try:
            request = self.controller._transition_started_failed(
                continuation.intent.task_id, continuation.operation_id,
            )
        except (TypeError, ValueError):
            return GateResult(GateResultCode.INDETERMINATE)
        object.__setattr__(request, "required_authoritative_dependencies",
                           continuation.dependencies.dependencies)
        committed = self.control_state_client.commit_authenticated_request(
            request, continuation.dependencies,
        )
        if committed.code is not GateResultCode.COMMITTED:
            return GateResult(GateResultCode.INDETERMINATE, committed.canonical_result)
        return GateResult(GateResultCode.PRECONDITION_CONFLICT, committed.canonical_result)

    def reconcile_recovered_effect(
        self, task_id: TaskId, operation_id: OperationId,
        subject: ProtectedEffectSubject,
    ) -> GateResult:
        """T-only consequence decision from exact canonical and read-only F facts."""
        if (self.binding is None or self.audit is None or self.control_state_client is None
                or type(task_id) is not TaskId or type(operation_id) is not OperationId
                or type(subject) is not ProtectedEffectSubject):
            return GateResult(GateResultCode.INDETERMINATE)
        working = self.read_state.read_task_working_set(task_id)
        operation = None if working is None else next((
            item for item in working.operations if item.intent.operation_id == operation_id
        ), None)
        durable = self.f_read_verify.read_prepared_effect_record(operation_id, subject.value)
        if (type(operation) is not OperationRecord
                or operation.state not in (OperationState.PERFORMING, OperationState.INDETERMINATE)
                or type(operation.start_binding_id) is not OperationStartBindingId
                or type(durable) is not PreparedProtectedStart
                or type(durable.preimage) is not PreparedProtectedStartPreimage):
            return GateResult(GateResultCode.INDETERMINATE)
        preimage = durable.preimage
        prepared_id = PreparedProtectedStartId(RawSha256(
            hashlib.sha256(canonical_json_bytes(preimage)).hexdigest()
        ))
        companion = operation.canonical_protected_start_binding
        held = None if type(companion) is not CanonicalProtectedStartBinding else companion.start_held_target_fence_binding
        role_name = ("MERGE_AUTHORITY" if subject is ProtectedEffectSubject.FAST_FORWARD_MERGE
                     else "PUBLICATION_AUTHORITY")
        expected_authority = RawSha256(hashlib.sha256(canonical_json_bytes((
            "autodev.fixture-role-authority-binding/v1",
            self.f_read_verify.substrate_identity, role_name,
            preimage.service_identity, self.binding.root_context_id,
            self.binding.runtime_generation.value, preimage.runtime_binding_id,
        ))).hexdigest())
        if (durable.prepared_start_id != prepared_id
                or durable.operation.intent != operation.intent
                or durable.subject is not subject or preimage.operation_id != operation_id
                or preimage.action is not subject or preimage.target_fence != durable.fence
                or preimage.root_context_id != self.binding.root_context_id
                or preimage.runtime_generation != self.binding.runtime_generation
                or preimage.service_identity != (
                    self.binding.merge_principal if subject is ProtectedEffectSubject.FAST_FORWARD_MERGE
                    else self.binding.publication_principal
                )
                or type(held) is not StartHeldTargetFenceBinding
                or companion.operation_start_binding_id != operation.start_binding_id
                or operation_start_binding_id_v2(held) != operation.start_binding_id
                or held.operation_id != operation_id or held.action_class != subject.value
                or held.prepared_start_id != prepared_id
                or held.fixture_substrate_identity != self.f_read_verify.substrate_identity
                or held.authority_binding_identity != expected_authority
                or not self.f_read_verify.resolve_historical_start_binding(held)
                or type(preimage.dependencies) is not ControlStateAuthoritativeDependencySet
                or preimage.dependencies != durable.preimage.dependencies
                or not self._dependencies_fresh_set(preimage.dependencies)):
            return GateResult(GateResultCode.INDETERMINATE)
        marker = self.f_read_verify.read_marker(operation_id, subject.value)
        state = self.f_read_verify.read_prepared_effect_state(operation_id, subject.value)
        if marker is not None:
            if (state != "CONSUMED" or marker.preimage.operation_id != operation_id
                    or marker.preimage.gate_action != subject.value
                    or marker.preimage.prepared_start_id != prepared_id):
                return GateResult(GateResultCode.INDETERMINATE)
            finding_value = (
                ReconciliationFinding.INTENDED_EFFECT_PROVEN
                if self.f_read_verify.verify_marker_postcondition(marker)
                else ReconciliationFinding.UNRESOLVED
            )
        elif state == "RELEASED":
            finding_value = ReconciliationFinding.INTENDED_EFFECT_PROVEN_ABSENT
        else:
            return GateResult(GateResultCode.INDETERMINATE)
        finding = object.__new__(TrustedReconciliationFinding)
        object.__setattr__(finding, "finding", finding_value)
        try:
            request = self.controller._decide_reconciliation(task_id, operation_id, finding)
        except (TypeError, ValueError):
            return GateResult(GateResultCode.INDETERMINATE)
        object.__setattr__(request, "required_authoritative_dependencies",
                           preimage.dependencies.dependencies)
        committed = self.control_state_client.commit_authenticated_request(
            request, preimage.dependencies,
        )
        if committed.code is not GateResultCode.COMMITTED:
            return GateResult(GateResultCode.INDETERMINATE, committed.canonical_result)
        outcome = {
            ReconciliationFinding.INTENDED_EFFECT_PROVEN: GateAuditOutcome.RECONCILED_SUCCEEDED,
            ReconciliationFinding.INTENDED_EFFECT_PROVEN_ABSENT: GateAuditOutcome.RECONCILED_FAILED,
            ReconciliationFinding.UNRESOLVED: GateAuditOutcome.INDETERMINATE,
        }[finding_value]
        dependencies = tuple(GateAuditAuthoritativeDependency(
            item.repository_id, item.observation_profile_id,
            item.transport_config_id, item.expected_binding_id,
        ) for item in preimage.dependencies.dependencies)
        event = GateAuditEventPreimage(
            "autodev.gate-audit-event/v1", "RECOVERY", subject.value, outcome,
            self.binding.root_context_id, self.binding.runtime_generation.value,
            self.binding.runtime_binding_id, self.binding.control_state_principal,
            dependencies, RawSha256(hashlib.sha256(canonical_json_bytes(
                preimage.dependencies,
            )).hexdigest()), self.read_state.occurrence,
            operation_id, operation.start_binding_id,
            None if marker is None else marker.marker_id,
            prepared_id.raw_sha256, "", "T reconciliation", task_id,
            operation.intent.candidate_id, operation.intent.authorization_id,
            operation.intent.target_registration_id,
            operation.intent.policy_epoch_identity,
            durable.preimage.materialization.materialization_id,
            durable.preimage.materialization.inventory.inventory_id,
        )
        if self.audit.append_event(build_gate_audit_event(event)) not in (
                AuditAppendStatus.APPENDED, AuditAppendStatus.ALREADY_PRESENT):
            return GateResult(GateResultCode.AUDIT_FAILURE_AFTER_COMMIT,
                              committed.canonical_result)
        code = {
            ReconciliationFinding.INTENDED_EFFECT_PROVEN: GateResultCode.EFFECT_SUCCEEDED,
            ReconciliationFinding.INTENDED_EFFECT_PROVEN_ABSENT: GateResultCode.EFFECT_FAILED,
            ReconciliationFinding.UNRESOLVED: GateResultCode.INDETERMINATE,
        }[finding_value]
        return GateResult(code, committed.canonical_result)

    def admit_contract(self, raw: bytes) -> ControlStateCommitRequest:
        context = self.contract_contexts.get(hashlib.sha256(raw).hexdigest())
        return self.controller.admit_contract(raw, context)

    def admit_authorization(
        self, proposal: CandidateAuthorizationProposal,
    ) -> ControlStateCommitRequest:
        context = self.authorization_contexts.get(
            hashlib.sha256(canonical_json_bytes(proposal)).hexdigest()
        )
        if context is None:
            raise ValueError("exact root-managed authorization context is unavailable")
        target, contract_context, policy, root, approval, issuer = context
        return self.controller.admit_authorization(
            proposal, target, contract_context, policy, root,
            approval=approval, issuer=issuer,
        )

    def reserve_operation(
        self, task_id: TaskId, command: OperationReservationCommand,
    ) -> ControlStateCommitRequest:
        if type(command) is OperationIntent:
            raise TypeError("callers cannot submit trusted OperationIntent")
        return self.controller.reserve_operation(
            task_id, command, self._derive_operation_authoritative_binding(task_id, command),
        )

    def _derive_operation_authoritative_binding(
        self, task_id: TaskId, command: OperationReservationCommand,
    ) -> AuthoritativeStateBindingId:
        if type(task_id) is not TaskId or type(command) is not OperationReservationCommand:
            raise TypeError("exact operation request inputs required")
        working = self.read_state.read_task_working_set(task_id)
        if working is None:
            raise ValueError("task is not canonical")
        resolved = self.read_state.read_resolved_target_registration(
            working.task.target_registration_id
        )
        if resolved is None:
            raise ValueError("target registration is not root-resolved")
        fixture_bindings = tuple(sorted((
            (profile_id.value, transport_id.value, binding.value)
            for profile_id in self.dependency_profiles
            for transport_id in self.dependency_transports
            for binding in (self.f_read_verify.authoritative_binding(
                resolved.registration.repository_id, profile_id, transport_id,
            ),)
            if binding is not None
        )))
        digest = hashlib.sha256(canonical_json_bytes((
            "autodev.g7-operation-authoritative-binding/v1",
            self.read_state.occurrence, task_id, command.action_id,
            command.subject_id, fixture_bindings,
        ))).hexdigest()
        return AuthoritativeStateBindingId(digest)

    def _dependencies_fresh_set(self, dependencies: ControlStateAuthoritativeDependencySet) -> bool:
        for item in dependencies.dependencies:
            profile = self.dependency_profiles.get(item.observation_profile_id)
            transport = self.dependency_transports.get(item.transport_config_id)
            snapshot = self.f_read_verify.authoritative_snapshot(*item.locator)
            if profile is None or transport is None or snapshot is None:
                return False
            if (snapshot.repository_id, snapshot.observation_profile_id,
                    snapshot.transport_config_id) != item.locator:
                return False
            if item.repository_id not in transport.permitted_repository_ids:
                return False
            if self.f_read_verify.authoritative_binding(*item.locator) != item.expected_binding_id:
                return False
        return True

    def _resolve_semantic_consumption(
        self, task_id: TaskId, requested_evidence_ids: tuple[EvidenceId, ...],
        expected_occurrence=None,
    ):
        environment = self.semantic_contexts.get(task_id)
        if environment is None:
            return None
        applicability_context, byte_reader, context_source, base_dependency = environment
        inputs = self.read_state.read_current_semantic_review_inputs(task_id)
        if inputs is None or (expected_occurrence is not None
                and inputs.canonical_state_occurrence_binding != expected_occurrence):
            return None
        base_observation = applicability_context.base_observation
        if (base_observation is None
                or base_observation.authoritative_state_binding_id != base_dependency.expected_binding_id
                or base_dependency.repository_id != inputs.resolved_target.registration.repository_id):
            return None
        resolution = resolve_current_semantic_review(
            inputs, applicability_context=applicability_context,
            byte_reader=byte_reader, semantic_context_source=context_source,
        )
        subject_ids = tuple(
            item.effective_subject.subject_id for item in resolution.obligation_outcomes
            if item.status.value == "RESOLVED" and item.effective_subject is not None
        ) if resolution.status is CurrentSemanticReviewResolutionStatus.RESOLVED else ()
        snapshot = self.read_state.read_semantic_consumption_snapshot(
            task_id, inputs.canonical_state_occurrence_binding, subject_ids,
            requested_evidence_ids,
        )
        if snapshot is None:
            return None
        try:
            result = consume_current_semantic_evidence(
                resolution, snapshot, requested_evidence_ids, current_contract=inputs.contract,
            )
        except (TypeError, ValueError):
            return None
        canonical_dependencies = _canonical_semantic_dependency_union(
            base_dependency, result.authoritative_dependencies,
        )
        if canonical_dependencies is None:
            return None
        return replace(result, authoritative_dependencies=canonical_dependencies)

    def evaluate_task(self, command: TaskEvaluationCommand) -> ControlStateCommitRequest:
        if type(command) is TaskEvaluationInput:
            raise TypeError("callers cannot submit trusted TaskEvaluationInput")
        request = self.controller.evaluate_task(command)
        current = self.read_state.read_task_working_set(command.task_id)
        if (current is None or current.canonical_state_occurrence_binding
                != request.transaction.expected_state_occurrence):
            raise _TaskSemanticDenied(TaskSemanticDenialCode.SEMANTIC_CONTEXT_INDETERMINATE)
        replacement = next((item.task for item in request.transaction.mutations
                            if type(item) is ReplaceTask), None)
        if replacement is None or replacement.state not in (TaskState.INTEGRATION_READY, TaskState.COMPLETED):
            return request
        required_ids: tuple[EvidenceId, ...] = ()
        if replacement.state is TaskState.INTEGRATION_READY:
            selected = next((item for item in current.operations
                if item.intent.operation_id == replacement.next_integration_operation_id), None)
            if (replacement.next_integration_operation_id is None or selected is None
                    or selected.intent.effect_class is not OperationEffectClass.PROTECTED_OR_AUTHORITATIVE_EFFECT
                    or type(selected.intent.integration_binding) is not IntegrationBound):
                raise _TaskSemanticDenied(TaskSemanticDenialCode.NEXT_INTEGRATION_OPERATION_INVALID)
            required_ids = selected.intent.required_evidence_ids
        semantic = self._resolve_semantic_consumption(
            command.task_id, required_ids, current.canonical_state_occurrence_binding,
        )
        if semantic is None:
            raise _TaskSemanticDenied(TaskSemanticDenialCode.SEMANTIC_CONTEXT_INDETERMINATE)
        if semantic.contract_status is ConditionStatus.UNSATISFIED:
            raise _TaskSemanticDenied(TaskSemanticDenialCode.SEMANTIC_CONTRACT_UNSATISFIED)
        if semantic.contract_status is not ConditionStatus.SATISFIED:
            raise _TaskSemanticDenied(TaskSemanticDenialCode.SEMANTIC_CONTEXT_INDETERMINATE)
        if replacement.state is TaskState.INTEGRATION_READY:
            statuses = {item.evidence_id: item for item in semantic.evidence_currentness}
            for evidence_id in required_ids:
                result = statuses.get(evidence_id)
                if result is None:
                    raise _TaskSemanticDenied(TaskSemanticDenialCode.SEMANTIC_CONTEXT_INDETERMINATE)
                if result.status is SemanticEvidenceCurrentnessStatus.NOT_SEMANTIC:
                    continue
                if result.status is not SemanticEvidenceCurrentnessStatus.CURRENT:
                    code = (TaskSemanticDenialCode.REQUIRED_SEMANTIC_EVIDENCE_NOT_CURRENT
                            if result.status in (SemanticEvidenceCurrentnessStatus.STALE,
                                                 SemanticEvidenceCurrentnessStatus.NOT_FOUND)
                            else TaskSemanticDenialCode.SEMANTIC_CONTEXT_INDETERMINATE)
                    raise _TaskSemanticDenied(code)
                if not any(evidence_id in item.progression_support_evidence_ids
                           for item in semantic.obligation_results):
                    raise _TaskSemanticDenied(
                        TaskSemanticDenialCode.REQUIRED_SEMANTIC_EVIDENCE_NOT_PROGRESSION_SUPPORT
                    )
        object.__setattr__(request, "required_authoritative_binding_ids", tuple(
            item.expected_binding_id for item in semantic.authoritative_dependencies
        ))
        object.__setattr__(request, "required_authoritative_dependencies", semantic.authoritative_dependencies)
        return request

    def admit_semantic_evidence(self, command: SemanticEvidenceCommand) -> ControlStateCommitRequest:
        if type(command) is not SemanticEvidenceCommand:
            raise TypeError("exact SemanticEvidenceCommand required")
        template = self.evidence_contexts.get(command.admission_context_id)
        if template is None:
            raise ValueError("trusted semantic evidence context is unavailable")
        snapshot = self.read_state.read_review_eligibility_snapshot(template.effective_subject.subject_id)
        if snapshot is None or snapshot.effective_subject != template.effective_subject:
            raise ValueError("canonical review eligibility context is unavailable")
        operation = template.operation
        if template.operation_binding is not None:
            operation = next((item for item in snapshot.review_attempt_operations
                if item.intent.operation_id == template.operation_binding.operation_id), None)
        request = replace(
            template, raw_response=command.raw_response, operation=operation,
            evidence_history=snapshot.g5_evidence_snapshot(),
            slot_attempt_history=snapshot.g5_attempt_snapshot(),
        )
        return self.controller.admit_semantic_evidence(request)


class TrustedControlCommandBoundary:
    __slots__ = ("_trusted_runtime",)

    def __init__(self, trusted_runtime: TrustedControllerRuntime) -> None:
        if type(trusted_runtime) is not TrustedControllerRuntime:
            raise TypeError("exact trusted controller runtime required")
        self._trusted_runtime = trusted_runtime

    def submit(self, *_: object, **__: object) -> ControlStateCommitRequest:
        raise TypeError("use one explicit closed semantic command method")

    def admit_contract(self, raw: bytes) -> ControlStateCommitRequest:
        if type(raw) is not bytes:
            raise TypeError("exact raw contract bytes required")
        return self._trusted_runtime.admit_contract(raw)

    def admit_authorization(
        self, proposal: CandidateAuthorizationProposal,
    ) -> ControlStateCommitRequest:
        if type(proposal) is not CandidateAuthorizationProposal:
            raise TypeError("exact candidate authorization proposal required")
        return self._trusted_runtime.admit_authorization(proposal)

    def create_task(self, **kwargs) -> ControlStateCommitRequest:
        return self._trusted_runtime.controller.create_task(**kwargs)

    def create_candidate_and_adopt(self, **_: object) -> ControlStateCommitRequest:
        raise TypeError("combined candidate creation/adoption is unavailable")

    def record_candidate_truth(self, **kwargs) -> ControlStateCommitRequest:
        return self._trusted_runtime.controller.record_candidate_truth(**kwargs)

    def adopt_recorded_candidate(self, **kwargs) -> ControlStateCommitRequest:
        return self._trusted_runtime.controller.adopt_recorded_candidate(**kwargs)

    def revise_supporting_evidence(self, *args, **kwargs) -> ControlStateCommitRequest:
        return self._trusted_runtime.controller.revise_supporting_evidence(*args, **kwargs)

    def reserve_operation(
        self, task_id: TaskId, command: OperationReservationCommand,
    ) -> ControlStateCommitRequest:
        return self._trusted_runtime.reserve_operation(task_id, command)

    def start_operation(self, *_: object, **__: object) -> ControlStateCommitRequest:
        raise TypeError("protected start is orchestrated only by the live gate runtime")

    def start_protected_operation(
        self, operation: OperationRecord, subject: ProtectedEffectSubject,
        fence: ActionTargetFence, dependencies: ControlStateAuthoritativeDependencySet,
        authorized_scope: MutationScope, root_forbidden_scope: MutationScope, *,
        materialization: CandidateMaterialization | AdmittedCandidateMaterialization,
        target_registration: AdmittedTargetRegistration,
        base_ref: CanonicalBranchRef | None = None,
        provenance_operation_id: OperationId | None = None,
    ) -> GateResult:
        if type(operation) is not OperationRecord:
            return GateResult(GateResultCode.REJECTED)
        return self._trusted_runtime.start_protected_operation(
            operation, subject, fence, dependencies, authorized_scope,
            root_forbidden_scope, materialization=materialization,
            target_registration=target_registration, base_ref=base_ref,
            provenance_operation_id=provenance_operation_id,
        )

    def reconcile_operation(
        self, task_id: TaskId, operation_id: OperationId,
        subject: ProtectedEffectSubject,
    ) -> GateResult:
        raise TypeError("recovery is fixture orchestration, not a T command")

    def evaluate_task(
        self, command: TaskEvaluationCommand,
    ) -> ControlStateCommitRequest:
        if type(command) is TaskEvaluationInput:
            raise TypeError("callers cannot submit trusted TaskEvaluationInput")
        return self._trusted_runtime.evaluate_task(command)

    def set_cancellation(self, *args, **kwargs) -> ControlStateCommitRequest:
        return self._trusted_runtime.controller.set_cancellation(*args, **kwargs)

    def admit_semantic_evidence(
        self, command: SemanticEvidenceCommand,
    ) -> ControlStateCommitRequest:
        return self._trusted_runtime.admit_semantic_evidence(command)


class ControlStateGateRuntime:
    """C-owned canonical writer with only a read/verify view of F.

    The fixture composition harness may construct this role, but the role does
    not retain that harness, P/M authority, or the broad fixture platform.
    """

    __slots__ = (
        "binding", "backend", "audit", "registry", "capability", "nonce",
        "runtime_identity", "controller_context", "control_context",
        "channel_token", "f_read_verify", "dependency_profiles",
        "dependency_transports",
    )

    def __init__(
        self, binding: GateRuntimeBinding,
        backend: InMemoryCanonicalStateBackend, audit: FixtureGateAudit,
        registry: ActiveFixtureRuntimeRegistry, capability: ControlStateCapability,
        nonce: object, runtime_identity: object,
        controller_context: RuntimeSecurityContext,
        control_context: RuntimeSecurityContext, channel_token: object,
        f_read_verify: FixtureReadVerifyClient,
        dependency_profiles: dict, dependency_transports: dict,
    ) -> None:
        if (type(binding) is not GateRuntimeBinding
                or type(backend) is not InMemoryCanonicalStateBackend
                or type(audit) is not FixtureGateAudit
                or type(registry) is not ActiveFixtureRuntimeRegistry
                or type(capability) is not ControlStateCapability
                or type(controller_context) is not RuntimeSecurityContext
                or type(control_context) is not RuntimeSecurityContext
                or controller_context.role is not TrustedRuntimeRole.CONTROLLER
                or control_context.role is not TrustedRuntimeRole.CONTROL_STATE_GATE
                or not isinstance(f_read_verify, FixtureReadVerifyClient)):
            raise TypeError("C runtime requires exact C-scoped dependencies")
        self.binding, self.backend, self.audit, self.registry = binding, backend, audit, registry
        self.capability, self.nonce, self.runtime_identity = capability, nonce, runtime_identity
        self.controller_context, self.control_context = controller_context, control_context
        self.channel_token, self.f_read_verify = channel_token, f_read_verify
        self.dependency_profiles, self.dependency_transports = dependency_profiles, dependency_transports

    def _is_active(self) -> bool:
        return self.registry.is_role_active(
            self.binding.root_context_id, self.binding.runtime_generation.value,
            "C", self.runtime_identity,
        )

    def _dependencies_fresh_set(self, dependencies: ControlStateAuthoritativeDependencySet) -> bool:
        for item in dependencies.dependencies:
            profile = self.dependency_profiles.get(item.observation_profile_id)
            transport = self.dependency_transports.get(item.transport_config_id)
            snapshot = self.f_read_verify.authoritative_snapshot(*item.locator)
            if profile is None or transport is None or snapshot is None:
                return False
            if (snapshot.repository_id, snapshot.observation_profile_id,
                    snapshot.transport_config_id) != item.locator:
                return False
            if item.repository_id not in transport.permitted_repository_ids:
                return False
            if self.f_read_verify.authoritative_binding(*item.locator) != item.expected_binding_id:
                return False
        return True

    @staticmethod
    def _dependency_digest(dependencies: ControlStateAuthoritativeDependencySet) -> RawSha256:
        return RawSha256(hashlib.sha256(canonical_json_bytes(dependencies)).hexdigest())

    def _audit_event(
        self, gate: str, action: str, outcome: GateAuditOutcome, *,
        service: ServicePrincipalId, dependencies: ControlStateAuthoritativeDependencySet,
        operation_id: OperationId | None = None,
        start_id: OperationStartBindingId | None = None,
        marker: ProtectedEffectMarker | None = None,
        action_digest: RawSha256 | None = None,
        result_identity: str = "", detail: str = "",
        intent: OperationIntent | None = None,
        materialization: CandidateMaterialization | AdmittedCandidateMaterialization | None = None,
    ) -> AuditAppendStatus:
        exact_dependencies = tuple(
            GateAuditAuthoritativeDependency(
                item.repository_id, item.observation_profile_id,
                item.transport_config_id, item.expected_binding_id,
            ) for item in dependencies.dependencies
        )
        preimage = GateAuditEventPreimage(
            "autodev.gate-audit-event/v1", gate, action, outcome,
            self.binding.root_context_id, self.binding.runtime_generation.value,
            self.binding.runtime_binding_id, service, exact_dependencies,
            self._dependency_digest(dependencies), self.backend.occurrence,
            operation_id, start_id,
            None if marker is None else marker.marker_id, action_digest,
            result_identity, detail,
            None if intent is None else intent.task_id,
            None if intent is None else intent.candidate_id,
            None if intent is None else intent.authorization_id,
            None if intent is None else intent.target_registration_id,
            None if intent is None else intent.policy_epoch_identity,
            None if materialization is None else materialization.materialization_id,
            None if materialization is None else materialization.inventory.inventory_id,
        )
        return self.audit.append_event(build_gate_audit_event(preimage))

    @staticmethod
    def _audit_ok(status: AuditAppendStatus) -> bool:
        return status in (AuditAppendStatus.APPENDED, AuditAppendStatus.ALREADY_PRESENT)

    def acquire_control_lease(
        self, dependencies: ControlStateAuthoritativeDependencySet,
        independence: ExternalStateIndependence | None = None,
    ) -> ControlStateCommitLease | None:
        if type(dependencies) is not ControlStateAuthoritativeDependencySet or not self._is_active():
            return None
        if not dependencies.dependencies:
            if type(independence) is not ExternalStateIndependence or independence._nonce is not self.nonce:
                return None
        elif independence is not None:
            return None
        facts: set[tuple] = set()
        for item in dependencies.dependencies:
            source_facts = self.f_read_verify.authoritative_facts(*item.locator)
            if source_facts is None:
                return None
            facts.update(source_facts)
        token = self.registry.acquire(self, frozenset(facts))
        if token is None:
            return None
        if not self._is_active() or not self._dependencies_fresh_set(dependencies):
            self.registry.release(token)
            return None
        lease = object.__new__(ControlStateCommitLease)
        lease._owner, lease._nonce, lease._used = self, self.nonce, False
        lease.root_context_id = self.binding.root_context_id
        lease.runtime_generation = self.binding.runtime_generation
        lease.runtime_binding = self.binding
        lease.dependencies = dependencies
        lease.capability = self.capability
        lease.fence_token = token
        return lease

    def commit(
        self, request: ControlStateCommitRequest, lease: ControlStateCommitLease,
        caller_context: AuthenticatedCallerContext | None,
    ) -> GateResult:
        with self.registry.lock:
            try:
                exact_request = (
                    type(request) is ControlStateCommitRequest
                    and type(request.command_kind) is TrustedControlCommandKind
                    and type(request.transaction) is CanonicalTransaction
                    and type(request._key) is ControllerRequestContext
                    and request._key.caller == self.controller_context
                    and request._key.destination == self.control_context
                    and request.request_format == "autodev.trusted-controller-to-control-state/v1"
                    and request.declared_t_identity == runtime_context_identity(self.controller_context)
                    and request.destination_c_identity == runtime_context_identity(self.control_context)
                    and request.root_context_id == self.binding.root_context_id
                    and request.runtime_generation == self.binding.runtime_generation.value
                    and request.request_digest == RawSha256(hashlib.sha256(canonical_json_bytes((
                        request.request_format, request.command_kind, request.transaction,
                        getattr(request, "required_authoritative_binding_ids", ()),
                        getattr(request, "required_authoritative_dependencies", ()),
                        request.declared_t_identity, request.destination_c_identity,
                        request.root_context_id, request.runtime_generation,
                        request.replay_identity,
                    ))).hexdigest())
                )
                exact_caller = (
                    type(caller_context) is AuthenticatedCallerContext
                    and caller_context.context == self.controller_context
                    and caller_context.request_digest == request.request_digest
                    and caller_context._channel_token is self.channel_token
                )
            except (AttributeError, TypeError, ValueError):
                exact_request = exact_caller = False
            if not exact_request or not exact_caller:
                return GateResult(GateResultCode.REJECTED)
            required_bindings = getattr(request, "required_authoritative_binding_ids", ())
            if required_bindings and frozenset(required_bindings) != frozenset(
                item.expected_binding_id for item in lease.dependencies.dependencies
            ):
                return GateResult(GateResultCode.LEASE_INVALID)
            required_dependencies = getattr(request, "required_authoritative_dependencies", ())
            if required_dependencies and required_dependencies != lease.dependencies.dependencies:
                return GateResult(GateResultCode.LEASE_INVALID)
            if (type(lease) is not ControlStateCommitLease
                    or not self._dependencies_fresh_set(lease.dependencies)
                    or not self._is_active()):
                return GateResult(GateResultCode.LEASE_INVALID)
            if (lease.runtime_binding is not self.binding
                    or lease.root_context_id != self.binding.root_context_id
                    or lease.runtime_generation != self.binding.runtime_generation
                    or lease.capability is not self.capability):
                return GateResult(GateResultCode.LEASE_INVALID)
            if request.command_kind is TrustedControlCommandKind.START_OPERATION:
                started = next((
                    mutation.operation for mutation in request.transaction.mutations
                    if type(mutation) is ReplaceOperation
                    and mutation.operation.state is OperationState.PERFORMING
                ), None)
                canonical = None if started is None else started.canonical_protected_start_binding
                held = None if type(canonical) is not CanonicalProtectedStartBinding else canonical.start_held_target_fence_binding
                durable = (None if type(held) is not StartHeldTargetFenceBinding else
                           self.f_read_verify.read_prepared_effect_record(
                               held.operation_id, held.action_class,
                           ))
                expected_subject = {
                    ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION.value:
                        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
                    ProtectedEffectSubject.PULL_REQUEST_CREATION.value:
                        ProtectedEffectSubject.PULL_REQUEST_CREATION,
                    ProtectedEffectSubject.FAST_FORWARD_MERGE.value:
                        ProtectedEffectSubject.FAST_FORWARD_MERGE,
                }.get(None if type(held) is not StartHeldTargetFenceBinding else held.action_class)
                expected_role_name = (
                    "MERGE_AUTHORITY"
                    if expected_subject is ProtectedEffectSubject.FAST_FORWARD_MERGE
                    else "PUBLICATION_AUTHORITY"
                )
                preimage = (None if type(durable) is not PreparedProtectedStart
                            else durable.preimage)
                expected_service = (
                    self.binding.merge_principal
                    if expected_role_name == "MERGE_AUTHORITY"
                    else self.binding.publication_principal
                )
                expected_authority_binding = (
                    None if preimage is None else RawSha256(hashlib.sha256(
                        canonical_json_bytes((
                            "autodev.fixture-role-authority-binding/v1",
                            self.f_read_verify.substrate_identity,
                            expected_role_name, expected_service,
                            self.binding.root_context_id,
                            self.binding.runtime_generation.value,
                            preimage.runtime_binding_id,
                        ))
                    ).hexdigest())
                )
                expected_fence_identity = (
                    None if preimage is None else RawSha256(hashlib.sha256(
                        canonical_json_bytes((
                            "autodev.fixture-target-fence/v1", preimage.target_fence,
                        ))
                    ).hexdigest())
                )
                if (started is None or type(held) is not StartHeldTargetFenceBinding
                        or expected_subject is None
                        or started.start_binding_id != operation_start_binding_id_v2(held)
                        or canonical.operation_start_binding_id != started.start_binding_id
                        or held.operation_id != started.intent.operation_id
                        or held.action_class != expected_subject.value
                        or type(durable) is not PreparedProtectedStart
                        or durable.state is not PreparedProtectedStartState.START_HELD
                        or durable.prepared_start_id != held.prepared_start_id
                        or durable.operation.intent != started.intent
                        or durable.subject is not expected_subject
                        or preimage.action is not expected_subject
                        or preimage.operation_id != started.intent.operation_id
                        or preimage.service_identity != expected_service
                        or held.fixture_substrate_identity != self.f_read_verify.substrate_identity
                        or held.authority_binding_identity != expected_authority_binding
                        or held.target_fence_identity != expected_fence_identity
                        or held.root_context_id != self.binding.root_context_id
                        or held.runtime_generation != self.binding.runtime_generation.value
                        or not self.f_read_verify.verify_start_held_target_fence(held)):
                    return GateResult(GateResultCode.REJECTED)
            if not lease._consume(self, self.nonce):
                return GateResult(GateResultCode.LEASE_CONSUMED)
            try:
                request_digest = request.request_digest
                audit_operation = next((
                    mutation.operation for mutation in request.transaction.mutations
                    if type(mutation) in (ReplaceOperation, CreateOperationAndAdvanceMembership)
                ), None)
                audit_intent = None if audit_operation is None else audit_operation.intent
                audit_operation_id = None if audit_operation is None else audit_operation.intent.operation_id
                audit_start_id = None if audit_operation is None else audit_operation.start_binding_id
                if not self._audit_ok(self._audit_event(
                    "CONTROL_STATE", request.command_kind.value, GateAuditOutcome.ATTEMPTED,
                    service=self.binding.control_state_principal, dependencies=lease.dependencies,
                    operation_id=audit_operation_id, start_id=audit_start_id,
                    action_digest=request_digest, intent=audit_intent,
                )):
                    return GateResult(GateResultCode.AUDIT_FAILURE_BEFORE_COMMIT)
                result = self.backend.apply(request.transaction)
                replay = (request.command_kind is TrustedControlCommandKind.ADMIT_CONTRACT
                          and result.status is CanonicalWriteStatus.ALREADY_PRESENT)
                if result.status is not CanonicalWriteStatus.APPLIED and not replay:
                    outcome = GateAuditOutcome.CAS_CONFLICT if result.status is CanonicalWriteStatus.CAS_CONFLICT else GateAuditOutcome.DENIED
                    self._audit_event(
                        "CONTROL_STATE", request.command_kind.value, outcome,
                        service=self.binding.control_state_principal, dependencies=lease.dependencies,
                        operation_id=audit_operation_id, start_id=audit_start_id,
                        action_digest=request_digest, detail=result.status.value,
                        intent=audit_intent,
                    )
                    return GateResult(GateResultCode.REJECTED, result)
                if not self._audit_ok(self._audit_event(
                    "CONTROL_STATE", request.command_kind.value, GateAuditOutcome.APPLIED,
                    service=self.binding.control_state_principal, dependencies=lease.dependencies,
                    operation_id=audit_operation_id, start_id=audit_start_id,
                    action_digest=request_digest, intent=audit_intent,
                )):
                    return GateResult(GateResultCode.AUDIT_FAILURE_AFTER_COMMIT, result)
                return GateResult(GateResultCode.COMMITTED, result)
            finally:
                self.registry.release(lease.fence_token)

    def commit_control_state(
        self, request: ControlStateCommitRequest, lease: ControlStateCommitLease,
        caller_context: AuthenticatedCallerContext | None = None,
    ) -> GateResult:
        return self.commit(request, lease, caller_context)

    def commit_authenticated_request(
        self, request: ControlStateCommitRequest,
        dependencies: ControlStateAuthoritativeDependencySet,
        caller_context: AuthenticatedCallerContext,
    ) -> GateResult:
        """C-owned lease acquisition for an authenticated T request."""
        if (type(request) is not ControlStateCommitRequest
                or type(dependencies) is not ControlStateAuthoritativeDependencySet
                or getattr(request, "required_authoritative_dependencies", None)
                != dependencies.dependencies):
            return GateResult(GateResultCode.LEASE_INVALID)
        independence = None
        if not dependencies.dependencies:
            independence = object.__new__(ExternalStateIndependence)
            independence._nonce = self.nonce
        lease = self.acquire_control_lease(dependencies, independence)
        if lease is None:
            return GateResult(GateResultCode.LEASE_INVALID)
        result = self.commit(request, lease, caller_context)
        if lease.fence_token.active:
            self.registry.release(lease.fence_token)
        return result


class FixtureProtectedGateRuntime:
    """Holds fixture authority; a new instance is a process restart boundary."""

    __slots__ = ("binding", "backend", "platform", "audit", "controller", "boundary",
                 "registry", "_lock", "_nonce", "_controller_key", "_t_context", "_c_context",
                 "_p_context", "_m_context", "_f_read_verify_client", "_publication_authority_client",
                 "_merge_authority_client", "_start_held_recovery_authority", "_t_to_c_channel_token", "_t_to_p_channel_token",
                 "_t_to_m_channel_token", "_profiles", "_readers", "_fixture_transports", "_contract_contexts", "_authorization_contexts", "_evidence_contexts", "_completion_contexts", "_semantic_contexts", "_object_store", "_control", "_publication", "_merge", "_control_runtime", "_publication_runtime", "_merge_runtime", "_control_gate_runtime", "_trusted_controller_runtime", "_publication_gate_runtime", "_merge_gate_runtime", "_fail_after_start", "_recovery_fence_hook", "_post_start_audit_failure_hook")

    def __init__(self, binding: GateRuntimeBinding, backend: InMemoryCanonicalStateBackend,
                 platform: FixtureGitPlatform, audit: FixtureGateAudit,
                 registry: ActiveFixtureRuntimeRegistry | None = None, *,
                 object_store: FixtureGitObjectStore | None = None,
                 _restart_from: tuple[object, object, object] | None = None) -> None:
        if type(binding) is not GateRuntimeBinding or type(backend) is not InMemoryCanonicalStateBackend:
            raise TypeError("runtime binding/backend has wrong exact type")
        if type(platform) is not FixtureGitPlatform or type(audit) is not FixtureGateAudit:
            raise TypeError("fixture platform/audit has wrong exact type")
        self.binding, self.backend, self.platform, self.audit = binding, backend, platform, audit
        self._f_read_verify_client = platform.read_verify_client()
        self._publication_authority_client = platform.publication_authority_client()
        self._merge_authority_client = platform.merge_authority_client()
        self._start_held_recovery_authority = platform.fixture_start_held_recovery_authority()
        self.registry = registry or ActiveFixtureRuntimeRegistry()
        self.platform.attach_registry(self.registry)
        self._lock, self._nonce = self.registry.lock, object()
        self._t_context = RuntimeSecurityContext(
            TrustedRuntimeRole.CONTROLLER, ServicePrincipalId("trusted-controller"),
            binding.root_context_id, binding.runtime_generation.value,
            binding.runtime_binding_id,
        )
        self._c_context = RuntimeSecurityContext(
            TrustedRuntimeRole.CONTROL_STATE_GATE, binding.control_state_principal,
            binding.root_context_id, binding.runtime_generation.value,
            binding.runtime_binding_id,
        )
        self._p_context = RuntimeSecurityContext(
            TrustedRuntimeRole.PUBLICATION_GATE, binding.publication_principal,
            binding.root_context_id, binding.runtime_generation.value,
            binding.runtime_binding_id,
        )
        self._m_context = RuntimeSecurityContext(
            TrustedRuntimeRole.MERGE_GATE, binding.merge_principal,
            binding.root_context_id, binding.runtime_generation.value,
            binding.runtime_binding_id,
        )
        self._controller_key = ControllerRequestContext(self._t_context, self._c_context)
        # This token belongs to the fixture transport, not to request data.
        self._t_to_c_channel_token = object()
        self._t_to_p_channel_token, self._t_to_m_channel_token = object(), object()
        self._profiles: dict[ImmutableConfigId, AuthoritativeObservationProfile] = {}
        self._readers: dict[ImmutableConfigId, GitHubStateReader] = {}
        self._fixture_transports: dict[ImmutableConfigId, TrustedGitHubReadTransportBinding] = {}
        self._authorization_contexts: dict[str, tuple] = {}
        self._contract_contexts: dict[str, TrustedIssueContractAdmissionContext] = {}
        self._evidence_contexts: dict[ImmutableConfigId, SemanticEvidenceAdmissionRequest] = {}
        self._completion_contexts: dict[ImmutableConfigId, TrustedCompletionEvaluationContext] = {}
        self._semantic_contexts: dict[TaskId, tuple] = {}
        if object_store is not None and type(object_store) is not FixtureGitObjectStore:
            raise TypeError("fixture Git-object store has wrong exact type")
        self._object_store = object_store
        self._fail_after_start = False
        self._recovery_fence_hook = None
        self._post_start_audit_failure_hook = None
        self._control = _mint_capability(ControlStateCapability, self._nonce, binding.control_state_principal)
        self._publication = _mint_capability(TargetPublicationCapability, self._nonce, binding.publication_principal)
        self._merge = _mint_capability(MergeCapability, self._nonce, binding.merge_principal)
        self._control_runtime, self._publication_runtime, self._merge_runtime = object(), object(), object()
        activated = (
            self.registry.activate(
                binding.root_context_id, binding.runtime_generation.value,
                self._control_runtime, self._publication_runtime, self._merge_runtime,
            )
            if _restart_from is None else
            self.registry.restart(
                binding.root_context_id, binding.runtime_generation.value,
                _restart_from, self._control_runtime,
                self._publication_runtime, self._merge_runtime,
            )
        )
        if not activated:
            raise RuntimeError("cannot replace active runtime while a gate lease is live")
        self._control_gate_runtime = ControlStateGateRuntime(
            binding, backend, audit, self.registry, self._control, self._nonce,
            self._control_runtime, self._t_context, self._c_context,
            self._t_to_c_channel_token, self._f_read_verify_client,
            self._profiles, self._fixture_transports,
        )
        self.controller = _new_controller(
            self._controller_key, self.backend.read_client(), self._completion_contexts, self._object_store
        )
        self._trusted_controller_runtime = TrustedControllerRuntime(
            self.controller, self.controller._backend, self._f_read_verify_client,
            self._profiles, self._fixture_transports, self._contract_contexts,
            self._authorization_contexts, self._evidence_contexts,
            self._semantic_contexts,
            _FixtureControlStateClient(
                self._control_gate_runtime, self._t_to_c_channel_token, self._t_context,
            ),
            binding, audit,
        )
        self.boundary = TrustedControlCommandBoundary(self._trusted_controller_runtime)
        self._publication_gate_runtime = PublicationGateRuntime(
            binding, self.backend.read_client(), audit, self._publication,
            self._publication_runtime, self._nonce, self._t_context, self._p_context,
            _FixtureRoleCallerVerifier(self._t_to_p_channel_token, self._t_context),
            self._f_read_verify_client,
            self._publication_authority_client,
            FixtureGateRoleFenceClient(
                self.registry, binding.root_context_id,
                binding.runtime_generation.value, "P", self._publication_runtime,
            ), self._profiles, self._fixture_transports,
        )
        self._merge_gate_runtime = MergeGateRuntime(
            binding, self.backend.read_client(), audit, self._merge,
            self._merge_runtime, self._nonce, self._t_context, self._m_context,
            _FixtureRoleCallerVerifier(self._t_to_m_channel_token, self._t_context),
            self._f_read_verify_client,
            self._merge_authority_client,
            FixtureGateRoleFenceClient(
                self.registry, binding.root_context_id,
                binding.runtime_generation.value, "M", self._merge_runtime,
            ), self._profiles, self._fixture_transports,
        )
        # T receives only role-specific transports after independent P/M
        # runtimes have been constructed; it never retains this composition.
        self._trusted_controller_runtime.publication_gate_client = self.publication_gate_client
        self._trusted_controller_runtime.merge_gate_client = self.merge_gate_client

    @property
    def control_capability(self) -> ControlStateCapability:
        return self._control

    @property
    def control_state_client(self) -> ControlStateGateClient:
        """The candidate C endpoint, with no reference to the composition harness."""
        return _FixtureControlStateClient(
            self._control_gate_runtime, self._t_to_c_channel_token, self._t_context,
        )

    @property
    def publication_gate_client(self) -> PublicationGateClient:
        return _FixturePublicationGateClient(
            self._publication_gate_runtime, self._trusted_controller_runtime,
            self._t_to_p_channel_token, self._t_context,
            self._start_held_recovery_authority,
        )

    @property
    def merge_gate_client(self) -> MergeGateClient:
        return _FixtureMergeGateClient(
            self._merge_gate_runtime, self._trusted_controller_runtime,
            self._t_to_m_channel_token, self._t_context,
            self._start_held_recovery_authority,
        )

    @property
    def publication_capability(self) -> TargetPublicationCapability:
        return self._publication

    @property
    def merge_capability(self) -> MergeCapability:
        return self._merge

    def _is_active(self) -> bool:
        return self.registry.is_active(
            self.binding.root_context_id, self.binding.runtime_generation.value,
            self._control_runtime, self._publication_runtime, self._merge_runtime,
        )

    @staticmethod
    def _dependency_digest(dependencies: ControlStateAuthoritativeDependencySet) -> RawSha256:
        return RawSha256(hashlib.sha256(canonical_json_bytes(dependencies)).hexdigest())

    def _authority_binding_identity(
        self, subject: ProtectedEffectSubject, service: ServicePrincipalId,
        runtime_binding_id: GateRuntimeBindingId | None = None,
    ) -> RawSha256:
        role = (
            "MERGE_AUTHORITY"
            if subject is ProtectedEffectSubject.FAST_FORWARD_MERGE
            else "PUBLICATION_AUTHORITY"
        )
        return RawSha256(hashlib.sha256(canonical_json_bytes((
            "autodev.fixture-role-authority-binding/v1", self.platform._substrate_identity,
            role, service, self.binding.root_context_id,
            self.binding.runtime_generation.value,
            self.binding.runtime_binding_id if runtime_binding_id is None else runtime_binding_id,
        ))).hexdigest())

    def _audit_event(self, gate: str, action: str, outcome: GateAuditOutcome, *,
                     service: ServicePrincipalId, dependencies: ControlStateAuthoritativeDependencySet,
                     operation_id: OperationId | None = None,
                     start_id: OperationStartBindingId | None = None,
                     marker: ProtectedEffectMarker | None = None,
                     action_digest: RawSha256 | None = None,
                     result_identity: str = "", detail: str = "",
                     intent: OperationIntent | None = None,
                     materialization: CandidateMaterialization | AdmittedCandidateMaterialization | None = None,
                     occurrence=None) -> AuditAppendStatus:
        exact_dependencies = tuple(
            GateAuditAuthoritativeDependency(
                item.repository_id, item.observation_profile_id,
                item.transport_config_id, item.expected_binding_id,
            )
            for item in dependencies.dependencies
        )
        preimage = GateAuditEventPreimage(
            "autodev.gate-audit-event/v1", gate, action, outcome,
            self.binding.root_context_id, self.binding.runtime_generation.value,
            self.binding.runtime_binding_id, service, exact_dependencies,
            self._dependency_digest(dependencies),
            self.backend.occurrence if occurrence is None else occurrence,
            operation_id, start_id,
            None if marker is None else marker.marker_id, action_digest,
            result_identity, detail,
            None if intent is None else intent.task_id,
            None if intent is None else intent.candidate_id,
            None if intent is None else intent.authorization_id,
            None if intent is None else intent.target_registration_id,
            None if intent is None else intent.policy_epoch_identity,
            None if materialization is None else materialization.materialization_id,
            None if materialization is None else materialization.inventory.inventory_id,
        )
        return self.audit.append_event(build_gate_audit_event(preimage))

    @staticmethod
    def _audit_ok(status: AuditAppendStatus) -> bool:
        return status in (AuditAppendStatus.APPENDED, AuditAppendStatus.ALREADY_PRESENT)

    def register_authoritative_source(self, profile: AuthoritativeObservationProfile,
                                      reader: GitHubStateReader) -> None:
        """Register a G6 reader for compatibility; it is intentionally not fenceable."""
        if type(profile) is not AuthoritativeObservationProfile or type(reader) is not GitHubStateReader:
            raise TypeError("exact trusted profile and reader required")
        config_id = reader._binding.config_id
        with self._lock:
            if profile.profile_id in self._profiles and self._profiles[profile.profile_id] is not profile:
                raise ValueError("observation profile identity conflict")
            if config_id in self._readers and self._readers[config_id] is not reader:
                raise ValueError("transport config identity conflict")
            self._profiles[profile.profile_id] = profile
            self._readers[config_id] = reader

    def register_fixture_authoritative_source(
        self, profile: AuthoritativeObservationProfile,
        transport: TrustedGitHubReadTransportBinding,
        snapshot: AuthoritativeStateSnapshot,
    ) -> None:
        """Install the exact root-managed fixture read path used by G7 leases."""
        if (type(profile) is not AuthoritativeObservationProfile
                or type(transport) is not TrustedGitHubReadTransportBinding
                or type(snapshot) is not AuthoritativeStateSnapshot):
            raise TypeError("exact fixture authoritative source inputs required")
        if (type(profile.registered_fact_descriptors) is not tuple
                or not profile.registered_fact_descriptors
                or any(type(item) is not RegisteredStateFactDescriptor
                       for item in profile.registered_fact_descriptors)):
            raise ValueError("fixture observation profile is malformed")
        transport_fields = (
            (transport.config_id, ImmutableConfigId),
            (transport.expected_api_host_identity, ImmutableConfigId),
            (transport.authentication_mode_identity, ImmutableConfigId),
            (transport.service_identity, ServicePrincipalId),
            (transport.transport_profile_id, ImmutableConfigId),
        )
        if any(type(value) is not expected for value, expected in transport_fields):
            raise TypeError("fixture transport binding is malformed")
        if (type(transport.permitted_repository_ids) is not tuple
                or any(type(item) is not GitHubRepositoryId
                       for item in transport.permitted_repository_ids)
                or len(set(transport.permitted_repository_ids))
                != len(transport.permitted_repository_ids)):
            raise TypeError("fixture transport repository set is malformed")
        if (snapshot.observation_profile_id != profile.profile_id
                or snapshot.transport_config_id != transport.config_id
                or snapshot.repository_id not in transport.permitted_repository_ids):
            raise ValueError("fixture authoritative source identities do not match")
        with self._lock:
            current_profile = self._profiles.get(profile.profile_id)
            current_transport = self._fixture_transports.get(transport.config_id)
            if current_profile is not None and current_profile is not profile:
                raise ValueError("observation profile identity conflict")
            if current_transport is not None and current_transport != transport:
                raise ValueError("transport config identity conflict")
            self._profiles[profile.profile_id] = profile
            self._fixture_transports[transport.config_id] = transport
            self.platform.install_authoritative_snapshot(snapshot)

    def register_authorization_context(
        self, proposal: CandidateAuthorizationProposal,
        target: AdmittedTargetRegistration | None,
        contract_context: TrustedIssueContractApplicabilityContext,
        policy: AuthorizationPolicyContext | None,
        root: OrdinaryRootProtectionContext | None, *,
        approval: AuthenticatedHumanAuthorizationApproval | None = None,
        issuer: DirectIssuerAuthorityEnvelope | None = None,
    ) -> None:
        """Fixture root/admin setup; these authority facts never cross the command boundary."""
        if type(proposal) is not CandidateAuthorizationProposal:
            raise TypeError("exact candidate authorization proposal required")
        if type(contract_context) is not TrustedIssueContractApplicabilityContext:
            raise TypeError("assembled current contract applicability context required")
        key = hashlib.sha256(canonical_json_bytes(proposal)).hexdigest()
        self._authorization_contexts[key] = (
            target, contract_context, policy, root, approval, issuer,
        )

    def register_contract_context(
        self, raw: bytes, context: TrustedIssueContractAdmissionContext,
    ) -> None:
        """Fixture root setup keeps trusted admission facts off the command surface."""
        if type(raw) is not bytes or type(context) is not TrustedIssueContractAdmissionContext:
            raise TypeError("exact raw bytes and trusted admission context required")
        self._contract_contexts[hashlib.sha256(raw).hexdigest()] = context

    def register_semantic_evidence_context(
        self, context_id: ImmutableConfigId,
        request: SemanticEvidenceAdmissionRequest,
    ) -> None:
        """Install trusted G5 composition inputs outside the untrusted command surface."""
        if type(context_id) is not ImmutableConfigId:
            raise TypeError("context id must be exact ImmutableConfigId")
        if type(request) is not SemanticEvidenceAdmissionRequest:
            raise TypeError("exact trusted semantic admission request required")
        if context_id in self._evidence_contexts and self._evidence_contexts[context_id] != request:
            raise ValueError("semantic evidence context identity conflict")
        self._evidence_contexts[context_id] = request

    def register_completion_evaluation_context(
        self, context: TrustedCompletionEvaluationContext,
    ) -> None:
        """Install immutable root-managed G4 completion inputs for fixture evaluation."""
        if type(context) is not TrustedCompletionEvaluationContext:
            raise TypeError("exact trusted completion context required")
        with self._lock:
            current = self._completion_contexts.get(context.context_id)
            if current is not None and current != context:
                raise ValueError("completion context identity conflict")
            self._completion_contexts[context.context_id] = context

    def register_semantic_consumption_context(
        self, task_id: TaskId, applicability_context: TrustedIssueContractApplicabilityContext,
        byte_reader: TrustedSemanticConfigByteReader | None,
        semantic_context_source: TrustedSemanticContextObservationSource | None,
        g1_base_dependency: AuthoritativeStateDependency,
    ) -> None:
        """Install root-assembled #29 inputs; none cross an untrusted command."""
        if (type(task_id) is not TaskId
                or type(applicability_context) is not TrustedIssueContractApplicabilityContext
                or (byte_reader is not None and type(byte_reader) is not TrustedSemanticConfigByteReader)
                or (semantic_context_source is not None
                    and type(semantic_context_source) is not TrustedSemanticContextObservationSource)
                or type(g1_base_dependency) is not AuthoritativeStateDependency):
            raise TypeError("exact trusted semantic-consumption environment required")
        observation = applicability_context.base_observation
        if (observation is None
                or observation.authoritative_state_binding_id
                != g1_base_dependency.expected_binding_id):
            raise ValueError("G1 base dependency must bind the exact G1 base observation")
        with self._lock:
            self._semantic_contexts[task_id] = (
                applicability_context, byte_reader, semantic_context_source,
                g1_base_dependency,
            )

    def _resolve_semantic_consumption(
        self, task_id: TaskId, requested_evidence_ids: tuple[EvidenceId, ...],
        expected_occurrence=None,
    ):
        return self._trusted_controller_runtime._resolve_semantic_consumption(
            task_id, requested_evidence_ids, expected_occurrence,
        )

    def _veto_task_transition(
        self, command: TaskEvaluationCommand, request: ControlStateCommitRequest,
    ) -> ControlStateCommitRequest:
        current = self.backend.read_task_working_set(command.task_id)
        if (current is None
                or current.canonical_state_occurrence_binding
                != request.transaction.expected_state_occurrence):
            raise _TaskSemanticDenied(TaskSemanticDenialCode.SEMANTIC_CONTEXT_INDETERMINATE)
        replacement = next((item.task for item in request.transaction.mutations
                            if type(item) is ReplaceTask), None)
        if replacement is None or replacement.state not in (
            TaskState.INTEGRATION_READY, TaskState.COMPLETED
        ):
            return request
        required_ids: tuple[EvidenceId, ...] = ()
        selected_operation = None
        if replacement.state is TaskState.INTEGRATION_READY:
            selected_operation = next((item for item in current.operations
                if item.intent.operation_id == replacement.next_integration_operation_id), None)
            if (replacement.next_integration_operation_id is None
                    or selected_operation is None
                    or selected_operation.intent.effect_class
                    is not OperationEffectClass.PROTECTED_OR_AUTHORITATIVE_EFFECT
                    or type(selected_operation.intent.integration_binding) is not IntegrationBound):
                raise _TaskSemanticDenied(
                    TaskSemanticDenialCode.NEXT_INTEGRATION_OPERATION_INVALID
                )
            required_ids = selected_operation.intent.required_evidence_ids
        semantic = self._resolve_semantic_consumption(
            command.task_id, required_ids, current.canonical_state_occurrence_binding,
        )
        if semantic is None:
            raise _TaskSemanticDenied(TaskSemanticDenialCode.SEMANTIC_CONTEXT_INDETERMINATE)
        if semantic.contract_status is ConditionStatus.UNSATISFIED:
            raise _TaskSemanticDenied(TaskSemanticDenialCode.SEMANTIC_CONTRACT_UNSATISFIED)
        if semantic.contract_status is not ConditionStatus.SATISFIED:
            raise _TaskSemanticDenied(TaskSemanticDenialCode.SEMANTIC_CONTEXT_INDETERMINATE)
        if replacement.state is TaskState.INTEGRATION_READY:
            statuses = {item.evidence_id: item for item in semantic.evidence_currentness}
            for evidence_id in required_ids:
                # The evidence result is exact for every requested ID.  A missing
                # lookup is treated as an indeterminate canonical inconsistency.
                result = statuses.get(evidence_id)
                if result is None:
                    raise _TaskSemanticDenied(
                        TaskSemanticDenialCode.SEMANTIC_CONTEXT_INDETERMINATE
                    )
                if result.status is SemanticEvidenceCurrentnessStatus.NOT_SEMANTIC:
                    continue
                if result.status is not SemanticEvidenceCurrentnessStatus.CURRENT:
                    code = (TaskSemanticDenialCode.REQUIRED_SEMANTIC_EVIDENCE_NOT_CURRENT
                            if result.status in (SemanticEvidenceCurrentnessStatus.STALE,
                                                 SemanticEvidenceCurrentnessStatus.NOT_FOUND)
                            else TaskSemanticDenialCode.SEMANTIC_CONTEXT_INDETERMINATE)
                    raise _TaskSemanticDenied(code)
                if not any(evidence_id in item.progression_support_evidence_ids
                           for item in semantic.obligation_results):
                    raise _TaskSemanticDenied(
                        TaskSemanticDenialCode.REQUIRED_SEMANTIC_EVIDENCE_NOT_PROGRESSION_SUPPORT
                    )
        object.__setattr__(request, "required_authoritative_binding_ids", tuple(
            item.expected_binding_id for item in semantic.authoritative_dependencies
        ))
        object.__setattr__(request, "required_authoritative_dependencies",
                           semantic.authoritative_dependencies)
        return request

    def _protected_start_semantic_denial(
        self, operation: OperationRecord, subject: ProtectedEffectSubject,
        expected_occurrence,
        dependencies: ControlStateAuthoritativeDependencySet,
    ) -> ProtectedStartSemanticDenialCode | None:
        working = self.backend.read_task_working_set(operation.intent.task_id)
        if (working is None
                or working.canonical_state_occurrence_binding != expected_occurrence
                or self.backend.occurrence != expected_occurrence):
            return ProtectedStartSemanticDenialCode.REQUIRED_EVIDENCE_CONTEXT_INDETERMINATE
        canonical_operation = next((
            item for item in working.operations
            if item.intent.operation_id == operation.intent.operation_id
        ), None)
        if canonical_operation != operation:
            return ProtectedStartSemanticDenialCode.REQUIRED_EVIDENCE_CONTEXT_INDETERMINATE
        forward = (
            subject is ProtectedEffectSubject.FAST_FORWARD_MERGE
            and type(operation.intent.integration_binding) is IntegrationBound
            and working.task.state is TaskState.INTEGRATION_READY
            and working.task.next_integration_operation_id
            == operation.intent.operation_id
        )
        if not operation.intent.required_evidence_ids and not forward:
            return None

        # Evidence class is canonical state, not a caller claim.  Read it at
        # the exact start occurrence before deciding whether #29 owns any of
        # the required IDs.  The empty history projection is facts-only G6.
        semantic_evidence_ids: tuple[EvidenceId, ...] = ()
        required_ids = operation.intent.required_evidence_ids
        if required_ids:
            evidence_snapshot = self.backend.read_semantic_consumption_snapshot(
                operation.intent.task_id, expected_occurrence, (), required_ids,
            )
            if (evidence_snapshot is None
                    or evidence_snapshot.canonical_state_occurrence_binding
                    != expected_occurrence
                    or self.backend.occurrence != expected_occurrence
                    or tuple(item.evidence_id for item in evidence_snapshot.requested_evidence)
                    != required_ids):
                return ProtectedStartSemanticDenialCode.REQUIRED_EVIDENCE_CONTEXT_INDETERMINATE
            if any(item.record is None for item in evidence_snapshot.requested_evidence):
                return ProtectedStartSemanticDenialCode.REQUIRED_EVIDENCE_NOT_CURRENT
            semantic_evidence_ids = tuple(
                item.evidence_id for item in evidence_snapshot.requested_evidence
                if item.record.evidence_class is EvidenceClass.SEMANTIC_REVIEW
            )
            if not semantic_evidence_ids and not forward:
                if self.backend.occurrence != expected_occurrence:
                    return ProtectedStartSemanticDenialCode.REQUIRED_EVIDENCE_CONTEXT_INDETERMINATE
                return None

        semantic = self._resolve_semantic_consumption(
            operation.intent.task_id, semantic_evidence_ids,
            expected_occurrence,
        )
        if (semantic is None or semantic.occurrence != expected_occurrence
                or self.backend.occurrence != expected_occurrence):
            return ProtectedStartSemanticDenialCode.REQUIRED_EVIDENCE_CONTEXT_INDETERMINATE
        currentness = {item.evidence_id: item for item in semantic.evidence_currentness}
        for evidence_id in semantic_evidence_ids:
            result = currentness.get(evidence_id)
            if result is None:
                return ProtectedStartSemanticDenialCode.REQUIRED_EVIDENCE_CONTEXT_INDETERMINATE
            if result.status in (SemanticEvidenceCurrentnessStatus.STALE,
                                 SemanticEvidenceCurrentnessStatus.NOT_FOUND):
                return ProtectedStartSemanticDenialCode.REQUIRED_EVIDENCE_NOT_CURRENT
            if result.status is SemanticEvidenceCurrentnessStatus.INDETERMINATE:
                return ProtectedStartSemanticDenialCode.REQUIRED_EVIDENCE_CONTEXT_INDETERMINATE
        if forward:
            if semantic.contract_status is ConditionStatus.UNSATISFIED:
                return ProtectedStartSemanticDenialCode.REQUIRED_EVIDENCE_NOT_VALID_FOR_OPERATION
            if semantic.contract_status is not ConditionStatus.SATISFIED:
                return ProtectedStartSemanticDenialCode.REQUIRED_EVIDENCE_CONTEXT_INDETERMINATE
            for evidence_id in semantic_evidence_ids:
                result = currentness.get(evidence_id)
                if result is not None and result.status is SemanticEvidenceCurrentnessStatus.CURRENT:
                    if not any(evidence_id in item.progression_support_evidence_ids
                               for item in semantic.obligation_results):
                        return ProtectedStartSemanticDenialCode.REQUIRED_EVIDENCE_NOT_VALID_FOR_OPERATION
        lease_dependencies = dependencies.dependencies
        if any(item not in lease_dependencies for item in semantic.authoritative_dependencies):
            return ProtectedStartSemanticDenialCode.REQUIRED_EVIDENCE_CONTEXT_INDETERMINATE
        if (not self._dependencies_fresh_set(dependencies)
                or self.backend.occurrence != expected_occurrence):
            return ProtectedStartSemanticDenialCode.REQUIRED_EVIDENCE_CONTEXT_INDETERMINATE
        return None

    def _compose_semantic_evidence_request(
        self, command: SemanticEvidenceCommand,
    ) -> SemanticEvidenceAdmissionRequest:
        if type(command) is not SemanticEvidenceCommand:
            raise TypeError("exact SemanticEvidenceCommand required")
        template = self._evidence_contexts.get(command.admission_context_id)
        if template is None:
            raise ValueError("trusted semantic evidence context is unavailable")
        snapshot = self.backend.read_review_eligibility_snapshot(
            template.effective_subject.subject_id
        )
        if snapshot is None or snapshot.effective_subject != template.effective_subject:
            raise ValueError("canonical review eligibility context is unavailable")
        operation = template.operation
        if template.operation_binding is not None:
            operation = next((
                item for item in snapshot.review_attempt_operations
                if item.intent.operation_id == template.operation_binding.operation_id
            ), None)
        return replace(
            template, raw_response=command.raw_response,
            operation=operation,
            evidence_history=snapshot.g5_evidence_snapshot(),
            slot_attempt_history=snapshot.g5_attempt_snapshot(),
        )

    def attest_external_state_independence(self) -> ExternalStateIndependence:
        """Trusted fixture decision for non-recovery commands with no dependencies."""
        return self._trusted_external_state_independence()

    def _trusted_external_state_independence(self) -> ExternalStateIndependence:
        value = object.__new__(ExternalStateIndependence)
        value._nonce = self._nonce
        return value

    def _derive_operation_authoritative_binding(
        self, task_id: TaskId, command: OperationReservationCommand,
    ) -> AuthoritativeStateBindingId:
        """Fresh trusted projection; callers cannot nominate a remembered binding."""
        if type(task_id) is not TaskId or type(command) is not OperationReservationCommand:
            raise TypeError("exact operation request inputs required")
        with self._lock:
            working = self.backend.read_task_working_set(task_id)
            if working is None:
                raise ValueError("task is not canonical")
            resolved = self.backend.read_resolved_target_registration(
                working.task.target_registration_id
            )
            if resolved is None:
                raise ValueError("target registration is not root-resolved")
            fixture_bindings = tuple(sorted((
                (
                    profile_id.value, transport_id.value,
                    binding.value,
                )
                for profile_id in self._profiles
                for transport_id in self._fixture_transports
                for binding in (
                    self.platform.authoritative_binding(
                        resolved.registration.repository_id,
                        profile_id, transport_id,
                    ),
                )
                if binding is not None
            )))
            digest = hashlib.sha256(canonical_json_bytes((
                "autodev.g7-operation-authoritative-binding/v1",
                self.backend.occurrence, task_id, command.action_id,
                command.subject_id, fixture_bindings,
            ))).hexdigest()
            return AuthoritativeStateBindingId(digest)

    def acquire_control_lease(self, capability: ControlStateCapability,
                              dependencies: ControlStateAuthoritativeDependencySet,
                              independence: ExternalStateIndependence | None = None) -> ControlStateCommitLease | None:
        if capability is not self._control:
            return None
        return self._control_gate_runtime.acquire_control_lease(dependencies, independence)

    def _dependencies_fresh(self, lease: ControlStateCommitLease) -> bool:
        return self._control_gate_runtime._dependencies_fresh_set(lease.dependencies)

    def _dependencies_fresh_set(self, dependencies: ControlStateAuthoritativeDependencySet) -> bool:
        return self._control_gate_runtime._dependencies_fresh_set(dependencies)

    def commit(
        self, request: ControlStateCommitRequest, lease: ControlStateCommitLease,
        caller_context: AuthenticatedCallerContext | None = None,
    ) -> GateResult:
        if caller_context is None:
            caller_context = _issue_fixture_caller_context(
                self._t_to_c_channel_token, self._t_context, request.request_digest,
            )
        return self._control_gate_runtime.commit(request, lease, caller_context)
        with self._lock:
            if caller_context is None:
                # The deterministic fixture transport supplies channel identity
                # out-of-band; candidate request bytes cannot mint this context.
                caller_context = _issue_fixture_caller_context(
                    self._t_to_c_channel_token, self._t_context,
                    request.request_digest,
                )
            try:
                exact_request = (
                    type(request) is ControlStateCommitRequest
                    and type(request.command_kind) is TrustedControlCommandKind
                    and type(request.transaction) is CanonicalTransaction
                    and type(request._key) is ControllerRequestContext
                    and request._key == self._controller_key
                    and request.request_format
                    == "autodev.trusted-controller-to-control-state/v1"
                    and request.declared_t_identity == runtime_context_identity(self._t_context)
                    and request.destination_c_identity == runtime_context_identity(self._c_context)
                    and request.root_context_id == self.binding.root_context_id
                    and request.runtime_generation == self.binding.runtime_generation.value
                    and request.request_digest == RawSha256(hashlib.sha256(canonical_json_bytes((
                        request.request_format, request.command_kind, request.transaction,
                        getattr(request, "required_authoritative_binding_ids", ()),
                        getattr(request, "required_authoritative_dependencies", ()),
                        request.declared_t_identity, request.destination_c_identity,
                        request.root_context_id, request.runtime_generation,
                        request.replay_identity,
                    ))).hexdigest())
                )
                exact_caller = (
                    type(caller_context) is AuthenticatedCallerContext
                    and caller_context.context == self._t_context
                    and caller_context.request_digest == request.request_digest
                    and caller_context._channel_token is self._t_to_c_channel_token
                )
            except (AttributeError, TypeError, ValueError):
                exact_request = exact_caller = False
            if not exact_request or not exact_caller:
                return GateResult(GateResultCode.REJECTED)
            required_bindings = getattr(request, "required_authoritative_binding_ids", ())
            if required_bindings and frozenset(required_bindings) != frozenset(
                item.expected_binding_id for item in lease.dependencies.dependencies
            ):
                return GateResult(GateResultCode.LEASE_INVALID)
            required_dependencies = getattr(request, "required_authoritative_dependencies", ())
            if required_dependencies and required_dependencies != lease.dependencies.dependencies:
                return GateResult(GateResultCode.LEASE_INVALID)
            if type(lease) is not ControlStateCommitLease or not self._dependencies_fresh(lease) or not self._is_active():
                return GateResult(GateResultCode.LEASE_INVALID)
            if (lease.runtime_binding is not self.binding or lease.root_context_id != self.binding.root_context_id
                    or lease.runtime_generation != self.binding.runtime_generation
                    or lease.capability is not self._control):
                return GateResult(GateResultCode.LEASE_INVALID)
            if request.command_kind is TrustedControlCommandKind.START_OPERATION:
                started = next((
                    mutation.operation for mutation in request.transaction.mutations
                    if type(mutation) is ReplaceOperation
                    and mutation.operation.state is OperationState.PERFORMING
                ), None)
                canonical = (
                    None if started is None
                    else started.canonical_protected_start_binding
                )
                held = (
                    None if type(canonical) is not CanonicalProtectedStartBinding
                    else canonical.start_held_target_fence_binding
                )
                if (started is None or type(held) is not StartHeldTargetFenceBinding
                        or started.start_binding_id != operation_start_binding_id_v2(held)
                        or canonical.operation_start_binding_id != started.start_binding_id
                        or held.root_context_id != self.binding.root_context_id
                        or held.runtime_generation != self.binding.runtime_generation.value
                        or not self._f_read_verify_client.verify_start_held_target_fence(held)):
                    return GateResult(GateResultCode.REJECTED)
            if not lease._consume(self, self._nonce):
                return GateResult(GateResultCode.LEASE_CONSUMED)
            try:
                request_digest = request.request_digest
                audit_operation = next((
                    mutation.operation
                    for mutation in request.transaction.mutations
                    if type(mutation) in (ReplaceOperation, CreateOperationAndAdvanceMembership)
                ), None)
                audit_intent = (
                    None if audit_operation is None else audit_operation.intent
                )
                audit_operation_id = (
                    None if audit_operation is None
                    else audit_operation.intent.operation_id
                )
                audit_start_id = (
                    None if audit_operation is None
                    else audit_operation.start_binding_id
                )
                if not self._audit_ok(self._audit_event(
                    "CONTROL_STATE", request.command_kind.value, GateAuditOutcome.ATTEMPTED,
                    service=self.binding.control_state_principal, dependencies=lease.dependencies,
                    operation_id=audit_operation_id, start_id=audit_start_id,
                    action_digest=request_digest, intent=audit_intent,
                )):
                    return GateResult(GateResultCode.AUDIT_FAILURE_BEFORE_COMMIT)
                result = self.backend.apply(request.transaction)
                replay = (
                    request.command_kind is TrustedControlCommandKind.ADMIT_CONTRACT
                    and result.status is CanonicalWriteStatus.ALREADY_PRESENT
                )
                if result.status is not CanonicalWriteStatus.APPLIED and not replay:
                    outcome = GateAuditOutcome.CAS_CONFLICT if result.status is CanonicalWriteStatus.CAS_CONFLICT else GateAuditOutcome.DENIED
                    self._audit_event(
                        "CONTROL_STATE", request.command_kind.value, outcome,
                        service=self.binding.control_state_principal, dependencies=lease.dependencies,
                        operation_id=audit_operation_id, start_id=audit_start_id,
                        action_digest=request_digest, detail=result.status.value,
                        intent=audit_intent,
                    )
                    return GateResult(GateResultCode.REJECTED, result)
                if not self._audit_ok(self._audit_event(
                    "CONTROL_STATE", request.command_kind.value, GateAuditOutcome.APPLIED,
                    service=self.binding.control_state_principal, dependencies=lease.dependencies,
                    operation_id=audit_operation_id, start_id=audit_start_id,
                    action_digest=request_digest, intent=audit_intent,
                )):
                    return GateResult(GateResultCode.AUDIT_FAILURE_AFTER_COMMIT, result)
                return GateResult(GateResultCode.COMMITTED, result)
            finally:
                self.registry.release(lease.fence_token)

    def prepare_protected_start(self, operation: OperationRecord, subject: ProtectedEffectSubject,
                                fence: ActionTargetFence, control_lease: ControlStateCommitLease,
                                target_capability: TargetPublicationCapability | MergeCapability,
                                authorized_scope: MutationScope,
                                root_forbidden_scope: MutationScope, *,
                                materialization: CandidateMaterialization,
                                target_registration: AdmittedTargetRegistration,
                                base_ref: CanonicalBranchRef | None = None,
                                provenance_operation_id: OperationId | None = None,
                                request: ProtectedGateRequest | None = None,
                                caller_context: AuthenticatedCallerContext | None = None,
                                ) -> PreparedStartCommitLease:
        if type(operation) is not OperationRecord or operation.state is not OperationState.RESERVED:
            raise ValueError("only RESERVED operation may be prepared")
        if type(subject) is not ProtectedEffectSubject or type(fence) is not ActionTargetFence:
            raise TypeError("protected start inputs have wrong exact type")
        expected_capability = self._merge if subject is ProtectedEffectSubject.FAST_FORWARD_MERGE else self._publication
        if target_capability is not expected_capability:
            raise ValueError("action capability does not match exact gate/principal")
        role = (
            TrustedRuntimeRole.MERGE_GATE
            if subject is ProtectedEffectSubject.FAST_FORWARD_MERGE
            else TrustedRuntimeRole.PUBLICATION_GATE
        )
        command = (
            ProtectedGateCommand.PREPARE_MERGE
            if role is TrustedRuntimeRole.MERGE_GATE
            else ProtectedGateCommand.PREPARE_PUBLICATION
        )
        expected_request = self._build_prepared_gate_request(
            operation, subject, fence, materialization, target_registration,
            role, command,
        )
        request = expected_request if request is None else request
        if caller_context is None and type(request) is ProtectedGateRequest:
            caller_context = self._fixture_role_caller_context(role, request)
        if not self._authenticated_role_request(
            request, expected_request, role, caller_context,
        ):
            raise PermissionError("T→P/M PREPARE request authentication failed")
        if type(authorized_scope) is not MutationScope or type(root_forbidden_scope) is not MutationScope:
            raise TypeError("exact admitted/root mutation scopes required")
        if type(control_lease) is not ControlStateCommitLease or control_lease._used or not self._is_active():
            raise ValueError("exact live current control-state lease required")
        target_fact_values = {
            ("repository", fence.repository_id), ("ref", fence.repository_id, fence.ref),
            ("prepared", operation.intent.operation_id, subject.value),
        }
        if subject is not ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION:
            target_fact_values.add(("prs", fence.repository_id))
        if fence.base_ref is not None:
            target_fact_values.add(("ref", fence.repository_id, fence.base_ref))
        target_facts = frozenset(target_fact_values)
        target_token = self.registry.acquire(self, target_facts)
        if target_token is None or not self._is_active():
            if target_token is not None:
                self.registry.release(target_token)
            raise RuntimeError("target runtime is not active")
        if not self._action_start_is_valid(
            operation, subject, fence, target_capability, authorized_scope,
            root_forbidden_scope, materialization, target_registration,
            base_ref, provenance_operation_id,
        ):
            self.registry.release(target_token)
            conflict_request = self.controller._transition_unstarted_conflict(
                operation.intent.task_id, operation.intent.operation_id
            )
            self.commit(conflict_request, control_lease)
            raise ValueError("protected action preconditions are not satisfied")
        prepared = self.prepare_action(
            operation, subject, fence, control_lease.dependencies,
            target_capability.service_identity,
            materialization=materialization,
            target_registration=target_registration,
            base_ref=base_ref,
            provenance_operation_id=provenance_operation_id,
            authorized_scope=authorized_scope,
            root_forbidden_scope=root_forbidden_scope,
            target_fence_token=target_token,
            request=request, caller_context=caller_context,
        )
        verify_command = (
            ProtectedGateCommand.READ_VERIFY_MERGE_STATE
            if role is TrustedRuntimeRole.MERGE_GATE
            else ProtectedGateCommand.READ_VERIFY_PUBLICATION_STATE
        )
        verify_request = self._build_prepared_gate_request(
            operation, subject, fence, materialization, target_registration,
            role, verify_command, prepared.prepared_start_id,
            prepared_target_fence_binding=prepared.prepared_target_fence_binding,
        )
        gate_runtime = (
            self._merge_gate_runtime if role is TrustedRuntimeRole.MERGE_GATE
            else self._publication_gate_runtime
        )
        verify_context = (
            None if verify_request is None
            else self._fixture_role_caller_context(role, verify_request)
        )
        if not gate_runtime.read_verify_candidate_action(
                prepared, verify_request, verify_context):
            self.registry.release(target_token)
            raise RuntimeError("durable PREPARED verification failed")
        value = object.__new__(PreparedStartCommitLease)
        value._owner, value._nonce, value._used = self, self._nonce, False
        value.control_lease, value.action_target_fence = control_lease, fence
        value.prepared_start = prepared
        value.target_capability, value.runtime_binding = target_capability, self.binding
        value.authorized_scope, value.root_forbidden_scope = authorized_scope, root_forbidden_scope
        value.target_fence_token = target_token
        return value

    def _action_start_is_valid(
        self, operation: OperationRecord, subject: ProtectedEffectSubject,
        fence: ActionTargetFence,
        capability: TargetPublicationCapability | MergeCapability,
        authorized_scope: MutationScope, root_forbidden_scope: MutationScope,
        materialization: CandidateMaterialization,
        target: AdmittedTargetRegistration,
        base_ref: CanonicalBranchRef | None,
        provenance_operation_id: OperationId | None,
    ) -> bool:
        intent = operation.intent
        resolved = self.backend.read_resolved_target_registration(intent.target_registration_id)
        if (
            type(materialization) not in (CandidateMaterialization, AdmittedCandidateMaterialization)
            or type(target) is not AdmittedTargetRegistration
            or resolved is None or resolved.registration != target
            or materialization.repository_id != fence.repository_id
            or target.repository_id != fence.repository_id
            or materialization.task_id != intent.task_id
            or materialization.candidate_id != intent.candidate_id
            or materialization.contract_id != intent.contract_id
            or materialization.contract_raw_sha256 != intent.contract_raw_sha256
            or materialization.authorization_id != intent.authorization_id
            or materialization.target_registration_id != intent.target_registration_id
            or materialization.policy_epoch_identity != intent.policy_epoch_identity
            or not self.platform.verify_materialization(materialization)
            or not inventory_is_authorized(
                materialization.inventory, authorized_scope, root_forbidden_scope
            )
            or not inventory_is_authorized(
                materialization.inventory, target.ordinary_allowed_scope,
                target.ordinary_forbidden_scope,
            )
        ):
            return False
        if subject is ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION:
            return (
                capability is self._publication
                and fence.ref == materialization.candidate_branch
                and fence.expected_sha is None and fence.base_ref is None
                and publication_context_is_valid(
                    target, capability, materialization, intent.integration_binding
                )
            )
        if subject is ProtectedEffectSubject.PULL_REQUEST_CREATION:
            provenance = None if provenance_operation_id is None else self.platform.marker(
                provenance_operation_id,
                ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION.value,
            )
            published = None if provenance is None else provenance.preimage.effect_subject
            return (
                capability is self._publication
                and target.target_publication is not None
                and target.target_publication.service_identity == capability.service_identity
                and target.merge is not None and type(base_ref) is CanonicalBranchRef
                and base_ref in target.merge.allowed_integration_refs
                and fence.ref == materialization.candidate_branch
                and fence.expected_sha == materialization.commit
                and fence.base_ref == base_ref
                and type(published) is PublishedCandidateRefEffectSubject
                and published == PublishedCandidateRefEffectSubject(
                    fence.repository_id, materialization.candidate_branch,
                    GitRef(materialization.candidate_branch.value), materialization.commit,
                )
                and self._marker_postcondition(provenance)
            )
        provenance = None if provenance_operation_id is None else self.platform.marker(
            provenance_operation_id, ProtectedEffectSubject.PULL_REQUEST_CREATION.value
        )
        created = None if provenance is None else provenance.preimage.effect_subject
        pr = (
            None if type(created) is not CreatedCandidatePrEffectSubject
            else self.platform.pull_request(created.pull_request_number)
        )
        return (
            capability is self._merge and target.merge is not None
            and target.merge.service_identity == capability.service_identity
            and fence.ref in target.merge.allowed_integration_refs
            and fence.expected_sha is not None
            and materialization.base == fence.expected_sha
            and type(created) is CreatedCandidatePrEffectSubject
            and created.repository_id == fence.repository_id
            and created.head_ref == GitRef(materialization.candidate_branch.value)
            and created.head_sha == materialization.commit
            and created.base_ref == GitRef(fence.ref.value)
            and created.base_sha == fence.expected_sha
            and pr is not None and not pr.merged
            and self._marker_postcondition(provenance)
        )

    def prepare_action(self, operation: OperationRecord, subject: ProtectedEffectSubject,
                       fence: ActionTargetFence,
                       dependencies: ControlStateAuthoritativeDependencySet,
                       service_identity: ServicePrincipalId, *,
                       materialization: CandidateMaterialization,
                       target_registration: AdmittedTargetRegistration,
                       base_ref: CanonicalBranchRef | None,
                       provenance_operation_id: OperationId | None,
                       authorized_scope: MutationScope,
                       root_forbidden_scope: MutationScope,
                       target_fence_token: FixtureFenceToken,
                       request: ProtectedGateRequest | None = None,
                       caller_context: AuthenticatedCallerContext | None = None,
                       ) -> PreparedProtectedStart:
        if type(operation) is not OperationRecord or operation.state is not OperationState.RESERVED:
            raise ValueError("only RESERVED operation may be prepared")
        value = object.__new__(PreparedProtectedStart)
        preimage = PreparedProtectedStartPreimage(
            "autodev.prepared-protected-start/v1", operation.intent.operation_id,
            subject, fence, self.binding.root_context_id, self.binding.runtime_generation,
            self.binding.runtime_binding_id, service_identity, dependencies,
            materialization, target_registration, base_ref,
            provenance_operation_id, authorized_scope, root_forbidden_scope,
        )
        value.prepared_start_id = PreparedProtectedStartId(
            RawSha256(hashlib.sha256(canonical_json_bytes(preimage)).hexdigest())
        )
        value.operation, value.subject, value.fence = operation, subject, fence
        value.preimage, value._platform = preimage, self._f_read_verify_client
        value.prepared_target_fence_binding = None
        value._sealed = False
        role = (TrustedRuntimeRole.MERGE_GATE
                if subject is ProtectedEffectSubject.FAST_FORWARD_MERGE
                else TrustedRuntimeRole.PUBLICATION_GATE)
        command = (ProtectedGateCommand.PREPARE_MERGE
                   if role is TrustedRuntimeRole.MERGE_GATE
                   else ProtectedGateCommand.PREPARE_PUBLICATION)
        expected = self._build_prepared_gate_request(
            operation, subject, fence, materialization, target_registration,
            role, command,
        )
        request = expected if request is None else request
        if caller_context is None and type(request) is ProtectedGateRequest:
            caller_context = self._fixture_role_caller_context(role, request)
        gate_runtime = (self._merge_gate_runtime if role is TrustedRuntimeRole.MERGE_GATE
                        else self._publication_gate_runtime)
        if not gate_runtime.prepare_candidate_action(
                value, target_fence_token, request, caller_context):
            raise PermissionError("role-scoped F PREPARE was rejected")
        target_binding = self._f_read_verify_client.prepared_target_fence_binding(
            operation.intent.operation_id, subject.value,
        )
        expected_authority = self._authority_binding_identity(
            subject, service_identity,
        )
        expected_fence = RawSha256(hashlib.sha256(canonical_json_bytes((
            "autodev.fixture-target-fence/v1", fence,
        ))).hexdigest())
        if (type(target_binding) is not PreparedTargetFenceBinding
                or target_binding.fixture_substrate_identity != self._f_read_verify_client.substrate_identity
                or target_binding.authority_binding_identity != expected_authority
                or target_binding.operation_id != operation.intent.operation_id
                or target_binding.action_class != subject.value
                or target_binding.target_fence_identity != expected_fence
                or target_binding.prepared_start_id != value.prepared_start_id
                or target_binding.root_context_id != self.binding.root_context_id
                or target_binding.runtime_generation != self.binding.runtime_generation.value):
            raise RuntimeError("F PREPARED target-fence binding is unavailable or inconsistent")
        value.prepared_target_fence_binding = target_binding
        value._sealed = True
        return value

    def release_prepared_action(
        self, prepared: PreparedProtectedStart,
        request: ProtectedGateRequest | None = None,
        caller_context: AuthenticatedCallerContext | None = None,
    ) -> bool:
        if type(prepared) is not PreparedProtectedStart:
            return False
        role = (
            TrustedRuntimeRole.MERGE_GATE
            if prepared.subject is ProtectedEffectSubject.FAST_FORWARD_MERGE
            else TrustedRuntimeRole.PUBLICATION_GATE
        )
        command = (
            ProtectedGateCommand.ABORT_PREPARED_MERGE
            if role is TrustedRuntimeRole.MERGE_GATE
            else ProtectedGateCommand.ABORT_PREPARED_PUBLICATION
        )
        expected = self._build_prepared_gate_request(
            prepared.operation, prepared.subject, prepared.fence,
            prepared.preimage.materialization,
            prepared.preimage.target_registration, role, command,
            prepared_start_id=prepared.prepared_start_id,
            prepared_target_fence_binding=prepared.prepared_target_fence_binding,
        )
        request = expected if request is None else request
        if caller_context is None and type(request) is ProtectedGateRequest:
            caller_context = self._fixture_role_caller_context(role, request)
        if not self._authenticated_role_request(request, expected, role, caller_context):
            return False
        gate_runtime = (
            self._merge_gate_runtime
            if prepared.subject is ProtectedEffectSubject.FAST_FORWARD_MERGE
            else self._publication_gate_runtime
        )
        released = gate_runtime.abort_candidate_action(prepared, request, caller_context)
        return released and prepared.state is PreparedProtectedStartState.RELEASED

    def _release_durable_prepared(
        self, prepared: PreparedProtectedStart,
        token: FixtureFenceToken,
        request: ProtectedGateRequest | None = None,
        caller_context: AuthenticatedCallerContext | None = None,
    ) -> bool:
        role = (
            TrustedRuntimeRole.MERGE_GATE
            if prepared.subject is ProtectedEffectSubject.FAST_FORWARD_MERGE
            else TrustedRuntimeRole.PUBLICATION_GATE
        )
        command = (
            ProtectedGateCommand.ABORT_PREPARED_MERGE
            if role is TrustedRuntimeRole.MERGE_GATE
            else ProtectedGateCommand.ABORT_PREPARED_PUBLICATION
        )
        expected = self._build_prepared_gate_request(
            prepared.operation, prepared.subject, prepared.fence,
            prepared.preimage.materialization,
            prepared.preimage.target_registration, role, command,
            prepared_start_id=prepared.prepared_start_id,
            prepared_target_fence_binding=prepared.prepared_target_fence_binding,
        )
        request = expected if request is None else request
        if caller_context is None and type(request) is ProtectedGateRequest:
            caller_context = self._fixture_role_caller_context(role, request)
        if not self._authenticated_role_request(request, expected, role, caller_context):
            return False
        gate_runtime = (
            self._merge_gate_runtime
            if prepared.subject is ProtectedEffectSubject.FAST_FORWARD_MERGE
            else self._publication_gate_runtime
        )
        released = gate_runtime.abort_candidate_action(
            prepared, request, target_fence_token=token,
            caller_context=caller_context,
        )
        return released and prepared.state is PreparedProtectedStartState.RELEASED

    def _durable_recovery_provenance(
        self, task_id: TaskId, operation_id: OperationId,
        subject: ProtectedEffectSubject,
    ) -> tuple[
        OperationRecord, PreparedProtectedStart, PreparedProtectedStartId,
        ControlStateAuthoritativeDependencySet,
    ] | None:
        """Resolve only the exact durable start record that may drive recovery."""
        current = self.backend.read_task_working_set(task_id)
        operation = None if current is None else next((
            item for item in current.operations
            if item.intent.operation_id == operation_id
        ), None)
        if (type(operation) is not OperationRecord
                or operation.state not in (
                    OperationState.PERFORMING, OperationState.INDETERMINATE,
                )
                or type(operation.start_binding_id) is not OperationStartBindingId):
            return None
        durable = self.platform.prepared_effect_record(operation_id, subject.value)
        if (type(durable) is not PreparedProtectedStart
                or type(durable.preimage) is not PreparedProtectedStartPreimage):
            return None
        expected_prepared_id = PreparedProtectedStartId(RawSha256(
            hashlib.sha256(canonical_json_bytes(durable.preimage)).hexdigest()
        ))
        expected_service = (
            self._merge.service_identity
            if subject is ProtectedEffectSubject.FAST_FORWARD_MERGE
            else self._publication.service_identity
        )
        dependencies = durable.preimage.dependencies
        canonical_start = operation.canonical_protected_start_binding
        held_binding = (
            None if type(canonical_start) is not CanonicalProtectedStartBinding
            else canonical_start.start_held_target_fence_binding
        )
        if (
            durable.prepared_start_id != expected_prepared_id
            or type(held_binding) is not StartHeldTargetFenceBinding
            or operation.start_binding_id != operation_start_binding_id_v2(held_binding)
            or canonical_start.operation_start_binding_id != operation.start_binding_id
            or held_binding.operation_id != operation_id
            or held_binding.action_class != subject.value
            or held_binding.prepared_start_id != expected_prepared_id
            or held_binding.fixture_substrate_identity != self.platform._substrate_identity
            or held_binding.authority_binding_identity
            != self._authority_binding_identity(
                subject, expected_service, durable.preimage.runtime_binding_id,
            )
            # Recovery may observe a terminal F state while retaining the exact
            # immutable start binding.  That historical binding is provenance,
            # not start permission; current start checks remain strict below.
            or not self._f_read_verify_client.resolve_historical_start_binding(held_binding)
            or durable.operation.intent != operation.intent
            or durable.subject is not subject
            or durable.preimage.operation_id != operation_id
            or durable.preimage.action is not subject
            or durable.preimage.target_fence != durable.fence
            or durable.preimage.root_context_id != self.binding.root_context_id
            or durable.preimage.runtime_generation != self.binding.runtime_generation
            or type(durable.preimage.runtime_binding_id) is not GateRuntimeBindingId
            or durable.preimage.service_identity != expected_service
            or type(dependencies) is not ControlStateAuthoritativeDependencySet
        ):
            return None
        return operation, durable, expected_prepared_id, dependencies

    def _recover_post_start_audit_failure(
        self, prepared: PreparedStartCommitLease,
        subject: ProtectedEffectSubject,
    ) -> GateResult:
        """Fail a started, unperformed operation from its fenced durable preimage."""
        prepared_start = prepared.prepared_start
        provenance = self._durable_recovery_provenance(
            prepared_start.operation.intent.task_id,
            prepared_start.operation.intent.operation_id, subject,
        )
        if (provenance is None or provenance[1] is not prepared_start
                or not prepared.target_fence_token.active):
            return GateResult(GateResultCode.INDETERMINATE)
        operation, durable, expected_prepared_id, dependencies = provenance
        if self._post_start_audit_failure_hook is not None:
            self._post_start_audit_failure_hook()
        independence = (
            self._trusted_external_state_independence()
            if not dependencies.dependencies else None
        )
        lease = self.acquire_control_lease(
            self._control, dependencies, independence
        )
        if lease is None:
            return GateResult(GateResultCode.INDETERMINATE)
        try:
            fenced = self._durable_recovery_provenance(
                operation.intent.task_id, operation.intent.operation_id, subject,
            )
            if (fenced is None or fenced[0] != operation
                    or fenced[1] is not durable
                    or fenced[2] != expected_prepared_id
                    or fenced[3] is not dependencies):
                return GateResult(GateResultCode.INDETERMINATE)
            if (self.platform.marker(operation.intent.operation_id, subject.value)
                    is not None
                    or self.platform.prepared_effect_state(
                        operation.intent.operation_id, subject.value
                    ) != "START_HELD"):
                return GateResult(GateResultCode.INDETERMINATE)
            binding = operation.canonical_protected_start_binding.start_held_target_fence_binding
            if not self._start_held_recovery_authority.release_proven_absent(
                binding, operation, durable, prepared_start.target_fence_token,
            ):
                return GateResult(GateResultCode.INDETERMINATE)
            try:
                request = self.controller._transition_started_failed(
                    operation.intent.task_id, operation.intent.operation_id
                )
            except (TypeError, ValueError):
                return GateResult(GateResultCode.INDETERMINATE)
            committed = self.commit(request, lease)
            lease = None
            if committed.code is not GateResultCode.COMMITTED:
                return GateResult(GateResultCode.INDETERMINATE,
                                  committed.canonical_result)
            return GateResult(GateResultCode.COMMITTED,
                              committed.canonical_result)
        finally:
            if lease is not None and lease.fence_token.active:
                self.registry.release(lease.fence_token)

    def commit_protected_start(self, prepared: PreparedStartCommitLease,
                               operation: OperationRecord,
                               subject: ProtectedEffectSubject,
                               request: ProtectedGateRequest | None = None,
                               caller_context: AuthenticatedCallerContext | None = None,
                               ) -> GateResult:
        with self._lock:
            if (type(prepared) is not PreparedStartCommitLease
                    or prepared._used or prepared._owner is not self
                    or prepared._nonce is not self._nonce):
                return GateResult(GateResultCode.LEASE_CONSUMED)
            prepared_start = prepared.prepared_start
            role = (
                TrustedRuntimeRole.MERGE_GATE
                if subject is ProtectedEffectSubject.FAST_FORWARD_MERGE
                else TrustedRuntimeRole.PUBLICATION_GATE
            )
            command = (
                ProtectedGateCommand.SEAL_MERGE_FOR_START
                if role is TrustedRuntimeRole.MERGE_GATE
                else ProtectedGateCommand.SEAL_PUBLICATION_FOR_START
            )
            expected_request = self._build_prepared_gate_request(
                operation, subject, prepared.action_target_fence,
                prepared_start.preimage.materialization,
                prepared_start.preimage.target_registration,
                role, command, prepared_start.prepared_start_id,
                prepared_target_fence_binding=prepared_start.prepared_target_fence_binding,
            )
            request = expected_request if request is None else request
            if caller_context is None and type(request) is ProtectedGateRequest:
                caller_context = self._fixture_role_caller_context(role, request)
            if not self._authenticated_role_request(
                request, expected_request, role, caller_context,
            ):
                return GateResult(GateResultCode.REJECTED)
            role_request = request
            if type(prepared) is not PreparedStartCommitLease or not prepared._consume(self, self._nonce):
                return GateResult(GateResultCode.LEASE_CONSUMED)
            expected_capability = self._merge if subject is ProtectedEffectSubject.FAST_FORWARD_MERGE else self._publication
            if (prepared.runtime_binding is not self.binding or prepared.target_capability is not expected_capability
                    or not prepared.target_fence_token.active or not self._is_active()):
                return GateResult(GateResultCode.LEASE_INVALID)
            if (operation != prepared.prepared_start.operation
                    or subject is not prepared.prepared_start.subject):
                self._release_durable_prepared(
                    prepared.prepared_start, prepared.target_fence_token
                )
                self.registry.release(prepared.target_fence_token)
                return GateResult(GateResultCode.REJECTED)
            if not self._f_read_verify_client.verify_prepared_start(
                operation.intent.operation_id, subject.value,
                prepared.prepared_start.prepared_start_id,
            ):
                self.registry.release(prepared.target_fence_token)
                return GateResult(GateResultCode.LEASE_INVALID)
            try:
                request = self.controller.start_operation(
                    operation.intent.task_id, operation.intent.operation_id,
                    prepared.prepared_start.prepared_start_id,
                )
            except _DeterministicStartDenied as error:
                self._release_durable_prepared(
                    prepared.prepared_start, prepared.target_fence_token
                )
                self.registry.release(prepared.target_fence_token)
                return GateResult(GateResultCode.REJECTED, failure_code=error.failure_code)
            except (TypeError, ValueError):
                self._release_durable_prepared(
                    prepared.prepared_start, prepared.target_fence_token
                )
                self.registry.release(prepared.target_fence_token)
                return GateResult(GateResultCode.REJECTED)
            proposed = next((mutation.operation for mutation in request.transaction.mutations
                             if type(mutation) is ReplaceOperation
                             and mutation.operation.intent.operation_id == operation.intent.operation_id), None)
            expected_start_id = operation_start_binding_id(
                prepared.prepared_start.prepared_start_id
            )
            if (proposed is None or proposed.state is not OperationState.PERFORMING
                    or proposed.start_binding_id != expected_start_id):
                self._release_durable_prepared(
                    prepared.prepared_start, prepared.target_fence_token
                )
                self.registry.release(prepared.target_fence_token)
                return GateResult(GateResultCode.REJECTED)
            semantic_denial = self._protected_start_semantic_denial(
                operation, subject,
                request.transaction.expected_state_occurrence,
                prepared.control_lease.dependencies,
            )
            if semantic_denial is not None:
                if not self._release_durable_prepared(
                    prepared.prepared_start, prepared.target_fence_token
                ):
                    self.registry.release(prepared.target_fence_token)
                    return GateResult(GateResultCode.INDETERMINATE)
                self.registry.release(prepared.target_fence_token)
                return GateResult(
                    GateResultCode.REJECTED,
                    semantic_denial_code=semantic_denial,
                )
            object.__setattr__(request, "required_authoritative_dependencies",
                               prepared.control_lease.dependencies.dependencies)
            fence = prepared.action_target_fence
            if (self.platform.read_ref(fence.repository_id, fence.ref) != fence.expected_sha
                    or (fence.base_ref is not None and self.platform.read_ref(
                        fence.repository_id, fence.base_ref
                    ) != fence.base_expected_sha)):
                if not self._release_durable_prepared(
                    prepared.prepared_start, prepared.target_fence_token
                ):
                    self.registry.release(prepared.target_fence_token)
                    return GateResult(GateResultCode.INDETERMINATE)
                conflict_request = self.controller._transition_unstarted_conflict(
                    operation.intent.task_id, operation.intent.operation_id
                )
                conflict_commit = self.commit(conflict_request, prepared.control_lease)
                if conflict_commit.code is not GateResultCode.COMMITTED:
                    self.registry.release(prepared.target_fence_token)
                    return conflict_commit
                self.registry.release(prepared.target_fence_token)
                return GateResult(GateResultCode.ACTION_PRECONDITION_CONFLICT,
                                  conflict_commit.canonical_result,
                                  failure_code=G4FailureCode.ACTION_PRECONDITION_CONFLICT)

            gate_runtime = (
                self._merge_gate_runtime
                if subject is ProtectedEffectSubject.FAST_FORWARD_MERGE
                else self._publication_gate_runtime
            )
            held_binding = gate_runtime.seal_candidate_action(
                prepared.prepared_start, role_request, caller_context,
            )
            if held_binding is None:
                if (self.platform.prepared_effect_state(
                        operation.intent.operation_id, subject.value
                    ) == "PREPARED"
                        and self._release_durable_prepared(
                            prepared.prepared_start, prepared.target_fence_token
                        )):
                    self.registry.release(prepared.target_fence_token)
                return GateResult(GateResultCode.INDETERMINATE)
            decision_transaction = request.transaction
            try:
                finalized_request = self.controller.start_operation(
                    operation.intent.task_id, operation.intent.operation_id,
                    held_binding,
                )
            except (_DeterministicStartDenied, TypeError, ValueError):
                # START_HELD is deliberately not released by an ordinary role.
                return GateResult(GateResultCode.INDETERMINATE)
            # Bind the finalized full-F record to the exact occurrence/revisions
            # used for G4/G5 evaluation above.  A later controller reread must
            # never refresh the semantic pre-start decision's snapshot.
            request = object.__new__(ControlStateCommitRequest)
            object.__setattr__(request, "command_kind", finalized_request.command_kind)
            object.__setattr__(request, "_key", finalized_request._key)
            object.__setattr__(request, "transaction", CanonicalTransaction(
                decision_transaction.expected_state_occurrence,
                decision_transaction.conditions,
                finalized_request.transaction.mutations,
            ))
            proposed = next((mutation.operation for mutation in request.transaction.mutations
                             if type(mutation) is ReplaceOperation
                             and mutation.operation.intent.operation_id == operation.intent.operation_id), None)
            expected_start_id = operation_start_binding_id_v2(held_binding)
            if (proposed is None or proposed.state is not OperationState.PERFORMING
                    or proposed.start_binding_id != expected_start_id
                    or proposed.canonical_protected_start_binding
                    != CanonicalProtectedStartBinding(expected_start_id, held_binding)):
                return GateResult(GateResultCode.INDETERMINATE)
            object.__setattr__(request, "required_authoritative_dependencies",
                               prepared.control_lease.dependencies.dependencies)
            committed = self.commit(request, prepared.control_lease)
            if committed.code is not GateResultCode.COMMITTED:
                # A failed/lost C CAS leaves F START_HELD and the target fenced
                # until exact recovery determines the canonical outcome.
                return GateResult(GateResultCode.INDETERMINATE,
                                  committed.canonical_result)
            if self._fail_after_start:
                self._fail_after_start = False
                return GateResult(GateResultCode.INDETERMINATE, committed.canonical_result)
            continuation = object.__new__(LiveProtectedEffectContinuation)
            # The one-use continuation is bound to an opaque role identity,
            # never to this fixture composition runtime.
            role_identity = (
                self._merge_runtime
                if subject is ProtectedEffectSubject.FAST_FORWARD_MERGE
                else self._publication_runtime
            )
            continuation._owner, continuation._nonce, continuation._used = role_identity, self._nonce, False
            continuation.operation_id = proposed.intent.operation_id
            continuation.idempotency_key = proposed.intent.idempotency_key
            continuation.action_id = proposed.intent.action_id
            continuation.intent = proposed.intent
            continuation.start_binding_id = proposed.start_binding_id
            continuation.prepared_start_id = prepared.prepared_start.prepared_start_id
            continuation.subject = subject
            continuation.action_target_fence = fence
            continuation.integration_binding = proposed.intent.integration_binding
            continuation.authorized_scope = prepared.authorized_scope
            continuation.root_forbidden_scope = prepared.root_forbidden_scope
            continuation.dependencies = prepared.control_lease.dependencies
            continuation.target_fence_token = prepared.target_fence_token
            continuation.materialization = prepared.prepared_start.preimage.materialization
            continuation.target_registration = prepared.prepared_start.preimage.target_registration
            continuation.base_ref = prepared.prepared_start.preimage.base_ref
            continuation.provenance_operation_id = prepared.prepared_start.preimage.provenance_operation_id
            if not self._audit_ok(self._audit_event(
                "PROTECTED_START", subject.value, GateAuditOutcome.APPLIED,
                service=prepared.target_capability.service_identity,
                dependencies=prepared.control_lease.dependencies,
                operation_id=proposed.intent.operation_id,
                start_id=proposed.start_binding_id,
                action_digest=prepared.prepared_start.prepared_start_id.raw_sha256,
                intent=proposed.intent,
            )):
                if self._post_start_audit_failure_hook is not None:
                    self._post_start_audit_failure_hook()
                role = (self._merge_gate_runtime
                        if subject is ProtectedEffectSubject.FAST_FORWARD_MERGE
                        else self._publication_gate_runtime)
                observation = role._fail_started_effect_proven_absent(continuation)
                if observation.code is GateResultCode.PRECONDITION_CONFLICT:
                    current = self.backend.read_task_working_set(operation.intent.task_id)
                    current_operation = None if current is None else next((
                        item for item in current.operations
                        if item.intent.operation_id == operation.intent.operation_id
                    ), None)
                    companion = (None if current_operation is None else
                                 current_operation.canonical_protected_start_binding)
                    held = (None if type(companion) is not CanonicalProtectedStartBinding else
                            companion.start_held_target_fence_binding)
                    durable = self._f_read_verify_client.read_prepared_effect_record(
                        operation.intent.operation_id, subject.value,
                    )
                    if (type(current_operation) is not OperationRecord
                            or type(held) is not StartHeldTargetFenceBinding
                            or not self._start_held_recovery_authority.release_proven_absent(
                                held, current_operation, durable,
                                prepared.target_fence_token,
                            )):
                        self.registry.release(prepared.target_fence_token)
                        return GateResult(GateResultCode.INDETERMINATE,
                                          committed.canonical_result)
                recovery = self._trusted_controller_runtime.reconcile_started_effect_absent(
                    observation,
                )
                self.registry.release(prepared.target_fence_token)
                if recovery.code is not GateResultCode.PRECONDITION_CONFLICT:
                    return GateResult(GateResultCode.INDETERMINATE,
                                      recovery.canonical_result)
                return GateResult(GateResultCode.AUDIT_FAILURE_AFTER_COMMIT,
                                  committed.canonical_result)
            return GateResult(GateResultCode.START_COMMITTED, committed.canonical_result, continuation)

    def _build_protected_gate_request(
        self, continuation: LiveProtectedEffectContinuation,
        role: TrustedRuntimeRole,
    ) -> ProtectedGateRequest | None:
        if type(continuation) is not LiveProtectedEffectContinuation:
            return None
        if role is TrustedRuntimeRole.PUBLICATION_GATE:
            destination = self._p_context
            command = ProtectedGateCommand.EXECUTE_PUBLICATION
            if continuation.subject is ProtectedEffectSubject.FAST_FORWARD_MERGE:
                return None
        elif role is TrustedRuntimeRole.MERGE_GATE:
            destination = self._m_context
            command = ProtectedGateCommand.EXECUTE_MERGE
            if continuation.subject is not ProtectedEffectSubject.FAST_FORWARD_MERGE:
                return None
        else:
            return None
        current = self.backend.read_task_working_set(continuation.intent.task_id)
        operation = None if current is None else next((
            item for item in current.operations
            if item.intent.operation_id == continuation.operation_id
        ), None)
        companion = None if operation is None else operation.canonical_protected_start_binding
        binding = (
            None if type(companion) is not CanonicalProtectedStartBinding
            else companion.start_held_target_fence_binding
        )
        if (type(binding) is not StartHeldTargetFenceBinding
                or operation.state is not OperationState.PERFORMING
                or operation.start_binding_id != continuation.start_binding_id
                or companion.operation_start_binding_id != continuation.start_binding_id):
            return None
        fence_identity = RawSha256(hashlib.sha256(canonical_json_bytes((
            "autodev.fixture-target-fence/v1", continuation.action_target_fence,
        ))).hexdigest())
        fields = (
            "autodev.trusted-controller-to-protected-gate/v1", command,
            runtime_context_identity(self._t_context),
            runtime_context_identity(destination), self.binding.root_context_id,
            self.binding.runtime_generation.value, continuation.operation_id,
            continuation.subject.value, continuation.action_id,
            continuation.idempotency_key, continuation.intent.candidate_id,
            continuation.materialization.materialization_id,
            continuation.intent.target_registration_id,
            continuation.prepared_start_id, continuation.start_binding_id,
            None, binding,
            binding.fixture_substrate_identity,
            self._authority_binding_identity(
                continuation.subject,
                self._merge.service_identity
                if role is TrustedRuntimeRole.MERGE_GATE
                else self._publication.service_identity,
            ),
            fence_identity,
        )
        request_identity = RawSha256(hashlib.sha256(canonical_json_bytes((
            "autodev.protected-gate-request-id/v1", *fields[1:],
        ))).hexdigest())
        request_digest = RawSha256(hashlib.sha256(canonical_json_bytes((
            *fields, request_identity,
        ))).hexdigest())
        try:
            return ProtectedGateRequest(*fields, request_identity, request_digest)
        except (TypeError, ValueError):
            return None

    def _build_prepared_gate_request(
        self, operation: OperationRecord, subject: ProtectedEffectSubject,
        fence: ActionTargetFence,
        materialization: CandidateMaterialization | AdmittedCandidateMaterialization,
        target_registration: AdmittedTargetRegistration,
        role: TrustedRuntimeRole, command: ProtectedGateCommand,
        prepared_start_id: PreparedProtectedStartId | None = None,
        start_binding_id: OperationStartBindingId | None = None,
        prepared_target_fence_binding: PreparedTargetFenceBinding | None = None,
        start_held_target_fence_binding: StartHeldTargetFenceBinding | None = None,
    ) -> ProtectedGateRequest | None:
        if (type(operation) is not OperationRecord
                or type(subject) is not ProtectedEffectSubject
                or type(fence) is not ActionTargetFence
                or type(materialization) not in (
                    CandidateMaterialization, AdmittedCandidateMaterialization,
                )
                or type(target_registration) is not AdmittedTargetRegistration):
            return None
        if role is TrustedRuntimeRole.PUBLICATION_GATE:
            destination = self._p_context
            service = self._publication.service_identity
            if subject is ProtectedEffectSubject.FAST_FORWARD_MERGE:
                return None
            if command not in {
                ProtectedGateCommand.PREPARE_PUBLICATION,
                ProtectedGateCommand.ABORT_PREPARED_PUBLICATION,
                ProtectedGateCommand.SEAL_PUBLICATION_FOR_START,
                ProtectedGateCommand.READ_VERIFY_PUBLICATION_STATE,
            }:
                return None
        elif role is TrustedRuntimeRole.MERGE_GATE:
            destination = self._m_context
            service = self._merge.service_identity
            if subject is not ProtectedEffectSubject.FAST_FORWARD_MERGE:
                return None
            if command not in {
                ProtectedGateCommand.PREPARE_MERGE,
                ProtectedGateCommand.ABORT_PREPARED_MERGE,
                ProtectedGateCommand.SEAL_MERGE_FOR_START,
                ProtectedGateCommand.READ_VERIFY_MERGE_STATE,
            }:
                return None
        else:
            return None
        fields = (
            "autodev.trusted-controller-to-protected-gate/v1", command,
            runtime_context_identity(self._t_context),
            runtime_context_identity(destination), self.binding.root_context_id,
            self.binding.runtime_generation.value,
            operation.intent.operation_id, subject.value,
            operation.intent.action_id, operation.intent.idempotency_key,
            operation.intent.candidate_id, materialization.materialization_id,
            target_registration.target_registration_id, prepared_start_id,
            start_binding_id, prepared_target_fence_binding,
            start_held_target_fence_binding, self.platform._substrate_identity,
            self._authority_binding_identity(subject, service),
            RawSha256(hashlib.sha256(canonical_json_bytes((
                "autodev.fixture-target-fence/v1", fence,
            ))).hexdigest()),
        )
        request_identity = RawSha256(hashlib.sha256(canonical_json_bytes((
            "autodev.protected-gate-request-id/v1", *fields[1:],
        ))).hexdigest())
        request_digest = RawSha256(hashlib.sha256(canonical_json_bytes((
            *fields, request_identity,
        ))).hexdigest())
        try:
            return ProtectedGateRequest(*fields, request_identity, request_digest)
        except (TypeError, ValueError):
            return None

    def _fixture_role_caller_context(
        self, role: TrustedRuntimeRole, request: ProtectedGateRequest,
    ) -> AuthenticatedCallerContext:
        if type(request) is not ProtectedGateRequest:
            raise TypeError("exact protected-gate request required")
        token = (
            self._t_to_p_channel_token
            if role is TrustedRuntimeRole.PUBLICATION_GATE
            else self._t_to_m_channel_token
            if role is TrustedRuntimeRole.MERGE_GATE
            else None
        )
        if token is None:
            raise TypeError("exact P/M role required")
        return _issue_fixture_caller_context(
            token, self._t_context, request.request_digest,
        )

    def _authenticated_role_request(
        self, request: ProtectedGateRequest,
        expected_request: ProtectedGateRequest | None,
        role: TrustedRuntimeRole,
        caller_context: AuthenticatedCallerContext | None,
    ) -> bool:
        if expected_request is None or type(request) is not ProtectedGateRequest:
            return False
        if role is TrustedRuntimeRole.PUBLICATION_GATE:
            destination, token = self._p_context, self._t_to_p_channel_token
        elif role is TrustedRuntimeRole.MERGE_GATE:
            destination, token = self._m_context, self._t_to_m_channel_token
        else:
            return False
        if caller_context is None:
            caller_context = self._fixture_role_caller_context(role, request)
        return (
            type(caller_context) is AuthenticatedCallerContext
            and caller_context.context == self._t_context
            and caller_context.request_digest == request.request_digest
            and caller_context._channel_token is token
            and request == expected_request
            and request.declared_t_identity == runtime_context_identity(self._t_context)
            and request.destination_identity == runtime_context_identity(destination)
            and request.root_context_id == self.binding.root_context_id
            and request.runtime_generation == self.binding.runtime_generation.value
        )

    def _dispatch_protected_gate(
        self, request: ProtectedGateRequest,
        continuation: LiveProtectedEffectContinuation,
        role: TrustedRuntimeRole,
        caller_context: AuthenticatedCallerContext | None = None,
    ) -> GateResult:
        if type(continuation) is not LiveProtectedEffectContinuation:
            return GateResult(GateResultCode.LEASE_CONSUMED)
        expected_request = self._build_protected_gate_request(continuation, role)
        if type(request) is not ProtectedGateRequest or expected_request is None:
            return GateResult(GateResultCode.REJECTED)
        if role is TrustedRuntimeRole.PUBLICATION_GATE:
            capability = self._publication
        elif role is TrustedRuntimeRole.MERGE_GATE:
            capability = self._merge
        else:
            return GateResult(GateResultCode.REJECTED)
        if not self._authenticated_role_request(
            request, expected_request, role, caller_context,
        ):
            return GateResult(GateResultCode.REJECTED)
        # Request authentication does not replace the independent C and F checks.
        return self.perform_effect(continuation, capability)

    def perform_effect(self, continuation: LiveProtectedEffectContinuation,
                       capability: TargetPublicationCapability | MergeCapability) -> GateResult:
        with self._lock:
            separated_role = type(self).__name__ in {
                "PublicationGateRuntime", "MergeGateRuntime",
            }
            owner = (
                self.runtime_identity if separated_role else
                (self._merge_runtime if continuation.subject is ProtectedEffectSubject.FAST_FORWARD_MERGE
                 else self._publication_runtime)
            )
            expected_capability = (
                self.capability if separated_role else
                (self._merge if continuation.subject is ProtectedEffectSubject.FAST_FORWARD_MERGE
                 else self._publication)
            )
            authority_client = (
                self.authority_client if separated_role else
                (self._merge_authority_client
                 if continuation.subject is ProtectedEffectSubject.FAST_FORWARD_MERGE
                 else self._publication_authority_client)
            )
            if type(continuation) is not LiveProtectedEffectContinuation or not continuation._consume(owner, self._nonce):
                return GateResult(GateResultCode.LEASE_CONSUMED)
            fence, subject = continuation.action_target_fence, continuation.subject
            try:
                materialization = continuation.materialization
                base_ref = continuation.base_ref
                target_registration = continuation.target_registration
                provenance_operation_id = continuation.provenance_operation_id
                if not continuation.target_fence_token.active or not self._is_active():
                    return GateResult(GateResultCode.LEASE_INVALID)
                durable = self._f_read_verify_client.read_prepared_effect_record(
                    continuation.operation_id, subject.value
                )
                if (type(durable) is not PreparedProtectedStart
                        or durable.prepared_start_id != continuation.prepared_start_id
                        or durable.state not in (
                            PreparedProtectedStartState.START_HELD,
                            PreparedProtectedStartState.PREPARED,
                            PreparedProtectedStartState.CONSUMED,
                        )):
                    return GateResult(GateResultCode.INDETERMINATE)
                current = self.backend.read_task_working_set(continuation.intent.task_id)
                canonical_operation = None if current is None else next((
                    item for item in current.operations
                    if item.intent.operation_id == continuation.operation_id
                ), None)
                canonical_start = (
                    None if canonical_operation is None
                    else canonical_operation.canonical_protected_start_binding
                )
                held_binding = (
                    None if type(canonical_start) is not CanonicalProtectedStartBinding
                    else canonical_start.start_held_target_fence_binding
                )
                if (canonical_operation is None
                        or canonical_operation.state is not OperationState.PERFORMING
                        or canonical_operation.start_binding_id != continuation.start_binding_id
                        or type(held_binding) is not StartHeldTargetFenceBinding
                        or canonical_start.operation_start_binding_id != continuation.start_binding_id
                        or not self._f_read_verify_client.verify_start_held_target_fence(held_binding)
                        or held_binding.prepared_start_id != continuation.prepared_start_id
                        or held_binding.operation_id != continuation.operation_id
                        or held_binding.action_class != subject.value):
                    return GateResult(GateResultCode.INDETERMINATE)
                if not self._dependencies_fresh_set(continuation.dependencies):
                    return GateResult(GateResultCode.INDETERMINATE)
                if type(materialization) not in (CandidateMaterialization, AdmittedCandidateMaterialization):
                    return GateResult(GateResultCode.REJECTED)
                intent = continuation.intent
                if (
                    materialization.repository_id != fence.repository_id
                    or materialization.task_id != intent.task_id
                    or materialization.candidate_id != intent.candidate_id
                    or materialization.contract_id != intent.contract_id
                    or materialization.contract_raw_sha256 != intent.contract_raw_sha256
                    or materialization.authorization_id != intent.authorization_id
                    or materialization.target_registration_id != intent.target_registration_id
                    or materialization.policy_epoch_identity != intent.policy_epoch_identity
                ):
                    return GateResult(GateResultCode.REJECTED)
                if not self._f_read_verify_client.verify_materialization(materialization):
                    return GateResult(GateResultCode.REJECTED)
                if not inventory_is_authorized(materialization.inventory, continuation.authorized_scope,
                                               continuation.root_forbidden_scope):
                    return GateResult(GateResultCode.REJECTED)
                if (type(target_registration) is not AdmittedTargetRegistration
                        or target_registration.repository_id != fence.repository_id
                        or target_registration.target_registration_id != intent.target_registration_id
                        or target_registration.policy_epoch_identity != intent.policy_epoch_identity
                        or not inventory_is_authorized(
                            materialization.inventory,
                            target_registration.ordinary_allowed_scope,
                            target_registration.ordinary_forbidden_scope,
                        )):
                    return GateResult(GateResultCode.REJECTED)
                resolved_target = self.backend.read_resolved_target_registration(
                    intent.target_registration_id
                )
                if (resolved_target is None
                        or resolved_target.registration != target_registration):
                    return GateResult(GateResultCode.REJECTED)
                effect_subject: PublishedCandidateRefEffectSubject | CreatedCandidatePrEffectSubject | FastForwardMergeEffectSubject
                current = self._f_read_verify_client.read_marker(
                    continuation.operation_id, subject.value
                )
                prerequisite_marker_id = None

                if subject is ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION:
                    if (capability is not expected_capability
                            or type(target_registration) is not AdmittedTargetRegistration
                            or fence.ref != materialization.candidate_branch
                            or fence.expected_sha is not None
                            or not publication_context_is_valid(target_registration, capability, materialization,
                                                                continuation.integration_binding)):
                        return GateResult(GateResultCode.REJECTED)
                    effect_subject = PublishedCandidateRefEffectSubject(
                        fence.repository_id, materialization.candidate_branch,
                        GitRef(materialization.candidate_branch.value), materialization.commit,
                    )
                elif subject is ProtectedEffectSubject.PULL_REQUEST_CREATION:
                    provenance = None if provenance_operation_id is None else self._f_read_verify_client.read_marker(
                        provenance_operation_id, ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION.value
                    )
                    published = None if provenance is None else provenance.preimage.effect_subject
                    if (capability is not expected_capability
                            or type(base_ref) is not CanonicalBranchRef
                            or base_ref != fence.base_ref
                            or type(target_registration) is not AdmittedTargetRegistration
                            or target_registration.target_publication.service_identity != capability.service_identity
                            or target_registration.merge is None
                            or base_ref not in target_registration.merge.allowed_integration_refs
                            or fence.ref != materialization.candidate_branch
                            or fence.expected_sha != materialization.commit
                            or type(published) is not PublishedCandidateRefEffectSubject
                            or published != PublishedCandidateRefEffectSubject(
                                fence.repository_id, materialization.candidate_branch,
                                GitRef(materialization.candidate_branch.value), materialization.commit,
                            )
                            or not self._marker_postcondition(provenance)):
                        return GateResult(GateResultCode.REJECTED)
                    prerequisite_marker_id = provenance.marker_id
                    base_sha = self._f_read_verify_client.read_ref(fence.repository_id, base_ref)
                    if base_sha is None or base_sha != fence.base_expected_sha:
                        return GateResult(GateResultCode.PRECONDITION_CONFLICT)
                    existing_subject = None if current is None else current.preimage.effect_subject
                    if current is not None and type(existing_subject) is not CreatedCandidatePrEffectSubject:
                        return GateResult(GateResultCode.INDETERMINATE)
                    number = (
                        self._f_read_verify_client.read_next_pull_request_number()
                        if existing_subject is None
                        else existing_subject.pull_request_number.value
                    )
                    effect_subject = CreatedCandidatePrEffectSubject(
                        fence.repository_id, GitHubPullRequestNumber(number),
                        GitRef(materialization.candidate_branch.value), materialization.commit,
                        GitRef(base_ref.value), base_sha,
                    )
                else:
                    provenance = None if provenance_operation_id is None else self._f_read_verify_client.read_marker(
                        provenance_operation_id, ProtectedEffectSubject.PULL_REQUEST_CREATION.value
                    )
                    created = None if provenance is None else provenance.preimage.effect_subject
                    if (capability is not expected_capability
                            or type(target_registration) is not AdmittedTargetRegistration
                            or target_registration.merge is None
                            or target_registration.merge.service_identity != capability.service_identity
                            or fence.ref not in target_registration.merge.allowed_integration_refs
                            or type(created) is not CreatedCandidatePrEffectSubject
                            or created.repository_id != fence.repository_id
                            or created.head_ref != GitRef(materialization.candidate_branch.value)
                            or created.head_sha != materialization.commit
                            or created.base_ref != GitRef(fence.ref.value)
                            or created.base_sha != fence.expected_sha
                            or not self._marker_postcondition(provenance)):
                        return GateResult(GateResultCode.REJECTED)
                    prerequisite_marker_id = provenance.marker_id
                    effect_subject = FastForwardMergeEffectSubject(
                        fence.repository_id, created.pull_request_number,
                        GitRef(fence.ref.value), fence.expected_sha, materialization.commit,
                    )

                pre_identity = RawSha256(hashlib.sha256(canonical_json_bytes(("pre", fence))).hexdigest())
                post_identity = RawSha256(hashlib.sha256(canonical_json_bytes(("post", effect_subject))).hexdigest())
                action_digest = RawSha256(hashlib.sha256(canonical_json_bytes((
                    subject, continuation.action_id, materialization.materialization_id,
                    materialization.inventory.inventory_id, effect_subject,
                ))).hexdigest())
                marker = build_protected_effect_marker(ProtectedEffectMarkerPreimage(
                    "autodev.protected-effect-marker/v1", subject.value,
                    continuation.operation_id, continuation.idempotency_key,
                    continuation.action_id, action_digest, materialization.materialization_id,
                    materialization.inventory.inventory_id, continuation.prepared_start_id,
                    self.binding.root_context_id, self.binding.runtime_generation.value,
                    capability.service_identity, effect_subject, pre_identity, post_identity,
                    prerequisite_marker_id,
                ))
                if current is not None:
                    if current != marker or not self._marker_postcondition(current):
                        return GateResult(GateResultCode.INDETERMINATE)
                    if not self._audit_ok(self._audit_event(
                        subject.value, continuation.action_id.value,
                        GateAuditOutcome.ALREADY_APPLIED,
                        service=capability.service_identity,
                        dependencies=continuation.dependencies,
                        operation_id=continuation.operation_id,
                        start_id=continuation.start_binding_id, marker=current,
                        action_digest=action_digest,
                        result_identity=current.marker_id.raw_sha256.value,
                        intent=continuation.intent, materialization=materialization,
                    )):
                        return GateResult(GateResultCode.AUDIT_FAILURE_AFTER_COMMIT)
                    return GateResult(GateResultCode.ALREADY_APPLIED)

                if subject is ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION:
                    applied = authority_client.execute_candidate_ref_publication(
                        fence.repository_id, materialization.candidate_branch,
                        materialization.commit, marker,
                        fence_token=continuation.target_fence_token,
                    )
                elif subject is ProtectedEffectSubject.PULL_REQUEST_CREATION:
                    applied = authority_client.execute_candidate_pr_creation(
                        fence.repository_id, materialization.candidate_branch, base_ref,
                        materialization.commit, marker,
                        fence_token=continuation.target_fence_token,
                    ) is not None
                else:
                    applied = authority_client.execute_fast_forward_merge(
                        fence.repository_id, fence.ref, fence.expected_sha,
                        materialization.commit, materialization.base,
                        effect_subject.pull_request_number.value, marker,
                        fence_token=continuation.target_fence_token,
                    )
                if not applied:
                    return self._fail_started_effect_proven_absent(continuation)

                if not self._audit_ok(self._audit_event(
                    subject.value, continuation.action_id.value, GateAuditOutcome.APPLIED,
                    service=capability.service_identity, dependencies=continuation.dependencies,
                    operation_id=continuation.operation_id,
                    start_id=continuation.start_binding_id, marker=marker,
                    action_digest=action_digest,
                    result_identity=marker.marker_id.raw_sha256.value,
                    intent=continuation.intent, materialization=materialization,
                )):
                    return GateResult(GateResultCode.AUDIT_FAILURE_AFTER_COMMIT)
                return GateResult(GateResultCode.EFFECT_SUCCEEDED)
            except Exception:
                return GateResult(GateResultCode.INDETERMINATE)
            finally:
                (self.fence_client.release if separated_role
                 else self.registry.release)(continuation.target_fence_token)

    def _fail_started_effect_proven_absent(
        self, continuation: LiveProtectedEffectContinuation,
    ) -> GateResult:
        if self._f_read_verify_client.read_marker(
            continuation.operation_id, continuation.subject.value
        ) is not None:
            return GateResult(GateResultCode.INDETERMINATE)
        current = self.backend.read_task_working_set(continuation.intent.task_id)
        operation = None if current is None else next((
            item for item in current.operations
            if item.intent.operation_id == continuation.operation_id
        ), None)
        canonical = None if operation is None else operation.canonical_protected_start_binding
        durable = self._f_read_verify_client.read_prepared_effect_record(
            continuation.operation_id, continuation.subject.value,
        )
        if (type(canonical) is not CanonicalProtectedStartBinding
                or operation.start_binding_id != continuation.start_binding_id
                or not self._start_held_recovery_authority.release_proven_absent(
                    canonical.start_held_target_fence_binding, operation, durable,
                    continuation.target_fence_token,
                )):
            return GateResult(GateResultCode.INDETERMINATE)
        independence = (
            self.attest_external_state_independence()
            if not continuation.dependencies.dependencies else None
        )
        lease = self.acquire_control_lease(
            self._control, continuation.dependencies, independence
        )
        if lease is None:
            return GateResult(GateResultCode.INDETERMINATE)
        try:
            request = self.controller._transition_started_failed(
                continuation.intent.task_id, continuation.operation_id
            )
        except (TypeError, ValueError):
            self.registry.release(lease.fence_token)
            return GateResult(GateResultCode.INDETERMINATE)
        committed = self.commit(request, lease)
        if committed.code is not GateResultCode.COMMITTED:
            return GateResult(GateResultCode.INDETERMINATE, committed.canonical_result)
        if not self._audit_ok(self._audit_event(
            continuation.subject.value, continuation.action_id.value,
            GateAuditOutcome.PRECONDITION_CONFLICT,
            service=(
                self.binding.merge_principal
                if continuation.subject is ProtectedEffectSubject.FAST_FORWARD_MERGE
                else self.binding.publication_principal
            ),
            dependencies=continuation.dependencies,
            operation_id=continuation.operation_id,
            start_id=continuation.start_binding_id,
            intent=continuation.intent,
        )):
            return GateResult(GateResultCode.AUDIT_FAILURE_AFTER_COMMIT, committed.canonical_result)
        return GateResult(GateResultCode.PRECONDITION_CONFLICT, committed.canonical_result)

    def _marker_postcondition(self, marker: ProtectedEffectMarker) -> bool:
        return self._f_read_verify_client.verify_marker_postcondition(marker)

    def reconcile_recovered_effect(
        self, task_id: TaskId, operation_id: OperationId,
        subject: ProtectedEffectSubject,
    ) -> GateResult:
        """Reconcile only from canonical operation and exact durable start provenance."""
        if not self._is_active():
            return GateResult(GateResultCode.LEASE_INVALID)
        if type(task_id) is not TaskId or type(operation_id) is not OperationId:
            raise TypeError("exact recovery identities required")
        if type(subject) is not ProtectedEffectSubject:
            raise TypeError("subject has wrong exact type")
        provenance = self._durable_recovery_provenance(
            task_id, operation_id, subject
        )
        if provenance is None:
            return GateResult(GateResultCode.INDETERMINATE)
        operation, durable, expected_prepared_id, dependencies = provenance
        fence = durable.fence
        recovery_fact_values = {
            ("prepared", operation_id, subject.value),
            ("repository", fence.repository_id),
            ("ref", fence.repository_id, fence.ref),
        }
        if subject is not ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION:
            recovery_fact_values.add(("prs", fence.repository_id))
        if fence.base_ref is not None:
            recovery_fact_values.add(("ref", fence.repository_id, fence.base_ref))
        recovery_token = self.registry.acquire(self, frozenset(recovery_fact_values))
        if recovery_token is None or not self._is_active():
            if recovery_token is not None:
                self.registry.release(recovery_token)
            return GateResult(GateResultCode.INDETERMINATE)
        try:
            if self._recovery_fence_hook is not None:
                self._recovery_fence_hook()
            fenced = self._durable_recovery_provenance(
                task_id, operation_id, subject
            )
            if (fenced is None or fenced[0] != operation
                    or fenced[1] is not durable
                    or fenced[2] != expected_prepared_id
                    or fenced[3] is not dependencies):
                return GateResult(GateResultCode.INDETERMINATE)
            marker = self._f_read_verify_client.read_marker(operation_id, subject.value)
            prepared_state = self._f_read_verify_client.read_prepared_effect_state(
                operation_id, subject.value
            )
            marker_coherent = (
                marker is None or (
                    marker.preimage.operation_id == operation_id
                    and marker.preimage.gate_action == subject.value
                    and marker.preimage.prepared_start_id == expected_prepared_id
                )
            )
            if not marker_coherent:
                return GateResult(GateResultCode.INDETERMINATE)
            if marker is None and prepared_state in ("PREPARED", "START_HELD", "RELEASED"):
                canonical = operation.canonical_protected_start_binding
                held = (None if type(canonical) is not CanonicalProtectedStartBinding
                        else canonical.start_held_target_fence_binding)
                if type(held) is not StartHeldTargetFenceBinding:
                    return GateResult(GateResultCode.INDETERMINATE)
                role_runtime = (
                    self._merge_gate_runtime
                    if subject is ProtectedEffectSubject.FAST_FORWARD_MERGE
                    else self._publication_gate_runtime
                )
                if prepared_state == "PREPARED":
                    if not role_runtime.abort_prepared_candidate_action(
                            durable, recovery_token):
                        return GateResult(GateResultCode.INDETERMINATE)
                elif not self._f_read_verify_client.resolve_historical_start_binding(held):
                    return GateResult(GateResultCode.INDETERMINATE)
                elif prepared_state == "START_HELD":
                    if not self._start_held_recovery_authority.release_proven_absent(
                            held, operation, durable, recovery_token):
                        return GateResult(GateResultCode.INDETERMINATE)
            elif marker is None or prepared_state != "CONSUMED":
                return GateResult(GateResultCode.INDETERMINATE)
            return self._trusted_controller_runtime.reconcile_recovered_effect(
                task_id, operation_id, subject,
            )
        finally:
            self.registry.release(recovery_token)

    def restart(self) -> "FixtureProtectedGateRuntime":
        previous = (
            self._control_runtime, self._publication_runtime, self._merge_runtime
        )
        self.registry.retire_owner_for_restart(self)
        restarted = FixtureProtectedGateRuntime(
            GateRuntimeBinding(self.binding.root_context_id,
                               self.binding.runtime_generation,
                               self.binding.control_state_principal, self.binding.publication_principal,
                               self.binding.merge_principal),
            self.backend, self.platform, self.audit, self.registry,
            object_store=self._object_store,
            _restart_from=previous,
        )
        restarted._profiles.update(self._profiles)
        restarted._readers.update(self._readers)
        restarted._fixture_transports.update(self._fixture_transports)
        restarted._authorization_contexts.update(self._authorization_contexts)
        restarted._contract_contexts.update(self._contract_contexts)
        restarted._evidence_contexts.update(self._evidence_contexts)
        restarted._completion_contexts.update(self._completion_contexts)
        restarted._semantic_contexts.update(self._semantic_contexts)
        return restarted

    def fail_after_start_commit_for_test(self) -> None:
        """Inject process loss immediately after the canonical start linearization."""
        self._fail_after_start = True

    def set_recovery_fence_hook_for_test(self, hook) -> None:
        """Run one fixture test hook after the exact recovery fence is live."""
        if hook is not None and not callable(hook):
            raise TypeError("recovery fence hook must be callable or None")
        self._recovery_fence_hook = hook

class _FixtureControlStateClient:
    """Deterministic T→C transport holding only C and its channel binding."""

    __slots__ = ("_control", "_channel_token", "_t_context")

    def __init__(
        self, control: ControlStateGateRuntime, channel_token: object,
        t_context: RuntimeSecurityContext,
    ) -> None:
        self._control, self._channel_token, self._t_context = control, channel_token, t_context

    def commit_control_state(self, request, lease, caller_context=None) -> GateResult:
        if caller_context is None and type(request) is ControlStateCommitRequest:
            caller_context = _issue_fixture_caller_context(
                self._channel_token, self._t_context, request.request_digest,
            )
        return self._control.commit_control_state(request, lease, caller_context)

    def commit_authenticated_request(
        self, request: ControlStateCommitRequest,
        dependencies: ControlStateAuthoritativeDependencySet,
    ) -> GateResult:
        if type(request) is not ControlStateCommitRequest:
            return GateResult(GateResultCode.REJECTED)
        caller_context = _issue_fixture_caller_context(
            self._channel_token, self._t_context, request.request_digest,
        )
        return self._control.commit_authenticated_request(
            request, dependencies, caller_context,
        )


class _FixtureRoleCallerVerifier:
    """External fixture verifier; candidate P/M receive no channel secret."""

    __slots__ = ("_channel_token", "_context")

    def __init__(self, channel_token: object, context: RuntimeSecurityContext) -> None:
        self._channel_token, self._context = channel_token, context

    def verify(
        self, request_digest: RawSha256,
        caller_context: AuthenticatedCallerContext | None,
    ) -> bool:
        return (
            type(request_digest) is RawSha256
            and type(caller_context) is AuthenticatedCallerContext
            and caller_context.context == self._context
            and caller_context.request_digest == request_digest
            and caller_context._channel_token is self._channel_token
        )


class _ProtectedGateRoleRuntime:
    """Shared implementation data for one narrowly bound P or M candidate role."""

    __slots__ = (
        "binding", "read_state", "audit", "capability", "runtime_identity",
        "_nonce", "_t_context", "_role_context", "caller_verifier",
        "_f_read_verify_client", "authority_client", "fence_client",
        "dependency_profiles", "dependency_transports", "_lock",
        "_prepared_target_tokens", "_prepared_records",
    )
    role: TrustedRuntimeRole
    execute_command: ProtectedGateCommand
    prepare_command: ProtectedGateCommand
    abort_command: ProtectedGateCommand
    seal_command: ProtectedGateCommand
    read_verify_command: ProtectedGateCommand
    allowed_commands: frozenset[ProtectedGateCommand]
    allowed_subjects: frozenset[ProtectedEffectSubject]

    def __init__(
        self, binding: GateRuntimeBinding, read_state: CanonicalStartReadContract,
        audit: GateAuditContract, capability: TargetPublicationCapability | MergeCapability,
        runtime_identity: object, nonce: object,
        t_context: RuntimeSecurityContext, role_context: RuntimeSecurityContext,
        caller_verifier: AuthenticatedCallerVerifier,
        f_read_verify_client: FixtureReadVerifyClient,
        authority_client: PublicationAuthorityContract | MergeAuthorityContract,
        fence_client: GateRoleFenceContract, dependency_profiles: dict,
        dependency_transports: dict,
    ) -> None:
        if (type(binding) is not GateRuntimeBinding
                or not isinstance(read_state, CanonicalStartReadContract)
                or not isinstance(audit, GateAuditContract)
                or type(t_context) is not RuntimeSecurityContext
                or t_context.role is not TrustedRuntimeRole.CONTROLLER
                or type(role_context) is not RuntimeSecurityContext
                or role_context.role is not self.role
                or not isinstance(caller_verifier, AuthenticatedCallerVerifier)
                or not isinstance(f_read_verify_client, FixtureReadVerifyClient)
                or not isinstance(fence_client, GateRoleFenceContract)):
            raise TypeError("P/M runtime requires exact role-scoped read and identity dependencies")
        if self.role is TrustedRuntimeRole.PUBLICATION_GATE:
            valid = (
                type(capability) is TargetPublicationCapability
                and isinstance(authority_client, PublicationAuthorityContract)
            )
        else:
            valid = (
                type(capability) is MergeCapability
                and isinstance(authority_client, MergeAuthorityContract)
            )
        if not valid:
            raise TypeError("P/M runtime received cross-role capability or authority")
        self.binding, self.read_state, self.audit = binding, read_state, audit
        self.capability, self.runtime_identity, self._nonce = capability, runtime_identity, nonce
        self._t_context, self._role_context = t_context, role_context
        self.caller_verifier = caller_verifier
        self._f_read_verify_client, self.authority_client = f_read_verify_client, authority_client
        self.fence_client = fence_client
        self.dependency_profiles, self.dependency_transports = dependency_profiles, dependency_transports
        self._lock = RLock()
        # Target fence tokens remain inside their owning P/M process role.
        # T carries only the prepared ID and immutable F bindings.
        self._prepared_target_tokens: dict[PreparedProtectedStartId, FixtureFenceToken] = {}
        self._prepared_records: dict[PreparedProtectedStartId, PreparedProtectedStart] = {}

    @property
    def backend(self) -> CanonicalStartReadContract:
        """Compatibility spelling used by the shared deterministic effect routine."""
        return self.read_state

    def _is_active(self) -> bool:
        return self.fence_client.is_active()

    def _verify_current_start_or_consumed_exact_replay(
        self, held: StartHeldTargetFenceBinding,
    ) -> bool:
        """Accept START_HELD, or only an already-proven exact consumed replay."""
        if self._f_read_verify_client.verify_start_held_target_fence(held):
            return True
        if (
            type(held) is not StartHeldTargetFenceBinding
            or self._f_read_verify_client.read_prepared_effect_state(
                held.operation_id, held.action_class,
            ) != PreparedProtectedStartState.CONSUMED.value
            or not self._f_read_verify_client.resolve_historical_start_binding(held)
        ):
            return False
        marker = self._f_read_verify_client.read_marker(
            held.operation_id, held.action_class,
        )
        return (
            type(marker) is ProtectedEffectMarker
            and marker.preimage.operation_id == held.operation_id
            and marker.preimage.gate_action == held.action_class
            and marker.preimage.prepared_start_id == held.prepared_start_id
            and marker.preimage.root_context_id == held.root_context_id
            and marker.preimage.runtime_generation == held.runtime_generation
            and self._marker_postcondition(marker)
        )

    @staticmethod
    def _target_facts(prepared: PreparedProtectedStart) -> frozenset[tuple]:
        fence = prepared.fence
        facts = {
            ("repository", fence.repository_id),
            ("ref", fence.repository_id, fence.ref),
            ("prepared", prepared.operation.intent.operation_id, prepared.subject.value),
        }
        if prepared.subject is not ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION:
            facts.add(("prs", fence.repository_id))
        if fence.base_ref is not None:
            facts.add(("ref", fence.repository_id, fence.base_ref))
        return frozenset(facts)

    def prepare_start(
        self, prepared: PreparedProtectedStart, request: ProtectedGateRequest,
        caller_context: AuthenticatedCallerContext | None = None,
    ) -> PreparedTargetFenceBinding | None:
        """P/M-owned PREPARE and target fencing; no fence capability leaves this role."""
        if (type(prepared) is not PreparedProtectedStart
                or prepared.subject not in self.allowed_subjects
                or not self._verify_prepared_command(
                    prepared, self.prepare_command, request, caller_context)):
            return None
        with self._lock:
            if prepared.prepared_start_id in self._prepared_target_tokens:
                return None
            # P/M creates and owns a private immutable copy.  The T-supplied
            # request/value cannot mutate the record retained by this role or
            # the durable fixture F store after PREPARE.
            role_prepared = object.__new__(PreparedProtectedStart)
            role_prepared.prepared_start_id = prepared.prepared_start_id
            role_prepared.operation = prepared.operation
            role_prepared.subject = prepared.subject
            role_prepared.fence = prepared.fence
            role_prepared.preimage = prepared.preimage
            role_prepared._platform = self._f_read_verify_client
            role_prepared.prepared_target_fence_binding = None
            role_prepared._sealed = False
            token = self.fence_client.acquire(self._target_facts(prepared))
            if type(token) is not FixtureFenceToken or not token.active:
                return None
            if not self.prepare_candidate_action(
                    role_prepared, token, request, caller_context):
                self.fence_client.release(token)
                return None
            binding = self._f_read_verify_client.prepared_target_fence_binding(
                role_prepared.operation.intent.operation_id, role_prepared.subject.value,
            )
            if (type(binding) is not PreparedTargetFenceBinding
                    or binding.prepared_start_id != role_prepared.prepared_start_id
                    or not self._f_read_verify_client.verify_prepared_target_fence(binding)):
                # F may have committed PREPARED even when its read response
                # is unavailable.  Retain the role-owned target fence and
                # fail closed; ordinary T cannot infer absence and release it.
                self._prepared_target_tokens[role_prepared.prepared_start_id] = token
                self._prepared_records[role_prepared.prepared_start_id] = role_prepared
                return None
            role_prepared.prepared_target_fence_binding = binding
            role_prepared._sealed = True
            self._prepared_target_tokens[role_prepared.prepared_start_id] = token
            self._prepared_records[role_prepared.prepared_start_id] = role_prepared
            return binding

    def abort_start(
        self, prepared_start_id: PreparedProtectedStartId,
        request: ProtectedGateRequest,
        caller_context: AuthenticatedCallerContext | None = None,
    ) -> bool:
        """Abort only this role's PREPARED record; START_HELD is never released here."""
        if type(prepared_start_id) is not PreparedProtectedStartId:
            return False
        with self._lock:
            prepared = self._prepared_records.get(prepared_start_id)
            token = self._prepared_target_tokens.get(prepared_start_id)
            if (prepared is None or token is None or not token.active
                    or not self.abort_candidate_action(
                        prepared, request, target_fence_token=token,
                        caller_context=caller_context)):
                return False
            self.fence_client.release(token)
            self._prepared_target_tokens.pop(prepared_start_id, None)
            self._prepared_records.pop(prepared_start_id, None)
            return prepared.state is PreparedProtectedStartState.RELEASED

    def seal_start(
        self, prepared_start_id: PreparedProtectedStartId,
        request: ProtectedGateRequest,
        caller_context: AuthenticatedCallerContext | None = None,
    ) -> StartHeldTargetFenceBinding | None:
        """Linearize this P/M PREPARED record to START_HELD, retaining its fence."""
        if type(prepared_start_id) is not PreparedProtectedStartId:
            return None
        with self._lock:
            prepared = self._prepared_records.get(prepared_start_id)
            token = self._prepared_target_tokens.get(prepared_start_id)
            if (prepared is None or token is None or not token.active
                    or not self._verify_prepared_command(
                        prepared, self.seal_command, request, caller_context)):
                return None
            return self.seal_candidate_action(prepared, request, caller_context)

    def _continuation_for_started_operation(
        self, prepared_start_id: PreparedProtectedStartId,
        expected_start_binding_id: OperationStartBindingId,
    ) -> LiveProtectedEffectContinuation | None:
        prepared = self._prepared_records.get(prepared_start_id)
        token = self._prepared_target_tokens.get(prepared_start_id)
        if (prepared is None or token is None or not token.active
                or type(expected_start_binding_id) is not OperationStartBindingId):
            return None
        working = self.read_state.read_task_working_set(prepared.operation.intent.task_id)
        operation = None if working is None else next((
            item for item in working.operations
            if item.intent.operation_id == prepared.operation.intent.operation_id
        ), None)
        companion = None if operation is None else operation.canonical_protected_start_binding
        held = None if type(companion) is not CanonicalProtectedStartBinding else companion.start_held_target_fence_binding
        if (type(operation) is not OperationRecord
                or operation.state is not OperationState.PERFORMING
                or operation.start_binding_id != expected_start_binding_id
                or type(companion) is not CanonicalProtectedStartBinding
                or companion.operation_start_binding_id != expected_start_binding_id
                or type(held) is not StartHeldTargetFenceBinding
                or held.prepared_start_id != prepared_start_id
                or operation_start_binding_id_v2(held) != expected_start_binding_id
                or not self._verify_current_start_or_consumed_exact_replay(held)):
            return None
        value = object.__new__(LiveProtectedEffectContinuation)
        value._owner, value._nonce, value._used = self.runtime_identity, self._nonce, False
        value.operation_id = operation.intent.operation_id
        value.idempotency_key = operation.intent.idempotency_key
        value.action_id = operation.intent.action_id
        value.intent = operation.intent
        value.start_binding_id = expected_start_binding_id
        value.prepared_start_id = prepared_start_id
        value.subject = prepared.subject
        value.action_target_fence = prepared.fence
        value.integration_binding = operation.intent.integration_binding
        value.authorized_scope = prepared.preimage.authorized_scope
        value.root_forbidden_scope = prepared.preimage.root_forbidden_scope
        value.dependencies = prepared.preimage.dependencies
        value.target_fence_token = token
        value.materialization = prepared.preimage.materialization
        value.target_registration = prepared.preimage.target_registration
        value.base_ref = prepared.preimage.base_ref
        value.provenance_operation_id = prepared.preimage.provenance_operation_id
        return value

    def execute_started(
        self, prepared_start_id: PreparedProtectedStartId,
        expected_start_binding_id: OperationStartBindingId,
        caller_context: AuthenticatedCallerContext | None = None,
    ) -> GateResult:
        """Execute only after independent canonical and F verification in this role."""
        continuation = self._continuation_for_started_operation(
            prepared_start_id, expected_start_binding_id,
        )
        if continuation is None:
            return GateResult(GateResultCode.REJECTED)
        request = self._build_execute_request(continuation)
        if (request is None or not self.caller_verifier.verify(
                request.request_digest, caller_context)
                or request.declared_t_identity != runtime_context_identity(self._t_context)
                or request.destination_identity != runtime_context_identity(self._role_context)):
            return GateResult(GateResultCode.REJECTED)
        if self.role is TrustedRuntimeRole.PUBLICATION_GATE:
            result = self.perform_publication(continuation, caller_context)
        else:
            result = self.perform_merge(continuation, caller_context)
        if result.code in (
                GateResultCode.EFFECT_SUCCEEDED, GateResultCode.EFFECT_FAILED,
                GateResultCode.ALREADY_APPLIED, GateResultCode.INDETERMINATE,
                GateResultCode.AUDIT_FAILURE_AFTER_COMMIT,
                GateResultCode.PRECONDITION_CONFLICT):
            with self._lock:
                self._prepared_target_tokens.pop(prepared_start_id, None)
                self._prepared_records.pop(prepared_start_id, None)
        # The role-local continuation contains the private fence token.  It
        # never crosses back into T or the authenticated transport response.
        return GateResult(
            result.code, result.canonical_result,
            failure_code=result.failure_code,
            semantic_denial_code=result.semantic_denial_code,
        )

    def _prepared_command_request(
        self, prepared: PreparedProtectedStart,
        command: ProtectedGateCommand,
    ) -> ProtectedGateRequest | None:
        if (type(prepared) is not PreparedProtectedStart
                or command not in self.allowed_commands
                or prepared.subject not in self.allowed_subjects
                or prepared.preimage.operation_id != prepared.operation.intent.operation_id):
            return None
        preimage = prepared.preimage
        fields = (
            "autodev.trusted-controller-to-protected-gate/v1", command,
            runtime_context_identity(self._t_context),
            runtime_context_identity(self._role_context), self.binding.root_context_id,
            self.binding.runtime_generation.value, prepared.operation.intent.operation_id,
            prepared.subject.value, prepared.operation.intent.action_id,
            prepared.operation.intent.idempotency_key,
            prepared.operation.intent.candidate_id, preimage.materialization.materialization_id,
            preimage.target_registration.target_registration_id,
            (None if command is self.prepare_command else prepared.prepared_start_id), None,
            (prepared.prepared_target_fence_binding if command in {
                self.abort_command, self.seal_command, self.read_verify_command,
            } else None),
            None, self._f_read_verify_client.substrate_identity,
            self.authority_client.binding_identity(
                preimage.service_identity, self.binding.root_context_id,
                self.binding.runtime_generation.value, self.binding.runtime_binding_id,
            ),
            RawSha256(hashlib.sha256(canonical_json_bytes((
                "autodev.fixture-target-fence/v1", prepared.fence,
            ))).hexdigest()),
        )
        identity = RawSha256(hashlib.sha256(canonical_json_bytes((
            "autodev.protected-gate-request-id/v1", *fields[1:],
        ))).hexdigest())
        digest = RawSha256(hashlib.sha256(canonical_json_bytes((
            *fields, identity,
        ))).hexdigest())
        try:
            return ProtectedGateRequest(*fields, identity, digest)
        except (TypeError, ValueError):
            return None

    def _verify_prepared_command(
        self, prepared: PreparedProtectedStart, command: ProtectedGateCommand,
        request: ProtectedGateRequest | None,
        caller_context: AuthenticatedCallerContext | None,
    ) -> bool:
        expected = self._prepared_command_request(prepared, command)
        if expected is None or type(request) is not ProtectedGateRequest:
            return False
        return (
            request == expected
            and self.caller_verifier.verify(request.request_digest, caller_context)
            and request.declared_t_identity == runtime_context_identity(self._t_context)
            and request.destination_identity == runtime_context_identity(self._role_context)
            and request.root_context_id == self.binding.root_context_id
            and request.runtime_generation == self.binding.runtime_generation.value
        )

    def prepare_candidate_action(
        self, prepared: PreparedProtectedStart, target_fence_token: FixtureFenceToken,
        request: ProtectedGateRequest,
        caller_context: AuthenticatedCallerContext | None = None,
    ) -> bool:
        if (not self._verify_prepared_command(
                prepared, self.prepare_command, request, caller_context)
                or type(target_fence_token) is not FixtureFenceToken
                or not target_fence_token.active or not self._is_active()):
            return False
        if self.role is TrustedRuntimeRole.PUBLICATION_GATE:
            return self.authority_client.prepare_publication(prepared, target_fence_token)
        return self.authority_client.prepare_merge(prepared, target_fence_token)

    def abort_candidate_action(
        self, prepared: PreparedProtectedStart, request: ProtectedGateRequest,
        *, target_fence_token: FixtureFenceToken | None = None,
        caller_context: AuthenticatedCallerContext | None = None,
    ) -> bool:
        if not self._verify_prepared_command(
                prepared, self.abort_command, request, caller_context):
            return False
        if self.role is TrustedRuntimeRole.PUBLICATION_GATE:
            return self.authority_client.abort_prepared_publication(
                prepared.operation.intent.operation_id, prepared.subject.value,
                target_fence_token,
            )
        return self.authority_client.abort_prepared_merge(
            prepared.operation.intent.operation_id, prepared.subject.value,
            target_fence_token,
        )

    def seal_candidate_action(
        self, prepared: PreparedProtectedStart, request: ProtectedGateRequest,
        caller_context: AuthenticatedCallerContext | None = None,
    ) -> StartHeldTargetFenceBinding | None:
        if (not self._verify_prepared_command(
                prepared, self.seal_command, request, caller_context)
                or not self._f_read_verify_client.verify_prepared_target_fence(
                    prepared.prepared_target_fence_binding)):
            return None
        authority_binding = self.authority_client.binding_identity(
            prepared.preimage.service_identity, self.binding.root_context_id,
            self.binding.runtime_generation.value, self.binding.runtime_binding_id,
        )
        if self.role is TrustedRuntimeRole.PUBLICATION_GATE:
            return self.authority_client.seal_publication_for_start(
                prepared.operation.intent.operation_id, prepared.subject.value,
                prepared, authority_binding,
            )
        return self.authority_client.seal_merge_for_start(
            prepared.operation.intent.operation_id, prepared.subject.value,
            prepared, authority_binding,
        )

    def read_verify_candidate_action(
        self, prepared: PreparedProtectedStart, request: ProtectedGateRequest,
        caller_context: AuthenticatedCallerContext | None = None,
    ) -> bool:
        if not self._verify_prepared_command(
                prepared, self.read_verify_command, request, caller_context):
            return False
        return self._f_read_verify_client.verify_prepared_start(
            prepared.operation.intent.operation_id, prepared.subject.value,
            prepared.prepared_start_id,
        ) and self._f_read_verify_client.verify_prepared_target_fence(
            prepared.prepared_target_fence_binding,
        )

    def abort_prepared_candidate_action(
        self, prepared: PreparedProtectedStart,
        recovery_fence_token: FixtureFenceToken,
    ) -> bool:
        """Abort only an exact orphaned PREPARED record; START_HELD is never released here."""
        if (type(prepared) is not PreparedProtectedStart
                or prepared.subject not in self.allowed_subjects
                or type(recovery_fence_token) is not FixtureFenceToken
                or not recovery_fence_token.active or not self._is_active()):
            return False
        operation_id, action = prepared.operation.intent.operation_id, prepared.subject.value
        durable = self._f_read_verify_client.read_prepared_effect_record(operation_id, action)
        expected_id = PreparedProtectedStartId(RawSha256(
            hashlib.sha256(canonical_json_bytes(prepared.preimage)).hexdigest()
        ))
        target_binding = self._f_read_verify_client.prepared_target_fence_binding(
            operation_id, action,
        )
        if (type(durable) is not PreparedProtectedStart
                or durable.prepared_start_id != expected_id
                or durable.preimage != prepared.preimage
                or prepared.prepared_start_id != expected_id
                or self._f_read_verify_client.read_prepared_effect_state(
                    operation_id, action,
                ) != "PREPARED"
                or self._f_read_verify_client.read_marker(operation_id, action) is not None
                or type(target_binding) is not PreparedTargetFenceBinding
                or target_binding.prepared_start_id != expected_id
                or not self._f_read_verify_client.verify_prepared_target_fence(target_binding)):
            return False
        if self.role is TrustedRuntimeRole.PUBLICATION_GATE:
            released = self.authority_client.abort_prepared_publication(
                operation_id, action, recovery_fence_token,
            )
        else:
            released = self.authority_client.abort_prepared_merge(
                operation_id, action, recovery_fence_token,
            )
        return (released
                and self._f_read_verify_client.read_prepared_effect_state(
                    operation_id, action,
                ) == "RELEASED"
                and self._f_read_verify_client.read_marker(operation_id, action) is None)

    def _dependencies_fresh_set(
        self, dependencies: ControlStateAuthoritativeDependencySet,
    ) -> bool:
        for item in dependencies.dependencies:
            profile = self.dependency_profiles.get(item.observation_profile_id)
            transport = self.dependency_transports.get(item.transport_config_id)
            snapshot = self._f_read_verify_client.authoritative_snapshot(*item.locator)
            if profile is None or transport is None or snapshot is None:
                return False
            if (snapshot.repository_id, snapshot.observation_profile_id,
                    snapshot.transport_config_id) != item.locator:
                return False
            if (item.repository_id not in transport.permitted_repository_ids
                    or self._f_read_verify_client.authoritative_binding(*item.locator)
                    != item.expected_binding_id):
                return False
        return True

    @staticmethod
    def _dependency_digest(
        dependencies: ControlStateAuthoritativeDependencySet,
    ) -> RawSha256:
        return RawSha256(hashlib.sha256(canonical_json_bytes(dependencies)).hexdigest())

    def _audit_event(
        self, gate: str, action: str, outcome: GateAuditOutcome, *,
        service: ServicePrincipalId, dependencies: ControlStateAuthoritativeDependencySet,
        operation_id: OperationId | None = None,
        start_id: OperationStartBindingId | None = None,
        marker: ProtectedEffectMarker | None = None,
        action_digest: RawSha256 | None = None,
        result_identity: str = "", detail: str = "",
        intent: OperationIntent | None = None,
        materialization: CandidateMaterialization | AdmittedCandidateMaterialization | None = None,
    ) -> AuditAppendStatus:
        exact_dependencies = tuple(
            GateAuditAuthoritativeDependency(
                item.repository_id, item.observation_profile_id,
                item.transport_config_id, item.expected_binding_id,
            ) for item in dependencies.dependencies
        )
        event = GateAuditEventPreimage(
            "autodev.gate-audit-event/v1", gate, action, outcome,
            self.binding.root_context_id, self.binding.runtime_generation.value,
            self.binding.runtime_binding_id, service, exact_dependencies,
            self._dependency_digest(dependencies), self.read_state.occurrence,
            operation_id, start_id,
            None if marker is None else marker.marker_id, action_digest,
            result_identity, detail,
            None if intent is None else intent.task_id,
            None if intent is None else intent.candidate_id,
            None if intent is None else intent.authorization_id,
            None if intent is None else intent.target_registration_id,
            None if intent is None else intent.policy_epoch_identity,
            None if materialization is None else materialization.materialization_id,
            None if materialization is None else materialization.inventory.inventory_id,
        )
        return self.audit.append_event(build_gate_audit_event(event))

    @staticmethod
    def _audit_ok(status: AuditAppendStatus) -> bool:
        return status in (AuditAppendStatus.APPENDED, AuditAppendStatus.ALREADY_PRESENT)

    def _marker_postcondition(self, marker: ProtectedEffectMarker) -> bool:
        return self._f_read_verify_client.verify_marker_postcondition(marker)

    def _fail_started_effect_proven_absent(
        self, continuation: LiveProtectedEffectContinuation,
    ) -> GateResult:
        if type(continuation) is not LiveProtectedEffectContinuation:
            return GateResult(GateResultCode.INDETERMINATE)
        current = self.read_state.read_task_working_set(continuation.intent.task_id)
        operation = None if current is None else next((
            item for item in current.operations
            if item.intent.operation_id == continuation.operation_id
        ), None)
        companion = None if operation is None else operation.canonical_protected_start_binding
        binding = (
            None if type(companion) is not CanonicalProtectedStartBinding
            else companion.start_held_target_fence_binding
        )
        durable = self._f_read_verify_client.read_prepared_effect_record(
            continuation.operation_id, continuation.subject.value,
        )
        if (operation is None or operation.intent != continuation.intent
                or operation.state is not OperationState.PERFORMING
                or operation.start_binding_id != continuation.start_binding_id
                or type(binding) is not StartHeldTargetFenceBinding
                or companion.operation_start_binding_id != continuation.start_binding_id
                or binding.prepared_start_id != continuation.prepared_start_id
                or binding.operation_id != continuation.operation_id
                or binding.action_class != continuation.subject.value
                or not self._dependencies_fresh_set(continuation.dependencies)
                or type(durable) is not PreparedProtectedStart
                or durable.prepared_start_id != continuation.prepared_start_id
                or durable.preimage.dependencies != continuation.dependencies
                or self._f_read_verify_client.read_prepared_effect_state(
                    continuation.operation_id, continuation.subject.value
                ) != "START_HELD"
                or self._f_read_verify_client.read_marker(
                    continuation.operation_id, continuation.subject.value
                ) is not None
                or not self._f_read_verify_client.verify_start_held_target_fence(binding)):
            return GateResult(GateResultCode.INDETERMINATE)
        if not self._audit_ok(self._audit_event(
            continuation.subject.value, continuation.action_id.value,
            GateAuditOutcome.PRECONDITION_CONFLICT,
            service=self.capability.service_identity,
            dependencies=continuation.dependencies,
            operation_id=continuation.operation_id,
            start_id=continuation.start_binding_id,
            action_digest=continuation.prepared_start_id.raw_sha256,
            intent=continuation.intent,
            materialization=continuation.materialization,
        )):
            return GateResult(GateResultCode.INDETERMINATE)
        # This is a non-bearer observation carrier. T revalidates the exact
        # canonical/F facts and makes the only canonical failure request.
        return GateResult(GateResultCode.PRECONDITION_CONFLICT, continuation=continuation)

    def _build_execute_request(
        self, continuation: LiveProtectedEffectContinuation,
    ) -> ProtectedGateRequest | None:
        if (type(continuation) is not LiveProtectedEffectContinuation
                or continuation.subject not in self.allowed_subjects):
            return None
        current = self.read_state.read_task_working_set(continuation.intent.task_id)
        operation = None if current is None else next((
            item for item in current.operations
            if item.intent.operation_id == continuation.operation_id
        ), None)
        companion = None if operation is None else operation.canonical_protected_start_binding
        held = (
            None if type(companion) is not CanonicalProtectedStartBinding
            else companion.start_held_target_fence_binding
        )
        expected_authority = self.authority_client.binding_identity(
            self.capability.service_identity, self.binding.root_context_id,
            self.binding.runtime_generation.value, self.binding.runtime_binding_id,
        )
        if (operation is None or operation.intent != continuation.intent
                or operation.state is not OperationState.PERFORMING
                or operation.start_binding_id != continuation.start_binding_id
                or type(companion) is not CanonicalProtectedStartBinding
                or companion.operation_start_binding_id != continuation.start_binding_id
                or operation_start_binding_id_v2(held) != continuation.start_binding_id
                or held.operation_id != continuation.operation_id
                or held.prepared_start_id != continuation.prepared_start_id
                or held.action_class != continuation.subject.value
                or held.root_context_id != self.binding.root_context_id
                or held.runtime_generation != self.binding.runtime_generation.value
                or held.fixture_substrate_identity != self._f_read_verify_client.substrate_identity
                or held.authority_binding_identity != expected_authority
                or not self._verify_current_start_or_consumed_exact_replay(held)):
            return None
        command = self.execute_command
        fields = (
            "autodev.trusted-controller-to-protected-gate/v1", command,
            runtime_context_identity(self._t_context),
            runtime_context_identity(self._role_context), self.binding.root_context_id,
            self.binding.runtime_generation.value, continuation.operation_id,
            continuation.subject.value, continuation.action_id,
            continuation.idempotency_key, continuation.intent.candidate_id,
            continuation.materialization.materialization_id,
            continuation.intent.target_registration_id,
            continuation.prepared_start_id, continuation.start_binding_id,
            None, held, held.fixture_substrate_identity, expected_authority,
            RawSha256(hashlib.sha256(canonical_json_bytes((
                "autodev.fixture-target-fence/v1", continuation.action_target_fence,
            ))).hexdigest()),
        )
        request_identity = RawSha256(hashlib.sha256(canonical_json_bytes((
            "autodev.protected-gate-request-id/v1", *fields[1:],
        ))).hexdigest())
        request_digest = RawSha256(hashlib.sha256(canonical_json_bytes((
            *fields, request_identity,
        ))).hexdigest())
        try:
            return ProtectedGateRequest(*fields, request_identity, request_digest)
        except (TypeError, ValueError):
            return None

    def _dispatch_execute(
        self, continuation: LiveProtectedEffectContinuation,
        caller_context: AuthenticatedCallerContext | None,
    ) -> GateResult:
        request = self._build_execute_request(continuation)
        if request is None:
            return GateResult(GateResultCode.REJECTED)
        if (not self.caller_verifier.verify(request.request_digest, caller_context)
                or request.declared_t_identity != runtime_context_identity(self._t_context)
                or request.destination_identity != runtime_context_identity(self._role_context)
                or request.root_context_id != self.binding.root_context_id
                or request.runtime_generation != self.binding.runtime_generation.value):
            return GateResult(GateResultCode.REJECTED)
        return self.perform_effect(continuation, self.capability)

    def perform_effect(
        self, continuation: LiveProtectedEffectContinuation,
        capability: TargetPublicationCapability | MergeCapability,
    ) -> GateResult:
        with self._lock:
            if (capability is not self.capability
                    or type(continuation) is not LiveProtectedEffectContinuation
                    or continuation.subject not in self.allowed_subjects
                    or not continuation._consume(self.runtime_identity, self._nonce)):
                return GateResult(GateResultCode.LEASE_CONSUMED)
            try:
                if not continuation.target_fence_token.active or not self._is_active():
                    return GateResult(GateResultCode.LEASE_INVALID)
                subject = continuation.subject
                fence = continuation.action_target_fence
                intent = continuation.intent
                materialization = continuation.materialization
                target = continuation.target_registration
                durable = self._f_read_verify_client.read_prepared_effect_record(
                    continuation.operation_id, subject.value,
                )
                working = self.read_state.read_task_working_set(intent.task_id)
                operation = None if working is None else next((
                    item for item in working.operations
                    if item.intent.operation_id == continuation.operation_id
                ), None)
                companion = None if operation is None else operation.canonical_protected_start_binding
                held = None if type(companion) is not CanonicalProtectedStartBinding else companion.start_held_target_fence_binding
                authority_binding = self.authority_client.binding_identity(
                    capability.service_identity, self.binding.root_context_id,
                    self.binding.runtime_generation.value, self.binding.runtime_binding_id,
                )
                if (type(durable) is not PreparedProtectedStart
                        or durable.prepared_start_id != continuation.prepared_start_id
                        or durable.state not in (PreparedProtectedStartState.START_HELD,
                                                 PreparedProtectedStartState.PREPARED,
                                                 PreparedProtectedStartState.CONSUMED)
                        or operation is None or operation.intent != intent
                        or operation.state is not OperationState.PERFORMING
                        or operation.start_binding_id != continuation.start_binding_id
                        or type(companion) is not CanonicalProtectedStartBinding
                        or companion.operation_start_binding_id != continuation.start_binding_id
                        or companion != CanonicalProtectedStartBinding(
                            continuation.start_binding_id, held,
                        )
                        or operation_start_binding_id_v2(held) != continuation.start_binding_id
                        or held.prepared_start_id != continuation.prepared_start_id
                        or held.operation_id != continuation.operation_id
                        or held.action_class != subject.value
                        or held.root_context_id != self.binding.root_context_id
                        or held.runtime_generation != self.binding.runtime_generation.value
                        or held.fixture_substrate_identity != self._f_read_verify_client.substrate_identity
                        or held.authority_binding_identity != authority_binding
                        or not self._verify_current_start_or_consumed_exact_replay(held)
                        or durable.preimage.dependencies != continuation.dependencies
                        or not self._dependencies_fresh_set(continuation.dependencies)):
                    return GateResult(GateResultCode.INDETERMINATE)
                if (type(materialization) not in (CandidateMaterialization,
                                                  AdmittedCandidateMaterialization)
                        or type(target) is not AdmittedTargetRegistration
                        or materialization.repository_id != fence.repository_id
                        or materialization.task_id != intent.task_id
                        or materialization.candidate_id != intent.candidate_id
                        or materialization.contract_id != intent.contract_id
                        or materialization.contract_raw_sha256 != intent.contract_raw_sha256
                        or materialization.authorization_id != intent.authorization_id
                        or materialization.target_registration_id != intent.target_registration_id
                        or materialization.policy_epoch_identity != intent.policy_epoch_identity
                        or not self._f_read_verify_client.verify_materialization(materialization)
                        or not inventory_is_authorized(materialization.inventory,
                                                       continuation.authorized_scope,
                                                       continuation.root_forbidden_scope)
                        or target.repository_id != fence.repository_id
                        or target.target_registration_id != intent.target_registration_id
                        or target.policy_epoch_identity != intent.policy_epoch_identity
                        or not inventory_is_authorized(
                            materialization.inventory, target.ordinary_allowed_scope,
                            target.ordinary_forbidden_scope,
                        )):
                    return GateResult(GateResultCode.REJECTED)
                resolved_target = self.read_state.read_resolved_target_registration(
                    intent.target_registration_id,
                )
                if resolved_target is None or resolved_target.registration != target:
                    return GateResult(GateResultCode.REJECTED)

                current = self._f_read_verify_client.read_marker(
                    continuation.operation_id, subject.value,
                )
                prerequisite_marker_id = None
                base_ref = continuation.base_ref
                if subject is ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION:
                    if (fence.ref != materialization.candidate_branch
                            or fence.expected_sha is not None
                            or not publication_context_is_valid(
                                target, capability, materialization,
                                continuation.integration_binding,
                            )):
                        return GateResult(GateResultCode.REJECTED)
                    effect_subject = PublishedCandidateRefEffectSubject(
                        fence.repository_id, materialization.candidate_branch,
                        GitRef(materialization.candidate_branch.value), materialization.commit,
                    )
                elif subject is ProtectedEffectSubject.PULL_REQUEST_CREATION:
                    provenance = None if continuation.provenance_operation_id is None else self._f_read_verify_client.read_marker(
                        continuation.provenance_operation_id,
                        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION.value,
                    )
                    published = None if provenance is None else provenance.preimage.effect_subject
                    if (type(base_ref) is not CanonicalBranchRef or fence.base_ref != base_ref
                            or target.target_publication is None
                            or target.target_publication.service_identity != capability.service_identity
                            or target.merge is None or base_ref not in target.merge.allowed_integration_refs
                            or fence.ref != materialization.candidate_branch
                            or fence.expected_sha != materialization.commit
                            or type(published) is not PublishedCandidateRefEffectSubject
                            or published != PublishedCandidateRefEffectSubject(
                                fence.repository_id, materialization.candidate_branch,
                                GitRef(materialization.candidate_branch.value), materialization.commit,
                            ) or not self._marker_postcondition(provenance)):
                        return GateResult(GateResultCode.REJECTED)
                    prerequisite_marker_id = provenance.marker_id
                    base_sha = self._f_read_verify_client.read_ref(fence.repository_id, base_ref)
                    if base_sha is None or base_sha != fence.base_expected_sha:
                        return GateResult(GateResultCode.PRECONDITION_CONFLICT)
                    existing = None if current is None else current.preimage.effect_subject
                    if current is not None and type(existing) is not CreatedCandidatePrEffectSubject:
                        return GateResult(GateResultCode.INDETERMINATE)
                    number = (self._f_read_verify_client.read_next_pull_request_number()
                              if existing is None else existing.pull_request_number.value)
                    effect_subject = CreatedCandidatePrEffectSubject(
                        fence.repository_id, GitHubPullRequestNumber(number),
                        GitRef(materialization.candidate_branch.value), materialization.commit,
                        GitRef(base_ref.value), base_sha,
                    )
                else:
                    provenance = None if continuation.provenance_operation_id is None else self._f_read_verify_client.read_marker(
                        continuation.provenance_operation_id,
                        ProtectedEffectSubject.PULL_REQUEST_CREATION.value,
                    )
                    created = None if provenance is None else provenance.preimage.effect_subject
                    if (target.merge is None
                            or target.merge.service_identity != capability.service_identity
                            or fence.ref not in target.merge.allowed_integration_refs
                            or type(created) is not CreatedCandidatePrEffectSubject
                            or created.repository_id != fence.repository_id
                            or created.head_ref != GitRef(materialization.candidate_branch.value)
                            or created.head_sha != materialization.commit
                            or created.base_ref != GitRef(fence.ref.value)
                            or created.base_sha != fence.expected_sha
                            or not self._marker_postcondition(provenance)):
                        return GateResult(GateResultCode.REJECTED)
                    prerequisite_marker_id = provenance.marker_id
                    effect_subject = FastForwardMergeEffectSubject(
                        fence.repository_id, created.pull_request_number,
                        GitRef(fence.ref.value), fence.expected_sha, materialization.commit,
                    )

                pre_identity = RawSha256(hashlib.sha256(canonical_json_bytes(("pre", fence))).hexdigest())
                post_identity = RawSha256(hashlib.sha256(canonical_json_bytes(("post", effect_subject))).hexdigest())
                action_digest = RawSha256(hashlib.sha256(canonical_json_bytes((
                    subject, continuation.action_id, materialization.materialization_id,
                    materialization.inventory.inventory_id, effect_subject,
                ))).hexdigest())
                marker = build_protected_effect_marker(ProtectedEffectMarkerPreimage(
                    "autodev.protected-effect-marker/v1", subject.value,
                    continuation.operation_id, continuation.idempotency_key,
                    continuation.action_id, action_digest, materialization.materialization_id,
                    materialization.inventory.inventory_id, continuation.prepared_start_id,
                    self.binding.root_context_id, self.binding.runtime_generation.value,
                    capability.service_identity, effect_subject, pre_identity, post_identity,
                    prerequisite_marker_id,
                ))
                if current is not None:
                    if current != marker or not self._marker_postcondition(current):
                        return GateResult(GateResultCode.INDETERMINATE)
                    if not self._audit_ok(self._audit_event(
                        subject.value, continuation.action_id.value,
                        GateAuditOutcome.ALREADY_APPLIED,
                        service=capability.service_identity,
                        dependencies=continuation.dependencies,
                        operation_id=continuation.operation_id,
                        start_id=continuation.start_binding_id, marker=current,
                        action_digest=action_digest,
                        result_identity=current.marker_id.raw_sha256.value,
                        intent=intent, materialization=materialization,
                    )):
                        return GateResult(GateResultCode.AUDIT_FAILURE_AFTER_COMMIT)
                    return GateResult(GateResultCode.ALREADY_APPLIED)
                if subject is ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION:
                    applied = self.authority_client.execute_candidate_ref_publication(
                        fence.repository_id, materialization.candidate_branch,
                        materialization.commit, marker,
                        fence_token=continuation.target_fence_token,
                    )
                elif subject is ProtectedEffectSubject.PULL_REQUEST_CREATION:
                    applied = self.authority_client.execute_candidate_pr_creation(
                        fence.repository_id, materialization.candidate_branch,
                        base_ref, materialization.commit, marker,
                        fence_token=continuation.target_fence_token,
                    ) is not None
                else:
                    applied = self.authority_client.execute_fast_forward_merge(
                        fence.repository_id, fence.ref, fence.expected_sha,
                        materialization.commit, materialization.base,
                        effect_subject.pull_request_number.value, marker,
                        fence_token=continuation.target_fence_token,
                    )
                if not applied:
                    return self._fail_started_effect_proven_absent(continuation)
                if not self._audit_ok(self._audit_event(
                    subject.value, continuation.action_id.value,
                    GateAuditOutcome.APPLIED,
                    service=capability.service_identity,
                    dependencies=continuation.dependencies,
                    operation_id=continuation.operation_id,
                    start_id=continuation.start_binding_id, marker=marker,
                    action_digest=action_digest,
                    result_identity=marker.marker_id.raw_sha256.value,
                    intent=intent, materialization=materialization,
                )):
                    return GateResult(GateResultCode.AUDIT_FAILURE_AFTER_COMMIT)
                return GateResult(GateResultCode.EFFECT_SUCCEEDED)
            except Exception:
                return GateResult(GateResultCode.INDETERMINATE)
            finally:
                self.fence_client.release(continuation.target_fence_token)


class PublicationGateRuntime(_ProtectedGateRoleRuntime):
    """Independent P candidate logic over publication-only F and read clients."""

    role = TrustedRuntimeRole.PUBLICATION_GATE
    execute_command = ProtectedGateCommand.EXECUTE_PUBLICATION
    prepare_command = ProtectedGateCommand.PREPARE_PUBLICATION
    abort_command = ProtectedGateCommand.ABORT_PREPARED_PUBLICATION
    seal_command = ProtectedGateCommand.SEAL_PUBLICATION_FOR_START
    read_verify_command = ProtectedGateCommand.READ_VERIFY_PUBLICATION_STATE
    allowed_commands = frozenset((
        prepare_command, abort_command, seal_command, execute_command,
        read_verify_command,
    ))
    allowed_subjects = frozenset((
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
        ProtectedEffectSubject.PULL_REQUEST_CREATION,
    ))

    __slots__ = ()

    def perform_publication(
        self, continuation: LiveProtectedEffectContinuation,
        caller_context: AuthenticatedCallerContext | None = None,
    ) -> GateResult:
        if type(continuation) is not LiveProtectedEffectContinuation:
            return GateResult(GateResultCode.LEASE_CONSUMED)
        return self._dispatch_execute(continuation, caller_context)


class MergeGateRuntime(_ProtectedGateRoleRuntime):
    """Independent M candidate logic over merge-only F and read clients."""

    role = TrustedRuntimeRole.MERGE_GATE
    execute_command = ProtectedGateCommand.EXECUTE_MERGE
    prepare_command = ProtectedGateCommand.PREPARE_MERGE
    abort_command = ProtectedGateCommand.ABORT_PREPARED_MERGE
    seal_command = ProtectedGateCommand.SEAL_MERGE_FOR_START
    read_verify_command = ProtectedGateCommand.READ_VERIFY_MERGE_STATE
    allowed_commands = frozenset((
        prepare_command, abort_command, seal_command, execute_command,
        read_verify_command,
    ))
    allowed_subjects = frozenset((ProtectedEffectSubject.FAST_FORWARD_MERGE,))

    __slots__ = ()

    def perform_merge(
        self, continuation: LiveProtectedEffectContinuation,
        caller_context: AuthenticatedCallerContext | None = None,
    ) -> GateResult:
        if type(continuation) is not LiveProtectedEffectContinuation:
            return GateResult(GateResultCode.LEASE_CONSUMED)
        return self._dispatch_execute(continuation, caller_context)


def _release_fixture_observed_absence(
    runtime: _ProtectedGateRoleRuntime,
    recovery_authority: FixtureStartHeldRecoveryAuthority,
    observation: GateResult,
) -> bool:
    """External fixture orchestration releases only an exact absent held effect."""
    continuation = observation.continuation
    if (observation.code is not GateResultCode.PRECONDITION_CONFLICT
            or type(continuation) is not LiveProtectedEffectContinuation):
        return False
    working = runtime.read_state.read_task_working_set(continuation.intent.task_id)
    operation = None if working is None else next((
        item for item in working.operations
        if item.intent.operation_id == continuation.operation_id
    ), None)
    companion = None if operation is None else operation.canonical_protected_start_binding
    held = (None if type(companion) is not CanonicalProtectedStartBinding
            else companion.start_held_target_fence_binding)
    durable = runtime._f_read_verify_client.read_prepared_effect_record(
        continuation.operation_id, continuation.subject.value,
    )
    if not (
        type(operation) is OperationRecord
        and operation.intent == continuation.intent
        and operation.state is OperationState.PERFORMING
        and operation.start_binding_id == continuation.start_binding_id
        and type(companion) is CanonicalProtectedStartBinding
        and companion.operation_start_binding_id == continuation.start_binding_id
        and type(held) is StartHeldTargetFenceBinding
        and held.prepared_start_id == continuation.prepared_start_id
        and held.operation_id == continuation.operation_id
        and held.action_class == continuation.subject.value
        and type(durable) is PreparedProtectedStart
        and durable.prepared_start_id == continuation.prepared_start_id
        and durable.preimage.dependencies == continuation.dependencies
        and runtime._f_read_verify_client.read_marker(
            continuation.operation_id, continuation.subject.value,
        ) is None
        and runtime._f_read_verify_client.read_prepared_effect_state(
            continuation.operation_id, continuation.subject.value,
        ) == PreparedProtectedStartState.START_HELD.value
        and runtime._f_read_verify_client.verify_start_held_target_fence(held)
    ):
        return False
    fence = durable.fence
    facts = {
        ("prepared", continuation.operation_id, continuation.subject.value),
        ("repository", fence.repository_id),
        ("ref", fence.repository_id, fence.ref),
    }
    if continuation.subject is not ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION:
        facts.add(("prs", fence.repository_id))
    if fence.base_ref is not None:
        facts.add(("ref", fence.repository_id, fence.base_ref))
    recovery_token = runtime.fence_client.acquire(frozenset(facts))
    if recovery_token is None:
        return False
    try:
        current = runtime.read_state.read_task_working_set(continuation.intent.task_id)
        current_operation = None if current is None else next((
            item for item in current.operations
            if item.intent.operation_id == continuation.operation_id
        ), None)
        current_durable = runtime._f_read_verify_client.read_prepared_effect_record(
            continuation.operation_id, continuation.subject.value,
        )
        return (
            current_operation == operation
            and current_durable is durable
            and runtime._f_read_verify_client.read_marker(
                continuation.operation_id, continuation.subject.value,
            ) is None
            and runtime._f_read_verify_client.read_prepared_effect_state(
                continuation.operation_id, continuation.subject.value,
            ) == PreparedProtectedStartState.START_HELD.value
            and runtime._f_read_verify_client.verify_start_held_target_fence(held)
            and recovery_authority.release_proven_absent(
                held, operation, durable, recovery_token,
            )
        )
    finally:
        runtime.fence_client.release(recovery_token)


class _FixturePublicationGateClient:
    """T-side fixture client of an independent P runtime."""

    __slots__ = ("_runtime", "_controller", "_channel_token", "_t_context",
                 "_recovery_authority")

    def __init__(
        self, runtime: PublicationGateRuntime,
        controller: TrustedControllerRuntime,
        channel_token: object, t_context: RuntimeSecurityContext,
        recovery_authority: FixtureStartHeldRecoveryAuthority,
    ) -> None:
        if (type(runtime) is not PublicationGateRuntime
                or type(controller) is not TrustedControllerRuntime
                or type(t_context) is not RuntimeSecurityContext):
            raise TypeError("exact publication gate runtime required")
        self._runtime, self._controller = runtime, controller
        if type(recovery_authority) is not FixtureStartHeldRecoveryAuthority:
            raise TypeError("fixture recovery authority is required by the external adapter")
        self._channel_token, self._t_context = channel_token, t_context
        self._recovery_authority = recovery_authority

    def prepare_start(self, prepared):
        request = self._runtime._prepared_command_request(
            prepared, self._runtime.prepare_command,
        )
        if request is None:
            return None
        context = _issue_fixture_caller_context(
            self._channel_token, self._t_context, request.request_digest,
        )
        return self._runtime.prepare_start(prepared, request, context)

    def abort_start(self, prepared_start_id: PreparedProtectedStartId) -> bool:
        prepared = self._runtime._prepared_records.get(prepared_start_id)
        if prepared is None:
            return False
        request = self._runtime._prepared_command_request(
            prepared, self._runtime.abort_command,
        )
        if request is None:
            return False
        context = _issue_fixture_caller_context(
            self._channel_token, self._t_context, request.request_digest,
        )
        return self._runtime.abort_start(prepared_start_id, request, context)

    def seal_start(
        self, prepared_start_id: PreparedProtectedStartId,
    ) -> StartHeldTargetFenceBinding | None:
        prepared = self._runtime._prepared_records.get(prepared_start_id)
        if prepared is None:
            return None
        request = self._runtime._prepared_command_request(
            prepared, self._runtime.seal_command,
        )
        if request is None:
            return None
        context = _issue_fixture_caller_context(
            self._channel_token, self._t_context, request.request_digest,
        )
        return self._runtime.seal_start(prepared_start_id, request, context)

    def execute_started(
        self, prepared_start_id: PreparedProtectedStartId,
        expected_start_binding_id: OperationStartBindingId,
    ) -> GateResult:
        continuation = self._runtime._continuation_for_started_operation(
            prepared_start_id, expected_start_binding_id,
        )
        request = (None if continuation is None else
                   self._runtime._build_execute_request(continuation))
        if request is None:
            return GateResult(GateResultCode.REJECTED)
        context = _issue_fixture_caller_context(
            self._channel_token, self._t_context, request.request_digest,
        )
        return self._runtime.execute_started(
            prepared_start_id, expected_start_binding_id, context,
        )

    def perform_publication(self, continuation, caller_context=None) -> GateResult:
        request = self._runtime._build_execute_request(continuation)
        if caller_context is None and request is not None:
            caller_context = _issue_fixture_caller_context(
                self._channel_token, self._t_context, request.request_digest,
            )
        result = self._runtime.perform_publication(continuation, caller_context)
        if result.code is GateResultCode.PRECONDITION_CONFLICT and result.continuation is not None:
            if not _release_fixture_observed_absence(
                    self._runtime, self._recovery_authority, result):
                return GateResult(GateResultCode.INDETERMINATE)
            return self._controller.reconcile_started_effect_absent(result)
        return result


class _FixtureMergeGateClient:
    """T-side fixture client of an independent M runtime."""

    __slots__ = ("_runtime", "_controller", "_channel_token", "_t_context",
                 "_recovery_authority")

    def __init__(
        self, runtime: MergeGateRuntime,
        controller: TrustedControllerRuntime,
        channel_token: object, t_context: RuntimeSecurityContext,
        recovery_authority: FixtureStartHeldRecoveryAuthority,
    ) -> None:
        if (type(runtime) is not MergeGateRuntime
                or type(controller) is not TrustedControllerRuntime
                or type(t_context) is not RuntimeSecurityContext):
            raise TypeError("exact merge gate runtime required")
        self._runtime, self._controller = runtime, controller
        if type(recovery_authority) is not FixtureStartHeldRecoveryAuthority:
            raise TypeError("fixture recovery authority is required by the external adapter")
        self._channel_token, self._t_context = channel_token, t_context
        self._recovery_authority = recovery_authority

    def prepare_start(self, prepared):
        request = self._runtime._prepared_command_request(
            prepared, self._runtime.prepare_command,
        )
        if request is None:
            return None
        context = _issue_fixture_caller_context(
            self._channel_token, self._t_context, request.request_digest,
        )
        return self._runtime.prepare_start(prepared, request, context)

    def abort_start(self, prepared_start_id: PreparedProtectedStartId) -> bool:
        prepared = self._runtime._prepared_records.get(prepared_start_id)
        if prepared is None:
            return False
        request = self._runtime._prepared_command_request(
            prepared, self._runtime.abort_command,
        )
        if request is None:
            return False
        context = _issue_fixture_caller_context(
            self._channel_token, self._t_context, request.request_digest,
        )
        return self._runtime.abort_start(prepared_start_id, request, context)

    def seal_start(
        self, prepared_start_id: PreparedProtectedStartId,
    ) -> StartHeldTargetFenceBinding | None:
        prepared = self._runtime._prepared_records.get(prepared_start_id)
        if prepared is None:
            return None
        request = self._runtime._prepared_command_request(
            prepared, self._runtime.seal_command,
        )
        if request is None:
            return None
        context = _issue_fixture_caller_context(
            self._channel_token, self._t_context, request.request_digest,
        )
        return self._runtime.seal_start(prepared_start_id, request, context)

    def execute_started(
        self, prepared_start_id: PreparedProtectedStartId,
        expected_start_binding_id: OperationStartBindingId,
    ) -> GateResult:
        continuation = self._runtime._continuation_for_started_operation(
            prepared_start_id, expected_start_binding_id,
        )
        request = (None if continuation is None else
                   self._runtime._build_execute_request(continuation))
        if request is None:
            return GateResult(GateResultCode.REJECTED)
        context = _issue_fixture_caller_context(
            self._channel_token, self._t_context, request.request_digest,
        )
        return self._runtime.execute_started(
            prepared_start_id, expected_start_binding_id, context,
        )

    def perform_merge(self, continuation, caller_context=None) -> GateResult:
        request = self._runtime._build_execute_request(continuation)
        if caller_context is None and request is not None:
            caller_context = _issue_fixture_caller_context(
                self._channel_token, self._t_context, request.request_digest,
            )
        result = self._runtime.perform_merge(continuation, caller_context)
        if result.code is GateResultCode.PRECONDITION_CONFLICT and result.continuation is not None:
            if not _release_fixture_observed_absence(
                    self._runtime, self._recovery_authority, result):
                return GateResult(GateResultCode.INDETERMINATE)
            return self._controller.reconcile_started_effect_absent(result)
        return result


class ControlStateGate:
    """C entry point depends only on the narrow authenticated C client."""

    __slots__ = ("_client",)

    def __init__(self, client: ControlStateGateClient) -> None:
        if not isinstance(client, ControlStateGateClient):
            raise TypeError("exact control-state gate client required")
        self._client = client

    def commit(
        self, request: ControlStateCommitRequest, lease: ControlStateCommitLease,
        caller_context: AuthenticatedCallerContext | None = None,
    ) -> GateResult:
        return self._client.commit_control_state(request, lease, caller_context)


class TargetPublicationGate:
    """P entry point depends only on its narrow publication client."""

    __slots__ = ("_client",)

    def __init__(self, client: PublicationGateClient) -> None:
        if not isinstance(client, PublicationGateClient):
            raise TypeError("exact publication gate client required")
        self._client = client

    def perform(
        self, continuation: LiveProtectedEffectContinuation,
        caller_context: AuthenticatedCallerContext | None = None,
    ) -> GateResult:
        return self._client.perform_publication(continuation, caller_context)


class MergeGate:
    """M entry point depends only on its narrow merge client."""

    __slots__ = ("_client",)

    def __init__(self, client: MergeGateClient) -> None:
        if not isinstance(client, MergeGateClient):
            raise TypeError("exact merge gate client required")
        self._client = client

    def perform(
        self, continuation: LiveProtectedEffectContinuation,
        caller_context: AuthenticatedCallerContext | None = None,
    ) -> GateResult:
        return self._client.perform_merge(continuation, caller_context)


def operation_start_binding_id(prepared_start_id: PreparedProtectedStartId) -> OperationStartBindingId:
    """Project the frozen prepared-start digest into its distinct lower-layer nominal type."""
    if type(prepared_start_id) is not PreparedProtectedStartId:
        raise TypeError("exact PreparedProtectedStartId required")
    return OperationStartBindingId(prepared_start_id.raw_sha256)


def publication_context_is_valid(registration: AdmittedTargetRegistration,
                                 capability: TargetPublicationCapability,
                                 materialization: CandidateMaterialization | AdmittedCandidateMaterialization,
                                 operation_integration_ref: object = None) -> bool:
    """Validate namespace/principal/ref separation without cross-nominal equality."""
    if (type(registration) is not AdmittedTargetRegistration
            or type(capability) is not TargetPublicationCapability
            or type(materialization) not in (CandidateMaterialization, AdmittedCandidateMaterialization)):
        return False
    destination = materialization.candidate_branch
    if (registration.target_publication is None
            or registration.target_publication.service_identity != capability.service_identity):
        return False
    if destination in registration.protected_refs:
        return False
    if registration.merge is not None and destination in registration.merge.allowed_integration_refs:
        return False
    if type(operation_integration_ref) is IntegrationBound:
        return GitRef(destination.value) != operation_integration_ref.integration_ref
    if type(operation_integration_ref) is NotIntegrationBound:
        return True
    if type(operation_integration_ref) is GitRef:
        return GitRef(destination.value) != operation_integration_ref
    if operation_integration_ref is not None and type(operation_integration_ref) is not CanonicalBranchRef:
        return False
    if type(operation_integration_ref) is CanonicalBranchRef:
        return GitRef(destination.value) != GitRef(operation_integration_ref.value)
    return True
