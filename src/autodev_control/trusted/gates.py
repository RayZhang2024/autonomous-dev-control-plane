"""G7 protected fixture gates.

The gates in this module are a semantic fixture implementation.  They have no
provider, network, credential, workflow, or controlled-runtime integration.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import Enum
import hashlib
import secrets

from .audit import (
    AuditAppendStatus, FixtureGateAudit, GateAuditAuthoritativeDependency,
    GateAuditEventPreimage, GateAuditOutcome, build_gate_audit_event,
)
from .backend import (
    AuthorizationExistsAndMatches, CanonicalNamespace, CanonicalTransaction,
    CanonicalWriteResult, CanonicalWriteStatus, CreateAuthorization, CreateCandidate,
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
from .evidence import (
    EvidenceAdmissionDecision, SemanticEvidenceAdmissionRequest, admit_semantic_review,
)
from .errors import G4FailureCode
from .fixture_platform import (
    ActiveFixtureRuntimeRegistry, CreatedCandidatePrEffectSubject,
    FastForwardMergeEffectSubject, FixtureFenceToken, FixtureGitPlatform,
    ProtectedEffectMarker, ProtectedEffectMarkerPreimage,
    PublishedCandidateRefEffectSubject, build_protected_effect_marker,
)
from .identity import (
    GateRuntimeBindingId, GitRef, GitSha, ImmutableConfigId,
    OperationStartBindingId, PreparedProtectedStartId, RawSha256, RootContextId,
)
from .materialization import (
    CandidateMaterialization, create_materialized_candidate_record,
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
    reconcile_operation as decide_reconciliation, transition_operation,
)
from .scope import (
    AuthorizationId, CanonicalBranchRef, ContractId, GitHubRepositoryId,
    MutationScope, ServicePrincipalId, TargetRegistrationId, TaskId,
)
from .state import (
    CancellationRequestId, CancellationStatus, ConditionStatus, EvidenceBindingRef,
    OperationRevisionBinding, RepairBudget, TaskEvaluationInput,
    _compose_candidate_applicability, _compose_completion_aggregate,
    adopt_candidate, evaluate_task, initial_task_proposal, reserve_task_operation,
    revise_supporting_evidence, set_cancellation, start_operation as decide_start_operation,
)
from .manifest import PolicyEpochIdentity
from .operation import AdmissionEventId, CandidateId, DecisionEventId
from .state_reader import (
    AuthoritativeObservationProfile, AuthoritativeStateSnapshot,
    GitHubPullRequestNumber, GitHubStateReader, RegisteredStateFactDescriptor,
    TrustedGitHubReadTransportBinding,
)
from .target_registration import AdmittedTargetRegistration


class TrustedControlCommandKind(Enum):
    ADMIT_AUTHORIZATION = "ADMIT_AUTHORIZATION"
    CREATE_TASK = "CREATE_TASK"
    CREATE_CANDIDATE = "CREATE_CANDIDATE"
    ADOPT_CANDIDATE = "ADOPT_CANDIDATE"
    REVISE_SUPPORTING_EVIDENCE = "REVISE_SUPPORTING_EVIDENCE"
    RESERVE_OPERATION = "RESERVE_OPERATION"
    START_OPERATION = "START_OPERATION"
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


class ProtectedEffectSubject(Enum):
    CANDIDATE_BRANCH_PUBLICATION = "CANDIDATE_BRANCH_PUBLICATION"
    PULL_REQUEST_CREATION = "PULL_REQUEST_CREATION"
    FAST_FORWARD_MERGE = "FAST_FORWARD_MERGE"


class PreparedProtectedStartState(Enum):
    PREPARED = "PREPARED"
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


@dataclass(frozen=True, slots=True)
class ControlStateAuthoritativeDependency:
    repository_id: GitHubRepositoryId
    observation_profile_id: ImmutableConfigId
    transport_config_id: ImmutableConfigId
    expected_binding_id: AuthoritativeStateBindingId

    def __post_init__(self) -> None:
        exact = ((self.repository_id, GitHubRepositoryId), (self.observation_profile_id, ImmutableConfigId),
                 (self.transport_config_id, ImmutableConfigId),
                 (self.expected_binding_id, AuthoritativeStateBindingId))
        if any(type(value) is not expected for value, expected in exact):
            raise TypeError("dependency field has wrong exact type")

    @property
    def locator(self) -> tuple[GitHubRepositoryId, ImmutableConfigId, ImmutableConfigId]:
        return self.repository_id, self.observation_profile_id, self.transport_config_id


@dataclass(frozen=True, slots=True)
class ControlStateAuthoritativeDependencySet:
    dependencies: tuple[ControlStateAuthoritativeDependency, ...]

    def __post_init__(self) -> None:
        if type(self.dependencies) is not tuple or any(type(item) is not ControlStateAuthoritativeDependency for item in self.dependencies):
            raise TypeError("dependencies must be an exact tuple")
        locators = tuple(item.locator for item in self.dependencies)
        keys = tuple((a.value, b.value, c.value) for a, b, c in locators)
        if keys != tuple(sorted(keys)) or len(locators) != len(set(locators)):
            raise ValueError("dependencies require unique canonical locator order")


# Compatibility aliases intentionally preserve the one closed dependency model.
ResolvableStateDependency = ControlStateAuthoritativeDependency
ExactDependencySet = ControlStateAuthoritativeDependencySet


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
    __slots__ = ("prepared_start_id", "operation", "subject", "fence", "preimage", "_platform", "_sealed")

    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("prepared protected starts are gate-private")

    @property
    def state(self) -> PreparedProtectedStartState:
        current = self._platform.prepared_effect_state(
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
    _key: object

    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("commit requests are emitted only by DeterministicTrustedController")


@dataclass(frozen=True, slots=True)
class GateResult:
    code: GateResultCode
    canonical_result: CanonicalWriteResult | None = None
    continuation: LiveProtectedEffectContinuation | None = None
    failure_code: G4FailureCode | None = None

    def __post_init__(self) -> None:
        if type(self.code) is not GateResultCode:
            raise TypeError("gate result code has wrong exact type")
        if self.canonical_result is not None and type(self.canonical_result) is not CanonicalWriteResult:
            raise TypeError("canonical result has wrong exact type")
        if self.continuation is not None and type(self.continuation) is not LiveProtectedEffectContinuation:
            raise TypeError("continuation has wrong exact type")
        if self.failure_code is not None and type(self.failure_code) is not G4FailureCode:
            raise TypeError("failure code has wrong exact type")


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

    __slots__ = ("_key", "_backend", "_completion_contexts")

    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("trusted controller is installed only by the active gate runtime")

    def admit_authorization(
        self, proposal: CandidateAuthorizationProposal,
        target: AdmittedTargetRegistration | None,
        contract: ContractAuthorityCeiling | None,
        policy: AuthorizationPolicyContext | None,
        root: OrdinaryRootProtectionContext | None,
        *, approval: AuthenticatedHumanAuthorizationApproval | None = None,
        issuer: DirectIssuerAuthorityEnvelope | None = None,
    ) -> ControlStateCommitRequest:
        if type(proposal) is not CandidateAuthorizationProposal:
            raise TypeError("exact candidate authorization proposal required")
        resolved = self._backend.read_resolved_target_registration(
            proposal.target_registration_id
        )
        if resolved is None or resolved.registration != target:
            raise ValueError("target registration is not the exact root-resolved value")
        if proposal.kind is AuthorizationKind.DIRECT_HUMAN:
            result = admit_direct_authorization(
                proposal, target, contract, policy, approval, issuer, root
            )
        else:
            parent = (
                None if proposal.parent_authorization_id is None
                else self._backend.read_authorization(proposal.parent_authorization_id)
            )
            result = admit_delegated_authorization(
                proposal, target, contract, policy, parent, root
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
        transaction = CanonicalTransaction(
            self._backend.occurrence,
            (
                AuthorizationExistsAndMatches(working),
                RecordAbsent(CanonicalNamespace.TASK, task_id),
            ),
            (CreateTaskAndInitialOperationMembership(proposal.proposed),),
        )
        request = object.__new__(ControlStateCommitRequest)
        object.__setattr__(request, "command_kind", TrustedControlCommandKind.CREATE_TASK)
        object.__setattr__(request, "transaction", transaction)
        object.__setattr__(request, "_key", self._key)
        return request

    def create_candidate_and_adopt(
        self, *, task_id: TaskId, materialization: CandidateMaterialization,
        admission_event_id: AdmissionEventId,
        decision_event_id: DecisionEventId,
        parent_candidate_ids: tuple[CandidateId, ...] = (),
        creation_operation_id: OperationId | None = None,
    ) -> ControlStateCommitRequest:
        current = self._backend.read_task_working_set(task_id)
        if current is None:
            raise ValueError("task is not canonical")
        task = current.task
        candidate = create_materialized_candidate_record(
            materialization=materialization, task_id=task.task_id,
            contract_id=task.contract_id,
            contract_raw_sha256=task.contract_raw_sha256,
            authorization_id=task.authorization_id,
            admission_event_id=admission_event_id,
            target_registration_id=task.target_registration_id,
            policy_epoch_identity=task.last_evaluated_policy_epoch_identity,
            parent_candidate_ids=parent_candidate_ids,
            creation_operation_id=creation_operation_id,
        )
        determination = _compose_candidate_applicability(
            task, candidate, decision_event_id
        )
        result = adopt_candidate(
            task, candidate, determination, expected_task_revision=task.revision,
            snapshot=current.task_operation_snapshot(),
            expected_membership_binding_id=current.task_operation_membership.membership_binding_id,
            expected_operation_revisions=tuple(
                OperationRevisionBinding(item.intent.operation_id, item.revision)
                for item in current.operations
                if item.intent.candidate_id == task.current_candidate_id
            ),
        )
        if result.proposal is None:
            raise ValueError(result.failure.code.value)
        transaction = CanonicalTransaction(
            current.canonical_state_occurrence_binding,
            (
                TaskRevisionEquals(task.task_id, task.revision),
                TaskOperationMembershipEquals(
                    task.task_id, current.task_operation_membership.membership_binding_id
                ),
                RecordAbsent(CanonicalNamespace.CANDIDATE, candidate.candidate_id),
            ),
            (CreateCandidate(candidate), ReplaceTask(task.revision, result.proposal.proposed)),
        )
        request = object.__new__(ControlStateCommitRequest)
        object.__setattr__(request, "command_kind", TrustedControlCommandKind.CREATE_CANDIDATE)
        object.__setattr__(request, "transaction", transaction)
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

    def start_operation(self, task_id: TaskId, operation_id: OperationId,
                        prepared_start_id: PreparedProtectedStartId) -> ControlStateCommitRequest:
        current = self._backend.read_task_working_set(task_id)
        if current is None:
            raise ValueError("task is not canonical")
        operation = next(
            (item for item in current.operations if item.intent.operation_id == operation_id), None
        )
        if operation is None:
            raise ValueError("operation is not canonical")
        result = decide_start_operation(
            current.task, operation, expected_task_revision=current.task.revision,
            expected_operation_revision=operation.revision,
            expected_cancellation_status=current.task.cancellation_status,
            operation_start_binding_id=operation_start_binding_id(prepared_start_id),
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
        mutations = (ReplaceOperation(operation.revision, proposal.proposed_operation),)
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
        object.__setattr__(request, "command_kind", TrustedControlCommandKind.START_OPERATION)
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
                    ) -> DeterministicTrustedController:
    value = object.__new__(DeterministicTrustedController)
    value._key, value._backend, value._completion_contexts = key, backend, completion_contexts
    return value


class TrustedControlCommandBoundary:
    __slots__ = ("_controller", "_runtime")

    def __init__(self, controller: DeterministicTrustedController,
                 runtime: "FixtureProtectedGateRuntime") -> None:
        if type(controller) is not DeterministicTrustedController:
            raise TypeError("exact trusted controller required")
        self._controller, self._runtime = controller, runtime

    def submit(self, *_: object, **__: object) -> ControlStateCommitRequest:
        raise TypeError("use one explicit closed semantic command method")

    def admit_authorization(
        self, proposal: CandidateAuthorizationProposal,
    ) -> ControlStateCommitRequest:
        if type(proposal) is not CandidateAuthorizationProposal:
            raise TypeError("exact candidate authorization proposal required")
        context = self._runtime._authorization_contexts.get(
            hashlib.sha256(canonical_json_bytes(proposal)).hexdigest()
        )
        if context is None:
            raise ValueError("exact root-managed authorization context is unavailable")
        target, contract, policy, root, approval, issuer = context
        return self._controller.admit_authorization(
            proposal, target, contract, policy, root,
            approval=approval, issuer=issuer,
        )

    def create_task(self, **kwargs) -> ControlStateCommitRequest:
        return self._controller.create_task(**kwargs)

    def create_candidate_and_adopt(self, **kwargs) -> ControlStateCommitRequest:
        return self._controller.create_candidate_and_adopt(**kwargs)

    def revise_supporting_evidence(self, *args, **kwargs) -> ControlStateCommitRequest:
        return self._controller.revise_supporting_evidence(*args, **kwargs)

    def reserve_operation(
        self, task_id: TaskId, command: OperationReservationCommand,
    ) -> ControlStateCommitRequest:
        if type(command) is OperationIntent:
            raise TypeError("callers cannot submit trusted OperationIntent")
        return self._controller.reserve_operation(
            task_id, command,
            self._runtime._derive_operation_authoritative_binding(task_id, command),
        )

    def start_operation(self, *_: object, **__: object) -> ControlStateCommitRequest:
        raise TypeError("protected start is orchestrated only by the live gate runtime")

    def reconcile_operation(
        self, task_id: TaskId, operation_id: OperationId,
        subject: ProtectedEffectSubject,
    ) -> GateResult:
        return self._runtime.reconcile_recovered_effect(
            task_id, operation_id, subject
        )

    def evaluate_task(
        self, command: TaskEvaluationCommand,
    ) -> ControlStateCommitRequest:
        if type(command) is TaskEvaluationInput:
            raise TypeError("callers cannot submit trusted TaskEvaluationInput")
        return self._controller.evaluate_task(command)

    def set_cancellation(self, *args, **kwargs) -> ControlStateCommitRequest:
        return self._controller.set_cancellation(*args, **kwargs)

    def admit_semantic_evidence(
        self, command: SemanticEvidenceCommand,
    ) -> ControlStateCommitRequest:
        if type(command) is SemanticEvidenceAdmissionRequest:
            raise TypeError("callers cannot submit trusted G5 admission context")
        return self._controller.admit_semantic_evidence(
            self._runtime._compose_semantic_evidence_request(command)
        )


class FixtureProtectedGateRuntime:
    """Holds fixture authority; a new instance is a process restart boundary."""

    __slots__ = ("binding", "backend", "platform", "audit", "controller", "boundary",
                 "registry", "_lock", "_nonce", "_controller_key", "_profiles", "_readers", "_fixture_transports", "_authorization_contexts", "_evidence_contexts", "_completion_contexts", "_control", "_publication", "_merge", "_control_runtime", "_publication_runtime", "_merge_runtime", "_fail_after_start", "_recovery_fence_hook", "_post_start_audit_failure_hook")

    def __init__(self, binding: GateRuntimeBinding, backend: InMemoryCanonicalStateBackend,
                 platform: FixtureGitPlatform, audit: FixtureGateAudit,
                 registry: ActiveFixtureRuntimeRegistry | None = None, *,
                 _restart_from: tuple[object, object, object] | None = None) -> None:
        if type(binding) is not GateRuntimeBinding or type(backend) is not InMemoryCanonicalStateBackend:
            raise TypeError("runtime binding/backend has wrong exact type")
        if type(platform) is not FixtureGitPlatform or type(audit) is not FixtureGateAudit:
            raise TypeError("fixture platform/audit has wrong exact type")
        self.binding, self.backend, self.platform, self.audit = binding, backend, platform, audit
        self.registry = registry or ActiveFixtureRuntimeRegistry()
        self.platform.attach_registry(self.registry)
        self._lock, self._nonce, self._controller_key = self.registry.lock, object(), object()
        self._profiles: dict[ImmutableConfigId, AuthoritativeObservationProfile] = {}
        self._readers: dict[ImmutableConfigId, GitHubStateReader] = {}
        self._fixture_transports: dict[ImmutableConfigId, TrustedGitHubReadTransportBinding] = {}
        self._authorization_contexts: dict[str, tuple] = {}
        self._evidence_contexts: dict[ImmutableConfigId, SemanticEvidenceAdmissionRequest] = {}
        self._completion_contexts: dict[ImmutableConfigId, TrustedCompletionEvaluationContext] = {}
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
        self.controller = _new_controller(
            self._controller_key, self.backend, self._completion_contexts
        )
        self.boundary = TrustedControlCommandBoundary(self.controller, self)

    @property
    def control_capability(self) -> ControlStateCapability:
        return self._control

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

    def _audit_event(self, gate: str, action: str, outcome: GateAuditOutcome, *,
                     service: ServicePrincipalId, dependencies: ControlStateAuthoritativeDependencySet,
                     operation_id: OperationId | None = None,
                     start_id: OperationStartBindingId | None = None,
                     marker: ProtectedEffectMarker | None = None,
                     action_digest: RawSha256 | None = None,
                     result_identity: str = "", detail: str = "",
                     intent: OperationIntent | None = None,
                     materialization: CandidateMaterialization | None = None,
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
        contract: ContractAuthorityCeiling | None,
        policy: AuthorizationPolicyContext | None,
        root: OrdinaryRootProtectionContext | None, *,
        approval: AuthenticatedHumanAuthorizationApproval | None = None,
        issuer: DirectIssuerAuthorityEnvelope | None = None,
    ) -> None:
        """Fixture root/admin setup; these authority facts never cross the command boundary."""
        if type(proposal) is not CandidateAuthorizationProposal:
            raise TypeError("exact candidate authorization proposal required")
        key = hashlib.sha256(canonical_json_bytes(proposal)).hexdigest()
        self._authorization_contexts[key] = (
            target, contract, policy, root, approval, issuer,
        )

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
        if (capability is not self._control or type(dependencies) is not ControlStateAuthoritativeDependencySet
                or not self._is_active()):
            return None
        if not dependencies.dependencies:
            if type(independence) is not ExternalStateIndependence or independence._nonce is not self._nonce:
                return None
        elif independence is not None:
            return None
        fact_values: set[tuple] = set()
        for item in dependencies.dependencies:
            source_facts = self.platform.authoritative_facts(*item.locator)
            if source_facts is None:
                return None
            fact_values.update(source_facts)
        facts = frozenset(fact_values)
        token = self.registry.acquire(self, facts)
        if token is None:
            return None
        if not self._is_active() or not self._dependencies_fresh_set(dependencies):
            self.registry.release(token)
            return None
        lease = object.__new__(ControlStateCommitLease)
        lease._owner, lease._nonce, lease._used = self, self._nonce, False
        lease.root_context_id = self.binding.root_context_id
        lease.runtime_generation = self.binding.runtime_generation
        lease.runtime_binding = self.binding
        lease.dependencies = dependencies
        lease.capability = capability
        lease.fence_token = token
        return lease

    def _dependencies_fresh(self, lease: ControlStateCommitLease) -> bool:
        return self._dependencies_fresh_set(lease.dependencies)

    def _dependencies_fresh_set(self, dependencies: ControlStateAuthoritativeDependencySet) -> bool:
        for item in dependencies.dependencies:
            profile = self._profiles.get(item.observation_profile_id)
            transport = self._fixture_transports.get(item.transport_config_id)
            snapshot = self.platform.authoritative_snapshot(*item.locator)
            if profile is None or transport is None or snapshot is None:
                return False
            if (snapshot.repository_id, snapshot.observation_profile_id,
                    snapshot.transport_config_id) != item.locator:
                return False
            if item.repository_id not in transport.permitted_repository_ids:
                return False
            if self.platform.authoritative_binding(*item.locator) != item.expected_binding_id:
                return False
        return True

    def commit(self, request: ControlStateCommitRequest, lease: ControlStateCommitLease) -> GateResult:
        with self._lock:
            if type(request) is not ControlStateCommitRequest or request._key is not self._controller_key:
                return GateResult(GateResultCode.REJECTED)
            if type(lease) is not ControlStateCommitLease or not self._dependencies_fresh(lease) or not self._is_active():
                return GateResult(GateResultCode.LEASE_INVALID)
            if (lease.runtime_binding is not self.binding or lease.root_context_id != self.binding.root_context_id
                    or lease.runtime_generation != self.binding.runtime_generation
                    or lease.capability is not self._control):
                return GateResult(GateResultCode.LEASE_INVALID)
            if not lease._consume(self, self._nonce):
                return GateResult(GateResultCode.LEASE_CONSUMED)
            try:
                request_digest = RawSha256(hashlib.sha256(canonical_json_bytes(request.transaction)).hexdigest())
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
                if result.status is not CanonicalWriteStatus.APPLIED:
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
                                ) -> PreparedStartCommitLease:
        if type(operation) is not OperationRecord or operation.state is not OperationState.RESERVED:
            raise ValueError("only RESERVED operation may be prepared")
        if type(subject) is not ProtectedEffectSubject or type(fence) is not ActionTargetFence:
            raise TypeError("protected start inputs have wrong exact type")
        expected_capability = self._merge if subject is ProtectedEffectSubject.FAST_FORWARD_MERGE else self._publication
        if target_capability is not expected_capability:
            raise ValueError("action capability does not match exact gate/principal")
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
        )
        if not self.platform.verify_prepared_effect(
            operation.intent.operation_id, subject.value, prepared
        ):
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
            type(materialization) is not CandidateMaterialization
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
                       target_fence_token: FixtureFenceToken) -> PreparedProtectedStart:
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
        value.preimage, value._platform = preimage, self.platform
        value._sealed = True
        self.platform.persist_prepared_effect(
            operation.intent.operation_id, subject.value, value,
            _fence_token=target_fence_token,
        )
        return value

    def release_prepared_action(self, prepared: PreparedProtectedStart) -> bool:
        if type(prepared) is not PreparedProtectedStart:
            return False
        released = self.platform.release_prepared_effect(
            prepared.operation.intent.operation_id, prepared.subject.value
        )
        return released and prepared.state is PreparedProtectedStartState.RELEASED

    def _release_durable_prepared(
        self, prepared: PreparedProtectedStart,
        token: FixtureFenceToken,
    ) -> bool:
        released = self.platform.release_prepared_effect(
            prepared.operation.intent.operation_id, prepared.subject.value,
            _fence_token=token,
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
        if (
            durable.prepared_start_id != expected_prepared_id
            or operation.start_binding_id
            != operation_start_binding_id(expected_prepared_id)
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
                    ) != "PREPARED"):
                return GateResult(GateResultCode.INDETERMINATE)
            if not self._release_durable_prepared(
                durable, prepared.target_fence_token
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
                               subject: ProtectedEffectSubject) -> GateResult:
        with self._lock:
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
            if not self.platform.verify_prepared_effect(
                operation.intent.operation_id, subject.value,
                prepared.prepared_start,
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
            committed = self.commit(request, prepared.control_lease)
            if committed.code is not GateResultCode.COMMITTED:
                if not self._release_durable_prepared(
                    prepared.prepared_start, prepared.target_fence_token
                ):
                    self.registry.release(prepared.target_fence_token)
                    return GateResult(GateResultCode.INDETERMINATE,
                                      committed.canonical_result)
                self.registry.release(prepared.target_fence_token)
                return committed
            if self._fail_after_start:
                self._fail_after_start = False
                return GateResult(GateResultCode.INDETERMINATE, committed.canonical_result)
            if not self._audit_ok(self._audit_event(
                "PROTECTED_START", subject.value, GateAuditOutcome.APPLIED,
                service=prepared.target_capability.service_identity,
                dependencies=prepared.control_lease.dependencies,
                operation_id=proposed.intent.operation_id,
                start_id=proposed.start_binding_id,
                action_digest=prepared.prepared_start.prepared_start_id.raw_sha256,
                intent=proposed.intent,
            )):
                recovery = self._recover_post_start_audit_failure(
                    prepared, subject
                )
                self.registry.release(prepared.target_fence_token)
                if recovery.code is not GateResultCode.COMMITTED:
                    return GateResult(GateResultCode.INDETERMINATE,
                                      recovery.canonical_result)
                return GateResult(GateResultCode.AUDIT_FAILURE_AFTER_COMMIT,
                                  committed.canonical_result)
            continuation = object.__new__(LiveProtectedEffectContinuation)
            continuation._owner, continuation._nonce, continuation._used = self, self._nonce, False
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
            return GateResult(GateResultCode.START_COMMITTED, committed.canonical_result, continuation)

    def perform_effect(self, continuation: LiveProtectedEffectContinuation,
                       capability: TargetPublicationCapability | MergeCapability) -> GateResult:
        with self._lock:
            if type(continuation) is not LiveProtectedEffectContinuation or not continuation._consume(self, self._nonce):
                return GateResult(GateResultCode.LEASE_CONSUMED)
            fence, subject = continuation.action_target_fence, continuation.subject
            try:
                materialization = continuation.materialization
                base_ref = continuation.base_ref
                target_registration = continuation.target_registration
                provenance_operation_id = continuation.provenance_operation_id
                if not continuation.target_fence_token.active or not self._is_active():
                    return GateResult(GateResultCode.LEASE_INVALID)
                durable = self.platform.prepared_effect_record(
                    continuation.operation_id, subject.value
                )
                if (type(durable) is not PreparedProtectedStart
                        or durable.prepared_start_id != continuation.prepared_start_id
                        or durable.state not in (
                            PreparedProtectedStartState.PREPARED,
                            PreparedProtectedStartState.CONSUMED,
                        )):
                    return GateResult(GateResultCode.INDETERMINATE)
                if not self._dependencies_fresh_set(continuation.dependencies):
                    return GateResult(GateResultCode.INDETERMINATE)
                if type(materialization) is not CandidateMaterialization:
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
                if not self.platform.verify_materialization(materialization):
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
                current = self.platform.marker(continuation.operation_id, subject.value)
                prerequisite_marker_id = None

                if subject is ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION:
                    if (capability is not self._publication
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
                    provenance = None if provenance_operation_id is None else self.platform.marker(
                        provenance_operation_id, ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION.value
                    )
                    published = None if provenance is None else provenance.preimage.effect_subject
                    if (capability is not self._publication
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
                    base_sha = self.platform.read_ref(fence.repository_id, base_ref)
                    if base_sha is None or base_sha != fence.base_expected_sha:
                        return GateResult(GateResultCode.PRECONDITION_CONFLICT)
                    existing_subject = None if current is None else current.preimage.effect_subject
                    if current is not None and type(existing_subject) is not CreatedCandidatePrEffectSubject:
                        return GateResult(GateResultCode.INDETERMINATE)
                    number = (
                        self.platform.next_pull_request_number()
                        if existing_subject is None
                        else existing_subject.pull_request_number.value
                    )
                    effect_subject = CreatedCandidatePrEffectSubject(
                        fence.repository_id, GitHubPullRequestNumber(number),
                        GitRef(materialization.candidate_branch.value), materialization.commit,
                        GitRef(base_ref.value), base_sha,
                    )
                else:
                    provenance = None if provenance_operation_id is None else self.platform.marker(
                        provenance_operation_id, ProtectedEffectSubject.PULL_REQUEST_CREATION.value
                    )
                    created = None if provenance is None else provenance.preimage.effect_subject
                    if (capability is not self._merge
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
                    applied = self.platform.publish_and_mark(
                        fence.repository_id, materialization.candidate_branch,
                        materialization.commit, marker,
                        _fence_token=continuation.target_fence_token,
                    )
                elif subject is ProtectedEffectSubject.PULL_REQUEST_CREATION:
                    applied = self.platform.create_pull_request_and_mark(
                        fence.repository_id, materialization.candidate_branch, base_ref,
                        materialization.commit, marker,
                        _fence_token=continuation.target_fence_token,
                    ) is not None
                else:
                    applied = self.platform.fast_forward_and_mark(
                        fence.repository_id, fence.ref, fence.expected_sha,
                        materialization.commit, materialization.base,
                        effect_subject.pull_request_number.value, marker,
                        _fence_token=continuation.target_fence_token,
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
                self.registry.release(continuation.target_fence_token)

    def _fail_started_effect_proven_absent(
        self, continuation: LiveProtectedEffectContinuation,
    ) -> GateResult:
        if self.platform.marker(
            continuation.operation_id, continuation.subject.value
        ) is not None:
            return GateResult(GateResultCode.INDETERMINATE)
        if not self.platform.release_prepared_effect(
            continuation.operation_id, continuation.subject.value,
            _fence_token=continuation.target_fence_token,
        ):
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
        subject = marker.preimage.effect_subject
        if type(subject) is PublishedCandidateRefEffectSubject:
            return self.platform.read_ref(subject.repository_id, subject.destination_branch) == subject.published_commit
        if type(subject) is CreatedCandidatePrEffectSubject:
            pr = self.platform.pull_request(subject.pull_request_number)
            return pr is not None and (
                pr.repository_id, GitRef(pr.head.value), pr.head_sha,
                GitRef(pr.base.value), pr.base_sha, pr.merged,
            ) == (subject.repository_id, subject.head_ref, subject.head_sha,
                  subject.base_ref, subject.base_sha, False)
        if type(subject) is FastForwardMergeEffectSubject:
            pr = self.platform.pull_request(subject.pull_request_number)
            return (pr is not None and pr.merged
                    and self.platform.read_ref(subject.repository_id, CanonicalBranchRef(subject.integration_ref.value)) == subject.after_sha)
        return False

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
        lease = None
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
            independence = (
                self._trusted_external_state_independence()
                if not dependencies.dependencies else None
            )
            lease = self.acquire_control_lease(
                self._control, dependencies, independence
            )
            if lease is None:
                return GateResult(GateResultCode.INDETERMINATE)
            marker = self.platform.marker(operation_id, subject.value)
            prepared_state = self.platform.prepared_effect_state(
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
            if marker is not None and prepared_state == "CONSUMED":
                finding_value = (
                    ReconciliationFinding.INTENDED_EFFECT_PROVEN
                    if self._marker_postcondition(marker)
                    else ReconciliationFinding.UNRESOLVED
                )
            elif marker is None and prepared_state in ("PREPARED", "RELEASED"):
                if prepared_state == "PREPARED" and not self.platform.release_prepared_effect(
                    operation_id, subject.value, _fence_token=recovery_token
                ):
                    return GateResult(GateResultCode.INDETERMINATE)
                if self.platform.prepared_effect_state(operation_id, subject.value) != "RELEASED":
                    return GateResult(GateResultCode.INDETERMINATE)
                finding_value = ReconciliationFinding.INTENDED_EFFECT_PROVEN_ABSENT
            else:
                return GateResult(GateResultCode.INDETERMINATE)
            finding = object.__new__(TrustedReconciliationFinding)
            object.__setattr__(finding, "finding", finding_value)
            try:
                request = self.controller._decide_reconciliation(
                    operation.intent.task_id, operation.intent.operation_id, finding
                )
            except (TypeError, ValueError):
                self.registry.release(lease.fence_token)
                return GateResult(GateResultCode.INDETERMINATE)
            committed = self.commit(request, lease)
            if committed.code is not GateResultCode.COMMITTED:
                return GateResult(GateResultCode.INDETERMINATE,
                                  committed.canonical_result)
            outcome = {
                ReconciliationFinding.INTENDED_EFFECT_PROVEN: GateAuditOutcome.RECONCILED_SUCCEEDED,
                ReconciliationFinding.INTENDED_EFFECT_PROVEN_ABSENT: GateAuditOutcome.RECONCILED_FAILED,
                ReconciliationFinding.UNRESOLVED: GateAuditOutcome.INDETERMINATE,
            }[finding_value]
            if not self._audit_ok(self._audit_event(
                "RECOVERY", subject.value, outcome,
                service=self.binding.control_state_principal,
                dependencies=dependencies,
                operation_id=operation.intent.operation_id,
                start_id=operation.start_binding_id, marker=marker,
                intent=operation.intent,
            )):
                return GateResult(GateResultCode.AUDIT_FAILURE_AFTER_COMMIT,
                                  committed.canonical_result)
            code = {
                ReconciliationFinding.INTENDED_EFFECT_PROVEN: GateResultCode.EFFECT_SUCCEEDED,
                ReconciliationFinding.INTENDED_EFFECT_PROVEN_ABSENT: GateResultCode.EFFECT_FAILED,
                ReconciliationFinding.UNRESOLVED: GateResultCode.INDETERMINATE,
            }[finding_value]
            return GateResult(code, committed.canonical_result)
        finally:
            if lease is not None and lease.fence_token.active:
                self.registry.release(lease.fence_token)
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
            _restart_from=previous,
        )
        restarted._profiles.update(self._profiles)
        restarted._readers.update(self._readers)
        restarted._fixture_transports.update(self._fixture_transports)
        restarted._authorization_contexts.update(self._authorization_contexts)
        restarted._evidence_contexts.update(self._evidence_contexts)
        restarted._completion_contexts.update(self._completion_contexts)
        return restarted

    def fail_after_start_commit_for_test(self) -> None:
        """Inject process loss immediately after the canonical start linearization."""
        self._fail_after_start = True

    def set_recovery_fence_hook_for_test(self, hook) -> None:
        """Run one fixture test hook after the exact recovery fence is live."""
        if hook is not None and not callable(hook):
            raise TypeError("recovery fence hook must be callable or None")
        self._recovery_fence_hook = hook

class ControlStateGate:
    """Persistence-only facade; it exposes no publication or merge capability."""

    __slots__ = ("_runtime",)

    def __init__(self, runtime: FixtureProtectedGateRuntime) -> None:
        if type(runtime) is not FixtureProtectedGateRuntime:
            raise TypeError("exact fixture runtime required")
        self._runtime = runtime

    def commit(self, request: ControlStateCommitRequest, lease: ControlStateCommitLease) -> GateResult:
        return self._runtime.commit(request, lease)


class TargetPublicationGate:
    """Publication-only facade; it cannot mutate canonical control state or merge."""

    __slots__ = ("_runtime",)

    def __init__(self, runtime: FixtureProtectedGateRuntime) -> None:
        if type(runtime) is not FixtureProtectedGateRuntime:
            raise TypeError("exact fixture runtime required")
        self._runtime = runtime

    def perform(self, continuation: LiveProtectedEffectContinuation) -> GateResult:
        return self._runtime.perform_effect(
            continuation, self._runtime.publication_capability,
        )


class MergeGate:
    """Merge-only facade; it exposes neither canonical persistence nor publication."""

    __slots__ = ("_runtime",)

    def __init__(self, runtime: FixtureProtectedGateRuntime) -> None:
        if type(runtime) is not FixtureProtectedGateRuntime:
            raise TypeError("exact fixture runtime required")
        self._runtime = runtime

    def perform(self, continuation: LiveProtectedEffectContinuation) -> GateResult:
        return self._runtime.perform_effect(
            continuation, self._runtime.merge_capability,
        )


def operation_start_binding_id(prepared_start_id: PreparedProtectedStartId) -> OperationStartBindingId:
    """Project the frozen prepared-start digest into its distinct lower-layer nominal type."""
    if type(prepared_start_id) is not PreparedProtectedStartId:
        raise TypeError("exact PreparedProtectedStartId required")
    return OperationStartBindingId(prepared_start_id.raw_sha256)


def publication_context_is_valid(registration: AdmittedTargetRegistration,
                                 capability: TargetPublicationCapability,
                                 materialization: CandidateMaterialization,
                                 operation_integration_ref: object = None) -> bool:
    """Validate namespace/principal/ref separation without cross-nominal equality."""
    if (type(registration) is not AdmittedTargetRegistration
            or type(capability) is not TargetPublicationCapability
            or type(materialization) is not CandidateMaterialization):
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
