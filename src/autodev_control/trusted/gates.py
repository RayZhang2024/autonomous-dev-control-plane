"""G7 protected fixture gates.

The gates in this module are a semantic fixture implementation.  They have no
provider, network, credential, workflow, or controlled-runtime integration.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
from threading import RLock

from .audit import FixtureGateAudit, GateAuditOutcome
from .backend import (
    CanonicalTransaction, CanonicalWriteResult, CanonicalWriteStatus,
    InMemoryCanonicalStateBackend, ReplaceOperation,
)
from .errors import G4FailureCode
from .fixture_platform import FixtureGitPlatform, ProtectedEffectMarker
from .identity import GitRef, GitSha, ImmutableConfigId, OperationStartBindingId, RootContextId
from .materialization import CandidateMaterialization, inventory_is_authorized
from .operation import (
    AuthoritativeStateBindingId, IntegrationBound, OperationId, OperationRecord,
    OperationState, transition_operation,
)
from .scope import CanonicalBranchRef, GitHubRepositoryId, MutationScope, ServicePrincipalId
from .state_reader import (
    AuthoritativeObservationProfile, AuthoritativeStateReadStatus, GitHubStateReader,
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

    def __post_init__(self) -> None:
        values = (self.control_state_principal, self.publication_principal, self.merge_principal)
        if type(self.root_context_id) is not RootContextId or type(self.runtime_generation) is not FixtureRuntimeGeneration:
            raise TypeError("runtime identity has wrong exact type")
        if any(type(item) is not ServicePrincipalId for item in values):
            raise TypeError("gate principal has wrong exact type")
        if len(set(values)) != 3:
            raise ValueError("control, publication, and merge principals must be pairwise distinct")


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
    __slots__ = ("root_context_id", "runtime_generation", "runtime_binding", "dependencies", "capability")


class PreparedStartCommitLease(_OneUse):
    __slots__ = ("control_lease", "action_target_fence", "prepared_start", "target_capability", "runtime_binding", "authorized_scope", "root_forbidden_scope")


class LiveProtectedEffectContinuation(_OneUse):
    __slots__ = ("operation_id", "idempotency_key", "action_id", "start_binding_id", "subject", "action_target_fence", "integration_binding", "authorized_scope", "root_forbidden_scope", "dependencies")


@dataclass(frozen=True, slots=True)
class ActionTargetFence:
    repository_id: GitHubRepositoryId
    ref: CanonicalBranchRef
    expected_sha: GitSha | None
    platform_generation: int

    def __post_init__(self) -> None:
        if type(self.repository_id) is not GitHubRepositoryId or type(self.ref) is not CanonicalBranchRef:
            raise TypeError("action target identity has wrong exact type")
        if self.expected_sha is not None and type(self.expected_sha) is not GitSha:
            raise TypeError("expected_sha must be exact GitSha or None")
        if type(self.platform_generation) is not int or self.platform_generation < 1:
            raise ValueError("platform generation must be positive")


class PreparedProtectedStart:
    __slots__ = ("operation", "subject", "fence", "_state", "_owner", "_nonce")

    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("prepared protected starts are gate-private")

    @property
    def state(self) -> PreparedProtectedStartState:
        return self._state

    def _consume(self, owner: object, nonce: object) -> bool:
        if self._owner is not owner or self._nonce is not nonce or self._state is not PreparedProtectedStartState.PREPARED:
            return False
        self._state = PreparedProtectedStartState.CONSUMED
        return True

    def _release(self, owner: object, nonce: object) -> bool:
        if self._owner is not owner or self._nonce is not nonce or self._state is not PreparedProtectedStartState.PREPARED:
            return False
        self._state = PreparedProtectedStartState.RELEASED
        return True

    def __reduce__(self) -> object:
        raise TypeError("prepared gate state cannot be serialized")


@dataclass(frozen=True, slots=True)
class PublishedCandidateRefEffectSubject:
    materialization_id: object
    destination: CanonicalBranchRef

    def __post_init__(self) -> None:
        from .identity import CandidateMaterializationId
        if type(self.materialization_id) is not CandidateMaterializationId or type(self.destination) is not CanonicalBranchRef:
            raise TypeError("published-ref subject has wrong exact type")


@dataclass(frozen=True, slots=True)
class CreatedCandidatePrEffectSubject:
    published_candidate_ref_operation_id: OperationId
    destination: CanonicalBranchRef

    def __post_init__(self) -> None:
        if type(self.published_candidate_ref_operation_id) is not OperationId or type(self.destination) is not CanonicalBranchRef:
            raise TypeError("created-PR subject has wrong exact type")


@dataclass(frozen=True, slots=True)
class FastForwardMergeEffectSubject:
    created_candidate_pr_operation_id: OperationId
    integration_ref: CanonicalBranchRef

    def __post_init__(self) -> None:
        if type(self.created_candidate_pr_operation_id) is not OperationId or type(self.integration_ref) is not CanonicalBranchRef:
            raise TypeError("merge subject has wrong exact type")


class ControlStateCommitRequest:
    __slots__ = ("command_kind", "transaction", "_key")

    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("commit requests are emitted only by DeterministicTrustedController")


def _request(kind: TrustedControlCommandKind, transaction: CanonicalTransaction, key: object) -> ControlStateCommitRequest:
    value = object.__new__(ControlStateCommitRequest)
    value.command_kind, value.transaction, value._key = kind, transaction, key
    return value


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


class DeterministicTrustedController:
    """Closed command-to-proposal boundary; caller G4 objects are never accepted."""

    __slots__ = ("_key",)

    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("trusted controller is installed only by the active gate runtime")

    def _prepare_commit(self, command_kind: TrustedControlCommandKind,
                        transaction: CanonicalTransaction) -> ControlStateCommitRequest:
        if type(command_kind) is not TrustedControlCommandKind or type(transaction) is not CanonicalTransaction:
            raise TypeError("exact closed command and canonical transaction required")
        return _request(command_kind, transaction, self._key)


def _new_controller(key: object) -> DeterministicTrustedController:
    value = object.__new__(DeterministicTrustedController)
    value._key = key
    return value


class TrustedControlCommandBoundary:
    __slots__ = ("_controller",)

    def __init__(self, controller: DeterministicTrustedController) -> None:
        if type(controller) is not DeterministicTrustedController:
            raise TypeError("exact trusted controller required")
        self._controller = controller

    def submit(self, *_: object, **__: object) -> ControlStateCommitRequest:
        raise TypeError("callers submit semantic command inputs, never commit requests or transactions")

    def _accept_trusted_result(self, command_kind: TrustedControlCommandKind,
                               transaction: CanonicalTransaction) -> ControlStateCommitRequest:
        return self._controller._prepare_commit(command_kind, transaction)


class FixtureProtectedGateRuntime:
    """Holds fixture authority; a new instance is a process restart boundary."""

    __slots__ = ("binding", "backend", "platform", "audit", "controller", "boundary",
                 "_lock", "_nonce", "_controller_key", "_profiles", "_readers", "_control", "_publication", "_merge")

    def __init__(self, binding: GateRuntimeBinding, backend: InMemoryCanonicalStateBackend,
                 platform: FixtureGitPlatform, audit: FixtureGateAudit) -> None:
        if type(binding) is not GateRuntimeBinding or type(backend) is not InMemoryCanonicalStateBackend:
            raise TypeError("runtime binding/backend has wrong exact type")
        if type(platform) is not FixtureGitPlatform or type(audit) is not FixtureGateAudit:
            raise TypeError("fixture platform/audit has wrong exact type")
        self.binding, self.backend, self.platform, self.audit = binding, backend, platform, audit
        self._lock, self._nonce, self._controller_key = RLock(), object(), object()
        self._profiles: dict[ImmutableConfigId, AuthoritativeObservationProfile] = {}
        self._readers: dict[ImmutableConfigId, GitHubStateReader] = {}
        self._control = _mint_capability(ControlStateCapability, self._nonce, binding.control_state_principal)
        self._publication = _mint_capability(TargetPublicationCapability, self._nonce, binding.publication_principal)
        self._merge = _mint_capability(MergeCapability, self._nonce, binding.merge_principal)
        self.controller = _new_controller(self._controller_key)
        self.boundary = TrustedControlCommandBoundary(self.controller)

    @property
    def control_capability(self) -> ControlStateCapability:
        return self._control

    @property
    def publication_capability(self) -> TargetPublicationCapability:
        return self._publication

    @property
    def merge_capability(self) -> MergeCapability:
        return self._merge

    def register_authoritative_source(self, profile: AuthoritativeObservationProfile,
                                      reader: GitHubStateReader) -> None:
        """Install root-managed fixture read capability, never an opaque remembered digest."""
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

    def attest_external_state_independence(self) -> ExternalStateIndependence:
        value = object.__new__(ExternalStateIndependence)
        value._nonce = self._nonce
        return value

    def acquire_control_lease(self, capability: ControlStateCapability,
                              dependencies: ControlStateAuthoritativeDependencySet,
                              independence: ExternalStateIndependence | None = None) -> ControlStateCommitLease | None:
        if capability is not self._control or type(dependencies) is not ControlStateAuthoritativeDependencySet:
            return None
        if not dependencies.dependencies:
            if type(independence) is not ExternalStateIndependence or independence._nonce is not self._nonce:
                return None
        elif independence is not None:
            return None
        if not self._dependencies_fresh_set(dependencies):
            return None
        lease = ControlStateCommitLease(self, self._nonce)
        lease.root_context_id = self.binding.root_context_id
        lease.runtime_generation = self.binding.runtime_generation
        lease.runtime_binding = self.binding
        lease.dependencies = dependencies
        lease.capability = capability
        return lease

    def _dependencies_fresh(self, lease: ControlStateCommitLease) -> bool:
        return self._dependencies_fresh_set(lease.dependencies)

    def _dependencies_fresh_set(self, dependencies: ControlStateAuthoritativeDependencySet) -> bool:
        for item in dependencies.dependencies:
            profile = self._profiles.get(item.observation_profile_id)
            reader = self._readers.get(item.transport_config_id)
            if profile is None or reader is None:
                return False
            result = reader.read_authoritative(item.repository_id, profile)
            if result.status is not AuthoritativeStateReadStatus.SUCCESS or result.binding_id != item.expected_binding_id:
                return False
            snapshot = result.snapshot
            if (snapshot.repository_id, snapshot.observation_profile_id, snapshot.transport_config_id) != (
                item.repository_id, item.observation_profile_id, item.transport_config_id
            ):
                return False
        return True

    def commit(self, request: ControlStateCommitRequest, lease: ControlStateCommitLease) -> GateResult:
        with self._lock:
            if type(request) is not ControlStateCommitRequest or request._key is not self._controller_key:
                return GateResult(GateResultCode.REJECTED)
            if type(lease) is not ControlStateCommitLease or not self._dependencies_fresh(lease):
                return GateResult(GateResultCode.LEASE_INVALID)
            if (lease.runtime_binding is not self.binding or lease.root_context_id != self.binding.root_context_id
                    or lease.runtime_generation != self.binding.runtime_generation
                    or lease.capability is not self._control):
                return GateResult(GateResultCode.LEASE_INVALID)
            if not lease._consume(self, self._nonce):
                return GateResult(GateResultCode.LEASE_CONSUMED)
            runtime_id = f"{self.binding.root_context_id.value}@{self.binding.runtime_generation.value}"
            dependency_id = "|".join(
                f"{item.repository_id.value}:{item.observation_profile_id.value}:{item.transport_config_id.value}:{item.expected_binding_id.value}"
                for item in lease.dependencies.dependencies
            )
            audit_fields = dict(runtime_identity=runtime_id,
                                service_identity=self.binding.control_state_principal.value,
                                dependency_identity=dependency_id)
            if not self.audit.append("CONTROL_STATE", request.command_kind.value, GateAuditOutcome.ATTEMPTED, **audit_fields):
                return GateResult(GateResultCode.AUDIT_FAILURE_BEFORE_COMMIT)
            result = self.backend.apply(request.transaction)
            if result.status is not CanonicalWriteStatus.APPLIED:
                outcome = GateAuditOutcome.CAS_CONFLICT if result.status is CanonicalWriteStatus.CAS_CONFLICT else GateAuditOutcome.DENIED
                self.audit.append("CONTROL_STATE", request.command_kind.value, outcome, result.status.value, **audit_fields)
                return GateResult(GateResultCode.REJECTED, result)
            if not self.audit.append("CONTROL_STATE", request.command_kind.value, GateAuditOutcome.APPLIED, **audit_fields):
                return GateResult(GateResultCode.AUDIT_FAILURE_AFTER_COMMIT, result)
            return GateResult(GateResultCode.COMMITTED, result)

    def prepare_protected_start(self, operation: OperationRecord, subject: ProtectedEffectSubject,
                                fence: ActionTargetFence, control_lease: ControlStateCommitLease,
                                target_capability: TargetPublicationCapability | MergeCapability,
                                authorized_scope: MutationScope,
                                root_forbidden_scope: MutationScope) -> PreparedStartCommitLease:
        if type(operation) is not OperationRecord or operation.state is not OperationState.RESERVED:
            raise ValueError("only RESERVED operation may be prepared")
        if type(subject) is not ProtectedEffectSubject or type(fence) is not ActionTargetFence:
            raise TypeError("protected start inputs have wrong exact type")
        expected_capability = self._merge if subject is ProtectedEffectSubject.FAST_FORWARD_MERGE else self._publication
        if target_capability is not expected_capability:
            raise ValueError("action capability does not match exact gate/principal")
        if type(authorized_scope) is not MutationScope or type(root_forbidden_scope) is not MutationScope:
            raise TypeError("exact admitted/root mutation scopes required")
        prepared = self.prepare_action(operation, subject, fence)
        value = PreparedStartCommitLease(self, self._nonce)
        value.control_lease, value.action_target_fence = control_lease, fence
        value.prepared_start = prepared
        value.target_capability, value.runtime_binding = target_capability, self.binding
        value.authorized_scope, value.root_forbidden_scope = authorized_scope, root_forbidden_scope
        return value

    def prepare_action(self, operation: OperationRecord, subject: ProtectedEffectSubject,
                       fence: ActionTargetFence) -> PreparedProtectedStart:
        if type(operation) is not OperationRecord or operation.state is not OperationState.RESERVED:
            raise ValueError("only RESERVED operation may be prepared")
        value = object.__new__(PreparedProtectedStart)
        value.operation, value.subject, value.fence = operation, subject, fence
        value._state, value._owner, value._nonce = PreparedProtectedStartState.PREPARED, self, self._nonce
        return value

    def release_prepared_action(self, prepared: PreparedProtectedStart) -> bool:
        return type(prepared) is PreparedProtectedStart and prepared._release(self, self._nonce)

    def commit_protected_start(self, prepared: PreparedStartCommitLease,
                               request: ControlStateCommitRequest, operation: OperationRecord,
                               subject: ProtectedEffectSubject) -> GateResult:
        with self._lock:
            if type(prepared) is not PreparedStartCommitLease or not prepared._consume(self, self._nonce):
                return GateResult(GateResultCode.LEASE_CONSUMED)
            expected_capability = self._merge if subject is ProtectedEffectSubject.FAST_FORWARD_MERGE else self._publication
            if prepared.runtime_binding is not self.binding or prepared.target_capability is not expected_capability:
                return GateResult(GateResultCode.LEASE_INVALID)
            fence = prepared.action_target_fence
            if self.platform.snapshot().generation != fence.platform_generation or self.platform.read_ref(fence.repository_id, fence.ref) != fence.expected_sha:
                prepared.prepared_start._release(self, self._nonce)
                conflict = transition_operation(
                    operation, operation.revision, OperationState.CONFLICT,
                    reason_code=G4FailureCode.ACTION_PRECONDITION_CONFLICT,
                )
                conflict_request = _request(
                    request.command_kind,
                    CanonicalTransaction(
                        request.transaction.expected_state_occurrence,
                        request.transaction.conditions,
                        (ReplaceOperation(operation.revision, conflict.operation),),
                    ),
                    self._controller_key,
                )
                conflict_commit = self.commit(conflict_request, prepared.control_lease)
                if conflict_commit.code is not GateResultCode.COMMITTED:
                    return conflict_commit
                return GateResult(GateResultCode.ACTION_PRECONDITION_CONFLICT,
                                  conflict_commit.canonical_result,
                                  failure_code=G4FailureCode.ACTION_PRECONDITION_CONFLICT)
            committed = self.commit(request, prepared.control_lease)
            if committed.code is not GateResultCode.COMMITTED:
                prepared.prepared_start._release(self, self._nonce)
                return committed
            proposed = next((mutation.operation for mutation in request.transaction.mutations
                             if hasattr(mutation, "operation") and type(mutation.operation) is OperationRecord
                             and mutation.operation.intent.operation_id == operation.intent.operation_id), None)
            if proposed is None or proposed.state is not OperationState.PERFORMING or proposed.start_binding_id is None:
                prepared.prepared_start._release(self, self._nonce)
                return GateResult(GateResultCode.REJECTED)
            self.platform.prepare_effect(proposed.intent.operation_id.value, subject.value)
            start_dependencies = "|".join(
                f"{item.repository_id.value}:{item.observation_profile_id.value}:{item.transport_config_id.value}:{item.expected_binding_id.value}"
                for item in prepared.control_lease.dependencies.dependencies
            )
            if not self.audit.append(
                "PROTECTED_START", proposed.intent.operation_id.value, GateAuditOutcome.APPLIED,
                runtime_identity=f"{self.binding.root_context_id.value}@{self.binding.runtime_generation.value}",
                service_identity=prepared.target_capability.service_identity.value,
                dependency_identity=start_dependencies,
            ):
                prepared.prepared_start._consume(self, self._nonce)
                return GateResult(GateResultCode.AUDIT_FAILURE_AFTER_COMMIT, committed.canonical_result)
            prepared.prepared_start._consume(self, self._nonce)
            continuation = LiveProtectedEffectContinuation(self, self._nonce)
            continuation.operation_id = proposed.intent.operation_id
            continuation.idempotency_key = proposed.intent.idempotency_key
            continuation.action_id = proposed.intent.action_id
            continuation.start_binding_id = proposed.start_binding_id
            continuation.subject = subject
            continuation.action_target_fence = fence
            continuation.integration_binding = proposed.intent.integration_binding
            continuation.authorized_scope = prepared.authorized_scope
            continuation.root_forbidden_scope = prepared.root_forbidden_scope
            continuation.dependencies = prepared.control_lease.dependencies
            return GateResult(GateResultCode.START_COMMITTED, committed.canonical_result, continuation)

    def perform_effect(self, continuation: LiveProtectedEffectContinuation,
                       capability: TargetPublicationCapability | MergeCapability,
                       *, materialization: CandidateMaterialization | None = None,
                       base_ref: CanonicalBranchRef | None = None,
                       target_registration: AdmittedTargetRegistration | None = None,
                       provenance_operation_id: OperationId | None = None) -> GateResult:
        with self._lock:
            if type(continuation) is not LiveProtectedEffectContinuation or not continuation._consume(self, self._nonce):
                return GateResult(GateResultCode.LEASE_CONSUMED)
            fence, subject = continuation.action_target_fence, continuation.subject
            if not self._dependencies_fresh_set(continuation.dependencies):
                return GateResult(GateResultCode.INDETERMINATE)
            marker = self.platform.marker(continuation.operation_id.value, subject.value)
            if marker is not None:
                return GateResult(GateResultCode.ALREADY_APPLIED)
            try:
                if type(materialization) is not CandidateMaterialization:
                    return GateResult(GateResultCode.REJECTED)
                if not self.platform.verify_materialization(materialization):
                    return GateResult(GateResultCode.REJECTED)
                if not inventory_is_authorized(materialization.inventory, continuation.authorized_scope,
                                               continuation.root_forbidden_scope):
                    return GateResult(GateResultCode.REJECTED)
                if (type(target_registration) is not AdmittedTargetRegistration
                        or not inventory_is_authorized(
                            materialization.inventory,
                            target_registration.ordinary_allowed_scope,
                            target_registration.ordinary_forbidden_scope,
                        )):
                    return GateResult(GateResultCode.REJECTED)
                pre_state = "ABSENT" if fence.expected_sha is None else fence.expected_sha.value

                def exact_marker(result_identity: str) -> ProtectedEffectMarker:
                    action_digest = hashlib.sha256("\0".join((
                        subject.value, continuation.action_id.value,
                        materialization.materialization_id.value,
                        materialization.inventory.inventory_id.value, pre_state, result_identity,
                    )).encode()).hexdigest()
                    return ProtectedEffectMarker(
                        continuation.operation_id.value, continuation.idempotency_key.value,
                        continuation.action_id.value, action_digest,
                        materialization.materialization_id.value,
                        materialization.inventory.inventory_id.value,
                        continuation.start_binding_id.value, self.binding.root_context_id.value,
                        self.binding.runtime_generation.value, capability.service_identity.value,
                        subject.value, fence.repository_id, pre_state, result_identity, result_identity,
                    )

                if subject is ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION:
                    if (capability is not self._publication
                            or type(target_registration) is not AdmittedTargetRegistration
                            or fence.ref != materialization.candidate_branch
                            or fence.expected_sha is not None
                            or not publication_context_is_valid(target_registration, capability, materialization,
                                                                continuation.integration_binding)):
                        return GateResult(GateResultCode.REJECTED)
                    if self.platform.read_ref(fence.repository_id, materialization.candidate_branch) is not None:
                        return GateResult(GateResultCode.PRECONDITION_CONFLICT)
                    result_identity = materialization.candidate_branch.value + "@" + materialization.commit.value
                    if not self.platform.publish_and_mark(
                        fence.repository_id, materialization.candidate_branch,
                        materialization.commit, exact_marker(result_identity),
                    ):
                        return GateResult(GateResultCode.PRECONDITION_CONFLICT)
                elif subject is ProtectedEffectSubject.PULL_REQUEST_CREATION:
                    provenance = None if provenance_operation_id is None else self.platform.marker(
                        provenance_operation_id.value, ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION.value
                    )
                    if (capability is not self._publication
                            or type(base_ref) is not CanonicalBranchRef
                            or type(target_registration) is not AdmittedTargetRegistration
                            or target_registration.target_publication.service_identity != capability.service_identity
                            or target_registration.merge is None
                            or base_ref not in target_registration.merge.allowed_integration_refs
                            or fence.ref != materialization.candidate_branch
                            or fence.expected_sha != materialization.commit
                            or provenance is None
                            or provenance.result_identity != materialization.candidate_branch.value + "@" + materialization.commit.value):
                        return GateResult(GateResultCode.REJECTED)
                    result_identity = str(self.platform.next_pull_request_number())
                    pr = self.platform.create_pull_request_and_mark(
                        fence.repository_id, materialization.candidate_branch, base_ref,
                        materialization.commit, exact_marker(result_identity),
                    )
                    if pr is None:
                        return GateResult(GateResultCode.INDETERMINATE)
                else:
                    provenance = None if provenance_operation_id is None else self.platform.marker(
                        provenance_operation_id.value, ProtectedEffectSubject.PULL_REQUEST_CREATION.value
                    )
                    if (capability is not self._merge
                            or type(target_registration) is not AdmittedTargetRegistration
                            or target_registration.merge is None
                            or target_registration.merge.service_identity != capability.service_identity
                            or fence.ref not in target_registration.merge.allowed_integration_refs
                            or provenance is None):
                        return GateResult(GateResultCode.REJECTED)
                    result_identity = materialization.commit.value
                    try:
                        pull_request_number = int(provenance.result_identity)
                    except (TypeError, ValueError):
                        return GateResult(GateResultCode.REJECTED)
                    if not self.platform.fast_forward_and_mark(
                        fence.repository_id, fence.ref, fence.expected_sha,
                        materialization.commit, materialization.base,
                        pull_request_number, exact_marker(result_identity),
                    ):
                        return GateResult(GateResultCode.PRECONDITION_CONFLICT)
            except Exception:
                self.audit.append(subject.value, continuation.operation_id.value, GateAuditOutcome.INDETERMINATE)
                return GateResult(GateResultCode.INDETERMINATE)
            if not self.audit.append(
                subject.value, continuation.operation_id.value, GateAuditOutcome.APPLIED,
                runtime_identity=f"{self.binding.root_context_id.value}@{self.binding.runtime_generation.value}",
                service_identity=capability.service_identity.value,
                dependency_identity="|".join(
                    f"{item.repository_id.value}:{item.observation_profile_id.value}:{item.transport_config_id.value}:{item.expected_binding_id.value}"
                    for item in continuation.dependencies.dependencies
                ),
            ):
                return GateResult(GateResultCode.AUDIT_FAILURE_AFTER_COMMIT)
            return GateResult(GateResultCode.EFFECT_SUCCEEDED)

    def reconcile_recovered_effect(self, operation: OperationRecord,
                                   subject: ProtectedEffectSubject) -> OperationState:
        """Classify recovery only; it never recreates an effect continuation."""
        if type(operation) is not OperationRecord or operation.state not in (OperationState.PERFORMING, OperationState.INDETERMINATE):
            raise ValueError("only unresolved started operations can be recovered")
        if type(subject) is not ProtectedEffectSubject:
            raise TypeError("subject has wrong exact type")
        marker = self.platform.marker(operation.intent.operation_id.value, subject.value)
        prepared = self.platform.prepared_effect_state(operation.intent.operation_id.value, subject.value)
        if marker is not None and prepared == "CONSUMED":
            return OperationState.SUCCEEDED
        if marker is None and prepared == "PREPARED":
            return OperationState.FAILED if self.platform.release_prepared_effect(
                operation.intent.operation_id.value, subject.value
            ) else OperationState.INDETERMINATE
        return OperationState.INDETERMINATE

    def restart(self) -> "FixtureProtectedGateRuntime":
        return FixtureProtectedGateRuntime(
            GateRuntimeBinding(self.binding.root_context_id,
                               self.binding.runtime_generation,
                               self.binding.control_state_principal, self.binding.publication_principal,
                               self.binding.merge_principal),
            self.backend, self.platform, self.audit,
        )


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

    def perform(self, continuation: LiveProtectedEffectContinuation, *,
                materialization: CandidateMaterialization, base_ref: CanonicalBranchRef | None,
                target_registration: AdmittedTargetRegistration,
                provenance_operation_id: OperationId | None = None) -> GateResult:
        return self._runtime.perform_effect(
            continuation, self._runtime.publication_capability,
            materialization=materialization, base_ref=base_ref,
            target_registration=target_registration,
            provenance_operation_id=provenance_operation_id,
        )


class MergeGate:
    """Merge-only facade; it exposes neither canonical persistence nor publication."""

    __slots__ = ("_runtime",)

    def __init__(self, runtime: FixtureProtectedGateRuntime) -> None:
        if type(runtime) is not FixtureProtectedGateRuntime:
            raise TypeError("exact fixture runtime required")
        self._runtime = runtime

    def perform(self, continuation: LiveProtectedEffectContinuation, *,
                materialization: CandidateMaterialization,
                target_registration: AdmittedTargetRegistration,
                provenance_operation_id: OperationId) -> GateResult:
        return self._runtime.perform_effect(
            continuation, self._runtime.merge_capability,
            materialization=materialization, target_registration=target_registration,
            provenance_operation_id=provenance_operation_id,
        )


def operation_start_binding_id(operation_id: OperationId, fence: ActionTargetFence,
                               subject: ProtectedEffectSubject) -> OperationStartBindingId:
    if type(operation_id) is not OperationId or type(fence) is not ActionTargetFence or type(subject) is not ProtectedEffectSubject:
        raise TypeError("start binding inputs have wrong exact type")
    payload = "\0".join((operation_id.value, subject.value, fence.repository_id.value,
                         fence.ref.value, "" if fence.expected_sha is None else fence.expected_sha.value,
                         str(fence.platform_generation)))
    return OperationStartBindingId(hashlib.sha256(payload.encode()).hexdigest())


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
    if type(operation_integration_ref) is GitRef:
        return GitRef(destination.value) != operation_integration_ref
    if operation_integration_ref is not None and type(operation_integration_ref) is not CanonicalBranchRef:
        return False
    if type(operation_integration_ref) is CanonicalBranchRef:
        return GitRef(destination.value) != GitRef(operation_integration_ref.value)
    return True
