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










































# Compatibility aliases intentionally preserve the one closed lower-layer model.

































from .runtime_roles import *
from .runtime_roles import (
    _DeterministicStartDenied, _TaskSemanticDenied, _canonical_semantic_dependency_union,
    _mint_capability, _new_controller,
)


class FixtureProtectedGateRuntime:
    """Holds fixture authority; a new instance is a process restart boundary."""

    __slots__ = ("binding", "backend", "platform", "audit", "controller", "boundary",
                 "registry", "_lock", "_nonce", "_controller_key", "_t_context", "_c_context",
                 "_p_context", "_m_context", "_f_read_verify_client", "_publication_authority_client",
                 "_merge_authority_client", "_start_held_recovery_authority", "_recovery_coordinator", "_t_to_c_channel_token", "_t_to_p_channel_token",
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
        self._recovery_coordinator = FixtureRecoveryCoordinator(
            self, self._start_held_recovery_authority,
        )
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
            self._publication_gate_runtime, self._t_to_p_channel_token,
            self._t_context,
        )

    @property
    def merge_gate_client(self) -> MergeGateClient:
        return _FixtureMergeGateClient(
            self._merge_gate_runtime, self._t_to_m_channel_token,
            self._t_context,
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


class FixtureRecoveryCoordinator:
    """External fixture orchestration for absence proof and held-lease release.

    This coordinator is owned by the composition harness. It is deliberately
    absent from T/P/M role objects and their ordinary invocation clients.
    """

    __slots__ = ("_runtime", "_recovery_authority")

    def __init__(
        self, runtime: FixtureProtectedGateRuntime,
        recovery_authority: FixtureStartHeldRecoveryAuthority,
    ) -> None:
        if (type(runtime) is not FixtureProtectedGateRuntime
                or type(recovery_authority) is not FixtureStartHeldRecoveryAuthority):
            raise TypeError("exact fixture recovery coordinator inputs required")
        self._runtime, self._recovery_authority = runtime, recovery_authority

    def release_proven_absence(self, observation: GateResult) -> bool:
        continuation = getattr(observation, "continuation", None)
        if type(continuation) is not LiveProtectedEffectContinuation:
            return False
        if continuation.subject is ProtectedEffectSubject.FAST_FORWARD_MERGE:
            role_runtime = self._runtime._merge_gate_runtime
        else:
            role_runtime = self._runtime._publication_gate_runtime
        return _release_fixture_observed_absence(
            role_runtime, self._recovery_authority, observation,
        )


class _FixturePublicationGateClient:
    """T-side fixture client of an independent P runtime."""

    __slots__ = ("_runtime", "_channel_token", "_t_context")

    def __init__(
        self, runtime: PublicationGateRuntime,
        channel_token: object, t_context: RuntimeSecurityContext,
    ) -> None:
        if (type(runtime) is not PublicationGateRuntime
                or type(t_context) is not RuntimeSecurityContext):
            raise TypeError("exact publication gate runtime required")
        self._runtime = runtime
        self._channel_token, self._t_context = channel_token, t_context

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
        return result


class _FixtureMergeGateClient:
    """T-side fixture client of an independent M runtime."""

    __slots__ = ("_runtime", "_channel_token", "_t_context")

    def __init__(
        self, runtime: MergeGateRuntime,
        channel_token: object, t_context: RuntimeSecurityContext,
    ) -> None:
        if (type(runtime) is not MergeGateRuntime
                or type(t_context) is not RuntimeSecurityContext):
            raise TypeError("exact merge gate runtime required")
        self._runtime = runtime
        self._channel_token, self._t_context = channel_token, t_context

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
        return result
