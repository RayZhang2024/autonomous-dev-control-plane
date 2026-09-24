import pickle
import inspect
import threading
import hashlib
from dataclasses import FrozenInstanceError, replace

import pytest

from autodev_control.trusted.audit import (
    AuditAppendStatus, FixtureGateAudit, GateAuditAuthoritativeDependency,
    GateAuditEventPreimage,
    GateAuditOutcome, build_gate_audit_event,
)
from autodev_control.trusted.authorization import (
    AdmittedAuthorization, AuthorizationOperationalConstraints, DelegationAllowance,
    DirectAuthoritySource,
)
from autodev_control.trusted.backend import (
    BackendGeneration, CanonicalStateOccurrenceBinding, CanonicalTransaction,
    CanonicalStateReadClient,
    CanonicalWriteStatus, CreateAuthorization, CreateContract,
    InMemoryCanonicalStateBackend, OperationRevisionEquals, ReplaceOperation,
    ReplaceTask, ResolvedTargetRegistration,
    TaskRevisionEquals,
    canonical_json_bytes,
)
from autodev_control.trusted.fixture_platform import (
    FixtureFenceConflict, FixtureGitPlatform,
    ProtectedEffectMarkerPreimage,
    PublishedCandidateRefEffectSubject, build_protected_effect_marker,
)
from autodev_control.trusted.gates import *
from autodev_control.trusted.gates import _TaskSemanticDenied
from autodev_control.trusted.runtime_authority import (
    AuthenticatedCallerVerifier, ControlStateGateClient, ControllerRequestContext,
    MergeAuthorityClient, MergeGateClient,
    ProtectedGateCommand, PublicationAuthorityClient, RuntimeSecurityContext,
    PublicationGateClient, TrustedRuntimeRole,
    _issue_fixture_caller_context,
)
import autodev_control.trusted.gates as gates_module
from autodev_control.trusted.identity import (
    CandidateMaterializationId, GitRef, GitSha, ImmutableConfigId,
    LogicalIdentifier, MutationInventoryId, PreparedProtectedStartId,
    RawSha256, RootContextId,
)
from autodev_control.trusted.operation import (
    AdmissionEventId, AuthoritativeStateBindingId, CandidateId,
    CompletionRuleSetId, EvidenceId, IntegrationBound, NotIntegrationBound, OperationActionId, OperationEffectClass, OperationId,
    OperationIdempotencyKey, OperationPurpose, OperationState, OperationSubjectId,
    TrustedOperationClassification, construct_trusted_operation_intent,
)
from autodev_control.trusted.manifest import PolicyEpochIdentity, TrustedManifestId
from autodev_control.trusted.materialization import (
    FixtureGitCommit, FixtureGitObjectStore, FixtureGitTree, FixtureGitTreeEntry,
    GitObjectKind, GitTreeEntry, build_candidate_materialization,
)
from autodev_control.trusted.scope import (
    AuthenticationEventId, AuthorizationId, AuthorizationKind, CanonicalBranchRef,
    CanonicalGitPath, ChangeType, ContractId, GitHubRepositoryId,
    HumanPrincipalId, MutationScope, MutationScopeRule, RepositorySelector,
    RiskTier, ServicePrincipalId, TargetRegistrationId, TaskCapability, TaskId,
)
from autodev_control.trusted.state import (
    CandidateApplicabilityDetermination, CompletionAggregate, DecisionEventId,
    RepairBudget, TaskEvaluationInput, TaskState,
)
from autodev_control.trusted.state_reader import (
    AuthenticatedGitHubReadTransport, AuthoritativeObservationProfile,
    AuthoritativeStateSnapshot, GitHubStateReader, NormalizedGitHubObservation,
    ReadRepositoryIdentity, RegisteredStateFactDescriptor,
    TrustedGitHubReadTransportBinding, authoritative_state_binding,
)
from autodev_control.trusted.target_registration import (
    AdmittedTargetRegistration, MergeConfiguration, TargetPublication,
)
from tests.trusted.contract_fixtures import (
    canonical_contract_fixture, trusted_admission_context_for_fixture,
)


REPO = GitHubRepositoryId("1")
REF = CanonicalBranchRef("refs/heads/main")
SHA = GitSha("a" * 40)
AUTH_RAW = RawSha256("6" * 64)
AUTH = AuthorizationId(AUTH_RAW)
TARGET = TargetRegistrationId(RawSha256("7" * 64))
TASK = TaskId("task")
CONTRACT = ContractId("contract")
ADMISSION = AdmissionEventId("admission")
EPOCH = PolicyEpochIdentity(TrustedManifestId(RawSha256("8" * 64)))
_, RAW, CONTRACT_RECORD = canonical_contract_fixture(
    contract_id=CONTRACT, task_id=TASK, target_registration_id=TARGET,
    repository_id=REPO, policy_epoch_identity=EPOCH, base_sha=SHA,
    allowed_repository_scope=True,
)


def mint(cls, **values):
    result = object.__new__(cls)
    for name, value in values.items():
        object.__setattr__(result, name, value)
    return result


def all_scope():
    return MutationScope((MutationScopeRule(RepositorySelector(), tuple(ChangeType)),))


def registration(integration_refs=(REF,)):
    return mint(
        AdmittedTargetRegistration, target_registration_id=TARGET,
        repository_id=REPO, policy_epoch_identity=EPOCH,
        approved_human_principal_id=HumanPrincipalId("admin"),
        authentication_event_id=AuthenticationEventId("target-approval"),
        path_model="git_utf8_regular_file/v1", protected_refs=(REF,),
        allowed_task_capabilities=(TaskCapability.IMPLEMENTATION, TaskCapability.MERGE),
        ordinary_allowed_scope=all_scope(), ordinary_forbidden_scope=MutationScope(()),
        risk_ceiling=RiskTier.SUPERVISED,
        target_publication=TargetPublication(ServicePrincipalId("publication"), ImmutableConfigId("publish")),
        merge=MergeConfiguration(ServicePrincipalId("merge"), ImmutableConfigId("merge-profile"), integration_refs),
        validation_profile_ids=(ImmutableConfigId("validation"),),
        controlled_runtime_profile_ids=(), event_state_profile_ids=(ImmutableConfigId("event"),),
        adapter_config_id=ImmutableConfigId("adapter"),
    )


def authorization():
    empty_ops = AuthorizationOperationalConstraints((), (), 0)
    return mint(
        AdmittedAuthorization, authorization_id=AUTH,
        kind=AuthorizationKind.DIRECT_HUMAN,
        authority_source=DirectAuthoritySource(HumanPrincipalId("human"), AuthenticationEventId("auth")),
        ancestry=(), task_id=TASK, contract_id=CONTRACT,
        contract_raw_sha256=RAW, target_registration_id=TARGET,
        authorized_capabilities=(TaskCapability.IMPLEMENTATION,),
        authorized_mutation_scope=all_scope(),
        authorized_operational_constraints=empty_ops,
        effective_authoritative_risk=RiskTier.ROUTINE,
        authorization_risk_ceiling=RiskTier.ROUTINE,
        delegation=DelegationAllowance(0, (), MutationScope(()), empty_ops, None),
        policy_epoch_identity=EPOCH,
    )


def runtime(target=None, object_store=None):
    target = target or registration()
    binding = GateRuntimeBinding(
        RootContextId(RawSha256("1" * 64)), FixtureRuntimeGeneration(1),
        ServicePrincipalId("control"), ServicePrincipalId("publication"), ServicePrincipalId("merge"),
    )
    resolved = mint(
        ResolvedTargetRegistration, registration=target,
        target_registration_id=TARGET, root_config_id=ImmutableConfigId("target-root"),
        policy_epoch_identity=EPOCH,
    )
    return FixtureProtectedGateRuntime(
        binding, InMemoryCanonicalStateBackend((resolved,)),
        FixtureGitPlatform(), FixtureGateAudit(),
        object_store=object_store or candidate_truth_store(),
    )


def dependency(binding="binding"):
    return ControlStateAuthoritativeDependency(
        REPO, ImmutableConfigId("observation"), ImmutableConfigId("transport"),
        AuthoritativeStateBindingId(binding),
    )


def source(profile_name="observation", transport_name="transport", owner="o"):
    transport_binding = object.__new__(TrustedGitHubReadTransportBinding)
    fields = dict(config_id=ImmutableConfigId(transport_name), expected_api_host_identity=ImmutableConfigId("host"),
                  authentication_mode_identity=ImmutableConfigId("auth"), service_identity=ServicePrincipalId("reader"),
                  permitted_repository_ids=(REPO,), transport_profile_id=ImmutableConfigId("read"))
    for name, value in fields.items():
        object.__setattr__(transport_binding, name, value)
    request = ReadRepositoryIdentity(REPO)
    descriptor = object.__new__(RegisteredStateFactDescriptor)
    object.__setattr__(descriptor, "descriptor_id", LogicalIdentifier("repository"))
    object.__setattr__(descriptor, "request", request)
    profile = object.__new__(AuthoritativeObservationProfile)
    object.__setattr__(profile, "profile_id", ImmutableConfigId(profile_name))
    object.__setattr__(profile, "registered_fact_descriptors", (descriptor,))
    transport = object.__new__(AuthenticatedGitHubReadTransport)
    object.__setattr__(transport, "_binding", transport_binding)
    object.__setattr__(transport, "_executor", lambda request, cursor: {"repository_id": REPO.value, "owner": owner, "name": "r"})
    reader = GitHubStateReader(transport_binding, transport)
    return profile, reader


def fixture_source(owner="o", profile_name="observation", transport_name="transport"):
    profile, reader = source(profile_name, transport_name, owner)
    snapshot = AuthoritativeStateSnapshot(
        REPO, profile.profile_id, reader._binding.config_id,
        (NormalizedGitHubObservation(
            "repository", (REPO.value, owner, "r"),
        ),),
    )
    return profile, reader._binding, snapshot


def install_fixture_dependencies(value, *names):
    dependencies = []
    for name in names:
        profile, transport, snapshot = fixture_source(
            owner="owner-" + name,
            profile_name="observation-" + name,
            transport_name="transport-" + name,
        )
        value.register_fixture_authoritative_source(profile, transport, snapshot)
        dependencies.append(ControlStateAuthoritativeDependency(
            REPO, profile.profile_id, transport.config_id,
            authoritative_state_binding(snapshot),
        ))
    dependencies.sort(key=lambda item: (
        item.repository_id.value, item.observation_profile_id.value,
        item.transport_config_id.value,
    ))
    return ControlStateAuthoritativeDependencySet(tuple(dependencies))


def register_zero_semantic_environment(value):
    """Root fixture assembly for G4 regression cases with no semantic evaluators."""
    working = value.backend.read_task_working_set(TASK)
    dependencies = install_fixture_dependencies(value, "semantic-base")
    base = dependencies.dependencies[0]
    contract = value.backend.read_contract(working.task.contract_id)
    resolved = value.backend.read_resolved_target_registration(TARGET)
    admission = trusted_admission_context_for_fixture(
        contract.raw_bytes, resolved.registration, EPOCH,
        base.expected_binding_id, base.expected_binding_id,
    )
    context = mint(
        TrustedIssueContractApplicabilityContext,
        policy_epoch_identity=admission.policy_epoch_identity,
        schema_binding=admission.schema_binding,
        resolved_target=admission.resolved_target,
        base_observation=admission.base_observation,
        evaluator_resolutions=admission.evaluator_resolutions,
        runtime_resolutions=admission.runtime_resolutions,
        root_context=admission.root_context,
        repair_policy_context=admission.repair_policy_context,
        operation_approval_enforcement_available=(
            admission.operation_approval_enforcement_available
        ),
    )
    value.register_semantic_consumption_context(
        TASK, context, None, None, base,
    )
    return dependencies


def marker(operation="one", result="result"):
    subject = PublishedCandidateRefEffectSubject(REPO, REF, GitRef(REF.value), SHA)
    preimage = ProtectedEffectMarkerPreimage(
        "autodev.protected-effect-marker/v1", "publication",
        OperationId(operation), OperationIdempotencyKey("key"),
        OperationActionId("action"), RawSha256("a" * 64),
        CandidateMaterializationId(RawSha256("b" * 64)),
        MutationInventoryId(RawSha256("c" * 64)),
        PreparedProtectedStartId(RawSha256("d" * 64)),
        RootContextId(RawSha256("1" * 64)), 1,
        ServicePrincipalId("publication"), subject,
        RawSha256("e" * 64), RawSha256(("f" if result == "result" else "0") * 64),
    )
    return build_protected_effect_marker(preimage)


def audit_event(outcome=GateAuditOutcome.ATTEMPTED):
    binding = GateRuntimeBinding(
        RootContextId(RawSha256("1" * 64)), FixtureRuntimeGeneration(1),
        ServicePrincipalId("control"), ServicePrincipalId("publication"),
        ServicePrincipalId("merge"),
    )
    return build_gate_audit_event(GateAuditEventPreimage(
        "autodev.gate-audit-event/v1", "gate", "op", outcome,
        RootContextId(RawSha256("1" * 64)), 1,
        binding.runtime_binding_id, ServicePrincipalId("control"), (),
        RawSha256("2" * 64), CanonicalStateOccurrenceBinding(BackendGeneration(1)),
        None, None, None, None, "", "",
    ))


def independent_lease(value):
    return value.acquire_control_lease(
        value.control_capability, ControlStateAuthoritativeDependencySet(()),
        value.attest_external_state_independence(),
    )


def completion_context(value, context_id="completion-context", *,
                       contract=ConditionStatus.UNSATISFIED,
                       additional=ConditionStatus.SATISFIED,
                       applicability=ConditionStatus.SATISFIED,
                       required=()):
    task = value.backend.read_task_working_set(TASK).task
    return mint(
        TrustedCompletionEvaluationContext,
        context_id=ImmutableConfigId(context_id), task_id=task.task_id,
        completion_rule_set_id=CompletionRuleSetId("completion"),
        contract_id=task.contract_id, contract_raw_sha256=task.contract_raw_sha256,
        authorization_id=task.authorization_id, admission_event_id=task.admission_event_id,
        target_registration_id=task.target_registration_id,
        policy_epoch_identity=task.last_evaluated_policy_epoch_identity,
        candidate_id=task.current_candidate_id,
        contract_acceptance_status=contract,
        additional_trusted_completion_conditions_status=additional,
        required_protected_operation_ids=required,
        current_applicability_and_authority_status=applicability,
    )


def initialize_task(value):
    assert value.backend.apply(CanonicalTransaction(
        value.backend.occurrence, (), (CreateContract(CONTRACT_RECORD), CreateAuthorization(authorization()))
    )).status is CanonicalWriteStatus.APPLIED
    request = value.boundary.create_task(
        task_id=TASK, contract_id=CONTRACT, contract_raw_sha256=RAW,
        authorization_id=AUTH, admission_event_id=ADMISSION,
        target_registration_id=TARGET, policy_epoch_identity=EPOCH,
        repair_budget=RepairBudget(2),
    )
    result = ControlStateGate(value.control_state_client).commit(request, independent_lease(value))
    assert result.code is GateResultCode.COMMITTED


def candidate_truth_store():
    candidate = GitSha("b" * 40)
    base_tree_entries = ()
    candidate_tree_entries = (GitTreeEntry(
        CanonicalGitPath("src/new.py"), GitObjectKind.BLOB, "100644",
        GitSha("c" * 40),
    ),)
    base_tree = FixtureGitPlatform.tree_identity(base_tree_entries)
    candidate_tree = FixtureGitPlatform.tree_identity(candidate_tree_entries)
    source_tree = GitSha("f" * 40)
    return FixtureGitObjectStore(
        REPO,
        (FixtureGitCommit(SHA, (), base_tree), FixtureGitCommit(candidate, (SHA,), candidate_tree)),
        (
            FixtureGitTree(base_tree, ()),
            FixtureGitTree(candidate_tree, (FixtureGitTreeEntry(
                "src", GitObjectKind.TREE, "040000", source_tree,
            ),)),
            FixtureGitTree(source_tree, (FixtureGitTreeEntry(
                "new.py", GitObjectKind.BLOB, "100644", GitSha("c" * 40),
            ),)),
        ),
    )


def test_issue30_recording_is_nonprogressing_and_adoption_resolves_canonical_pair():
    value = runtime(object_store=candidate_truth_store())
    initialize_task(value)
    before = value.backend.read_task_working_set(TASK).task
    record = value.boundary.record_candidate_truth(
        task_id=TASK, candidate_id=CandidateId("candidate"), candidate_commit_id=GitSha("b" * 40),
    )
    assert record.command_kind is TrustedControlCommandKind.RECORD_CANDIDATE_TRUTH
    assert ControlStateGate(value.control_state_client).commit(record, independent_lease(value)).code is GateResultCode.COMMITTED
    after_record = value.backend.read_task_working_set(TASK).task
    assert after_record == before
    candidate = value.backend.read_candidate(CandidateId("candidate"))
    assert candidate is not None
    assert value.backend.read_candidate_materialization(candidate.materialization_id) is not None
    adopt = value.boundary.adopt_recorded_candidate(
        task_id=TASK, candidate_id=candidate.candidate_id,
        decision_event_id=DecisionEventId("candidate-applicability"),
    )
    assert ControlStateGate(value.control_state_client).commit(adopt, independent_lease(value)).code is GateResultCode.COMMITTED
    assert value.backend.read_task_working_set(TASK).task.current_candidate_id == candidate.candidate_id


def test_issue30_recording_derives_security_bindings_from_canonical_trusted_state():
    value = runtime()
    initialize_task(value)
    task = value.backend.read_task_working_set(TASK).task
    contract = value.backend.read_contract(task.contract_id)
    resolved_target = value.backend.read_resolved_target_registration(task.target_registration_id)
    assert contract is not None and resolved_target is not None
    request = value.boundary.record_candidate_truth(
        task_id=TASK, candidate_id=CandidateId("derived-bindings"), candidate_commit_id=GitSha("b" * 40),
    )
    assert ControlStateGate(value.control_state_client).commit(request, independent_lease(value)).code is GateResultCode.COMMITTED
    candidate = value.backend.read_candidate(CandidateId("derived-bindings"))
    assert candidate is not None
    materialization = value.backend.read_candidate_materialization(candidate.materialization_id)
    assert materialization is not None
    assert (
        candidate.task_id, candidate.contract_id, candidate.contract_raw_sha256,
        candidate.authorization_id, candidate.admission_event_id, candidate.target_registration_id,
        candidate.policy_epoch_identity, candidate.base,
    ) == (
        task.task_id, task.contract_id, task.contract_raw_sha256,
        task.authorization_id, task.admission_event_id, task.target_registration_id,
        task.last_evaluated_policy_epoch_identity, contract.base_sha,
    )
    assert (
        materialization.repository_id, materialization.task_id, materialization.contract_id,
        materialization.contract_raw_sha256, materialization.authorization_id,
        materialization.target_registration_id, materialization.policy_epoch_identity,
        materialization.base_commit,
    ) == (
        resolved_target.registration.repository_id, task.task_id, task.contract_id,
        task.contract_raw_sha256, task.authorization_id, task.target_registration_id,
        task.last_evaluated_policy_epoch_identity, contract.base_sha,
    )


def test_issue30_recording_rejects_caller_security_binding_overrides():
    value = runtime()
    initialize_task(value)
    before_task = value.backend.read_task_working_set(TASK).task
    before_occurrence = value.backend.occurrence
    with pytest.raises(TypeError):
        value.boundary.record_candidate_truth(
            task_id=TASK, candidate_id=CandidateId("no-overrides"),
            candidate_commit_id=GitSha("b" * 40), contract_id=ContractId("conflict"),
        )
    with pytest.raises(TypeError):
        value.boundary.record_candidate_truth(
            task_id=TASK, candidate_id=CandidateId("no-overrides"),
            candidate_commit_id=GitSha("b" * 40), repository_id=GitHubRepositoryId("2"),
        )
    assert value.backend.occurrence == before_occurrence
    assert value.backend.read_task_working_set(TASK).task == before_task
    assert value.backend.read_candidate(CandidateId("no-overrides")) is None


def test_issue30_materialization_admission_does_not_grant_publication_authority():
    value = runtime()
    initialize_task(value)
    admitted = record_materialization_truth(value, materialize(value))
    before = value.platform.snapshot()
    # The only public publication entry point accepts a gate-private live continuation,
    # never an admitted materialization as bearer authority.
    result = TargetPublicationGate(value.publication_gate_client).perform(admitted)
    assert result.code is GateResultCode.LEASE_CONSUMED
    assert value.platform.snapshot() == before
    assert value.backend.read_task_working_set(TASK).task.current_candidate_id is None
    assert value.platform.marker(
        OperationId("publication-from-materialization"),
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION.value,
    ) is None


def test_issue30_combined_candidate_creation_and_adoption_path_is_unavailable():
    value = runtime()
    initialize_task(value)
    candidate_id = CandidateId("combined-path")
    before_task = value.backend.read_task_working_set(TASK).task
    before_occurrence = value.backend.occurrence
    before_candidates = dict(value.backend._state.candidates)
    before_materializations = dict(value.backend._state.candidate_materializations)
    with pytest.raises(TypeError, match="combined candidate creation/adoption is unavailable"):
        value.boundary.create_candidate_and_adopt(
            task_id=TASK, candidate_id=candidate_id, candidate_commit_id=GitSha("b" * 40),
        )
    assert value.backend.occurrence == before_occurrence
    assert value.backend.read_task_working_set(TASK).task == before_task
    assert value.backend.read_candidate(candidate_id) is None
    assert value.backend._state.candidates == before_candidates
    assert value.backend._state.candidate_materializations == before_materializations


def test_issue30_recording_binds_repository_to_resolved_target_not_issue_anchor():
    issue_repository = GitHubRepositoryId("2")
    _, issue_raw, issue_contract = canonical_contract_fixture(
        contract_id=CONTRACT, task_id=TASK, target_registration_id=TARGET,
        repository_id=issue_repository, policy_epoch_identity=EPOCH, base_sha=SHA,
        allowed_repository_scope=True,
    )
    value = runtime(object_store=candidate_truth_store())
    admitted = authorization()
    issue_authorization = mint(
        AdmittedAuthorization,
        **{
            name: issue_raw if name == "contract_raw_sha256" else getattr(admitted, name)
            for name in admitted.__dataclass_fields__
        },
    )
    assert value.backend.apply(CanonicalTransaction(
        value.backend.occurrence, (), (
            CreateContract(issue_contract),
            CreateAuthorization(issue_authorization),
        ),
    )).status is CanonicalWriteStatus.APPLIED
    create = value.boundary.create_task(
        task_id=TASK, contract_id=CONTRACT, contract_raw_sha256=issue_raw,
        authorization_id=AUTH, admission_event_id=ADMISSION,
        target_registration_id=TARGET, policy_epoch_identity=EPOCH,
        repair_budget=RepairBudget(2),
    )
    assert ControlStateGate(value.control_state_client).commit(
        create, independent_lease(value)
    ).code is GateResultCode.COMMITTED
    recorded = value.boundary.record_candidate_truth(
        task_id=TASK, candidate_id=CandidateId("target-repository"),
        candidate_commit_id=GitSha("b" * 40),
    )
    assert ControlStateGate(value.control_state_client).commit(
        recorded, independent_lease(value)
    ).code is GateResultCode.COMMITTED
    candidate = value.backend.read_candidate(CandidateId("target-repository"))
    assert candidate is not None
    materialization = value.backend.read_candidate_materialization(candidate.materialization_id)
    assert materialization is not None
    assert materialization.repository_id == REPO

    target_store = candidate_truth_store()
    issue_store = FixtureGitObjectStore(
        issue_repository, target_store.commits, target_store.trees,
    )
    value._object_store = issue_store
    value.controller._object_store = issue_store
    with pytest.raises(ValueError, match="REPOSITORY_MISMATCH"):
        value.boundary.record_candidate_truth(
            task_id=TASK, candidate_id=CandidateId("issue-repository"),
            candidate_commit_id=GitSha("b" * 40),
        )


def test_issue30_adoption_is_candidate_id_only_and_missing_candidate_fails_closed():
    value = runtime()
    initialize_task(value)
    before = value.backend.read_task_working_set(TASK).task
    occurrence = value.backend.occurrence
    with pytest.raises(TypeError):
        value.boundary.adopt_recorded_candidate(
            task_id=TASK, candidate_id=CandidateId("missing"),
            decision_event_id=DecisionEventId("missing"), candidate=object(),
        )
    with pytest.raises(ValueError, match="candidate is unavailable"):
        value.boundary.adopt_recorded_candidate(
            task_id=TASK, candidate_id=CandidateId("missing"),
            decision_event_id=DecisionEventId("missing"),
        )
    assert value.backend.read_task_working_set(TASK).task == before
    assert value.backend.occurrence == occurrence


def test_issue30_adoption_rejects_unavailable_or_mismatched_materialization_before_g4():
    value = runtime()
    initialize_task(value)
    proposed = materialize(value)
    admitted = record_materialization_truth(value, proposed)
    other_request = value.boundary.record_candidate_truth(
        task_id=TASK, candidate_id=CandidateId("other"), candidate_commit_id=proposed.commit,
    )
    assert ControlStateGate(value.control_state_client).commit(other_request, independent_lease(value)).code is GateResultCode.COMMITTED
    other_candidate = value.backend.read_candidate(CandidateId("other"))
    assert other_candidate is not None
    other = value.backend.read_candidate_materialization(other_candidate.materialization_id)
    assert other is not None
    candidate = value.backend.read_candidate(admitted.candidate_id)
    assert candidate is not None
    before_task, before_occurrence = value.backend.read_task_working_set(TASK).task, value.backend.occurrence

    class ReadFacade:
        def __init__(self, materialization):
            self.materialization = materialization

        def read_task_working_set(self, task_id):
            return value.backend.read_task_working_set(task_id)

        def read_candidate(self, candidate_id):
            return value.backend.read_candidate(candidate_id)

        def read_candidate_materialization(self, _):
            return self.materialization

    controller_backend = value.controller._backend
    try:
        value.controller._backend = ReadFacade(None)
        with pytest.raises(ValueError, match="continuity is unavailable"):
            value.boundary.adopt_recorded_candidate(
                task_id=TASK, candidate_id=candidate.candidate_id,
                decision_event_id=DecisionEventId("missing-materialization"),
            )
        assert other.candidate_id != candidate.candidate_id
        value.controller._backend = ReadFacade(other)
        with pytest.raises(ValueError, match="continuity is unavailable"):
            value.boundary.adopt_recorded_candidate(
                task_id=TASK, candidate_id=candidate.candidate_id,
                decision_event_id=DecisionEventId("mismatched-materialization"),
            )
    finally:
        value.controller._backend = controller_backend
    assert value.backend.read_task_working_set(TASK).task == before_task
    assert value.backend.occurrence == before_occurrence


def test_issue30_recorded_truth_survives_authoritative_cancellation_g4_denial():
    value = runtime()
    initialize_task(value)
    admitted = record_materialization_truth(value, materialize(value))
    candidate = value.backend.read_candidate(admitted.candidate_id)
    assert candidate is not None
    cancel = value.boundary.set_cancellation(
        TASK, CancellationStatus.AUTHORITATIVE, CancellationRequestId("deny-adoption"),
    )
    assert ControlStateGate(value.control_state_client).commit(cancel, independent_lease(value)).code is GateResultCode.COMMITTED
    before_task, before_occurrence = value.backend.read_task_working_set(TASK).task, value.backend.occurrence
    with pytest.raises(ValueError, match="TERMINAL_TASK"):
        value.boundary.adopt_recorded_candidate(
            task_id=TASK, candidate_id=candidate.candidate_id,
            decision_event_id=DecisionEventId("cancelled-adoption"),
        )
    assert value.backend.read_task_working_set(TASK).task == before_task
    assert value.backend.occurrence == before_occurrence
    assert value.backend.read_candidate(candidate.candidate_id) == candidate
    assert value.backend.read_candidate_materialization(admitted.materialization_id) == admitted


def test_issue30_stale_adoption_request_cannot_overwrite_newer_task_state():
    value = runtime()
    initialize_task(value)
    admitted = record_materialization_truth(value, materialize(value))
    stale = value.boundary.adopt_recorded_candidate(
        task_id=TASK, candidate_id=admitted.candidate_id,
        decision_event_id=DecisionEventId("stale-adoption"),
    )
    stale_occurrence = stale.transaction.expected_state_occurrence
    cancel = value.boundary.set_cancellation(
        TASK, CancellationStatus.REQUESTED, CancellationRequestId("competing-write"),
    )
    assert ControlStateGate(value.control_state_client).commit(cancel, independent_lease(value)).code is GateResultCode.COMMITTED
    after_competing_task, after_competing_occurrence = value.backend.read_task_working_set(TASK).task, value.backend.occurrence
    assert stale_occurrence != after_competing_occurrence
    result = ControlStateGate(value.control_state_client).commit(stale, independent_lease(value))
    assert result.code is GateResultCode.REJECTED
    assert result.canonical_result.status is CanonicalWriteStatus.CAS_CONFLICT
    assert value.backend.read_task_working_set(TASK).task == after_competing_task
    assert value.backend.occurrence == after_competing_occurrence
    assert value.backend.read_candidate(admitted.candidate_id) is not None
    assert value.backend.read_candidate_materialization(admitted.materialization_id) == admitted


def test_issue30_candidate_replacement_preserves_historical_pairs_without_retirement_authority():
    value = runtime()
    initialize_task(value)
    first = record_materialization_truth(value, materialize(value))
    first_candidate = value.backend.read_candidate(first.candidate_id)
    assert first_candidate is not None
    first_adopt = value.boundary.adopt_recorded_candidate(
        task_id=TASK, candidate_id=first.candidate_id, decision_event_id=DecisionEventId("adopt-first"),
    )
    assert ControlStateGate(value.control_state_client).commit(first_adopt, independent_lease(value)).code is GateResultCode.COMMITTED
    second_request = value.boundary.record_candidate_truth(
        task_id=TASK, candidate_id=CandidateId("second"), candidate_commit_id=GitSha("b" * 40),
    )
    assert ControlStateGate(value.control_state_client).commit(second_request, independent_lease(value)).code is GateResultCode.COMMITTED
    second_candidate = value.backend.read_candidate(CandidateId("second"))
    assert second_candidate is not None
    second = value.backend.read_candidate_materialization(second_candidate.materialization_id)
    assert second is not None
    second_adopt = value.boundary.adopt_recorded_candidate(
        task_id=TASK, candidate_id=second.candidate_id, decision_event_id=DecisionEventId("adopt-second"),
    )
    assert ControlStateGate(value.control_state_client).commit(second_adopt, independent_lease(value)).code is GateResultCode.COMMITTED
    assert value.backend.read_task_working_set(TASK).task.current_candidate_id == second.candidate_id
    assert value.backend.read_candidate(first.candidate_id) == first_candidate
    assert value.backend.read_candidate_materialization(first.materialization_id) == first
    assert value.backend.read_candidate(second.candidate_id) == second_candidate
    assert value.backend.read_candidate_materialization(second.materialization_id) == second
    assert not any("retire" in name.lower() or "delete" in name.lower() or "gc" in name.lower()
                   for name in TrustedControlCommandKind.__members__)


def test_admit_contract_uses_controller_gate_cas_and_exact_authoritative_dependencies():
    value = runtime()
    dependencies = install_fixture_dependencies(value, "contract-base", "contract-issue")
    context = trusted_admission_context_for_fixture(
        CONTRACT_RECORD.raw_bytes, registration(), EPOCH,
        dependencies.dependencies[0].expected_binding_id,
        dependencies.dependencies[1].expected_binding_id,
    )
    value.register_contract_context(CONTRACT_RECORD.raw_bytes, context)
    request = value.boundary.admit_contract(CONTRACT_RECORD.raw_bytes)
    assert request.command_kind is TrustedControlCommandKind.ADMIT_CONTRACT
    alternate = install_fixture_dependencies(value, "contract-alternate")
    wrong_lease = value.acquire_control_lease(value.control_capability, alternate)
    assert ControlStateGate(value.control_state_client).commit(request, wrong_lease).code is GateResultCode.LEASE_INVALID
    lease = value.acquire_control_lease(value.control_capability, dependencies)
    result = ControlStateGate(value.control_state_client).commit(request, lease)
    assert result.code is GateResultCode.COMMITTED
    assert value.backend.read_contract(CONTRACT) == CONTRACT_RECORD
    replay = value.boundary.admit_contract(CONTRACT_RECORD.raw_bytes)
    replay_lease = value.acquire_control_lease(value.control_capability, dependencies)
    assert ControlStateGate(value.control_state_client).commit(replay, replay_lease).code is GateResultCode.COMMITTED


def materialize(value):
    base, commit = GitSha("a" * 40), GitSha("b" * 40)
    base_tree = ()
    candidate_tree = (GitTreeEntry(
        CanonicalGitPath("src/new.py"), GitObjectKind.BLOB, "100644",
        GitSha("c" * 40),
    ),)
    base_tree_id = value.platform.tree_identity(base_tree)
    result_tree_id = value.platform.tree_identity(candidate_tree)
    value.platform.seed_commit(base, (), base_tree, base_tree_id)
    value.platform.seed_commit(commit, (base,), candidate_tree, result_tree_id)
    value.platform.seed_ref(REPO, REF, base)
    return build_candidate_materialization(
        repository_id=REPO, task_id=TASK, candidate_id=CandidateId("candidate"),
        contract_id=CONTRACT, contract_raw_sha256=RAW,
        authorization_id=AUTH, target_registration_id=TARGET,
        policy_epoch_identity=EPOCH, base=base, base_tree_id=base_tree_id,
        commit=commit, result_tree_id=result_tree_id, parent_commits=(base,),
        base_tree=base_tree, candidate_tree=candidate_tree,
        materialization_profile_id=ImmutableConfigId("materialization"),
    )


def record_materialization_truth(value, materialization):
    """Record the pair through the public non-progressing truth boundary."""
    before = value.backend.read_task_working_set(TASK).task
    request = value.boundary.record_candidate_truth(
        task_id=TASK, candidate_id=materialization.candidate_id,
        candidate_commit_id=materialization.commit,
    )
    assert ControlStateGate(value.control_state_client).commit(
        request, independent_lease(value)
    ).code is GateResultCode.COMMITTED
    after = value.backend.read_task_working_set(TASK).task
    assert after == before
    assert after.revision == before.revision
    assert after.current_candidate_id is None
    assert after.state is not TaskState.EVALUATING
    candidate = value.backend.read_candidate(materialization.candidate_id)
    assert candidate is not None
    admitted = value.backend.read_candidate_materialization(candidate.materialization_id)
    assert admitted is not None
    return admitted


def adopt_recorded_candidate(value, materialization):
    """Adopt a previously recorded candidate only by its canonical identity."""
    admitted = record_materialization_truth(value, materialization)
    request = value.boundary.adopt_recorded_candidate(
        task_id=TASK, candidate_id=admitted.candidate_id,
        decision_event_id=DecisionEventId("candidate-applicability"),
    )
    assert ControlStateGate(value.control_state_client).commit(
        request, independent_lease(value)
    ).code is GateResultCode.COMMITTED
    return admitted


def reserve_protected(value, name, candidate_id, *, integration_binding=None,
                      required_evidence_ids=()):
    command = OperationReservationCommand(
        operation_id=OperationId(name),
        idempotency_key=OperationIdempotencyKey("key-" + name),
        action_id=OperationActionId(name), subject_id=OperationSubjectId(name),
        required_evidence_ids=required_evidence_ids,
        integration_binding=(
            NotIntegrationBound() if integration_binding is None else integration_binding
        ),
        is_repair_attempt=False,
    )
    request = value.boundary.reserve_operation(TASK, command)
    assert ControlStateGate(value.control_state_client).commit(
        request, independent_lease(value)
    ).code is GateResultCode.COMMITTED
    return next(
        item for item in value.backend.read_task_working_set(TASK).operations
        if item.intent.operation_id == command.operation_id
    )


def start_protected(value, operation, subject, fence, materialization, *,
                    target=None, base_ref=None, provenance_operation_id=None,
                    dependencies=None):
    if dependencies is None:
        control = independent_lease(value)
    else:
        control = value.acquire_control_lease(
            value.control_capability, dependencies,
            value.attest_external_state_independence()
            if not dependencies.dependencies else None,
        )
        assert type(control) is ControlStateCommitLease
    capability = (
        value.merge_capability
        if subject is ProtectedEffectSubject.FAST_FORWARD_MERGE
        else value.publication_capability
    )
    prepared = value.prepare_protected_start(
        operation, subject, fence, control, capability,
        all_scope(), MutationScope(()),
        materialization=materialization,
        target_registration=target or registration(), base_ref=base_ref,
        provenance_operation_id=provenance_operation_id,
    )
    return value.commit_protected_start(prepared, operation, subject)


def test_gate_principals_must_be_pairwise_distinct():
    with pytest.raises(ValueError):
        GateRuntimeBinding(RootContextId(RawSha256("1" * 64)), FixtureRuntimeGeneration(1),
                           ServicePrincipalId("same"), ServicePrincipalId("same"), ServicePrincipalId("merge"))


def test_three_capabilities_are_distinct_and_principal_bound():
    value = runtime()
    assert value.control_capability is not value.publication_capability
    assert value.publication_capability.service_identity == ServicePrincipalId("publication")
    assert value.merge_capability.service_identity == ServicePrincipalId("merge")


def test_issue29_semantic_denial_domains_are_exact_and_separate_from_g4():
    assert {item.value for item in TaskSemanticDenialCode} == {
        "NEXT_INTEGRATION_OPERATION_INVALID",
        "SEMANTIC_CONTRACT_UNSATISFIED",
        "SEMANTIC_CONTEXT_INDETERMINATE",
        "REQUIRED_SEMANTIC_EVIDENCE_NOT_CURRENT",
        "REQUIRED_SEMANTIC_EVIDENCE_NOT_PROGRESSION_SUPPORT",
    }
    assert {item.value for item in ProtectedStartSemanticDenialCode} == {
        "REQUIRED_EVIDENCE_NOT_CURRENT",
        "REQUIRED_EVIDENCE_NOT_VALID_FOR_OPERATION",
        "REQUIRED_EVIDENCE_CONTEXT_INDETERMINATE",
    }
    with pytest.raises(ValueError, match="mutually exclusive"):
        GateResult(
            GateResultCode.REJECTED,
            failure_code=G4FailureCode.ACTION_PRECONDITION_CONFLICT,
            semantic_denial_code=(
                ProtectedStartSemanticDenialCode.REQUIRED_EVIDENCE_CONTEXT_INDETERMINATE
            ),
        )


def _issue29_semantic_publication_runtime(
    *, stale_schema=True, verdict_name="approved", config_available=True,
    extra_evaluation_ids=(),
):
    from tests.trusted.test_current_semantic_review import (
        _canonical_inputs, _current_applicability_context,
        _semantic_config_bytes, _semantic_contract,
        _trusted_reader, REPOSITORY,
    )
    from tests.trusted.test_semantic_consumption import _resolved_backend_with_current_evidence

    config_bytes = _semantic_config_bytes()
    contract, _, _ = _semantic_contract(
        config_bytes=config_bytes, extra_evaluation_ids=extra_evaluation_ids,
    )
    target_template = registration()
    target = mint(
        AdmittedTargetRegistration,
        **{
            **{name: getattr(target_template, name)
               for name in target_template.__dataclass_fields__},
            "target_registration_id": contract.target_registration_id,
            "repository_id": REPOSITORY,
            "policy_epoch_identity": contract.admission_policy_epoch_identity,
        },
    )
    resolved_template = _canonical_inputs(contract).resolved_target
    resolved_target = mint(
        type(resolved_template),
        **{
            **{name: getattr(resolved_template, name)
               for name in resolved_template.__dataclass_fields__},
            "registration": target,
            "target_registration_id": contract.target_registration_id,
            "policy_epoch_identity": contract.admission_policy_epoch_identity,
        },
    )
    store, _, record, _ = _resolved_backend_with_current_evidence(
        contract=contract, config_bytes=config_bytes, resolved_target=resolved_target,
        verdict_name=verdict_name,
    )
    platform = FixtureGitPlatform()
    materialization = store.read_candidate_materialization(
        store.read_candidate(record.subject.candidate_id).materialization_id
    )
    candidate_tree = (GitTreeEntry(
        CanonicalGitPath("candidate-.txt"), GitObjectKind.BLOB,
        "100644", GitSha("1" * 40),
    ),)
    platform.seed_commit(materialization.base, (), (), materialization.base_tree)
    platform.seed_commit(
        materialization.commit, (materialization.base,), candidate_tree,
        materialization.result_tree,
    )
    binding = GateRuntimeBinding(
        RootContextId(RawSha256("2" * 64)), FixtureRuntimeGeneration(10),
        ServicePrincipalId("control-semantic-start"),
        target.target_publication.service_identity,
        target.merge.service_identity,
    )
    value = FixtureProtectedGateRuntime(
        binding, store, platform, FixtureGateAudit(),
    )
    profile_id, transport_id = (
        ImmutableConfigId("semantic-base-observation"),
        ImmutableConfigId("semantic-base-transport"),
    )
    transport_binding = object.__new__(TrustedGitHubReadTransportBinding)
    for name, item in {
        "config_id": transport_id,
        "expected_api_host_identity": ImmutableConfigId("semantic-host"),
        "authentication_mode_identity": ImmutableConfigId("semantic-auth"),
        "service_identity": ServicePrincipalId("semantic-reader"),
        "permitted_repository_ids": (REPOSITORY,),
        "transport_profile_id": ImmutableConfigId("semantic-read-profile"),
    }.items():
        object.__setattr__(transport_binding, name, item)
    descriptor = object.__new__(RegisteredStateFactDescriptor)
    object.__setattr__(descriptor, "descriptor_id", LogicalIdentifier("repository"))
    object.__setattr__(descriptor, "request", ReadRepositoryIdentity(REPOSITORY))
    profile = object.__new__(AuthoritativeObservationProfile)
    object.__setattr__(profile, "profile_id", profile_id)
    object.__setattr__(profile, "registered_fact_descriptors", (descriptor,))
    transport = object.__new__(AuthenticatedGitHubReadTransport)
    object.__setattr__(transport, "_binding", transport_binding)
    object.__setattr__(transport, "_executor", lambda request, cursor: {
        "repository_id": REPOSITORY.value, "owner": "semantic-owner", "name": "repo",
    })
    value.register_fixture_authoritative_source(profile, transport_binding, AuthoritativeStateSnapshot(
        REPOSITORY, profile_id, transport_id,
        (NormalizedGitHubObservation(
            "repository", (REPOSITORY.value, "semantic-owner", "repo"),
        ),),
    ))
    base_binding = authoritative_state_binding(
        value.platform.authoritative_snapshot(REPOSITORY, profile_id, transport_id)
    )
    base_dependency = AuthoritativeStateDependency(
        REPOSITORY, profile_id, transport_id, base_binding,
    )
    context = _current_applicability_context(contract)
    base_observation = mint(
        type(context.base_observation),
        **{
            **{name: getattr(context.base_observation, name)
               for name in context.base_observation.__dataclass_fields__},
            "authoritative_state_binding_id": base_binding,
        },
    )
    if stale_schema:
        stale_epoch = PolicyEpochIdentity(TrustedManifestId(RawSha256("d" * 64)))
        context_schema_binding = mint(
            type(context.schema_binding),
            **{
                **{name: getattr(context.schema_binding, name)
                   for name in context.schema_binding.__dataclass_fields__},
                "policy_epoch_identity": stale_epoch,
            },
        )
    else:
        context_schema_binding = context.schema_binding
    context = mint(
        type(context),
        **{
            **{name: getattr(context, name) for name in context.__dataclass_fields__},
            "base_observation": base_observation,
            "schema_binding": context_schema_binding,
        },
    )
    value.register_semantic_consumption_context(
        record.subject.task_id,
        context, _trusted_reader(contract, config_bytes) if config_available else None,
        None, base_dependency,
    )
    return value, materialization, target, base_dependency, record


@pytest.mark.parametrize(("stale_schema", "config_available", "authoritative_cancellation", "semantic_code"), [
    (True, True, False, ProtectedStartSemanticDenialCode.REQUIRED_EVIDENCE_NOT_CURRENT),
    (False, False, False, ProtectedStartSemanticDenialCode.REQUIRED_EVIDENCE_CONTEXT_INDETERMINATE),
    (True, True, True, None),
])
def test_issue29_g4_first_start_precedence_for_semantic_evidence(
    stale_schema, config_available, authoritative_cancellation, semantic_code,
):
    value, materialization, target, dependencies, record = (
        _issue29_semantic_publication_runtime(
            stale_schema=stale_schema, config_available=config_available,
        )
    )
    command = OperationReservationCommand(
        operation_id=OperationId("stale-semantic-publication"),
        idempotency_key=OperationIdempotencyKey("stale-semantic-publication-key"),
        action_id=OperationActionId("stale-semantic-publication-action"),
        subject_id=OperationSubjectId("stale-semantic-publication-subject"),
        required_evidence_ids=(record.evidence_id,),
        integration_binding=NotIntegrationBound(),
        is_repair_attempt=False,
    )
    request = value.boundary.reserve_operation(record.subject.task_id, command)
    assert ControlStateGate(value.control_state_client).commit(
        request, independent_lease(value),
    ).code is GateResultCode.COMMITTED
    if authoritative_cancellation:
        cancellation = value.boundary.set_cancellation(
            record.subject.task_id, CancellationStatus.AUTHORITATIVE,
            CancellationRequestId("semantic-start-cancellation"),
        )
        assert ControlStateGate(value.control_state_client).commit(
            cancellation, independent_lease(value),
        ).code is GateResultCode.COMMITTED
    working = value.backend.read_task_working_set(record.subject.task_id)
    operation = next(item for item in working.operations
                     if item.intent.operation_id == command.operation_id)
    fence = ActionTargetFence(
        record.subject.repository_id, materialization.candidate_branch, None,
        value.platform.snapshot().generation,
    )
    dependency_set = ControlStateAuthoritativeDependencySet((dependencies,))
    lease = value.acquire_control_lease(value.control_capability, dependency_set)
    prepared = value.prepare_protected_start(
        operation, ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
        fence, lease, value.publication_capability, all_scope(), MutationScope(()),
        materialization=materialization, target_registration=target,
    )
    result = value.commit_protected_start(
        prepared, operation, ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
    )
    assert result.code is GateResultCode.REJECTED
    if authoritative_cancellation:
        assert result.failure_code is G4FailureCode.CANCELLATION_BLOCKS_OPERATION_START
        assert result.semantic_denial_code is None
    else:
        assert result.failure_code is None
        assert result.semantic_denial_code is semantic_code
    after = value.backend.read_task_working_set(record.subject.task_id)
    stored = next(item for item in after.operations
                  if item.intent.operation_id == command.operation_id)
    assert stored.state is OperationState.RESERVED
    assert stored.start_binding_id is None
    assert value.backend.occurrence == working.canonical_state_occurrence_binding
    assert value.platform.marker(
        command.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION.value,
    ) is None
    assert value.platform.read_ref(
        record.subject.repository_id, materialization.candidate_branch,
    ) is None


def test_issue29_stale_semantic_evidence_blocks_public_pr_creation_start():
    value, materialization, target, dependency, record = (
        _issue29_semantic_publication_runtime(stale_schema=False)
    )
    backend = value.backend
    task_id = record.subject.task_id
    dependencies = ControlStateAuthoritativeDependencySet((dependency,))

    def reserve_and_commit(name, evidence_id):
        command = OperationReservationCommand(
            operation_id=OperationId(name),
            idempotency_key=OperationIdempotencyKey(name + "-key"),
            action_id=OperationActionId(name), subject_id=OperationSubjectId(name),
            required_evidence_ids=(evidence_id,),
            integration_binding=NotIntegrationBound(), is_repair_attempt=False,
        )
        request = value.boundary.reserve_operation(task_id, command)
        assert ControlStateGate(value.control_state_client).commit(
            request, independent_lease(value),
        ).code is GateResultCode.COMMITTED
        return next(item for item in backend.read_task_working_set(task_id).operations
                    if item.intent.operation_id == command.operation_id)

    publish = reserve_and_commit("issue29-pr-prepublish", record.evidence_id)
    publish_control = value.acquire_control_lease(value.control_capability, dependencies)
    publish_prepared = value.prepare_protected_start(
        publish, ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
        ActionTargetFence(
            record.subject.repository_id, materialization.candidate_branch, None,
            value.platform.snapshot().generation,
        ), publish_control, value.publication_capability, all_scope(), MutationScope(()),
        materialization=materialization, target_registration=target,
    )
    publish_start = value.commit_protected_start(
        publish_prepared, publish, ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
    )
    assert publish_start.code is GateResultCode.START_COMMITTED
    assert TargetPublicationGate(value.publication_gate_client).perform(
        publish_start.continuation,
    ).code is GateResultCode.EFFECT_SUCCEEDED

    create_pr = reserve_and_commit("issue29-stale-pr", record.evidence_id)
    pr_prepared = value.prepare_protected_start(
        create_pr, ProtectedEffectSubject.PULL_REQUEST_CREATION,
        ActionTargetFence(
            record.subject.repository_id, materialization.candidate_branch,
            materialization.commit, value.platform.snapshot().generation,
            REF, materialization.base,
        ), value.acquire_control_lease(value.control_capability, dependencies),
        value.publication_capability, all_scope(), MutationScope(()),
        materialization=materialization, target_registration=target,
        base_ref=REF, provenance_operation_id=publish.intent.operation_id,
    )

    applicability, reader, context_source, base_dependency = value._semantic_contexts[task_id]
    old_epoch = PolicyEpochIdentity(TrustedManifestId(RawSha256("d" * 64)))
    stale_binding = mint(
        type(applicability.schema_binding),
        **{
            **{name: getattr(applicability.schema_binding, name)
               for name in applicability.schema_binding.__dataclass_fields__},
            "policy_epoch_identity": old_epoch,
        },
    )
    stale_context = mint(
        type(applicability),
        **{
            **{name: getattr(applicability, name)
               for name in applicability.__dataclass_fields__},
            "schema_binding": stale_binding,
        },
    )
    value._semantic_contexts[task_id] = (
        stale_context, reader, context_source, base_dependency,
    )
    before = backend.read_task_working_set(task_id)
    start = value.commit_protected_start(
        pr_prepared, create_pr, ProtectedEffectSubject.PULL_REQUEST_CREATION,
    )
    assert start.code is GateResultCode.REJECTED
    assert start.failure_code is None
    assert start.semantic_denial_code is ProtectedStartSemanticDenialCode.REQUIRED_EVIDENCE_NOT_CURRENT
    assert start.continuation is None
    after = backend.read_task_working_set(task_id)
    stored = next(item for item in after.operations
                  if item.intent.operation_id == create_pr.intent.operation_id)
    assert stored.state is OperationState.RESERVED
    assert stored.start_binding_id is None
    assert backend.occurrence == before.canonical_state_occurrence_binding
    assert value.platform.marker(
        create_pr.intent.operation_id,
        ProtectedEffectSubject.PULL_REQUEST_CREATION.value,
    ) is None
    assert value.platform.snapshot().pull_requests == ()


def test_issue29_base_movement_blocks_publication_requiring_exact_semantic_evidence():
    value, materialization, target, dependency, record = (
        _issue29_semantic_publication_runtime(stale_schema=False)
    )
    task_id = record.subject.task_id
    command = OperationReservationCommand(
        operation_id=OperationId("issue29-base-movement-publication"),
        idempotency_key=OperationIdempotencyKey("issue29-base-movement-publication-key"),
        action_id=OperationActionId("issue29-base-movement-publication-action"),
        subject_id=OperationSubjectId("issue29-base-movement-publication-subject"),
        required_evidence_ids=(record.evidence_id,),
        integration_binding=NotIntegrationBound(), is_repair_attempt=False,
    )
    reserve = value.boundary.reserve_operation(task_id, command)
    assert ControlStateGate(value.control_state_client).commit(
        reserve, independent_lease(value),
    ).code is GateResultCode.COMMITTED
    operation = next(item for item in value.backend.read_task_working_set(task_id).operations
                     if item.intent.operation_id == command.operation_id)
    dependencies = ControlStateAuthoritativeDependencySet((dependency,))
    prepared = value.prepare_protected_start(
        operation, ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
        ActionTargetFence(
            record.subject.repository_id, materialization.candidate_branch, None,
            value.platform.snapshot().generation,
        ), value.acquire_control_lease(value.control_capability, dependencies),
        value.publication_capability, all_scope(), MutationScope(()),
        materialization=materialization, target_registration=target,
    )
    applicability, reader, context_source, base_dependency = value._semantic_contexts[task_id]
    moved_base = mint(
        type(applicability.base_observation),
        **{
            **{name: getattr(applicability.base_observation, name)
               for name in applicability.base_observation.__dataclass_fields__},
            "sha": type(applicability.base_observation.sha)("d" * 40),
        },
    )
    moved_context = mint(
        type(applicability),
        **{
            **{name: getattr(applicability, name)
               for name in applicability.__dataclass_fields__},
            "base_observation": moved_base,
        },
    )
    value._semantic_contexts[task_id] = (
        moved_context, reader, context_source, base_dependency,
    )
    before = value.backend.read_task_working_set(task_id)
    result = value.commit_protected_start(
        prepared, operation, ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
    )
    assert result.code is GateResultCode.REJECTED
    assert result.failure_code is None
    assert result.semantic_denial_code is (
        ProtectedStartSemanticDenialCode.REQUIRED_EVIDENCE_NOT_CURRENT
    )
    assert result.continuation is None
    after = value.backend.read_task_working_set(task_id)
    stored = next(item for item in after.operations
                  if item.intent.operation_id == command.operation_id)
    assert stored.state is OperationState.RESERVED
    assert stored.start_binding_id is None
    assert after == before
    assert value.platform.marker(
        command.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION.value,
    ) is None
    assert value.platform.read_ref(
        record.subject.repository_id, materialization.candidate_branch,
    ) is None


@pytest.mark.parametrize("movement", ("canonical", "authoritative"))
def test_issue29_state_movement_after_freshness_prevents_start_commit(monkeypatch, movement):
    value, materialization, target, dependency, evidence = (
        _issue29_semantic_publication_runtime(stale_schema=False)
    )
    task_id = evidence.subject.task_id
    command = OperationReservationCommand(
        operation_id=OperationId("issue29-occurrence-race-publication"),
        idempotency_key=OperationIdempotencyKey("issue29-occurrence-race-key"),
        action_id=OperationActionId("issue29-occurrence-race-action"),
        subject_id=OperationSubjectId("issue29-occurrence-race-subject"),
        required_evidence_ids=(evidence.evidence_id,),
        integration_binding=NotIntegrationBound(), is_repair_attempt=False,
    )
    reservation = value.boundary.reserve_operation(task_id, command)
    assert ControlStateGate(value.control_state_client).commit(
        reservation, independent_lease(value),
    ).code is GateResultCode.COMMITTED
    working = value.backend.read_task_working_set(task_id)
    operation = next(item for item in working.operations
                     if item.intent.operation_id == command.operation_id)
    dependencies = ControlStateAuthoritativeDependencySet((dependency,))
    prepared = value.prepare_protected_start(
        operation, ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
        ActionTargetFence(
            evidence.subject.repository_id, materialization.candidate_branch,
            None, value.platform.snapshot().generation,
        ), value.acquire_control_lease(value.control_capability, dependencies),
        value.publication_capability, all_scope(), MutationScope(()),
        materialization=materialization, target_registration=target,
    )
    original = gates_module.FixtureProtectedGateRuntime._protected_start_semantic_denial

    def move_after_semantic_check(runtime_value, *args):
        result = original(runtime_value, *args)
        assert result is None
        if movement == "canonical":
            cancellation = value.boundary.set_cancellation(
                task_id, CancellationStatus.REQUESTED,
                CancellationRequestId("issue29-post-check-occurrence-move"),
            )
            assert ControlStateGate(value.control_state_client).commit(
                cancellation, independent_lease(value),
            ).code is GateResultCode.COMMITTED
        else:
            current = value.platform.authoritative_snapshot(*dependency.locator)
            moved = replace(
                current,
                observations=(NormalizedGitHubObservation(
                    "repository",
                    (dependency.repository_id.value, "moved-owner", "repo"),
                ),),
            )
            # Model provider-side movement during the narrow post-check window.
            with value.platform._lock:
                value.platform._authoritative[dependency.locator] = moved
        return result

    monkeypatch.setattr(
        gates_module.FixtureProtectedGateRuntime,
        "_protected_start_semantic_denial", move_after_semantic_check,
    )
    before_start = value.backend.read_task_working_set(task_id)
    result = value.commit_protected_start(
        prepared, operation, ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
    )
    if movement == "canonical":
        # Once F has linearized PREPARED -> START_HELD, a stale C CAS is
        # uncertain until exact recovery; the target remains fenced.
        assert result.code is GateResultCode.INDETERMINATE
        assert result.canonical_result.status is CanonicalWriteStatus.CAS_CONFLICT
    else:
        assert result.code is GateResultCode.INDETERMINATE
        assert value.backend.occurrence == before_start.canonical_state_occurrence_binding
    assert result.continuation is None
    after = value.backend.read_task_working_set(task_id)
    stored = next(item for item in after.operations
                  if item.intent.operation_id == command.operation_id)
    if movement == "canonical":
        assert after.task.cancellation_status is CancellationStatus.REQUESTED
        assert after.canonical_state_occurrence_binding != before_start.canonical_state_occurrence_binding
    else:
        assert after.canonical_state_occurrence_binding == before_start.canonical_state_occurrence_binding
    assert stored.state is OperationState.RESERVED
    assert stored.start_binding_id is None
    assert value.platform.prepared_effect_state(
        command.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION.value,
    ) == "START_HELD"
    assert value.platform.marker(
        command.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION.value,
    ) is None
    assert value.platform.read_ref(
        evidence.subject.repository_id, materialization.candidate_branch,
    ) is None


def test_issue29_semantic_pass_then_external_target_conflict_preserves_g7_result(monkeypatch):
    value, materialization, target, dependency, evidence = (
        _issue29_semantic_publication_runtime(stale_schema=False)
    )
    command = OperationReservationCommand(
        operation_id=OperationId("issue29-target-conflict-publication"),
        idempotency_key=OperationIdempotencyKey("issue29-target-conflict-key"),
        action_id=OperationActionId("issue29-target-conflict-action"),
        subject_id=OperationSubjectId("issue29-target-conflict-subject"),
        required_evidence_ids=(evidence.evidence_id,),
        integration_binding=NotIntegrationBound(), is_repair_attempt=False,
    )
    reservation = value.boundary.reserve_operation(evidence.subject.task_id, command)
    assert ControlStateGate(value.control_state_client).commit(
        reservation, independent_lease(value),
    ).code is GateResultCode.COMMITTED
    working = value.backend.read_task_working_set(evidence.subject.task_id)
    operation = next(item for item in working.operations
                     if item.intent.operation_id == command.operation_id)
    dependencies = ControlStateAuthoritativeDependencySet((dependency,))
    prepared = value.prepare_protected_start(
        operation, ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
        ActionTargetFence(
            evidence.subject.repository_id, materialization.candidate_branch,
            None, value.platform.snapshot().generation,
        ), value.acquire_control_lease(value.control_capability, dependencies),
        value.publication_capability, all_scope(), MutationScope(()),
        materialization=materialization, target_registration=target,
    )
    original = gates_module.FixtureProtectedGateRuntime._protected_start_semantic_denial

    def move_external_ref_after_semantics(runtime_value, *args):
        result = original(runtime_value, *args)
        assert result is None
        # Deliberately model an external/untrusted target mutation that races
        # the final target-fence recheck, bypassing the fixture's local lock.
        with value.platform._lock:
            value.platform._refs[(
                evidence.subject.repository_id, materialization.candidate_branch,
            )] = GitSha("f" * 40)
            value.platform._generation += 1
        return result

    monkeypatch.setattr(
        gates_module.FixtureProtectedGateRuntime,
        "_protected_start_semantic_denial", move_external_ref_after_semantics,
    )
    result = value.commit_protected_start(
        prepared, operation, ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
    )
    assert result.code is GateResultCode.ACTION_PRECONDITION_CONFLICT
    assert result.failure_code is G4FailureCode.ACTION_PRECONDITION_CONFLICT
    assert result.semantic_denial_code is None
    assert result.continuation is None
    stored = next(item for item in value.backend.read_task_working_set(
        evidence.subject.task_id
    ).operations if item.intent.operation_id == command.operation_id)
    assert stored.state is OperationState.CONFLICT
    assert stored.start_binding_id is None
    assert value.platform.read_ref(
        evidence.subject.repository_id, materialization.candidate_branch,
    ) == GitSha("f" * 40)
    assert value.platform.marker(
        command.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION.value,
    ) is None


@pytest.mark.parametrize(("required_ids", "denial", "movement"), [
    (("evidence",), ProtectedStartSemanticDenialCode.REQUIRED_EVIDENCE_NOT_CURRENT, "before"),
    ((), ProtectedStartSemanticDenialCode.REQUIRED_EVIDENCE_CONTEXT_INDETERMINATE, "before"),
    (("evidence",), None, "after"),
    (("evidence",), ProtectedStartSemanticDenialCode.REQUIRED_EVIDENCE_NOT_VALID_FOR_OPERATION,
     "historical-unsatisfied"),
])
def test_issue29_persisted_ready_forward_start_revalidates_semantics(
    required_ids, denial, movement,
):
    value, materialization, target, dependency, evidence = (
        _issue29_semantic_publication_runtime(
            stale_schema=False,
            verdict_name=("changes_required" if movement == "historical-unsatisfied"
                          else "approved"),
        )
    )
    task_id = evidence.subject.task_id
    repository_id = evidence.subject.repository_id
    dependencies = ControlStateAuthoritativeDependencySet((dependency,))

    def reserve(name, evidence_ids, binding):
        command = OperationReservationCommand(
            operation_id=OperationId(name),
            idempotency_key=OperationIdempotencyKey(name + "-key"),
            action_id=OperationActionId(name), subject_id=OperationSubjectId(name),
            required_evidence_ids=evidence_ids, integration_binding=binding,
            is_repair_attempt=False,
        )
        request = value.boundary.reserve_operation(task_id, command)
        assert ControlStateGate(value.control_state_client).commit(
            request, independent_lease(value),
        ).code is GateResultCode.COMMITTED
        working = value.backend.read_task_working_set(task_id)
        return next(item for item in working.operations
                    if item.intent.operation_id == command.operation_id)

    value.platform.seed_ref(repository_id, REF, materialization.base)
    publish = reserve(
        "issue29-ready-publish", (evidence.evidence_id,), NotIntegrationBound(),
    )
    publish_start = start_protected(
        value, publish, ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
        ActionTargetFence(
            repository_id, materialization.candidate_branch, None,
            value.platform.snapshot().generation,
        ), materialization, target=target, dependencies=dependencies,
    )
    assert publish_start.code is GateResultCode.START_COMMITTED
    assert TargetPublicationGate(value.publication_gate_client).perform(
        publish_start.continuation,
    ).code is GateResultCode.EFFECT_SUCCEEDED

    create_pr = reserve(
        "issue29-ready-pr", (evidence.evidence_id,), NotIntegrationBound(),
    )
    pr_start = start_protected(
        value, create_pr, ProtectedEffectSubject.PULL_REQUEST_CREATION,
        ActionTargetFence(
            repository_id, materialization.candidate_branch, materialization.commit,
            value.platform.snapshot().generation, REF, materialization.base,
        ), materialization, target=target, base_ref=REF,
        provenance_operation_id=publish.intent.operation_id,
        dependencies=dependencies,
    )
    assert pr_start.code is GateResultCode.START_COMMITTED
    assert TargetPublicationGate(value.publication_gate_client).perform(
        pr_start.continuation,
    ).code is GateResultCode.EFFECT_SUCCEEDED

    required_evidence_ids = (
        (evidence.evidence_id,) if required_ids else ()
    )
    forward = reserve(
        "issue29-ready-forward", required_evidence_ids,
        IntegrationBound(GitRef(REF.value)),
    )
    task = value.backend.read_task_working_set(task_id).task
    context = mint(
        TrustedCompletionEvaluationContext,
        context_id=ImmutableConfigId("persisted-ready-semantic-context"),
        task_id=task_id, completion_rule_set_id=CompletionRuleSetId("persisted-ready-rule"),
        contract_id=task.contract_id, contract_raw_sha256=task.contract_raw_sha256,
        authorization_id=task.authorization_id, admission_event_id=task.admission_event_id,
        target_registration_id=task.target_registration_id,
        policy_epoch_identity=task.last_evaluated_policy_epoch_identity,
        candidate_id=task.current_candidate_id,
        contract_acceptance_status=ConditionStatus.SATISFIED,
        additional_trusted_completion_conditions_status=ConditionStatus.SATISFIED,
        required_protected_operation_ids=(forward.intent.operation_id,),
        current_applicability_and_authority_status=ConditionStatus.SATISFIED,
    )
    value.register_completion_evaluation_context(context)
    evaluation = TaskEvaluationCommand(
        task_id, context.context_id, (), (), forward.intent.operation_id,
    )
    if movement == "historical-unsatisfied":
        # G4 can produce and persist readiness independently of #29's post-G4
        # veto; model that already-persisted state, then exercise the real
        # protected-start boundary against newly enforced semantics.
        ready_request = value.controller.evaluate_task(evaluation)
    else:
        ready_request = value.boundary.evaluate_task(evaluation)
    assert ready_request.transaction.mutations[0].task.state is TaskState.INTEGRATION_READY
    ready_lease = value.acquire_control_lease(value.control_capability, dependencies)
    assert ControlStateGate(value.control_state_client).commit(ready_request, ready_lease).code is GateResultCode.COMMITTED
    ready_working = value.backend.read_task_working_set(task_id)
    assert ready_working.task.next_integration_operation_id == forward.intent.operation_id

    prepared = value.prepare_protected_start(
        forward, ProtectedEffectSubject.FAST_FORWARD_MERGE,
        ActionTargetFence(
            repository_id, REF, materialization.base,
            value.platform.snapshot().generation,
        ), value.acquire_control_lease(value.control_capability, dependencies),
        value.merge_capability, all_scope(), MutationScope(()),
        materialization=materialization, target_registration=target,
        provenance_operation_id=create_pr.intent.operation_id,
    )

    def move_semantic_context():
        applicability, reader, context_source, base_dependency = value._semantic_contexts[task_id]
        stale_epoch = PolicyEpochIdentity(TrustedManifestId(RawSha256("e" * 64)))
        stale_binding = mint(
            type(applicability.schema_binding),
            **{
                **{name: getattr(applicability.schema_binding, name)
                   for name in applicability.schema_binding.__dataclass_fields__},
                "policy_epoch_identity": stale_epoch,
            },
        )
        stale_context = mint(
            type(applicability),
            **{
                **{name: getattr(applicability, name)
                   for name in applicability.__dataclass_fields__},
                "schema_binding": stale_binding,
            },
        )
        value._semantic_contexts[task_id] = (
            stale_context, reader, context_source, base_dependency,
        )

    before = value.backend.read_task_working_set(task_id)
    if movement == "before":
        # Simulate a newly stale current schema immediately after durable
        # preparation and before the consequential start commit.
        move_semantic_context()
    elif movement == "historical-unsatisfied":
        semantic = value._resolve_semantic_consumption(
            task_id, required_evidence_ids, value.backend.occurrence,
        )
        assert semantic.contract_status is ConditionStatus.UNSATISFIED
        assert semantic.evidence_currentness[0].status is SemanticEvidenceCurrentnessStatus.CURRENT
        assert semantic.obligation_results[0].progression_support_evidence_ids == ()
    start = value.commit_protected_start(
        prepared, forward, ProtectedEffectSubject.FAST_FORWARD_MERGE,
    )
    if movement == "before":
        assert start.code is GateResultCode.REJECTED
        assert start.failure_code is None
        assert start.semantic_denial_code is denial
        assert start.continuation is None
    elif movement == "after":
        assert start.code is GateResultCode.START_COMMITTED
        assert start.semantic_denial_code is None
        assert start.continuation is not None
        started = next(item for item in value.backend.read_task_working_set(task_id).operations
                       if item.intent.operation_id == forward.intent.operation_id)
        assert started.state is OperationState.PERFORMING
        original_start_binding = started.start_binding_id
        move_semantic_context()
        after_movement = value.backend.read_task_working_set(task_id)
        retained = next(item for item in after_movement.operations
                        if item.intent.operation_id == forward.intent.operation_id)
        assert retained.state is OperationState.PERFORMING
        assert retained.start_binding_id == original_start_binding
        assert value.platform.marker(
            forward.intent.operation_id,
            ProtectedEffectSubject.FAST_FORWARD_MERGE.value,
        ) is None
        return
    else:
        assert start.code is GateResultCode.REJECTED
        assert start.failure_code is None
        assert start.semantic_denial_code is denial
        assert start.continuation is None
    after = value.backend.read_task_working_set(task_id)
    stored = next(item for item in after.operations
                  if item.intent.operation_id == forward.intent.operation_id)
    assert after.task.state is TaskState.INTEGRATION_READY
    assert stored.state is OperationState.RESERVED
    assert stored.start_binding_id is None
    assert value.backend.occurrence == before.canonical_state_occurrence_binding
    assert value.platform.marker(
        forward.intent.operation_id,
        ProtectedEffectSubject.FAST_FORWARD_MERGE.value,
    ) is None
    assert value.platform.read_ref(repository_id, REF) == materialization.base


@pytest.mark.parametrize(("verdict_name", "include_dependency"), [
    ("changes_required", True),
    ("approved", False),
])
def test_issue29_start_freshness_and_dependency_lease_are_orthogonal(
    verdict_name, include_dependency,
):
    value, materialization, target, dependency, record = _issue29_semantic_publication_runtime(
        stale_schema=False, verdict_name=verdict_name,
    )
    command = OperationReservationCommand(
        operation_id=OperationId("current-negative-semantic-publication"),
        idempotency_key=OperationIdempotencyKey("current-negative-semantic-publication-key"),
        action_id=OperationActionId("current-negative-semantic-publication-action"),
        subject_id=OperationSubjectId("current-negative-semantic-publication-subject"),
        required_evidence_ids=(record.evidence_id,),
        integration_binding=NotIntegrationBound(),
        is_repair_attempt=False,
    )
    reserve = value.boundary.reserve_operation(record.subject.task_id, command)
    assert ControlStateGate(value.control_state_client).commit(
        reserve, independent_lease(value),
    ).code is GateResultCode.COMMITTED
    working = value.backend.read_task_working_set(record.subject.task_id)
    operation = next(item for item in working.operations
                     if item.intent.operation_id == command.operation_id)
    fence = ActionTargetFence(
        record.subject.repository_id, materialization.candidate_branch, None,
        value.platform.snapshot().generation,
    )
    dependencies = ControlStateAuthoritativeDependencySet((dependency,))
    lease = (value.acquire_control_lease(value.control_capability, dependencies)
             if include_dependency else independent_lease(value))
    prepared = value.prepare_protected_start(
        operation, ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
        fence, lease, value.publication_capability, all_scope(), MutationScope(()),
        materialization=materialization, target_registration=target,
    )
    result = value.commit_protected_start(
        prepared, operation, ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
    )
    after = value.backend.read_task_working_set(record.subject.task_id)
    started = next(item for item in after.operations
                   if item.intent.operation_id == command.operation_id)
    if include_dependency:
        assert result.code is GateResultCode.START_COMMITTED
        assert result.semantic_denial_code is None
        assert result.continuation is not None
        assert started.state is OperationState.PERFORMING
        assert started.start_binding_id is not None
    else:
        assert result.code is GateResultCode.REJECTED
        assert result.failure_code is None
        assert result.semantic_denial_code is (
            ProtectedStartSemanticDenialCode.REQUIRED_EVIDENCE_CONTEXT_INDETERMINATE
        )
        assert result.continuation is None
        assert started.state is OperationState.RESERVED
        assert started.start_binding_id is None
        assert value.backend.occurrence == working.canonical_state_occurrence_binding
    assert value.platform.marker(
        command.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION.value,
    ) is None


def test_issue29_semantic_satisfaction_allows_g4_completion_with_exact_n_plus_f_lease():
    value, _, _, dependency, record = _issue29_semantic_publication_runtime(
        stale_schema=False, verdict_name="approved",
    )
    task = value.backend.read_task_working_set(record.subject.task_id).task
    context = mint(
        TrustedCompletionEvaluationContext,
        context_id=ImmutableConfigId("semantic-satisfied-completion-context"),
        task_id=task.task_id, completion_rule_set_id=CompletionRuleSetId("semantic-satisfied-rule"),
        contract_id=task.contract_id, contract_raw_sha256=task.contract_raw_sha256,
        authorization_id=task.authorization_id, admission_event_id=task.admission_event_id,
        target_registration_id=task.target_registration_id,
        policy_epoch_identity=task.last_evaluated_policy_epoch_identity,
        candidate_id=task.current_candidate_id,
        contract_acceptance_status=ConditionStatus.SATISFIED,
        additional_trusted_completion_conditions_status=ConditionStatus.SATISFIED,
        required_protected_operation_ids=(),
        current_applicability_and_authority_status=ConditionStatus.SATISFIED,
    )
    value.register_completion_evaluation_context(context)
    request = value.boundary.evaluate_task(TaskEvaluationCommand(
        task.task_id, context.context_id, (), (), None,
    ))
    assert request.transaction.mutations[0].task.state is TaskState.COMPLETED
    assert request.required_authoritative_dependencies == (dependency,)
    dependency_set = ControlStateAuthoritativeDependencySet((dependency,))
    lease = value.acquire_control_lease(value.control_capability, dependency_set)
    assert ControlStateGate(value.control_state_client).commit(request, lease).code is GateResultCode.COMMITTED
    assert value.backend.read_task_working_set(task.task_id).task.state is TaskState.COMPLETED


def test_issue29_authoritative_dependency_movement_after_resolution_prevents_completion_commit():
    value, _, _, dependency, record = _issue29_semantic_publication_runtime(
        stale_schema=False, verdict_name="approved",
    )
    task = value.backend.read_task_working_set(record.subject.task_id).task
    context = mint(
        TrustedCompletionEvaluationContext,
        context_id=ImmutableConfigId("semantic-moving-completion-context"),
        task_id=task.task_id, completion_rule_set_id=CompletionRuleSetId("semantic-moving-rule"),
        contract_id=task.contract_id, contract_raw_sha256=task.contract_raw_sha256,
        authorization_id=task.authorization_id, admission_event_id=task.admission_event_id,
        target_registration_id=task.target_registration_id,
        policy_epoch_identity=task.last_evaluated_policy_epoch_identity,
        candidate_id=task.current_candidate_id,
        contract_acceptance_status=ConditionStatus.SATISFIED,
        additional_trusted_completion_conditions_status=ConditionStatus.SATISFIED,
        required_protected_operation_ids=(),
        current_applicability_and_authority_status=ConditionStatus.SATISFIED,
    )
    value.register_completion_evaluation_context(context)
    request = value.boundary.evaluate_task(TaskEvaluationCommand(
        task.task_id, context.context_id, (), (), None,
    ))
    before = value.backend.read_task_working_set(task.task_id)
    locator = value.platform.authoritative_snapshot(*dependency.locator)
    moved_snapshot = AuthoritativeStateSnapshot(
        locator.repository_id, locator.observation_profile_id, locator.transport_config_id,
        (NormalizedGitHubObservation(
            "repository", (locator.repository_id.value, "moved-owner", "repo"),
        ),),
    )
    value.platform.replace_authoritative_snapshot(moved_snapshot)
    lease = value.acquire_control_lease(
        value.control_capability,
        ControlStateAuthoritativeDependencySet((dependency,)),
    )
    assert lease is None
    assert value.backend.read_task_working_set(task.task_id) == before
    assert request.transaction.mutations[0].task.state is TaskState.COMPLETED


def test_issue29_authoritative_dependency_movement_prevents_readiness_commit():
    value, _, _, dependency, record = _issue29_semantic_publication_runtime(
        stale_schema=False, verdict_name="approved",
    )
    task = value.backend.read_task_working_set(record.subject.task_id).task
    operation_command = OperationReservationCommand(
        operation_id=OperationId("semantic-moving-readiness-operation"),
        idempotency_key=OperationIdempotencyKey("semantic-moving-readiness-key"),
        action_id=OperationActionId("semantic-moving-readiness-action"),
        subject_id=OperationSubjectId("semantic-moving-readiness-subject"),
        required_evidence_ids=(record.evidence_id,),
        integration_binding=IntegrationBound(GitRef(REF.value)),
        is_repair_attempt=False,
    )
    reservation = value.boundary.reserve_operation(task.task_id, operation_command)
    assert ControlStateGate(value.control_state_client).commit(
        reservation, independent_lease(value),
    ).code is GateResultCode.COMMITTED
    completion = mint(
        TrustedCompletionEvaluationContext,
        context_id=ImmutableConfigId("semantic-moving-readiness-context"),
        task_id=task.task_id,
        completion_rule_set_id=CompletionRuleSetId("semantic-moving-readiness-rule"),
        contract_id=task.contract_id,
        contract_raw_sha256=task.contract_raw_sha256,
        authorization_id=task.authorization_id,
        admission_event_id=task.admission_event_id,
        target_registration_id=task.target_registration_id,
        policy_epoch_identity=task.last_evaluated_policy_epoch_identity,
        candidate_id=task.current_candidate_id,
        contract_acceptance_status=ConditionStatus.SATISFIED,
        additional_trusted_completion_conditions_status=ConditionStatus.SATISFIED,
        required_protected_operation_ids=(operation_command.operation_id,),
        current_applicability_and_authority_status=ConditionStatus.SATISFIED,
    )
    value.register_completion_evaluation_context(completion)
    request = value.boundary.evaluate_task(TaskEvaluationCommand(
        task.task_id, completion.context_id, (), (), operation_command.operation_id,
    ))
    assert request.transaction.mutations[0].task.state is TaskState.INTEGRATION_READY
    assert request.required_authoritative_dependencies == (dependency,)
    before = value.backend.read_task_working_set(task.task_id)
    locator = value.platform.authoritative_snapshot(*dependency.locator)
    moved_snapshot = AuthoritativeStateSnapshot(
        locator.repository_id, locator.observation_profile_id, locator.transport_config_id,
        (NormalizedGitHubObservation(
            "repository", (locator.repository_id.value, "moved-owner", "repo"),
        ),),
    )
    value.platform.replace_authoritative_snapshot(moved_snapshot)
    lease = value.acquire_control_lease(
        value.control_capability,
        ControlStateAuthoritativeDependencySet((dependency,)),
    )
    assert lease is None
    assert value.backend.read_task_working_set(task.task_id) == before


@pytest.mark.parametrize("kind", [ControlStateCapability, TargetPublicationCapability, MergeCapability])
def test_capabilities_cannot_be_minted_by_callers(kind):
    with pytest.raises(TypeError):
        kind()


def test_dependency_locator_is_exact_structured_tuple():
    item = dependency()
    assert item.locator == (REPO, ImmutableConfigId("observation"), ImmutableConfigId("transport"))


def test_duplicate_dependency_locator_fails_closed():
    with pytest.raises(ValueError):
        ControlStateAuthoritativeDependencySet((dependency(), dependency("other")))


def test_dependency_set_requires_canonical_order():
    a = ControlStateAuthoritativeDependency(GitHubRepositoryId("2"), ImmutableConfigId("o"), ImmutableConfigId("t"), AuthoritativeStateBindingId("b"))
    with pytest.raises(ValueError):
        ControlStateAuthoritativeDependencySet((a, dependency()))


def test_unresolved_dependency_denies_lease():
    value = runtime()
    assert value.acquire_control_lease(value.control_capability, ControlStateAuthoritativeDependencySet((dependency(),))) is None


def test_exact_fresh_dependency_issues_lease():
    value = runtime()
    profile, transport, snapshot = fixture_source()
    expected = authoritative_state_binding(snapshot)
    item = ControlStateAuthoritativeDependency(REPO, profile.profile_id, transport.config_id, expected)
    value.register_fixture_authoritative_source(profile, transport, snapshot)
    assert type(value.acquire_control_lease(value.control_capability, ControlStateAuthoritativeDependencySet((item,)))) is ControlStateCommitLease


def test_unrelated_mutable_reader_is_not_a_fenceable_g7_source():
    value = runtime()
    profile, reader = source()
    expected = reader.read_authoritative(REPO, profile).binding_id
    value.register_authoritative_source(profile, reader)
    dependency_set = ControlStateAuthoritativeDependencySet((
        ControlStateAuthoritativeDependency(
            REPO, profile.profile_id, reader._binding.config_id, expected,
        ),
    ))
    assert value.acquire_control_lease(
        value.control_capability, dependency_set
    ) is None


def test_wrong_capability_denies_control_lease():
    value = runtime()
    profile, transport, snapshot = fixture_source()
    expected = authoritative_state_binding(snapshot)
    item = ControlStateAuthoritativeDependency(REPO, profile.profile_id, transport.config_id, expected)
    value.register_fixture_authoritative_source(profile, transport, snapshot)
    assert value.acquire_control_lease(value.publication_capability, ControlStateAuthoritativeDependencySet((item,))) is None


def test_empty_dependency_set_needs_trusted_independence():
    value = runtime()
    assert value.acquire_control_lease(value.control_capability, ControlStateAuthoritativeDependencySet(())) is None
    proof = value.attest_external_state_independence()
    assert type(value.acquire_control_lease(value.control_capability, ControlStateAuthoritativeDependencySet(()), proof)) is ControlStateCommitLease


def test_control_lease_is_nonserializable():
    value = runtime()
    lease = value.acquire_control_lease(value.control_capability, ControlStateAuthoritativeDependencySet(()), value.attest_external_state_independence())
    with pytest.raises(TypeError):
        pickle.dumps(lease)


def test_commit_request_constructor_is_closed():
    with pytest.raises(TypeError):
        ControlStateCommitRequest()


def test_controller_cannot_be_installed_by_caller():
    with pytest.raises(TypeError):
        DeterministicTrustedController(object())


def test_boundary_rejects_arbitrary_transaction_submission():
    value = runtime()
    with pytest.raises(TypeError):
        value.boundary.submit(TrustedControlCommandKind.CREATE_TASK, object())


def test_prepared_start_constructor_is_closed():
    with pytest.raises(TypeError):
        PreparedProtectedStart()


def test_continuation_constructor_is_not_caller_usable():
    with pytest.raises(TypeError):
        LiveProtectedEffectContinuation()


def test_fixture_publication_is_create_if_absent():
    platform = FixtureGitPlatform()
    assert platform.create_ref_if_absent(REPO, REF, SHA)
    assert not platform.create_ref_if_absent(REPO, REF, SHA)
    assert platform.read_ref(REPO, REF) == SHA


def test_fast_forward_requires_exact_current_and_parent():
    platform = FixtureGitPlatform()
    platform.seed_ref(REPO, REF, SHA)
    assert not platform.fast_forward(REPO, REF, GitSha("b" * 40), GitSha("c" * 40), SHA)
    assert not platform.fast_forward(REPO, REF, SHA, GitSha("c" * 40), GitSha("b" * 40))
    assert platform.fast_forward(REPO, REF, SHA, GitSha("c" * 40), SHA)


def test_effect_marker_requires_same_operation_provenance():
    platform = FixtureGitPlatform()
    platform.record_marker(marker())
    assert platform.marker(OperationId("two"), "publication") is None


def test_effect_marker_cannot_change_result():
    platform = FixtureGitPlatform()
    platform.record_marker(marker())
    with pytest.raises(ValueError):
        platform.record_marker(marker(result="different"))


def test_prepared_effect_cannot_return_from_consumed():
    platform = FixtureGitPlatform()
    platform.prepare_effect(OperationId("one"), "publication")
    platform.record_marker(marker())
    with pytest.raises(ValueError):
        platform.prepare_effect(OperationId("one"), "publication")


def test_restart_preserves_fixture_authority_but_rotates_capabilities():
    value = runtime()
    value.platform.seed_ref(REPO, REF, SHA)
    restarted = value.restart()
    assert restarted.platform.read_ref(REPO, REF) == SHA
    assert restarted.control_capability is not value.control_capability
    assert restarted.binding.runtime_generation.value == 1


def test_audit_is_append_only_snapshot():
    audit = FixtureGateAudit()
    assert audit.append_event(audit_event()) is AuditAppendStatus.APPENDED
    snapshot = audit.snapshot()
    assert snapshot[0].sequence == 1
    with pytest.raises(FrozenInstanceError):
        snapshot[0].sequence = 2


def test_injected_audit_failure_does_not_append_record():
    audit = FixtureGateAudit()
    audit.fail_next_append_for_test()
    assert audit.append_event(audit_event()) is AuditAppendStatus.INTEGRITY_FAILURE
    assert audit.snapshot() == ()


def test_audit_identity_is_canonical_idempotent_and_conflict_detecting():
    audit = FixtureGateAudit()
    event = audit_event()
    assert audit.append_event(event) is AuditAppendStatus.APPENDED
    assert audit.append_event(event) is AuditAppendStatus.ALREADY_PRESENT
    conflicting = object.__new__(type(event))
    object.__setattr__(conflicting, "event_id", event.event_id)
    object.__setattr__(conflicting, "preimage", audit_event(GateAuditOutcome.DENIED).preimage)
    assert audit.append_event(conflicting) is AuditAppendStatus.IDENTITY_CONFLICT
    assert len(audit.snapshot()) == 1


@pytest.mark.parametrize("subject", list(ProtectedEffectSubject))
def test_closed_effect_subject_domain(subject):
    assert subject.value in {"CANDIDATE_BRANCH_PUBLICATION", "PULL_REQUEST_CREATION", "FAST_FORWARD_MERGE"}


@pytest.mark.parametrize("state", list(PreparedProtectedStartState))
def test_closed_prepared_start_state_domain(state):
    assert state.value in {"PREPARED", "START_HELD", "CONSUMED", "RELEASED"}


@pytest.mark.parametrize("kind", list(TrustedControlCommandKind))
def test_closed_control_command_domain(kind):
    assert type(kind) is TrustedControlCommandKind


def test_closed_t_to_p_and_t_to_m_command_families():
    assert set(ProtectedGateCommand) == {
        ProtectedGateCommand.PREPARE_PUBLICATION,
        ProtectedGateCommand.ABORT_PREPARED_PUBLICATION,
        ProtectedGateCommand.SEAL_PUBLICATION_FOR_START,
        ProtectedGateCommand.EXECUTE_PUBLICATION,
        ProtectedGateCommand.READ_VERIFY_PUBLICATION_STATE,
        ProtectedGateCommand.PREPARE_MERGE,
        ProtectedGateCommand.ABORT_PREPARED_MERGE,
        ProtectedGateCommand.SEAL_MERGE_FOR_START,
        ProtectedGateCommand.EXECUTE_MERGE,
        ProtectedGateCommand.READ_VERIFY_MERGE_STATE,
    }


def test_authenticated_control_state_request_rejects_exact_request_from_untrusted_channel():
    value = runtime()
    initialize_task(value)
    request = value.boundary.set_cancellation(
        TASK, CancellationStatus.REQUESTED,
        CancellationRequestId("forged-channel-request"),
    )
    assert request.request_format == "autodev.trusted-controller-to-control-state/v1"
    assert request.root_context_id == value.binding.root_context_id
    assert request.runtime_generation == value.binding.runtime_generation.value
    assert request.declared_t_identity != request.destination_c_identity
    assert request.request_digest == RawSha256(hashlib.sha256(canonical_json_bytes((
        request.request_format, request.command_kind, request.transaction,
        getattr(request, "required_authoritative_binding_ids", ()),
        getattr(request, "required_authoritative_dependencies", ()),
        request.declared_t_identity, request.destination_c_identity,
        request.root_context_id, request.runtime_generation,
        request.replay_identity,
    ))).hexdigest())
    user_context = RuntimeSecurityContext(
        TrustedRuntimeRole.CONTROLLER, ServicePrincipalId("untrusted-caller"),
        value.binding.root_context_id, value.binding.runtime_generation.value,
        value.binding.runtime_binding_id,
    )
    caller = _issue_fixture_caller_context(object(), user_context, request.request_digest)
    lease = independent_lease(value)
    before = value.backend.read_task_working_set(TASK)
    rejected = ControlStateGate(value.control_state_client).commit(request, lease, caller)
    assert rejected.code is GateResultCode.REJECTED
    assert value.backend.read_task_working_set(TASK) == before
    # Failed caller authentication does not consume the C lease or authorize a
    # write; the fixture's separately authenticated T channel can still submit.
    assert ControlStateGate(value.control_state_client).commit(request, lease).code is GateResultCode.COMMITTED
    occurrence_after_first = value.backend.occurrence
    replay = ControlStateGate(value.control_state_client).commit(request, independent_lease(value))
    assert replay.code is GateResultCode.REJECTED
    assert value.backend.occurrence == occurrence_after_first


def test_candidate_gate_entrypoints_receive_only_role_specific_client_contracts():
    value = runtime()
    t_runtime = value.boundary._trusted_runtime
    control = ControlStateGate(value.control_state_client)
    publication = TargetPublicationGate(value.publication_gate_client)
    merge = MergeGate(value.merge_gate_client)
    assert set(control.__slots__) == {"_client"}
    assert set(publication.__slots__) == {"_client"}
    assert set(merge.__slots__) == {"_client"}
    assert not hasattr(control._client, "platform")
    assert not hasattr(control._client, "backend")
    assert not hasattr(control._client, "publication_authority_client")
    assert not hasattr(control._client, "merge_authority_client")
    assert not hasattr(control._client, "_runtime")
    # T's deterministic controller is backed by an explicit read projection,
    # not the canonical mutation endpoint.
    assert type(value.controller._backend) is CanonicalStateReadClient
    assert not hasattr(value.controller._backend, "apply")
    assert not hasattr(value.controller._backend, "backend")
    c_runtime = control._client._control
    assert type(c_runtime).__name__ == "ControlStateGateRuntime"
    assert set(c_runtime.__slots__) == {
        "binding", "backend", "audit", "registry", "capability", "nonce",
        "runtime_identity", "controller_context", "control_context",
        "channel_token", "f_read_verify", "dependency_profiles",
        "dependency_transports",
    }
    assert not hasattr(c_runtime, "platform")
    assert not hasattr(c_runtime, "publication_capability")
    assert not hasattr(c_runtime, "merge_capability")
    assert type(c_runtime.f_read_verify).__name__ == "FixtureReadVerifyClient"
    assert hasattr(publication._client, "perform_publication")
    assert not hasattr(publication._client, "perform_merge")
    assert hasattr(merge._client, "perform_merge")
    assert not hasattr(merge._client, "perform_publication")
    assert type(t_runtime).__name__ == "TrustedControllerRuntime"
    assert set(value.boundary.__slots__) == {"_trusted_runtime"}
    assert set(t_runtime.__slots__) == {
        "controller", "read_state", "f_read_verify", "dependency_profiles",
        "dependency_transports", "contract_contexts", "authorization_contexts",
        "evidence_contexts", "semantic_contexts", "control_state_client",
        "binding", "audit", "publication_gate_client", "merge_gate_client",
    }
    assert type(t_runtime.read_state) is CanonicalStateReadClient
    assert not hasattr(t_runtime, "backend")
    assert not hasattr(t_runtime, "platform")
    assert not hasattr(t_runtime, "publication_authority")
    assert not hasattr(t_runtime, "merge_authority")
    assert not hasattr(t_runtime, "_runtime")
    assert not hasattr(t_runtime, "publication_authority_client")
    assert not hasattr(t_runtime, "merge_authority_client")
    assert isinstance(t_runtime.control_state_client, ControlStateGateClient)
    assert isinstance(t_runtime.publication_gate_client, PublicationGateClient)
    assert isinstance(t_runtime.merge_gate_client, MergeGateClient)
    assert t_runtime.publication_gate_client is not value
    assert t_runtime.merge_gate_client is not value
    assert not hasattr(value.boundary, "_runtime")
    assert not hasattr(value.boundary, "_controller")
    assert t_runtime is not value
    with pytest.raises(TypeError):
        ControlStateGate(value)
    with pytest.raises(TypeError):
        TargetPublicationGate(value)
    with pytest.raises(TypeError):
        MergeGate(value)


def test_publication_and_merge_runtimes_have_separate_candidate_role_slots():
    value = runtime()
    publication = value._publication_gate_runtime
    merge = value._merge_gate_runtime
    assert type(publication).__name__ == "PublicationGateRuntime"
    assert type(merge).__name__ == "MergeGateRuntime"
    for role in (publication, merge):
        assert not isinstance(role, FixtureProtectedGateRuntime)
        assert not hasattr(role, "platform")
        assert not hasattr(role, "registry")
        assert not hasattr(role, "controller")
        assert not hasattr(role, "_control")
        assert not hasattr(role, "_runtime")
        assert not hasattr(role, "_channel_token")
        assert type(role.read_state) is CanonicalStateReadClient
        assert not hasattr(role.read_state, "apply")
        assert type(role._f_read_verify_client).__name__ == "FixtureReadVerifyClient"
        assert isinstance(role.caller_verifier, AuthenticatedCallerVerifier)
        assert not hasattr(role, "commit")
        assert not hasattr(role, "apply")
        assert callable(role.prepare_candidate_action)
        assert callable(role.abort_candidate_action)
        assert callable(role.seal_candidate_action)
        assert callable(role.read_verify_candidate_action)
        assert callable(role.perform_effect)
    assert type(publication.authority_client).__name__ == "FixturePublicationAuthorityClient"
    assert type(merge.authority_client).__name__ == "FixtureMergeAuthorityClient"
    assert isinstance(publication.authority_client, PublicationAuthorityClient)
    assert isinstance(merge.authority_client, MergeAuthorityClient)
    assert not hasattr(publication.authority_client, "prepare_merge")
    assert not hasattr(publication.authority_client, "execute_fast_forward_merge")
    assert not hasattr(merge.authority_client, "prepare_publication")
    assert not hasattr(merge.authority_client, "execute_candidate_ref_publication")
    publication_client = value.publication_gate_client
    merge_client = value.merge_gate_client
    assert type(publication_client._runtime).__name__ == "PublicationGateRuntime"
    assert type(merge_client._runtime).__name__ == "MergeGateRuntime"
    assert publication_client._runtime is publication
    assert merge_client._runtime is merge
    assert not isinstance(publication_client._runtime, FixtureProtectedGateRuntime)
    assert not isinstance(merge_client._runtime, FixtureProtectedGateRuntime)
    assert type(publication.capability) is TargetPublicationCapability
    assert type(merge.capability) is MergeCapability
    assert not hasattr(publication, "_merge_authority_client")
    assert not hasattr(merge, "_publication_authority_client")
    assert not hasattr(publication.read_state, "apply")
    assert not hasattr(merge.read_state, "apply")
    assert publication is not value and merge is not value
    assert value._control_gate_runtime is not value
    assert value._trusted_controller_runtime is not value
    assert value._control_gate_runtime.backend is value.backend
    assert value._control_gate_runtime.f_read_verify is value._f_read_verify_client
    assert publication.authority_client is value._publication_authority_client
    assert merge.authority_client is value._merge_authority_client
    assert publication.allowed_subjects == frozenset((
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
        ProtectedEffectSubject.PULL_REQUEST_CREATION,
    ))
    assert merge.allowed_subjects == frozenset((ProtectedEffectSubject.FAST_FORWARD_MERGE,))
    assert publication.allowed_commands == frozenset((
        ProtectedGateCommand.PREPARE_PUBLICATION,
        ProtectedGateCommand.ABORT_PREPARED_PUBLICATION,
        ProtectedGateCommand.SEAL_PUBLICATION_FOR_START,
        ProtectedGateCommand.EXECUTE_PUBLICATION,
        ProtectedGateCommand.READ_VERIFY_PUBLICATION_STATE,
    ))
    assert merge.allowed_commands == frozenset((
        ProtectedGateCommand.PREPARE_MERGE,
        ProtectedGateCommand.ABORT_PREPARED_MERGE,
        ProtectedGateCommand.SEAL_MERGE_FOR_START,
        ProtectedGateCommand.EXECUTE_MERGE,
        ProtectedGateCommand.READ_VERIFY_MERGE_STATE,
    ))


def test_f_read_verify_projection_exposes_only_explicit_observation_operations():
    value = runtime()
    client = value._f_read_verify_client
    assert type(client).__name__ == "FixtureReadVerifyClient"
    for name in (
        "read_prepared_effect_record", "read_prepared_effect_state", "read_ref",
        "read_marker", "read_pull_request", "verify_materialization",
        "verify_start_held_target_fence",
    ):
        assert callable(getattr(client, name))
    for name in (
        "prepare_publication", "prepare_merge", "abort_prepared_publication",
        "abort_prepared_merge", "seal_publication_for_start", "seal_merge_for_start",
        "execute_candidate_ref_publication", "execute_candidate_pr_creation",
        "execute_fast_forward_merge", "apply", "write", "administer",
    ):
        assert not hasattr(client, name)


def test_p_and_m_do_not_self_issue_authenticated_t_channel_contexts():
    value = runtime()
    initialize_task(value)
    materialization = adopt_recorded_candidate(value, materialize(value))
    operation = reserve_protected(value, "role-auth-context", materialization.candidate_id)
    started = start_protected(
        value, operation, ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
        ActionTargetFence(
            REPO, materialization.candidate_branch, None,
            value.platform.snapshot().generation,
        ), materialization,
    )
    role = value._publication_gate_runtime
    assert role._dispatch_execute(started.continuation, None).code is GateResultCode.REJECTED
    assert TargetPublicationGate(value.publication_gate_client).perform(
        started.continuation,
    ).code is GateResultCode.EFFECT_SUCCEEDED


def test_candidate_publication_execution_does_not_route_through_fixture_runtime(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("candidate P reached FixtureProtectedGateRuntime")

    monkeypatch.setattr(FixtureProtectedGateRuntime, "perform_effect", forbidden)
    value = runtime()
    initialize_task(value)
    materialization = adopt_recorded_candidate(value, materialize(value))
    operation = reserve_protected(value, "independent-p-execution", materialization.candidate_id)
    started = start_protected(
        value, operation, ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
        ActionTargetFence(
            REPO, materialization.candidate_branch, None,
            value.platform.snapshot().generation,
        ), materialization,
    )
    assert TargetPublicationGate(value.publication_gate_client).perform(
        started.continuation,
    ).code is GateResultCode.EFFECT_SUCCEEDED


def test_f_role_clients_reject_cross_role_prepared_authority_commands():
    value = runtime()
    publication = value.platform.publication_authority_client()
    merge = value.platform.merge_authority_client()
    operation = OperationId("cross-role-f-authority")
    assert not hasattr(publication, "prepare_merge")
    assert not hasattr(publication, "execute_fast_forward_merge")
    assert not hasattr(merge, "prepare_publication")
    assert not hasattr(merge, "execute_candidate_ref_publication")
    assert not publication.abort_prepared_publication(
        operation, "FAST_FORWARD_MERGE",
    )
    assert not merge.abort_prepared_merge(
        operation, "CANDIDATE_BRANCH_PUBLICATION",
    )
    assert publication.seal_publication_for_start(
        operation, "FAST_FORWARD_MERGE", object(), RawSha256("a" * 64),
    ) is None
    assert merge.seal_merge_for_start(
        operation, "PULL_REQUEST_CREATION", object(), RawSha256("a" * 64),
    ) is None


def test_unauthenticated_t_to_p_prepare_request_cannot_create_prepared_authority():
    value = runtime()
    initialize_task(value)
    materialization = adopt_recorded_candidate(value, materialize(value))
    operation = reserve_protected(value, "unauthenticated-prepare", materialization.candidate_id)
    fence = ActionTargetFence(
        REPO, materialization.candidate_branch, None,
        value.platform.snapshot().generation,
    )
    request = value._build_prepared_gate_request(
        operation, ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
        fence, materialization, registration(),
        TrustedRuntimeRole.PUBLICATION_GATE,
        ProtectedGateCommand.PREPARE_PUBLICATION,
    )
    untrusted = RuntimeSecurityContext(
        TrustedRuntimeRole.CONTROLLER, ServicePrincipalId("untrusted-prepare"),
        value.binding.root_context_id, value.binding.runtime_generation.value,
        value.binding.runtime_binding_id,
    )
    caller = _issue_fixture_caller_context(object(), untrusted, request.request_digest)
    with pytest.raises(PermissionError):
        value.prepare_protected_start(
            operation, ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
            fence, independent_lease(value), value.publication_capability,
            all_scope(), MutationScope(()), materialization=materialization,
            target_registration=registration(), request=request,
            caller_context=caller,
        )
    assert value.platform.prepared_effect_state(
        operation.intent.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION.value,
    ) is None


def test_unauthenticated_t_to_m_prepare_request_cannot_create_prepared_authority():
    value = runtime()
    initialize_task(value)
    materialization = adopt_recorded_candidate(value, materialize(value))
    operation = reserve_protected(value, "unauthenticated-merge-prepare", materialization.candidate_id)
    fence = ActionTargetFence(
        REPO, REF, materialization.base, value.platform.snapshot().generation,
    )
    request = value._build_prepared_gate_request(
        operation, ProtectedEffectSubject.FAST_FORWARD_MERGE,
        fence, materialization, registration(),
        TrustedRuntimeRole.MERGE_GATE, ProtectedGateCommand.PREPARE_MERGE,
    )
    untrusted = RuntimeSecurityContext(
        TrustedRuntimeRole.CONTROLLER, ServicePrincipalId("untrusted-merge-prepare"),
        value.binding.root_context_id, value.binding.runtime_generation.value,
        value.binding.runtime_binding_id,
    )
    caller = _issue_fixture_caller_context(object(), untrusted, request.request_digest)
    with pytest.raises(PermissionError):
        value.prepare_protected_start(
            operation, ProtectedEffectSubject.FAST_FORWARD_MERGE,
            fence, independent_lease(value), value.merge_capability,
            all_scope(), MutationScope(()), materialization=materialization,
            target_registration=registration(), request=request,
            caller_context=caller,
        )
    assert value.platform.prepared_effect_state(
        operation.intent.operation_id,
        ProtectedEffectSubject.FAST_FORWARD_MERGE.value,
    ) is None


def test_unauthenticated_t_to_p_abort_cannot_release_prepared_authority():
    value = runtime()
    initialize_task(value)
    materialization = adopt_recorded_candidate(value, materialize(value))
    operation = reserve_protected(value, "unauthenticated-abort", materialization.candidate_id)
    fence = ActionTargetFence(
        REPO, materialization.candidate_branch, None,
        value.platform.snapshot().generation,
    )
    prepared = value.prepare_protected_start(
        operation, ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
        fence, independent_lease(value), value.publication_capability,
        all_scope(), MutationScope(()), materialization=materialization,
        target_registration=registration(),
    )
    record = prepared.prepared_start
    request = value._build_prepared_gate_request(
        operation, ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
        fence, materialization, registration(),
        TrustedRuntimeRole.PUBLICATION_GATE,
        ProtectedGateCommand.ABORT_PREPARED_PUBLICATION,
        prepared_start_id=record.prepared_start_id,
        prepared_target_fence_binding=prepared.prepared_start.prepared_target_fence_binding,
    )
    untrusted = RuntimeSecurityContext(
        TrustedRuntimeRole.CONTROLLER, ServicePrincipalId("untrusted-abort"),
        value.binding.root_context_id, value.binding.runtime_generation.value,
        value.binding.runtime_binding_id,
    )
    caller = _issue_fixture_caller_context(object(), untrusted, request.request_digest)
    assert not value.release_prepared_action(record, request, caller)
    assert record.state is PreparedProtectedStartState.PREPARED


def test_unauthenticated_t_to_p_seal_cannot_start_operation():
    value = runtime()
    initialize_task(value)
    materialization = adopt_recorded_candidate(value, materialize(value))
    operation = reserve_protected(value, "unauthenticated-seal", materialization.candidate_id)
    fence = ActionTargetFence(
        REPO, materialization.candidate_branch, None,
        value.platform.snapshot().generation,
    )
    prepared = value.prepare_protected_start(
        operation, ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
        fence, independent_lease(value), value.publication_capability,
        all_scope(), MutationScope(()), materialization=materialization,
        target_registration=registration(),
    )
    request = value._build_prepared_gate_request(
        operation, ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
        fence, materialization, registration(),
        TrustedRuntimeRole.PUBLICATION_GATE,
        ProtectedGateCommand.SEAL_PUBLICATION_FOR_START,
        prepared_start_id=prepared.prepared_start.prepared_start_id,
        prepared_target_fence_binding=prepared.prepared_start.prepared_target_fence_binding,
    )
    untrusted = RuntimeSecurityContext(
        TrustedRuntimeRole.CONTROLLER, ServicePrincipalId("untrusted-seal"),
        value.binding.root_context_id, value.binding.runtime_generation.value,
        value.binding.runtime_binding_id,
    )
    caller = _issue_fixture_caller_context(object(), untrusted, request.request_digest)
    rejected = value.commit_protected_start(
        prepared, operation, ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
        request, caller,
    )
    assert rejected.code is GateResultCode.REJECTED
    assert prepared.prepared_start.state is PreparedProtectedStartState.PREPARED
    assert operation.state is OperationState.RESERVED


def test_authenticated_control_state_request_rejects_stale_t_runtime_epoch():
    value = runtime()
    initialize_task(value)
    request = value.boundary.set_cancellation(
        TASK, CancellationStatus.REQUESTED,
        CancellationRequestId("stale-epoch-request"),
    )
    old_binding = GateRuntimeBinding(
        value.binding.root_context_id, value.binding.runtime_generation,
        value.binding.control_state_principal,
        value.binding.publication_principal, value.binding.merge_principal,
    )
    stale_context = RuntimeSecurityContext(
        TrustedRuntimeRole.CONTROLLER, ServicePrincipalId("trusted-controller"),
        value.binding.root_context_id, value.binding.runtime_generation.value,
        old_binding.runtime_binding_id,
    )
    caller = _issue_fixture_caller_context(object(), stale_context, request.request_digest)
    result = ControlStateGate(value.control_state_client).commit(
        request, independent_lease(value), caller,
    )
    assert result.code is GateResultCode.REJECTED
    stored = value.backend.read_task_working_set(TASK)
    assert stored.task.cancellation_status is CancellationStatus.NONE


@pytest.mark.parametrize("mismatch", ("controller", "destination"))
def test_control_state_rejects_request_with_mismatched_declared_role_identity(mismatch):
    value = runtime()
    initialize_task(value)
    request = value.boundary.set_cancellation(
        TASK, CancellationStatus.REQUESTED,
        CancellationRequestId(f"identity-mismatch-{mismatch}"),
    )
    if mismatch == "controller":
        altered_caller = RuntimeSecurityContext(
            TrustedRuntimeRole.CONTROLLER, ServicePrincipalId("other-controller"),
            value.binding.root_context_id, value.binding.runtime_generation.value,
            value.binding.runtime_binding_id,
        )
        altered_destination = value._c_context
    else:
        altered_caller = value._t_context
        altered_destination = RuntimeSecurityContext(
            TrustedRuntimeRole.CONTROL_STATE_GATE, ServicePrincipalId("other-control"),
            value.binding.root_context_id, value.binding.runtime_generation.value,
            value.binding.runtime_binding_id,
        )
    object.__setattr__(request, "_key", ControllerRequestContext(
        altered_caller, altered_destination,
    ))
    before = value.backend.read_task_working_set(TASK)
    result = ControlStateGate(value.control_state_client).commit(request, independent_lease(value))
    assert result.code is GateResultCode.REJECTED
    assert value.backend.read_task_working_set(TASK) == before


def test_control_state_rejects_transaction_tampered_after_fixture_transport_authentication():
    value = runtime()
    initialize_task(value)
    request = value.boundary.set_cancellation(
        TASK, CancellationStatus.REQUESTED,
        CancellationRequestId("tampered-after-transport-auth"),
    )
    caller = _issue_fixture_caller_context(
        value._t_to_c_channel_token, value._t_context, request.request_digest,
    )
    object.__setattr__(request, "transaction", replace(
        request.transaction, conditions=(),
    ))
    before = value.backend.read_task_working_set(TASK)
    result = ControlStateGate(value.control_state_client).commit(
        request, independent_lease(value), caller,
    )
    assert result.code is GateResultCode.REJECTED
    assert value.backend.read_task_working_set(TASK) == before


@pytest.mark.parametrize("role", (TrustedRuntimeRole.PUBLICATION_GATE,
                                   TrustedRuntimeRole.MERGE_GATE))
def test_publication_or_merge_context_cannot_submit_canonical_mutation(role):
    value = runtime()
    initialize_task(value)
    request = value.boundary.set_cancellation(
        TASK, CancellationStatus.REQUESTED,
        CancellationRequestId(f"wrong-role-c-write-{role.value}"),
    )
    if role is TrustedRuntimeRole.PUBLICATION_GATE:
        context, token = value._p_context, value._t_to_p_channel_token
    else:
        context, token = value._m_context, value._t_to_m_channel_token
    caller = _issue_fixture_caller_context(token, context, request.request_digest)
    before = value.backend.read_task_working_set(TASK)
    result = ControlStateGate(value.control_state_client).commit(
        request, independent_lease(value), caller,
    )
    assert result.code is GateResultCode.REJECTED
    assert value.backend.read_task_working_set(TASK) == before


@pytest.mark.parametrize("code", list(GateResultCode))
def test_closed_gate_result_domain(code):
    assert type(code) is GateResultCode


def test_start_binding_changes_with_action_fence():
    prepared = PreparedProtectedStartId(RawSha256("a" * 64))
    binding = operation_start_binding_id(prepared)
    assert binding.raw_sha256 == prepared.raw_sha256
    assert type(binding) is not type(prepared)


def test_controller_exposes_no_transaction_taking_decision_method():
    for name, member in inspect.getmembers(DeterministicTrustedController, inspect.isfunction):
        if name.startswith("__"):
            continue
        assert "CanonicalTransaction" not in str(inspect.signature(member))


def test_semantic_create_task_flows_through_lease_and_g6_commit():
    value = runtime()
    assert value.backend.apply(CanonicalTransaction(
        value.backend.occurrence, (), (CreateContract(CONTRACT_RECORD), CreateAuthorization(authorization()))
    )).status is CanonicalWriteStatus.APPLIED
    request = value.boundary.create_task(
        task_id=TASK, contract_id=CONTRACT, contract_raw_sha256=RAW,
        authorization_id=AUTH, admission_event_id=ADMISSION,
        target_registration_id=TARGET, policy_epoch_identity=EPOCH,
        repair_budget=RepairBudget(2),
    )
    with pytest.raises(FrozenInstanceError):
        request.transaction = CanonicalTransaction(value.backend.occurrence, (), ())
    assert ControlStateGate(value.control_state_client).commit(
        request, independent_lease(value)
    ).code is GateResultCode.COMMITTED
    assert value.backend.read_task_working_set(TASK).task.task_id == TASK


def test_dependency_mutation_cannot_linearize_while_control_lease_is_live():
    value = runtime()
    assert value.backend.apply(CanonicalTransaction(
        value.backend.occurrence, (), (CreateContract(CONTRACT_RECORD), CreateAuthorization(authorization()))
    )).status is CanonicalWriteStatus.APPLIED
    request = value.boundary.create_task(
        task_id=TASK, contract_id=CONTRACT, contract_raw_sha256=RAW,
        authorization_id=AUTH, admission_event_id=ADMISSION,
        target_registration_id=TARGET, policy_epoch_identity=EPOCH,
        repair_budget=RepairBudget(1),
    )
    profile, transport, snapshot = fixture_source()
    expected = authoritative_state_binding(snapshot)
    value.register_fixture_authoritative_source(profile, transport, snapshot)
    lease = value.acquire_control_lease(
        value.control_capability,
        ControlStateAuthoritativeDependencySet((ControlStateAuthoritativeDependency(
            REPO, profile.profile_id, transport.config_id, expected,
        ),)),
    )
    completed = threading.Event()
    failures = []

    def mutate():
        try:
            value.platform.replace_authoritative_snapshot(fixture_source("changed")[2])
        except FixtureFenceConflict as error:
            failures.append(error)
        finally:
            completed.set()

    thread = threading.Thread(target=mutate)
    thread.start()
    assert completed.wait(1)
    assert len(failures) == 1
    assert value.platform.authoritative_snapshot(
        REPO, profile.profile_id, transport.config_id
    ) == snapshot
    assert ControlStateGate(value.control_state_client).commit(request, lease).code is GateResultCode.COMMITTED
    thread.join()


def test_same_thread_fenced_fixture_mutation_is_rejected_deterministically():
    value = runtime()
    dependency_facts = frozenset({("repository", REPO)})
    token = value.registry.acquire(value, dependency_facts)
    with pytest.raises(FixtureFenceConflict):
        value.platform.seed_ref(REPO, REF, SHA)
    value.registry.release(token)


def test_runtime_replacement_waits_for_live_lease_and_retires_old_runtime():
    value = runtime()
    assert value.backend.apply(CanonicalTransaction(
        value.backend.occurrence, (), (CreateContract(CONTRACT_RECORD), CreateAuthorization(authorization()))
    )).status is CanonicalWriteStatus.APPLIED
    request = value.boundary.create_task(
        task_id=TASK, contract_id=CONTRACT, contract_raw_sha256=RAW,
        authorization_id=AUTH, admission_event_id=ADMISSION,
        target_registration_id=TARGET, policy_epoch_identity=EPOCH,
        repair_budget=RepairBudget(1),
    )
    lease = independent_lease(value)
    with pytest.raises(RuntimeError):
        FixtureProtectedGateRuntime(
            value.binding, value.backend, value.platform, value.audit, value.registry
        )
    assert ControlStateGate(value.control_state_client).commit(request, lease).code is GateResultCode.COMMITTED
    restarted = value.restart()
    assert restarted.binding.runtime_generation == value.binding.runtime_generation
    assert independent_lease(value) is None
    assert independent_lease(restarted) is not None


def test_new_generation_retires_old_runtime_for_normal_work():
    old = runtime()
    replacement = FixtureProtectedGateRuntime(
        GateRuntimeBinding(
            RootContextId(RawSha256("9" * 64)), FixtureRuntimeGeneration(2),
            ServicePrincipalId("control"), ServicePrincipalId("publication"),
            ServicePrincipalId("merge"),
        ), old.backend, old.platform, old.audit, old.registry,
    )
    assert independent_lease(old) is None
    assert type(independent_lease(replacement)) is ControlStateCommitLease


def test_prepared_start_to_publication_and_one_use_continuation():
    value = runtime()
    initialize_task(value)
    materialization = materialize(value)
    materialization = adopt_recorded_candidate(value, materialization)
    operation = reserve_protected(value, "publish", materialization.candidate_id)
    fence = ActionTargetFence(
        REPO, materialization.candidate_branch, None,
        value.platform.snapshot().generation,
    )
    started = start_protected(
        value, operation, ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION, fence,
        materialization,
    )
    assert started.code is GateResultCode.START_COMMITTED
    assert started.continuation._owner is value._publication_runtime
    assert started.continuation._owner is not value
    assert started.continuation._owner is not value.platform
    assert started.continuation._owner is not value.backend
    binding = value.platform.prepared_start_binding(
        operation.intent.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION.value,
    )
    assert type(binding) is StartHeldTargetFenceBinding
    assert started.continuation.start_binding_id == operation_start_binding_id_v2(binding)
    published = TargetPublicationGate(value.publication_gate_client).perform(started.continuation)
    assert published.code is GateResultCode.EFFECT_SUCCEEDED
    assert value.platform.read_ref(REPO, materialization.candidate_branch) == materialization.commit
    assert TargetPublicationGate(value.publication_gate_client).perform(
        started.continuation
    ).code is GateResultCode.LEASE_CONSUMED


def test_candidate_t_publication_start_uses_authenticated_roles_not_legacy_runtime(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("candidate T path invoked legacy same-runtime start/effect")

    monkeypatch.setattr(FixtureProtectedGateRuntime, "prepare_protected_start", forbidden)
    monkeypatch.setattr(FixtureProtectedGateRuntime, "commit_protected_start", forbidden)
    monkeypatch.setattr(FixtureProtectedGateRuntime, "perform_effect", forbidden)
    value = runtime()
    initialize_task(value)
    materialization = adopt_recorded_candidate(value, materialize(value))
    operation = reserve_protected(value, "candidate-t-publication", materialization.candidate_id)
    fence = ActionTargetFence(
        REPO, materialization.candidate_branch, None,
        value.platform.snapshot().generation,
    )
    result = value.boundary.start_protected_operation(
        operation, ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION, fence,
        ControlStateAuthoritativeDependencySet(()), all_scope(), MutationScope(()),
        materialization=materialization, target_registration=registration(),
    )
    assert result.code is GateResultCode.EFFECT_SUCCEEDED
    assert result.continuation is None
    trusted = value.boundary._trusted_runtime
    assert not hasattr(trusted, "target_fence_token")
    assert not hasattr(trusted, "platform")
    assert not isinstance(trusted, FixtureProtectedGateRuntime)
    current = value.backend.read_task_working_set(TASK)
    started = next(item for item in current.operations
                   if item.intent.operation_id == operation.intent.operation_id)
    assert started.state is OperationState.SUCCEEDED
    assert type(started.canonical_protected_start_binding) is CanonicalProtectedStartBinding
    held = started.canonical_protected_start_binding.start_held_target_fence_binding
    assert started.start_binding_id == operation_start_binding_id_v2(held)
    assert value.platform.read_ref(REPO, materialization.candidate_branch) == materialization.commit
    assert value.platform.marker(
        operation.intent.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION.value,
    ) is not None


def test_candidate_t_merge_start_uses_authenticated_roles_not_legacy_runtime(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("candidate T path invoked legacy same-runtime start/effect")

    monkeypatch.setattr(FixtureProtectedGateRuntime, "prepare_protected_start", forbidden)
    monkeypatch.setattr(FixtureProtectedGateRuntime, "commit_protected_start", forbidden)
    monkeypatch.setattr(FixtureProtectedGateRuntime, "perform_effect", forbidden)
    value = runtime()
    initialize_task(value)
    materialization = adopt_recorded_candidate(value, materialize(value))
    dependencies = ControlStateAuthoritativeDependencySet(())
    publish = reserve_protected(value, "candidate-t-merge-publish", materialization.candidate_id)
    publish_result = value.boundary.start_protected_operation(
        publish, ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
        ActionTargetFence(
            REPO, materialization.candidate_branch, None,
            value.platform.snapshot().generation,
        ), dependencies, all_scope(), MutationScope(()),
        materialization=materialization, target_registration=registration(),
    )
    assert publish_result.code is GateResultCode.EFFECT_SUCCEEDED
    assert publish_result.continuation is None
    create_pr = reserve_protected(value, "candidate-t-merge-pr", materialization.candidate_id)
    pr_result = value.boundary.start_protected_operation(
        create_pr, ProtectedEffectSubject.PULL_REQUEST_CREATION,
        ActionTargetFence(
            REPO, materialization.candidate_branch, materialization.commit,
            value.platform.snapshot().generation, REF, materialization.base,
        ), dependencies, all_scope(), MutationScope(()),
        materialization=materialization, target_registration=registration(),
        base_ref=REF, provenance_operation_id=publish.intent.operation_id,
    )
    assert pr_result.code is GateResultCode.EFFECT_SUCCEEDED
    assert pr_result.continuation is None
    merge = reserve_protected(value, "candidate-t-merge-forward", materialization.candidate_id)
    merge_result = value.boundary.start_protected_operation(
        merge, ProtectedEffectSubject.FAST_FORWARD_MERGE,
        ActionTargetFence(
            REPO, REF, materialization.base, value.platform.snapshot().generation,
        ), dependencies, all_scope(), MutationScope(()),
        materialization=materialization, target_registration=registration(),
        provenance_operation_id=create_pr.intent.operation_id,
    )
    assert merge_result.code is GateResultCode.EFFECT_SUCCEEDED
    assert merge_result.continuation is None
    current = value.backend.read_task_working_set(TASK)
    started = next(item for item in current.operations
                   if item.intent.operation_id == merge.intent.operation_id)
    assert started.state is OperationState.SUCCEEDED
    assert type(started.canonical_protected_start_binding) is CanonicalProtectedStartBinding
    assert value.platform.read_ref(REPO, REF) == materialization.commit
    assert value.platform.marker(
        merge.intent.operation_id, ProtectedEffectSubject.FAST_FORWARD_MERGE.value,
    ) is not None


def test_candidate_t_aborts_role_prepared_record_on_semantic_denial():
    value, materialization, target, dependency_record, evidence = (
        _issue29_semantic_publication_runtime(stale_schema=True)
    )
    task_id = evidence.subject.task_id
    command = OperationReservationCommand(
        operation_id=OperationId("candidate-t-abort-prepared"),
        idempotency_key=OperationIdempotencyKey("candidate-t-abort-prepared-key"),
        action_id=OperationActionId("candidate-t-abort-prepared-action"),
        subject_id=OperationSubjectId("candidate-t-abort-prepared-subject"),
        required_evidence_ids=(evidence.evidence_id,),
        integration_binding=NotIntegrationBound(), is_repair_attempt=False,
    )
    request = value.boundary.reserve_operation(task_id, command)
    assert ControlStateGate(value.control_state_client).commit(
        request, independent_lease(value),
    ).code is GateResultCode.COMMITTED
    operation = next(item for item in value.backend.read_task_working_set(task_id).operations
                     if item.intent.operation_id == command.operation_id)
    dependencies = ControlStateAuthoritativeDependencySet((dependency_record,))
    fence = ActionTargetFence(
        target.repository_id, materialization.candidate_branch, None,
        value.platform.snapshot().generation,
    )
    result = value.boundary.start_protected_operation(
        operation, ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION, fence,
        dependencies, target.ordinary_allowed_scope, target.ordinary_forbidden_scope,
        materialization=materialization, target_registration=target,
    )
    assert result.code is GateResultCode.REJECTED
    assert result.semantic_denial_code is ProtectedStartSemanticDenialCode.REQUIRED_EVIDENCE_NOT_CURRENT
    assert value.platform.prepared_effect_state(
        operation.intent.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION.value,
    ) == "RELEASED"
    stored = next(item for item in value.backend.read_task_working_set(task_id).operations
                  if item.intent.operation_id == operation.intent.operation_id)
    assert stored.state is OperationState.RESERVED
    assert stored.start_binding_id is None
    assert value.platform.marker(
        operation.intent.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION.value,
    ) is None


def test_candidate_t_prepared_abort_wins_and_cannot_seal_or_start():
    value = runtime()
    initialize_task(value)
    materialization = adopt_recorded_candidate(value, materialize(value))
    operation = reserve_protected(value, "candidate-t-abort-wins", materialization.candidate_id)
    dependencies = ControlStateAuthoritativeDependencySet(())
    fence = ActionTargetFence(
        REPO, materialization.candidate_branch, None,
        value.platform.snapshot().generation,
    )
    trusted = value.boundary._trusted_runtime
    prepared = trusted._prepared_start_record(
        operation, ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION, fence,
        dependencies, materialization, registration(), None, None,
        all_scope(), MutationScope(()),
    )
    binding = value.publication_gate_client.prepare_start(prepared)
    assert type(binding) is PreparedTargetFenceBinding
    prepared.prepared_target_fence_binding = binding
    prepared._sealed = True
    assert value.publication_gate_client.abort_start(prepared.prepared_start_id)
    assert value.publication_gate_client.seal_start(prepared.prepared_start_id) is None
    denied = value.controller.start_operation(
        TASK, operation.intent.operation_id, prepared.prepared_start_id,
    )
    object.__setattr__(denied, "required_authoritative_dependencies", ())
    assert value.control_state_client.commit_authenticated_request(
        denied, dependencies,
    ).code is GateResultCode.REJECTED
    assert value.platform.prepared_effect_state(
        operation.intent.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION.value,
    ) == "RELEASED"


def test_candidate_t_seal_wins_and_ordinary_abort_is_rejected():
    value = runtime()
    initialize_task(value)
    materialization = adopt_recorded_candidate(value, materialize(value))
    operation = reserve_protected(value, "candidate-t-seal-wins", materialization.candidate_id)
    dependencies = ControlStateAuthoritativeDependencySet(())
    fence = ActionTargetFence(
        REPO, materialization.candidate_branch, None,
        value.platform.snapshot().generation,
    )
    trusted = value.boundary._trusted_runtime
    prepared = trusted._prepared_start_record(
        operation, ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION, fence,
        dependencies, materialization, registration(), None, None,
        all_scope(), MutationScope(()),
    )
    binding = value.publication_gate_client.prepare_start(prepared)
    assert type(binding) is PreparedTargetFenceBinding
    prepared.prepared_target_fence_binding = binding
    prepared._sealed = True
    held = value.publication_gate_client.seal_start(prepared.prepared_start_id)
    assert type(held) is StartHeldTargetFenceBinding
    assert value.publication_gate_client.abort_start(prepared.prepared_start_id) is False
    assert value.platform.prepared_effect_state(
        operation.intent.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION.value,
    ) == "START_HELD"


@pytest.mark.parametrize("tamper", ("operation", "substrate", "epoch", "role"))
def test_c_rejects_start_request_not_bound_to_exact_authoritative_start_held(tamper):
    value = runtime()
    initialize_task(value)
    materialization = adopt_recorded_candidate(value, materialize(value))
    operation = reserve_protected(
        value, f"c-exact-held-{tamper}", materialization.candidate_id,
    )
    other = reserve_protected(
        value, f"c-other-operation-{tamper}", materialization.candidate_id,
    )
    dependencies = ControlStateAuthoritativeDependencySet(())
    fence = ActionTargetFence(
        REPO, materialization.candidate_branch, None,
        value.platform.snapshot().generation,
    )
    trusted = value.boundary._trusted_runtime
    prepared = trusted._prepared_start_record(
        operation, ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION, fence,
        dependencies, materialization, registration(), None, None,
        all_scope(), MutationScope(()),
    )
    prepared_binding = value.publication_gate_client.prepare_start(prepared)
    assert type(prepared_binding) is PreparedTargetFenceBinding
    prepared.prepared_target_fence_binding = prepared_binding
    prepared._sealed = True
    held = value.publication_gate_client.seal_start(prepared.prepared_start_id)
    assert type(held) is StartHeldTargetFenceBinding
    target = other if tamper == "operation" else operation
    submitted_binding = held
    if tamper == "substrate":
        submitted_binding = replace(held, fixture_substrate_identity=RawSha256("f" * 64))
    elif tamper == "epoch":
        submitted_binding = replace(held, runtime_generation=held.runtime_generation + 1)
    elif tamper == "role":
        submitted_binding = replace(held, action_class=ProtectedEffectSubject.FAST_FORWARD_MERGE.value)
    request = value.controller.start_operation(
        TASK, target.intent.operation_id, submitted_binding,
    )
    object.__setattr__(request, "required_authoritative_dependencies", ())
    before = value.backend.read_task_working_set(TASK)
    result = value.control_state_client.commit_authenticated_request(request, dependencies)
    assert result.code is GateResultCode.REJECTED
    assert value.backend.read_task_working_set(TASK) == before
    assert value.platform.prepared_effect_state(
        operation.intent.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION.value,
    ) == "START_HELD"


def test_candidate_t_concurrent_prepared_abort_and_seal_have_one_f_linearized_winner():
    value = runtime()
    initialize_task(value)
    materialization = adopt_recorded_candidate(value, materialize(value))
    operation = reserve_protected(value, "candidate-t-abort-seal-race", materialization.candidate_id)
    dependencies = ControlStateAuthoritativeDependencySet(())
    prepared = value.boundary._trusted_runtime._prepared_start_record(
        operation, ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
        ActionTargetFence(
            REPO, materialization.candidate_branch, None,
            value.platform.snapshot().generation,
        ), dependencies, materialization, registration(), None, None,
        all_scope(), MutationScope(()),
    )
    binding = value.publication_gate_client.prepare_start(prepared)
    assert type(binding) is PreparedTargetFenceBinding
    prepared.prepared_target_fence_binding = binding
    prepared._sealed = True
    barrier = threading.Barrier(2)
    outcomes = []

    def abort():
        barrier.wait()
        outcomes.append(("abort", value.publication_gate_client.abort_start(
            prepared.prepared_start_id,
        )))

    def seal():
        barrier.wait()
        outcomes.append(("seal", value.publication_gate_client.seal_start(
            prepared.prepared_start_id,
        )))

    threads = (threading.Thread(target=abort), threading.Thread(target=seal))
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    abort_result = next(result for name, result in outcomes if name == "abort")
    seal_result = next(result for name, result in outcomes if name == "seal")
    assert (abort_result is True) != (type(seal_result) is StartHeldTargetFenceBinding)
    state = value.platform.prepared_effect_state(
        operation.intent.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION.value,
    )
    assert state in ("RELEASED", "START_HELD")
    if state == "RELEASED":
        denied = value.controller.start_operation(
            TASK, operation.intent.operation_id, prepared.prepared_start_id,
        )
        object.__setattr__(denied, "required_authoritative_dependencies", ())
        assert value.control_state_client.commit_authenticated_request(
            denied, dependencies,
        ).code is GateResultCode.REJECTED
    else:
        assert type(seal_result) is StartHeldTargetFenceBinding


@pytest.mark.parametrize("commit_outcome", ("cas-failure", "response-lost"))
def test_candidate_t_c_start_uncertainty_keeps_start_held_and_requires_recovery(
    monkeypatch, commit_outcome,
):
    value = runtime()
    initialize_task(value)
    materialization = adopt_recorded_candidate(value, materialize(value))
    operation = reserve_protected(
        value, f"candidate-t-start-{commit_outcome}", materialization.candidate_id,
    )
    dependencies = ControlStateAuthoritativeDependencySet(())
    fence = ActionTargetFence(
        REPO, materialization.candidate_branch, None,
        value.platform.snapshot().generation,
    )
    trusted = value.boundary._trusted_runtime
    prepared = trusted._prepared_start_record(
        operation, ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION, fence,
        dependencies, materialization, registration(), None, None,
        all_scope(), MutationScope(()),
    )
    control = value._control_gate_runtime
    original = control.commit_authenticated_request

    if commit_outcome == "cas-failure":
        def fail_commit(request, exact_dependencies, caller_context):
            current = value.backend.read_task_working_set(TASK)
            stored = next(item for item in current.operations
                          if item.intent.operation_id == operation.intent.operation_id)
            advanced = replace(stored, revision=stored.revision + 1)
            movement = value.backend.apply(CanonicalTransaction(
                current.canonical_state_occurrence_binding,
                (OperationRevisionEquals(stored.intent.operation_id, stored.revision),),
                (ReplaceOperation(stored.revision, advanced),),
            ))
            assert movement.status is CanonicalWriteStatus.APPLIED
            return original(request, exact_dependencies, caller_context)

        monkeypatch.setattr(
            gates_module.ControlStateGateRuntime,
            "commit_authenticated_request",
            lambda self, request, exact_dependencies, caller_context: fail_commit(
                request, exact_dependencies, caller_context,
            ),
        )
    else:
        def lose_response(request, exact_dependencies, caller_context):
            original_result = original(request, exact_dependencies, caller_context)
            assert original_result.code is GateResultCode.COMMITTED
            return GateResult(GateResultCode.INDETERMINATE)

        monkeypatch.setattr(
            gates_module.ControlStateGateRuntime,
            "commit_authenticated_request",
            lambda self, request, exact_dependencies, caller_context: lose_response(
                request, exact_dependencies, caller_context,
            ),
        )

    result = value.boundary.start_protected_operation(
        operation, ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION, fence,
        dependencies, all_scope(), MutationScope(()),
        materialization=materialization, target_registration=registration(),
    )
    assert result.code is GateResultCode.INDETERMINATE
    assert value.platform.prepared_effect_state(
        operation.intent.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION.value,
    ) == "START_HELD"
    held = value.platform.prepared_start_binding(
        operation.intent.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION.value,
    )
    assert type(held) is StartHeldTargetFenceBinding
    assert value.publication_gate_client.abort_start(prepared.prepared_start_id) is False
    if commit_outcome == "cas-failure":
        assert value.publication_gate_client.execute_started(
            prepared.prepared_start_id, operation_start_binding_id_v2(held),
        ).code is GateResultCode.REJECTED
    assert value.platform.marker(
        operation.intent.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION.value,
    ) is None
    with pytest.raises(FixtureFenceConflict):
        value.platform.seed_ref(REPO, materialization.candidate_branch, SHA)
    if commit_outcome == "response-lost":
        stored = next(item for item in value.backend.read_task_working_set(TASK).operations
                      if item.intent.operation_id == operation.intent.operation_id)
        assert stored.state is OperationState.PERFORMING
        assert trusted.reconcile_recovered_effect(
            TASK, operation.intent.operation_id,
            ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
        ).code is GateResultCode.INDETERMINATE


def test_publication_request_binds_exact_full_operation_and_rejects_untrusted_caller():
    value = runtime()
    initialize_task(value)
    materialization = materialize(value)
    materialization = adopt_recorded_candidate(value, materialization)
    operation = reserve_protected(value, "publication-auth-request", materialization.candidate_id)
    started = start_protected(
        value, operation, ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
        ActionTargetFence(
            REPO, materialization.candidate_branch, None,
            value.platform.snapshot().generation,
        ), materialization,
    )
    request = value._build_protected_gate_request(
        started.continuation, TrustedRuntimeRole.PUBLICATION_GATE,
    )
    assert type(request) is ProtectedGateRequest
    assert request.command is ProtectedGateCommand.EXECUTE_PUBLICATION
    assert request.operation_id == operation.intent.operation_id
    assert request.candidate_id == materialization.candidate_id
    assert request.materialization_id == materialization.materialization_id
    assert request.prepared_start_id == started.continuation.prepared_start_id
    assert request.operation_start_binding_id == started.continuation.start_binding_id
    wrong_caller_context = RuntimeSecurityContext(
        TrustedRuntimeRole.CONTROLLER, ServicePrincipalId("untrusted-controller"),
        value.binding.root_context_id, value.binding.runtime_generation.value,
        value.binding.runtime_binding_id,
    )
    result = TargetPublicationGate(value.publication_gate_client).perform(
        started.continuation,
        _issue_fixture_caller_context(
            object(), wrong_caller_context, request.request_digest,
        ),
    )
    assert result.code is GateResultCode.REJECTED
    assert value.platform.marker(
        operation.intent.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION.value,
    ) is None
    assert value.platform.prepared_effect_state(
        operation.intent.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION.value,
    ) == "START_HELD"


@pytest.mark.parametrize("tamper", ("declared_t", "destination"))
def test_protected_gate_rejects_request_identity_or_destination_mismatch(tamper):
    value = runtime()
    initialize_task(value)
    materialization = adopt_recorded_candidate(value, materialize(value))
    operation = reserve_protected(value, f"request-mismatch-{tamper}", materialization.candidate_id)
    started = start_protected(
        value, operation, ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
        ActionTargetFence(
            REPO, materialization.candidate_branch, None,
            value.platform.snapshot().generation,
        ), materialization,
    )
    request = value._build_protected_gate_request(
        started.continuation, TrustedRuntimeRole.PUBLICATION_GATE,
    )
    values = {
        name: getattr(request, name)
        for name in (
            "format", "command", "declared_t_identity", "destination_identity",
            "root_context_id", "runtime_generation", "operation_id", "action_class",
            "action_id", "idempotency_key", "candidate_id", "materialization_id",
            "target_registration_id", "prepared_start_id", "operation_start_binding_id",
            "prepared_target_fence_binding", "start_held_target_fence_binding",
            "fixture_substrate_identity", "authority_binding_identity", "target_fence_identity",
        )
    }
    if tamper == "declared_t":
        values["declared_t_identity"] = RawSha256("1" * 64)
    else:
        values["destination_identity"] = RawSha256("2" * 64)
    identity = RawSha256(hashlib.sha256(canonical_json_bytes((
        "autodev.protected-gate-request-id/v1", values["command"],
        values["declared_t_identity"], values["destination_identity"],
        values["root_context_id"], values["runtime_generation"],
        values["operation_id"], values["action_class"], values["action_id"],
        values["idempotency_key"], values["candidate_id"],
        values["materialization_id"], values["target_registration_id"],
        values["prepared_start_id"], values["operation_start_binding_id"],
        values["prepared_target_fence_binding"],
        values["start_held_target_fence_binding"],
        values["fixture_substrate_identity"], values["authority_binding_identity"],
        values["target_fence_identity"],
    ))).hexdigest())
    values["request_identity"] = identity
    values["request_digest"] = RawSha256(hashlib.sha256(canonical_json_bytes((
        values["format"], values["command"], values["declared_t_identity"],
        values["destination_identity"], values["root_context_id"],
        values["runtime_generation"], values["operation_id"], values["action_class"],
        values["action_id"], values["idempotency_key"], values["candidate_id"],
        values["materialization_id"], values["target_registration_id"],
        values["prepared_start_id"], values["operation_start_binding_id"],
        values["prepared_target_fence_binding"],
        values["start_held_target_fence_binding"],
        values["fixture_substrate_identity"], values["authority_binding_identity"],
        values["target_fence_identity"], identity,
    ))).hexdigest())
    forged = ProtectedGateRequest(**values)
    caller = _issue_fixture_caller_context(
        value._t_to_p_channel_token, value._t_context, forged.request_digest,
    )
    result = value._dispatch_protected_gate(
        forged, started.continuation, TrustedRuntimeRole.PUBLICATION_GATE, caller,
    )
    assert result.code is GateResultCode.REJECTED
    assert value.platform.marker(
        operation.intent.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION.value,
    ) is None


def test_publication_gate_cannot_route_merge_continuation():
    value = runtime()
    initialize_task(value)
    materialization = materialize(value)
    materialization = adopt_recorded_candidate(value, materialization)
    publish = reserve_protected(value, "wrong-role-publish", materialization.candidate_id)
    publish_start = start_protected(
        value, publish, ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
        ActionTargetFence(
            REPO, materialization.candidate_branch, None,
            value.platform.snapshot().generation,
        ), materialization,
    )
    assert TargetPublicationGate(value.publication_gate_client).perform(
        publish_start.continuation
    ).code is GateResultCode.EFFECT_SUCCEEDED
    create_pr = reserve_protected(value, "wrong-role-pr", materialization.candidate_id)
    pr_start = start_protected(
        value, create_pr, ProtectedEffectSubject.PULL_REQUEST_CREATION,
        ActionTargetFence(
            REPO, materialization.candidate_branch, materialization.commit,
            value.platform.snapshot().generation, REF, materialization.base,
        ), materialization, base_ref=REF,
        provenance_operation_id=publish.intent.operation_id,
    )
    assert TargetPublicationGate(value.publication_gate_client).perform(
        pr_start.continuation
    ).code is GateResultCode.EFFECT_SUCCEEDED
    operation = reserve_protected(value, "wrong-role-request", materialization.candidate_id)
    started = start_protected(
        value, operation, ProtectedEffectSubject.FAST_FORWARD_MERGE,
        ActionTargetFence(
            REPO, REF, materialization.base,
            value.platform.snapshot().generation,
        ), materialization,
        provenance_operation_id=create_pr.intent.operation_id,
    )
    result = TargetPublicationGate(value.publication_gate_client).perform(started.continuation)
    assert result.code is GateResultCode.REJECTED
    assert value.platform.marker(
        operation.intent.operation_id,
        ProtectedEffectSubject.FAST_FORWARD_MERGE.value,
    ) is None


def test_target_mutation_cannot_linearize_across_prepared_start_and_effect():
    value = runtime()
    initialize_task(value)
    materialization = materialize(value)
    materialization = adopt_recorded_candidate(value, materialization)
    operation = reserve_protected(value, "publish-fenced", materialization.candidate_id)
    fence = ActionTargetFence(
        REPO, materialization.candidate_branch, None,
        value.platform.snapshot().generation,
    )
    prepared = value.prepare_protected_start(
        operation, ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION, fence,
        independent_lease(value), value.publication_capability,
        all_scope(), MutationScope(()), materialization=materialization,
        target_registration=registration(),
    )
    completed = threading.Event()
    failures = []

    def mutate_target():
        try:
            value.platform.create_ref_if_absent(
                REPO, materialization.candidate_branch, materialization.commit
            )
        except FixtureFenceConflict as error:
            failures.append(error)
        finally:
            completed.set()

    thread = threading.Thread(target=mutate_target)
    thread.start()
    assert completed.wait(1)
    assert len(failures) == 1
    started = value.commit_protected_start(
        prepared, operation,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
    )
    assert TargetPublicationGate(value.publication_gate_client).perform(
        started.continuation
    ).code is GateResultCode.EFFECT_SUCCEEDED
    thread.join()


def test_same_operation_exact_marker_and_postcondition_is_already_applied():
    value = runtime()
    initialize_task(value)
    materialization = materialize(value)
    materialization = adopt_recorded_candidate(value, materialization)
    operation = reserve_protected(value, "publish-replay", materialization.candidate_id)
    fence = ActionTargetFence(
        REPO, materialization.candidate_branch, None,
        value.platform.snapshot().generation,
    )
    started = start_protected(
        value, operation, ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION, fence,
        materialization,
    )
    continuation = started.continuation
    effect_subject = PublishedCandidateRefEffectSubject(
        REPO, materialization.candidate_branch,
        GitRef(materialization.candidate_branch.value), materialization.commit,
    )
    pre_identity = RawSha256(hashlib.sha256(
        canonical_json_bytes(("pre", fence))
    ).hexdigest())
    post_identity = RawSha256(hashlib.sha256(
        canonical_json_bytes(("post", effect_subject))
    ).hexdigest())
    action_digest = RawSha256(hashlib.sha256(canonical_json_bytes((
        continuation.subject, continuation.action_id,
        materialization.materialization_id,
        materialization.inventory.inventory_id, effect_subject,
    ))).hexdigest())
    exact = build_protected_effect_marker(ProtectedEffectMarkerPreimage(
        "autodev.protected-effect-marker/v1", continuation.subject.value,
        continuation.operation_id, continuation.idempotency_key,
        continuation.action_id, action_digest, materialization.materialization_id,
        materialization.inventory.inventory_id, continuation.prepared_start_id,
        value.binding.root_context_id, value.binding.runtime_generation.value,
        value.publication_capability.service_identity, effect_subject,
        pre_identity, post_identity,
    ))
    assert value.platform.publish_and_mark(
        REPO, materialization.candidate_branch, materialization.commit, exact,
        _fence_token=continuation.target_fence_token,
    )
    assert TargetPublicationGate(value.publication_gate_client).perform(
        continuation
    ).code is GateResultCode.ALREADY_APPLIED


def test_manual_same_sha_candidate_branch_conflicts_before_start():
    value = runtime()
    initialize_task(value)
    materialization = materialize(value)
    materialization = adopt_recorded_candidate(value, materialization)
    operation = reserve_protected(value, "publish", materialization.candidate_id)
    value.platform.create_ref_if_absent(
        REPO, materialization.candidate_branch, materialization.commit
    )
    fence = ActionTargetFence(
        REPO, materialization.candidate_branch, None,
        value.platform.snapshot().generation,
    )
    started = start_protected(
        value, operation, ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION, fence,
        materialization,
    )
    assert started.code is GateResultCode.ACTION_PRECONDITION_CONFLICT
    canonical = value.backend.read_task_working_set(TASK)
    stored = next(item for item in canonical.operations if item.intent.operation_id == operation.intent.operation_id)
    assert stored.state is OperationState.CONFLICT


def test_authoritative_cancellation_start_denial_preserves_exact_g4_failure():
    value = runtime()
    initialize_task(value)
    materialization = materialize(value)
    materialization = adopt_recorded_candidate(value, materialization)
    operation = reserve_protected(value, "cancelled-start", materialization.candidate_id)
    cancellation = value.boundary.set_cancellation(
        TASK, CancellationStatus.AUTHORITATIVE, CancellationRequestId("cancel-first")
    )
    assert ControlStateGate(value.control_state_client).commit(
        cancellation, independent_lease(value)
    ).code is GateResultCode.COMMITTED

    result = start_protected(
        value, operation, ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
        ActionTargetFence(
            REPO, materialization.candidate_branch, None,
            value.platform.snapshot().generation,
        ), materialization,
    )

    assert result.code is GateResultCode.REJECTED
    assert result.failure_code is G4FailureCode.CANCELLATION_BLOCKS_OPERATION_START
    stored = next(
        item for item in value.backend.read_task_working_set(TASK).operations
        if item.intent.operation_id == operation.intent.operation_id
    )
    assert stored.state is OperationState.RESERVED
    assert stored.start_binding_id is None
    assert value.platform.marker(
        operation.intent.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION.value,
    ) is None
    assert value.platform.prepared_effect_state(
        operation.intent.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION.value,
    ) == "RELEASED"


def test_nonready_integration_start_denial_preserves_exact_g4_failure():
    value = runtime()
    initialize_task(value)
    materialization = materialize(value)
    materialization = adopt_recorded_candidate(value, materialization)
    operation = reserve_protected(
        value, "nonready-integration-start", materialization.candidate_id,
        integration_binding=IntegrationBound(GitRef(REF.value)),
    )

    result = start_protected(
        value, operation, ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
        ActionTargetFence(
            REPO, materialization.candidate_branch, None,
            value.platform.snapshot().generation,
        ), materialization,
    )

    assert result.code is GateResultCode.REJECTED
    assert result.failure_code is G4FailureCode.OPERATION_NOT_STARTABLE
    stored = next(
        item for item in value.backend.read_task_working_set(TASK).operations
        if item.intent.operation_id == operation.intent.operation_id
    )
    assert stored.state is OperationState.RESERVED
    assert stored.start_binding_id is None
    assert value.platform.marker(
        operation.intent.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION.value,
    ) is None


def test_start_audit_failure_mints_no_continuation_and_reconciles_failed():
    value = runtime()
    initialize_task(value)
    materialization = materialize(value)
    materialization = adopt_recorded_candidate(value, materialization)
    operation = reserve_protected(value, "publish", materialization.candidate_id)
    fence = ActionTargetFence(
        REPO, materialization.candidate_branch, None,
        value.platform.snapshot().generation,
    )
    value.audit.fail_append_after_for_test(2)
    started = start_protected(
        value, operation, ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION, fence,
        materialization,
    )
    assert started.code is GateResultCode.AUDIT_FAILURE_AFTER_COMMIT
    assert started.continuation is None
    canonical = value.backend.read_task_working_set(TASK)
    stored = next(item for item in canonical.operations if item.intent.operation_id == operation.intent.operation_id)
    assert stored.state is OperationState.FAILED


def test_post_start_audit_failure_reuses_frozen_dependencies_without_effect_replay():
    value = runtime()
    dependencies = install_fixture_dependencies(value, "post-start-a", "post-start-b")
    alternate = install_fixture_dependencies(value, "post-start-alternate")
    initialize_task(value)
    materialization = materialize(value)
    materialization = adopt_recorded_candidate(value, materialization)
    operation = reserve_protected(value, "post-start-frozen", materialization.candidate_id)
    fence = ActionTargetFence(
        REPO, materialization.candidate_branch, None,
        value.platform.snapshot().generation,
    )
    value.audit.fail_append_after_for_test(2)
    started = start_protected(
        value, operation, ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
        fence, materialization, dependencies=dependencies,
    )
    assert started.code is GateResultCode.AUDIT_FAILURE_AFTER_COMMIT
    assert started.continuation is None
    stored = next(
        item for item in value.backend.read_task_working_set(TASK).operations
        if item.intent.operation_id == operation.intent.operation_id
    )
    assert stored.state is OperationState.FAILED
    assert value.platform.marker(
        operation.intent.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION.value,
    ) is None
    assert value.platform.prepared_effect_state(
        operation.intent.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION.value,
    ) == "RELEASED"
    expected_dependencies = tuple(
        GateAuditAuthoritativeDependency(
            item.repository_id, item.observation_profile_id,
            item.transport_config_id, item.expected_binding_id,
        )
        for item in dependencies.dependencies
    )
    path_records = [
        record.event.preimage for record in value.audit.snapshot()
        if (record.event.preimage.gate == "CONTROL_STATE"
            and record.event.preimage.action in (
                "START_OPERATION", "RECONCILE_OPERATION",
            )
            and record.event.preimage.operation_id == operation.intent.operation_id)
    ]
    assert [record.action for record in path_records] == [
        "START_OPERATION", "START_OPERATION",
        "RECONCILE_OPERATION", "RECONCILE_OPERATION",
    ]
    for record in path_records:
        assert record.authoritative_dependencies == expected_dependencies
        assert record.authoritative_dependencies != ()
        assert record.authoritative_dependencies != tuple(
            GateAuditAuthoritativeDependency(
                item.repository_id, item.observation_profile_id,
                item.transport_config_id, item.expected_binding_id,
            )
            for item in alternate.dependencies
        )
        assert record.runtime_binding_id == value.binding.runtime_binding_id
        assert record.canonical_state_occurrence_binding is not None
        assert record.operation_id == operation.intent.operation_id
        assert record.operation_start_binding_id == stored.start_binding_id


def test_post_start_audit_failure_stale_frozen_dependencies_fail_closed():
    value = runtime()
    dependencies = install_fixture_dependencies(value, "post-start-stale")
    initialize_task(value)
    materialization = materialize(value)
    materialization = adopt_recorded_candidate(value, materialization)
    operation = reserve_protected(value, "post-start-stale", materialization.candidate_id)
    frozen = dependencies.dependencies[0]

    def stale_dependency():
        value.platform.replace_authoritative_snapshot(AuthoritativeStateSnapshot(
            frozen.repository_id, frozen.observation_profile_id,
            frozen.transport_config_id,
            (NormalizedGitHubObservation(
                "repository", (REPO.value, "stale", "repository"),
            ),),
        ))

    value._post_start_audit_failure_hook = stale_dependency
    value.audit.fail_append_after_for_test(2)
    started = start_protected(
        value, operation, ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
        ActionTargetFence(
            REPO, materialization.candidate_branch, None,
            value.platform.snapshot().generation,
        ), materialization, dependencies=dependencies,
    )
    assert started.code is GateResultCode.INDETERMINATE
    assert started.continuation is None
    stored = next(
        item for item in value.backend.read_task_working_set(TASK).operations
        if item.intent.operation_id == operation.intent.operation_id
    )
    assert stored.state is OperationState.PERFORMING
    assert value.platform.marker(
        operation.intent.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION.value,
    ) is None
    assert value.platform.prepared_effect_state(
        operation.intent.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION.value,
    ) == "START_HELD"


def test_post_start_audit_failure_altered_frozen_dependencies_fail_closed():
    value = runtime()
    dependencies = install_fixture_dependencies(value, "post-start-original")
    alternate = install_fixture_dependencies(value, "post-start-altered")
    initialize_task(value)
    materialization = materialize(value)
    materialization = adopt_recorded_candidate(value, materialization)
    operation = reserve_protected(value, "post-start-altered", materialization.candidate_id)

    def alter_preimage():
        durable = value.platform.prepared_effect_record(
            operation.intent.operation_id,
            ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION.value,
        )
        object.__setattr__(durable.preimage, "dependencies", alternate)

    value._post_start_audit_failure_hook = alter_preimage
    value.audit.fail_append_after_for_test(2)
    started = start_protected(
        value, operation, ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
        ActionTargetFence(
            REPO, materialization.candidate_branch, None,
            value.platform.snapshot().generation,
        ), materialization, dependencies=dependencies,
    )
    assert started.code is GateResultCode.INDETERMINATE
    assert started.continuation is None
    stored = next(
        item for item in value.backend.read_task_working_set(TASK).operations
        if item.intent.operation_id == operation.intent.operation_id
    )
    assert stored.state is OperationState.PERFORMING
    assert value.platform.marker(
        operation.intent.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION.value,
    ) is None
    assert value.platform.prepared_effect_state(
        operation.intent.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION.value,
    ) == "START_HELD"


def test_exact_publication_marker_to_pr_marker_to_fast_forward_merge():
    value = runtime()
    initialize_task(value)
    materialization = materialize(value)
    materialization = adopt_recorded_candidate(value, materialization)

    publish = reserve_protected(value, "publish-chain", materialization.candidate_id)
    publish_fence = ActionTargetFence(
        REPO, materialization.candidate_branch, None,
        value.platform.snapshot().generation,
    )
    publish_start = start_protected(
        value, publish, ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
        publish_fence, materialization,
    )
    assert TargetPublicationGate(value.publication_gate_client).perform(
        publish_start.continuation
    ).code is GateResultCode.EFFECT_SUCCEEDED
    publication_marker = value.platform.marker(
        publish.intent.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION.value,
    )
    assert type(publication_marker.preimage.effect_subject) is PublishedCandidateRefEffectSubject

    create_pr = reserve_protected(value, "create-pr", materialization.candidate_id)
    pr_fence = ActionTargetFence(
        REPO, materialization.candidate_branch, materialization.commit,
        value.platform.snapshot().generation, REF, materialization.base,
    )
    pr_start = start_protected(
        value, create_pr, ProtectedEffectSubject.PULL_REQUEST_CREATION, pr_fence,
        materialization, base_ref=REF,
        provenance_operation_id=publish.intent.operation_id,
    )
    assert TargetPublicationGate(value.publication_gate_client).perform(
        pr_start.continuation
    ).code is GateResultCode.EFFECT_SUCCEEDED
    pr_marker = value.platform.marker(
        create_pr.intent.operation_id,
        ProtectedEffectSubject.PULL_REQUEST_CREATION.value,
    )
    assert type(pr_marker.preimage.effect_subject) is CreatedCandidatePrEffectSubject
    assert pr_marker.preimage.effect_subject.base_ref == GitRef(REF.value)

    merge = reserve_protected(value, "merge", materialization.candidate_id)
    merge_fence = ActionTargetFence(
        REPO, REF, materialization.base, value.platform.snapshot().generation
    )
    merge_start = start_protected(
        value, merge, ProtectedEffectSubject.FAST_FORWARD_MERGE, merge_fence,
        materialization, provenance_operation_id=create_pr.intent.operation_id,
    )
    assert MergeGate(value.merge_gate_client).perform(
        merge_start.continuation
    ).code is GateResultCode.EFFECT_SUCCEEDED
    merge_marker = value.platform.marker(
        merge.intent.operation_id,
        ProtectedEffectSubject.FAST_FORWARD_MERGE.value,
    )
    assert type(merge_marker.preimage.effect_subject) is FastForwardMergeEffectSubject
    assert value.platform.read_ref(REPO, REF) == materialization.commit
    assert value.platform.pull_request(
        pr_marker.preimage.effect_subject.pull_request_number
    ).merged


def test_pr_marker_for_different_base_ref_same_sha_cannot_authorize_merge():
    alternate = CanonicalBranchRef("refs/heads/release")
    target = registration((REF, alternate))
    value = runtime(target)
    initialize_task(value)
    materialization = materialize(value)
    value.platform.seed_ref(REPO, alternate, materialization.base)
    materialization = adopt_recorded_candidate(value, materialization)

    publish = reserve_protected(value, "publish-wrong-base", materialization.candidate_id)
    publish_start = start_protected(value, publish,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
        ActionTargetFence(REPO, materialization.candidate_branch, None,
                          value.platform.snapshot().generation), materialization,
        target=target)
    assert TargetPublicationGate(value.publication_gate_client).perform(
        publish_start.continuation
    ).code is GateResultCode.EFFECT_SUCCEEDED

    create_pr = reserve_protected(value, "pr-wrong-base", materialization.candidate_id)
    pr_start = start_protected(value, create_pr,
        ProtectedEffectSubject.PULL_REQUEST_CREATION,
        ActionTargetFence(REPO, materialization.candidate_branch,
                          materialization.commit, value.platform.snapshot().generation,
                          alternate, materialization.base), materialization,
        target=target, base_ref=alternate,
        provenance_operation_id=publish.intent.operation_id)
    assert TargetPublicationGate(value.publication_gate_client).perform(
        pr_start.continuation
    ).code is GateResultCode.EFFECT_SUCCEEDED

    merge = reserve_protected(value, "merge-wrong-base", materialization.candidate_id)
    with pytest.raises(ValueError):
        start_protected(value, merge,
            ProtectedEffectSubject.FAST_FORWARD_MERGE,
            ActionTargetFence(REPO, REF, materialization.base,
                              value.platform.snapshot().generation), materialization,
            target=target, provenance_operation_id=create_pr.intent.operation_id)
    assert value.platform.read_ref(REPO, REF) == materialization.base


def test_manual_equivalent_pr_cannot_substitute_for_exact_pr_marker():
    value = runtime()
    initialize_task(value)
    materialization = materialize(value)
    materialization = adopt_recorded_candidate(value, materialization)
    publish = reserve_protected(value, "publish-manual-pr", materialization.candidate_id)
    publish_start = start_protected(value, publish,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
        ActionTargetFence(REPO, materialization.candidate_branch, None,
                          value.platform.snapshot().generation), materialization)
    assert TargetPublicationGate(value.publication_gate_client).perform(
        publish_start.continuation
    ).code is GateResultCode.EFFECT_SUCCEEDED
    value.platform.create_pull_request(
        REPO, materialization.candidate_branch, REF, materialization.commit
    )
    merge = reserve_protected(value, "merge-manual-pr", materialization.candidate_id)
    with pytest.raises(ValueError):
        start_protected(value, merge,
            ProtectedEffectSubject.FAST_FORWARD_MERGE,
            ActionTargetFence(REPO, REF, materialization.base,
                              value.platform.snapshot().generation), materialization,
            provenance_operation_id=OperationId("manual-pr"))
    assert value.platform.read_ref(REPO, REF) == materialization.base


def test_target_effect_audit_failure_preserves_marker_and_restart_reconciles_without_replay():
    value = runtime()
    initialize_task(value)
    materialization = materialize(value)
    materialization = adopt_recorded_candidate(value, materialization)
    operation = reserve_protected(value, "publish-audit", materialization.candidate_id)
    fence = ActionTargetFence(
        REPO, materialization.candidate_branch, None,
        value.platform.snapshot().generation,
    )
    started = start_protected(
        value, operation, ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION, fence,
        materialization,
    )
    value.audit.fail_next_append_for_test()
    result = TargetPublicationGate(value.publication_gate_client).perform(started.continuation)
    assert result.code is GateResultCode.AUDIT_FAILURE_AFTER_COMMIT
    assert value.platform.marker(
        operation.intent.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION.value,
    ) is not None
    restarted = value.restart()
    performing = next(
        item for item in restarted.backend.read_task_working_set(TASK).operations
        if item.intent.operation_id == operation.intent.operation_id
    )
    assert restarted.reconcile_recovered_effect(
        TASK, performing.intent.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
    ).code is GateResultCode.EFFECT_SUCCEEDED
    recovery_audit = next(
        record.event.preimage for record in reversed(restarted.audit.snapshot())
        if record.event.preimage.gate == "RECOVERY"
    )
    assert recovery_audit.protected_effect_marker_id == value.platform.marker(
        operation.intent.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION.value,
    ).marker_id
    assert recovery_audit.operation_start_binding_id == performing.start_binding_id
    assert value.reconcile_recovered_effect(
        TASK, performing.intent.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
    ).code is GateResultCode.LEASE_INVALID


def test_post_start_target_conflict_proves_absence_releases_and_reconciles_failed():
    value = runtime()
    initialize_task(value)
    materialization = materialize(value)
    materialization = adopt_recorded_candidate(value, materialization)
    operation = reserve_protected(value, "publish-conflict", materialization.candidate_id)
    started = start_protected(value, operation,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
        ActionTargetFence(REPO, materialization.candidate_branch, None,
                          value.platform.snapshot().generation), materialization)
    value.platform.fail_next_effect_for_test()
    result = TargetPublicationGate(value.publication_gate_client).perform(started.continuation)
    assert result.code is GateResultCode.PRECONDITION_CONFLICT
    assert value.platform.read_ref(REPO, materialization.candidate_branch) is None
    assert value.platform.prepared_effect_state(
        operation.intent.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION.value,
    ) == "RELEASED"
    stored = next(
        item for item in value.backend.read_task_working_set(TASK).operations
        if item.intent.operation_id == operation.intent.operation_id
    )
    assert stored.state is OperationState.FAILED


def test_recovered_performing_with_prepared_and_no_marker_releases_and_fails():
    value = runtime()
    initialize_task(value)
    materialization = materialize(value)
    materialization = adopt_recorded_candidate(value, materialization)
    operation = reserve_protected(value, "prepared-recovery", materialization.candidate_id)
    fence = ActionTargetFence(
        REPO, materialization.candidate_branch, None,
        value.platform.snapshot().generation,
    )
    started = start_protected(
        value, operation, ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION, fence,
        materialization,
    )
    # Restart itself models process loss and discards all ephemeral authority.
    restarted = value.restart()
    assert not started.continuation.target_fence_token.active
    performing = next(
        item for item in restarted.backend.read_task_working_set(TASK).operations
        if item.intent.operation_id == operation.intent.operation_id
    )
    assert restarted.reconcile_recovered_effect(
        TASK, performing.intent.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
    ).code is GateResultCode.EFFECT_FAILED
    assert restarted.platform.prepared_effect_state(
        operation.intent.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION.value,
    ) == "RELEASED"
    canonical = restarted.backend.read_task_working_set(TASK)
    stored = next(item for item in canonical.operations if item.intent.operation_id == operation.intent.operation_id)
    assert stored.state is OperationState.FAILED


def test_contradictory_consumed_marker_postcondition_reconciles_indeterminate():
    value = runtime()
    initialize_task(value)
    materialization = materialize(value)
    materialization = adopt_recorded_candidate(value, materialization)
    operation = reserve_protected(value, "contradictory", materialization.candidate_id)
    started = start_protected(value, operation,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
        ActionTargetFence(REPO, materialization.candidate_branch, None,
                          value.platform.snapshot().generation), materialization)
    assert TargetPublicationGate(value.publication_gate_client).perform(
        started.continuation
    ).code is GateResultCode.EFFECT_SUCCEEDED
    value.platform.seed_ref(REPO, materialization.candidate_branch, GitSha("d" * 40))
    restarted = value.restart()
    performing = next(
        item for item in restarted.backend.read_task_working_set(TASK).operations
        if item.intent.operation_id == operation.intent.operation_id
    )
    assert restarted.reconcile_recovered_effect(
        TASK, performing.intent.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
    ).code is GateResultCode.INDETERMINATE
    stored = next(
        item for item in restarted.backend.read_task_working_set(TASK).operations
        if item.intent.operation_id == operation.intent.operation_id
    )
    assert stored.state is OperationState.INDETERMINATE


def test_durable_prepared_record_exists_before_canonical_start():
    value = runtime()
    initialize_task(value)
    materialization = materialize(value)
    materialization = adopt_recorded_candidate(value, materialization)
    operation = reserve_protected(value, "prepared-first", materialization.candidate_id)
    prepared = value.prepare_protected_start(
        operation, ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
        ActionTargetFence(REPO, materialization.candidate_branch, None,
                          value.platform.snapshot().generation),
        independent_lease(value), value.publication_capability,
        all_scope(), MutationScope(()), materialization=materialization,
        target_registration=registration(),
    )
    assert value.platform.prepared_effect_state(
        operation.intent.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION.value,
    ) == "PREPARED"
    assert value.platform.prepared_effect_record(
        operation.intent.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION.value,
    ) is prepared.prepared_start
    stored = next(
        item for item in value.backend.read_task_working_set(TASK).operations
        if item.intent.operation_id == operation.intent.operation_id
    )
    assert stored.state is OperationState.RESERVED


def test_failed_g6_start_releases_and_verifies_exact_prepared_record():
    value = runtime()
    initialize_task(value)
    materialization = materialize(value)
    materialization = adopt_recorded_candidate(value, materialization)
    operation = reserve_protected(value, "start-cas-failure", materialization.candidate_id)
    prepared = value.prepare_protected_start(
        operation, ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
        ActionTargetFence(REPO, materialization.candidate_branch, None,
                          value.platform.snapshot().generation),
        independent_lease(value), value.publication_capability,
        all_scope(), MutationScope(()), materialization=materialization,
        target_registration=registration(),
    )
    value.audit.fail_next_append_for_test()
    result = value.commit_protected_start(
        prepared, operation,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
    )
    assert result.code is GateResultCode.INDETERMINATE
    assert prepared.prepared_start.state is PreparedProtectedStartState.START_HELD
    assert value.platform.marker(
        operation.intent.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION.value,
    ) is None


def test_process_loss_after_performing_recovers_prepared_to_failed_without_effect():
    value = runtime()
    initialize_task(value)
    materialization = materialize(value)
    materialization = adopt_recorded_candidate(value, materialization)
    operation = reserve_protected(value, "crash-after-start", materialization.candidate_id)
    prepared = value.prepare_protected_start(
        operation, ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
        ActionTargetFence(REPO, materialization.candidate_branch, None,
                          value.platform.snapshot().generation),
        independent_lease(value), value.publication_capability,
        all_scope(), MutationScope(()), materialization=materialization,
        target_registration=registration(),
    )
    value.fail_after_start_commit_for_test()
    crashed = value.commit_protected_start(
        prepared, operation,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
    )
    assert crashed.code is GateResultCode.INDETERMINATE
    assert crashed.continuation is None
    assert prepared.prepared_start.state is PreparedProtectedStartState.START_HELD
    assert value.platform.marker(
        operation.intent.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION.value,
    ) is None
    performing = next(
        item for item in value.backend.read_task_working_set(TASK).operations
        if item.intent.operation_id == operation.intent.operation_id
    )
    assert performing.state is OperationState.PERFORMING
    restarted = value.restart()
    assert restarted.reconcile_recovered_effect(
        TASK, performing.intent.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
    ).code is GateResultCode.EFFECT_FAILED
    assert restarted.platform.prepared_effect_state(
        operation.intent.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION.value,
    ) == "RELEASED"
    failed = next(
        item for item in restarted.backend.read_task_working_set(TASK).operations
        if item.intent.operation_id == operation.intent.operation_id
    )
    assert failed.state is OperationState.FAILED


def test_public_boundary_rejects_fabricated_trusted_products_and_authority_contexts():
    value = runtime()
    fake_intent = object.__new__(OperationIntent)
    fake_evaluation = object.__new__(TaskEvaluationInput)
    fake_completion = object.__new__(CompletionAggregate)
    fake_applicability = object.__new__(CandidateApplicabilityDetermination)
    fake_evidence_request = object.__new__(SemanticEvidenceAdmissionRequest)
    with pytest.raises(TypeError):
        value.boundary.reserve_operation(TASK, fake_intent)
    with pytest.raises(TypeError):
        value.boundary.evaluate_task(fake_evaluation)
    with pytest.raises(TypeError):
        value.boundary.evaluate_task(fake_completion)
    with pytest.raises(TypeError):
        value.boundary.create_candidate_and_adopt(determination=fake_applicability)
    with pytest.raises(TypeError):
        value.boundary.admit_authorization(object(), policy=object())
    with pytest.raises(TypeError):
        value.boundary.admit_semantic_evidence(fake_evidence_request)
    assert tuple(inspect.signature(value.boundary.admit_authorization).parameters) == ("proposal",)
    candidate_source = inspect.getsource(DeterministicTrustedController.adopt_recorded_candidate)
    assert "_compose_candidate_applicability" in candidate_source
    assert "object.__new__(CandidateApplicabilityDetermination)" not in candidate_source


def test_task_evaluation_request_composes_trusted_input_inside_controller():
    value = runtime()
    initialize_task(value)
    context = completion_context(value)
    value.register_completion_evaluation_context(context)
    command = TaskEvaluationCommand(
        TASK, context.context_id, (BlockingConditionId("not-ready"),), (), None,
    )
    request = value.boundary.evaluate_task(command)
    assert request.command_kind is TrustedControlCommandKind.EVALUATE_TASK
    assert all(type(item) is not TaskEvaluationInput
               for item in request.transaction.mutations)
    assert tuple(inspect.signature(TaskEvaluationCommand).parameters) == (
        "task_id", "completion_context_id", "blocking_condition_ids",
        "awaiting_input_requirement_ids", "next_integration_operation_id",
    )


def test_evaluation_uses_all_root_managed_completion_facts_not_controller_defaults():
    positive = runtime()
    initialize_task(positive)
    complete = completion_context(
        positive, "complete-context", contract=ConditionStatus.SATISFIED,
        additional=ConditionStatus.SATISFIED, applicability=ConditionStatus.SATISFIED,
    )
    positive.register_completion_evaluation_context(complete)
    semantic_dependencies = register_zero_semantic_environment(positive)
    semantic_lease = positive.acquire_control_lease(
        positive.control_capability, semantic_dependencies,
    )
    assert ControlStateGate(positive.control_state_client).commit(
        positive.boundary.evaluate_task(TaskEvaluationCommand(
            TASK, complete.context_id, (), (), None,
        )), semantic_lease,
    ).code is GateResultCode.COMMITTED
    assert positive.backend.read_task_working_set(TASK).task.state is TaskState.COMPLETED

    for name, fields, blockers, expected_state in (
        ("contract", {"contract": ConditionStatus.UNSATISFIED,
                      "additional": ConditionStatus.SATISFIED,
                      "applicability": ConditionStatus.SATISFIED}, (), TaskState.ADMITTED),
        ("additional", {"contract": ConditionStatus.SATISFIED,
                        "additional": ConditionStatus.UNSATISFIED,
                        "applicability": ConditionStatus.SATISFIED}, (), TaskState.ADMITTED),
        ("applicability", {"contract": ConditionStatus.SATISFIED,
                            "additional": ConditionStatus.SATISFIED,
                            "applicability": ConditionStatus.UNSATISFIED},
         (BlockingConditionId("not-applicable"),), TaskState.BLOCKED),
    ):
        value = runtime()
        initialize_task(value)
        context = completion_context(value, "negative-" + name, **fields)
        value.register_completion_evaluation_context(context)
        assert ControlStateGate(value.control_state_client).commit(
            value.boundary.evaluate_task(TaskEvaluationCommand(
                TASK, context.context_id, blockers, (), None,
            )), independent_lease(value),
        ).code is GateResultCode.COMMITTED
        assert value.backend.read_task_working_set(TASK).task.state is expected_state


def test_issue29_zero_semantic_obligations_keep_readiness_neutral_but_bind_g1_facts():
    value = runtime()
    initialize_task(value)
    adopt_recorded_candidate(value, materialize(value))
    dependencies = register_zero_semantic_environment(value)
    operation = reserve_protected(
        value, "forward-operation", None,
        integration_binding=IntegrationBound(GitRef(REF.value)),
    )
    context = completion_context(
        value, "semantic-neutral-completion",
        contract=ConditionStatus.SATISFIED,
        additional=ConditionStatus.SATISFIED,
        applicability=ConditionStatus.SATISFIED,
        required=(operation.intent.operation_id,),
    )
    value.register_completion_evaluation_context(context)
    request = value.boundary.evaluate_task(TaskEvaluationCommand(
        TASK, context.context_id, (), (), operation.intent.operation_id,
    ))
    assert request.transaction.mutations[0].task.state is TaskState.INTEGRATION_READY
    assert request.required_authoritative_dependencies == dependencies.dependencies
    lease = value.acquire_control_lease(value.control_capability, dependencies)
    assert ControlStateGate(value.control_state_client).commit(request, lease).code is GateResultCode.COMMITTED
    assert value.backend.read_task_working_set(TASK).task.state is TaskState.INTEGRATION_READY


@pytest.mark.parametrize("additional_status", tuple(ConditionStatus))
def test_issue29_leaves_each_existing_additional_completion_status_unchanged(
    monkeypatch, additional_status,
):
    value = runtime()
    initialize_task(value)
    adopt_recorded_candidate(value, materialize(value))
    dependencies = register_zero_semantic_environment(value)
    context = completion_context(
        value, f"issue29-additional-{additional_status.name}",
        contract=ConditionStatus.SATISFIED,
        additional=additional_status,
        applicability=ConditionStatus.SATISFIED,
    )
    value.register_completion_evaluation_context(context)
    observed = []
    original = gates_module._compose_completion_aggregate

    def capture_additional_status(**kwargs):
        observed.append(kwargs["additional_conditions_status"])
        return original(**kwargs)

    monkeypatch.setattr(
        gates_module, "_compose_completion_aggregate", capture_additional_status,
    )
    command = TaskEvaluationCommand(TASK, context.context_id, (), (), None)
    request = value.boundary.evaluate_task(command)
    assert observed == [additional_status]
    proposed = request.transaction.mutations[0].task
    if proposed.state in (TaskState.COMPLETED, TaskState.INTEGRATION_READY):
        assert dependencies is not None
        lease = value.acquire_control_lease(
            value.control_capability, dependencies,
        )
        assert ControlStateGate(value.control_state_client).commit(request, lease).code is GateResultCode.COMMITTED


def test_issue29_readiness_rejects_non_integration_bound_next_operation_first():
    value = runtime()
    initialize_task(value)
    materialization = adopt_recorded_candidate(value, materialize(value))
    operation = reserve_protected(
        value, "not-integration-bound", materialization.candidate_id,
    )
    context = completion_context(
        value, "invalid-next-operation-context",
        contract=ConditionStatus.SATISFIED,
        additional=ConditionStatus.SATISFIED,
        applicability=ConditionStatus.SATISFIED,
        required=(operation.intent.operation_id,),
    )
    value.register_completion_evaluation_context(context)
    before = value.backend.read_task_working_set(TASK)
    occurrence = value.backend.occurrence
    with pytest.raises(_TaskSemanticDenied) as denied:
        value.boundary.evaluate_task(TaskEvaluationCommand(
            TASK, context.context_id, (), (), operation.intent.operation_id,
        ))
    assert denied.value.code is TaskSemanticDenialCode.NEXT_INTEGRATION_OPERATION_INVALID
    assert value.backend.read_task_working_set(TASK) == before
    assert value.backend.occurrence == occurrence


def test_issue29_occurrence_movement_between_current_review_and_g6_snapshot_fails_closed(monkeypatch):
    value = runtime()
    initialize_task(value)
    register_zero_semantic_environment(value)
    working = value.backend.read_task_working_set(TASK)
    occurrence = working.canonical_state_occurrence_binding
    original = gates_module.resolve_current_semantic_review

    def resolve_then_advance(*args, **kwargs):
        result = original(*args, **kwargs)
        current = value.backend.read_task_working_set(TASK)
        moved = replace(current.task, revision=current.task.revision + 1)
        advanced = value.backend.apply(CanonicalTransaction(
            current.canonical_state_occurrence_binding,
            (TaskRevisionEquals(TASK, current.task.revision),),
            (ReplaceTask(current.task.revision, moved),),
        ))
        assert advanced.status is CanonicalWriteStatus.APPLIED
        return result

    monkeypatch.setattr(gates_module, "resolve_current_semantic_review", resolve_then_advance)
    assert value._resolve_semantic_consumption(TASK, (), occurrence) is None
    assert value.backend.occurrence != occurrence


def test_issue29_g1_base_dependency_must_match_exact_context_binding():
    value = runtime()
    initialize_task(value)
    dependencies = register_zero_semantic_environment(value)
    applicability, reader, source, base = value._semantic_contexts[TASK]
    altered = replace(
        base, expected_binding_id=AuthoritativeStateBindingId("not-the-g1-binding"),
    )
    with pytest.raises(ValueError, match="exact G1 base observation"):
        value.register_semantic_consumption_context(
            TASK, applicability, reader, source, altered,
        )
    assert value._semantic_contexts[TASK] == (
        applicability, reader, source, dependencies.dependencies[0],
    )


def test_issue29_g1_and_65_semantic_dependencies_form_uncapped_exact_66_union():
    base = dependency("base")
    semantic = tuple(ControlStateAuthoritativeDependency(
        REPO, ImmutableConfigId(f"semantic-observation-{index:02d}"),
        ImmutableConfigId(f"semantic-transport-{index:02d}"),
        AuthoritativeStateBindingId(f"semantic-binding-{index:02d}"),
    ) for index in range(65))
    canonical = gates_module._canonical_semantic_dependency_union(base, semantic)
    assert canonical is not None
    assert len(canonical) == 66
    assert base in canonical
    assert all(item in canonical for item in semantic)
    # One cross-layer exact duplicate collapses, while contradictory locator
    # bindings and malformed lower-layer ordering fail closed.
    assert gates_module._canonical_semantic_dependency_union(base, (base,)) == (base,)
    contradiction = replace(
        base, expected_binding_id=AuthoritativeStateBindingId("other-binding"),
    )
    assert gates_module._canonical_semantic_dependency_union(base, (contradiction,)) is None
    assert gates_module._canonical_semantic_dependency_union(
        base, tuple(reversed(semantic[:2])),
    ) is None


def _issue29_semantic_gate_runtime(*, config_available=True):
    from tests.trusted.test_current_semantic_review import (
        _canonical_backend_with_candidate, _candidate, _current_applicability_context,
        _materialization as semantic_materialization, _semantic_config_bytes,
        _semantic_contract, _trusted_reader, REPOSITORY,
    )

    config_bytes = _semantic_config_bytes()
    contract, _, _ = _semantic_contract(config_bytes=config_bytes)
    materialization = semantic_materialization(
        CandidateId("semantic-candidate"), contract_raw=contract.contract_raw_sha256,
    )
    candidate = _candidate(materialization, contract=contract)
    backend = _canonical_backend_with_candidate(contract, candidate, materialization)
    gate_binding = GateRuntimeBinding(
        RootContextId(RawSha256("2" * 64)), FixtureRuntimeGeneration(9),
        ServicePrincipalId("control-semantic"), ServicePrincipalId("publication-semantic"),
        ServicePrincipalId("merge-semantic"),
    )
    value = FixtureProtectedGateRuntime(
        gate_binding, backend, FixtureGitPlatform(), FixtureGateAudit(),
    )
    base = ControlStateAuthoritativeDependency(
        REPOSITORY,
        ImmutableConfigId("semantic-base-observation"),
        ImmutableConfigId("semantic-base-transport"),
        AuthoritativeStateBindingId("base-current"),
    )
    value.register_semantic_consumption_context(
        candidate.task_id, _current_applicability_context(contract),
        _trusted_reader(contract, config_bytes) if config_available else None,
        None, base,
    )
    return value, backend, candidate


def test_issue29_empty_readiness_evidence_cannot_bypass_unsatisfied_contract_semantics():
    value, backend, candidate = _issue29_semantic_gate_runtime()
    command = OperationReservationCommand(
        operation_id=OperationId("semantic-forward-operation"),
        idempotency_key=OperationIdempotencyKey("semantic-forward-key"),
        action_id=OperationActionId("semantic-forward-action"),
        subject_id=OperationSubjectId("semantic-forward-subject"),
        required_evidence_ids=(),
        integration_binding=IntegrationBound(GitRef(REF.value)),
        is_repair_attempt=False,
    )
    reserve = value.boundary.reserve_operation(candidate.task_id, command)
    assert ControlStateGate(value.control_state_client).commit(reserve, independent_lease(value)).code is GateResultCode.COMMITTED
    working = backend.read_task_working_set(candidate.task_id)
    operation = next(item for item in working.operations
                     if item.intent.operation_id == command.operation_id)
    task = working.task
    context = mint(
        TrustedCompletionEvaluationContext,
        context_id=ImmutableConfigId("semantic-readiness-context"),
        task_id=task.task_id, completion_rule_set_id=CompletionRuleSetId("semantic-rule"),
        contract_id=task.contract_id, contract_raw_sha256=task.contract_raw_sha256,
        authorization_id=task.authorization_id, admission_event_id=task.admission_event_id,
        target_registration_id=task.target_registration_id,
        policy_epoch_identity=task.last_evaluated_policy_epoch_identity,
        candidate_id=task.current_candidate_id,
        contract_acceptance_status=ConditionStatus.SATISFIED,
        additional_trusted_completion_conditions_status=ConditionStatus.SATISFIED,
        required_protected_operation_ids=(operation.intent.operation_id,),
        current_applicability_and_authority_status=ConditionStatus.SATISFIED,
    )
    value.register_completion_evaluation_context(context)
    before = backend.read_task_working_set(candidate.task_id)
    occurrence = backend.occurrence
    with pytest.raises(_TaskSemanticDenied) as denied:
        value.boundary.evaluate_task(TaskEvaluationCommand(
            candidate.task_id, context.context_id, (), (), operation.intent.operation_id,
        ))
    assert denied.value.code is TaskSemanticDenialCode.SEMANTIC_CONTRACT_UNSATISFIED
    assert operation.intent.required_evidence_ids == ()
    assert backend.read_task_working_set(candidate.task_id) == before
    assert backend.occurrence == occurrence


def _issue29_nonsemantic_protected_start_fixture():
    from tests.trusted.test_current_semantic_review import resolve_current_semantic_review
    from tests.trusted.test_semantic_consumption import _append_canonical_nonsemantic_evidence

    value, materialization, target, dependency, semantic_record = (
        _issue29_semantic_publication_runtime(stale_schema=False)
    )
    task_id = semantic_record.subject.task_id
    inputs = value.backend.read_current_semantic_review_inputs(task_id)
    applicability, reader, source, _ = value._semantic_contexts[task_id]
    resolution = resolve_current_semantic_review(
        inputs, applicability_context=applicability, byte_reader=reader,
        semantic_context_source=source,
    )
    nonsemantic = _append_canonical_nonsemantic_evidence(
        value.backend, resolution, semantic_record,
    )
    return value, materialization, target, dependency, semantic_record, nonsemantic


def test_issue29_pure_nonsemantic_nonforward_start_needs_no_semantic_context():
    (value, materialization, target, _, _, nonsemantic) = (
        _issue29_nonsemantic_protected_start_fixture()
    )
    value._semantic_contexts.clear()
    operation = reserve_protected(
        value, "pure-nonsemantic-no-context", materialization.candidate_id,
        required_evidence_ids=(nonsemantic.evidence_id,),
    )
    result = start_protected(
        value, operation, ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
        ActionTargetFence(
            nonsemantic.subject.repository_id, materialization.candidate_branch,
            None, value.platform.snapshot().generation,
        ), materialization, target=target,
    )
    assert result.code is GateResultCode.START_COMMITTED
    stored = next(item for item in value.backend.read_task_working_set(
        nonsemantic.subject.task_id,
    ).operations if item.intent.operation_id == operation.intent.operation_id)
    assert stored.state is OperationState.PERFORMING
    assert stored.start_binding_id is not None


def test_issue29_pure_nonsemantic_nonforward_start_needs_no_semantic_dependencies():
    (value, materialization, target, _, _, nonsemantic) = (
        _issue29_nonsemantic_protected_start_fixture()
    )
    operation = reserve_protected(
        value, "pure-nonsemantic-no-dependencies", materialization.candidate_id,
        required_evidence_ids=(nonsemantic.evidence_id,),
    )
    result = start_protected(
        value, operation, ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
        ActionTargetFence(
            nonsemantic.subject.repository_id, materialization.candidate_branch,
            None, value.platform.snapshot().generation,
        ), materialization, target=target,
        dependencies=ControlStateAuthoritativeDependencySet(()),
    )
    assert result.code is GateResultCode.START_COMMITTED


def test_issue29_missing_required_evidence_fails_closed_before_nonsemantic_classification():
    (value, _, _, _, semantic_record, _) = (
        _issue29_nonsemantic_protected_start_fixture()
    )
    value._semantic_contexts.clear()
    missing_id = EvidenceId("missing-required-protected-evidence")
    command = OperationReservationCommand(
        operation_id=OperationId("missing-required-evidence"),
        idempotency_key=OperationIdempotencyKey("key-missing-required-evidence"),
        action_id=OperationActionId("missing-required-evidence"),
        subject_id=OperationSubjectId("missing-required-evidence"),
        required_evidence_ids=(missing_id,),
        integration_binding=NotIntegrationBound(), is_repair_attempt=False,
    )
    before = value.backend.read_task_working_set(semantic_record.subject.task_id)
    request = value.boundary.reserve_operation(semantic_record.subject.task_id, command)
    result = ControlStateGate(value.control_state_client).commit(request, independent_lease(value))
    assert result.code is GateResultCode.REJECTED
    assert value.backend.read_task_working_set(semantic_record.subject.task_id) == before
    assert all(item.intent.operation_id != command.operation_id for item in
               value.backend.read_task_working_set(semantic_record.subject.task_id).operations)


def test_issue29_mixed_protected_evidence_applies_semantics_only_to_semantic_ids(
    monkeypatch,
):
    (value, materialization, target, dependency, semantic_record, nonsemantic) = (
        _issue29_nonsemantic_protected_start_fixture()
    )
    operation = reserve_protected(
        value, "mixed-semantic-and-deterministic", materialization.candidate_id,
        required_evidence_ids=(semantic_record.evidence_id, nonsemantic.evidence_id),
    )
    calls = []
    original = gates_module.FixtureProtectedGateRuntime._resolve_semantic_consumption

    def record_projection(self, task_id, evidence_ids, expected_occurrence=None):
        if self is value:
            calls.append(evidence_ids)
        return original(self, task_id, evidence_ids, expected_occurrence)

    monkeypatch.setattr(
        gates_module.FixtureProtectedGateRuntime, "_resolve_semantic_consumption",
        record_projection,
    )
    fence = ActionTargetFence(
        semantic_record.subject.repository_id, materialization.candidate_branch,
        None, value.platform.snapshot().generation,
    )
    denied = start_protected(
        value, operation, ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
        fence, materialization, target=target,
        dependencies=ControlStateAuthoritativeDependencySet(()),
    )
    assert denied.code is GateResultCode.REJECTED
    assert denied.semantic_denial_code is (
        ProtectedStartSemanticDenialCode.REQUIRED_EVIDENCE_CONTEXT_INDETERMINATE
    )
    assert calls == [(semantic_record.evidence_id,)]
    stored = next(item for item in value.backend.read_task_working_set(
        semantic_record.subject.task_id,
    ).operations if item.intent.operation_id == operation.intent.operation_id)
    assert stored.state is OperationState.RESERVED
    assert stored.start_binding_id is None
    assert value.platform.marker(
        operation.intent.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION.value,
    ) is None

    accepted_operation = reserve_protected(
        value, "mixed-semantic-and-deterministic-with-dependencies",
        materialization.candidate_id,
        required_evidence_ids=(semantic_record.evidence_id, nonsemantic.evidence_id),
    )
    accepted = start_protected(
        value, accepted_operation, ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
        fence, materialization, target=target,
        dependencies=ControlStateAuthoritativeDependencySet((dependency,)),
    )
    assert accepted.code is GateResultCode.START_COMMITTED
    assert calls == [(semantic_record.evidence_id,), (semantic_record.evidence_id,)]
    semantic = original(
        value, semantic_record.subject.task_id, (semantic_record.evidence_id,),
        value.backend.occurrence,
    )
    assert semantic is not None
    assert tuple(item.evidence_id for item in semantic.evidence_currentness) == (
        semantic_record.evidence_id,
    )
    assert all(nonsemantic.evidence_id not in item.progression_support_evidence_ids
               for item in semantic.obligation_results)


@pytest.mark.parametrize("required_kind", ("empty", "nonsemantic"))
def test_issue29_forward_start_remains_contract_wide_with_only_nonsemantic_or_empty_evidence(
    required_kind,
):
    (value, materialization, target, dependency, semantic_record, nonsemantic) = (
        _issue29_nonsemantic_protected_start_fixture()
    )
    required_ids = () if required_kind == "empty" else (nonsemantic.evidence_id,)
    command = OperationReservationCommand(
        operation_id=OperationId(f"forward-with-{required_kind}-evidence"),
        idempotency_key=OperationIdempotencyKey(f"forward-with-{required_kind}-key"),
        action_id=OperationActionId(f"forward-with-{required_kind}-action"),
        subject_id=OperationSubjectId(f"forward-with-{required_kind}-subject"),
        required_evidence_ids=required_ids,
        integration_binding=IntegrationBound(GitRef(REF.value)),
        is_repair_attempt=False,
    )
    reservation = value.boundary.reserve_operation(semantic_record.subject.task_id, command)
    assert ControlStateGate(value.control_state_client).commit(
        reservation, independent_lease(value),
    ).code is GateResultCode.COMMITTED
    operation = next(item for item in value.backend.read_task_working_set(
        semantic_record.subject.task_id,
    ).operations if item.intent.operation_id == command.operation_id)
    working = value.backend.read_task_working_set(semantic_record.subject.task_id)
    ready_task = replace(
        working.task, state=TaskState.INTEGRATION_READY,
        next_integration_operation_id=command.operation_id,
        revision=working.task.revision + 1,
    )
    ready = value.backend.apply(CanonicalTransaction(
        working.canonical_state_occurrence_binding,
        (TaskRevisionEquals(working.task.task_id, working.task.revision),),
        (ReplaceTask(working.task.revision, ready_task),),
    ))
    assert ready.status is CanonicalWriteStatus.APPLIED

    assert value._protected_start_semantic_denial(
        operation, ProtectedEffectSubject.FAST_FORWARD_MERGE,
        value.backend.occurrence,
        ControlStateAuthoritativeDependencySet(()),
    ) is ProtectedStartSemanticDenialCode.REQUIRED_EVIDENCE_CONTEXT_INDETERMINATE
    assert value._protected_start_semantic_denial(
        operation, ProtectedEffectSubject.FAST_FORWARD_MERGE,
        value.backend.occurrence,
        ControlStateAuthoritativeDependencySet((dependency,)),
    ) is None


def test_issue29_nonready_nonnext_integration_operation_does_not_receive_forward_semantic_veto():
    value, backend, candidate = _issue29_semantic_gate_runtime()
    command = OperationReservationCommand(
        operation_id=OperationId("forward-semantic-denial"),
        idempotency_key=OperationIdempotencyKey("forward-semantic-denial-key"),
        action_id=OperationActionId("forward-semantic-denial-action"),
        subject_id=OperationSubjectId("forward-semantic-denial-subject"),
        required_evidence_ids=(),
        integration_binding=IntegrationBound(GitRef(REF.value)),
        is_repair_attempt=False,
    )
    reservation = value.boundary.reserve_operation(candidate.task_id, command)
    assert ControlStateGate(value.control_state_client).commit(
        reservation, independent_lease(value),
    ).code is GateResultCode.COMMITTED
    operation = next(item for item in backend.read_task_working_set(candidate.task_id).operations
                     if item.intent.operation_id == command.operation_id)
    base_dependency = value._semantic_contexts[candidate.task_id][3]
    denied = value._protected_start_semantic_denial(
        operation, ProtectedEffectSubject.FAST_FORWARD_MERGE,
        backend.occurrence,
        ControlStateAuthoritativeDependencySet((base_dependency,)),
    )
    # It is IntegrationBound, but neither persisted INTEGRATION_READY nor
    # exact next-operation identity holds.  G4 owns that denial; #29's
    # stronger forward-only semantic rule must not be inferred from the flag.
    assert denied is None


def test_issue29_forward_start_accepts_only_current_progression_support():
    value, _, _, dependency, record = _issue29_semantic_publication_runtime(
        stale_schema=False, verdict_name="approved",
    )
    command = OperationReservationCommand(
        operation_id=OperationId("forward-semantic-supported"),
        idempotency_key=OperationIdempotencyKey("forward-semantic-supported-key"),
        action_id=OperationActionId("forward-semantic-supported-action"),
        subject_id=OperationSubjectId("forward-semantic-supported-subject"),
        required_evidence_ids=(record.evidence_id,),
        integration_binding=IntegrationBound(GitRef(REF.value)),
        is_repair_attempt=False,
    )
    reservation = value.boundary.reserve_operation(record.subject.task_id, command)
    assert ControlStateGate(value.control_state_client).commit(
        reservation, independent_lease(value),
    ).code is GateResultCode.COMMITTED
    operation = next(item for item in value.backend.read_task_working_set(
        record.subject.task_id
    ).operations if item.intent.operation_id == command.operation_id)
    assert value._protected_start_semantic_denial(
        operation, ProtectedEffectSubject.FAST_FORWARD_MERGE,
        value.backend.occurrence,
        ControlStateAuthoritativeDependencySet((dependency,)),
    ) is None


@pytest.mark.parametrize(("extra_evaluation_ids", "config_available"), [
    ((), True), ((), False), (("second-evaluator",), True),
])
def test_issue29_readiness_is_contract_wide_and_requires_exact_progression_support(
    extra_evaluation_ids, config_available,
):
    value, _, _, dependency, record = _issue29_semantic_publication_runtime(
        stale_schema=False, config_available=config_available,
        extra_evaluation_ids=extra_evaluation_ids,
    )
    task = value.backend.read_task_working_set(record.subject.task_id).task
    command = OperationReservationCommand(
        operation_id=OperationId("semantic-readiness-operation"),
        idempotency_key=OperationIdempotencyKey("semantic-readiness-key"),
        action_id=OperationActionId("semantic-readiness-action"),
        subject_id=OperationSubjectId("semantic-readiness-subject"),
        required_evidence_ids=(record.evidence_id,),
        integration_binding=IntegrationBound(GitRef(REF.value)),
        is_repair_attempt=False,
    )
    reservation = value.boundary.reserve_operation(task.task_id, command)
    assert ControlStateGate(value.control_state_client).commit(
        reservation, independent_lease(value),
    ).code is GateResultCode.COMMITTED
    operation = next(item for item in value.backend.read_task_working_set(task.task_id).operations
                     if item.intent.operation_id == command.operation_id)
    context = mint(
        TrustedCompletionEvaluationContext,
        context_id=ImmutableConfigId("semantic-readiness-exact-context"),
        task_id=task.task_id, completion_rule_set_id=CompletionRuleSetId("semantic-readiness-rule"),
        contract_id=task.contract_id, contract_raw_sha256=task.contract_raw_sha256,
        authorization_id=task.authorization_id, admission_event_id=task.admission_event_id,
        target_registration_id=task.target_registration_id,
        policy_epoch_identity=task.last_evaluated_policy_epoch_identity,
        candidate_id=task.current_candidate_id,
        contract_acceptance_status=ConditionStatus.SATISFIED,
        additional_trusted_completion_conditions_status=ConditionStatus.SATISFIED,
        required_protected_operation_ids=(operation.intent.operation_id,),
        current_applicability_and_authority_status=ConditionStatus.SATISFIED,
    )
    value.register_completion_evaluation_context(context)
    before = value.backend.read_task_working_set(task.task_id)
    occurrence = value.backend.occurrence
    evaluation = TaskEvaluationCommand(
        task.task_id, context.context_id, (), (), operation.intent.operation_id,
    )
    if extra_evaluation_ids or not config_available:
        # The named EvidenceId satisfies the first obligation, but the second
        # mandatory evaluator has no history.  G5 contract status must win over
        # any favorable subset supplied by the operation.
        with pytest.raises(_TaskSemanticDenied) as denied:
            value.boundary.evaluate_task(evaluation)
        expected = (TaskSemanticDenialCode.SEMANTIC_CONTRACT_UNSATISFIED
                    if extra_evaluation_ids
                    else TaskSemanticDenialCode.SEMANTIC_CONTEXT_INDETERMINATE)
        assert denied.value.code is expected
        assert value.backend.read_task_working_set(task.task_id) == before
        assert value.backend.occurrence == occurrence
    else:
        request = value.boundary.evaluate_task(evaluation)
        assert request.transaction.mutations[0].task.state is TaskState.INTEGRATION_READY
        assert request.required_authoritative_dependencies == (dependency,)
        lease = value.acquire_control_lease(
            value.control_capability,
            ControlStateAuthoritativeDependencySet((dependency,)),
        )
        assert ControlStateGate(value.control_state_client).commit(request, lease).code is GateResultCode.COMMITTED
        assert value.backend.read_task_working_set(task.task_id).task.state is TaskState.INTEGRATION_READY
        assert value.backend.read_task_working_set(task.task_id).task.next_integration_operation_id == operation.intent.operation_id
        assert value._protected_start_semantic_denial(
            operation, ProtectedEffectSubject.FAST_FORWARD_MERGE,
            value.backend.occurrence,
            ControlStateAuthoritativeDependencySet((dependency,)),
        ) is None


def test_issue29_readiness_rejects_stale_superseded_required_evidence():
    from tests.trusted.test_current_semantic_review import resolve_current_semantic_review
    from tests.trusted.test_semantic_consumption import _append_superseding_approved_evidence

    value, _, _, _, earlier = _issue29_semantic_publication_runtime(
        stale_schema=False,
    )
    task_id = earlier.subject.task_id
    current_inputs = value.backend.read_current_semantic_review_inputs(task_id)
    applicability, reader, context_source, _ = value._semantic_contexts[task_id]
    current_resolution = resolve_current_semantic_review(
        current_inputs, applicability_context=applicability, byte_reader=reader,
        semantic_context_source=context_source,
    )
    effective_subject = current_resolution.obligation_outcomes[0].effective_subject
    later = _append_superseding_approved_evidence(
        value.backend, current_resolution, earlier, effective_subject,
    )
    command = OperationReservationCommand(
        operation_id=OperationId("readiness-with-superseded-evidence"),
        idempotency_key=OperationIdempotencyKey("readiness-superseded-key"),
        action_id=OperationActionId("readiness-superseded-action"),
        subject_id=OperationSubjectId("readiness-superseded-subject"),
        required_evidence_ids=(earlier.evidence_id,),
        integration_binding=IntegrationBound(GitRef(REF.value)),
        is_repair_attempt=False,
    )
    reservation = value.boundary.reserve_operation(task_id, command)
    assert ControlStateGate(value.control_state_client).commit(
        reservation, independent_lease(value),
    ).code is GateResultCode.COMMITTED
    task = value.backend.read_task_working_set(task_id).task
    context = mint(
        TrustedCompletionEvaluationContext,
        context_id=ImmutableConfigId("superseded-readiness-context"),
        task_id=task.task_id, completion_rule_set_id=CompletionRuleSetId("superseded-readiness-rule"),
        contract_id=task.contract_id, contract_raw_sha256=task.contract_raw_sha256,
        authorization_id=task.authorization_id, admission_event_id=task.admission_event_id,
        target_registration_id=task.target_registration_id,
        policy_epoch_identity=task.last_evaluated_policy_epoch_identity,
        candidate_id=task.current_candidate_id,
        contract_acceptance_status=ConditionStatus.SATISFIED,
        additional_trusted_completion_conditions_status=ConditionStatus.SATISFIED,
        required_protected_operation_ids=(command.operation_id,),
        current_applicability_and_authority_status=ConditionStatus.SATISFIED,
    )
    value.register_completion_evaluation_context(context)
    before = value.backend.read_task_working_set(task_id)
    occurrence = value.backend.occurrence
    with pytest.raises(_TaskSemanticDenied) as denied:
        value.boundary.evaluate_task(TaskEvaluationCommand(
            task_id, context.context_id, (), (), command.operation_id,
        ))
    assert denied.value.code is TaskSemanticDenialCode.REQUIRED_SEMANTIC_EVIDENCE_NOT_CURRENT
    assert later.evidence_id != earlier.evidence_id
    assert value.backend.read_task_working_set(task_id) == before
    assert value.backend.occurrence == occurrence


@pytest.mark.parametrize(("config_available", "expected_code"), [
    (True, TaskSemanticDenialCode.SEMANTIC_CONTRACT_UNSATISFIED),
    (False, TaskSemanticDenialCode.SEMANTIC_CONTEXT_INDETERMINATE),
])
def test_issue29_semantic_completion_veto_preserves_g4_success_and_state(
    config_available, expected_code,
):
    value, backend, candidate = _issue29_semantic_gate_runtime(
        config_available=config_available,
    )
    task = backend.read_task_working_set(candidate.task_id).task
    context = mint(
        TrustedCompletionEvaluationContext,
        context_id=ImmutableConfigId("semantic-completion-context"),
        task_id=task.task_id, completion_rule_set_id=CompletionRuleSetId("semantic-completion-rule"),
        contract_id=task.contract_id, contract_raw_sha256=task.contract_raw_sha256,
        authorization_id=task.authorization_id, admission_event_id=task.admission_event_id,
        target_registration_id=task.target_registration_id,
        policy_epoch_identity=task.last_evaluated_policy_epoch_identity,
        candidate_id=task.current_candidate_id,
        contract_acceptance_status=ConditionStatus.SATISFIED,
        additional_trusted_completion_conditions_status=ConditionStatus.SATISFIED,
        required_protected_operation_ids=(),
        current_applicability_and_authority_status=ConditionStatus.SATISFIED,
    )
    value.register_completion_evaluation_context(context)
    command = TaskEvaluationCommand(candidate.task_id, context.context_id, (), (), None)
    g4_request = value.controller.evaluate_task(command)
    assert g4_request.transaction.mutations[0].task.state is TaskState.COMPLETED
    before = backend.read_task_working_set(candidate.task_id)
    occurrence = backend.occurrence
    with pytest.raises(_TaskSemanticDenied) as denied:
        value.boundary.evaluate_task(command)
    assert denied.value.code is expected_code
    assert backend.read_task_working_set(candidate.task_id) == before
    assert backend.occurrence == occurrence


def test_issue29_preserves_g4_completion_inconsistency_before_semantic_veto(monkeypatch):
    value, backend, candidate = _issue29_semantic_gate_runtime()
    task = backend.read_task_working_set(candidate.task_id).task
    context = mint(
        TrustedCompletionEvaluationContext,
        context_id=ImmutableConfigId("semantic-g4-inconsistency-context"),
        task_id=task.task_id,
        completion_rule_set_id=CompletionRuleSetId("semantic-g4-inconsistency-rule"),
        contract_id=task.contract_id,
        contract_raw_sha256=task.contract_raw_sha256,
        authorization_id=task.authorization_id,
        admission_event_id=task.admission_event_id,
        target_registration_id=task.target_registration_id,
        policy_epoch_identity=task.last_evaluated_policy_epoch_identity,
        candidate_id=task.current_candidate_id,
        contract_acceptance_status=ConditionStatus.SATISFIED,
        additional_trusted_completion_conditions_status=ConditionStatus.SATISFIED,
        required_protected_operation_ids=(),
        current_applicability_and_authority_status=ConditionStatus.SATISFIED,
    )
    value.register_completion_evaluation_context(context)
    monkeypatch.setattr(
        gates_module.FixtureProtectedGateRuntime, "_resolve_semantic_consumption",
        lambda *_: pytest.fail("G4 completion inconsistency must precede semantic policy"),
    )
    with pytest.raises(ValueError, match="INCONSISTENT_TASK_EVALUATION"):
        value.boundary.evaluate_task(TaskEvaluationCommand(
            task.task_id, context.context_id,
            (BlockingConditionId("completion-blocker"),), (), None,
        ))
    assert backend.read_task_working_set(task.task_id).task == task


def test_issue29_ordinary_g4_proposal_does_not_resolve_semantics(monkeypatch):
    value, backend, candidate = _issue29_semantic_gate_runtime()
    task = backend.read_task_working_set(candidate.task_id).task
    context = mint(
        TrustedCompletionEvaluationContext,
        context_id=ImmutableConfigId("semantic-ordinary-state-context"),
        task_id=task.task_id,
        completion_rule_set_id=CompletionRuleSetId("semantic-ordinary-state-rule"),
        contract_id=task.contract_id,
        contract_raw_sha256=task.contract_raw_sha256,
        authorization_id=task.authorization_id,
        admission_event_id=task.admission_event_id,
        target_registration_id=task.target_registration_id,
        policy_epoch_identity=task.last_evaluated_policy_epoch_identity,
        candidate_id=task.current_candidate_id,
        contract_acceptance_status=ConditionStatus.UNSATISFIED,
        additional_trusted_completion_conditions_status=ConditionStatus.SATISFIED,
        required_protected_operation_ids=(),
        current_applicability_and_authority_status=ConditionStatus.SATISFIED,
    )
    value.register_completion_evaluation_context(context)
    monkeypatch.setattr(
        gates_module.FixtureProtectedGateRuntime, "_resolve_semantic_consumption",
        lambda *_: pytest.fail("ordinary G4 state proposals have no #29 semantic policy"),
    )
    request = value.boundary.evaluate_task(TaskEvaluationCommand(
        task.task_id, context.context_id,
        (BlockingConditionId("semantic-ordinary-blocker"),), (), None,
    ))
    assert request.transaction.mutations[0].task.state is TaskState.BLOCKED
    assert backend.read_task_working_set(task.task_id).task == task


def test_evaluation_fails_closed_when_completion_context_is_missing_or_mismatched():
    value = runtime()
    initialize_task(value)
    missing = TaskEvaluationCommand(
        TASK, ImmutableConfigId("missing-completion-context"), (), (), None,
    )
    with pytest.raises(ValueError, match="completion context is unavailable"):
        value.boundary.evaluate_task(missing)
    context = completion_context(value, "wrong-task-context")
    object.__setattr__(context, "task_id", TaskId("different-task"))
    value.register_completion_evaluation_context(context)
    with pytest.raises(ValueError, match="completion context does not match canonical task"):
        value.boundary.evaluate_task(TaskEvaluationCommand(
            TASK, context.context_id, (), (), None,
        ))


def test_audit_binds_exact_dependency_members_and_runtime_binding():
    value = runtime()
    assert value.backend.apply(CanonicalTransaction(
        value.backend.occurrence, (), (CreateContract(CONTRACT_RECORD), CreateAuthorization(authorization()))
    )).status is CanonicalWriteStatus.APPLIED
    request = value.boundary.create_task(
        task_id=TASK, contract_id=CONTRACT, contract_raw_sha256=RAW,
        authorization_id=AUTH, admission_event_id=ADMISSION,
        target_registration_id=TARGET, policy_epoch_identity=EPOCH,
        repair_budget=RepairBudget(1),
    )
    profile, transport, snapshot = fixture_source()
    value.register_fixture_authoritative_source(profile, transport, snapshot)
    item = ControlStateAuthoritativeDependency(
        REPO, profile.profile_id, transport.config_id,
        authoritative_state_binding(snapshot),
    )
    dependencies = ControlStateAuthoritativeDependencySet((item,))
    lease = value.acquire_control_lease(value.control_capability, dependencies)
    assert value.commit(request, lease).code is GateResultCode.COMMITTED
    events = tuple(record.event.preimage for record in value.audit.snapshot())
    event = next(item for item in reversed(events) if item.authoritative_dependencies)
    assert event.runtime_binding_id == value.binding.runtime_binding_id
    assert event.authoritative_dependencies == (
        GateAuditAuthoritativeDependency(
            item.repository_id, item.observation_profile_id,
            item.transport_config_id, item.expected_binding_id,
        ),
    )
    assert event.canonical_state_occurrence_binding is not None


def test_restart_same_generation_rotates_runtime_identity_in_audit():
    value = runtime()
    initialize_task(value)
    old_id = value.binding.runtime_binding_id
    restarted = value.restart()
    assert restarted.binding.runtime_generation == value.binding.runtime_generation
    assert restarted.binding.runtime_binding_id != old_id
    request = restarted.boundary.set_cancellation(
        TASK, CancellationStatus.REQUESTED, CancellationRequestId("restart-request")
    )
    assert restarted.commit(
        request, independent_lease(restarted)
    ).code is GateResultCode.COMMITTED
    first_restart_id = restarted.binding.runtime_binding_id
    restarted_again = restarted.restart()
    request = restarted_again.boundary.set_cancellation(
        TASK, CancellationStatus.NONE, None
    )
    assert restarted_again.commit(
        request, independent_lease(restarted_again)
    ).code is GateResultCode.COMMITTED
    audit_ids = {record.event.preimage.runtime_binding_id
                 for record in restarted_again.audit.snapshot()}
    assert {
        old_id, first_restart_id, restarted_again.binding.runtime_binding_id,
    } <= audit_ids
    assert len({old_id, first_restart_id,
                restarted_again.binding.runtime_binding_id}) == 3


def test_admin_runtime_replacement_requires_strictly_higher_generation():
    value = runtime()
    with pytest.raises(RuntimeError):
        FixtureProtectedGateRuntime(
            GateRuntimeBinding(
                value.binding.root_context_id, FixtureRuntimeGeneration(1),
                value.binding.control_state_principal,
                value.binding.publication_principal,
                value.binding.merge_principal,
            ), value.backend, value.platform, value.audit, value.registry,
        )
    replacement = FixtureProtectedGateRuntime(
        GateRuntimeBinding(
            value.binding.root_context_id, FixtureRuntimeGeneration(2),
            value.binding.control_state_principal,
            value.binding.publication_principal,
            value.binding.merge_principal,
        ), value.backend, value.platform, value.audit, value.registry,
    )
    assert replacement._is_active()
    assert not value._is_active()
    assert value.acquire_control_lease(
        value.control_capability, ControlStateAuthoritativeDependencySet(()),
        value.attest_external_state_independence(),
    ) is None
    for generation in (1, 2):
        with pytest.raises(RuntimeError):
            FixtureProtectedGateRuntime(
                GateRuntimeBinding(
                    value.binding.root_context_id,
                    FixtureRuntimeGeneration(generation),
                    value.binding.control_state_principal,
                    value.binding.publication_principal,
                    value.binding.merge_principal,
                ), value.backend, value.platform, value.audit, value.registry,
            )


def test_effect_action_package_is_frozen_before_performing():
    value = runtime()
    initialize_task(value)
    materialization = materialize(value)
    materialization = adopt_recorded_candidate(value, materialization)
    operation = reserve_protected(value, "frozen-effect", materialization.candidate_id)
    started = start_protected(
        value, operation, ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
        ActionTargetFence(REPO, materialization.candidate_branch, None,
                          value.platform.snapshot().generation),
        materialization,
    )
    with pytest.raises(TypeError):
        TargetPublicationGate(value.publication_gate_client).perform(
            started.continuation, materialization=object()
        )
    assert TargetPublicationGate(value.publication_gate_client).perform(
        started.continuation
    ).code is GateResultCode.EFFECT_SUCCEEDED


def recovered_prepared_operation(value, name, dependencies=None):
    initialize_task(value)
    materialization = materialize(value)
    materialization = adopt_recorded_candidate(value, materialization)
    operation = reserve_protected(value, name, materialization.candidate_id)
    started = start_protected(
        value, operation, ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
        ActionTargetFence(REPO, materialization.candidate_branch, None,
                          value.platform.snapshot().generation),
        materialization, dependencies=dependencies,
    )
    assert started.code is GateResultCode.START_COMMITTED
    restarted = value.restart()
    performing = next(
        item for item in restarted.backend.read_task_working_set(TASK).operations
        if item.intent.operation_id == operation.intent.operation_id
    )
    return restarted, performing


def test_public_recovery_api_cannot_accept_dependencies_or_independence():
    value = runtime()
    signature = inspect.signature(value.boundary.reconcile_operation)
    assert "dependencies" not in signature.parameters
    assert "independence" not in signature.parameters
    with pytest.raises(TypeError):
        value.boundary.reconcile_operation(
            TASK, OperationId("operation"),
            ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
            dependencies=ControlStateAuthoritativeDependencySet(()),
        )
    with pytest.raises(TypeError):
        value.boundary.reconcile_operation(
            TASK, OperationId("operation"),
            ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
            independence=value.attest_external_state_independence(),
        )
    with pytest.raises(TypeError):
        value.reconcile_recovered_effect(
            TASK, OperationId("operation"),
            ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
            ControlStateAuthoritativeDependencySet(()),
        )


def test_nonempty_frozen_dependencies_cannot_be_replaced_by_empty_or_d2():
    value = runtime()
    d1 = install_fixture_dependencies(value, "d1")
    d2 = install_fixture_dependencies(value, "d2")
    restarted, performing = recovered_prepared_operation(value, "frozen-d1", d1)
    with pytest.raises(TypeError):
        restarted.reconcile_recovered_effect(
            TASK, performing.intent.operation_id,
            ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
            dependencies=ControlStateAuthoritativeDependencySet(()),
            independence=restarted.attest_external_state_independence(),
        )
    with pytest.raises(TypeError):
        restarted.reconcile_recovered_effect(
            TASK, performing.intent.operation_id,
            ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
            dependencies=d2,
        )
    frozen = d1.dependencies[0]
    restarted.platform.replace_authoritative_snapshot(AuthoritativeStateSnapshot(
        frozen.repository_id, frozen.observation_profile_id,
        frozen.transport_config_id,
        (NormalizedGitHubObservation(
            "repository", (REPO.value, "moved", "r"),
        ),),
    ))
    assert restarted.reconcile_recovered_effect(
        TASK, performing.intent.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
    ).code is GateResultCode.INDETERMINATE


def test_recovery_reuses_exact_frozen_dependencies_and_audits_them():
    value = runtime()
    dependencies = install_fixture_dependencies(value, "a", "b")
    restarted, performing = recovered_prepared_operation(
        value, "exact-recovery-dependencies", dependencies
    )
    durable = restarted.platform.prepared_effect_record(
        performing.intent.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION.value,
    )
    assert durable.preimage.dependencies == dependencies
    result = restarted.reconcile_recovered_effect(
        TASK, performing.intent.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
    )
    assert result.code is GateResultCode.EFFECT_FAILED
    recovery = next(
        record.event.preimage for record in reversed(restarted.audit.snapshot())
        if record.event.preimage.gate == "RECOVERY"
    )
    assert recovery.authoritative_dependencies == tuple(
        GateAuditAuthoritativeDependency(
            item.repository_id, item.observation_profile_id,
            item.transport_config_id, item.expected_binding_id,
        )
        for item in durable.preimage.dependencies.dependencies
    )
    assert recovery.runtime_binding_id == restarted.binding.runtime_binding_id
    assert recovery.canonical_state_occurrence_binding is not None
    assert recovery.operation_id == performing.intent.operation_id
    assert recovery.operation_start_binding_id == performing.start_binding_id
    assert recovery.protected_effect_marker_id is None


def test_empty_recovery_dependencies_are_derived_only_from_frozen_start():
    value = runtime()
    restarted, performing = recovered_prepared_operation(
        value, "empty-frozen-recovery"
    )
    assert restarted.reconcile_recovered_effect(
        TASK, performing.intent.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
    ).code is GateResultCode.EFFECT_FAILED
    recovery = next(
        record.event.preimage for record in reversed(restarted.audit.snapshot())
        if record.event.preimage.gate == "RECOVERY"
    )
    assert recovery.authoritative_dependencies == ()


def test_missing_or_mismatched_durable_start_fails_recovery_closed():
    value = runtime()
    restarted, performing = recovered_prepared_operation(
        value, "missing-durable-start"
    )
    key = (
        performing.intent.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION.value,
    )
    with restarted.platform._lock:
        restarted.platform._prepared[key] = (None, "PREPARED", None)
    assert restarted.reconcile_recovered_effect(
        TASK, performing.intent.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
    ).code is GateResultCode.INDETERMINATE


def test_prepared_start_dependency_identity_contradiction_fails_closed():
    value = runtime()
    d1 = install_fixture_dependencies(value, "original")
    d2 = install_fixture_dependencies(value, "altered")
    restarted, performing = recovered_prepared_operation(
        value, "dependency-identity-contradiction", d1
    )
    durable = restarted.platform.prepared_effect_record(
        performing.intent.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION.value,
    )
    object.__setattr__(durable.preimage, "dependencies", d2)
    assert restarted.reconcile_recovered_effect(
        TASK, performing.intent.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
    ).code is GateResultCode.INDETERMINATE


def test_recovery_fence_blocks_prepared_state_race():
    value = runtime()
    restarted, performing = recovered_prepared_operation(
        value, "recovery-state-race"
    )
    completed = threading.Event()
    conflicts = []

    def race_release():
        try:
            restarted.platform.release_prepared_effect(
                performing.intent.operation_id,
                ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION.value,
            )
        except FixtureFenceConflict as error:
            conflicts.append(error)
        finally:
            completed.set()

    def hook():
        thread = threading.Thread(target=race_release)
        thread.start()
        assert completed.wait(1)
        thread.join()

    restarted.set_recovery_fence_hook_for_test(hook)
    assert restarted.reconcile_recovered_effect(
        TASK, performing.intent.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
    ).code is GateResultCode.EFFECT_FAILED
    assert len(conflicts) == 1
