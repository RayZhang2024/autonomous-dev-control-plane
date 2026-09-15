import pickle
import inspect
import threading
import hashlib
from dataclasses import FrozenInstanceError

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
    CanonicalWriteStatus, CreateAuthorization, CreateContract,
    InMemoryCanonicalStateBackend, ResolvedTargetRegistration,
    canonical_json_bytes,
)
from autodev_control.trusted.fixture_platform import (
    FixtureFenceConflict, FixtureGitPlatform,
    ProtectedEffectMarkerPreimage,
    PublishedCandidateRefEffectSubject, build_protected_effect_marker,
)
from autodev_control.trusted.gates import *
from autodev_control.trusted.identity import (
    CandidateMaterializationId, GitRef, GitSha, ImmutableConfigId,
    LogicalIdentifier, MutationInventoryId, PreparedProtectedStartId,
    RawSha256, RootContextId,
)
from autodev_control.trusted.operation import (
    AdmissionEventId, AuthoritativeStateBindingId, CandidateId,
    CompletionRuleSetId, IntegrationBound, NotIntegrationBound, OperationActionId, OperationEffectClass, OperationId,
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
    result = ControlStateGate(value).commit(request, independent_lease(value))
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
    assert ControlStateGate(value).commit(record, independent_lease(value)).code is GateResultCode.COMMITTED
    after_record = value.backend.read_task_working_set(TASK).task
    assert after_record == before
    candidate = value.backend.read_candidate(CandidateId("candidate"))
    assert candidate is not None
    assert value.backend.read_candidate_materialization(candidate.materialization_id) is not None
    adopt = value.boundary.adopt_recorded_candidate(
        task_id=TASK, candidate_id=candidate.candidate_id,
        decision_event_id=DecisionEventId("candidate-applicability"),
    )
    assert ControlStateGate(value).commit(adopt, independent_lease(value)).code is GateResultCode.COMMITTED
    assert value.backend.read_task_working_set(TASK).task.current_candidate_id == candidate.candidate_id


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
    assert ControlStateGate(value).commit(request, wrong_lease).code is GateResultCode.LEASE_INVALID
    lease = value.acquire_control_lease(value.control_capability, dependencies)
    result = ControlStateGate(value).commit(request, lease)
    assert result.code is GateResultCode.COMMITTED
    assert value.backend.read_contract(CONTRACT) == CONTRACT_RECORD
    replay = value.boundary.admit_contract(CONTRACT_RECORD.raw_bytes)
    replay_lease = value.acquire_control_lease(value.control_capability, dependencies)
    assert ControlStateGate(value).commit(replay, replay_lease).code is GateResultCode.COMMITTED


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
    assert ControlStateGate(value).commit(
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
    assert ControlStateGate(value).commit(
        request, independent_lease(value)
    ).code is GateResultCode.COMMITTED
    return admitted


def reserve_protected(value, name, candidate_id, *, integration_binding=None):
    command = OperationReservationCommand(
        operation_id=OperationId(name),
        idempotency_key=OperationIdempotencyKey("key-" + name),
        action_id=OperationActionId(name), subject_id=OperationSubjectId(name),
        required_evidence_ids=(),
        integration_binding=(
            NotIntegrationBound() if integration_binding is None else integration_binding
        ),
        is_repair_attempt=False,
    )
    request = value.boundary.reserve_operation(TASK, command)
    assert ControlStateGate(value).commit(
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
    assert state.value in {"PREPARED", "CONSUMED", "RELEASED"}


@pytest.mark.parametrize("kind", list(TrustedControlCommandKind))
def test_closed_control_command_domain(kind):
    assert type(kind) is TrustedControlCommandKind


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
    assert ControlStateGate(value).commit(
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
    assert ControlStateGate(value).commit(request, lease).code is GateResultCode.COMMITTED
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
    assert ControlStateGate(value).commit(request, lease).code is GateResultCode.COMMITTED
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
    assert started.continuation.start_binding_id.raw_sha256 == started.continuation.prepared_start_id.raw_sha256
    published = TargetPublicationGate(value).perform(started.continuation)
    assert published.code is GateResultCode.EFFECT_SUCCEEDED
    assert value.platform.read_ref(REPO, materialization.candidate_branch) == materialization.commit
    assert TargetPublicationGate(value).perform(
        started.continuation
    ).code is GateResultCode.LEASE_CONSUMED


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
    assert TargetPublicationGate(value).perform(
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
    assert TargetPublicationGate(value).perform(
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
    assert ControlStateGate(value).commit(
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
    ) == "PREPARED"


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
    ) == "PREPARED"


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
    assert TargetPublicationGate(value).perform(
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
    assert TargetPublicationGate(value).perform(
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
    assert MergeGate(value).perform(
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
    assert TargetPublicationGate(value).perform(
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
    assert TargetPublicationGate(value).perform(
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
    assert TargetPublicationGate(value).perform(
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
    result = TargetPublicationGate(value).perform(started.continuation)
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
    result = TargetPublicationGate(value).perform(started.continuation)
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
    assert TargetPublicationGate(value).perform(
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
    assert result.code is GateResultCode.AUDIT_FAILURE_BEFORE_COMMIT
    assert prepared.prepared_start.state is PreparedProtectedStartState.RELEASED


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
    assert prepared.prepared_start.state is PreparedProtectedStartState.PREPARED
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
    assert ControlStateGate(positive).commit(
        positive.boundary.evaluate_task(TaskEvaluationCommand(
            TASK, complete.context_id, (), (), None,
        )), independent_lease(positive),
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
        assert ControlStateGate(value).commit(
            value.boundary.evaluate_task(TaskEvaluationCommand(
                TASK, context.context_id, blockers, (), None,
            )), independent_lease(value),
        ).code is GateResultCode.COMMITTED
        assert value.backend.read_task_working_set(TASK).task.state is expected_state


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
        TargetPublicationGate(value).perform(
            started.continuation, materialization=object()
        )
    assert TargetPublicationGate(value).perform(
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
        restarted.boundary.reconcile_operation(
            TASK, performing.intent.operation_id,
            ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
            dependencies=ControlStateAuthoritativeDependencySet(()),
            independence=restarted.attest_external_state_independence(),
        )
    with pytest.raises(TypeError):
        restarted.boundary.reconcile_operation(
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
    assert restarted.boundary.reconcile_operation(
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
    result = restarted.boundary.reconcile_operation(
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
    assert restarted.boundary.reconcile_operation(
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
        restarted.platform._prepared[key] = (None, "PREPARED")
    assert restarted.boundary.reconcile_operation(
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
    assert restarted.boundary.reconcile_operation(
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
    assert restarted.boundary.reconcile_operation(
        TASK, performing.intent.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
    ).code is GateResultCode.EFFECT_FAILED
    assert len(conflicts) == 1
