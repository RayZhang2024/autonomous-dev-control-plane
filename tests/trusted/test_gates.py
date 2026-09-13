import pickle
from dataclasses import FrozenInstanceError

import pytest

from autodev_control.trusted.audit import FixtureGateAudit, GateAuditOutcome
from autodev_control.trusted.backend import InMemoryCanonicalStateBackend
from autodev_control.trusted.fixture_platform import FixtureGitPlatform, ProtectedEffectMarker
from autodev_control.trusted.gates import *
from autodev_control.trusted.identity import GitSha, ImmutableConfigId, LogicalIdentifier, RootContextId
from autodev_control.trusted.operation import AuthoritativeStateBindingId, OperationId
from autodev_control.trusted.scope import CanonicalBranchRef, GitHubRepositoryId, ServicePrincipalId
from autodev_control.trusted.state_reader import (
    AuthenticatedGitHubReadTransport, AuthoritativeObservationProfile, GitHubStateReader,
    ReadRepositoryIdentity, RegisteredStateFactDescriptor, TrustedGitHubReadTransportBinding,
)


REPO = GitHubRepositoryId("1")
REF = CanonicalBranchRef("refs/heads/main")
SHA = GitSha("a" * 40)


def runtime():
    binding = GateRuntimeBinding(
        RootContextId("root"), FixtureRuntimeGeneration(1),
        ServicePrincipalId("control"), ServicePrincipalId("publication"), ServicePrincipalId("merge"),
    )
    return FixtureProtectedGateRuntime(binding, InMemoryCanonicalStateBackend(), FixtureGitPlatform(), FixtureGateAudit())


def dependency(binding="binding"):
    return ControlStateAuthoritativeDependency(
        REPO, ImmutableConfigId("observation"), ImmutableConfigId("transport"),
        AuthoritativeStateBindingId(binding),
    )


def source():
    transport_binding = object.__new__(TrustedGitHubReadTransportBinding)
    fields = dict(config_id=ImmutableConfigId("transport"), expected_api_host_identity=ImmutableConfigId("host"),
                  authentication_mode_identity=ImmutableConfigId("auth"), service_identity=ServicePrincipalId("reader"),
                  permitted_repository_ids=(REPO,), transport_profile_id=ImmutableConfigId("read"))
    for name, value in fields.items():
        object.__setattr__(transport_binding, name, value)
    request = ReadRepositoryIdentity(REPO)
    descriptor = object.__new__(RegisteredStateFactDescriptor)
    object.__setattr__(descriptor, "descriptor_id", LogicalIdentifier("repository"))
    object.__setattr__(descriptor, "request", request)
    profile = object.__new__(AuthoritativeObservationProfile)
    object.__setattr__(profile, "profile_id", ImmutableConfigId("observation"))
    object.__setattr__(profile, "registered_fact_descriptors", (descriptor,))
    transport = object.__new__(AuthenticatedGitHubReadTransport)
    object.__setattr__(transport, "_binding", transport_binding)
    object.__setattr__(transport, "_executor", lambda request, cursor: {"repository_id": REPO.value, "owner": "o", "name": "r"})
    reader = GitHubStateReader(transport_binding, transport)
    return profile, reader


def marker(operation="one", result="result"):
    return ProtectedEffectMarker(
        operation, "key", "action", "a" * 64, "b" * 64, "c" * 64,
        "d" * 64, "root", 1, "publication", "publication", REPO,
        "ABSENT", result, result,
    )


def test_gate_principals_must_be_pairwise_distinct():
    with pytest.raises(ValueError):
        GateRuntimeBinding(RootContextId("r"), FixtureRuntimeGeneration(1),
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
    profile, reader = source()
    expected = reader.read_authoritative(REPO, profile).binding_id
    item = ControlStateAuthoritativeDependency(REPO, profile.profile_id, reader._binding.config_id, expected)
    value.register_authoritative_source(profile, reader)
    assert type(value.acquire_control_lease(value.control_capability, ControlStateAuthoritativeDependencySet((item,)))) is ControlStateCommitLease


def test_wrong_capability_denies_control_lease():
    value = runtime()
    profile, reader = source()
    expected = reader.read_authoritative(REPO, profile).binding_id
    item = ControlStateAuthoritativeDependency(REPO, profile.profile_id, reader._binding.config_id, expected)
    value.register_authoritative_source(profile, reader)
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
    assert platform.marker("two", "publication") is None


def test_effect_marker_cannot_change_result():
    platform = FixtureGitPlatform()
    platform.record_marker(marker())
    with pytest.raises(ValueError):
        platform.record_marker(marker(result="different"))


def test_prepared_effect_cannot_return_from_consumed():
    platform = FixtureGitPlatform()
    platform.prepare_effect("one", "publication")
    platform.record_marker(marker())
    with pytest.raises(ValueError):
        platform.prepare_effect("one", "publication")


def test_restart_preserves_fixture_authority_but_rotates_capabilities():
    value = runtime()
    value.platform.seed_ref(REPO, REF, SHA)
    restarted = value.restart()
    assert restarted.platform.read_ref(REPO, REF) == SHA
    assert restarted.control_capability is not value.control_capability
    assert restarted.binding.runtime_generation.value == 1


def test_audit_is_append_only_snapshot():
    audit = FixtureGateAudit()
    assert audit.append("gate", "op", GateAuditOutcome.ATTEMPTED)
    snapshot = audit.snapshot()
    assert snapshot[0].sequence == 1
    with pytest.raises(FrozenInstanceError):
        snapshot[0].detail = "changed"


def test_injected_audit_failure_does_not_append_record():
    audit = FixtureGateAudit()
    audit.fail_next_append_for_test()
    assert not audit.append("gate", "op", GateAuditOutcome.ATTEMPTED)
    assert audit.snapshot() == ()


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
    one = ActionTargetFence(REPO, REF, SHA, 1)
    two = ActionTargetFence(REPO, REF, SHA, 2)
    assert operation_start_binding_id(OperationId("op"), one, ProtectedEffectSubject.FAST_FORWARD_MERGE) != operation_start_binding_id(OperationId("op"), two, ProtectedEffectSubject.FAST_FORWARD_MERGE)
