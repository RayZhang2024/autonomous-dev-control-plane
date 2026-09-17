"""Focused B1 current-context regressions through the real G6 reader boundary."""
from __future__ import annotations

import pytest
from decimal import Decimal

from autodev_control.trusted.backend import ResolvedTargetRegistration
from autodev_control.trusted.contract import contract_json_value_digest
from autodev_control.trusted.identity import CandidateMaterializationId, GitRef, GitSha, ImmutableConfigId, LogicalIdentifier, RawSha256
from autodev_control.trusted.manifest import PolicyEpochIdentity, TrustedManifestId
from autodev_control.trusted.materialization import AdmittedCandidateMaterialization
from autodev_control.trusted.scope import CanonicalBranchRef, ContractId, GitHubRepositoryId, TargetRegistrationId
from autodev_control.trusted.semantic_context import *
from autodev_control.trusted import semantic_context as contexts
from autodev_control.trusted.state_reader import *
from autodev_control.trusted.target_registration import AdmittedTargetRegistration, MergeConfiguration


REPO = GitHubRepositoryId("1")
TARGET = TargetRegistrationId(RawSha256("1" * 64))
EPOCH = PolicyEpochIdentity(TrustedManifestId(RawSha256("2" * 64)))
BASE, HEAD = GitSha("a" * 40), GitSha("b" * 40)
CONTRACT = ContractId("contract")


def mint(cls, **fields):
    value = object.__new__(cls)
    for name, item in fields.items():
        object.__setattr__(value, name, item)
    return value


def reader(*, pages, profile="event", transport="transport"):
    binding = mint(TrustedGitHubReadTransportBinding, config_id=ImmutableConfigId(transport),
        expected_api_host_identity=ImmutableConfigId("host"), authentication_mode_identity=ImmutableConfigId("auth"),
        service_identity=__import__("autodev_control.trusted.scope", fromlist=["ServicePrincipalId"]).ServicePrincipalId("reader"),
        permitted_repository_ids=(REPO,), transport_profile_id=ImmutableConfigId("read"))
    transport_value = object.__new__(AuthenticatedGitHubReadTransport)
    values = list(pages)
    def execute(request, cursor):
        assert type(request) in (ReadRepositoryIdentity, ReadCandidatePullRequestSet)
        if type(request) is ReadRepositoryIdentity:
            return {"repository_id": REPO.value, "owner": "o", "name": "r"}
        return values.pop(0) if len(values) > 1 else values[0]
    object.__setattr__(transport_value, "_binding", binding)
    object.__setattr__(transport_value, "_executor", execute)
    descriptor = mint(RegisteredStateFactDescriptor, descriptor_id=LogicalIdentifier("repository"), request=ReadRepositoryIdentity(REPO))
    return mint(AuthoritativeObservationProfile, profile_id=ImmutableConfigId(profile), registered_fact_descriptors=(descriptor,)), GitHubStateReader(binding, transport_value)


def target(event_ids=(ImmutableConfigId("event"),)):
    registration = mint(AdmittedTargetRegistration, repository_id=REPO, event_state_profile_ids=event_ids,
        merge=MergeConfiguration(__import__("autodev_control.trusted.scope", fromlist=["ServicePrincipalId"]).ServicePrincipalId("merge"), ImmutableConfigId("merge"), (CanonicalBranchRef("refs/heads/main"),)))
    return mint(ResolvedTargetRegistration, registration=registration, target_registration_id=TARGET,
                root_config_id=ImmutableConfigId("root"), policy_epoch_identity=EPOCH)


def source(bindings=(), policy=None, pr_reader=None):
    items = tuple(mint(TrustedSemanticTargetObservationBinding, profile=profile, reader=reader) for profile, reader in bindings)
    return mint(TrustedSemanticContextObservationSource, target_bindings=items, pull_request_policy=policy, pull_request_reader=pr_reader)


def item(number=1, *, head=HEAD, base=BASE, base_ref="refs/heads/main"):
    return {"number": number, "state": "open", "merged": False, "base_repository_id": REPO.value,
            "base_ref": base_ref, "base_sha": base.value, "head_repository_id": REPO.value,
            "head_ref": "refs/heads/autodev/candidates/" + "3" * 64, "head_sha": head.value, "merge_sha": None}


def page(items):
    return {"repository_id": REPO.value, "head_ref": "refs/heads/autodev/candidates/" + "3" * 64,
            "items": items, "next_cursor": None, "complete": True}


def test_target_uses_registration_profiles_and_ignores_unrelated_sources():
    needed, needed_reader = reader(pages=[])
    extra, extra_reader = reader(pages=[], profile="extra")
    result = resolve_current_semantic_target_context(target(), source(((needed, needed_reader), (extra, extra_reader))))
    assert result.status is SemanticContextResolutionStatus.RESOLVED
    assert len(result.dependencies) == 1 and result.dependencies[0].observation_profile_id == ImmutableConfigId("event")
    expected = contract_json_value_digest(("autodev.current-semantic-target-context/v1", REPO.value, TARGET.raw_sha256.value,
        EPOCH.manifest_id.raw_sha256.value, ((REPO.value, "event", "transport", result.dependencies[0].expected_binding_id.value),))).value
    assert result.target_context_id.value == expected


def test_target_missing_duplicate_and_empty_sources_fail_closed_in_frozen_domains():
    profile, state_reader = reader(pages=[])
    assert resolve_current_semantic_target_context(target(), source()).reason is CurrentSemanticTargetContextReason.TARGET_PROFILE_SOURCE_UNAVAILABLE
    assert resolve_current_semantic_target_context(target(), source(((profile, state_reader), (profile, state_reader)))).reason is CurrentSemanticTargetContextReason.SOURCE_INVALID
    assert resolve_current_semantic_target_context(target(()), source()).reason is CurrentSemanticTargetContextReason.TARGET_PROFILE_SET_UNAVAILABLE


def test_target_limit_allows_64_and_denies_65_before_reading():
    profiles = tuple(ImmutableConfigId(f"p{i}") for i in range(65))
    assert resolve_current_semantic_target_context(target(profiles), source()).reason is CurrentSemanticTargetContextReason.TARGET_CONTEXT_LIMIT_EXCEEDED


def test_target_exactly_64_sources_resolve_in_canonical_dependency_order():
    profile, state_reader = reader(pages=[])
    ids = tuple(ImmutableConfigId(f"p{i:02}") for i in range(64))
    bindings = tuple((mint(AuthoritativeObservationProfile, profile_id=item, registered_fact_descriptors=profile.registered_fact_descriptors), state_reader) for item in reversed(ids))
    result = resolve_current_semantic_target_context(target(ids), source(bindings))
    assert result.status is SemanticContextResolutionStatus.RESOLVED
    assert tuple(item.observation_profile_id for item in result.dependencies) == ids


def test_context_source_and_policy_are_closed_to_ordinary_construction():
    with pytest.raises(TypeError):
        TrustedSemanticContextObservationSource()
    with pytest.raises(TypeError):
        TrustedSemanticPullRequestObservationPolicy()
    with pytest.raises(TypeError):
        TrustedSemanticTargetObservationBinding()


def test_target_read_failure_mapping_never_keeps_partial_dependency_or_identity():
    profile, state_reader = reader(pages=[])
    # Reader's authoritative descriptor is malformed for its exact target repository.
    bad = mint(AuthoritativeObservationProfile, profile_id=profile.profile_id,
               registered_fact_descriptors=())
    result = resolve_current_semantic_target_context(target(), source(((bad, state_reader),)))
    assert result.status is SemanticContextResolutionStatus.INDETERMINATE
    assert result.reason is CurrentSemanticTargetContextReason.TARGET_OBSERVATION_UNAVAILABLE
    assert result.state_read_failure is StateReadFailure.INCOMPLETE
    assert result.target_context_id is None and result.dependencies == ()


def test_closed_pr_request_uses_only_repo_and_candidate_branch_and_two_pass_binding():
    profile, state_reader = reader(pages=[page([item()]), page([item()])], profile="pr")
    request = ReadCandidatePullRequestSet(REPO, GitRef("refs/heads/autodev/candidates/" + "3" * 64))
    complete = state_reader.read_candidate_pull_request_set(request, profile.profile_id)
    assert complete.status is AuthoritativeStateReadStatus.SUCCESS
    assert complete.snapshot.observations[0].fact_value[1] == request.head_ref.value
    with pytest.raises(TypeError):
        ReadCandidatePullRequestSet(REPO, GitRef("x"), HEAD)  # no expected head SHA query field


def test_pr_context_discovers_then_denies_head_movement_without_partial_identity():
    profile, state_reader = reader(pages=[page([item(head=GitSha("c" * 40))]), page([item(head=GitSha("c" * 40))])], profile="pr")
    policy = mint(TrustedSemanticPullRequestObservationPolicy, profile_id=profile.profile_id, policy_epoch_identity=EPOCH,
        target_registration_id=TARGET, repository_id=REPO, transport_config_id=ImmutableConfigId("transport"))
    contract = mint(__import__("autodev_control.trusted.contract", fromlist=["AdmittedIssueContract"]).AdmittedIssueContract,
        target_registration_id=TARGET, contract_id=CONTRACT, contract_raw_sha256=RawSha256("4" * 64), base_sha=BASE, integration_ref=CanonicalBranchRef("refs/heads/main"))
    materialization = mint(AdmittedCandidateMaterialization, target_registration_id=TARGET, repository_id=REPO, contract_id=CONTRACT,
        contract_raw_sha256=RawSha256("4" * 64), policy_epoch_identity=EPOCH, base_commit=BASE, candidate_commit=HEAD,
        materialization_id=CandidateMaterializationId(RawSha256("3" * 64)))
    result = resolve_current_semantic_pull_request_context(target(), contract, materialization, source(policy=policy, pr_reader=state_reader))
    assert result.status is SemanticContextResolutionStatus.DENIED
    assert result.reason is CurrentSemanticPullRequestContextReason.PR_CONTEXT_CONFLICT
    assert result.pull_request_identity is None and result.dependencies == ()


def test_pr_context_resolves_with_exact_v2_identity_and_base_ref_continuity():
    profile, state_reader = reader(pages=[page([item()]), page([item()])], profile="pr")
    policy = mint(TrustedSemanticPullRequestObservationPolicy, profile_id=profile.profile_id, policy_epoch_identity=EPOCH,
        target_registration_id=TARGET, repository_id=REPO, transport_config_id=ImmutableConfigId("transport"))
    raw = RawSha256("4" * 64)
    contract = mint(__import__("autodev_control.trusted.contract", fromlist=["AdmittedIssueContract"]).AdmittedIssueContract,
        target_registration_id=TARGET, contract_id=CONTRACT, contract_raw_sha256=raw, base_sha=BASE, integration_ref=CanonicalBranchRef("refs/heads/main"))
    materialization = mint(AdmittedCandidateMaterialization, target_registration_id=TARGET, repository_id=REPO, contract_id=CONTRACT,
        contract_raw_sha256=raw, policy_epoch_identity=EPOCH, base_commit=BASE, candidate_commit=HEAD,
        materialization_id=CandidateMaterializationId(RawSha256("3" * 64)))
    result = resolve_current_semantic_pull_request_context(target(), contract, materialization, source(policy=policy, pr_reader=state_reader))
    assert result.status is SemanticContextResolutionStatus.RESOLVED
    dependency = result.dependencies[0]
    expected = contract_json_value_digest(("autodev.current-semantic-pr-context/v2", REPO.value, TARGET.raw_sha256.value,
        EPOCH.manifest_id.raw_sha256.value, CONTRACT.value, raw.value, materialization.materialization_id.raw_sha256.value,
        Decimal(1), dependency.observation_profile_id.value, dependency.transport_config_id.value, dependency.expected_binding_id.value)).value
    assert result.pull_request_identity.value == expected


def test_pr_context_base_ref_and_multiple_set_conflicts_are_not_filtered_away():
    profile, state_reader = reader(pages=[page([item(base_ref="refs/heads/release")]), page([item(base_ref="refs/heads/release")])], profile="pr")
    policy = mint(TrustedSemanticPullRequestObservationPolicy, profile_id=profile.profile_id, policy_epoch_identity=EPOCH,
        target_registration_id=TARGET, repository_id=REPO, transport_config_id=ImmutableConfigId("transport"))
    raw = RawSha256("4" * 64)
    contract = mint(__import__("autodev_control.trusted.contract", fromlist=["AdmittedIssueContract"]).AdmittedIssueContract,
        target_registration_id=TARGET, contract_id=CONTRACT, contract_raw_sha256=raw, base_sha=BASE, integration_ref=CanonicalBranchRef("refs/heads/main"))
    materialization = mint(AdmittedCandidateMaterialization, target_registration_id=TARGET, repository_id=REPO, contract_id=CONTRACT,
        contract_raw_sha256=raw, policy_epoch_identity=EPOCH, base_commit=BASE, candidate_commit=HEAD,
        materialization_id=CandidateMaterializationId(RawSha256("3" * 64)))
    result = resolve_current_semantic_pull_request_context(target(), contract, materialization, source(policy=policy, pr_reader=state_reader))
    assert result.reason is CurrentSemanticPullRequestContextReason.PR_CONTEXT_CONFLICT


def test_pr_two_pass_movement_is_indeterminate_without_authoritative_binding():
    profile, state_reader = reader(pages=[page([item(1)]), page([item(2)])], profile="pr")
    result = state_reader.read_candidate_pull_request_set(ReadCandidatePullRequestSet(REPO, GitRef("refs/heads/autodev/candidates/" + "3" * 64)), profile.profile_id)
    assert result.status is AuthoritativeStateReadStatus.FAILURE
    assert result.failure is StateReadFailure.STATE_MOVED and result.binding_id is None


def test_pr_enumeration_duplicate_and_malformed_pages_fail_closed_without_binding():
    request = ReadCandidatePullRequestSet(REPO, GitRef("refs/heads/autodev/candidates/" + "3" * 64))
    profile, duplicate_reader = reader(pages=[page([item(1), item(1)])], profile="pr")
    duplicate = duplicate_reader.read_candidate_pull_request_set(request, profile.profile_id)
    assert duplicate.failure is StateReadFailure.INCOMPLETE and duplicate.binding_id is None
    profile, malformed_reader = reader(pages=[{"repository_id": REPO.value}], profile="pr")
    malformed = malformed_reader.read_candidate_pull_request_set(request, profile.profile_id)
    assert malformed.failure is StateReadFailure.MALFORMED_RESPONSE and malformed.binding_id is None
