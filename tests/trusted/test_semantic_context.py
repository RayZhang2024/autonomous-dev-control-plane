"""Focused B1 current-context regressions through the real G6 reader boundary."""
from __future__ import annotations

import pytest
from decimal import Decimal
from dataclasses import fields
import inspect

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
from autodev_control.trusted.gates import ControlStateAuthoritativeDependency, ControlStateAuthoritativeDependencySet


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


def reader(*, pages, profile="event", transport="transport", permitted=(REPO,), owner="o", record=None):
    binding = mint(TrustedGitHubReadTransportBinding, config_id=ImmutableConfigId(transport),
        expected_api_host_identity=ImmutableConfigId("host"), authentication_mode_identity=ImmutableConfigId("auth"),
        service_identity=__import__("autodev_control.trusted.scope", fromlist=["ServicePrincipalId"]).ServicePrincipalId("reader"),
        permitted_repository_ids=permitted, transport_profile_id=ImmutableConfigId("read"))
    transport_value = object.__new__(AuthenticatedGitHubReadTransport)
    values = list(pages)
    def execute(request, cursor):
        if record is not None:
            record.append(request)
        assert type(request) in (ReadRepositoryIdentity, ReadCandidatePullRequestSet)
        if type(request) is ReadRepositoryIdentity:
            return {"repository_id": REPO.value, "owner": owner, "name": "r"}
        return values.pop(0) if len(values) > 1 else values[0]
    object.__setattr__(transport_value, "_binding", binding)
    object.__setattr__(transport_value, "_executor", execute)
    descriptor = mint(RegisteredStateFactDescriptor, descriptor_id=LogicalIdentifier("repository"), request=ReadRepositoryIdentity(REPO))
    return mint(AuthoritativeObservationProfile, profile_id=ImmutableConfigId(profile), registered_fact_descriptors=(descriptor,)), GitHubStateReader(binding, transport_value)


def target(event_ids=(ImmutableConfigId("event"),), *, target_id=TARGET, epoch=EPOCH):
    registration = mint(AdmittedTargetRegistration, repository_id=REPO, event_state_profile_ids=event_ids,
        merge=MergeConfiguration(__import__("autodev_control.trusted.scope", fromlist=["ServicePrincipalId"]).ServicePrincipalId("merge"), ImmutableConfigId("merge"), (CanonicalBranchRef("refs/heads/main"),)))
    return mint(ResolvedTargetRegistration, registration=registration, target_registration_id=target_id,
                root_config_id=ImmutableConfigId("root"), policy_epoch_identity=epoch)


def source(bindings=(), policy=None, pr_reader=None):
    items = tuple(mint(TrustedSemanticTargetObservationBinding, required_profile_id=selector,
                       profile=profile, reader=reader)
                  for selector, profile, reader in bindings)
    return mint(TrustedSemanticContextObservationSource, target_bindings=items, pull_request_policy=policy, pull_request_reader=pr_reader)


def item(number=1, *, head=HEAD, base=BASE, base_ref="refs/heads/main"):
    return {"number": number, "state": "open", "merged": False, "base_repository_id": REPO.value,
            "base_ref": base_ref, "base_sha": base.value, "head_repository_id": REPO.value,
            "head_ref": "refs/heads/autodev/candidates/" + "3" * 64, "head_sha": head.value, "merge_sha": None}


def page(items):
    return {"repository_id": REPO.value, "head_ref": "refs/heads/autodev/candidates/" + "3" * 64,
            "items": items, "next_cursor": None, "complete": True}


def pr_inputs(*, pages=None, policy_fields=None, contract_fields=None, materialization_fields=None,
              target_value=None, reader_kwargs=None):
    profile, state_reader = reader(pages=pages or [page([item()]), page([item()])], profile="pr", **(reader_kwargs or {}))
    policy_fields = {"profile_id": profile.profile_id, "policy_epoch_identity": EPOCH,
                     "target_registration_id": TARGET, "repository_id": REPO,
                     "transport_config_id": ImmutableConfigId("transport"), **(policy_fields or {})}
    policy = mint(TrustedSemanticPullRequestObservationPolicy, **policy_fields)
    raw = RawSha256("4" * 64)
    contract = mint(__import__("autodev_control.trusted.contract", fromlist=["AdmittedIssueContract"]).AdmittedIssueContract,
                    **{"target_registration_id": TARGET, "contract_id": CONTRACT, "contract_raw_sha256": raw,
                       "base_sha": BASE, "integration_ref": CanonicalBranchRef("refs/heads/main"), **(contract_fields or {})})
    materialization = mint(AdmittedCandidateMaterialization,
                           **{"target_registration_id": TARGET, "repository_id": REPO, "contract_id": CONTRACT,
                              "contract_raw_sha256": raw, "policy_epoch_identity": EPOCH, "base_commit": BASE,
                              "candidate_commit": HEAD, "materialization_id": CandidateMaterializationId(RawSha256("3" * 64)),
                              **(materialization_fields or {})})
    return target_value or target(), contract, materialization, source(policy=policy, pr_reader=state_reader)


def test_target_uses_registration_profiles_and_ignores_unrelated_sources():
    needed, needed_reader = reader(pages=[])
    extra, extra_reader = reader(pages=[], profile="extra")
    result = resolve_current_semantic_target_context(target(), source(((ImmutableConfigId("event"), needed, needed_reader), (ImmutableConfigId("extra"), extra, extra_reader))))
    assert result.status is SemanticContextResolutionStatus.RESOLVED
    assert len(result.dependencies) == 1 and result.dependencies[0].observation_profile_id == ImmutableConfigId("event")
    expected = contract_json_value_digest(("autodev.current-semantic-target-context/v1", REPO.value, TARGET.raw_sha256.value,
        EPOCH.manifest_id.raw_sha256.value, ((REPO.value, "event", "transport", result.dependencies[0].expected_binding_id.value),))).value
    assert result.target_context_id.value == expected


def test_target_missing_duplicate_and_empty_sources_fail_closed_in_frozen_domains():
    profile, state_reader = reader(pages=[])
    assert resolve_current_semantic_target_context(target(), source()).reason is CurrentSemanticTargetContextReason.TARGET_PROFILE_SOURCE_UNAVAILABLE
    assert resolve_current_semantic_target_context(target(), source(((ImmutableConfigId("event"), profile, state_reader), (ImmutableConfigId("event"), profile, state_reader)))).reason is CurrentSemanticTargetContextReason.SOURCE_INVALID
    assert resolve_current_semantic_target_context(target(()), source()).reason is CurrentSemanticTargetContextReason.TARGET_PROFILE_SET_UNAVAILABLE


def test_target_selector_profile_mismatch_is_denied_not_reclassified_as_missing():
    wrong_profile, state_reader = reader(pages=[], profile="other")
    result = resolve_current_semantic_target_context(
        target(), source(((ImmutableConfigId("event"), wrong_profile, state_reader),))
    )
    assert result.status is SemanticContextResolutionStatus.DENIED
    assert result.reason is CurrentSemanticTargetContextReason.TARGET_PROFILE_BINDING_MISMATCH


def test_target_limit_allows_64_and_denies_65_before_reading():
    profiles = tuple(ImmutableConfigId(f"p{i}") for i in range(65))
    assert resolve_current_semantic_target_context(target(profiles), source()).reason is CurrentSemanticTargetContextReason.TARGET_CONTEXT_LIMIT_EXCEEDED


def test_target_exactly_64_sources_resolve_in_canonical_dependency_order():
    profile, state_reader = reader(pages=[])
    ids = tuple(ImmutableConfigId(f"p{i:02}") for i in range(64))
    bindings = tuple((item, mint(AuthoritativeObservationProfile, profile_id=item, registered_fact_descriptors=profile.registered_fact_descriptors), state_reader) for item in reversed(ids))
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
    result = resolve_current_semantic_target_context(target(), source(((ImmutableConfigId("event"), bad, state_reader),)))
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


@pytest.mark.parametrize("changes", [
    {"state": "closed"}, {"merged": True, "state": "closed", "merge_sha": "d" * 40},
    {"base_repository_id": "2"}, {"head_repository_id": "2"},
    {"head_ref": "refs/heads/other"}, {"merge_sha": "d" * 40},
])
def test_pr_adapter_contract_rejects_every_nonmember_instead_of_silent_filtering(changes):
    raw = item()
    raw.update(changes)
    profile, state_reader = reader(pages=[page([raw])], profile="pr")
    result = state_reader.read_candidate_pull_request_set(
        ReadCandidatePullRequestSet(REPO, GitRef("refs/heads/autodev/candidates/" + "3" * 64)), profile.profile_id)
    assert result.status is AuthoritativeStateReadStatus.FAILURE
    assert result.failure is StateReadFailure.MISMATCH and result.binding_id is None


def test_pr_result_and_page_bounds_are_exactly_64_then_incomplete_at_65():
    request = ReadCandidatePullRequestSet(REPO, GitRef("refs/heads/autodev/candidates/" + "3" * 64))
    items64 = [item(number=index + 1) for index in range(64)]
    profile, reader64 = reader(pages=[page(items64), page(items64)], profile="pr")
    assert reader64.read_candidate_pull_request_set(request, profile.profile_id).status is AuthoritativeStateReadStatus.SUCCESS
    items65 = [item(number=index + 1) for index in range(65)]
    profile, reader65 = reader(pages=[page(items65)], profile="pr")
    assert reader65.read_candidate_pull_request_set(request, profile.profile_id).failure is StateReadFailure.INCOMPLETE
    pages64 = [dict(page([item(1)]), complete=False, next_cursor=f"c{index}") for index in range(63)] + [page([item(1)])]
    # The duplicate number itself makes this incomplete before the page limit;
    # use empty intermediate pages to exercise the exact page bound.
    pages64 = [dict(page([]), complete=False, next_cursor=f"c{index}") for index in range(63)] + [page([item(1)])]
    profile, pages_reader = reader(pages=pages64 + pages64, profile="pr")
    assert pages_reader.read_candidate_pull_request_set(request, profile.profile_id).status is AuthoritativeStateReadStatus.SUCCESS
    pages65 = [dict(page([]), complete=False, next_cursor=f"c{index}") for index in range(64)] + [page([item(1)])]
    profile, overflow_reader = reader(pages=pages65, profile="pr")
    assert overflow_reader.read_candidate_pull_request_set(request, profile.profile_id).failure is StateReadFailure.INCOMPLETE


@pytest.mark.parametrize("policy_fields, reader_kwargs", [
    ({"target_registration_id": TargetRegistrationId(RawSha256("5" * 64))}, {}),
    ({"policy_epoch_identity": PolicyEpochIdentity(TrustedManifestId(RawSha256("5" * 64)))}, {}),
    ({"repository_id": GitHubRepositoryId("2")}, {}),
    ({"transport_config_id": ImmutableConfigId("other")}, {}),
    ({}, {"permitted": ()}),
])
def test_pr_policy_and_reader_continuity_contradictions_are_source_invalid(policy_fields, reader_kwargs):
    inputs = pr_inputs(policy_fields=policy_fields, reader_kwargs=reader_kwargs)
    result = resolve_current_semantic_pull_request_context(*inputs)
    assert result.status is SemanticContextResolutionStatus.DENIED
    assert result.reason is CurrentSemanticPullRequestContextReason.SOURCE_INVALID
    assert result.pull_request_identity is None and result.dependencies == ()


def test_pr_missing_source_policy_or_reader_is_indeterminate():
    resolved, contract, materialization, present = pr_inputs()
    assert resolve_current_semantic_pull_request_context(resolved, contract, materialization, None).reason is CurrentSemanticPullRequestContextReason.SOURCE_UNAVAILABLE
    assert resolve_current_semantic_pull_request_context(resolved, contract, materialization, source()).reason is CurrentSemanticPullRequestContextReason.SOURCE_UNAVAILABLE
    assert resolve_current_semantic_pull_request_context(resolved, contract, materialization,
        mint(TrustedSemanticContextObservationSource, target_bindings=(), pull_request_policy=present.pull_request_policy, pull_request_reader=None)).reason is CurrentSemanticPullRequestContextReason.SOURCE_UNAVAILABLE


def test_pr_complete_cardinality_has_no_favorable_tie_break():
    resolved, contract, materialization, current = pr_inputs(pages=[page([]), page([])])
    assert resolve_current_semantic_pull_request_context(resolved, contract, materialization, current).reason is CurrentSemanticPullRequestContextReason.PR_CONTEXT_UNAVAILABLE
    resolved, contract, materialization, current = pr_inputs(pages=[page([item(2), item(1)]), page([item(1), item(2)])])
    result = resolve_current_semantic_pull_request_context(resolved, contract, materialization, current)
    assert result.status is SemanticContextResolutionStatus.DENIED
    assert result.reason is CurrentSemanticPullRequestContextReason.PR_CONTEXT_CONFLICT
    assert result.pull_request_identity is None and result.dependencies == ()


@pytest.mark.parametrize("pages, reason", [
    ([{"repository_id": REPO.value}], CurrentSemanticPullRequestContextReason.PR_OBSERVATION_UNAVAILABLE),
    ([dict(page([]), complete=False, next_cursor=None)], CurrentSemanticPullRequestContextReason.PR_OBSERVATION_INCOMPLETE),
    ([page([item(1)]), page([item(2)])], CurrentSemanticPullRequestContextReason.PR_OBSERVATION_MOVED),
    ([page([dict(item(), head_repository_id="2")])], CurrentSemanticPullRequestContextReason.PR_CONTEXT_CONFLICT),
])
def test_pr_failure_mapping_never_preserves_partial_context(pages, reason):
    resolved, contract, materialization, current = pr_inputs(pages=pages)
    result = resolve_current_semantic_pull_request_context(resolved, contract, materialization, current)
    assert result.reason is reason
    assert result.pull_request_identity is None and result.dependencies == ()


@pytest.mark.parametrize("contract_fields, materialization_fields", [
    ({"target_registration_id": TargetRegistrationId(RawSha256("5" * 64))}, {}),
    ({}, {"target_registration_id": TargetRegistrationId(RawSha256("5" * 64))}),
    ({}, {"repository_id": GitHubRepositoryId("2")}),
    ({"contract_id": ContractId("other")}, {}),
    ({"base_sha": GitSha("c" * 40)}, {}),
])
def test_pr_pre_read_contract_candidate_target_continuity_fails_before_transport(contract_fields, materialization_fields):
    resolved, contract, materialization, current = pr_inputs(contract_fields=contract_fields, materialization_fields=materialization_fields)
    result = resolve_current_semantic_pull_request_context(resolved, contract, materialization, current)
    assert result.reason is CurrentSemanticPullRequestContextReason.PR_CONTEXT_CONFLICT
    assert result.pull_request_identity is None and result.dependencies == ()


@pytest.mark.parametrize("failure, status, reason", [
    (StateReadFailure.UNAVAILABLE, SemanticContextResolutionStatus.INDETERMINATE, CurrentSemanticTargetContextReason.TARGET_OBSERVATION_UNAVAILABLE),
    (StateReadFailure.UNSUPPORTED, SemanticContextResolutionStatus.INDETERMINATE, CurrentSemanticTargetContextReason.TARGET_OBSERVATION_UNAVAILABLE),
    (StateReadFailure.INDETERMINATE, SemanticContextResolutionStatus.INDETERMINATE, CurrentSemanticTargetContextReason.TARGET_OBSERVATION_UNAVAILABLE),
    (StateReadFailure.MALFORMED_RESPONSE, SemanticContextResolutionStatus.INDETERMINATE, CurrentSemanticTargetContextReason.TARGET_OBSERVATION_UNAVAILABLE),
    (StateReadFailure.INCOMPLETE, SemanticContextResolutionStatus.INDETERMINATE, CurrentSemanticTargetContextReason.TARGET_OBSERVATION_UNAVAILABLE),
    (StateReadFailure.STATE_MOVED, SemanticContextResolutionStatus.INDETERMINATE, CurrentSemanticTargetContextReason.TARGET_OBSERVATION_UNAVAILABLE),
    (StateReadFailure.MISMATCH, SemanticContextResolutionStatus.DENIED, CurrentSemanticTargetContextReason.TARGET_OBSERVATION_CONFLICT),
    (StateReadFailure.UNTRUSTED_TRANSPORT, SemanticContextResolutionStatus.DENIED, CurrentSemanticTargetContextReason.SOURCE_INVALID),
], ids=lambda value: getattr(value, "value", str(value)))
def test_target_every_frozen_state_read_failure_maps_exactly(monkeypatch, failure, status, reason):
    profile, state_reader = reader(pages=[])
    monkeypatch.setattr(GitHubStateReader, "read_authoritative", lambda *_: AuthoritativeStateReadResult(AuthoritativeStateReadStatus.FAILURE, failure=failure))
    result = resolve_current_semantic_target_context(target(), source(((ImmutableConfigId("event"), profile, state_reader),)))
    assert (result.status, result.reason, result.state_read_failure) == (status, reason, failure)
    assert result.target_context_id is None and result.dependencies == ()


def test_shared_dependency_is_exact_lower_layer_model_with_canonical_locator_validation():
    dependency = AuthoritativeStateDependency(REPO, ImmutableConfigId("p"), ImmutableConfigId("t"), AuthoritativeStateBindingId("1" * 64))
    assert ControlStateAuthoritativeDependency is AuthoritativeStateDependency
    assert ControlStateAuthoritativeDependencySet is AuthoritativeStateDependencySet
    assert dependency.locator == (REPO, ImmutableConfigId("p"), ImmutableConfigId("t"))
    with pytest.raises(TypeError):
        AuthoritativeStateDependency("1", ImmutableConfigId("p"), ImmutableConfigId("t"), AuthoritativeStateBindingId("1" * 64))
    with pytest.raises(ValueError):
        AuthoritativeStateDependencySet((dependency, dependency))


def test_closed_request_has_exactly_two_fields_and_rejects_other_github_request_types():
    assert tuple(field.name for field in fields(ReadCandidatePullRequestSet)) == ("repository_id", "head_ref")
    with pytest.raises(TypeError):
        GitHubStateReader.read_candidate_pull_request_set(reader(pages=[])[1], ReadRepositoryIdentity(REPO), ImmutableConfigId("p"))


def test_reader_complete_set_order_is_canonical_and_binding_moves_with_every_observed_member():
    request = ReadCandidatePullRequestSet(REPO, GitRef("refs/heads/autodev/candidates/" + "3" * 64))
    profile, unordered = reader(pages=[page([item(2), item(1)]), page([item(1), item(2)])], profile="pr")
    first = unordered.read_candidate_pull_request_set(request, profile.profile_id)
    profile, ordered = reader(pages=[page([item(1), item(2)]), page([item(2), item(1)])], profile="pr")
    second = ordered.read_candidate_pull_request_set(request, profile.profile_id)
    assert tuple(entry.number.value for entry in first.observations) == (1, 2)
    assert first.binding_id == second.binding_id
    for changed in (item(head=GitSha("c" * 40)), item(base=GitSha("c" * 40)), item(base_ref="refs/heads/release"), item(2)):
        profile, changed_reader = reader(pages=[page([changed]), page([changed])], profile="pr")
        changed_result = changed_reader.read_candidate_pull_request_set(request, profile.profile_id)
        assert changed_result.binding_id != first.binding_id


def test_target_identity_is_repeatable_and_moves_with_each_frozen_input():
    def resolve(*, profile_id="event", transport_id="transport", owner="o", target_id=TARGET, epoch=EPOCH):
        profile, state_reader = reader(pages=[], profile=profile_id, transport=transport_id, owner=owner)
        result = resolve_current_semantic_target_context(
            target((ImmutableConfigId(profile_id),), target_id=target_id, epoch=epoch),
            source(((ImmutableConfigId(profile_id), profile, state_reader),)),
        )
        assert result.status is SemanticContextResolutionStatus.RESOLVED
        return result.target_context_id
    original = resolve()
    assert resolve() == original
    assert resolve(profile_id="other") != original
    assert resolve(transport_id="other") != original
    assert resolve(owner="moved") != original
    assert resolve(target_id=TargetRegistrationId(RawSha256("5" * 64))) != original
    assert resolve(epoch=PolicyEpochIdentity(TrustedManifestId(RawSha256("5" * 64)))) != original


def test_pr_identity_is_repeatable_and_moves_with_contract_candidate_set_profile_and_transport():
    def resolve(*, number=1, contract_id=CONTRACT, raw=RawSha256("4" * 64), materialization="3", profile_name="pr", transport="transport"):
        branch = "refs/heads/autodev/candidates/" + materialization * 64
        observed = item(number)
        observed["head_ref"] = branch
        complete_page = {**page([observed]), "head_ref": branch}
        profile, state_reader = reader(pages=[complete_page, complete_page], profile=profile_name, transport=transport)
        policy = mint(TrustedSemanticPullRequestObservationPolicy, profile_id=profile.profile_id,
            policy_epoch_identity=EPOCH, target_registration_id=TARGET, repository_id=REPO,
            transport_config_id=ImmutableConfigId(transport))
        contract = mint(__import__("autodev_control.trusted.contract", fromlist=["AdmittedIssueContract"]).AdmittedIssueContract,
            target_registration_id=TARGET, contract_id=contract_id, contract_raw_sha256=raw,
            base_sha=BASE, integration_ref=CanonicalBranchRef("refs/heads/main"))
        materialization_record = mint(AdmittedCandidateMaterialization, target_registration_id=TARGET,
            repository_id=REPO, contract_id=contract_id, contract_raw_sha256=raw, policy_epoch_identity=EPOCH,
            base_commit=BASE, candidate_commit=HEAD,
            materialization_id=CandidateMaterializationId(RawSha256(materialization * 64)))
        value = resolve_current_semantic_pull_request_context(target(), contract, materialization_record,
            source(policy=policy, pr_reader=state_reader))
        assert value.status is SemanticContextResolutionStatus.RESOLVED
        return value.pull_request_identity
    baseline = resolve()
    assert resolve() == baseline
    assert resolve(contract_id=ContractId("other")) != baseline
    assert resolve(raw=RawSha256("5" * 64)) != baseline
    assert resolve(materialization="5") != baseline
    assert resolve(number=2) != baseline
    assert resolve(profile_name="other") != baseline
    assert resolve(transport="other") != baseline


def test_pr_resolver_derives_closed_request_from_target_and_candidate_without_historical_or_g7_inputs():
    seen = []
    profile, state_reader = reader(pages=[page([item()]), page([item()])], profile="pr", record=seen)
    policy = mint(TrustedSemanticPullRequestObservationPolicy, profile_id=profile.profile_id,
                  policy_epoch_identity=EPOCH, target_registration_id=TARGET, repository_id=REPO,
                  transport_config_id=ImmutableConfigId("transport"))
    resolved, contract, materialization, _ = pr_inputs()
    result = resolve_current_semantic_pull_request_context(resolved, contract, materialization,
        source(policy=policy, pr_reader=state_reader))
    assert result.status is SemanticContextResolutionStatus.RESOLVED
    observed = [request for request in seen if type(request) is ReadCandidatePullRequestSet]
    assert len(observed) == 2
    assert all(request.repository_id == resolved.registration.repository_id for request in observed)
    assert all(request.head_ref == GitRef(materialization.candidate_branch.value) for request in observed)
    implementation = inspect.getsource(resolve_current_semantic_pull_request_context)
    assert "SemanticReviewEffectiveSubject" not in implementation
    assert "ProtectedEffectMarker" not in implementation
    assert "CreatedCandidatePrEffectSubject" not in implementation
