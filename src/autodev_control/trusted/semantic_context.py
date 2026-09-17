"""B1 read-only current semantic target and pull-request observation.

This module deliberately derives factual, non-bearer context identities only.
It has no canonical storage, cache, effect, semantic acceptance, or progression
surface.  Trusted source objects are root-assembly products and have closed
constructors.
"""
from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from enum import Enum

from .backend import ResolvedTargetRegistration
from .contract import AdmittedIssueContract, contract_json_value_digest
from .identity import GitRef, GitSha, ImmutableConfigId
from .materialization import AdmittedCandidateMaterialization
from .manifest import PolicyEpochIdentity
from .review import PullRequestIdentity, TargetContextId
from .scope import CanonicalBranchRef, GitHubRepositoryId, TargetRegistrationId
from .state_reader import (
    AuthoritativeObservationProfile, AuthoritativeStateDependency,
    AuthoritativeStateReadStatus, GitHubStateReader, ReadCandidatePullRequestSet,
    StateReadFailure, TrustedGitHubReadTransportBinding,
)

MAX_CURRENT_SEMANTIC_TARGET_CONTEXT_DEPENDENCIES = 64
MAX_CURRENT_SEMANTIC_PR_DISCOVERY_PAGES = 64
MAX_CURRENT_SEMANTIC_PR_DISCOVERY_RESULTS = 64
_SOURCE_KEY = object()


class SemanticContextResolutionStatus(Enum):
    RESOLVED = "RESOLVED"
    INDETERMINATE = "INDETERMINATE"
    DENIED = "DENIED"


class CurrentSemanticTargetContextReason(Enum):
    RESOLVED = "RESOLVED"
    SOURCE_UNAVAILABLE = "SOURCE_UNAVAILABLE"
    SOURCE_INVALID = "SOURCE_INVALID"
    TARGET_PROFILE_SET_UNAVAILABLE = "TARGET_PROFILE_SET_UNAVAILABLE"
    TARGET_PROFILE_SOURCE_UNAVAILABLE = "TARGET_PROFILE_SOURCE_UNAVAILABLE"
    TARGET_PROFILE_BINDING_MISMATCH = "TARGET_PROFILE_BINDING_MISMATCH"
    TARGET_OBSERVATION_UNAVAILABLE = "TARGET_OBSERVATION_UNAVAILABLE"
    TARGET_OBSERVATION_CONFLICT = "TARGET_OBSERVATION_CONFLICT"
    TARGET_CONTEXT_LIMIT_EXCEEDED = "TARGET_CONTEXT_LIMIT_EXCEEDED"


class CurrentSemanticPullRequestContextReason(Enum):
    RESOLVED = "RESOLVED"
    SOURCE_UNAVAILABLE = "SOURCE_UNAVAILABLE"
    SOURCE_INVALID = "SOURCE_INVALID"
    PR_CONTEXT_UNAVAILABLE = "PR_CONTEXT_UNAVAILABLE"
    PR_CONTEXT_CONFLICT = "PR_CONTEXT_CONFLICT"
    PR_OBSERVATION_UNAVAILABLE = "PR_OBSERVATION_UNAVAILABLE"
    PR_OBSERVATION_INCOMPLETE = "PR_OBSERVATION_INCOMPLETE"
    PR_OBSERVATION_MOVED = "PR_OBSERVATION_MOVED"
    PR_CONTEXT_LIMIT_EXCEEDED = "PR_CONTEXT_LIMIT_EXCEEDED"


@dataclass(frozen=True, slots=True)
class CurrentSemanticTargetContextResolution:
    status: SemanticContextResolutionStatus
    reason: CurrentSemanticTargetContextReason
    target_context_id: TargetContextId | None = None
    dependencies: tuple[AuthoritativeStateDependency, ...] = ()
    state_read_failure: StateReadFailure | None = None

    def __post_init__(self) -> None:
        if type(self.status) is not SemanticContextResolutionStatus or type(self.reason) is not CurrentSemanticTargetContextReason:
            raise TypeError("target result has wrong exact domain")
        if type(self.dependencies) is not tuple or any(type(item) is not AuthoritativeStateDependency for item in self.dependencies):
            raise TypeError("target dependencies must be exact")
        if self.status is SemanticContextResolutionStatus.RESOLVED:
            if type(self.target_context_id) is not TargetContextId or self.state_read_failure is not None:
                raise ValueError("resolved target result requires its identity only")
        elif self.target_context_id is not None or self.dependencies:
            raise ValueError("failed target result cannot retain partial authority")


@dataclass(frozen=True, slots=True)
class CurrentSemanticPullRequestContextResolution:
    status: SemanticContextResolutionStatus
    reason: CurrentSemanticPullRequestContextReason
    pull_request_identity: PullRequestIdentity | None = None
    dependencies: tuple[AuthoritativeStateDependency, ...] = ()
    state_read_failure: StateReadFailure | None = None

    def __post_init__(self) -> None:
        if type(self.status) is not SemanticContextResolutionStatus or type(self.reason) is not CurrentSemanticPullRequestContextReason:
            raise TypeError("PR result has wrong exact domain")
        if type(self.dependencies) is not tuple or any(type(item) is not AuthoritativeStateDependency for item in self.dependencies):
            raise TypeError("PR dependencies must be exact")
        if self.status is SemanticContextResolutionStatus.RESOLVED:
            if type(self.pull_request_identity) is not PullRequestIdentity or self.state_read_failure is not None:
                raise ValueError("resolved PR result requires its identity only")
        elif self.pull_request_identity is not None or self.dependencies:
            raise ValueError("failed PR result cannot retain partial authority")


@dataclass(frozen=True, slots=True, init=False)
class TrustedSemanticTargetObservationBinding:
    profile: AuthoritativeObservationProfile
    reader: GitHubStateReader

    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("semantic target source bindings come from trusted root assembly")


@dataclass(frozen=True, slots=True, init=False)
class TrustedSemanticPullRequestObservationPolicy:
    profile_id: ImmutableConfigId
    policy_epoch_identity: PolicyEpochIdentity
    target_registration_id: TargetRegistrationId
    repository_id: GitHubRepositoryId
    transport_config_id: ImmutableConfigId

    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("semantic PR observation policy comes from trusted root assembly")


@dataclass(frozen=True, slots=True, init=False)
class TrustedSemanticContextObservationSource:
    target_bindings: tuple[TrustedSemanticTargetObservationBinding, ...]
    pull_request_policy: TrustedSemanticPullRequestObservationPolicy | None
    pull_request_reader: GitHubStateReader | None

    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("semantic context source comes from trusted root assembly")


def _assemble_trusted_semantic_context_source(
    key: object, *, target_bindings: tuple[TrustedSemanticTargetObservationBinding, ...],
    pull_request_policy: TrustedSemanticPullRequestObservationPolicy | None,
    pull_request_reader: GitHubStateReader | None,
) -> TrustedSemanticContextObservationSource:
    if key is not _SOURCE_KEY:
        raise TypeError("internal trusted construction only")
    result = object.__new__(TrustedSemanticContextObservationSource)
    object.__setattr__(result, "target_bindings", target_bindings)
    object.__setattr__(result, "pull_request_policy", pull_request_policy)
    object.__setattr__(result, "pull_request_reader", pull_request_reader)
    return result


def _target_failure(status, reason, failure=None):
    return CurrentSemanticTargetContextResolution(status, reason, state_read_failure=failure)


def _pr_failure(status, reason, failure=None):
    return CurrentSemanticPullRequestContextResolution(status, reason, state_read_failure=failure)


def _reader_binding(reader: object) -> TrustedGitHubReadTransportBinding | None:
    if type(reader) is not GitHubStateReader:
        return None
    binding = reader.binding
    return binding if type(binding) is TrustedGitHubReadTransportBinding else None


def resolve_current_semantic_target_context(
    resolved_target: ResolvedTargetRegistration,
    source: TrustedSemanticContextObservationSource | None,
) -> CurrentSemanticTargetContextResolution:
    if type(resolved_target) is not ResolvedTargetRegistration:
        return _target_failure(SemanticContextResolutionStatus.DENIED, CurrentSemanticTargetContextReason.SOURCE_INVALID)
    if source is None:
        return _target_failure(SemanticContextResolutionStatus.INDETERMINATE, CurrentSemanticTargetContextReason.SOURCE_UNAVAILABLE)
    if type(source) is not TrustedSemanticContextObservationSource:
        return _target_failure(SemanticContextResolutionStatus.DENIED, CurrentSemanticTargetContextReason.SOURCE_INVALID)
    required = resolved_target.registration.event_state_profile_ids
    if type(required) is not tuple or any(type(item) is not ImmutableConfigId for item in required):
        return _target_failure(SemanticContextResolutionStatus.DENIED, CurrentSemanticTargetContextReason.SOURCE_INVALID)
    if not required:
        return _target_failure(SemanticContextResolutionStatus.INDETERMINATE, CurrentSemanticTargetContextReason.TARGET_PROFILE_SET_UNAVAILABLE)
    if len(required) > MAX_CURRENT_SEMANTIC_TARGET_CONTEXT_DEPENDENCIES:
        return _target_failure(SemanticContextResolutionStatus.DENIED, CurrentSemanticTargetContextReason.TARGET_CONTEXT_LIMIT_EXCEEDED)
    if type(getattr(source, "target_bindings", None)) is not tuple or any(type(item) is not TrustedSemanticTargetObservationBinding for item in source.target_bindings):
        return _target_failure(SemanticContextResolutionStatus.DENIED, CurrentSemanticTargetContextReason.SOURCE_INVALID)
    dependencies: list[AuthoritativeStateDependency] = []
    for required_id in required:
        candidates = tuple(item for item in source.target_bindings if type(getattr(item, "profile", None)) is AuthoritativeObservationProfile and item.profile.profile_id == required_id)
        if not candidates:
            return _target_failure(SemanticContextResolutionStatus.INDETERMINATE, CurrentSemanticTargetContextReason.TARGET_PROFILE_SOURCE_UNAVAILABLE)
        if len(candidates) != 1:
            return _target_failure(SemanticContextResolutionStatus.DENIED, CurrentSemanticTargetContextReason.SOURCE_INVALID)
        binding = candidates[0]
        reader_binding = _reader_binding(binding.reader)
        if reader_binding is None:
            return _target_failure(SemanticContextResolutionStatus.DENIED, CurrentSemanticTargetContextReason.SOURCE_INVALID)
        if (binding.profile.profile_id != required_id or resolved_target.registration.repository_id not in reader_binding.permitted_repository_ids):
            return _target_failure(SemanticContextResolutionStatus.DENIED, CurrentSemanticTargetContextReason.TARGET_PROFILE_BINDING_MISMATCH)
        result = binding.reader.read_authoritative(resolved_target.registration.repository_id, binding.profile)
        if result.status is not AuthoritativeStateReadStatus.SUCCESS:
            mapping = {
                StateReadFailure.MISMATCH: (SemanticContextResolutionStatus.DENIED, CurrentSemanticTargetContextReason.TARGET_OBSERVATION_CONFLICT),
                StateReadFailure.UNTRUSTED_TRANSPORT: (SemanticContextResolutionStatus.DENIED, CurrentSemanticTargetContextReason.SOURCE_INVALID),
            }
            status, reason = mapping.get(result.failure, (SemanticContextResolutionStatus.INDETERMINATE, CurrentSemanticTargetContextReason.TARGET_OBSERVATION_UNAVAILABLE))
            return _target_failure(status, reason, result.failure)
        snapshot = result.snapshot
        if (snapshot.repository_id != resolved_target.registration.repository_id
                or snapshot.observation_profile_id != required_id
                or snapshot.transport_config_id != reader_binding.config_id):
            return _target_failure(SemanticContextResolutionStatus.DENIED, CurrentSemanticTargetContextReason.TARGET_PROFILE_BINDING_MISMATCH)
        dependencies.append(AuthoritativeStateDependency(snapshot.repository_id, snapshot.observation_profile_id, snapshot.transport_config_id, result.binding_id))
    ordered = tuple(sorted(dependencies, key=lambda item: tuple(value.value for value in item.locator)))
    if len({item.locator for item in ordered}) != len(ordered):
        return _target_failure(SemanticContextResolutionStatus.DENIED, CurrentSemanticTargetContextReason.SOURCE_INVALID)
    identity = TargetContextId(contract_json_value_digest((
        "autodev.current-semantic-target-context/v1", resolved_target.registration.repository_id.value,
        resolved_target.target_registration_id.raw_sha256.value,
        resolved_target.policy_epoch_identity.manifest_id.raw_sha256.value,
        tuple((item.repository_id.value, item.observation_profile_id.value, item.transport_config_id.value, item.expected_binding_id.value) for item in ordered),
    )).value)
    return CurrentSemanticTargetContextResolution(SemanticContextResolutionStatus.RESOLVED, CurrentSemanticTargetContextReason.RESOLVED, identity, ordered)


def resolve_current_semantic_pull_request_context(
    resolved_target: ResolvedTargetRegistration, contract: AdmittedIssueContract,
    materialization: AdmittedCandidateMaterialization, source: TrustedSemanticContextObservationSource | None,
) -> CurrentSemanticPullRequestContextResolution:
    if type(resolved_target) is not ResolvedTargetRegistration or type(contract) is not AdmittedIssueContract or type(materialization) is not AdmittedCandidateMaterialization:
        return _pr_failure(SemanticContextResolutionStatus.DENIED, CurrentSemanticPullRequestContextReason.SOURCE_INVALID)
    if (contract.target_registration_id != resolved_target.target_registration_id
            or materialization.target_registration_id != resolved_target.target_registration_id
            or materialization.repository_id != resolved_target.registration.repository_id
            or materialization.contract_id != contract.contract_id
            or materialization.contract_raw_sha256 != contract.contract_raw_sha256
            or materialization.policy_epoch_identity != resolved_target.policy_epoch_identity
            or materialization.base_commit != contract.base_sha):
        return _pr_failure(SemanticContextResolutionStatus.DENIED, CurrentSemanticPullRequestContextReason.PR_CONTEXT_CONFLICT)
    if source is None:
        return _pr_failure(SemanticContextResolutionStatus.INDETERMINATE, CurrentSemanticPullRequestContextReason.SOURCE_UNAVAILABLE)
    if type(source) is not TrustedSemanticContextObservationSource:
        return _pr_failure(SemanticContextResolutionStatus.DENIED, CurrentSemanticPullRequestContextReason.SOURCE_INVALID)
    policy, reader = getattr(source, "pull_request_policy", None), getattr(source, "pull_request_reader", None)
    if policy is None or reader is None:
        return _pr_failure(SemanticContextResolutionStatus.INDETERMINATE, CurrentSemanticPullRequestContextReason.SOURCE_UNAVAILABLE)
    if type(policy) is not TrustedSemanticPullRequestObservationPolicy or type(reader) is not GitHubStateReader:
        return _pr_failure(SemanticContextResolutionStatus.DENIED, CurrentSemanticPullRequestContextReason.SOURCE_INVALID)
    reader_binding = _reader_binding(reader)
    if reader_binding is None or (policy.policy_epoch_identity != resolved_target.policy_epoch_identity
            or policy.target_registration_id != resolved_target.target_registration_id
            or policy.repository_id != resolved_target.registration.repository_id
            or policy.transport_config_id != reader_binding.config_id
            or resolved_target.registration.repository_id not in reader_binding.permitted_repository_ids):
        return _pr_failure(SemanticContextResolutionStatus.DENIED, CurrentSemanticPullRequestContextReason.SOURCE_INVALID)
    request = ReadCandidatePullRequestSet(resolved_target.registration.repository_id, GitRef(materialization.candidate_branch.value))
    result = reader.read_candidate_pull_request_set(request, policy.profile_id)
    if result.status is not AuthoritativeStateReadStatus.SUCCESS:
        mapping = {
            StateReadFailure.INCOMPLETE: (SemanticContextResolutionStatus.INDETERMINATE, CurrentSemanticPullRequestContextReason.PR_OBSERVATION_INCOMPLETE),
            StateReadFailure.STATE_MOVED: (SemanticContextResolutionStatus.INDETERMINATE, CurrentSemanticPullRequestContextReason.PR_OBSERVATION_MOVED),
            StateReadFailure.MISMATCH: (SemanticContextResolutionStatus.DENIED, CurrentSemanticPullRequestContextReason.PR_CONTEXT_CONFLICT),
            StateReadFailure.UNTRUSTED_TRANSPORT: (SemanticContextResolutionStatus.DENIED, CurrentSemanticPullRequestContextReason.SOURCE_INVALID),
        }
        status, reason = mapping.get(result.failure, (SemanticContextResolutionStatus.INDETERMINATE, CurrentSemanticPullRequestContextReason.PR_OBSERVATION_UNAVAILABLE))
        return _pr_failure(status, reason, result.failure)
    if not result.observations:
        return _pr_failure(SemanticContextResolutionStatus.INDETERMINATE, CurrentSemanticPullRequestContextReason.PR_CONTEXT_UNAVAILABLE)
    if len(result.observations) != 1:
        return _pr_failure(SemanticContextResolutionStatus.DENIED, CurrentSemanticPullRequestContextReason.PR_CONTEXT_CONFLICT)
    observed = result.observations[0]
    merge = resolved_target.registration.merge
    try:
        allowed_base_ref = CanonicalBranchRef(observed.base_ref.value)
    except (TypeError, ValueError):
        return _pr_failure(SemanticContextResolutionStatus.DENIED, CurrentSemanticPullRequestContextReason.PR_CONTEXT_CONFLICT)
    if (observed.head_sha != materialization.candidate_commit or observed.base_sha != materialization.base_commit
            or merge is None or allowed_base_ref not in merge.allowed_integration_refs
            or (contract.integration_ref is not None and observed.base_ref != GitRef(contract.integration_ref.value))):
        return _pr_failure(SemanticContextResolutionStatus.DENIED, CurrentSemanticPullRequestContextReason.PR_CONTEXT_CONFLICT)
    dependency = AuthoritativeStateDependency(result.snapshot.repository_id, result.snapshot.observation_profile_id, result.snapshot.transport_config_id, result.binding_id)
    identity = PullRequestIdentity(contract_json_value_digest((
        "autodev.current-semantic-pr-context/v2", resolved_target.registration.repository_id.value,
        resolved_target.target_registration_id.raw_sha256.value,
        resolved_target.policy_epoch_identity.manifest_id.raw_sha256.value, contract.contract_id.value,
        contract.contract_raw_sha256.value, materialization.materialization_id.raw_sha256.value,
        Decimal(observed.number.value), dependency.observation_profile_id.value, dependency.transport_config_id.value,
        dependency.expected_binding_id.value,
    )).value)
    return CurrentSemanticPullRequestContextResolution(SemanticContextResolutionStatus.RESOLVED, CurrentSemanticPullRequestContextReason.RESOLVED, identity, (dependency,))
