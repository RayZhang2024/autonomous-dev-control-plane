"""Neutral immutable protected-effect values shared by candidate roles and F.

This module contains value definitions only.  It deliberately has no fixture
platform, mutation-adapter, or provider implementation imports.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib

from .backend import canonical_json_bytes
from .identity import (
    CandidateMaterializationId, MutationInventoryId, PreparedProtectedStartId,
    ProtectedEffectMarkerId, RawSha256, RootContextId,
)
from .operation import OperationActionId, OperationId, OperationIdempotencyKey
from .scope import CanonicalBranchRef, GitHubRepositoryId, ServicePrincipalId
from .state_reader import GitHubPullRequestNumber
from .identity import GitRef, GitSha


@dataclass(frozen=True, slots=True)
class PublishedCandidateRefEffectSubject:
    repository_id: GitHubRepositoryId
    destination_branch: CanonicalBranchRef
    platform_ref: GitRef
    published_commit: GitSha

    def __post_init__(self) -> None:
        if (type(self.repository_id) is not GitHubRepositoryId
                or type(self.destination_branch) is not CanonicalBranchRef
                or type(self.platform_ref) is not GitRef
                or type(self.published_commit) is not GitSha):
            raise TypeError("published candidate-ref subject has wrong exact type")
        if self.platform_ref != GitRef(self.destination_branch.value):
            raise ValueError("canonical destination and platform ref differ")


@dataclass(frozen=True, slots=True)
class CreatedCandidatePrEffectSubject:
    repository_id: GitHubRepositoryId
    pull_request_number: GitHubPullRequestNumber
    head_ref: GitRef
    head_sha: GitSha
    base_ref: GitRef
    base_sha: GitSha

    def __post_init__(self) -> None:
        exact = (
            (self.repository_id, GitHubRepositoryId),
            (self.pull_request_number, GitHubPullRequestNumber),
            (self.head_ref, GitRef), (self.head_sha, GitSha),
            (self.base_ref, GitRef), (self.base_sha, GitSha),
        )
        if any(type(value) is not expected for value, expected in exact):
            raise TypeError("created candidate-PR subject has wrong exact type")


@dataclass(frozen=True, slots=True)
class FastForwardMergeEffectSubject:
    repository_id: GitHubRepositoryId
    pull_request_number: GitHubPullRequestNumber
    integration_ref: GitRef
    before_sha: GitSha
    after_sha: GitSha

    def __post_init__(self) -> None:
        exact = (
            (self.repository_id, GitHubRepositoryId),
            (self.pull_request_number, GitHubPullRequestNumber),
            (self.integration_ref, GitRef), (self.before_sha, GitSha),
            (self.after_sha, GitSha),
        )
        if any(type(value) is not expected for value, expected in exact):
            raise TypeError("fast-forward merge subject has wrong exact type")


EffectSubject = (
    PublishedCandidateRefEffectSubject
    | CreatedCandidatePrEffectSubject
    | FastForwardMergeEffectSubject
)


@dataclass(frozen=True, slots=True)
class ProtectedEffectMarkerPreimage:
    format: str
    gate_action: str
    operation_id: OperationId
    idempotency_key: OperationIdempotencyKey
    action_id: OperationActionId
    action_digest: RawSha256
    materialization_id: CandidateMaterializationId
    mutation_inventory_id: MutationInventoryId
    prepared_start_id: PreparedProtectedStartId
    root_context_id: RootContextId
    runtime_generation: int
    service_identity: ServicePrincipalId
    effect_subject: EffectSubject
    pre_state_identity: RawSha256
    post_state_identity: RawSha256
    prerequisite_marker_id: ProtectedEffectMarkerId | None = None

    def __post_init__(self) -> None:
        exact = (
            (self.gate_action, str), (self.operation_id, OperationId),
            (self.idempotency_key, OperationIdempotencyKey),
            (self.action_id, OperationActionId), (self.action_digest, RawSha256),
            (self.materialization_id, CandidateMaterializationId),
            (self.mutation_inventory_id, MutationInventoryId),
            (self.prepared_start_id, PreparedProtectedStartId),
            (self.root_context_id, RootContextId),
            (self.runtime_generation, int),
            (self.service_identity, ServicePrincipalId),
            (self.pre_state_identity, RawSha256),
            (self.post_state_identity, RawSha256),
        )
        if self.format != "autodev.protected-effect-marker/v1":
            raise ValueError("unsupported protected effect marker format")
        if any(type(value) is not expected for value, expected in exact):
            raise TypeError("protected effect marker preimage has wrong exact type")
        if type(self.effect_subject) not in (
            PublishedCandidateRefEffectSubject, CreatedCandidatePrEffectSubject,
            FastForwardMergeEffectSubject,
        ):
            raise TypeError("marker effect subject is outside the closed domain")
        if (self.prerequisite_marker_id is not None
                and type(self.prerequisite_marker_id) is not ProtectedEffectMarkerId):
            raise TypeError("prerequisite marker identity has wrong exact type")
        if self.runtime_generation < 1:
            raise ValueError("runtime generation must be positive")


@dataclass(frozen=True, slots=True)
class ProtectedEffectMarker:
    marker_id: ProtectedEffectMarkerId
    preimage: ProtectedEffectMarkerPreimage

    def __post_init__(self) -> None:
        if (type(self.marker_id) is not ProtectedEffectMarkerId
                or type(self.preimage) is not ProtectedEffectMarkerPreimage):
            raise TypeError("marker fields have wrong exact type")
        expected = ProtectedEffectMarkerId(
            RawSha256(hashlib.sha256(canonical_json_bytes(self.preimage)).hexdigest())
        )
        if self.marker_id != expected:
            raise ValueError("marker identity does not match canonical content")


def build_protected_effect_marker(
    preimage: ProtectedEffectMarkerPreimage,
) -> ProtectedEffectMarker:
    identity = ProtectedEffectMarkerId(
        RawSha256(hashlib.sha256(canonical_json_bytes(preimage)).hexdigest())
    )
    return ProtectedEffectMarker(identity, preimage)
