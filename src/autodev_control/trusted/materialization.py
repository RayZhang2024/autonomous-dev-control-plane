"""Deterministic fixture candidate materialization from Git object truth."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib

from .backend import canonical_json_bytes
from .identity import CandidateMaterializationId, GitSha, ImmutableConfigId, MutationInventoryId
from .operation import AdmissionEventId, CandidateId, OperationId
from .scope import (
    AuthorizationId, CanonicalBranchRef, CanonicalGitPath, ChangeType, ContractId,
    ExactPathSelector, GitHubRepositoryId, MutationScope, MutationScopeRule,
    TargetRegistrationId, TaskId,
    scope_contains, scopes_overlap,
)
from .identity import RawSha256
from .manifest import PolicyEpochIdentity


class GitObjectKind(Enum):
    BLOB = "blob"
    TREE = "tree"
    SYMLINK = "symlink"
    GITLINK = "gitlink"


class GitBlobMode(Enum):
    REGULAR = "100644"
    EXECUTABLE = "100755"


class MutationKind(Enum):
    ADDED = "ADDED"
    MODIFIED = "MODIFIED"
    DELETED = "DELETED"


@dataclass(frozen=True, slots=True)
class GitTreeEntry:
    path: CanonicalGitPath
    object_kind: GitObjectKind
    mode: str
    object_id: GitSha

    def __post_init__(self) -> None:
        if type(self.path) is not CanonicalGitPath or type(self.object_kind) is not GitObjectKind:
            raise TypeError("tree entry identity has wrong exact type")
        if type(self.mode) is not str or type(self.object_id) is not GitSha:
            raise TypeError("tree entry value has wrong exact type")


@dataclass(frozen=True, slots=True)
class MutationFact:
    path: CanonicalGitPath
    kind: MutationKind
    base_object_id: GitSha | None
    candidate_object_id: GitSha | None
    base_mode: GitBlobMode | None
    candidate_mode: GitBlobMode | None

    def __post_init__(self) -> None:
        if type(self.path) is not CanonicalGitPath or type(self.kind) is not MutationKind:
            raise TypeError("mutation identity has wrong exact type")
        for value in (self.base_object_id, self.candidate_object_id):
            if value is not None and type(value) is not GitSha:
                raise TypeError("mutation object id has wrong exact type")
        for value in (self.base_mode, self.candidate_mode):
            if value is not None and type(value) is not GitBlobMode:
                raise TypeError("mutation mode has wrong exact type")
        if self.kind is MutationKind.ADDED and (self.base_object_id is not None or self.candidate_object_id is None):
            raise ValueError("added mutation has inconsistent objects")
        if self.kind is MutationKind.DELETED and (self.base_object_id is None or self.candidate_object_id is not None):
            raise ValueError("deleted mutation has inconsistent objects")
        if self.kind is MutationKind.MODIFIED and (self.base_object_id is None or self.candidate_object_id is None):
            raise ValueError("modified mutation requires both objects")


@dataclass(frozen=True, slots=True)
class MutationInventory:
    inventory_id: MutationInventoryId
    mutations: tuple[MutationFact, ...]

    def __post_init__(self) -> None:
        if type(self.inventory_id) is not MutationInventoryId or type(self.mutations) is not tuple:
            raise TypeError("inventory has wrong exact type")
        if any(type(item) is not MutationFact for item in self.mutations):
            raise TypeError("inventory item has wrong exact type")
        paths = tuple(item.path.value for item in self.mutations)
        if paths != tuple(sorted(paths)) or len(paths) != len(set(paths)):
            raise ValueError("inventory paths must be unique and canonical-order sorted")
        expected = MutationInventoryId(RawSha256(hashlib.sha256(canonical_json_bytes(
            MutationInventoryPreimage("autodev.mutation-inventory/v1", self.mutations)
        )).hexdigest()))
        if self.inventory_id != expected:
            raise ValueError("inventory identity does not match canonical content")


@dataclass(frozen=True, slots=True)
class MutationInventoryPreimage:
    format: str
    mutations: tuple[MutationFact, ...]


@dataclass(frozen=True, slots=True)
class CandidateMaterialization:
    materialization_id: CandidateMaterializationId
    candidate_id: CandidateId
    base: GitSha
    commit: GitSha
    parent_commits: tuple[GitSha, ...]
    inventory: MutationInventory
    candidate_branch: CanonicalBranchRef
    repository_id: GitHubRepositoryId
    task_id: TaskId
    contract_id: ContractId
    contract_raw_sha256: RawSha256
    authorization_id: AuthorizationId
    target_registration_id: TargetRegistrationId
    policy_epoch_identity: PolicyEpochIdentity
    base_tree: GitSha
    result_tree: GitSha
    materialization_profile_id: ImmutableConfigId

    def __post_init__(self) -> None:
        exact = (
            (self.materialization_id, CandidateMaterializationId),
            (self.candidate_id, CandidateId), (self.base, GitSha),
            (self.commit, GitSha), (self.inventory, MutationInventory),
            (self.candidate_branch, CanonicalBranchRef),
            (self.repository_id, GitHubRepositoryId), (self.task_id, TaskId),
            (self.contract_id, ContractId),
            (self.contract_raw_sha256, RawSha256),
            (self.authorization_id, AuthorizationId),
            (self.target_registration_id, TargetRegistrationId),
            (self.policy_epoch_identity, PolicyEpochIdentity),
            (self.base_tree, GitSha), (self.result_tree, GitSha),
            (self.materialization_profile_id, ImmutableConfigId),
        )
        if any(type(v) is not t for v, t in exact) or type(self.parent_commits) is not tuple:
            raise TypeError("materialization field has wrong exact type")
        if any(type(item) is not GitSha for item in self.parent_commits):
            raise TypeError("parent commits must be exact GitSha values")
        if self.parent_commits != (self.base,):
            raise ValueError("initial candidate commit must have exactly the base parent")
        preimage = CandidateMaterializationPreimage(
            "autodev.candidate-materialization/v1", self.repository_id,
            self.task_id, self.candidate_id, self.contract_id,
            self.contract_raw_sha256, self.authorization_id,
            self.target_registration_id, self.policy_epoch_identity, self.base,
            self.base_tree, self.commit, self.result_tree, self.parent_commits,
            self.inventory.inventory_id, self.materialization_profile_id,
        )
        expected_identity = CandidateMaterializationId(RawSha256(
            hashlib.sha256(canonical_json_bytes(preimage)).hexdigest()
        ))
        if self.materialization_id != expected_identity:
            raise ValueError("materialization identity does not match canonical content")
        expected = f"refs/heads/autodev/candidates/{self.materialization_id.raw_sha256.value}"
        if self.candidate_branch.value != expected:
            raise ValueError("candidate branch is not derived from materialization identity")


@dataclass(frozen=True, slots=True)
class CandidateMaterializationPreimage:
    format: str
    repository_id: GitHubRepositoryId
    task_id: TaskId
    candidate_id: CandidateId
    contract_id: ContractId
    contract_raw_sha256: RawSha256
    authorization_id: AuthorizationId
    target_registration_id: TargetRegistrationId
    policy_epoch_identity: PolicyEpochIdentity
    base_commit: GitSha
    base_tree: GitSha
    result_commit: GitSha
    result_tree: GitSha
    parent_commits: tuple[GitSha, ...]
    mutation_inventory_id: MutationInventoryId
    materialization_profile_id: ImmutableConfigId


def _tree(entries: tuple[GitTreeEntry, ...]) -> dict[str, tuple[GitSha, GitBlobMode]]:
    if type(entries) is not tuple:
        raise TypeError("tree entries must be exactly tuple")
    result: dict[str, tuple[GitSha, GitBlobMode]] = {}
    for entry in entries:
        if type(entry) is not GitTreeEntry:
            raise TypeError("tree entry has wrong exact type")
        if entry.object_kind is not GitObjectKind.BLOB or entry.mode not in ("100644", "100755"):
            raise ValueError("unsupported tree entry kind or mode")
        if entry.path.value in result:
            raise ValueError("duplicate tree path")
        result[entry.path.value] = (entry.object_id, GitBlobMode(entry.mode))
    return result


def derive_mutation_inventory(
    base_tree: tuple[GitTreeEntry, ...], candidate_tree: tuple[GitTreeEntry, ...]
) -> MutationInventory:
    """Derive per-path facts; rename-like changes remain a deletion plus an addition."""
    before, after = _tree(base_tree), _tree(candidate_tree)
    facts: list[MutationFact] = []
    for path in sorted(before.keys() | after.keys()):
        old, new = before.get(path), after.get(path)
        if old == new:
            continue
        if old is None:
            facts.append(MutationFact(CanonicalGitPath(path), MutationKind.ADDED, None, new[0], None, new[1]))
        elif new is None:
            facts.append(MutationFact(CanonicalGitPath(path), MutationKind.DELETED, old[0], None, old[1], None))
        else:
            facts.append(MutationFact(CanonicalGitPath(path), MutationKind.MODIFIED, old[0], new[0], old[1], new[1]))
    preimage = MutationInventoryPreimage("autodev.mutation-inventory/v1", tuple(facts))
    digest = RawSha256(hashlib.sha256(canonical_json_bytes(preimage)).hexdigest())
    return MutationInventory(MutationInventoryId(digest), tuple(facts))


def build_candidate_materialization(
    *, repository_id: GitHubRepositoryId, task_id: TaskId,
    candidate_id: CandidateId, contract_id: ContractId,
    contract_raw_sha256: RawSha256, authorization_id: AuthorizationId,
    target_registration_id: TargetRegistrationId,
    policy_epoch_identity: PolicyEpochIdentity,
    base: GitSha, base_tree_id: GitSha, commit: GitSha, result_tree_id: GitSha,
    parent_commits: tuple[GitSha, ...], base_tree: tuple[GitTreeEntry, ...],
    candidate_tree: tuple[GitTreeEntry, ...], materialization_profile_id: ImmutableConfigId,
) -> CandidateMaterialization:
    inventory = derive_mutation_inventory(base_tree, candidate_tree)
    preimage = CandidateMaterializationPreimage(
        "autodev.candidate-materialization/v1", repository_id, task_id, candidate_id,
        contract_id, contract_raw_sha256, authorization_id, target_registration_id,
        policy_epoch_identity, base, base_tree_id, commit, result_tree_id,
        parent_commits, inventory.inventory_id, materialization_profile_id,
    )
    identity = CandidateMaterializationId(
        RawSha256(hashlib.sha256(canonical_json_bytes(preimage)).hexdigest())
    )
    branch = CanonicalBranchRef(f"refs/heads/autodev/candidates/{identity.raw_sha256.value}")
    return CandidateMaterialization(
        identity, candidate_id, base, commit, parent_commits, inventory, branch,
        repository_id, task_id, contract_id, contract_raw_sha256, authorization_id,
        target_registration_id, policy_epoch_identity, base_tree_id, result_tree_id,
        materialization_profile_id,
    )


def mutation_inventory_scope(inventory: MutationInventory) -> MutationScope:
    if type(inventory) is not MutationInventory:
        raise TypeError("exact MutationInventory required")
    rules: list[MutationScopeRule] = []
    for fact in inventory.mutations:
        if fact.kind is MutationKind.ADDED:
            changes = (ChangeType.ADD,)
        elif fact.kind is MutationKind.DELETED:
            changes = (ChangeType.DELETE,)
        else:
            values: list[ChangeType] = []
            if fact.base_object_id != fact.candidate_object_id:
                values.append(ChangeType.MODIFY)
            if fact.base_mode != fact.candidate_mode:
                values.append(ChangeType.MODE_CHANGE)
            changes = tuple(values)
        rules.append(MutationScopeRule(ExactPathSelector(fact.path), changes))
    return MutationScope(tuple(rules))


def inventory_is_authorized(inventory: MutationInventory, authorized: MutationScope,
                            forbidden_root: MutationScope) -> bool:
    actual = mutation_inventory_scope(inventory)
    return scope_contains(authorized, actual) and not scopes_overlap(actual, forbidden_root)


def create_materialized_candidate_record(
    *, materialization: CandidateMaterialization, task_id: TaskId,
    contract_id: ContractId, contract_raw_sha256: RawSha256,
    authorization_id: AuthorizationId, admission_event_id: AdmissionEventId,
    target_registration_id: TargetRegistrationId,
    policy_epoch_identity: PolicyEpochIdentity,
    parent_candidate_ids: tuple[CandidateId, ...] = (),
    creation_operation_id: OperationId | None = None,
):
    """Create the first CandidateRecord only after exact materialization exists."""
    if type(materialization) is not CandidateMaterialization:
        raise TypeError("exact verified CandidateMaterialization required")
    if (
        task_id != materialization.task_id
        or contract_id != materialization.contract_id
        or contract_raw_sha256 != materialization.contract_raw_sha256
        or authorization_id != materialization.authorization_id
        or target_registration_id != materialization.target_registration_id
        or policy_epoch_identity != materialization.policy_epoch_identity
    ):
        raise ValueError("candidate metadata does not match exact materialization")
    from .state import CandidateRecord
    return CandidateRecord(
        materialization.candidate_id, task_id, materialization.base, contract_id,
        contract_raw_sha256, authorization_id, admission_event_id,
        target_registration_id, policy_epoch_identity, materialization.materialization_id,
        parent_candidate_ids, creation_operation_id,
    )
