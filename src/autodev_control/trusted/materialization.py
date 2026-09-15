"""Deterministic fixture candidate materialization from Git object truth."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib

from .identity import (
    CandidateMaterializationId, GitObjectObservationBindingId, GitSha,
    ImmutableConfigId, MutationInventoryId,
)
from .operation import AdmissionEventId, CandidateId, OperationId
from .scope import (
    AuthorizationId, CanonicalBranchRef, CanonicalGitPath, ChangeType, ContractId,
    ExactPathSelector, GitHubRepositoryId, MutationScope, MutationScopeRule,
    TargetRegistrationId, TaskId,
    scope_contains, scopes_overlap,
)
from .identity import RawSha256
from .manifest import PolicyEpochIdentity


def _canonical_json_bytes(value: object) -> bytes:
    """Avoid a module-import cycle: G6 imports admitted materialization types."""
    from .backend import canonical_json_bytes
    return canonical_json_bytes(value)


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
        expected = MutationInventoryId(RawSha256(hashlib.sha256(_canonical_json_bytes(
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
            hashlib.sha256(_canonical_json_bytes(preimage)).hexdigest()
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
    digest = RawSha256(hashlib.sha256(_canonical_json_bytes(preimage)).hexdigest())
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
        RawSha256(hashlib.sha256(_canonical_json_bytes(preimage)).hexdigest())
    )
    branch = CanonicalBranchRef(f"refs/heads/autodev/candidates/{identity.raw_sha256.value}")
    return CandidateMaterialization(
        identity, candidate_id, base, commit, parent_commits, inventory, branch,
        repository_id, task_id, contract_id, contract_raw_sha256, authorization_id,
        target_registration_id, policy_epoch_identity, base_tree_id, result_tree_id,
        materialization_profile_id,
    )


# Issue #30 candidate truth.  The older CandidateMaterialization above remains
# a non-authoritative proposal/diagnostic value: none of the following trusted
# admission code accepts its tree entries or inventory as input.
MAX_TREE_DEPTH = 32
MAX_TREE_OBJECTS = 4096
MAX_LEAF_ENTRIES = 16384
MAX_OBJECT_OBSERVATIONS = 32768
MAX_CANONICAL_PATH_BYTES = 4096
MAX_TOTAL_NORMALIZED_PATH_BYTES = 1_048_576


class CandidateMaterializationAdmissionStatus(Enum):
    ADMITTED = "ADMITTED"
    DENIED = "DENIED"
    INDETERMINATE = "INDETERMINATE"


class CandidateMaterializationAdmissionReason(Enum):
    ADMITTED = "ADMITTED"
    REPOSITORY_MISMATCH = "REPOSITORY_MISMATCH"
    TASK_BINDING_MISMATCH = "TASK_BINDING_MISMATCH"
    CONTRACT_BINDING_MISMATCH = "CONTRACT_BINDING_MISMATCH"
    AUTHORIZATION_BINDING_MISMATCH = "AUTHORIZATION_BINDING_MISMATCH"
    TARGET_BINDING_MISMATCH = "TARGET_BINDING_MISMATCH"
    POLICY_BINDING_MISMATCH = "POLICY_BINDING_MISMATCH"
    INVALID_PARENT_TOPOLOGY = "INVALID_PARENT_TOPOLOGY"
    BASE_PARENT_MISMATCH = "BASE_PARENT_MISMATCH"
    TREE_OBJECT_UNSUPPORTED = "TREE_OBJECT_UNSUPPORTED"
    TREE_MODE_UNSUPPORTED = "TREE_MODE_UNSUPPORTED"
    TREE_PATH_INVALID = "TREE_PATH_INVALID"
    TREE_PATH_DUPLICATE = "TREE_PATH_DUPLICATE"
    OBSERVATION_LIMIT_EXCEEDED = "OBSERVATION_LIMIT_EXCEEDED"
    MATERIALIZATION_IDENTITY_MISMATCH = "MATERIALIZATION_IDENTITY_MISMATCH"
    BASE_COMMIT_UNAVAILABLE = "BASE_COMMIT_UNAVAILABLE"
    CANDIDATE_COMMIT_UNAVAILABLE = "CANDIDATE_COMMIT_UNAVAILABLE"
    BASE_TREE_UNAVAILABLE = "BASE_TREE_UNAVAILABLE"
    CANDIDATE_TREE_UNAVAILABLE = "CANDIDATE_TREE_UNAVAILABLE"
    TREE_OBJECT_UNAVAILABLE = "TREE_OBJECT_UNAVAILABLE"
    TREE_ENUMERATION_INCOMPLETE = "TREE_ENUMERATION_INCOMPLETE"
    OBSERVATION_PROVIDER_FAILURE = "OBSERVATION_PROVIDER_FAILURE"
    OBSERVATION_CONFLICT = "OBSERVATION_CONFLICT"


@dataclass(frozen=True, slots=True)
class FixtureGitCommit:
    commit_id: GitSha
    parents: tuple[GitSha, ...]
    tree_id: GitSha

    def __post_init__(self) -> None:
        if type(self.commit_id) is not GitSha or type(self.tree_id) is not GitSha:
            raise TypeError("fixture commit identities must be exact GitSha values")
        if type(self.parents) is not tuple or any(type(value) is not GitSha for value in self.parents):
            raise TypeError("fixture commit parents must be an exact GitSha tuple")


@dataclass(frozen=True, slots=True)
class FixtureGitTreeEntry:
    name: str
    object_kind: GitObjectKind
    mode: str
    object_id: GitSha

    def __post_init__(self) -> None:
        if type(self.name) is not str or type(self.object_kind) is not GitObjectKind or type(self.mode) is not str or type(self.object_id) is not GitSha:
            raise TypeError("fixture tree entry fields have wrong exact type")


@dataclass(frozen=True, slots=True)
class FixtureGitTree:
    tree_id: GitSha
    entries: tuple[FixtureGitTreeEntry, ...]

    def __post_init__(self) -> None:
        if type(self.tree_id) is not GitSha or type(self.entries) is not tuple or any(type(value) is not FixtureGitTreeEntry for value in self.entries):
            raise TypeError("fixture tree fields have wrong exact type")


@dataclass(frozen=True, slots=True)
class FixtureGitObjectStore:
    """Immutable fixture-only substrate for trusted exhaustive object reads."""

    repository_id: GitHubRepositoryId
    commits: tuple[FixtureGitCommit, ...]
    trees: tuple[FixtureGitTree, ...]
    unavailable_object_ids: frozenset[GitSha] = frozenset()
    provider_failure: bool = False
    observation_instance_id: RawSha256 = RawSha256("0" * 64)

    def __post_init__(self) -> None:
        if type(self.repository_id) is not GitHubRepositoryId or type(self.commits) is not tuple or type(self.trees) is not tuple:
            raise TypeError("fixture object store has wrong exact type")
        if any(type(value) is not FixtureGitCommit for value in self.commits) or any(type(value) is not FixtureGitTree for value in self.trees):
            raise TypeError("fixture object store values have wrong exact type")
        if len({value.commit_id for value in self.commits}) != len(self.commits) or len({value.tree_id for value in self.trees}) != len(self.trees):
            raise ValueError("fixture object identities must be unique")
        if type(self.unavailable_object_ids) is not frozenset or any(type(value) is not GitSha for value in self.unavailable_object_ids) or type(self.provider_failure) is not bool or type(self.observation_instance_id) is not RawSha256:
            raise TypeError("fixture object store availability fields have wrong exact type")

    def commit(self, identity: GitSha) -> FixtureGitCommit | None:
        if self.provider_failure or identity in self.unavailable_object_ids:
            return None
        return next((value for value in self.commits if value.commit_id == identity), None)

    def tree(self, identity: GitSha) -> FixtureGitTree | None:
        if self.provider_failure or identity in self.unavailable_object_ids:
            return None
        return next((value for value in self.trees if value.tree_id == identity), None)


@dataclass(frozen=True, slots=True, init=False)
class TrustedCandidateMaterializationContext:
    repository_id: GitHubRepositoryId
    task_id: TaskId
    contract_id: ContractId
    contract_raw_sha256: RawSha256
    authorization_id: AuthorizationId
    target_registration_id: TargetRegistrationId
    policy_epoch_identity: PolicyEpochIdentity
    base_commit: GitSha

    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("candidate-materialization context must come from canonical trusted state")


@dataclass(frozen=True, slots=True, init=False)
class AdmittedCandidateMaterialization:
    materialization_id: CandidateMaterializationId
    repository_id: GitHubRepositoryId
    task_id: TaskId
    candidate_id: CandidateId
    contract_id: ContractId
    contract_raw_sha256: RawSha256
    authorization_id: AuthorizationId
    target_registration_id: TargetRegistrationId
    policy_epoch_identity: PolicyEpochIdentity
    base_commit: GitSha
    candidate_commit: GitSha
    base_tree: GitSha
    result_tree: GitSha
    parent_commits: tuple[GitSha, ...]
    mutation_inventory: MutationInventory

    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("admitted materialization may only be constructed by trusted admission")

    @property
    def base(self) -> GitSha:
        return self.base_commit

    @property
    def commit(self) -> GitSha:
        return self.candidate_commit

    @property
    def inventory(self) -> MutationInventory:
        return self.mutation_inventory

    @property
    def candidate_branch(self) -> CanonicalBranchRef:
        return CanonicalBranchRef(
            f"refs/heads/autodev/candidates/{self.materialization_id.raw_sha256.value}"
        )


@dataclass(frozen=True, slots=True)
class CandidateMaterializationAdmissionResult:
    status: CandidateMaterializationAdmissionStatus
    reason: CandidateMaterializationAdmissionReason
    admitted_materialization: AdmittedCandidateMaterialization | None
    git_object_observation_binding_id: GitObjectObservationBindingId | None

    def __post_init__(self) -> None:
        if type(self.status) is not CandidateMaterializationAdmissionStatus or type(self.reason) is not CandidateMaterializationAdmissionReason:
            raise TypeError("admission result has wrong exact status or reason")
        if self.admitted_materialization is not None and type(self.admitted_materialization) is not AdmittedCandidateMaterialization:
            raise TypeError("admitted materialization has wrong exact type")
        if self.git_object_observation_binding_id is not None and type(self.git_object_observation_binding_id) is not GitObjectObservationBindingId:
            raise TypeError("observation binding has wrong exact type")
        if self.status is CandidateMaterializationAdmissionStatus.ADMITTED:
            if self.admitted_materialization is None or self.git_object_observation_binding_id is None:
                raise ValueError("admitted candidate materialization requires complete observation")
        elif self.admitted_materialization is not None:
            raise ValueError("non-admitted result cannot carry materialization")


def _admission_result(status: CandidateMaterializationAdmissionStatus, reason: CandidateMaterializationAdmissionReason, binding: GitObjectObservationBindingId | None = None, materialization: AdmittedCandidateMaterialization | None = None) -> CandidateMaterializationAdmissionResult:
    return CandidateMaterializationAdmissionResult(status, reason, materialization, binding)


def _normal_leaf_tree(store: FixtureGitObjectStore, root: GitSha, unavailable_reason: CandidateMaterializationAdmissionReason) -> tuple[CandidateMaterializationAdmissionReason | None, tuple[GitTreeEntry, ...]]:
    """Trusted bounded recursive traversal; callers never supply leaf entries."""
    leaves: dict[str, GitTreeEntry] = {}
    seen_trees: set[GitSha] = set()
    observations = 0
    total_path_bytes = 0

    def walk(tree_id: GitSha, prefix: str, depth: int) -> CandidateMaterializationAdmissionReason | None:
        nonlocal observations, total_path_bytes
        if depth > MAX_TREE_DEPTH:
            return CandidateMaterializationAdmissionReason.OBSERVATION_LIMIT_EXCEEDED
        if tree_id in seen_trees:
            return CandidateMaterializationAdmissionReason.OBSERVATION_CONFLICT
        seen_trees.add(tree_id)
        observations += 1
        if observations > MAX_OBJECT_OBSERVATIONS or len(seen_trees) > MAX_TREE_OBJECTS:
            return CandidateMaterializationAdmissionReason.OBSERVATION_LIMIT_EXCEEDED
        tree = store.tree(tree_id)
        if tree is None:
            return unavailable_reason if tree_id == root else CandidateMaterializationAdmissionReason.TREE_OBJECT_UNAVAILABLE
        for entry in tree.entries:
            observations += 1
            if observations > MAX_OBJECT_OBSERVATIONS:
                return CandidateMaterializationAdmissionReason.OBSERVATION_LIMIT_EXCEEDED
            if not entry.name or entry.name in (".", "..") or "/" in entry.name or "\\" in entry.name or "\x00" in entry.name:
                return CandidateMaterializationAdmissionReason.TREE_PATH_INVALID
            path = entry.name if not prefix else f"{prefix}/{entry.name}"
            try:
                canonical = CanonicalGitPath(path)
            except (TypeError, ValueError):
                return CandidateMaterializationAdmissionReason.TREE_PATH_INVALID
            path_bytes = len(canonical.value.encode("utf-8"))
            if path_bytes > MAX_CANONICAL_PATH_BYTES:
                return CandidateMaterializationAdmissionReason.OBSERVATION_LIMIT_EXCEEDED
            if entry.object_kind is GitObjectKind.TREE:
                if entry.mode != "040000":
                    return CandidateMaterializationAdmissionReason.TREE_MODE_UNSUPPORTED
                result = walk(entry.object_id, canonical.value, depth + 1)
                if result is not None:
                    return result
                continue
            if entry.object_kind is not GitObjectKind.BLOB:
                return CandidateMaterializationAdmissionReason.TREE_OBJECT_UNSUPPORTED
            if entry.mode not in ("100644", "100755"):
                return CandidateMaterializationAdmissionReason.TREE_MODE_UNSUPPORTED
            if canonical.value in leaves:
                return CandidateMaterializationAdmissionReason.TREE_PATH_DUPLICATE
            leaves[canonical.value] = GitTreeEntry(canonical, entry.object_kind, entry.mode, entry.object_id)
            total_path_bytes += path_bytes
            if len(leaves) > MAX_LEAF_ENTRIES or total_path_bytes > MAX_TOTAL_NORMALIZED_PATH_BYTES:
                return CandidateMaterializationAdmissionReason.OBSERVATION_LIMIT_EXCEEDED
        return None

    result = walk(root, "", 1)
    return result, tuple(leaves[path] for path in sorted(leaves))


def _admitted_materialization(context: TrustedCandidateMaterializationContext, candidate_id: CandidateId, candidate_commit: FixtureGitCommit, base_commit: FixtureGitCommit, base_entries: tuple[GitTreeEntry, ...], candidate_entries: tuple[GitTreeEntry, ...]) -> AdmittedCandidateMaterialization:
    inventory = derive_mutation_inventory(base_entries, candidate_entries)
    preimage = (
        "autodev.admitted-candidate-materialization/v1", context.repository_id,
        context.task_id, candidate_id, context.contract_id,
        context.contract_raw_sha256, context.authorization_id,
        context.target_registration_id, context.policy_epoch_identity,
        context.base_commit, candidate_commit.commit_id, base_commit.tree_id,
        candidate_commit.tree_id, candidate_commit.parents, inventory.inventory_id,
    )
    identity = CandidateMaterializationId(RawSha256(hashlib.sha256(_canonical_json_bytes(preimage)).hexdigest()))
    result = object.__new__(AdmittedCandidateMaterialization)
    for name, value in (
        ("materialization_id", identity), ("repository_id", context.repository_id),
        ("task_id", context.task_id), ("candidate_id", candidate_id),
        ("contract_id", context.contract_id), ("contract_raw_sha256", context.contract_raw_sha256),
        ("authorization_id", context.authorization_id), ("target_registration_id", context.target_registration_id),
        ("policy_epoch_identity", context.policy_epoch_identity), ("base_commit", context.base_commit),
        ("candidate_commit", candidate_commit.commit_id), ("base_tree", base_commit.tree_id),
        ("result_tree", candidate_commit.tree_id), ("parent_commits", candidate_commit.parents),
        ("mutation_inventory", inventory),
    ):
        object.__setattr__(result, name, value)
    return result


def admitted_candidate_materialization_is_valid(value: object) -> bool:
    if type(value) is not AdmittedCandidateMaterialization:
        return False
    try:
        inventory = value.mutation_inventory
        if type(inventory) is not MutationInventory or value.parent_commits != (value.base_commit,):
            return False
        preimage = (
            "autodev.admitted-candidate-materialization/v1", value.repository_id,
            value.task_id, value.candidate_id, value.contract_id,
            value.contract_raw_sha256, value.authorization_id,
            value.target_registration_id, value.policy_epoch_identity,
            value.base_commit, value.candidate_commit, value.base_tree,
            value.result_tree, value.parent_commits, inventory.inventory_id,
        )
        expected = CandidateMaterializationId(RawSha256(hashlib.sha256(_canonical_json_bytes(preimage)).hexdigest()))
        return value.materialization_id == expected
    except (AttributeError, TypeError, ValueError):
        return False


def admit_candidate_materialization(*, store: FixtureGitObjectStore, context: TrustedCandidateMaterializationContext, candidate_id: CandidateId, candidate_commit_id: GitSha) -> CandidateMaterializationAdmissionResult:
    """Establish candidate truth solely from an exhaustive trusted object read."""
    if type(store) is not FixtureGitObjectStore or type(context) is not TrustedCandidateMaterializationContext or type(candidate_id) is not CandidateId or type(candidate_commit_id) is not GitSha:
        raise TypeError("exact trusted object store, context, candidate identity and commit required")
    if store.repository_id != context.repository_id:
        return _admission_result(CandidateMaterializationAdmissionStatus.DENIED, CandidateMaterializationAdmissionReason.REPOSITORY_MISMATCH)
    if store.provider_failure:
        return _admission_result(CandidateMaterializationAdmissionStatus.INDETERMINATE, CandidateMaterializationAdmissionReason.OBSERVATION_PROVIDER_FAILURE)
    base_commit = store.commit(context.base_commit)
    if base_commit is None:
        return _admission_result(CandidateMaterializationAdmissionStatus.INDETERMINATE, CandidateMaterializationAdmissionReason.BASE_COMMIT_UNAVAILABLE)
    candidate_commit = store.commit(candidate_commit_id)
    if candidate_commit is None:
        return _admission_result(CandidateMaterializationAdmissionStatus.INDETERMINATE, CandidateMaterializationAdmissionReason.CANDIDATE_COMMIT_UNAVAILABLE)
    base_reason, base_entries = _normal_leaf_tree(store, base_commit.tree_id, CandidateMaterializationAdmissionReason.BASE_TREE_UNAVAILABLE)
    if base_reason is not None:
        status = CandidateMaterializationAdmissionStatus.INDETERMINATE if base_reason in (CandidateMaterializationAdmissionReason.BASE_TREE_UNAVAILABLE, CandidateMaterializationAdmissionReason.TREE_OBJECT_UNAVAILABLE, CandidateMaterializationAdmissionReason.OBSERVATION_CONFLICT) else CandidateMaterializationAdmissionStatus.DENIED
        return _admission_result(status, base_reason)
    candidate_reason, candidate_entries = _normal_leaf_tree(store, candidate_commit.tree_id, CandidateMaterializationAdmissionReason.CANDIDATE_TREE_UNAVAILABLE)
    if candidate_reason is not None:
        status = CandidateMaterializationAdmissionStatus.INDETERMINATE if candidate_reason in (CandidateMaterializationAdmissionReason.CANDIDATE_TREE_UNAVAILABLE, CandidateMaterializationAdmissionReason.TREE_OBJECT_UNAVAILABLE, CandidateMaterializationAdmissionReason.OBSERVATION_CONFLICT) else CandidateMaterializationAdmissionStatus.DENIED
        return _admission_result(status, candidate_reason)
    binding_preimage = (
        "autodev.git-object-observation/v1", store.observation_instance_id, store.repository_id, context.base_commit,
        candidate_commit_id, base_commit.tree_id, candidate_commit.tree_id,
        RawSha256(hashlib.sha256(_canonical_json_bytes(base_entries)).hexdigest()),
        RawSha256(hashlib.sha256(_canonical_json_bytes(candidate_entries)).hexdigest()),
    )
    binding = GitObjectObservationBindingId(RawSha256(hashlib.sha256(_canonical_json_bytes(binding_preimage)).hexdigest()))
    if candidate_commit.parents != (context.base_commit,):
        reason = CandidateMaterializationAdmissionReason.INVALID_PARENT_TOPOLOGY if len(candidate_commit.parents) != 1 else CandidateMaterializationAdmissionReason.BASE_PARENT_MISMATCH
        return _admission_result(CandidateMaterializationAdmissionStatus.DENIED, reason, binding)
    materialization = _admitted_materialization(context, candidate_id, candidate_commit, base_commit, base_entries, candidate_entries)
    return _admission_result(CandidateMaterializationAdmissionStatus.ADMITTED, CandidateMaterializationAdmissionReason.ADMITTED, binding, materialization)


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


def create_admitted_candidate_record(
    *, materialization: AdmittedCandidateMaterialization,
    admission_event_id: AdmissionEventId,
    parent_candidate_ids: tuple[CandidateId, ...] = (),
    creation_operation_id: OperationId | None = None,
):
    """Bind a CandidateRecord to an already admitted exact C/M fact pair."""
    if type(materialization) is not AdmittedCandidateMaterialization:
        raise TypeError("exact admitted candidate materialization required")
    from .state import CandidateRecord
    return CandidateRecord(
        materialization.candidate_id, materialization.task_id,
        materialization.base_commit, materialization.contract_id,
        materialization.contract_raw_sha256, materialization.authorization_id,
        admission_event_id, materialization.target_registration_id,
        materialization.policy_epoch_identity, materialization.materialization_id,
        parent_candidate_ids, creation_operation_id,
    )
