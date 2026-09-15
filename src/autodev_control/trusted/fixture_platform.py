"""One-lock fixture-only Git platform used to exercise G7 gate semantics."""

from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
from threading import RLock

from .backend import canonical_json_bytes
from .identity import (
    CandidateMaterializationId, GitRef, GitSha, MutationInventoryId,
    PreparedProtectedStartId, ProtectedEffectMarkerId, RawSha256, RootContextId,
)
from .materialization import AdmittedCandidateMaterialization, CandidateMaterialization, GitTreeEntry, derive_mutation_inventory
from .operation import (
    AuthoritativeStateBindingId, OperationActionId, OperationId,
    OperationIdempotencyKey,
)
from .scope import CanonicalBranchRef, GitHubRepositoryId
from .scope import ServicePrincipalId
from .state_reader import (
    AuthoritativeStateSnapshot, GitHubPullRequestNumber,
    authoritative_state_binding,
)


@dataclass(frozen=True, slots=True)
class FixturePullRequest:
    number: int
    repository_id: GitHubRepositoryId
    head: CanonicalBranchRef
    base: CanonicalBranchRef
    head_sha: GitSha
    base_sha: GitSha
    merged: bool = False


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


EffectSubject = PublishedCandidateRefEffectSubject | CreatedCandidatePrEffectSubject | FastForwardMergeEffectSubject


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
        if type(self.marker_id) is not ProtectedEffectMarkerId or type(self.preimage) is not ProtectedEffectMarkerPreimage:
            raise TypeError("marker fields have wrong exact type")
        expected = ProtectedEffectMarkerId(RawSha256(hashlib.sha256(canonical_json_bytes(self.preimage)).hexdigest()))
        if self.marker_id != expected:
            raise ValueError("marker identity does not match canonical content")


def build_protected_effect_marker(preimage: ProtectedEffectMarkerPreimage) -> ProtectedEffectMarker:
    identity = ProtectedEffectMarkerId(RawSha256(hashlib.sha256(canonical_json_bytes(preimage)).hexdigest()))
    return ProtectedEffectMarker(identity, preimage)


@dataclass(frozen=True, slots=True)
class FixturePlatformSnapshot:
    generation: int
    refs: tuple[tuple[GitHubRepositoryId, CanonicalBranchRef, GitSha], ...]
    pull_requests: tuple[FixturePullRequest, ...]
    markers: tuple[ProtectedEffectMarker, ...]
    prepared_effects: tuple[tuple[str, str, str], ...]


class FixtureFenceConflict(RuntimeError):
    pass


class FixtureFenceToken:
    __slots__ = ("owner", "facts", "active")

    def __init__(self, owner: object, facts: frozenset[tuple]) -> None:
        self.owner, self.facts, self.active = owner, facts, True


class ActiveFixtureRuntimeRegistry:
    """Shared root/runtime authority and cross-store synchronization substrate."""

    __slots__ = ("lock", "_active", "_live")

    def __init__(self) -> None:
        self.lock = RLock()
        self._active: tuple[RootContextId, int, object, object, object] | None = None
        self._live: set[FixtureFenceToken] = set()

    def activate(self, root: RootContextId, generation: int, control: object,
                 publication: object, merge: object) -> bool:
        if type(root) is not RootContextId or type(generation) is not int or generation < 1:
            raise TypeError("active root/runtime identity has wrong exact type")
        if len({id(control), id(publication), id(merge)}) != 3:
            raise ValueError("active gate runtimes must be pairwise distinct")
        with self.lock:
            if self._live:
                return False
            if self._active is not None and generation <= self._active[1]:
                return False
            self._active = root, generation, control, publication, merge
            return True

    def restart(self, root: RootContextId, generation: int,
                previous: tuple[object, object, object], control: object,
                publication: object, merge: object) -> bool:
        """Rotate process bindings without changing root or fixture generation."""
        with self.lock:
            if self._live or self._active != (root, generation, *previous):
                return False
            self._active = root, generation, control, publication, merge
            return True

    def is_active(self, root: RootContextId, generation: int, control: object,
                  publication: object, merge: object) -> bool:
        with self.lock:
            return self._active == (root, generation, control, publication, merge)

    @property
    def has_active_runtime(self) -> bool:
        with self.lock:
            return self._active is not None

    def acquire(self, owner: object, facts: frozenset[tuple]) -> FixtureFenceToken | None:
        with self.lock:
            if self._active is None:
                return None
            token = FixtureFenceToken(owner, facts)
            self._live.add(token)
            return token

    def release(self, token: FixtureFenceToken) -> None:
        with self.lock:
            if token in self._live and token.active:
                token.active = False
                self._live.remove(token)

    def retire_owner_for_restart(self, owner: object) -> None:
        """Model process loss: ephemeral authorities owned by that runtime vanish."""
        with self.lock:
            for token in tuple(self._live):
                if token.owner is owner:
                    token.active = False
                    self._live.remove(token)

    def assert_mutation_allowed(self, fact: tuple, token: FixtureFenceToken | None = None) -> None:
        for live in self._live:
            if live is not token and fact in live.facts:
                raise FixtureFenceConflict("authoritative fixture fact is fenced by a live lease")


class FixtureGitPlatform:
    """Authoritative fixture state. It performs no network or provider calls."""

    __slots__ = ("_lock", "_registry", "_generation", "_refs", "_prs", "_markers", "_prepared", "_commits", "_authoritative", "_fail_next_effect")

    def __init__(self) -> None:
        self._registry: ActiveFixtureRuntimeRegistry | None = None
        self._lock = RLock()
        self._generation = 1
        self._refs: dict[tuple[GitHubRepositoryId, CanonicalBranchRef], GitSha] = {}
        self._prs: list[FixturePullRequest] = []
        self._markers: dict[tuple[OperationId, str], ProtectedEffectMarker] = {}
        self._prepared: dict[tuple[OperationId, str], tuple[object | None, str]] = {}
        self._commits: dict[GitSha, tuple[tuple[GitSha, ...], GitSha, tuple[GitTreeEntry, ...]]] = {}
        self._authoritative: dict[tuple[GitHubRepositoryId, object, object], AuthoritativeStateSnapshot] = {}
        self._fail_next_effect = False

    def fail_next_effect_for_test(self) -> None:
        with self._lock:
            self._fail_next_effect = True

    def _consume_effect_failure(self) -> bool:
        if self._fail_next_effect:
            self._fail_next_effect = False
            return True
        return False

    def attach_registry(self, registry: ActiveFixtureRuntimeRegistry) -> None:
        if type(registry) is not ActiveFixtureRuntimeRegistry:
            raise TypeError("exact ActiveFixtureRuntimeRegistry required")
        if self._registry is not None and self._registry is not registry:
            raise ValueError("fixture platform is already attached to another runtime registry")
        self._registry, self._lock = registry, registry.lock

    def _guard(self, fact: tuple, token: FixtureFenceToken | None = None) -> None:
        if self._registry is not None:
            self._registry.assert_mutation_allowed(fact, token)

    def snapshot(self) -> FixturePlatformSnapshot:
        with self._lock:
            refs = tuple(sorted(((r, b, s) for (r, b), s in self._refs.items()), key=lambda x: (x[0].value, x[1].value)))
            prepared = tuple(
                (key[0].value, key[1], value[1])
                for key, value in sorted(self._prepared.items(), key=lambda item: (item[0][0].value, item[0][1]))
            )
            return FixturePlatformSnapshot(self._generation, refs, tuple(self._prs), tuple(self._markers.values()), prepared)

    def prepare_effect(self, operation_id: OperationId, gate_action: str, *, _fence_token: FixtureFenceToken | None = None) -> None:
        with self._lock:
            self._guard(("prepared", operation_id, gate_action), _fence_token)
            key = operation_id, gate_action
            if key in self._markers:
                raise ValueError("completed effect cannot return to PREPARED")
            current = self._prepared.setdefault(key, (None, "PREPARED"))
            if current[1] != "PREPARED":
                raise ValueError("terminal prepared state cannot return to PREPARED")
            self._generation += 1

    def persist_prepared_effect(self, operation_id: OperationId, gate_action: str,
                                prepared: object, *,
                                _fence_token: FixtureFenceToken) -> None:
        """Durably persist the exact gate-private prepared record before G6 start."""
        with self._lock:
            self._guard(("prepared", operation_id, gate_action), _fence_token)
            key = operation_id, gate_action
            current = self._prepared.get(key)
            if current is not None and current != (prepared, "PREPARED"):
                raise ValueError("prepared start identity conflict")
            if key in self._markers:
                raise ValueError("completed effect cannot return to PREPARED")
            if current is None:
                self._prepared[key] = (prepared, "PREPARED")
                self._generation += 1

    def verify_prepared_effect(self, operation_id: OperationId, gate_action: str,
                               prepared: object) -> bool:
        with self._lock:
            return self._prepared.get((operation_id, gate_action)) == (prepared, "PREPARED")

    def prepared_effect_record(self, operation_id: OperationId,
                               gate_action: str) -> object | None:
        with self._lock:
            current = self._prepared.get((operation_id, gate_action))
            return None if current is None else current[0]

    def prepared_effect_state(self, operation_id: OperationId, gate_action: str) -> str | None:
        with self._lock:
            current = self._prepared.get((operation_id, gate_action))
            return None if current is None else current[1]

    def release_prepared_effect(self, operation_id: OperationId, gate_action: str, *, _fence_token: FixtureFenceToken | None = None) -> bool:
        with self._lock:
            self._guard(("prepared", operation_id, gate_action), _fence_token)
            key = operation_id, gate_action
            current = self._prepared.get(key)
            if current is None or current[1] != "PREPARED" or key in self._markers:
                return False
            self._prepared[key] = (current[0], "RELEASED")
            self._generation += 1
            return True

    def install_authoritative_snapshot(self, snapshot: AuthoritativeStateSnapshot) -> None:
        """Install one exact root-managed fixture observation source."""
        if type(snapshot) is not AuthoritativeStateSnapshot:
            raise TypeError("exact AuthoritativeStateSnapshot required")
        locator = (snapshot.repository_id, snapshot.observation_profile_id,
                   snapshot.transport_config_id)
        with self._lock:
            if locator in self._authoritative and self._authoritative[locator] != snapshot:
                raise ValueError("authoritative fixture locator identity conflict")
            self._guard(("authoritative-profile", *locator))
            for observation in snapshot.observations:
                self._guard(("authoritative", *locator, observation.fact_key))
            self._authoritative[locator] = snapshot
            self._generation += 1

    def replace_authoritative_snapshot(self, snapshot: AuthoritativeStateSnapshot) -> None:
        """Fixture mutation hook; live leases fence every contributing observation."""
        if type(snapshot) is not AuthoritativeStateSnapshot:
            raise TypeError("exact AuthoritativeStateSnapshot required")
        locator = (snapshot.repository_id, snapshot.observation_profile_id,
                   snapshot.transport_config_id)
        with self._lock:
            current = self._authoritative.get(locator)
            if current is None:
                raise ValueError("authoritative fixture source is not installed")
            self._guard(("authoritative-profile", *locator))
            for fact_key in {item.fact_key for item in (*current.observations, *snapshot.observations)}:
                self._guard(("authoritative", *locator, fact_key))
            self._authoritative[locator] = snapshot
            self._generation += 1

    def authoritative_snapshot(self, repository_id: GitHubRepositoryId,
                               profile_id: object, transport_id: object) -> AuthoritativeStateSnapshot | None:
        with self._lock:
            return self._authoritative.get((repository_id, profile_id, transport_id))

    def authoritative_facts(self, repository_id: GitHubRepositoryId,
                            profile_id: object, transport_id: object) -> frozenset[tuple] | None:
        with self._lock:
            locator = (repository_id, profile_id, transport_id)
            snapshot = self._authoritative.get(locator)
            if snapshot is None:
                return None
            return frozenset({
                ("authoritative-profile", *locator),
                *(("authoritative", *locator, item.fact_key) for item in snapshot.observations),
            })

    def authoritative_binding(self, repository_id: GitHubRepositoryId,
                              profile_id: object,
                              transport_id: object) -> AuthoritativeStateBindingId | None:
        snapshot = self.authoritative_snapshot(repository_id, profile_id, transport_id)
        return None if snapshot is None else authoritative_state_binding(snapshot)

    def seed_ref(self, repository_id: GitHubRepositoryId, ref: CanonicalBranchRef, sha: GitSha) -> None:
        with self._lock:
            self._guard(("repository", repository_id))
            self._guard(("ref", repository_id, ref))
            self._refs[(repository_id, ref)] = sha
            self._generation += 1

    @staticmethod
    def tree_identity(tree: tuple[GitTreeEntry, ...]) -> GitSha:
        if type(tree) is not tuple or any(type(item) is not GitTreeEntry for item in tree):
            raise TypeError("tree must be an exact tuple of GitTreeEntry")
        return GitSha(hashlib.sha256(canonical_json_bytes(("fixture-git-tree/v1", tree))).hexdigest())

    def seed_commit(self, sha: GitSha, parents: tuple[GitSha, ...],
                    tree: tuple[GitTreeEntry, ...], tree_id: GitSha | None = None) -> None:
        if type(sha) is not GitSha or type(parents) is not tuple or type(tree) is not tuple:
            raise TypeError("commit fixture fields have wrong exact type")
        if any(type(item) is not GitSha for item in parents) or any(type(item) is not GitTreeEntry for item in tree):
            raise TypeError("commit fixture member has wrong exact type")
        if tree_id is None:
            tree_id = self.tree_identity(tree)
        if type(tree_id) is not GitSha:
            raise TypeError("tree_id must be exact GitSha")
        with self._lock:
            self._guard(("commit", sha))
            value = parents, tree_id, tree
            if sha in self._commits and self._commits[sha] != value:
                raise ValueError("immutable commit identity conflict")
            self._commits[sha] = value
            self._generation += 1

    def verify_materialization(self, materialization: CandidateMaterialization | AdmittedCandidateMaterialization) -> bool:
        if type(materialization) not in (CandidateMaterialization, AdmittedCandidateMaterialization):
            return False
        with self._lock:
            base = self._commits.get(materialization.base)
            candidate = self._commits.get(materialization.commit)
            if (base is None or candidate is None
                    or candidate[0] != (materialization.base,)
                    or base[1] != materialization.base_tree
                    or candidate[1] != materialization.result_tree):
                return False
            try:
                inventory = derive_mutation_inventory(base[2], candidate[2])
            except (TypeError, ValueError):
                return False
            return inventory == materialization.inventory

    def read_ref(self, repository_id: GitHubRepositoryId, ref: CanonicalBranchRef) -> GitSha | None:
        with self._lock:
            return self._refs.get((repository_id, ref))

    def create_ref_if_absent(self, repository_id: GitHubRepositoryId, ref: CanonicalBranchRef, sha: GitSha) -> bool:
        with self._lock:
            self._guard(("repository", repository_id))
            self._guard(("ref", repository_id, ref))
            key = (repository_id, ref)
            if key in self._refs:
                return False
            self._refs[key] = sha
            self._generation += 1
            return True

    def create_pull_request(self, repository_id: GitHubRepositoryId, head: CanonicalBranchRef,
                            base: CanonicalBranchRef, head_sha: GitSha) -> FixturePullRequest:
        with self._lock:
            self._guard(("repository", repository_id))
            self._guard(("prs", repository_id))
            if self._refs.get((repository_id, head)) != head_sha:
                raise ValueError("pull request head does not match authoritative ref")
            base_sha = self._refs.get((repository_id, base))
            if base_sha is None:
                raise ValueError("pull request base is unavailable")
            pr = FixturePullRequest(len(self._prs) + 1, repository_id, head, base, head_sha, base_sha)
            self._prs.append(pr)
            self._generation += 1
            return pr

    def next_pull_request_number(self) -> int:
        with self._lock:
            return len(self._prs) + 1

    def pull_request(self, number: GitHubPullRequestNumber) -> FixturePullRequest | None:
        if type(number) is not GitHubPullRequestNumber:
            raise TypeError("exact GitHubPullRequestNumber required")
        with self._lock:
            return next((item for item in self._prs if item.number == number.value), None)

    def publish_and_mark(self, repository_id: GitHubRepositoryId, ref: CanonicalBranchRef,
                         sha: GitSha, marker: ProtectedEffectMarker, *,
                         _fence_token: FixtureFenceToken | None = None) -> bool:
        with self._lock:
            self._guard(("repository", repository_id), _fence_token)
            self._guard(("ref", repository_id, ref), _fence_token)
            marker_key = marker.preimage.operation_id, marker.preimage.gate_action
            self._guard(("prepared", *marker_key), _fence_token)
            key = repository_id, ref
            subject = marker.preimage.effect_subject
            if self._consume_effect_failure():
                return False
            if (key in self._refs or marker_key in self._markers
                    or type(subject) is not PublishedCandidateRefEffectSubject
                    or subject.repository_id != repository_id
                    or subject.destination_branch != ref or subject.platform_ref != GitRef(ref.value)
                    or subject.published_commit != sha):
                return False
            self._refs[key] = sha
            self._markers[marker_key] = marker
            prepared = self._prepared.get(marker_key)
            self._prepared[marker_key] = (None if prepared is None else prepared[0], "CONSUMED")
            self._generation += 1
            return True

    def create_pull_request_and_mark(self, repository_id: GitHubRepositoryId,
                                     head: CanonicalBranchRef, base: CanonicalBranchRef,
                                     head_sha: GitSha, marker: ProtectedEffectMarker, *,
                                     _fence_token: FixtureFenceToken | None = None) -> FixturePullRequest | None:
        with self._lock:
            self._guard(("repository", repository_id), _fence_token)
            self._guard(("prs", repository_id), _fence_token)
            base_sha = self._refs.get((repository_id, base))
            marker_key = marker.preimage.operation_id, marker.preimage.gate_action
            self._guard(("prepared", *marker_key), _fence_token)
            number = len(self._prs) + 1
            subject = marker.preimage.effect_subject
            if self._consume_effect_failure():
                return None
            if (self._refs.get((repository_id, head)) != head_sha or base_sha is None
                    or marker_key in self._markers
                    or type(subject) is not CreatedCandidatePrEffectSubject
                    or subject.repository_id != repository_id
                    or subject.pull_request_number.value != number
                    or subject.head_ref != GitRef(head.value) or subject.head_sha != head_sha
                    or subject.base_ref != GitRef(base.value) or subject.base_sha != base_sha):
                return None
            pr = FixturePullRequest(number, repository_id, head, base, head_sha, base_sha)
            self._prs.append(pr)
            self._markers[marker_key] = marker
            prepared = self._prepared.get(marker_key)
            self._prepared[marker_key] = (None if prepared is None else prepared[0], "CONSUMED")
            self._generation += 1
            return pr

    def fast_forward_and_mark(self, repository_id: GitHubRepositoryId, target: CanonicalBranchRef,
                              expected: GitSha, candidate: GitSha, candidate_parent: GitSha,
                              pull_request_number: int, marker: ProtectedEffectMarker, *,
                              _fence_token: FixtureFenceToken | None = None) -> bool:
        with self._lock:
            self._guard(("repository", repository_id), _fence_token)
            self._guard(("ref", repository_id, target), _fence_token)
            self._guard(("prs", repository_id), _fence_token)
            marker_key = marker.preimage.operation_id, marker.preimage.gate_action
            self._guard(("prepared", *marker_key), _fence_token)
            pr = next((item for item in self._prs if item.number == pull_request_number), None)
            subject = marker.preimage.effect_subject
            if self._consume_effect_failure():
                return False
            if (self._refs.get((repository_id, target)) != expected or candidate_parent != expected
                    or pr is None or pr.merged or pr.repository_id != repository_id
                    or pr.head_sha != candidate or pr.base_sha != expected
                    or type(subject) is not FastForwardMergeEffectSubject
                    or subject.repository_id != repository_id
                    or subject.pull_request_number.value != pull_request_number
                    or subject.integration_ref != GitRef(target.value)
                    or subject.before_sha != expected or subject.after_sha != candidate
                    or marker_key in self._markers):
                return False
            self._refs[(repository_id, target)] = candidate
            self._prs[self._prs.index(pr)] = replace(pr, merged=True)
            self._markers[marker_key] = marker
            prepared = self._prepared.get(marker_key)
            self._prepared[marker_key] = (None if prepared is None else prepared[0], "CONSUMED")
            self._generation += 1
            return True

    def fast_forward(self, repository_id: GitHubRepositoryId, target: CanonicalBranchRef,
                     expected: GitSha, candidate: GitSha, candidate_parent: GitSha) -> bool:
        with self._lock:
            self._guard(("repository", repository_id))
            self._guard(("ref", repository_id, target))
            key = (repository_id, target)
            if self._refs.get(key) != expected or candidate_parent != expected:
                return False
            self._refs[key] = candidate
            self._generation += 1
            return True

    def marker(self, operation_id: OperationId, gate_action: str) -> ProtectedEffectMarker | None:
        with self._lock:
            return self._markers.get((operation_id, gate_action))

    def record_marker(self, marker: ProtectedEffectMarker) -> ProtectedEffectMarker:
        with self._lock:
            if type(marker) is not ProtectedEffectMarker:
                raise TypeError("exact ProtectedEffectMarker required")
            key = marker.preimage.operation_id, marker.preimage.gate_action
            subject = marker.preimage.effect_subject
            self._guard(("prepared", *key))
            self._guard(("repository", subject.repository_id))
            if type(subject) is PublishedCandidateRefEffectSubject:
                self._guard(("ref", subject.repository_id, subject.destination_branch))
            elif type(subject) is CreatedCandidatePrEffectSubject:
                self._guard(("prs", subject.repository_id))
            elif type(subject) is FastForwardMergeEffectSubject:
                self._guard(("prs", subject.repository_id))
                self._guard(("ref", subject.repository_id, CanonicalBranchRef(subject.integration_ref.value)))
            current = self._markers.get(key)
            if current is not None and current != marker:
                raise ValueError("effect marker provenance conflict")
            if current is None:
                self._markers[key] = marker
                prepared = self._prepared.get(key)
                self._prepared[key] = (None if prepared is None else prepared[0], "CONSUMED")
                self._generation += 1
            return marker

    @staticmethod
    def deterministic_sha(*parts: str) -> GitSha:
        if any(type(part) is not str for part in parts):
            raise TypeError("fixture SHA parts must be exact strings")
        return GitSha(hashlib.sha256(canonical_json_bytes(
            ("autodev.fixture-git-sha/v1", parts)
        )).hexdigest())


# Earlier fixture name remains an alias; there is only one authoritative marker model.
FixtureEffectMarker = ProtectedEffectMarker
