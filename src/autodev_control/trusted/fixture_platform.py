"""One-lock fixture-only Git platform used to exercise G7 gate semantics."""

from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
from threading import RLock

from .identity import GitSha
from .materialization import CandidateMaterialization, GitTreeEntry, derive_mutation_inventory
from .scope import CanonicalBranchRef, GitHubRepositoryId


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
class ProtectedEffectMarker:
    operation_id: str
    idempotency_key: str
    action_id: str
    action_digest: str
    materialization_id: str
    mutation_inventory_id: str
    prepared_start_binding_id: str
    root_context_id: str
    runtime_generation: int
    service_identity: str
    effect_subject: str
    repository_id: GitHubRepositoryId
    pre_state_identity: str
    post_state_identity: str
    result_identity: str

    def __post_init__(self) -> None:
        strings = (
            self.operation_id, self.idempotency_key, self.action_id, self.action_digest,
            self.materialization_id, self.mutation_inventory_id,
            self.prepared_start_binding_id, self.root_context_id, self.service_identity,
            self.effect_subject, self.pre_state_identity, self.post_state_identity,
            self.result_identity,
        )
        if any(type(item) is not str or not item for item in strings):
            raise ValueError("marker identities must be non-empty exact strings")
        if any(len(value) != 64 or any(char not in "0123456789abcdef" for char in value)
               for value in (self.action_digest, self.materialization_id,
                             self.mutation_inventory_id, self.prepared_start_binding_id)):
            raise ValueError("marker digest identities must be lowercase SHA-256")
        if type(self.runtime_generation) is not int or self.runtime_generation < 1:
            raise ValueError("marker runtime generation must be positive")
        if type(self.repository_id) is not GitHubRepositoryId:
            raise TypeError("marker repository identity has wrong exact type")


@dataclass(frozen=True, slots=True)
class FixturePlatformSnapshot:
    generation: int
    refs: tuple[tuple[GitHubRepositoryId, CanonicalBranchRef, GitSha], ...]
    pull_requests: tuple[FixturePullRequest, ...]
    markers: tuple[ProtectedEffectMarker, ...]
    prepared_effects: tuple[tuple[str, str, str], ...]


class FixtureGitPlatform:
    """Authoritative fixture state. It performs no network or provider calls."""

    __slots__ = ("_lock", "_generation", "_refs", "_prs", "_markers", "_prepared", "_commits")

    def __init__(self) -> None:
        self._lock = RLock()
        self._generation = 1
        self._refs: dict[tuple[GitHubRepositoryId, CanonicalBranchRef], GitSha] = {}
        self._prs: list[FixturePullRequest] = []
        self._markers: dict[tuple[str, str], ProtectedEffectMarker] = {}
        self._prepared: dict[tuple[str, str], str] = {}
        self._commits: dict[GitSha, tuple[tuple[GitSha, ...], tuple[GitTreeEntry, ...]]] = {}

    def snapshot(self) -> FixturePlatformSnapshot:
        with self._lock:
            refs = tuple(sorted(((r, b, s) for (r, b), s in self._refs.items()), key=lambda x: (x[0].value, x[1].value)))
            prepared = tuple((key[0], key[1], value) for key, value in sorted(self._prepared.items()))
            return FixturePlatformSnapshot(self._generation, refs, tuple(self._prs), tuple(self._markers.values()), prepared)

    def prepare_effect(self, operation_id: str, subject: str) -> None:
        with self._lock:
            key = operation_id, subject
            if key in self._markers:
                raise ValueError("completed effect cannot return to PREPARED")
            if self._prepared.setdefault(key, "PREPARED") != "PREPARED":
                raise ValueError("terminal prepared state cannot return to PREPARED")
            self._generation += 1

    def prepared_effect_state(self, operation_id: str, subject: str) -> str | None:
        with self._lock:
            return self._prepared.get((operation_id, subject))

    def release_prepared_effect(self, operation_id: str, subject: str) -> bool:
        with self._lock:
            key = operation_id, subject
            if self._prepared.get(key) != "PREPARED" or key in self._markers:
                return False
            self._prepared[key] = "RELEASED"
            self._generation += 1
            return True

    def seed_ref(self, repository_id: GitHubRepositoryId, ref: CanonicalBranchRef, sha: GitSha) -> None:
        with self._lock:
            self._refs[(repository_id, ref)] = sha
            self._generation += 1

    def seed_commit(self, sha: GitSha, parents: tuple[GitSha, ...],
                    tree: tuple[GitTreeEntry, ...]) -> None:
        if type(sha) is not GitSha or type(parents) is not tuple or type(tree) is not tuple:
            raise TypeError("commit fixture fields have wrong exact type")
        if any(type(item) is not GitSha for item in parents) or any(type(item) is not GitTreeEntry for item in tree):
            raise TypeError("commit fixture member has wrong exact type")
        with self._lock:
            value = parents, tree
            if sha in self._commits and self._commits[sha] != value:
                raise ValueError("immutable commit identity conflict")
            self._commits[sha] = value
            self._generation += 1

    def verify_materialization(self, materialization: CandidateMaterialization) -> bool:
        if type(materialization) is not CandidateMaterialization:
            return False
        with self._lock:
            base = self._commits.get(materialization.base)
            candidate = self._commits.get(materialization.commit)
            if base is None or candidate is None or candidate[0] != (materialization.base,):
                return False
            try:
                inventory = derive_mutation_inventory(base[1], candidate[1])
            except (TypeError, ValueError):
                return False
            return inventory == materialization.inventory

    def read_ref(self, repository_id: GitHubRepositoryId, ref: CanonicalBranchRef) -> GitSha | None:
        with self._lock:
            return self._refs.get((repository_id, ref))

    def create_ref_if_absent(self, repository_id: GitHubRepositoryId, ref: CanonicalBranchRef, sha: GitSha) -> bool:
        with self._lock:
            key = (repository_id, ref)
            if key in self._refs:
                return False
            self._refs[key] = sha
            self._generation += 1
            return True

    def create_pull_request(self, repository_id: GitHubRepositoryId, head: CanonicalBranchRef,
                            base: CanonicalBranchRef, head_sha: GitSha) -> FixturePullRequest:
        with self._lock:
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

    def publish_and_mark(self, repository_id: GitHubRepositoryId, ref: CanonicalBranchRef,
                         sha: GitSha, marker: ProtectedEffectMarker) -> bool:
        with self._lock:
            key, marker_key = (repository_id, ref), (marker.operation_id, marker.effect_subject)
            if key in self._refs or marker_key in self._markers or marker.repository_id != repository_id:
                return False
            self._refs[key] = sha
            self._markers[marker_key] = marker
            self._prepared[marker_key] = "CONSUMED"
            self._generation += 1
            return True

    def create_pull_request_and_mark(self, repository_id: GitHubRepositoryId,
                                     head: CanonicalBranchRef, base: CanonicalBranchRef,
                                     head_sha: GitSha, marker: ProtectedEffectMarker) -> FixturePullRequest | None:
        with self._lock:
            base_sha = self._refs.get((repository_id, base))
            marker_key = marker.operation_id, marker.effect_subject
            number = len(self._prs) + 1
            if (self._refs.get((repository_id, head)) != head_sha or base_sha is None
                    or marker_key in self._markers or marker.result_identity != str(number)):
                return None
            pr = FixturePullRequest(number, repository_id, head, base, head_sha, base_sha)
            self._prs.append(pr)
            self._markers[marker_key] = marker
            self._prepared[marker_key] = "CONSUMED"
            self._generation += 1
            return pr

    def fast_forward_and_mark(self, repository_id: GitHubRepositoryId, target: CanonicalBranchRef,
                              expected: GitSha, candidate: GitSha, candidate_parent: GitSha,
                              pull_request_number: int, marker: ProtectedEffectMarker) -> bool:
        with self._lock:
            marker_key = marker.operation_id, marker.effect_subject
            pr = next((item for item in self._prs if item.number == pull_request_number), None)
            if (self._refs.get((repository_id, target)) != expected or candidate_parent != expected
                    or pr is None or pr.merged or pr.repository_id != repository_id
                    or pr.head_sha != candidate or pr.base_sha != expected
                    or marker_key in self._markers):
                return False
            self._refs[(repository_id, target)] = candidate
            self._prs[self._prs.index(pr)] = replace(pr, merged=True)
            self._markers[marker_key] = marker
            self._prepared[marker_key] = "CONSUMED"
            self._generation += 1
            return True

    def fast_forward(self, repository_id: GitHubRepositoryId, target: CanonicalBranchRef,
                     expected: GitSha, candidate: GitSha, candidate_parent: GitSha) -> bool:
        with self._lock:
            key = (repository_id, target)
            if self._refs.get(key) != expected or candidate_parent != expected:
                return False
            self._refs[key] = candidate
            self._generation += 1
            return True

    def marker(self, operation_id: str, subject: str) -> ProtectedEffectMarker | None:
        with self._lock:
            return self._markers.get((operation_id, subject))

    def record_marker(self, marker: ProtectedEffectMarker) -> ProtectedEffectMarker:
        with self._lock:
            if type(marker) is not ProtectedEffectMarker:
                raise TypeError("exact ProtectedEffectMarker required")
            key = (marker.operation_id, marker.effect_subject)
            current = self._markers.get(key)
            if current is not None and current != marker:
                raise ValueError("effect marker provenance conflict")
            if current is None:
                self._markers[key] = marker
                self._prepared[key] = "CONSUMED"
                self._generation += 1
            return marker

    @staticmethod
    def deterministic_sha(*parts: str) -> GitSha:
        return GitSha(hashlib.sha256("\0".join(parts).encode()).hexdigest())


# Earlier fixture name remains an alias; there is only one authoritative marker model.
FixtureEffectMarker = ProtectedEffectMarker
