"""One-lock fixture-only Git platform used to exercise G7 gate semantics."""

from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import secrets
from threading import RLock

from .backend import canonical_json_bytes
from .identity import (
    CandidateMaterializationId, GateRuntimeBindingId, GitRef, GitSha, MutationInventoryId,
    PreparedProtectedStartId, ProtectedEffectMarkerId, RawSha256, RootContextId,
)
from .materialization import AdmittedCandidateMaterialization, CandidateMaterialization, GitTreeEntry, derive_mutation_inventory
from .operation import (
    AuthoritativeStateBindingId, OperationActionId, OperationId,
    OperationIdempotencyKey, OperationRecord, OperationState,
    StartHeldTargetFenceBinding, CanonicalProtectedStartBinding,
    derive_operation_start_binding_id_v2,
)
from .runtime_authority import PreparedTargetFenceBinding
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


class FixtureReadVerifyClient:
    """Narrow read-only F view supplied to candidate verification paths."""

    __slots__ = ("_platform",)

    def __init__(self, platform: "FixtureGitPlatform") -> None:
        self._platform = platform

    @property
    def substrate_identity(self) -> RawSha256:
        return self._platform._substrate_identity

    def verify_prepared_start(
        self, operation_id: OperationId, action_class: str,
        prepared_start_id: PreparedProtectedStartId,
    ) -> bool:
        if (type(operation_id) is not OperationId or type(action_class) is not str
                or type(prepared_start_id) is not PreparedProtectedStartId):
            return False
        with self._platform._lock:
            current = self._platform._prepared.get((operation_id, action_class))
            record = None if current is None else current[0]
            return (
                current is not None and current[1] == "PREPARED"
                and current[2] is None
                and type(getattr(record, "prepared_start_id", None)) is PreparedProtectedStartId
                and record.prepared_start_id == prepared_start_id
            )

    def prepared_target_fence_binding(
        self, operation_id: OperationId, action_class: str,
    ) -> PreparedTargetFenceBinding | None:
        return self._platform.prepared_target_fence_binding(
            operation_id, action_class,
        )

    def verify_prepared_target_fence(
        self, binding: PreparedTargetFenceBinding,
    ) -> bool:
        if type(binding) is not PreparedTargetFenceBinding:
            return False
        return self.prepared_target_fence_binding(
            binding.operation_id, binding.action_class,
        ) == binding

    def verify_start_held_target_fence(
        self, binding: StartHeldTargetFenceBinding,
    ) -> bool:
        return self._platform.verify_start_held_target_fence(binding)

    def resolve_historical_start_binding(
        self, binding: StartHeldTargetFenceBinding,
    ) -> bool:
        """Verify retained identity only; lifecycle state is queried separately."""
        return self._platform.resolve_historical_start_binding(binding)

    def prepared_start_binding(
        self, operation_id: OperationId, action_class: str,
    ) -> StartHeldTargetFenceBinding | None:
        return self._platform.prepared_start_binding(operation_id, action_class)

    def read_prepared_effect_record(
        self, operation_id: OperationId, action_class: str,
    ) -> object | None:
        """Read one exact durable PREPARED/start record without mutation authority."""
        if type(operation_id) is not OperationId or type(action_class) is not str:
            return None
        return self._platform.prepared_effect_record(operation_id, action_class)

    def read_prepared_effect_state(
        self, operation_id: OperationId, action_class: str,
    ) -> str | None:
        if type(operation_id) is not OperationId or type(action_class) is not str:
            return None
        return self._platform.prepared_effect_state(operation_id, action_class)

    def read_ref(
        self, repository_id: GitHubRepositoryId, ref: CanonicalBranchRef,
    ) -> GitSha | None:
        if type(repository_id) is not GitHubRepositoryId or type(ref) is not CanonicalBranchRef:
            return None
        return self._platform.read_ref(repository_id, ref)

    def read_marker(
        self, operation_id: OperationId, action_class: str,
    ) -> ProtectedEffectMarker | None:
        if type(operation_id) is not OperationId or type(action_class) is not str:
            return None
        return self._platform.marker(operation_id, action_class)

    def read_pull_request(
        self, number: GitHubPullRequestNumber,
    ) -> FixturePullRequest | None:
        if type(number) is not GitHubPullRequestNumber:
            return None
        return self._platform.pull_request(number)

    def read_next_pull_request_number(self) -> int:
        """Read the fixture's next PR sequence under the active target fence."""
        return self._platform.next_pull_request_number()

    def verify_materialization(
        self, materialization: CandidateMaterialization | AdmittedCandidateMaterialization,
    ) -> bool:
        if type(materialization) not in (CandidateMaterialization, AdmittedCandidateMaterialization):
            return False
        return self._platform.verify_materialization(materialization)

    def verify_marker_postcondition(self, marker: ProtectedEffectMarker) -> bool:
        """Verify the exact postcondition recorded by one immutable F marker."""
        if type(marker) is not ProtectedEffectMarker:
            return False
        subject = marker.preimage.effect_subject
        if type(subject) is PublishedCandidateRefEffectSubject:
            return self.read_ref(subject.repository_id, subject.destination_branch) == subject.published_commit
        if type(subject) is CreatedCandidatePrEffectSubject:
            pr = self.read_pull_request(subject.pull_request_number)
            return pr is not None and (
                pr.repository_id, GitRef(pr.head.value), pr.head_sha,
                GitRef(pr.base.value), pr.base_sha, pr.merged,
            ) == (subject.repository_id, subject.head_ref, subject.head_sha,
                  subject.base_ref, subject.base_sha, False)
        if type(subject) is FastForwardMergeEffectSubject:
            pr = self.read_pull_request(subject.pull_request_number)
            return (pr is not None and pr.merged
                    and self.read_ref(
                        subject.repository_id, CanonicalBranchRef(subject.integration_ref.value)
                    ) == subject.after_sha)
        return False

    def authoritative_snapshot(
        self, repository_id: GitHubRepositoryId, profile_id: object,
        transport_id: object,
    ) -> AuthoritativeStateSnapshot | None:
        """Narrow G7 read projection; this client exposes no fixture mutation."""
        return self._platform.authoritative_snapshot(
            repository_id, profile_id, transport_id,
        )

    def authoritative_facts(
        self, repository_id: GitHubRepositoryId, profile_id: object,
        transport_id: object,
    ) -> frozenset[tuple] | None:
        return self._platform.authoritative_facts(
            repository_id, profile_id, transport_id,
        )

    def authoritative_binding(
        self, repository_id: GitHubRepositoryId, profile_id: object,
        transport_id: object,
    ) -> AuthoritativeStateBindingId | None:
        return self._platform.authoritative_binding(
            repository_id, profile_id, transport_id,
        )


class FixtureFenceToken:
    __slots__ = ("owner", "facts", "active")

    def __init__(self, owner: object, facts: frozenset[tuple]) -> None:
        self.owner, self.facts, self.active = owner, facts, True


class FixturePublicationAuthorityClient:
    """P-only client over the shared fixture substrate."""

    __slots__ = ("_platform", "_authority")
    _ACTIONS = frozenset(("CANDIDATE_BRANCH_PUBLICATION", "PULL_REQUEST_CREATION"))

    def __init__(self, platform: "FixtureGitPlatform", authority: object) -> None:
        self._platform, self._authority = platform, authority

    def binding_identity(
        self, service_identity: ServicePrincipalId, root_context_id: RootContextId,
        runtime_generation: int, runtime_binding_id: GateRuntimeBindingId,
    ) -> RawSha256:
        if (type(service_identity) is not ServicePrincipalId
                or type(root_context_id) is not RootContextId
                or type(runtime_generation) is not int
                or type(runtime_binding_id) is not GateRuntimeBindingId):
            raise TypeError("exact publication authority binding inputs required")
        return RawSha256(hashlib.sha256(canonical_json_bytes((
            "autodev.fixture-role-authority-binding/v1",
            self._platform._substrate_identity, "PUBLICATION_AUTHORITY",
            service_identity, root_context_id, runtime_generation,
            runtime_binding_id,
        ))).hexdigest())

    def prepare_publication(self, prepared: object, fence_token: FixtureFenceToken) -> bool:
        action = getattr(getattr(getattr(prepared, "preimage", None), "action", None), "value", None)
        if action not in self._ACTIONS:
            return False
        self._platform.persist_prepared_effect(
            prepared.operation.intent.operation_id, action, prepared,
            _fence_token=fence_token, _authority=self._authority,
        )
        return True

    def abort_prepared_publication(
        self, operation_id: OperationId, action_class: str,
        fence_token: FixtureFenceToken | None = None,
    ) -> bool:
        if action_class not in self._ACTIONS:
            return False
        return self._platform.release_prepared_effect(
            operation_id, action_class, _fence_token=fence_token,
            _authority=self._authority,
        )

    def seal_publication_for_start(
        self, operation_id: OperationId, action_class: str, prepared: object,
        authority_binding_identity: RawSha256,
    ) -> StartHeldTargetFenceBinding | None:
        if action_class not in self._ACTIONS:
            return None
        return self._platform.seal_prepared_for_start(
            operation_id, action_class, prepared, authority_binding_identity,
            _authority=self._authority,
        )

    def execute_candidate_ref_publication(
        self, repository_id: GitHubRepositoryId, ref: CanonicalBranchRef,
        sha: GitSha, marker: ProtectedEffectMarker, *,
        fence_token: FixtureFenceToken | None = None,
    ) -> bool:
        if marker.preimage.gate_action != "CANDIDATE_BRANCH_PUBLICATION":
            return False
        return self._platform.publish_and_mark(
            repository_id, ref, sha, marker, _fence_token=fence_token,
            _authority=self._authority,
        )

    def execute_candidate_pr_creation(
        self, repository_id: GitHubRepositoryId, head: CanonicalBranchRef,
        base: CanonicalBranchRef, head_sha: GitSha, marker: ProtectedEffectMarker,
        *, fence_token: FixtureFenceToken | None = None,
    ) -> FixturePullRequest | None:
        if marker.preimage.gate_action != "PULL_REQUEST_CREATION":
            return None
        return self._platform.create_pull_request_and_mark(
            repository_id, head, base, head_sha, marker,
            _fence_token=fence_token, _authority=self._authority,
        )

class FixtureMergeAuthorityClient:
    """M-only client over the same fixture substrate, with no P methods."""

    __slots__ = ("_platform", "_authority")

    def __init__(self, platform: "FixtureGitPlatform", authority: object) -> None:
        self._platform, self._authority = platform, authority

    def binding_identity(
        self, service_identity: ServicePrincipalId, root_context_id: RootContextId,
        runtime_generation: int, runtime_binding_id: GateRuntimeBindingId,
    ) -> RawSha256:
        if (type(service_identity) is not ServicePrincipalId
                or type(root_context_id) is not RootContextId
                or type(runtime_generation) is not int
                or type(runtime_binding_id) is not GateRuntimeBindingId):
            raise TypeError("exact merge authority binding inputs required")
        return RawSha256(hashlib.sha256(canonical_json_bytes((
            "autodev.fixture-role-authority-binding/v1",
            self._platform._substrate_identity, "MERGE_AUTHORITY",
            service_identity, root_context_id, runtime_generation,
            runtime_binding_id,
        ))).hexdigest())

    def prepare_merge(self, prepared: object, fence_token: FixtureFenceToken) -> bool:
        action = getattr(getattr(getattr(prepared, "preimage", None), "action", None), "value", None)
        if action != "FAST_FORWARD_MERGE":
            return False
        self._platform.persist_prepared_effect(
            prepared.operation.intent.operation_id, action, prepared,
            _fence_token=fence_token, _authority=self._authority,
        )
        return True

    def abort_prepared_merge(
        self, operation_id: OperationId, action_class: str,
        fence_token: FixtureFenceToken | None = None,
    ) -> bool:
        if action_class != "FAST_FORWARD_MERGE":
            return False
        return self._platform.release_prepared_effect(
            operation_id, action_class, _fence_token=fence_token,
            _authority=self._authority,
        )

    def seal_merge_for_start(
        self, operation_id: OperationId, action_class: str, prepared: object,
        authority_binding_identity: RawSha256,
    ) -> StartHeldTargetFenceBinding | None:
        if action_class != "FAST_FORWARD_MERGE":
            return None
        return self._platform.seal_prepared_for_start(
            operation_id, action_class, prepared, authority_binding_identity,
            _authority=self._authority,
        )

    def execute_fast_forward_merge(
        self, repository_id: GitHubRepositoryId, target: CanonicalBranchRef,
        expected: GitSha, candidate: GitSha, candidate_parent: GitSha,
        pull_request_number: int, marker: ProtectedEffectMarker, *,
        fence_token: FixtureFenceToken | None = None,
    ) -> bool:
        if marker.preimage.gate_action != "FAST_FORWARD_MERGE":
            return False
        return self._platform.fast_forward_and_mark(
            repository_id, target, expected, candidate, candidate_parent,
            pull_request_number, marker, _fence_token=fence_token,
            _authority=self._authority,
        )

class FixtureStartHeldRecoveryAuthority:
    """External fixture-only capability for governed START_HELD recovery."""

    __slots__ = ("_platform", "_authority")

    def __init__(self, platform: "FixtureGitPlatform", authority: object) -> None:
        if (type(platform) is not FixtureGitPlatform
                or authority is not platform._external_recovery_authority):
            raise TypeError("fixture recovery capability construction is closed")
        self._platform, self._authority = platform, authority

    def release_proven_absent(
        self, binding: StartHeldTargetFenceBinding, operation: OperationRecord,
        prepared_record: object, fence_token: "FixtureFenceToken",
    ) -> bool:
        """Release only exact held authority after fixture recovery proves absence."""
        companion = (
            None if type(operation) is not OperationRecord
            else operation.canonical_protected_start_binding
        )
        record_id = getattr(prepared_record, "prepared_start_id", None)
        record_operation = getattr(prepared_record, "operation", None)
        if (type(binding) is not StartHeldTargetFenceBinding
                or type(operation) is not OperationRecord
                or operation.state not in (OperationState.PERFORMING, OperationState.INDETERMINATE)
                or operation.start_binding_id != derive_operation_start_binding_id_v2(binding)
                or type(companion) is not CanonicalProtectedStartBinding
                or companion.start_held_target_fence_binding != binding
                or companion.operation_start_binding_id != operation.start_binding_id
                or record_id != binding.prepared_start_id
                or type(record_operation) is not OperationRecord
                or record_operation.intent != operation.intent
                or type(fence_token) is not FixtureFenceToken
                or not fence_token.active
                or ("prepared", binding.operation_id, binding.action_class) not in fence_token.facts):
            return False
        return self._platform._release_start_held_for_fixture_recovery(
            binding, prepared_record, self._authority,
        )


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

    def is_role_active(
        self, root: RootContextId, generation: int, role: str, runtime: object,
    ) -> bool:
        """Check one role binding without exposing the other role identities."""
        index = {"C": 2, "P": 3, "M": 4}.get(role)
        if index is None:
            return False
        with self.lock:
            active = self._active
            return (
                active is not None and active[0] == root
                and active[1] == generation and active[index] is runtime
            )

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


class FixtureGateRoleFenceClient:
    """Role-scoped liveness/fence-release contract for a candidate gate runtime."""

    __slots__ = ("_registry", "_root", "_generation", "_role", "_identity")

    def __init__(
        self, registry: ActiveFixtureRuntimeRegistry, root: RootContextId,
        generation: int, role: str, identity: object,
    ) -> None:
        if (type(registry) is not ActiveFixtureRuntimeRegistry
                or type(root) is not RootContextId or type(generation) is not int
                or role not in {"P", "M"}):
            raise TypeError("exact publication/merge fence client binding required")
        self._registry, self._root, self._generation = registry, root, generation
        self._role, self._identity = role, identity

    def is_active(self) -> bool:
        return self._registry.is_role_active(
            self._root, self._generation, self._role, self._identity,
        )

    def release(self, token: FixtureFenceToken) -> None:
        if type(token) is not FixtureFenceToken:
            raise TypeError("exact fixture target-fence token required")
        self._registry.release(token)

    def acquire(self, facts: frozenset[tuple]) -> FixtureFenceToken | None:
        """Acquire a target fence for this P/M role without exposing the registry."""
        if type(facts) is not frozenset or any(type(fact) is not tuple for fact in facts):
            raise TypeError("exact immutable fixture target facts required")
        if not self.is_active():
            return None
        return self._registry.acquire(self._identity, facts)


class FixtureGitPlatform:
    """Authoritative fixture state. It performs no network or provider calls."""

    __slots__ = ("_lock", "_registry", "_generation", "_refs", "_prs", "_markers", "_prepared", "_prepared_fence_generations", "_commits", "_authoritative", "_fail_next_effect", "_substrate_identity", "_publication_authority", "_merge_authority", "_external_recovery_authority")

    def __init__(self) -> None:
        self._registry: ActiveFixtureRuntimeRegistry | None = None
        self._lock = RLock()
        self._generation = 1
        self._refs: dict[tuple[GitHubRepositoryId, CanonicalBranchRef], GitSha] = {}
        self._prs: list[FixturePullRequest] = []
        self._markers: dict[tuple[OperationId, str], ProtectedEffectMarker] = {}
        self._prepared: dict[tuple[OperationId, str], tuple[object | None, str, StartHeldTargetFenceBinding | None]] = {}
        self._prepared_fence_generations: dict[tuple[OperationId, str], int] = {}
        self._commits: dict[GitSha, tuple[tuple[GitSha, ...], GitSha, tuple[GitTreeEntry, ...]]] = {}
        self._authoritative: dict[tuple[GitHubRepositoryId, object, object], AuthoritativeStateSnapshot] = {}
        self._fail_next_effect = False
        self._substrate_identity = RawSha256(hashlib.sha256(
            b"autodev.fixture-substrate/v1\0" + secrets.token_bytes(32)
        ).hexdigest())
        self._publication_authority, self._merge_authority = object(), object()
        self._external_recovery_authority = object()

    def fail_next_effect_for_test(self) -> None:
        with self._lock:
            self._fail_next_effect = True

    def read_verify_client(self) -> FixtureReadVerifyClient:
        """Return a read-only F protocol, not the broad fixture admin object."""
        return FixtureReadVerifyClient(self)

    def publication_authority_client(self) -> FixturePublicationAuthorityClient:
        return FixturePublicationAuthorityClient(self, self._publication_authority)

    def merge_authority_client(self) -> FixtureMergeAuthorityClient:
        return FixtureMergeAuthorityClient(self, self._merge_authority)

    def fixture_start_held_recovery_authority(self) -> FixtureStartHeldRecoveryAuthority:
        """Constructed only by the external fixture/recovery harness."""
        return FixtureStartHeldRecoveryAuthority(self, self._external_recovery_authority)

    def _consume_effect_failure(self) -> bool:
        if self._fail_next_effect:
            self._fail_next_effect = False
            return True
        return False

    def _authority_matches_action(self, action_class: str, authority: object | None) -> bool:
        if authority is None:
            # Direct calls are fixture-admin/setup operations, never role clients.
            return True
        if action_class in FixturePublicationAuthorityClient._ACTIONS:
            return authority is self._publication_authority
        if action_class == "FAST_FORWARD_MERGE":
            return authority is self._merge_authority
        return False

    def attach_registry(self, registry: ActiveFixtureRuntimeRegistry) -> None:
        if type(registry) is not ActiveFixtureRuntimeRegistry:
            raise TypeError("exact ActiveFixtureRuntimeRegistry required")
        if self._registry is not None and self._registry is not registry:
            raise ValueError("fixture platform is already attached to another runtime registry")
        self._registry, self._lock = registry, registry.lock

    def _guard(
        self, fact: tuple, token: FixtureFenceToken | None = None,
        *, allow_prepared_key: tuple[OperationId, str] | None = None,
    ) -> None:
        if self._registry is not None:
            self._registry.assert_mutation_allowed(fact, token)
        for key, (record, state, _binding) in self._prepared.items():
            if state not in ("PREPARED", "START_HELD") or record is None or key == allow_prepared_key:
                continue
            preimage = getattr(record, "preimage", None)
            fence = getattr(preimage, "target_fence", None)
            if fence is None:
                continue
            action = getattr(getattr(preimage, "action", None), "value", None)
            guarded = (
                fact == ("repository", fence.repository_id)
                or (len(fact) == 3 and fact[0] == "ref"
                    and fact[1] == fence.repository_id
                    and fact[2] in (fence.ref, fence.base_ref))
                or (len(fact) == 2 and fact[0] == "prs"
                    and fact[1] == fence.repository_id
                    and action != "CANDIDATE_BRANCH_PUBLICATION")
                or (len(fact) == 3 and fact[0] == "prepared"
                    and fact[1:] == key)
            )
            if guarded:
                raise FixtureFenceConflict("F-authoritative prepared/start-held target fence is live")

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
            current = self._prepared.setdefault(key, (None, "PREPARED", None))
            if current[1] != "PREPARED":
                raise ValueError("terminal prepared state cannot return to PREPARED")
            self._generation += 1

    def persist_prepared_effect(self, operation_id: OperationId, gate_action: str,
                                prepared: object, *,
                                _fence_token: FixtureFenceToken,
                                _authority: object | None = None) -> None:
        """Durably persist the exact gate-private prepared record before G6 start."""
        with self._lock:
            if not self._authority_matches_action(gate_action, _authority):
                raise PermissionError("F rejected cross-role PREPARE authority")
            key = operation_id, gate_action
            self._guard(("prepared", operation_id, gate_action), _fence_token,
                        allow_prepared_key=key)
            current = self._prepared.get(key)
            if current is not None and current[:2] != (prepared, "PREPARED"):
                raise ValueError("prepared start identity conflict")
            if key in self._markers:
                raise ValueError("completed effect cannot return to PREPARED")
            if current is None:
                self._prepared[key] = (prepared, "PREPARED", None)
                self._generation += 1
                self._prepared_fence_generations[key] = self._generation

    def verify_prepared_effect(self, operation_id: OperationId, gate_action: str,
                               prepared: object) -> bool:
        with self._lock:
            current = self._prepared.get((operation_id, gate_action))
            return current is not None and current[:2] == (prepared, "PREPARED")

    def prepared_effect_record(self, operation_id: OperationId,
                               gate_action: str) -> object | None:
        with self._lock:
            current = self._prepared.get((operation_id, gate_action))
            return None if current is None else current[0]

    def prepared_effect_state(self, operation_id: OperationId, gate_action: str) -> str | None:
        with self._lock:
            current = self._prepared.get((operation_id, gate_action))
            return None if current is None else current[1]

    def seal_prepared_for_start(
        self, operation_id: OperationId, gate_action: str, prepared: object,
        authority_binding_identity: RawSha256,
        *, _authority: object | None = None,
    ) -> StartHeldTargetFenceBinding | None:
        """Linearize the owning role's PREPARED → START_HELD transition in F."""
        with self._lock:
            if not self._authority_matches_action(gate_action, _authority):
                return None
            key = operation_id, gate_action
            current = self._prepared.get(key)
            if (current is None or current[0] is not prepared
                    or current[1] != "PREPARED" or current[2] is not None
                    or type(authority_binding_identity) is not RawSha256):
                return None
            preimage = getattr(prepared, "preimage", None)
            prepared_id = getattr(prepared, "prepared_start_id", None)
            if (getattr(preimage, "operation_id", None) != operation_id
                    or getattr(preimage, "action", None) is None
                    or getattr(preimage, "service_identity", None) is None
                    or type(prepared_id) is not PreparedProtectedStartId
                    or getattr(preimage, "root_context_id", None) is None
                    or getattr(preimage, "runtime_generation", None) is None):
                return None
            target_fence = getattr(preimage, "target_fence", None)
            if target_fence is None:
                return None
            fence_identity = RawSha256(hashlib.sha256(canonical_json_bytes((
                "autodev.fixture-target-fence/v1", target_fence,
            ))).hexdigest())
            fence_generation = self._generation + 1
            hold_identity = RawSha256(hashlib.sha256(canonical_json_bytes((
                "autodev.fixture-start-hold/v1", self._substrate_identity,
                authority_binding_identity, operation_id, gate_action,
                prepared_id, fence_identity, preimage.root_context_id,
                preimage.runtime_generation.value, fence_generation,
            ))).hexdigest())
            binding = StartHeldTargetFenceBinding(
                "autodev.start-held-target-fence-binding/v1",
                self._substrate_identity, authority_binding_identity,
                operation_id, gate_action, fence_identity, prepared_id,
                hold_identity, preimage.root_context_id,
                preimage.runtime_generation.value, fence_generation,
            )
            self._prepared[key] = (current[0], "START_HELD", binding)
            self._generation += 1
            return binding

    def verify_start_held_target_fence(
        self, binding: StartHeldTargetFenceBinding,
    ) -> bool:
        if type(binding) is not StartHeldTargetFenceBinding:
            return False
        with self._lock:
            current = self._prepared.get((binding.operation_id, binding.action_class))
            return (current is not None and current[2] == binding
                    and current[1] == "START_HELD")

    def resolve_historical_start_binding(
        self, binding: StartHeldTargetFenceBinding,
    ) -> bool:
        """Resolve exact retained binding identity; inspect state separately."""
        if type(binding) is not StartHeldTargetFenceBinding:
            return False
        with self._lock:
            current = self._prepared.get((binding.operation_id, binding.action_class))
            return (current is not None and current[2] == binding
                    and current[1] in ("START_HELD", "CONSUMED", "RELEASED"))

    def prepared_start_binding(
        self, operation_id: OperationId, gate_action: str,
    ) -> StartHeldTargetFenceBinding | None:
        with self._lock:
            current = self._prepared.get((operation_id, gate_action))
            return None if current is None else current[2]

    def prepared_target_fence_binding(
        self, operation_id: OperationId, gate_action: str,
    ) -> PreparedTargetFenceBinding | None:
        with self._lock:
            key = operation_id, gate_action
            current = self._prepared.get(key)
            if current is None or current[1] != "PREPARED" or current[2] is not None:
                return None
            record = current[0]
            preimage = getattr(record, "preimage", None)
            prepared_start_id = getattr(record, "prepared_start_id", None)
            fence_generation = self._prepared_fence_generations.get(key)
            if (prepared_start_id is None or preimage is None
                    or type(fence_generation) is not int):
                return None
            target_fence = getattr(preimage, "target_fence", None)
            root_context_id = getattr(preimage, "root_context_id", None)
            runtime_generation = getattr(preimage, "runtime_generation", None)
            runtime_binding_id = getattr(preimage, "runtime_binding_id", None)
            service_identity = getattr(preimage, "service_identity", None)
            if (target_fence is None or type(root_context_id) is not RootContextId
                    or type(getattr(runtime_generation, "value", None)) is not int
                    or type(runtime_binding_id) is not GateRuntimeBindingId
                    or type(service_identity) is not ServicePrincipalId):
                return None
            role = (
                "MERGE_AUTHORITY" if gate_action == "FAST_FORWARD_MERGE"
                else "PUBLICATION_AUTHORITY"
            )
            authority_identity = RawSha256(hashlib.sha256(canonical_json_bytes((
                "autodev.fixture-role-authority-binding/v1", self._substrate_identity,
                role, service_identity, root_context_id,
                runtime_generation.value, runtime_binding_id,
            ))).hexdigest())
            target_identity = RawSha256(hashlib.sha256(canonical_json_bytes((
                "autodev.fixture-target-fence/v1", target_fence,
            ))).hexdigest())
            return PreparedTargetFenceBinding(
                "autodev.prepared-target-fence-binding/v1",
                self._substrate_identity, authority_identity, operation_id,
                gate_action, target_identity, prepared_start_id, root_context_id,
                runtime_generation.value, fence_generation,
            )

    def _release_start_held_for_fixture_recovery(
        self, binding: StartHeldTargetFenceBinding, prepared_record: object,
        authority: object,
    ) -> bool:
        """External recovery mutation inaccessible through ordinary P/M clients."""
        if (type(binding) is not StartHeldTargetFenceBinding
                or authority is not self._external_recovery_authority):
            return False
        with self._lock:
            key = binding.operation_id, binding.action_class
            current = self._prepared.get(key)
            if (current is None or current[0] is not prepared_record
                    or current[1] != "START_HELD"
                    or current[2] != binding or key in self._markers):
                return False
            self._prepared[key] = (current[0], "RELEASED", binding)
            self._generation += 1
            return True

    def release_prepared_effect(
        self, operation_id: OperationId, gate_action: str, *,
        _fence_token: FixtureFenceToken | None = None,
        _authority: object | None = None,
    ) -> bool:
        with self._lock:
            if not self._authority_matches_action(gate_action, _authority):
                return False
            key = operation_id, gate_action
            self._guard(("prepared", operation_id, gate_action), _fence_token,
                        allow_prepared_key=key)
            current = self._prepared.get(key)
            if current is None or current[1] != "PREPARED" or key in self._markers:
                return False
            self._prepared[key] = (current[0], "RELEASED", None)
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
                         _fence_token: FixtureFenceToken | None = None,
                         _authority: object | None = None) -> bool:
        with self._lock:
            if (marker.preimage.gate_action != "CANDIDATE_BRANCH_PUBLICATION"
                    or not self._authority_matches_action(marker.preimage.gate_action, _authority)):
                return False
            marker_key = marker.preimage.operation_id, marker.preimage.gate_action
            held = self._prepared.get(marker_key)
            if held is None or held[1] != "START_HELD" or held[2] is None:
                return False
            self._guard(("repository", repository_id), _fence_token, allow_prepared_key=marker_key)
            self._guard(("ref", repository_id, ref), _fence_token, allow_prepared_key=marker_key)
            self._guard(("prepared", *marker_key), _fence_token, allow_prepared_key=marker_key)
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
            if prepared is not None and prepared[1] == "START_HELD":
                self._prepared[marker_key] = (prepared[0], "CONSUMED", prepared[2])
            else:
                self._prepared[marker_key] = (None if prepared is None else prepared[0], "CONSUMED", None)
            self._generation += 1
            return True

    def create_pull_request_and_mark(self, repository_id: GitHubRepositoryId,
                                     head: CanonicalBranchRef, base: CanonicalBranchRef,
                                     head_sha: GitSha, marker: ProtectedEffectMarker, *,
                                     _fence_token: FixtureFenceToken | None = None,
                                     _authority: object | None = None) -> FixturePullRequest | None:
        with self._lock:
            if (marker.preimage.gate_action != "PULL_REQUEST_CREATION"
                    or not self._authority_matches_action(marker.preimage.gate_action, _authority)):
                return None
            base_sha = self._refs.get((repository_id, base))
            marker_key = marker.preimage.operation_id, marker.preimage.gate_action
            held = self._prepared.get(marker_key)
            if held is None or held[1] != "START_HELD" or held[2] is None:
                return None
            self._guard(("repository", repository_id), _fence_token, allow_prepared_key=marker_key)
            self._guard(("prs", repository_id), _fence_token, allow_prepared_key=marker_key)
            self._guard(("prepared", *marker_key), _fence_token, allow_prepared_key=marker_key)
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
            if prepared is not None and prepared[1] == "START_HELD":
                self._prepared[marker_key] = (prepared[0], "CONSUMED", prepared[2])
            else:
                self._prepared[marker_key] = (None if prepared is None else prepared[0], "CONSUMED", None)
            self._generation += 1
            return pr

    def fast_forward_and_mark(self, repository_id: GitHubRepositoryId, target: CanonicalBranchRef,
                              expected: GitSha, candidate: GitSha, candidate_parent: GitSha,
                              pull_request_number: int, marker: ProtectedEffectMarker, *,
                              _fence_token: FixtureFenceToken | None = None,
                              _authority: object | None = None) -> bool:
        with self._lock:
            if (marker.preimage.gate_action != "FAST_FORWARD_MERGE"
                    or not self._authority_matches_action(marker.preimage.gate_action, _authority)):
                return False
            marker_key = marker.preimage.operation_id, marker.preimage.gate_action
            held = self._prepared.get(marker_key)
            if held is None or held[1] != "START_HELD" or held[2] is None:
                return False
            self._guard(("repository", repository_id), _fence_token, allow_prepared_key=marker_key)
            self._guard(("ref", repository_id, target), _fence_token, allow_prepared_key=marker_key)
            self._guard(("prs", repository_id), _fence_token, allow_prepared_key=marker_key)
            self._guard(("prepared", *marker_key), _fence_token, allow_prepared_key=marker_key)
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
            if prepared is not None and prepared[1] == "START_HELD":
                self._prepared[marker_key] = (prepared[0], "CONSUMED", prepared[2])
            else:
                self._prepared[marker_key] = (None if prepared is None else prepared[0], "CONSUMED", None)
            self._generation += 1
            return True

    def fast_forward(self, repository_id: GitHubRepositoryId, target: CanonicalBranchRef,
                     expected: GitSha, candidate: GitSha, candidate_parent: GitSha) -> bool:
        """Model an out-of-band external ref update, not an F-authorized merge.

        Role-scoped protected mutation uses ``fast_forward_and_mark`` and is
        fenced by the exact START_HELD binding.  This fixture-only hook models
        an independent actor changing provider state despite our local fence;
        reconciliation must then fail closed rather than infer our effect.
        """
        with self._lock:
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
            self._guard(("prepared", *key), allow_prepared_key=key)
            self._guard(("repository", subject.repository_id), allow_prepared_key=key)
            if type(subject) is PublishedCandidateRefEffectSubject:
                self._guard(("ref", subject.repository_id, subject.destination_branch), allow_prepared_key=key)
            elif type(subject) is CreatedCandidatePrEffectSubject:
                self._guard(("prs", subject.repository_id), allow_prepared_key=key)
            elif type(subject) is FastForwardMergeEffectSubject:
                self._guard(("prs", subject.repository_id), allow_prepared_key=key)
                self._guard(("ref", subject.repository_id, CanonicalBranchRef(subject.integration_ref.value)), allow_prepared_key=key)
            current = self._markers.get(key)
            if current is not None and current != marker:
                raise ValueError("effect marker provenance conflict")
            if current is None:
                self._markers[key] = marker
                prepared = self._prepared.get(key)
                if prepared is not None and prepared[1] == "START_HELD":
                    self._prepared[key] = (prepared[0], "CONSUMED", prepared[2])
                else:
                    self._prepared[key] = (None if prepared is None else prepared[0], "CONSUMED", None)
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
