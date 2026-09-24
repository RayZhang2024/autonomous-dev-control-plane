"""Closed pre-G9 role and external-fixture authority contracts.

These immutable contracts describe the caller and F-side authority carried
between the four candidate roles.  They do not implement a production
transport or claim process isolation; fixture channels are deterministic test
bindings only.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
from typing import Protocol, runtime_checkable

from .backend import canonical_json_bytes
from .identity import (
    CandidateMaterializationId, GateRuntimeBindingId, OperationStartBindingId,
    PreparedProtectedStartId, RawSha256, RootContextId,
)
from .operation import (
    CandidateId, OperationActionId, OperationId, OperationIdempotencyKey,
    StartHeldTargetFenceBinding,
)
from .scope import ServicePrincipalId, TargetRegistrationId


class TrustedRuntimeRole(Enum):
    CONTROLLER = "trusted-controller"
    CONTROL_STATE_GATE = "control-state-gate"
    PUBLICATION_GATE = "fixture-publication-gate"
    MERGE_GATE = "fixture-merge-gate"


class ProtectedGateCommand(Enum):
    PREPARE_PUBLICATION = "PREPARE_PUBLICATION"
    ABORT_PREPARED_PUBLICATION = "ABORT_PREPARED_PUBLICATION"
    SEAL_PUBLICATION_FOR_START = "SEAL_PUBLICATION_FOR_START"
    EXECUTE_PUBLICATION = "EXECUTE_PUBLICATION"
    READ_VERIFY_PUBLICATION_STATE = "READ_VERIFY_PUBLICATION_STATE"
    PREPARE_MERGE = "PREPARE_MERGE"
    ABORT_PREPARED_MERGE = "ABORT_PREPARED_MERGE"
    SEAL_MERGE_FOR_START = "SEAL_MERGE_FOR_START"
    EXECUTE_MERGE = "EXECUTE_MERGE"
    READ_VERIFY_MERGE_STATE = "READ_VERIFY_MERGE_STATE"


@dataclass(frozen=True, slots=True)
class ProtectedGateRequest:
    """Closed T→P/M request; channel authentication remains out-of-band."""

    format: str
    command: ProtectedGateCommand
    declared_t_identity: RawSha256
    destination_identity: RawSha256
    root_context_id: RootContextId
    runtime_generation: int
    operation_id: OperationId
    action_class: str
    action_id: OperationActionId
    idempotency_key: OperationIdempotencyKey
    candidate_id: CandidateId
    materialization_id: CandidateMaterializationId
    target_registration_id: TargetRegistrationId
    prepared_start_id: PreparedProtectedStartId | None
    operation_start_binding_id: OperationStartBindingId | None
    prepared_target_fence_binding: PreparedTargetFenceBinding | None
    start_held_target_fence_binding: StartHeldTargetFenceBinding | None
    fixture_substrate_identity: RawSha256
    authority_binding_identity: RawSha256
    target_fence_identity: RawSha256
    request_identity: RawSha256
    request_digest: RawSha256

    def __post_init__(self) -> None:
        if self.format != "autodev.trusted-controller-to-protected-gate/v1":
            raise ValueError("unsupported protected-gate request format")
        exact = (
            (self.command, ProtectedGateCommand),
            (self.declared_t_identity, RawSha256),
            (self.destination_identity, RawSha256),
            (self.root_context_id, RootContextId),
            (self.operation_id, OperationId),
            (self.action_id, OperationActionId),
            (self.idempotency_key, OperationIdempotencyKey),
            (self.candidate_id, CandidateId),
            (self.materialization_id, CandidateMaterializationId),
            (self.target_registration_id, TargetRegistrationId),
            (self.fixture_substrate_identity, RawSha256),
            (self.authority_binding_identity, RawSha256),
            (self.target_fence_identity, RawSha256),
            (self.request_identity, RawSha256),
            (self.request_digest, RawSha256),
        )
        if any(type(value) is not expected for value, expected in exact):
            raise TypeError("protected-gate request contains a non-exact field")
        if type(self.action_class) is not str or not self.action_class:
            raise TypeError("protected-gate action class must be exact")
        if type(self.runtime_generation) is not int or self.runtime_generation < 1:
            raise ValueError("protected-gate runtime generation must be positive")
        publication_commands = {
            ProtectedGateCommand.PREPARE_PUBLICATION,
            ProtectedGateCommand.ABORT_PREPARED_PUBLICATION,
            ProtectedGateCommand.SEAL_PUBLICATION_FOR_START,
            ProtectedGateCommand.EXECUTE_PUBLICATION,
            ProtectedGateCommand.READ_VERIFY_PUBLICATION_STATE,
        }
        merge_commands = {
            ProtectedGateCommand.PREPARE_MERGE,
            ProtectedGateCommand.ABORT_PREPARED_MERGE,
            ProtectedGateCommand.SEAL_MERGE_FOR_START,
            ProtectedGateCommand.EXECUTE_MERGE,
            ProtectedGateCommand.READ_VERIFY_MERGE_STATE,
        }
        publication_actions = {"CANDIDATE_BRANCH_PUBLICATION", "PULL_REQUEST_CREATION"}
        if ((self.command in publication_commands) != (self.action_class in publication_actions)):
            raise ValueError("protected request command and action class differ")
        execute_commands = {
            ProtectedGateCommand.EXECUTE_PUBLICATION,
            ProtectedGateCommand.EXECUTE_MERGE,
        }
        if self.command in execute_commands:
            if (type(self.prepared_start_id) is not PreparedProtectedStartId
                    or type(self.operation_start_binding_id) is not OperationStartBindingId
                    or type(self.start_held_target_fence_binding) is not StartHeldTargetFenceBinding):
                raise TypeError("EXECUTE requires exact prepared and canonical start identities")
        elif (self.prepared_start_id is not None
              and type(self.prepared_start_id) is not PreparedProtectedStartId):
            raise TypeError("prepared identity must be exact or absent")
        elif (self.operation_start_binding_id is not None
              and type(self.operation_start_binding_id) is not OperationStartBindingId):
            raise TypeError("canonical start identity must be exact or absent")
        if (self.prepared_target_fence_binding is not None
                and type(self.prepared_target_fence_binding) is not PreparedTargetFenceBinding):
            raise TypeError("prepared target-fence binding must be exact or absent")
        if (self.start_held_target_fence_binding is not None
                and type(self.start_held_target_fence_binding) is not StartHeldTargetFenceBinding):
            raise TypeError("start-held target-fence binding must be exact or absent")
        if (self.command in {
            ProtectedGateCommand.ABORT_PREPARED_PUBLICATION,
            ProtectedGateCommand.SEAL_PUBLICATION_FOR_START,
            ProtectedGateCommand.ABORT_PREPARED_MERGE,
            ProtectedGateCommand.SEAL_MERGE_FOR_START,
        } and type(self.prepared_target_fence_binding) is not PreparedTargetFenceBinding):
            raise TypeError("ABORT/SEAL requires the exact F-prepared fence binding")
        expected_identity = RawSha256(hashlib.sha256(canonical_json_bytes((
            "autodev.protected-gate-request-id/v1", self.command,
            self.declared_t_identity, self.destination_identity,
            self.root_context_id, self.runtime_generation, self.operation_id,
            self.action_class, self.action_id, self.idempotency_key,
            self.candidate_id, self.materialization_id,
            self.target_registration_id, self.prepared_start_id,
            self.operation_start_binding_id, self.prepared_target_fence_binding,
            self.start_held_target_fence_binding, self.fixture_substrate_identity,
            self.authority_binding_identity,
            self.target_fence_identity,
        ))).hexdigest())
        if self.request_identity != expected_identity:
            raise ValueError("protected-gate request identity differs from exact fields")
        expected_digest = RawSha256(hashlib.sha256(canonical_json_bytes((
            self.format, self.command, self.declared_t_identity,
            self.destination_identity, self.root_context_id,
            self.runtime_generation, self.operation_id, self.action_class,
            self.action_id, self.idempotency_key, self.candidate_id,
            self.materialization_id, self.target_registration_id,
            self.prepared_start_id, self.operation_start_binding_id,
            self.prepared_target_fence_binding,
            self.start_held_target_fence_binding, self.fixture_substrate_identity,
            self.authority_binding_identity,
            self.target_fence_identity,
            self.request_identity,
        ))).hexdigest())
        if self.request_digest != expected_digest:
            raise ValueError("protected-gate request digest differs from exact fields")


@dataclass(frozen=True, slots=True)
class RuntimeSecurityContext:
    role: TrustedRuntimeRole
    service_identity: ServicePrincipalId
    root_context_id: RootContextId
    runtime_generation: int
    runtime_binding_id: GateRuntimeBindingId

    def __post_init__(self) -> None:
        if type(self.role) is not TrustedRuntimeRole:
            raise TypeError("runtime role must be exact")
        if type(self.service_identity) is not ServicePrincipalId:
            raise TypeError("runtime service identity must be exact")
        if type(self.root_context_id) is not RootContextId:
            raise TypeError("runtime root identity must be exact")
        if type(self.runtime_generation) is not int or self.runtime_generation < 1:
            raise ValueError("runtime generation must be positive")
        if type(self.runtime_binding_id) is not GateRuntimeBindingId:
            raise TypeError("runtime binding id must be exact")


@dataclass(frozen=True, slots=True, init=False)
class AuthenticatedCallerContext:
    """Transport-established caller identity, deliberately absent from request bytes."""

    context: RuntimeSecurityContext
    request_digest: RawSha256
    _channel_token: object

    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("caller contexts are issued only by a trusted channel boundary")


@dataclass(frozen=True, slots=True)
class ControllerRequestContext:
    """Non-secret declared T→C routing identities carried by closed requests."""

    caller: RuntimeSecurityContext
    destination: RuntimeSecurityContext

    def __post_init__(self) -> None:
        if (type(self.caller) is not RuntimeSecurityContext
                or self.caller.role is not TrustedRuntimeRole.CONTROLLER
                or type(self.destination) is not RuntimeSecurityContext
                or self.destination.role is not TrustedRuntimeRole.CONTROL_STATE_GATE):
            raise TypeError("controller request context has wrong exact roles")


def runtime_context_identity(context: RuntimeSecurityContext) -> RawSha256:
    if type(context) is not RuntimeSecurityContext:
        raise TypeError("exact runtime context required")
    return RawSha256(hashlib.sha256(canonical_json_bytes((
        "autodev.trusted-runtime-context/v1", context,
    ))).hexdigest())


def _issue_fixture_caller_context(
    channel_token: object, context: RuntimeSecurityContext,
    request_digest: RawSha256,
) -> AuthenticatedCallerContext:
    if (type(channel_token) is not object
            or type(context) is not RuntimeSecurityContext
            or type(request_digest) is not RawSha256):
        raise TypeError("exact fixture channel and runtime context required")
    value = object.__new__(AuthenticatedCallerContext)
    object.__setattr__(value, "context", context)
    object.__setattr__(value, "request_digest", request_digest)
    object.__setattr__(value, "_channel_token", channel_token)
    return value


@dataclass(frozen=True, slots=True)
class PreparedTargetFenceBinding:
    format: str
    fixture_substrate_identity: RawSha256
    authority_binding_identity: RawSha256
    operation_id: OperationId
    action_class: str
    target_fence_identity: RawSha256
    prepared_start_id: PreparedProtectedStartId
    root_context_id: RootContextId
    runtime_generation: int
    fence_generation: int

    def __post_init__(self) -> None:
        if self.format != "autodev.prepared-target-fence-binding/v1":
            raise ValueError("unsupported prepared-fence binding format")
        if any(type(v) is not RawSha256 for v in (
            self.fixture_substrate_identity, self.authority_binding_identity,
            self.target_fence_identity,
        )):
            raise TypeError("prepared-fence digests must be exact RawSha256")
        if type(self.operation_id) is not OperationId or type(self.action_class) is not str or not self.action_class:
            raise TypeError("prepared-fence action identity is malformed")
        if type(self.prepared_start_id) is not PreparedProtectedStartId:
            raise TypeError("prepared-fence start id must be exact")
        if type(self.root_context_id) is not RootContextId:
            raise TypeError("prepared-fence root must be exact")
        if (type(self.runtime_generation) is not int or self.runtime_generation < 1
                or type(self.fence_generation) is not int or self.fence_generation < 1):
            raise ValueError("prepared-fence generations must be positive")


@runtime_checkable
class FixtureReadVerifyClient(Protocol):
    """Narrow F read/verify contract suitable for C and protected-role checks."""

    def verify_prepared_target_fence(self, binding: PreparedTargetFenceBinding) -> bool: ...
    def verify_start_held_target_fence(self, binding: StartHeldTargetFenceBinding) -> bool: ...
    def prepared_target_fence_binding(
        self, operation_id: OperationId, action_class: str,
    ) -> PreparedTargetFenceBinding | None: ...

    def authoritative_snapshot(
        self, repository_id: object, profile_id: object, transport_id: object,
    ) -> object | None: ...
    def authoritative_facts(
        self, repository_id: object, profile_id: object, transport_id: object,
    ) -> frozenset[tuple] | None: ...
    def authoritative_binding(
        self, repository_id: object, profile_id: object, transport_id: object,
    ) -> object | None: ...
    @property
    def substrate_identity(self) -> RawSha256: ...
    def read_prepared_effect_record(self, operation_id: OperationId, action_class: str) -> object | None: ...
    def read_prepared_effect_state(self, operation_id: OperationId, action_class: str) -> str | None: ...
    def read_ref(self, repository_id: object, ref: object) -> object | None: ...
    def read_marker(self, operation_id: OperationId, action_class: str) -> object | None: ...
    def read_pull_request(self, number: object) -> object | None: ...
    def read_next_pull_request_number(self) -> int: ...
    def verify_materialization(self, materialization: object) -> bool: ...
    def verify_marker_postcondition(self, marker: object) -> bool: ...


@runtime_checkable
class ControlStateGateClient(Protocol):
    """Authenticated C transport; it exposes no fixture F mutation surface."""

    def commit_control_state(
        self, request: object, lease: object,
        caller_context: AuthenticatedCallerContext | None = None,
    ) -> object: ...

    def commit_authenticated_request(
        self, request: object, dependencies: object,
        caller_context: AuthenticatedCallerContext,
    ) -> object: ...


@runtime_checkable
class PublicationGateClient(Protocol):
    """Publication-only T→P transport; no merge or canonical-write methods."""

    def prepare_start(self, prepared: object) -> object | None: ...

    def abort_start(self, prepared_start_id: PreparedProtectedStartId) -> bool: ...

    def seal_start(
        self, prepared_start_id: PreparedProtectedStartId,
    ) -> StartHeldTargetFenceBinding | None: ...

    def execute_started(
        self, prepared_start_id: PreparedProtectedStartId,
        expected_start_binding_id: OperationStartBindingId,
    ) -> object: ...

    def perform_publication(
        self, continuation: object,
        caller_context: AuthenticatedCallerContext | None = None,
    ) -> object: ...


@runtime_checkable
class MergeGateClient(Protocol):
    """Merge-only T→M transport; no publication or canonical-write methods."""

    def prepare_start(self, prepared: object) -> object | None: ...

    def abort_start(self, prepared_start_id: PreparedProtectedStartId) -> bool: ...

    def seal_start(
        self, prepared_start_id: PreparedProtectedStartId,
    ) -> StartHeldTargetFenceBinding | None: ...

    def execute_started(
        self, prepared_start_id: PreparedProtectedStartId,
        expected_start_binding_id: OperationStartBindingId,
    ) -> object: ...

    def perform_merge(
        self, continuation: object,
        caller_context: AuthenticatedCallerContext | None = None,
    ) -> object: ...


@runtime_checkable
class PublicationAuthorityClient(Protocol):
    """Publication-only F mutation contract; it has no merge operations."""

    def prepare_publication(self, prepared: object, fence_token: object) -> bool: ...
    def binding_identity(
        self, service_identity: object, root_context_id: object,
        runtime_generation: int, runtime_binding_id: object,
    ) -> RawSha256: ...
    def abort_prepared_publication(
        self, operation_id: OperationId, action_class: str,
        fence_token: object | None = None,
    ) -> bool: ...
    def seal_publication_for_start(
        self, operation_id: OperationId, action_class: str, prepared: object,
        authority_binding_identity: RawSha256,
    ) -> StartHeldTargetFenceBinding | None: ...
    def execute_candidate_ref_publication(
        self, repository_id: object, ref: object, sha: object, marker: object,
        *, fence_token: object | None = None,
    ) -> bool: ...
    def execute_candidate_pr_creation(
        self, repository_id: object, head: object, base: object, head_sha: object,
        marker: object, *, fence_token: object | None = None,
    ) -> object | None: ...
    def recover_release_start_held(self, binding: StartHeldTargetFenceBinding) -> bool: ...


@runtime_checkable
class MergeAuthorityClient(Protocol):
    """Merge-only F mutation contract; it has no publication operations."""

    def prepare_merge(self, prepared: object, fence_token: object) -> bool: ...
    def binding_identity(
        self, service_identity: object, root_context_id: object,
        runtime_generation: int, runtime_binding_id: object,
    ) -> RawSha256: ...
    def abort_prepared_merge(
        self, operation_id: OperationId, action_class: str,
        fence_token: object | None = None,
    ) -> bool: ...
    def seal_merge_for_start(
        self, operation_id: OperationId, action_class: str, prepared: object,
        authority_binding_identity: RawSha256,
    ) -> StartHeldTargetFenceBinding | None: ...
    def execute_fast_forward_merge(
        self, repository_id: object, target: object, expected: object,
        candidate: object, candidate_parent: object,
        pull_request_number: int, marker: object,
        *, fence_token: object | None = None,
    ) -> bool: ...
    def recover_release_start_held(self, binding: StartHeldTargetFenceBinding) -> bool: ...


@runtime_checkable
class CanonicalStartReadClient(Protocol):
    """Exact canonical read surface required by P/M before protected effects."""

    @property
    def occurrence(self) -> object: ...

    def read_task_working_set(self, task_id: object) -> object | None: ...

    def read_resolved_target_registration(self, target_registration_id: object) -> object | None: ...


@runtime_checkable
class GateRoleFenceClient(Protocol):
    """Role-scoped F fence lifecycle contract, excluding broad fixture administration."""

    def is_active(self) -> bool: ...

    def acquire(self, facts: frozenset[tuple]) -> object | None: ...

    def release(self, token: object) -> None: ...


@runtime_checkable
class GateAuditClient(Protocol):
    """Append-only audit sink contract for a candidate role."""

    def append_event(self, event: object) -> object: ...


@runtime_checkable
class AuthenticatedCallerVerifier(Protocol):
    """Narrow fixture/transport verifier; it cannot issue caller contexts."""

    def verify(
        self, request_digest: RawSha256,
        caller_context: AuthenticatedCallerContext | None,
    ) -> bool: ...
