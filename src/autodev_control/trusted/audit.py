"""Versioned, append-only and explicitly non-authoritative gate audit."""

from dataclasses import dataclass
from enum import Enum
import hashlib
from threading import RLock

from .backend import CanonicalStateOccurrenceBinding, canonical_json_bytes
from .identity import (
    CandidateMaterializationId, GateAuditEventId, MutationInventoryId,
    GateRuntimeBindingId, ImmutableConfigId, OperationStartBindingId,
    ProtectedEffectMarkerId, RawSha256, RootContextId,
)
from .manifest import PolicyEpochIdentity
from .operation import AuthoritativeStateBindingId, CandidateId, OperationId
from .scope import (
    AuthorizationId, GitHubRepositoryId, ServicePrincipalId,
    TargetRegistrationId, TaskId,
)


class GateAuditOutcome(Enum):
    APPLIED = "APPLIED"
    ALREADY_APPLIED = "ALREADY_APPLIED"
    DENIED = "DENIED"
    ESCALATED = "ESCALATED"
    PRECONDITION_CONFLICT = "PRECONDITION_CONFLICT"
    CAS_CONFLICT = "CAS_CONFLICT"
    RELEASED = "RELEASED"
    RECONCILED_SUCCEEDED = "RECONCILED_SUCCEEDED"
    RECONCILED_FAILED = "RECONCILED_FAILED"
    INDETERMINATE = "INDETERMINATE"
    NO_EFFECT = "NO_EFFECT"
    AUDIT_INTEGRITY_FAILURE = "AUDIT_INTEGRITY_FAILURE"
    ATTEMPTED = "ATTEMPTED"


class AuditAppendStatus(Enum):
    APPENDED = "APPENDED"
    ALREADY_PRESENT = "ALREADY_PRESENT"
    IDENTITY_CONFLICT = "IDENTITY_CONFLICT"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


@dataclass(frozen=True, slots=True)
class GateAuditAuthoritativeDependency:
    """Exact audit projection of one authoritative dependency member."""

    repository_id: GitHubRepositoryId
    observation_profile_id: ImmutableConfigId
    transport_config_id: ImmutableConfigId
    expected_binding_id: AuthoritativeStateBindingId

    def __post_init__(self) -> None:
        exact = (
            (self.repository_id, GitHubRepositoryId),
            (self.observation_profile_id, ImmutableConfigId),
            (self.transport_config_id, ImmutableConfigId),
            (self.expected_binding_id, AuthoritativeStateBindingId),
        )
        if any(type(value) is not expected for value, expected in exact):
            raise TypeError("audit dependency has wrong exact type")


@dataclass(frozen=True, slots=True)
class GateAuditEventPreimage:
    format: str
    gate: str
    action: str
    outcome: GateAuditOutcome
    root_context_id: RootContextId
    runtime_generation: int
    runtime_binding_id: GateRuntimeBindingId
    service_identity: ServicePrincipalId
    authoritative_dependencies: tuple[GateAuditAuthoritativeDependency, ...]
    dependency_set_identity: RawSha256
    canonical_state_occurrence_binding: CanonicalStateOccurrenceBinding | None
    operation_id: OperationId | None
    operation_start_binding_id: OperationStartBindingId | None
    protected_effect_marker_id: ProtectedEffectMarkerId | None
    action_digest: RawSha256 | None
    result_identity: str
    detail: str
    task_id: TaskId | None = None
    candidate_id: CandidateId | None = None
    authorization_id: AuthorizationId | None = None
    target_registration_id: TargetRegistrationId | None = None
    policy_epoch_identity: PolicyEpochIdentity | None = None
    candidate_materialization_id: CandidateMaterializationId | None = None
    mutation_inventory_id: MutationInventoryId | None = None

    def __post_init__(self) -> None:
        exact = (
            (self.gate, str), (self.action, str),
            (self.outcome, GateAuditOutcome),
            (self.root_context_id, RootContextId),
            (self.runtime_generation, int),
            (self.runtime_binding_id, GateRuntimeBindingId),
            (self.service_identity, ServicePrincipalId),
            (self.dependency_set_identity, RawSha256),
            (self.result_identity, str), (self.detail, str),
        )
        if self.format != "autodev.gate-audit-event/v1":
            raise ValueError("unsupported gate audit event format")
        if any(type(value) is not expected for value, expected in exact):
            raise TypeError("gate audit preimage has wrong exact type")
        if (type(self.authoritative_dependencies) is not tuple
                or any(type(item) is not GateAuditAuthoritativeDependency
                       for item in self.authoritative_dependencies)):
            raise TypeError("authoritative dependencies must be an exact tuple")
        dependency_keys = tuple(
            (item.repository_id.value, item.observation_profile_id.value,
             item.transport_config_id.value)
            for item in self.authoritative_dependencies
        )
        if dependency_keys != tuple(sorted(dependency_keys)) or len(set(dependency_keys)) != len(dependency_keys):
            raise ValueError("audit dependencies require canonical unique order")
        if (self.canonical_state_occurrence_binding is not None
                and type(self.canonical_state_occurrence_binding)
                is not CanonicalStateOccurrenceBinding):
            raise TypeError("canonical occurrence has wrong exact type")
        optional = (
            (self.operation_id, OperationId),
            (self.operation_start_binding_id, OperationStartBindingId),
            (self.protected_effect_marker_id, ProtectedEffectMarkerId),
            (self.action_digest, RawSha256),
            (self.task_id, TaskId), (self.candidate_id, CandidateId),
            (self.authorization_id, AuthorizationId),
            (self.target_registration_id, TargetRegistrationId),
            (self.policy_epoch_identity, PolicyEpochIdentity),
            (self.candidate_materialization_id, CandidateMaterializationId),
            (self.mutation_inventory_id, MutationInventoryId),
        )
        if any(value is not None and type(value) is not expected for value, expected in optional):
            raise TypeError("optional audit provenance has wrong exact type")
        if self.runtime_generation < 1:
            raise ValueError("runtime generation must be positive")


@dataclass(frozen=True, slots=True)
class GateAuditEvent:
    event_id: GateAuditEventId
    preimage: GateAuditEventPreimage

    def __post_init__(self) -> None:
        if type(self.event_id) is not GateAuditEventId or type(self.preimage) is not GateAuditEventPreimage:
            raise TypeError("audit event fields have wrong exact type")
        expected = GateAuditEventId(RawSha256(hashlib.sha256(canonical_json_bytes(self.preimage)).hexdigest()))
        if self.event_id != expected:
            raise ValueError("audit event identity does not match canonical content")


@dataclass(frozen=True, slots=True)
class GateAuditRecord:
    sequence: int
    event: GateAuditEvent

    def __post_init__(self) -> None:
        if type(self.sequence) is not int or self.sequence < 1:
            raise ValueError("audit sequence must be a positive int")
        if type(self.event) is not GateAuditEvent:
            raise TypeError("audit record event has wrong exact type")


def build_gate_audit_event(preimage: GateAuditEventPreimage) -> GateAuditEvent:
    if type(preimage) is not GateAuditEventPreimage:
        raise TypeError("exact GateAuditEventPreimage required")
    identity = GateAuditEventId(RawSha256(hashlib.sha256(canonical_json_bytes(preimage)).hexdigest()))
    return GateAuditEvent(identity, preimage)


class FixtureGateAudit:
    """Diagnostic sink. Its contents cannot authorize any control or effect."""

    __slots__ = ("_lock", "_records", "_by_id", "_append_attempts", "_fail_attempt")

    def __init__(self) -> None:
        self._lock = RLock()
        self._records: list[GateAuditRecord] = []
        self._by_id: dict[GateAuditEventId, GateAuditEvent] = {}
        self._append_attempts = 0
        self._fail_attempt: int | None = None

    def fail_next_append_for_test(self) -> None:
        with self._lock:
            self._fail_attempt = self._append_attempts + 1

    def fail_append_after_for_test(self, successful_attempts: int) -> None:
        if type(successful_attempts) is not int or successful_attempts < 0:
            raise ValueError("successful_attempts must be a non-negative int")
        with self._lock:
            self._fail_attempt = self._append_attempts + successful_attempts + 1

    def append_event(self, event: GateAuditEvent) -> AuditAppendStatus:
        if type(event) is not GateAuditEvent:
            raise TypeError("exact GateAuditEvent required")
        with self._lock:
            self._append_attempts += 1
            if self._fail_attempt == self._append_attempts:
                self._fail_attempt = None
                return AuditAppendStatus.INTEGRITY_FAILURE
            current = self._by_id.get(event.event_id)
            if current is not None:
                return AuditAppendStatus.ALREADY_PRESENT if current == event else AuditAppendStatus.IDENTITY_CONFLICT
            self._by_id[event.event_id] = event
            self._records.append(GateAuditRecord(len(self._records) + 1, event))
            return AuditAppendStatus.APPENDED

    def snapshot(self) -> tuple[GateAuditRecord, ...]:
        with self._lock:
            return tuple(self._records)
