"""Append-only, explicitly non-authoritative fixture gate audit trail."""

from dataclasses import dataclass
from enum import Enum
from threading import RLock


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

    # Attempt is useful diagnostic context but never authoritative.
    ATTEMPTED = "ATTEMPTED"


@dataclass(frozen=True, slots=True)
class GateAuditRecord:
    sequence: int
    gate: str
    operation: str
    outcome: GateAuditOutcome
    detail: str = ""
    runtime_identity: str = ""
    service_identity: str = ""
    dependency_identity: str = ""

    def __post_init__(self) -> None:
        if type(self.sequence) is not int or self.sequence < 1:
            raise ValueError("audit sequence must be positive")
        if any(type(value) is not str for value in (
            self.gate, self.operation, self.detail, self.runtime_identity,
            self.service_identity, self.dependency_identity,
        )):
            raise TypeError("audit text has wrong exact type")
        if type(self.outcome) is not GateAuditOutcome:
            raise TypeError("audit outcome has wrong exact type")


class FixtureGateAudit:
    """Fixture persistence for diagnostics only; records can never authorize work."""

    __slots__ = ("_lock", "_records", "_fail_next")

    def __init__(self) -> None:
        self._lock = RLock()
        self._records: list[GateAuditRecord] = []
        self._fail_next = False

    def fail_next_append_for_test(self) -> None:
        self._fail_next = True

    def append(self, gate: str, operation: str, outcome: GateAuditOutcome, detail: str = "",
               *, runtime_identity: str = "", service_identity: str = "",
               dependency_identity: str = "") -> bool:
        with self._lock:
            if self._fail_next:
                self._fail_next = False
                return False
            self._records.append(GateAuditRecord(
                len(self._records) + 1, gate, operation, outcome, detail,
                runtime_identity, service_identity, dependency_identity,
            ))
            return True

    def snapshot(self) -> tuple[GateAuditRecord, ...]:
        with self._lock:
            return tuple(self._records)
