"""Non-genesis in-memory audit sink and deterministic fault injection."""

from threading import RLock

from .audit import AuditAppendStatus, GateAuditEvent, GateAuditEventId, GateAuditRecord


class FixtureGateAudit:
    """Diagnostic fixture sink. Its contents cannot authorize control or effects."""

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
