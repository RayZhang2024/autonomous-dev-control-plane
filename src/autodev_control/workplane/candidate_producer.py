"""Fixture-only candidate production with opaque requests and untrusted proposals.

SUCCESS means only that the configured untrusted proposal was returned. This
component establishes no worker or model identity, provenance, authorization,
candidate or materialization truth, evidence, admission, lifecycle state, or
authority. TIMEOUT is a configured synthetic fixture outcome only.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Protocol


class ProposedChangeKind(Enum):
    ADD = "ADD"
    REPLACE = "REPLACE"
    DELETE = "DELETE"


@dataclass(frozen=True)
class ProposedFileChange:
    """Raw, untrusted proposed file change."""

    kind: ProposedChangeKind
    path: str
    content_bytes: bytes | None = None
    mode: str | None = None

    def __post_init__(self) -> None:
        if type(self.kind) is not ProposedChangeKind:
            raise TypeError("kind must be a proposed change kind")
        if type(self.path) is not str:
            raise TypeError("path must be a string")
        if self.content_bytes is not None and type(self.content_bytes) is not bytes:
            raise TypeError("content_bytes must be bytes or None")
        if self.mode is not None and type(self.mode) is not str:
            raise TypeError("mode must be a string or None")
        if self.kind is ProposedChangeKind.DELETE:
            if self.content_bytes is not None:
                raise ValueError("DELETE cannot carry content bytes")
        elif self.content_bytes is None:
            raise ValueError("ADD and REPLACE require content bytes")


@dataclass(frozen=True)
class CandidateProposal:
    """Immutable proposal data; it is not a materialized candidate."""

    claimed_base_revision: str
    changes: tuple[ProposedFileChange, ...]

    def __post_init__(self) -> None:
        if type(self.claimed_base_revision) is not str:
            raise TypeError("claimed_base_revision must be a string")
        if type(self.changes) is not tuple:
            raise TypeError("changes must be a tuple")
        if any(type(change) is not ProposedFileChange for change in self.changes):
            raise TypeError("changes must contain proposed file changes")


class ProducerStatus(Enum):
    SUCCESS = "SUCCESS"
    PRODUCER_ERROR = "PRODUCER_ERROR"
    TIMEOUT = "TIMEOUT"


@dataclass(frozen=True)
class CandidateProducerResult:
    """One untrusted scripted producer outcome."""

    status: ProducerStatus
    candidate_proposal: CandidateProposal | None = None
    untrusted_metadata: object | None = None

    def __post_init__(self) -> None:
        if type(self.status) is not ProducerStatus:
            raise TypeError("status must be a producer transport status")
        if self.status is ProducerStatus.SUCCESS:
            if type(self.candidate_proposal) is not CandidateProposal:
                raise TypeError("SUCCESS requires a candidate proposal")
        elif self.candidate_proposal is not None or self.untrusted_metadata is not None:
            raise ValueError("failure outcomes carry no proposal or metadata")


class CandidateProducer(Protocol):
    def invoke(self, request_bytes: bytes) -> CandidateProducerResult: ...


class ScriptedCandidateProducer:
    """Return one configured in-memory outcome per explicit invocation."""

    def __init__(self, scripted_result: CandidateProducerResult) -> None:
        self._scripted_result = scripted_result
        self.attempt_count = 0
        self.last_request_bytes: bytes | None = None

    def invoke(self, request_bytes: bytes) -> CandidateProducerResult:
        self.attempt_count += 1
        self.last_request_bytes = request_bytes
        return self._scripted_result
