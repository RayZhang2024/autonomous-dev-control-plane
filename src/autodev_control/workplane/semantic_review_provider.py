"""Fixture-only semantic-review transport with opaque requests and responses."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Protocol


class ProviderStatus(Enum):
    SUCCESS = "SUCCESS"
    PROVIDER_ERROR = "PROVIDER_ERROR"
    TIMEOUT = "TIMEOUT"


@dataclass(frozen=True)
class ProviderResult:
    """Raw, untrusted transport outcome; metadata has no authority."""

    status: ProviderStatus
    raw_response_bytes: bytes | None = None
    untrusted_metadata: object | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.status, ProviderStatus):
            raise TypeError("status must be a provider transport status")
        if self.status is ProviderStatus.SUCCESS:
            if not isinstance(self.raw_response_bytes, bytes):
                raise TypeError("success requires raw response bytes")
        elif self.raw_response_bytes is not None or self.untrusted_metadata is not None:
            raise ValueError("failure outcomes have no response or metadata")


class SemanticReviewProvider(Protocol):
    def invoke(self, canonical_request_bytes: bytes) -> ProviderResult: ...


class ScriptedSemanticReviewProvider:
    """Return one configured in-memory outcome per explicit invocation."""

    def __init__(self, scripted_result: ProviderResult) -> None:
        self._scripted_result = scripted_result
        self.attempt_count = 0
        self.last_request_bytes: bytes | None = None

    def invoke(self, canonical_request_bytes: bytes) -> ProviderResult:
        self.attempt_count += 1
        self.last_request_bytes = canonical_request_bytes
        return self._scripted_result
