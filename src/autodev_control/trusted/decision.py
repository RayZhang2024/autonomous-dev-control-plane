"""The policy/action decision domain, deliberately separate from parsing."""

from dataclasses import dataclass
from enum import Enum

from .errors import DecisionReasonCode
from .identity import LogicalIdentifier


class Decision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    ESCALATE = "ESCALATE"


@dataclass(frozen=True, slots=True)
class TrustedDecision:
    decision: Decision
    reason_code: DecisionReasonCode
    subject: LogicalIdentifier | None = None
    explanation: str | None = None
