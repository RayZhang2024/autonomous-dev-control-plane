import pytest

from autodev_control.trusted.decision import Decision, TrustedDecision
from autodev_control.trusted.errors import DecisionReasonCode, ParseFailure, ParseFailureCode
from autodev_control.trusted.parsing import ParseLimits, parse_trusted_json


def test_decision_domain_has_exact_outcomes() -> None:
    assert {item.value for item in Decision} == {"ALLOW", "DENY", "ESCALATE"}
    assert Decision.ALLOW != "ALLOW"
    assert TrustedDecision(Decision.ALLOW, DecisionReasonCode.UNSPECIFIED).decision is Decision.ALLOW


@pytest.mark.parametrize(
    "decision, reason",
    [
        ("ALLOW", DecisionReasonCode.UNSPECIFIED),
        (Decision.ALLOW, "UNSPECIFIED"),
        (Decision.ALLOW, ParseFailureCode.INVALID_JSON),
    ],
)
def test_decision_rejects_plain_and_cross_domain_values(decision: object, reason: object) -> None:
    with pytest.raises(TypeError):
        TrustedDecision(decision, reason)


def test_parser_results_are_not_decisions() -> None:
    for result in (parse_trusted_json(b"null", ParseLimits(4, 1)), parse_trusted_json("null", ParseLimits(4, 1))):
        assert not isinstance(result, TrustedDecision)
        assert not isinstance(result, Decision)
    assert isinstance(parse_trusted_json("null", ParseLimits(4, 1)), ParseFailure)
