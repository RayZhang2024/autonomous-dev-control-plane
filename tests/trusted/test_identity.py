import pytest

from autodev_control.trusted.errors import (
    DecisionReasonCode,
    IdentityValidationError,
    IdentityValidationFailureCode,
    ParseFailureCode,
)
from autodev_control.trusted.identity import GitRef, GitSha, ImmutableConfigId, LogicalIdentifier, RawSha256


def test_unicode_identifiers_preserve_exact_value_and_boundaries() -> None:
    assert LogicalIdentifier("x").value == "x"
    assert LogicalIdentifier("a" * 512).value == "a" * 512
    assert LogicalIdentifier(" é ").value == " é "
    assert ImmutableConfigId("e\u0301").value != ImmutableConfigId("é").value
    with pytest.raises(IdentityValidationError): LogicalIdentifier("")
    with pytest.raises(IdentityValidationError): LogicalIdentifier("a" * 513)


def test_git_types_apply_only_lexical_rules() -> None:
    assert GitRef("refs/heads/does-not-exist").value == "refs/heads/does-not-exist"
    assert GitRef("x" * 1024).value == "x" * 1024
    with pytest.raises(IdentityValidationError): GitRef("")
    with pytest.raises(IdentityValidationError): GitRef("x" * 1025)
    assert GitSha("a" * 40).value == "a" * 40
    assert GitSha("b" * 64).value == "b" * 64
    assert RawSha256("c" * 64).value == "c" * 64
    for invalid in ("A" * 40, "a" * 39, "g" * 64):
        with pytest.raises(IdentityValidationError): GitSha(invalid)
    for invalid in ("c" * 63, "C" * 64, "z" * 64):
        with pytest.raises(IdentityValidationError): RawSha256(invalid)


@pytest.mark.parametrize("code", ["INVALID_TYPE", DecisionReasonCode.UNSPECIFIED, ParseFailureCode.INVALID_JSON])
def test_identity_error_rejects_plain_and_cross_domain_codes(code: object) -> None:
    with pytest.raises(TypeError):
        IdentityValidationError(code)
    assert IdentityValidationError(IdentityValidationFailureCode.INVALID_TYPE).code is IdentityValidationFailureCode.INVALID_TYPE
