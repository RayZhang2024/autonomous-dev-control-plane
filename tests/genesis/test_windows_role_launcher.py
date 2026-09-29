"""Noninteractive proofs for child primary-token evidence and handle ownership."""

from __future__ import annotations

from pathlib import Path

import pytest

from windows_role_launcher import (
    ChildTokenEvidence,
    ROLE_PRINCIPALS,
    _SECURITY_IMPERSONATION,
    _TOKEN_DUPLICATE,
    _TOKEN_IMPERSONATION,
    _TOKEN_IMPERSONATE,
    _TOKEN_PRIMARY,
    _TOKEN_QUERY,
    _TOKEN_TYPE,
    _TOKEN_USER,
    _primary_token_evidence,
    _profile_environment_arguments,
    _validate_role_token,
    launch_role,
)


class FakeTokenApi:
    def __init__(self, *, sid: str = ROLE_PRINCIPALS["T"][1], token_type: int = _TOKEN_PRIMARY,
                 duplicate_error: Exception | None = None,
                 membership_error: Exception | None = None,
                 type_query_error: Exception | None = None) -> None:
        self.sid = sid
        self.token_type = token_type
        self.duplicate_error = duplicate_error
        self.membership_error = membership_error
        self.type_query_error = type_query_error
        self.closed: list[int] = []
        self.events: list[tuple] = []

    def open_process_token(self, process: int, access: int) -> int:
        self.events.append(("open", process, access))
        assert access == _TOKEN_QUERY | _TOKEN_DUPLICATE
        return 101

    def token_information(self, token: int, info_class: int) -> str | int:
        self.events.append(("information", token, info_class))
        assert token == 101  # SID and type must come from the child's primary token.
        if info_class == _TOKEN_USER:
            return self.sid
        assert info_class == _TOKEN_TYPE
        if self.type_query_error is not None:
            raise self.type_query_error
        return self.token_type

    def duplicate_token_ex(self, token: int, access: int, level: int, token_type: int) -> int:
        self.events.append(("duplicate", token, access, level, token_type))
        assert token == 101
        assert access == _TOKEN_QUERY | _TOKEN_IMPERSONATE
        assert level == _SECURITY_IMPERSONATION
        assert token_type == _TOKEN_IMPERSONATION
        if self.duplicate_error is not None:
            raise self.duplicate_error
        return 202

    def is_administrator(self, token: int) -> bool:
        self.events.append(("membership", token))
        assert token == 202  # Never pass the primary token to CheckTokenMembership.
        if self.membership_error is not None:
            raise self.membership_error
        return False

    def close_handle(self, handle: int) -> None:
        self.events.append(("close", handle))
        self.closed.append(handle)


def test_sid_and_token_type_are_queried_from_child_primary_token():
    api = FakeTokenApi()
    evidence = _primary_token_evidence(77, api)
    assert evidence == ChildTokenEvidence(ROLE_PRINCIPALS["T"][1], _TOKEN_PRIMARY, False)
    assert ("information", 101, _TOKEN_USER) in api.events
    assert ("information", 101, _TOKEN_TYPE) in api.events
    assert [event for event in api.events if event[0] == "membership"] == [("membership", 202)]
    assert api.closed == [202, 101]


def test_primary_token_is_distinguished_from_impersonation_and_rejected():
    api = FakeTokenApi(token_type=_TOKEN_IMPERSONATION)
    with pytest.raises(RuntimeError, match="not TokenPrimary"):
        _primary_token_evidence(77, api)
    assert not any(event[0] == "duplicate" for event in api.events)
    assert api.closed == [101]


def test_duplicate_token_failure_fails_closed_and_closes_primary():
    api = FakeTokenApi(duplicate_error=OSError("duplicate failed"))
    with pytest.raises(OSError, match="duplicate failed"):
        _primary_token_evidence(77, api)
    assert not any(event[0] == "membership" for event in api.events)
    assert api.closed == [101]


def test_membership_failure_fails_closed_and_closes_both_token_handles():
    api = FakeTokenApi(membership_error=OSError("membership failed"))
    with pytest.raises(OSError, match="membership failed"):
        _primary_token_evidence(77, api)
    assert api.closed == [202, 101]


def test_later_token_evidence_failure_closes_primary_without_fallback():
    api = FakeTokenApi(type_query_error=OSError("TokenType unavailable"))
    with pytest.raises(OSError, match="TokenType unavailable"):
        _primary_token_evidence(77, api)
    assert not any(event[0] == "duplicate" for event in api.events)
    assert api.closed == [101]


def test_exact_actual_role_sid_is_required_and_missing_evidence_never_falls_back():
    _validate_role_token("T", ChildTokenEvidence(ROLE_PRINCIPALS["T"][1], _TOKEN_PRIMARY, False))
    with pytest.raises(PermissionError, match="child SID"):
        _validate_role_token("T", ChildTokenEvidence(ROLE_PRINCIPALS["C"][1], _TOKEN_PRIMARY, False))
    with pytest.raises(TypeError, match="actual child-token evidence"):
        _validate_role_token("T", None)  # type: ignore[arg-type]


def test_administrator_child_token_is_rejected():
    with pytest.raises(PermissionError, match="administrator"):
        _validate_role_token("T", ChildTokenEvidence(ROLE_PRINCIPALS["T"][1], _TOKEN_PRIMARY, True))


@pytest.mark.parametrize("role", ("T", "C", "P", "M"))
def test_every_role_uses_profile_environment_and_null_environment_pointer(role):
    logon_flags, creation_flags, buffer, environment_pointer = _profile_environment_arguments(role)
    from windows_role_launcher import _LOGON_WITH_PROFILE
    assert logon_flags == _LOGON_WITH_PROFILE
    assert creation_flags == 0
    assert buffer is None
    assert environment_pointer is None


def test_normal_role_launcher_has_no_caller_environment_parameter_or_diagnostic_mode():
    import inspect
    parameters = inspect.signature(launch_role).parameters
    assert "environment" not in parameters
    assert "target_user_environment" not in parameters
    source = (Path(__file__).parents[2] / "tools" / "genesis" / "windows_role_launcher.py").read_text()
    assert "os.environ" not in source
    assert "create(username, domain, password_buffer, logon_flags," in source
    assert "str(python_executable), command_buffer, creation_flags," in source
    assert "environment_pointer, str(working_directory)" in source


def test_ctypes_declarations_and_native_path_use_duplicate_membership_token():
    source = (Path(__file__).parents[2] / "tools" / "genesis" / "windows_role_launcher.py").read_text()
    assert "ctypes.WinDLL(\"kernel32\", use_last_error=True)" in source
    assert "ctypes.WinDLL(\"advapi32\", use_last_error=True)" in source
    assert "OpenProcessToken.argtypes" in source and "OpenProcessToken.restype = wintypes.BOOL" in source
    assert "GetTokenInformation.argtypes" in source and "GetTokenInformation.restype = wintypes.BOOL" in source
    assert "DuplicateTokenEx.argtypes" in source and "DuplicateTokenEx.restype = wintypes.BOOL" in source
    assert "CheckTokenMembership.argtypes" in source and "CheckTokenMembership.restype = wintypes.BOOL" in source
    assert "ConvertStringSidToSidW.argtypes" in source
    assert "CheckTokenMembership(token, admin_sid" in source
    assert "CheckTokenMembership(primary" not in source
