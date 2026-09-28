"""Adversarial tests for the non-candidate G9 root and fixture boundaries."""

from __future__ import annotations

import errno
import hashlib
import json
from types import SimpleNamespace
import sqlite3

import pytest

import fixture_substrate
import fence_controller
import root_admin
import role_worker
import windows_role_runner
import windows_substrate_launcher
from deployment_readiness import build_deployment_readiness, verify_deployment_readiness
from fixture_substrate import (
    FixtureEffectState,
    FixtureSubstrateServer,
    call_service,
    encode_request,
    new_channel_keys,
)
from role_adapter import RoleSubstrateAdapter, construct_candidate_runtime, role_capability_surface


ANCHOR = "a" * 64
PACKAGE = "b" * 64
MANIFEST = "c" * 64
ADMIN_SID = "S-1-5-21-1-1001"


def _substrate_ready_record(port=54321):
    record = {
        "format": "autodev.g9-fixture-substrate-ready/v1",
        "pid": 1234,
        "endpoint": ["127.0.0.1", port],
        "candidate_package_id": PACKAGE,
    }
    record["endpoint_identity"] = hashlib.sha256(
        windows_substrate_launcher._canonical_bytes((
            "autodev.g9-fixture-substrate-endpoint/v1", "127.0.0.1", port, PACKAGE,
        ))
    ).hexdigest()
    return record


def test_launcher_probes_exact_validated_ready_endpoint_once_without_sending(monkeypatch):
    events = []

    class ConnectedSocket:
        def __enter__(self):
            events.append("entered")
            return self

        def __exit__(self, *_):
            events.append("closed")

        def sendall(self, _data):
            pytest.fail("launcher reachability probe must not send protocol bytes")

    def connect(endpoint, *, timeout):
        events.append((endpoint, timeout))
        return ConnectedSocket()

    monkeypatch.setattr(windows_substrate_launcher.socket, "create_connection", connect)
    endpoint = windows_substrate_launcher._validate_and_probe_readiness(
        _substrate_ready_record(), process_id=1234, candidate_package_id=PACKAGE,
    )
    assert endpoint == ("127.0.0.1", 54321)
    assert events == [(("127.0.0.1", 54321), 2), "entered", "closed"]


@pytest.mark.parametrize("change", (
    lambda record: record.update(pid=1235),
    lambda record: record.update(endpoint=["127.0.0.2", 54321]),
    lambda record: record.update(candidate_package_id="c" * 64),
    lambda record: record.update(endpoint_identity="0" * 64),
    lambda record: record.update(extra="unexpected"),
))
def test_existing_ready_binding_rejects_invalid_records_before_probe(monkeypatch, change):
    record = _substrate_ready_record()
    change(record)
    monkeypatch.setattr(windows_substrate_launcher.socket, "create_connection",
                        lambda *_args, **_kwargs: pytest.fail("invalid READY reached probe"))
    with pytest.raises(RuntimeError, match="substrate service readiness|endpoint digest"):
        windows_substrate_launcher._validate_and_probe_readiness(
            record, process_id=1234, candidate_package_id=PACKAGE,
        )


def test_launcher_probe_failure_is_fixed_and_stops_before_any_role_launch(
        monkeypatch, tmp_path):
    import root_admin

    monkeypatch.setattr(root_admin, "ROOT_STORE_PATH", tmp_path / "absent-root" / "root.sqlite3")
    monkeypatch.setattr(windows_role_runner, "_host_profiles",
                        lambda: ({}, {}, "anchor", ("root-dep", "substrate-dep")))
    package = SimpleNamespace(graph=b"{}", raw_resources={}, candidate_package_id=PACKAGE)
    monkeypatch.setattr(windows_role_runner, "assemble_candidate", lambda **_kwargs: package)
    monkeypatch.setattr(windows_role_runner, "_stage",
                        lambda _package: (tmp_path, tmp_path / "worker.py", tmp_path))
    launches = []

    def refused_connect(_endpoint, *, timeout):
        assert timeout == 2
        raise OSError(10061, "SECRET socket detail at 127.0.0.1:54321")

    def launch_substrate(**_kwargs):
        return windows_substrate_launcher._validate_and_probe_readiness(
            _substrate_ready_record(), process_id=1234, candidate_package_id=PACKAGE,
        )

    monkeypatch.setattr(windows_substrate_launcher.socket, "create_connection", refused_connect)
    monkeypatch.setattr(windows_role_runner, "launch_substrate", launch_substrate)
    monkeypatch.setattr(windows_role_runner, "launch_role",
                        lambda *_args, **_kwargs: launches.append("role"))
    with pytest.raises(RuntimeError) as caught:
        windows_role_runner.run_realized_roles()
    assert str(caught.value) == "SUBSTRATE_LAUNCHER_REACHABILITY_FAIL"
    assert "SECRET" not in str(caught.value)
    assert "54321" not in str(caught.value)
    assert "10061" not in str(caught.value)
    assert launches == []


def test_connect_and_close_is_no_op_for_fixture_replay_and_protected_state():
    import socket

    keys = new_channel_keys()
    resource = b"unchanged resource"
    state = FixtureEffectState(PACKAGE, {"r1": resource})
    service = FixtureSubstrateServer(state, keys)
    service.start()
    try:
        with socket.create_connection(service.address, timeout=2):
            pass
        assert call_service(
            service.address, role="T", request_id="after-probe", nonce="fresh-nonce",
            command="F_READ_VERIFY",
            payload={"resource_id": "r1", "expected_sha256": hashlib.sha256(resource).hexdigest()},
            key=keys["T"],
        ) == {"verified": True, "resource_id": "r1", "candidate_package_id": PACKAGE}
        assert state.seen == {("T", "fresh-nonce")}
        assert state.recovery_records == {}
        assert state.p_fence == state.m_fence == "FENCED"
    finally:
        service.close()


def test_role_worker_startup_failure_with_exact_type_and_stage_is_failure_evidence_only():
    report = {"startup_failure": {"type": "OSError", "stage": "SUBSTRATE_RESOURCE_VERIFY"}}
    with pytest.raises(
            AssertionError,
            match=r"role T worker startup failed at SUBSTRATE_RESOURCE_VERIFY: OSError") as caught:
        windows_role_runner._validate_role_identity_report("T", report)
    assert str(caught.value) == "role T worker startup failed at SUBSTRATE_RESOURCE_VERIFY: OSError"


@pytest.mark.parametrize("report", (
    {"startup_failure": {"type": "OSError", "stage": "UNKNOWN_STAGE"}},
    {"startup_failure": {"type": "SubstrateTransportError", "stage": "SUBSTRATE_CONNECT"}},
    {"startup_failure": {"type": "SubstrateTransportError", "stage": "SUBSTRATE_CONNECT",
                          "class": "UNKNOWN_CONNECT_FAILURE"}},
    {"startup_failure": {"type": "SubstrateTransportError", "stage": "SUBSTRATE_CONNECT",
                          "class": "OTHER_CONNECT_FAILURE", "os_code": "10022"}},
    {"startup_failure": {"type": "SubstrateTransportError", "stage": "SUBSTRATE_CONNECT",
                          "class": "OTHER_CONNECT_FAILURE", "os_code": True}},
    {"startup_failure": {"type": "SubstrateTransportError", "stage": "SUBSTRATE_CONNECT",
                          "class": "OTHER_CONNECT_FAILURE", "os_code": 1.5}},
    {"startup_failure": {"type": "SubstrateTransportError", "stage": "SUBSTRATE_CONNECT",
                          "class": "OTHER_CONNECT_FAILURE", "os_code": None, "extra": "x"}},
    {"startup_failure": {"type": "SubstrateTransportError", "stage": "SUBSTRATE_SEND",
                          "class": "CONNECTION_REFUSED"}},
    {"startup_failure": {"type": "OSError"}},
    {"startup_failure": {"type": "OSError", "stage": "SUBSTRATE_SETUP", "extra": "secret"}},
    {"startup_failure": {"type": "", "stage": "SUBSTRATE_SETUP"}},
    {"startup_failure": {"type": 7, "stage": "SUBSTRATE_SETUP"}},
    {"startup_failure": {"type": "OSError", "stage": None}},
    {"startup_failure": {"type": "OSError: secret", "stage": "SUBSTRATE_SETUP"}},
    {"startup_failure": {"type": "OSError\nsecret", "stage": "SUBSTRATE_SETUP"}},
    {"startup_failure": {"type": "OSError", "stage": "SUBSTRATE_SETUP"},
     "bootstrap": "BOOTSTRAP_SECRET", "key": "CHANNEL_KEY"},
))
def test_malformed_nested_startup_failure_evidence_fails_closed_without_echoing_content(report):
    with pytest.raises(AssertionError, match=r"role C returned malformed startup failure evidence") as caught:
        windows_role_runner._validate_role_identity_report("C", report)
    message = str(caught.value)
    assert "BOOTSTRAP_SECRET" not in message
    assert "CHANNEL_KEY" not in message
    assert "secret" not in message


def test_startup_failure_object_cannot_be_accepted_as_a_success_identity_report():
    failure = {"startup_failure": {"type": "ImportError", "stage": "RUNTIME_IMPORT"}}
    with pytest.raises(AssertionError, match=r"role M worker startup failed at RUNTIME_IMPORT: ImportError"):
        windows_role_runner._validate_role_identity_report("M", failure)


def test_successful_role_identity_report_retains_the_exact_existing_field_set():
    report = {field: None for field in windows_role_runner._ROLE_IDENTITY_REPORT_FIELDS}
    assert windows_role_runner._validate_role_identity_report("P", report) is report
    assert windows_role_runner._ROLE_IDENTITY_REPORT_FIELDS == frozenset({
        "role", "pid", "ppid", "python_executable", "python_sha256", "runtime_sha256",
        "candidate_package_id", "runtime_generation", "endpoint_identity", "private_directory",
        "security_context_identity", "entrypoint_identity", "access",
        "destination_channel_credentials", "runtime_preparation",
        "production_github_mutation_credentials",
    })


def test_normal_runner_has_no_t_only_profile_environment_branch():
    import inspect
    assert not inspect.signature(windows_role_runner.run_realized_roles).parameters
    source = (windows_role_runner.REPOSITORY / "tools" / "genesis" / "windows_role_runner.py").read_text()
    assert "target_user_environment_for_t" not in source
    assert "diagnose-t-user-environment" not in source


def test_role_environment_github_credential_check_is_name_only_and_closed():
    environment = {
        "GH_TOKEN": "SENSITIVE_TOKEN_VALUE",
        "GITHUB_APP_PRIVATE_KEY": "SENSITIVE_PRIVATE_KEY_VALUE",
        "GITHUB_ACTIONS": "false",
        "PATH": "C:\\Windows",
    }
    assert role_worker._github_mutation_credential_names(environment) == (
        "GH_TOKEN", "GITHUB_APP_PRIVATE_KEY",
    )
    assert "SENSITIVE_TOKEN_VALUE" not in repr(
        role_worker._github_mutation_credential_names(environment))
    assert role_worker._github_mutation_credential_names({"GITHUB_ACTIONS": "false", "PATH": "x"}) == ()


def test_role_worker_fails_closed_without_disclosing_profile_credential_value(monkeypatch):
    evidence = []
    monkeypatch.setattr(role_worker.os, "environ", {"GH_TOKEN": "NEVER_PRINT_THIS_VALUE"})
    monkeypatch.setattr(role_worker, "_write", evidence.append)
    assert role_worker.main() == 2
    assert evidence == [{"startup_failure": {
        "type": "RuntimeError", "stage": "BOOTSTRAP_VALIDATION",
    }}]
    assert "NEVER_PRINT_THIS_VALUE" not in repr(evidence)


def test_worker_and_runner_share_the_same_closed_startup_stage_domain():
    assert windows_role_runner._STARTUP_STAGES == frozenset(stage.value for stage in role_worker._StartupStage)


@pytest.mark.parametrize(("phase", "startup_stage", "failure_class"), (
    ("CONNECT", "SUBSTRATE_CONNECT", "CONNECTION_REFUSED"),
    ("SEND", "SUBSTRATE_SEND", None),
    ("RECEIVE", "SUBSTRATE_RECEIVE", None),
))
def test_substrate_transport_oserror_maps_to_one_closed_worker_stage(phase, startup_stage, failure_class):
    error = fixture_substrate.SubstrateTransportError(phase, failure_class)
    expected_failure = {"type": "SubstrateTransportError", "stage": startup_stage}
    if failure_class is not None:
        expected_failure["class"] = failure_class
        expected_failure["os_code"] = None
    assert role_worker._startup_failure_evidence(
        error, role_worker._StartupStage.SUBSTRATE_RESOURCE_VERIFY,
        fixture_substrate.SubstrateTransportError,
    ) == {"startup_failure": expected_failure}


@pytest.mark.parametrize("phase", ("", "DNS", "CONNECT\nsecret", None))
def test_substrate_transport_error_rejects_unrecognized_phase(phase):
    with pytest.raises(ValueError, match="invalid substrate transport phase"):
        fixture_substrate.SubstrateTransportError(phase)


@pytest.mark.parametrize("failure_class", ("", "WSAECONNREFUSED", "CONNECTION_REFUSED\nsecret", None))
def test_substrate_transport_connect_error_rejects_unrecognized_failure_class(failure_class):
    with pytest.raises(ValueError, match="invalid substrate connect failure class"):
        fixture_substrate.SubstrateTransportError("CONNECT", failure_class)


@pytest.mark.parametrize(("phase", "failure_class", "os_code"), (
    ("CONNECT", "OTHER_CONNECT_FAILURE", True),
    ("CONNECT", "OTHER_CONNECT_FAILURE", "10022"),
    ("SEND", None, 10022),
    ("RECEIVE", None, 10022),
))
def test_substrate_transport_error_rejects_invalid_os_code_binding(phase, failure_class, os_code):
    with pytest.raises(ValueError):
        fixture_substrate.SubstrateTransportError(phase, failure_class, os_code)


def _call_service_with_injected_socket_error(monkeypatch, operation, error):
    class FakeClient:
        def __init__(self):
            self.closed = False

        def settimeout(self, timeout):
            assert timeout == 2

        def connect(self, address):
            assert address == ("127.0.0.1", 54321)
            if operation == "connect":
                raise error

        def sendall(self, _data):
            if operation == "send":
                raise error

        def recv(self, _size):
            if operation == "recv":
                raise error
            return b""

        def close(self):
            self.closed = True

    clients = []

    def make_socket(family, socket_type):
        assert family == fixture_substrate.socket.AF_INET
        assert socket_type == fixture_substrate.socket.SOCK_STREAM
        client = FakeClient()
        clients.append(client)
        return client

    monkeypatch.setattr(fixture_substrate.socket, "socket", make_socket)
    with pytest.raises(fixture_substrate.SubstrateTransportError) as caught:
        fixture_substrate.call_service(
            ("127.0.0.1", 54321), role="T", request_id="request", nonce="nonce",
            command="F_READ_VERIFY",
            payload={"resource_id": "resource", "expected_sha256": "a" * 64},
            key=b"k" * 32,
        )
    assert len(clients) == 1 and clients[0].closed
    return caught.value


def test_role_transport_constructs_exact_ipv4_tcp_socket_without_resolution(monkeypatch):
    observed = {}

    class FakeClient:
        def settimeout(self, value):
            observed["timeout"] = value

        def connect(self, address):
            observed["address"] = address
            raise ConnectionRefusedError("SECRET connect message")

        def close(self):
            observed["closed"] = True

    def make_socket(family, socket_type):
        observed["family"] = family
        observed["socket_type"] = socket_type
        return FakeClient()

    monkeypatch.setattr(fixture_substrate.socket, "socket", make_socket)
    monkeypatch.setattr(fixture_substrate.socket, "create_connection",
                        lambda *_args, **_kwargs: pytest.fail("generic connection helper used"))
    monkeypatch.setattr(fixture_substrate.socket, "getaddrinfo",
                        lambda *_args, **_kwargs: pytest.fail("name resolution used"))
    with pytest.raises(fixture_substrate.SubstrateTransportError) as caught:
        fixture_substrate.call_service(
            ("127.0.0.1", 54321), role="T", request_id="request", nonce="nonce",
            command="F_READ_VERIFY", payload={"resource_id": "r", "expected_sha256": "a" * 64},
            key=b"k" * 32,
        )
    assert caught.value.phase == "CONNECT"
    assert caught.value.failure_class == "CONNECTION_REFUSED"
    assert observed == {
        "family": fixture_substrate.socket.AF_INET,
        "socket_type": fixture_substrate.socket.SOCK_STREAM,
        "timeout": 2,
        "address": ("127.0.0.1", 54321),
        "closed": True,
    }


@pytest.mark.parametrize("address", (
    ("localhost", 54321), ("::1", 54321), ("127.0.0.2", 54321),
    ("127.0.0.1", 0), ("127.0.0.1", 65536), ("127.0.0.1", True),
    ["127.0.0.1", 54321],
))
def test_role_transport_rejects_non_exact_loopback_endpoint_before_socket_creation(monkeypatch, address):
    monkeypatch.setattr(fixture_substrate.socket, "socket",
                        lambda *_args: pytest.fail("invalid endpoint reached socket creation"))
    with pytest.raises(ValueError, match="exact IPv4 loopback substrate endpoint"):
        fixture_substrate.call_service(
            address, role="T", request_id="request", nonce="nonce",
            command="F_READ_VERIFY", payload={"resource_id": "r", "expected_sha256": "a" * 64},
            key=b"k" * 32,
        )


@pytest.mark.parametrize(("error_number", "expected_class"), (
    (10061, "CONNECTION_REFUSED"),
    (10013, "ACCESS_DENIED"),
    (10060, "TIMED_OUT"),
    (10051, "NETWORK_UNREACHABLE"),
    (10065, "HOST_UNREACHABLE"),
    (12345, "OTHER_CONNECT_FAILURE"),
))
def test_connect_failure_numbers_map_to_closed_classes_without_disclosure(
        monkeypatch, error_number, expected_class):
    underlying = OSError(22, "SECRET connect message", ("127.0.0.1", 54321))
    assert type(underlying) is OSError
    underlying.winerror = error_number
    error = _call_service_with_injected_socket_error(monkeypatch, "connect", underlying)
    assert error.phase == "CONNECT"
    assert error.failure_class == expected_class
    assert error.os_code == error_number
    assert error.args == ()
    assert str(error) == ""
    assert error.__suppress_context__ is True
    evidence = role_worker._startup_failure_evidence(
        error, role_worker._StartupStage.SUBSTRATE_RESOURCE_VERIFY,
        fixture_substrate.SubstrateTransportError,
    )
    assert evidence == {"startup_failure": {
        "type": "SubstrateTransportError", "stage": "SUBSTRATE_CONNECT",
        "class": expected_class, "os_code": error_number,
    }}
    with pytest.raises(AssertionError) as caught_diagnostic:
        windows_role_runner._validate_role_identity_report("T", evidence)
    diagnostic = str(caught_diagnostic.value)
    assert diagnostic == (f"role T worker startup failed at SUBSTRATE_CONNECT: "
                          f"SubstrateTransportError ({expected_class}, os_code={error_number})")
    assert "SECRET" not in diagnostic
    assert "54321" not in diagnostic


@pytest.mark.parametrize(("exception_type", "expected_class"), (
    (ConnectionRefusedError, "CONNECTION_REFUSED"),
    (PermissionError, "ACCESS_DENIED"),
    (TimeoutError, "TIMED_OUT"),
))
def test_connect_exception_subclass_precedes_conflicting_winerror_and_errno(
        monkeypatch, exception_type, expected_class):
    underlying = exception_type("SECRET normalized socket failure")
    underlying.winerror = 10065
    underlying.errno = errno.EHOSTUNREACH
    error = _call_service_with_injected_socket_error(monkeypatch, "connect", underlying)
    assert error.failure_class == expected_class
    assert error.os_code == 10065
    assert error.args == ()
    assert str(error) == ""


def test_connect_winerror_precedes_conflicting_errno():
    underlying = OSError(22, "SECRET conflicting socket codes")
    assert type(underlying) is OSError
    underlying.winerror = 10013
    underlying.errno = errno.ECONNREFUSED
    assert fixture_substrate._connect_failure_class(underlying) == "ACCESS_DENIED"


def test_connect_preserves_winerror_before_errno_without_changing_classification(monkeypatch):
    underlying = OSError(22, "SECRET conflict", ("127.0.0.1", 54321))
    underlying.winerror = 10013
    underlying.errno = errno.ECONNREFUSED
    error = _call_service_with_injected_socket_error(monkeypatch, "connect", underlying)
    assert (error.failure_class, error.os_code) == ("ACCESS_DENIED", 10013)


def test_connect_uses_errno_when_winerror_is_unavailable(monkeypatch):
    underlying = OSError(22, "SECRET errno-only failure", ("127.0.0.1", 54321))
    underlying.winerror = None
    underlying.errno = 424242
    error = _call_service_with_injected_socket_error(monkeypatch, "connect", underlying)
    assert error.failure_class == "OTHER_CONNECT_FAILURE"
    assert error.os_code == 424242


def test_connect_without_numeric_os_code_emits_null_and_safe_diagnostic(monkeypatch):
    underlying = OSError("SECRET message at 127.0.0.1:54321")
    underlying.winerror = None
    underlying.errno = None
    error = _call_service_with_injected_socket_error(monkeypatch, "connect", underlying)
    assert error.failure_class == "OTHER_CONNECT_FAILURE"
    assert error.os_code is None
    evidence = role_worker._startup_failure_evidence(
        error, role_worker._StartupStage.SUBSTRATE_RESOURCE_VERIFY,
        fixture_substrate.SubstrateTransportError,
    )
    assert evidence == {"startup_failure": {
        "type": "SubstrateTransportError", "stage": "SUBSTRATE_CONNECT",
        "class": "OTHER_CONNECT_FAILURE", "os_code": None,
    }}
    with pytest.raises(AssertionError) as caught:
        windows_role_runner._validate_role_identity_report("T", evidence)
    assert str(caught.value).endswith(
        "SubstrateTransportError (OTHER_CONNECT_FAILURE, os_code=None)")
    for hidden in ("SECRET", "127.0.0.1", "54321"):
        assert hidden not in str(caught.value)


@pytest.mark.parametrize(("socket_errno", "expected_class"), (
    (10061, "CONNECTION_REFUSED"),
    (10013, "ACCESS_DENIED"),
    (10060, "TIMED_OUT"),
    (10051, "NETWORK_UNREACHABLE"),
    (10065, "HOST_UNREACHABLE"),
    (errno.ECONNREFUSED, "CONNECTION_REFUSED"),
    (errno.EACCES, "ACCESS_DENIED"),
    (errno.EPERM, "ACCESS_DENIED"),
    (errno.ETIMEDOUT, "TIMED_OUT"),
    (errno.ENETUNREACH, "NETWORK_UNREACHABLE"),
    (errno.EHOSTUNREACH, "HOST_UNREACHABLE"),
))
def test_connect_errno_fallback_maps_only_recognized_socket_codes(
        monkeypatch, socket_errno, expected_class):
    underlying = OSError(22, "SECRET errno socket failure", ("127.0.0.1", 54321))
    assert type(underlying) is OSError
    underlying.winerror = None
    underlying.errno = socket_errno
    error = _call_service_with_injected_socket_error(monkeypatch, "connect", underlying)
    assert error.failure_class == expected_class
    evidence = role_worker._startup_failure_evidence(
        error, role_worker._StartupStage.SUBSTRATE_RESOURCE_VERIFY,
        fixture_substrate.SubstrateTransportError,
    )
    assert evidence == {"startup_failure": {
        "type": "SubstrateTransportError", "stage": "SUBSTRATE_CONNECT",
        "class": expected_class, "os_code": socket_errno,
    }}
    with pytest.raises(AssertionError) as caught:
        windows_role_runner._validate_role_identity_report("T", evidence)
    diagnostic = str(caught.value)
    assert diagnostic.endswith(f"SubstrateTransportError ({expected_class}, os_code={socket_errno})")
    assert "SECRET" not in diagnostic
    assert "54321" not in diagnostic
    assert str(socket_errno) in diagnostic


@pytest.mark.parametrize(("operation", "phase", "startup_stage", "error_number"), (
    ("send", "SEND", "SUBSTRATE_SEND", 10061),
    ("recv", "RECEIVE", "SUBSTRATE_RECEIVE", 10054),
))
def test_send_and_receive_diagnostics_remain_phase_only_without_socket_details(
        monkeypatch, operation, phase, startup_stage, error_number):
    underlying = OSError(error_number, "SECRET socket detail", ("127.0.0.1", 54321))
    error = _call_service_with_injected_socket_error(monkeypatch, operation, underlying)
    assert error.phase == phase
    assert error.failure_class is None
    assert error.os_code is None
    assert error.args == ()
    assert str(error) == ""
    evidence = role_worker._startup_failure_evidence(
        error, role_worker._StartupStage.SUBSTRATE_RESOURCE_VERIFY,
        fixture_substrate.SubstrateTransportError,
    )
    assert evidence == {"startup_failure": {"type": "SubstrateTransportError", "stage": startup_stage}}
    with pytest.raises(AssertionError) as caught_diagnostic:
        windows_role_runner._validate_role_identity_report("T", evidence)
    diagnostic = str(caught_diagnostic.value)
    assert diagnostic == f"role T worker startup failed at {startup_stage}: SubstrateTransportError"
    assert "SECRET" not in diagnostic
    assert "54321" not in diagnostic
    assert str(error_number) not in diagnostic


def _root_fixture(path, *, root_rows: bool = False, state: str = "FENCED", revision: int = 0,
                  candidate_package_id: str = PACKAGE) -> None:
    connection = sqlite3.connect(path)
    try:
        for statement in root_admin._SCHEMA_STATEMENTS:
            connection.execute(statement)
        connection.execute(
            "INSERT INTO capability_fence(candidate_package_id, root_anchor_id, state, revision) "
            "VALUES (?, ?, ?, ?)", (candidate_package_id, ANCHOR, state, revision),
        )
        if root_rows:
            connection.execute(
                "INSERT INTO root_state(format, root_anchor_id, active_manifest_id, transition, revision) "
                "VALUES (?, ?, ?, 'G_OPEN', 1)",
                (root_admin.ROOT_STATE_FORMAT, ANCHOR, MANIFEST),
            )
        connection.commit()
    finally:
        connection.close()


def test_root_store_inspection_is_read_only_and_recognizes_only_exact_stage_b_state(tmp_path):
    database = tmp_path / "fixture.sqlite3"
    _root_fixture(database)
    before = database.read_bytes()
    evidence = root_admin.inspect_uninitialized_root(
        database, expected_anchor_id=ANCHOR, expected_candidate_package_id=PACKAGE,
    )
    assert evidence == {
        "status": "UNINITIALIZED", "root_anchor_id": ANCHOR,
        "candidate_package_id": PACKAGE, "root_state_row_count": 0,
        "capability_fence_row_count": 1, "fence_state": "FENCED",
        "fence_revision": 0, "schema_sha256": root_admin.ROOT_STORE_SCHEMA_SHA256,
    }
    assert database.read_bytes() == before


@pytest.mark.parametrize("kwargs", (
    {"root_rows": True},
    {"state": "RELEASED", "revision": 1},
    {"revision": 1},
    {"candidate_package_id": "d" * 64},
))
def test_root_store_inspection_fails_closed_on_initialized_stale_or_ambiguous_state(tmp_path, kwargs):
    database = tmp_path / "fixture.sqlite3"
    _root_fixture(database, **kwargs)
    with pytest.raises(ValueError):
        root_admin.inspect_uninitialized_root(
            database, expected_anchor_id=ANCHOR, expected_candidate_package_id=PACKAGE,
        )


def test_root_store_inspection_fails_closed_on_schema_tampering(tmp_path):
    database = tmp_path / "fixture.sqlite3"
    connection = sqlite3.connect(database)
    connection.execute("CREATE TABLE root_state (x TEXT)")
    connection.execute("CREATE TABLE capability_fence (x TEXT)")
    connection.commit()
    connection.close()
    with pytest.raises(ValueError, match="schema"):
        root_admin.inspect_uninitialized_root(
            database, expected_anchor_id=ANCHOR, expected_candidate_package_id=PACKAGE,
        )


def test_external_root_admin_genesis_initialization_is_explicit_and_create_once(tmp_path, monkeypatch):
    database = tmp_path / "fixture.sqlite3"
    _root_fixture(database, state="RELEASED", revision=1)
    monkeypatch.setattr(root_admin, "_is_canonical_path", lambda _: True)
    monkeypatch.setattr(root_admin, "_require_external_root_admin", lambda _: None)
    monkeypatch.setattr(fence_controller, "_require_external_root_admin", lambda _: None)
    with pytest.raises(PermissionError, match="explicit"):
        root_admin.initialize_genesis_state(
            database, expected_anchor_id=ANCHOR, expected_candidate_package_id=PACKAGE,
            active_manifest_id=MANIFEST, explicit_initialization=False,
            expected_admin_sid=ADMIN_SID,
        )
    assert root_admin.initialize_genesis_state(
        database, expected_anchor_id=ANCHOR, expected_candidate_package_id=PACKAGE,
        active_manifest_id=MANIFEST, explicit_initialization=True,
        expected_admin_sid=ADMIN_SID,
    ) == 1
    with pytest.raises(ValueError, match="precondition"):
        root_admin.initialize_genesis_state(
            database, expected_anchor_id=ANCHOR, expected_candidate_package_id=PACKAGE,
            active_manifest_id=MANIFEST, explicit_initialization=True,
            expected_admin_sid=ADMIN_SID,
        )


def test_external_fence_is_root_admin_only_and_exact_revision_cas(tmp_path, monkeypatch):
    database = tmp_path / "fixture.sqlite3"
    _root_fixture(database)
    monkeypatch.setattr(root_admin, "_is_canonical_path", lambda _: True)
    monkeypatch.setattr(root_admin, "_require_external_root_admin", lambda _: None)
    monkeypatch.setattr(fence_controller, "_require_external_root_admin", lambda _: None)
    assert fence_controller.set_fence(
        database, expected_admin_sid=ADMIN_SID, candidate_package_id=PACKAGE,
        expected_revision=0, state="RELEASED",
    ) == {"candidate_package_id": PACKAGE, "state": "RELEASED", "revision": 1,
          "authority": "EXTERNAL_ROOT_ADMIN_ONLY"}
    with pytest.raises(ValueError, match="stale"):
        fence_controller.set_fence(
            database, expected_admin_sid=ADMIN_SID, candidate_package_id=PACKAGE,
            expected_revision=0, state="FENCED",
        )


def test_substrate_protocol_role_scopes_keep_all_protected_endpoints_fenced(monkeypatch):
    monkeypatch.setattr(fixture_substrate.socket, "create_connection",
                        lambda *_args, **_kwargs: pytest.fail("generic connection helper used"))
    keys = new_channel_keys()
    resource = b"content-addressed resource"
    state = FixtureEffectState(PACKAGE, {"r1": resource})
    service = FixtureSubstrateServer(state, keys)
    service.start()
    try:
        address = service.address
        assert call_service(address, role="T", request_id="t1", nonce="tn1", command="F_READ_VERIFY",
                            payload={"resource_id": "r1",
                                     "expected_sha256": hashlib.sha256(resource).hexdigest()},
                            key=keys["T"]) == {"verified": True, "resource_id": "r1",
                                                "candidate_package_id": PACKAGE}
        assert call_service(address, role="C", request_id="c1", nonce="cn1", command="F_READ_VERIFY",
                            payload={"resource_id": "r1", "expected_sha256": hashlib.sha256(resource).hexdigest()},
                            key=keys["C"]) == {"verified": True, "resource_id": "r1",
                                                "candidate_package_id": PACKAGE}
        assert call_service(address, role="P", request_id="p1", nonce="pn1", command="P_FENCE_READ",
                            payload={}, key=keys["P"]) == {"fence": "FENCED", "revision": 0,
                                                            "candidate_package_id": PACKAGE}
        assert call_service(address, role="M", request_id="m1", nonce="mn1", command="M_FENCE_READ",
                            payload={}, key=keys["M"]) == {"fence": "FENCED", "revision": 0,
                                                            "candidate_package_id": PACKAGE}
        for role, command in (("P", "PUBLICATION_PREPARE"), ("M", "MERGE_PREPARE")):
            result = call_service(
                address, role=role, request_id=role + "2", nonce=role + "n2", command=command,
                payload={"effect_id": "effect", "payload_sha256": "e" * 64}, key=keys[role],
            )
            assert result == {"accepted": False, "reason": "TARGET_FENCED",
                              "candidate_package_id": PACKAGE}
    finally:
        service.close()


@pytest.mark.parametrize("role,command", (
    ("T", "PUBLICATION_PREPARE"), ("C", "MERGE_PREPARE"),
    ("P", "MERGE_PREPARE"), ("M", "PUBLICATION_PREPARE"),
    ("T", "START_HELD_RECOVER"), ("C", "START_HELD_RECOVER"),
    ("P", "START_HELD_RECOVER"), ("M", "START_HELD_RECOVER"),
))
def test_candidate_roles_cannot_construct_cross_role_or_recovery_requests(role, command):
    with pytest.raises(ValueError):
        encode_request(role=role, request_id="request", nonce="nonce", command=command,
                       payload={"operation_id": "op", "expected_start_id": "start"}
                       if command == "START_HELD_RECOVER" else
                       {"effect_id": "effect", "payload_sha256": "e" * 64},
                       key=b"k" * 32)


def test_substrate_rejects_hmac_tampering_and_replay():
    keys = new_channel_keys()
    resource = b"verified fixture resource"
    service = FixtureSubstrateServer(FixtureEffectState(PACKAGE, {"r1": resource}), keys)
    service.start()
    try:
        frame = encode_request(role="C", request_id="request", nonce="one-shot", command="F_READ_VERIFY",
                               payload={"resource_id": "r1",
                                        "expected_sha256": hashlib.sha256(resource).hexdigest()},
                               key=keys["C"])
        with __import__("socket").create_connection(service.address, timeout=2) as client:
            client.sendall(frame + b"\n")
            first = client.recv(4096)
        assert json.loads(first)["result"] == {"verified": True, "resource_id": "r1",
                                                "candidate_package_id": PACKAGE}
        with __import__("socket").create_connection(service.address, timeout=2) as client:
            client.sendall(frame + b"\n")
            second = client.recv(4096)
        response = json.loads(second)
        assert response["result"] == {"accepted": False, "reason": "REQUEST_REJECTED"}
    finally:
        service.close()


def test_each_real_candidate_runtime_role_constructs_with_only_its_narrow_substrate_surface():
    keys = new_channel_keys()
    resource = b"exact candidate runtime resource"
    service = FixtureSubstrateServer(
        FixtureEffectState(PACKAGE, {"runtime": resource}), keys,
    )
    service.start()
    try:
        expected_types = {
            "T": "TrustedControllerRuntime", "C": "ControlStateGateRuntime",
            "P": "PublicationGateRuntime", "M": "MergeGateRuntime",
        }
        observations = {}
        for role in ("T", "C", "P", "M"):
            adapter = RoleSubstrateAdapter(
                role=role, address=service.address, key=keys[role],
                candidate_package_id=PACKAGE,
            )
            assert adapter.verify_resource("runtime", hashlib.sha256(resource).hexdigest())
            prepared = construct_candidate_runtime(
                role=role, candidate_package_id=PACKAGE, substrate_adapter=adapter,
                runtime_run_id="f" * 64,
            )
            assert prepared["role"] == role
            assert prepared["runtime_type"] == expected_types[role]
            assert prepared["independent_process_local_composition"] is True
            assert len(prepared["runtime_role_identity"]) == 64
            if role in ("P", "M"):
                assert prepared["protected_fence"] == {"fence": "FENCED", "revision": 0,
                                                        "candidate_package_id": PACKAGE}
                assert prepared["fenced_effect_probe_accepted"] is False
            else:
                assert prepared["protected_fence"] is None
            observations[role] = prepared
        assert role_capability_surface("T") == ("F_READ_VERIFY",)
        assert role_capability_surface("C") == ("F_READ_VERIFY",)
        assert role_capability_surface("P") == (
            "F_READ_VERIFY", "PUBLICATION_PREPARE", "P_FENCE_READ",
        )
        assert role_capability_surface("M") == (
            "F_READ_VERIFY", "MERGE_PREPARE", "M_FENCE_READ",
        )
        assert observations["P"]["runtime_role_identity"] != observations["M"]["runtime_role_identity"]
    finally:
        service.close()


def test_substrate_requires_one_complete_line_and_rejects_trailing_frame_bytes():
    keys = new_channel_keys()
    service = FixtureSubstrateServer(FixtureEffectState(PACKAGE, {}), keys)
    service.start()
    try:
        frame = encode_request(role="C", request_id="request", nonce="strict-line",
                               command="F_READ_VERIFY",
                               payload={"resource_id": "missing", "expected_sha256": "a" * 64},
                               key=keys["C"])
        import socket
        with socket.create_connection(service.address, timeout=2) as client:
            client.sendall(frame + b"\n{}")
            response = json.loads(client.recv(4096))
        assert response["result"] == {"accepted": False, "reason": "REQUEST_REJECTED"}
    finally:
        service.close()


def _readiness_preimage() -> dict[str, object]:
    roles = {}
    for index, role in enumerate(("T", "C", "P", "M"), start=1):
        roles[role] = {
            "sid": f"S-1-5-21-1-{index}", "token_type": 1, "administrator": False,
            "pid": 1000 + index, "ppid": 50, "candidate_package_id": PACKAGE,
            "runtime_sha256": "d" * 64, "entrypoint_identity": "e" * 64,
            "security_context_identity": "f" * 64, "wiring_identity": "1" * 64,
            "endpoint_identity": "2" * 64, "private_directory": f"C:/private/{role}",
            "destination_channel_credentials": "NONE" if role == "T" else "ROLE_LOCAL_ONLY",
            "runtime_type": {"T": "TrustedControllerRuntime", "C": "ControlStateGateRuntime",
                             "P": "PublicationGateRuntime", "M": "MergeGateRuntime"}[role],
            "runtime_role_identity": "a" * 64, "runtime_binding_id": "b" * 64,
            "runtime_active": role in ("T", "C"),
        }
    return {
        "format": "autodev.genesis-deployment-readiness/v1",
        "candidate_package_id": PACKAGE,
        "genesis_manifest_id": "3" * 64,
        "deterministic_evidence_ids": ["D-001", "D-002"],
        "repository_source_commit": "4" * 40,
        "runtime_artifact_sha256": "d" * 64,
        "python_runtime": {"identity": "CPython", "version": "3.13.14",
                           "path": r"C:\AutodevG9\shared\python313\python.exe", "sha256": "5" * 64},
        "execution_isolation_dependency_id": "dep-execution-isolation-test",
        "root_fence_dependency_id": "dep-root-activation-fence-test",
        "root_fence_profile_sha256": "6" * 64,
        "fixture_substrate_dependency_id": "dep-fixture-effect-substrate-test",
        "fixture_substrate_profile_sha256": "7" * 64,
        "root_anchor_id": ANCHOR,
        "root_state_observation": {
            "status": "UNINITIALIZED", "root_anchor_id": ANCHOR,
            "candidate_package_id": PACKAGE, "root_state_row_count": 0,
            "capability_fence_row_count": 1, "fence_state": "FENCED",
            "fence_revision": 0, "schema_sha256": "8" * 64,
            "observation_scope": "NON_AUTHORITATIVE_TEMPORARY_FIXTURE_ONLY",
            "canonical_root_database": "ABSENT_UNTOUCHED",
            "fixture_database_sha256": "9" * 64,
        },
        "roles": roles,
        "staged_external_material": [
            {"path": "tools/genesis/fixture_substrate.py", "sha256": "9" * 64},
        ],
        "substrate_service": {
            "sid": "S-1-5-21-1-99", "token_type": 1, "administrator": False,
            "pid": 1999, "endpoint_identity": "a" * 64,
            "implementation_identity": "b" * 64, "configuration_identity": "c" * 64,
            "working_directory": "C:/shared/external-g9",
        },
        "shared_runtime_read_only": True,
        "cross_role_private_write_denial": {role: True for role in ("T", "C", "P", "M")},
        "candidate_root_store_write_denial": {role: True for role in ("T", "C", "P", "M")},
        "protected_endpoint_state": {
            "C_WRITER": {"state": "FENCED", "identity": "1" * 64, "credential_withheld": True},
            "P_PUBLICATION": {"state": "FENCED", "identity": "2" * 64, "credential_withheld": True},
            "M_MERGE": {"state": "FENCED", "identity": "3" * 64, "credential_withheld": True},
        },
        "recovery_fence_inventory": ["external-start-held-recovery"],
        "production_github_mutation_credentials": "NONE",
        "host_profile_id": "g9-host-profile-test",
        "observed_at": "2026-09-27T00:00:00Z",
    }


def test_deployment_readiness_is_content_addressed_pre_review_and_binds_all_roles():
    preimage = _readiness_preimage()
    record = build_deployment_readiness(preimage)
    assert verify_deployment_readiness(record)
    assert record["record_id"] == hashlib.sha256(
        __import__("external_profiles").canonical_json_bytes(preimage)
    ).hexdigest()
    assert "review_record_id" not in record["preimage"]
    assert "merge_commit_sha" not in record["preimage"]
    assert record["preimage"]["candidate_package_id"] == PACKAGE


def test_runner_projects_complete_closed_role_evidence_for_deployment_readiness():
    process = SimpleNamespace(
        sid="S-1-5-21-1-1016", token_type=1, is_administrator=False, pid=1016,
    )
    report = {
        "ppid": 50,
        "entrypoint_identity": "e" * 64,
        "security_context_identity": "f" * 64,
        "endpoint_identity": "2" * 64,
        "private_directory": "C:/private/T",
        "destination_channel_credentials": "NONE",
        "runtime_preparation": {
            "runtime_type": "TrustedControllerRuntime",
            "runtime_role_identity": "a" * 64,
            "runtime_binding_id": "b" * 64,
            "runtime_active": True,
        },
    }

    evidence = windows_role_runner._deployment_role_evidence(
        "T", process, report,
        candidate_package_id=PACKAGE,
        runtime_sha256="d" * 64,
        wiring_identity="1" * 64,
    )

    assert evidence == {
        "sid": process.sid, "token_type": 1, "administrator": False,
        "pid": 1016, "ppid": 50, "candidate_package_id": PACKAGE,
        "runtime_sha256": "d" * 64, "entrypoint_identity": "e" * 64,
        "security_context_identity": "f" * 64, "wiring_identity": "1" * 64,
        "endpoint_identity": "2" * 64, "private_directory": "C:/private/T",
        "destination_channel_credentials": "NONE",
        "runtime_type": "TrustedControllerRuntime",
        "runtime_role_identity": "a" * 64, "runtime_binding_id": "b" * 64,
        "runtime_active": True,
    }
    assert set(evidence) == set(_readiness_preimage()["roles"]["T"])


@pytest.mark.parametrize("change", (
    lambda p: p["roles"]["P"].update(administrator=True),
    lambda p: p["roles"]["C"].update(pid=p["roles"]["T"]["pid"]),
    lambda p: p["roles"]["M"].update(candidate_package_id="e" * 64),
    lambda p: p["substrate_service"].update(sid=p["roles"]["P"]["sid"]),
    lambda p: p["root_state_observation"].update(fence_state="RELEASED"),
    lambda p: p["protected_endpoint_state"]["M_MERGE"].update(credential_withheld=False),
    lambda p: p["candidate_root_store_write_denial"].update(C=False),
))
def test_deployment_readiness_rejects_missing_or_overlapping_authority_proofs(change):
    import copy

    preimage = copy.deepcopy(_readiness_preimage())
    change(preimage)
    with pytest.raises(ValueError):
        build_deployment_readiness(preimage)


def test_deployment_readiness_record_tampering_fails_verification():
    record = build_deployment_readiness(_readiness_preimage())
    record["preimage"]["root_state_observation"]["fence_revision"] = 1
    assert not verify_deployment_readiness(record)
