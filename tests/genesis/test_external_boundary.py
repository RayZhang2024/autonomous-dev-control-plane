"""Adversarial tests for the non-candidate G9 root and fixture boundaries."""

from __future__ import annotations

import errno
import hashlib
import io
import inspect
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import sqlite3

import pytest

import fixture_substrate
import fence_controller
import root_admin
import role_worker
import windows_role_runner
import windows_substrate_launcher
from genesis_provenance import stage_b_subject_digest
from deployment_readiness import build_deployment_readiness, verify_deployment_readiness
from external_profiles import (build_external_profiles, canonical_json_bytes,
                               derive_external_root_controller_identity, derive_host_profile_id)
from fixture_substrate import (
    FixtureEffectState,
    FixtureSubstrateServer,
    call_service,
    encode_request,
    new_channel_keys,
)
from role_adapter import RoleSubstrateAdapter, construct_candidate_runtime, role_capability_surface
from provenance_fixtures import make_github_observation, make_post_merge_binding, make_review_record


PACKAGE = "b" * 64
MANIFEST = "c" * 64
ADMIN_SID = "S-1-5-21-711519901-190585334-3846127459-1001"
_REPOSITORY = Path(__file__).resolve().parents[2]
_TEST_ROOT_PROFILE, _TEST_SUBSTRATE_PROFILE, ANCHOR, _TEST_DEPENDENCIES = build_external_profiles(
    str(_REPOSITORY),
    root_admin_principal={"account": r"ray\zhang", "sid": ADMIN_SID, "administrator": True},
    substrate_principal={"account": r"Ray\autodev-g9-s",
                         "sid": "S-1-5-21-711519901-190585334-3846127459-1020",
                         "token_type": "PRIMARY", "administrator": False},
    python_runtime={"identity": "CPython", "version": "3.13.14",
                    "path": r"C:\AutodevG9\shared\python313\python.exe", "sha256": "8" * 64},
)
_TEST_STORE_ID = _TEST_ROOT_PROFILE["root_store_profile_id"]
_TEST_ACL_ID = _TEST_ROOT_PROFILE["root_namespace_acl_profile"]["profile_id"]
_TEST_ACCEPTANCE_ID = _TEST_ROOT_PROFILE["acceptance_profile"]["profile_id"]
from build_definition import sha256 as _sha256
from assemble_candidate import (
    _derive_execution_isolation_dependency_id,
    _make_execution_isolation_profile,
    assemble_candidate,
)
_EXTERNAL_PATHS = (
    "ipc.py", "role_worker.py", "windows_role_launcher.py", "windows_role_runner.py",
    "role_adapter.py", "substrate_client.py", "canonical_state_channel.py",
)
_TEST_ISOLATION_MATERIAL = [
    {"path": f"tools/genesis/{name}", "sha256": _sha256((_REPOSITORY / "tools" / "genesis" / name).read_bytes())}
    for name in sorted(_EXTERNAL_PATHS)
]
_TEST_ISOLATION_PROFILE = _make_execution_isolation_profile(_TEST_ISOLATION_MATERIAL)
_TEST_ISOLATION_DEPENDENCY = _derive_execution_isolation_dependency_id(_TEST_ISOLATION_PROFILE)
_TEST_STORE_ID = _TEST_ROOT_PROFILE["root_store_profile_id"]


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


def test_canonical_path_accepts_only_the_exact_resolved_path_family(tmp_path, monkeypatch):
    canonical = tmp_path / "root" / "root.sqlite3"
    monkeypatch.setattr(root_admin, "ROOT_STORE_PATH", canonical)

    assert root_admin._is_canonical_path(canonical) is True
    assert root_admin._is_canonical_path(Path(str(canonical))) is True
    assert root_admin._is_canonical_path(canonical.with_name("sibling.sqlite3")) is False
    assert root_admin._is_canonical_path(str(canonical)) is False


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
                        lambda: ({}, {}, ANCHOR, ("root-dep", "substrate-dep")))
    role_members = [{"role": role, "security_context_config_resource": f"security-{role}",
                     "capability_wiring_resource": f"wiring-{role}"}
                    for role in ("T", "C", "P", "M")]
    raw_resources = {f"security-{role}": role.encode() for role in ("T", "C", "P", "M")}
    raw_resources.update({f"wiring-{role}": (role + "-wiring").encode()
                          for role in ("C", "P", "M")})
    package = SimpleNamespace(
        graph=json.dumps({"members": role_members}).encode(), raw_resources=raw_resources,
        candidate_package_id=PACKAGE, manifest_id=MANIFEST, runtime_sha256="d" * 64,
        build_definition=json.dumps({"execution_isolation_dependency_id": "dep-exec-test"}).encode(),
    )
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


def _test_fence_row(candidate_package_id: str = PACKAGE, manifest_id: str = MANIFEST,
                    runtime_sha256: str = "d" * 64) -> dict[str, object]:
    return root_admin.build_fence_row(
        root_anchor_id=ANCHOR, candidate_package_id=candidate_package_id,
        manifest_id=manifest_id, runtime_artifact_sha256=runtime_sha256,
        runtime_generation="g9-generation-test",
        execution_isolation_dependency_id=_TEST_ISOLATION_DEPENDENCY,
        fixture_effect_substrate_dependency_id=_TEST_DEPENDENCIES[1],
        security_context_identities={role: hashlib.sha256(role.encode()).hexdigest()
                                     for role in ("T", "C", "P", "M")},
        prepared_endpoint_identities={role: hashlib.sha256((role + "-endpoint").encode()).hexdigest()
                                      for role in ("C", "P", "M")},
    )


def _root_fixture(path, *, root_rows: bool = False, state: str = "FENCED", revision: int = 0,
                  candidate_package_id: str = PACKAGE) -> dict[str, object]:
    fence = _test_fence_row(candidate_package_id)
    fence["state"], fence["revision"] = state, revision
    connection = sqlite3.connect(path)
    try:
        for statement in root_admin._SCHEMA_STATEMENTS:
            connection.execute(statement)
        columns = ",".join(root_admin.FENCE_BINDING_FIELDS)
        placeholders = ",".join("?" for _ in root_admin.FENCE_BINDING_FIELDS)
        connection.execute(f"INSERT INTO capability_fence({columns}) VALUES ({placeholders})",
                           tuple(fence[field] for field in root_admin.FENCE_BINDING_FIELDS))
        if root_rows:
            connection.execute(
                "INSERT INTO root_state(format, root_anchor_id, active_manifest_id, transition, revision) "
                "VALUES (?, ?, ?, 'open', 1)",
                (root_admin.ROOT_STATE_FORMAT, ANCHOR, MANIFEST),
            )
        connection.commit()
    finally:
        connection.close()
    return fence


def test_root_store_inspection_is_read_only_and_recognizes_only_exact_stage_b_state(tmp_path):
    database = tmp_path / "fixture.sqlite3"
    fence = _root_fixture(database)
    before = database.read_bytes()
    evidence = root_admin.inspect_uninitialized_root(
        database, expected_fence_row=fence, deployment_session_id="e" * 64,
    )
    assert evidence == {
        "status": "UNINITIALIZED", "root_anchor_id": ANCHOR,
        "candidate_package_id": PACKAGE, "root_state_row_count": 0,
        "capability_fence_row_count": 1, "fence_state": "FENCED",
        "manifest_id": MANIFEST, "fence_id": fence["fence_id"],
        "fence_revision": 0, "capability_fence": fence,
        "acceptance_history_count": 0, "initialization_record_count": 0,
        "acceptance_history_digest": hashlib.sha256(
            b"autodev.genesis-acceptance-history/v1\0[]"
        ).hexdigest(),
        "applicable_acceptance_for_this_deployment_session": None,
        "deployment_session_id": "e" * 64,
        "release_verification_count": 0, "schema_sha256": root_admin.ROOT_STORE_SCHEMA_SHA256,
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
        expected = _test_fence_row()
        root_admin.inspect_uninitialized_root(
            database, expected_fence_row=expected, deployment_session_id="e" * 64,
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
            database, expected_fence_row=_test_fence_row(), deployment_session_id="e" * 64,
        )


def _fixture_attestation(fence: dict[str, object], session: str) -> dict[str, object]:
    roles: dict[str, dict[str, object]] = {}
    process_observations: dict[str, dict[str, object]] = {}
    role_types = {"T": "TrustedControllerRuntime", "C": "ControlStateGateRuntime",
                  "P": "PublicationGateRuntime", "M": "MergeGateRuntime"}
    role_sids = {item["role"]: item["sid"] for item in _TEST_ISOLATION_PROFILE["role_principals"]}
    for index, role in enumerate(("T", "C", "P", "M"), start=101):
        role_record: dict[str, object] = {
            "sid": role_sids[role],
            "token_type": 1, "administrator": False, "pid": index,
            "ppid": 900, "candidate_package_id": fence["candidate_package_id"],
        "runtime_sha256": fence["runtime_artifact_sha256"],
            "entrypoint_identity": hashlib.sha256((role + "-entry").encode()).hexdigest(),
            "security_context_identity": fence[f"security_context_{role.lower()}_identity"],
            "wiring_identity": hashlib.sha256((role + "-wiring").encode()).hexdigest(),
            "endpoint_identity": hashlib.sha256((role + "-endpoint").encode()).hexdigest(),
            "private_directory": f"C:/AutodevG9/private/{role}",
            "destination_channel_credentials": "NONE" if role == "T" else "ROLE_LOCAL_ONLY",
            "runtime_type": role_types[role],
            "runtime_role_identity": hashlib.sha256((role + "-runtime-role").encode()).hexdigest(),
            "runtime_binding_id": hashlib.sha256((role + "-binding").encode()).hexdigest(),
            "runtime_active": role in ("T", "C"), "canonical_state": {},
        }
        roles[role] = role_record
        process_subject = {
            "role": role, "pid": index, "creation_time_100ns": index * 100,
            "sid": role_record["sid"], "token_type": 1, "administrator": False,
            "deployment_session_id": session,
            "security_context_identity": role_record["security_context_identity"],
            "entrypoint_identity": role_record["entrypoint_identity"],
            "wiring_identity": role_record["wiring_identity"],
            "endpoint_identity": role_record["endpoint_identity"],
            "runtime_role_identity": role_record["runtime_role_identity"],
            "runtime_binding_id": role_record["runtime_binding_id"],
        }
        process_observations[role] = {
            **process_subject,
            "process_instance_id": hashlib.sha256(
                b"autodev.g9-process-instance/v1\0" + canonical_json_bytes(process_subject)
            ).hexdigest(),
        }
    process_subject = {
        "role": "S", "pid": 100, "creation_time_100ns": 10000,
        "sid": "S-1-5-21-711519901-190585334-3846127459-1020",
        "token_type": 1, "administrator": False, "deployment_session_id": session,
        "security_context_identity": hashlib.sha256(b"S-context").hexdigest(),
        "entrypoint_identity": hashlib.sha256(b"S-entry").hexdigest(),
        "wiring_identity": hashlib.sha256(b"S-wiring").hexdigest(),
        "endpoint_identity": hashlib.sha256(b"S-endpoint").hexdigest(),
        "runtime_role_identity": hashlib.sha256(b"S-runtime").hexdigest(),
        "runtime_binding_id": hashlib.sha256(b"S-binding").hexdigest(),
    }
    process_observations["S"] = {
        **process_subject,
        "process_instance_id": hashlib.sha256(
            b"autodev.g9-process-instance/v1\0" + canonical_json_bytes(process_subject)
        ).hexdigest(),
    }
    root_observation = {
        "status": "UNINITIALIZED", "root_anchor_id": fence["root_anchor_id"],
        "candidate_package_id": fence["candidate_package_id"], "manifest_id": fence["manifest_id"],
        "root_state_row_count": 0, "capability_fence_row_count": 1,
        "fence_id": fence["fence_id"], "fence_state": "FENCED", "fence_revision": 0,
        "capability_fence": fence, "acceptance_history_count": 0,
        "acceptance_history_digest": hashlib.sha256(
            b"autodev.genesis-acceptance-history/v1\0[]"
        ).hexdigest(), "applicable_acceptance_for_this_deployment_session": None,
        "deployment_session_id": session, "initialization_record_count": 0,
        "release_verification_count": 0, "schema_sha256": root_admin.ROOT_STORE_SCHEMA_SHA256,
    }
    review_record = make_review_record(
        package_id=fence["candidate_package_id"], manifest_id=fence["manifest_id"],
        evidence_id="D-" + "1" * 24, runtime_sha256=fence["runtime_artifact_sha256"],
        root_anchor_id=fence["root_anchor_id"], dependencies={
            "ROOT_ACTIVATION_FENCE": _TEST_DEPENDENCIES[0],
            "EXECUTION_ISOLATION": _TEST_ISOLATION_DEPENDENCY,
            "FIXTURE_EFFECT_SUBSTRATE": _TEST_DEPENDENCIES[1],
        },
    )
    post_merge_binding = make_post_merge_binding(review_record)
    controller_identity = derive_external_root_controller_identity(_TEST_ROOT_PROFILE)
    controller_security_context = {
        "root_admin_sid": ADMIN_SID,
        "primary_token": True,
        "elevated_admin": True,
        "administrators_sid_enabled": True,
        "controller_implementation_identity": controller_identity["implementation_sha256"],
        "controller_configuration_identity": controller_identity["configuration_sha256"],
        "deployment_session_id": session,
    }
    preimage = {
        "format": "autodev.genesis-deployment-attestation/v1",
        "candidate_package_id": fence["candidate_package_id"],
        "genesis_manifest_id": fence["manifest_id"],
        "deterministic_evidence_ids": ["D-" + "1" * 24],
        "genesis_review_record": review_record,
        "post_merge_binding": post_merge_binding,
        "stage_b_subject_digest": stage_b_subject_digest(review_record, post_merge_binding),
        "external_root_controller_security_context": controller_security_context,
        "runtime_artifact_sha256": fence["runtime_artifact_sha256"],
        "python_runtime": _TEST_ROOT_PROFILE["python_runtime"],
        "execution_isolation_dependency_id": fence["execution_isolation_dependency_id"],
        "execution_isolation_profile": _TEST_ISOLATION_PROFILE,
        "execution_isolation_profile_sha256": hashlib.sha256(
            canonical_json_bytes(_TEST_ISOLATION_PROFILE)).hexdigest(),
        "root_fence_dependency_id": _TEST_DEPENDENCIES[0],
        "root_fence_profile": _TEST_ROOT_PROFILE,
        "root_fence_profile_sha256": hashlib.sha256(
            canonical_json_bytes(_TEST_ROOT_PROFILE)).hexdigest(),
        "root_store_profile_id": _TEST_STORE_ID,
        "root_store_schema_sha256": root_admin.ROOT_STORE_SCHEMA_SHA256,
        "root_namespace_acl_profile_id": _TEST_ACL_ID,
        "acceptance_profile_id": _TEST_ACCEPTANCE_ID,
        "fixture_substrate_dependency_id": fence["fixture_effect_substrate_dependency_id"],
        "fixture_substrate_profile": _TEST_SUBSTRATE_PROFILE,
        "fixture_substrate_profile_sha256": hashlib.sha256(
            canonical_json_bytes(_TEST_SUBSTRATE_PROFILE)).hexdigest(),
        "root_anchor_id": fence["root_anchor_id"],
        "deployment_session_id": session,
        "root_state_observation": root_observation,
        "roles": roles, "process_instance_observations": process_observations,
        "external_root_controller_identity": derive_external_root_controller_identity(
            _TEST_ROOT_PROFILE),
        "staged_external_material": sorted({
            item["path"]: item["sha256"]
            for collection in (
                _TEST_ROOT_PROFILE["root_admin_tool_material"],
                _TEST_ROOT_PROFILE["fence_controller_material"],
                _TEST_ROOT_PROFILE["genesis_provenance_material"],
                _TEST_SUBSTRATE_PROFILE["implementation_material"],
                _TEST_ISOLATION_PROFILE["external_adapter_material"],
            ) for item in collection
        }.items()),
        "substrate_service": {"sid": process_subject["sid"], "token_type": 1,
            "administrator": False, "pid": process_subject["pid"],
            "endpoint_identity": process_subject["endpoint_identity"],
            "implementation_identity": next(
                item["sha256"] for item in _TEST_SUBSTRATE_PROFILE["implementation_material"]
                if item["path"] == "tools/genesis/fixture_substrate.py"),
            "configuration_identity": hashlib.sha256(
                canonical_json_bytes(_TEST_SUBSTRATE_PROFILE)).hexdigest(),
            "working_directory": r"C:\AutodevG9\shared"},
        "shared_runtime_read_only": True,
        "cross_role_private_write_denial": {role: True for role in ("T", "C", "P", "M")},
        "candidate_root_store_write_denial": {role: True for role in ("T", "C", "P", "M")},
        "protected_endpoint_state": {
            "C_WRITER": {"state": "FENCED", "identity": fence["prepared_endpoint_c_identity"],
                          "credential_withheld": True},
            "P_PUBLICATION": {"state": "FENCED", "identity": fence["prepared_endpoint_p_identity"],
                              "credential_withheld": True},
            "M_MERGE": {"state": "FENCED", "identity": fence["prepared_endpoint_m_identity"],
                        "credential_withheld": True},
        },
        "recovery_fence_inventory": [
            _TEST_SUBSTRATE_PROFILE["external_recovery_endpoint"]["endpoint_id"],
        ],
        "production_github_mutation_credentials": "NONE",
        "host_profile_id": derive_host_profile_id(
            root_fence_profile_sha256=hashlib.sha256(canonical_json_bytes(_TEST_ROOT_PROFILE)).hexdigest(),
            fixture_substrate_profile_sha256=hashlib.sha256(
                canonical_json_bytes(_TEST_SUBSTRATE_PROFILE)).hexdigest(),
            execution_isolation_profile_sha256=hashlib.sha256(
                canonical_json_bytes(_TEST_ISOLATION_PROFILE)).hexdigest(),
        ),
        "observed_at": "2026-09-28T12:00:00.000000Z",
    }
    preimage["staged_external_material"] = [
        {"path": path, "sha256": digest}
        for path, digest in preimage["staged_external_material"]
    ]
    record = {"record_id": hashlib.sha256(canonical_json_bytes(preimage)).hexdigest(),
              "preimage": preimage}
    root_admin._validate_deployment_attestation(record, fence, session)
    return record


def test_execution_isolation_material_closure_distinguishes_adapters_from_role_modules():
    adapter_paths = {item["path"] for item in _TEST_ISOLATION_PROFILE["external_adapter_material"]}
    interpreter_paths = {item["path"] for item in _TEST_ISOLATION_PROFILE["role_interpreter_modules"]}
    assert len(adapter_paths) == 7
    assert adapter_paths == {
        "tools/genesis/ipc.py",
        "tools/genesis/role_worker.py",
        "tools/genesis/windows_role_launcher.py",
        "tools/genesis/windows_role_runner.py",
        "tools/genesis/role_adapter.py",
        "tools/genesis/substrate_client.py",
        "tools/genesis/canonical_state_channel.py",
    }
    assert len(interpreter_paths) == 5
    assert interpreter_paths == {
        "tools/genesis/ipc.py",
        "tools/genesis/role_worker.py",
        "tools/genesis/role_adapter.py",
        "tools/genesis/substrate_client.py",
        "tools/genesis/canonical_state_channel.py",
    }


@pytest.mark.parametrize(("mutation", "path"), (
    ("omit", "tools/genesis/windows_role_launcher.py"),
    ("omit", "tools/genesis/windows_role_runner.py"),
    ("digest", "tools/genesis/windows_role_launcher.py"),
    ("digest", "tools/genesis/windows_role_runner.py"),
    ("extra", "tools/genesis/unauthorized-extra.py"),
))
def test_deployment_attestation_requires_exact_external_tcb_closure(mutation, path):
    fence = _test_fence_row()
    session = "2" * 64
    changed = json.loads(json.dumps(_fixture_attestation(fence, session)))
    material = changed["preimage"]["staged_external_material"]
    if mutation == "omit":
        material[:] = [item for item in material if item["path"] != path]
    elif mutation == "digest":
        selected = next(item for item in material if item["path"] == path)
        selected["sha256"] = "0" * 64
    else:
        material.append({"path": path, "sha256": "f" * 64})
        material.sort(key=lambda item: item["path"])
    changed["record_id"] = hashlib.sha256(
        canonical_json_bytes(changed["preimage"])
    ).hexdigest()
    with pytest.raises(ValueError, match="staged material differs from bound profiles"):
        root_admin._validate_deployment_attestation(changed, fence, session)


def test_deployment_attestation_rejects_caller_selected_controller_digests():
    fence = _test_fence_row()
    attestation = _fixture_attestation(fence, "2" * 64)
    changed = json.loads(json.dumps(attestation))
    changed["preimage"]["external_root_controller_identity"] = {
        "implementation_sha256": "9" * 64,
        "configuration_sha256": "a" * 64,
    }
    changed["record_id"] = hashlib.sha256(canonical_json_bytes(changed["preimage"])).hexdigest()
    with pytest.raises(ValueError, match="exact bound controller"):
        root_admin._validate_deployment_attestation(changed, fence, "2" * 64)


def test_s_requires_exact_review_merge_binding_and_has_no_generic_commit_assertion():
    fence = _test_fence_row()
    session = "2" * 64
    attestation = _fixture_attestation(fence, session)
    preimage = attestation["preimage"]
    assert "review_record_id" not in preimage
    assert "repository_source_commit" not in preimage
    assert "genesis_review_record" in preimage
    assert "post_merge_binding" in preimage
    assert "stage_b_subject_digest" in preimage

    missing_binding = json.loads(json.dumps(attestation))
    del missing_binding["preimage"]["post_merge_binding"]
    missing_binding["record_id"] = hashlib.sha256(
        canonical_json_bytes(missing_binding["preimage"])
    ).hexdigest()
    with pytest.raises(ValueError, match="unsupported"):
        root_admin._validate_deployment_attestation(missing_binding, fence, session)

    stale_time = json.loads(json.dumps(attestation))
    stale_time["preimage"]["observed_at"] = "2026-09-28T12:00:00Z"
    stale_time["record_id"] = hashlib.sha256(
        canonical_json_bytes(stale_time["preimage"])
    ).hexdigest()
    with pytest.raises(ValueError, match="timestamp"):
        root_admin._validate_deployment_attestation(stale_time, fence, session)


def test_acceptance_confirmation_binds_exact_stable_subject_not_timestamp():
    preimage = root_admin.acceptance_preimage(
        acceptance_profile_id=_TEST_ACCEPTANCE_ID, approver_account=r"ray\zhang",
        approver_sid=ADMIN_SID, candidate_package_id=PACKAGE, genesis_manifest_id=MANIFEST,
        runtime_artifact_sha256="d" * 64, root_anchor_id=ANCHOR,
        deployment_attestation_id="1" * 64, deployment_session_id="2" * 64,
    )
    assert preimage["activation_subject"] == {
        "kind": "GENESIS_BOOTSTRAP", "manifest_id": MANIFEST,
    }
    digest = root_admin.acceptance_confirmation_subject(preimage)
    stable = {key: value for key, value in preimage.items() if key != "accepted_at"}
    assert digest == hashlib.sha256(
        b"autodev.genesis-acceptance-subject/v1\0" + canonical_json_bytes(stable)
    ).hexdigest()
    changed_timestamp = dict(preimage, accepted_at="2026-09-28T12:00:00.000001Z")
    assert root_admin.acceptance_confirmation_subject(changed_timestamp) == digest
    changed_subject = dict(preimage, deployment_session_id="3" * 64)
    assert root_admin.acceptance_confirmation_subject(changed_subject) != digest
    malformed = dict(preimage, activation_subject={
        "kind": "GENESIS_BOOTSTRAP", "genesis_manifest_id": MANIFEST,
    })
    with pytest.raises(ValueError, match="confirmation subject"):
        root_admin.acceptance_confirmation_subject(malformed)


def _fixture_live_observation(attestation: dict[str, object]) -> dict[str, object]:
    preimage = attestation["preimage"]
    return {
        "deployment_session_id": preimage["deployment_session_id"],
        "deployment_attestation_id": attestation["record_id"],
        "candidate_package_id": preimage["candidate_package_id"],
        "genesis_manifest_id": preimage["genesis_manifest_id"],
        "runtime_artifact_sha256": preimage["runtime_artifact_sha256"],
        "root_anchor_id": preimage["root_anchor_id"],
        "root_profile_identities": {
            "root_store_profile_id": preimage["root_store_profile_id"],
            "root_namespace_acl_profile_id": preimage["root_namespace_acl_profile_id"],
            "acceptance_profile_id": preimage["acceptance_profile_id"],
            "root_fence_dependency_id": preimage["root_fence_dependency_id"],
            "execution_isolation_dependency_id": preimage["execution_isolation_dependency_id"],
            "fixture_substrate_dependency_id": preimage["fixture_substrate_dependency_id"],
            "root_anchor_id": preimage["root_anchor_id"],
        },
        "security_context_identities": {
            role: preimage["roles"][role]["security_context_identity"]
            for role in ("T", "C", "P", "M")
        },
        "role_bindings": {
            role: {key: preimage["roles"][role][key] for key in (
                "security_context_identity", "entrypoint_identity", "wiring_identity",
                "endpoint_identity", "runtime_role_identity", "runtime_binding_id")}
            for role in ("T", "C", "P", "M")
        },
        "process_instance_identities": {
            role: item["process_instance_id"]
            for role, item in preimage["process_instance_observations"].items()
        },
        "external_material_identities": {
            item["path"]: item["sha256"] for item in preimage["staged_external_material"]
        },
        "substrate_endpoint_identity": preimage["substrate_service"]["endpoint_identity"],
        "protected_effect_denial_observation": {
            "p_target_fence_state": "FENCED", "m_target_fence_state": "FENCED",
            "p_protected_effect_denied": True, "m_protected_effect_denied": True,
            "candidate_root_store_write_denied": True, "candidate_fence_release_denied": True,
            "production_github_mutation_credentials": "NONE",
        },
    }


def test_fresh_release_observation_is_bound_to_exact_s_processes_material_and_denials():
    fence = _test_fence_row()
    attestation = _fixture_attestation(fence, "2" * 64)
    observation = _fixture_live_observation(attestation)
    assert root_admin._verify_live_observation(
        observation, fence, "2" * 64, attestation,
    )
    for mutate in (
        lambda value: value["process_instance_identities"].update(T="0" * 64),
        lambda value: value["external_material_identities"].update(
            {"tools/genesis/root_admin.py": "0" * 64}),
        lambda value: value["role_bindings"]["P"].update(runtime_binding_id="0" * 64),
        lambda value: value["protected_effect_denial_observation"].update(
            m_protected_effect_denied=False),
        lambda value: value["root_profile_identities"].update(root_store_profile_id="0" * 64),
    ):
        altered = json.loads(json.dumps(observation))
        mutate(altered)
        assert not root_admin._verify_live_observation(altered, fence, "2" * 64, attestation)


def test_root_mutations_require_retained_native_session_not_a_boolean_callback():
    with pytest.raises(TypeError, match="exact retained native launcher process type"):
        root_admin.RetainedDeploymentSession(
            "1" * 64, {role: object() for role in ("S", "T", "C", "P", "M")},
        )
    assert "final_liveness_check" not in inspect.signature(
        root_admin.initialize_genesis_state,
    ).parameters
    assert "final_liveness_check" not in inspect.signature(
        root_admin.release_capability_fence,
    ).parameters
    with pytest.raises(TypeError, match="use RetainedRootControllerSession.launch"):
        fence_controller.RetainedRootControllerSession()


def test_controller_launch_generates_session_id_and_transfers_exact_process_set(monkeypatch):
    session_id = "d" * 64
    processes = {role: object() for role in ("S", "T", "C", "P", "M")}
    fence = _test_fence_row()
    fixture_s = _fixture_attestation(fence, session_id)
    fixture_preimage = fixture_s["preimage"]
    package = assemble_candidate(
        git_cwd=str(_REPOSITORY),
        root_fence_profile=_TEST_ROOT_PROFILE,
        fixture_substrate_profile=_TEST_SUBSTRATE_PROFILE,
        root_anchor_id=ANCHOR,
    )
    candidate_build_definition = json.loads(package.build_definition)
    assert "fixture_substrate_dependency_id" in candidate_build_definition
    assert "fixture_effect_substrate_dependency_id" not in candidate_build_definition
    assert len(candidate_build_definition["external_tcb_material"]) == 14
    assert candidate_build_definition["fixture_substrate_dependency_id"] == (
        fixture_preimage["fixture_substrate_dependency_id"]
    )

    class FakeRetained:
        def __init__(self, received_id, received_processes):
            assert received_id == session_id
            assert received_processes is processes
            self.deployment_session_id = received_id

        def assert_live(self):
            return None

        def verify(self, attestation, received_id):
            return received_id == session_id and attestation["preimage"][
                "deployment_session_id"] == session_id

    import windows_role_runner

    monkeypatch.setattr(windows_role_runner, "_host_profiles", lambda: (
        _TEST_ROOT_PROFILE, _TEST_SUBSTRATE_PROFILE, ANCHOR, _TEST_DEPENDENCIES,
    ))
    readiness_keys = (
        "roles", "shared_runtime_read_only", "cross_role_private_write_denial",
        "candidate_root_store_write_denial", "protected_endpoint_state", "host_profile_id",
    )
    launch_payload = {
        "_root_fence_profile": _TEST_ROOT_PROFILE,
        "_deployment_session_id": session_id,
        "_retained_process_instances": processes,
        "_deployment_readiness_preimage": {
            key: fixture_preimage[key] for key in readiness_keys
        },
        "_candidate_build_definition": candidate_build_definition,
        "_fixture_substrate_profile": fixture_preimage["fixture_substrate_profile"],
        "candidate_package_id": fixture_preimage["candidate_package_id"],
        "manifest_id": fixture_preimage["genesis_manifest_id"],
        "deterministic_evidence_id": fixture_preimage["deterministic_evidence_ids"][0],
        "runtime_sha256": fixture_preimage["runtime_artifact_sha256"],
        "root_anchor_id": fixture_preimage["root_anchor_id"],
    }
    assert launch_payload["_candidate_build_definition"]["fixture_substrate_dependency_id"] == (
        fixture_preimage["fixture_substrate_dependency_id"]
    )
    assert "fixture_effect_substrate_dependency_id" not in launch_payload["_candidate_build_definition"]
    monkeypatch.setattr(windows_role_runner, "_launch_retained_deployment_processes",
                        lambda value: dict(launch_payload, _deployment_session_id=value))
    monkeypatch.setattr(root_admin, "new_deployment_session_id", lambda: session_id)
    monkeypatch.setattr(root_admin, "_current_token_facts", lambda: (
        ADMIN_SID, True, True, True,
    ))
    monkeypatch.setattr(fence_controller, "RetainedDeploymentSession", FakeRetained)
    monkeypatch.setattr(fence_controller, "revalidate_post_merge_binding", lambda *args: {})
    monkeypatch.setattr(fence_controller, "verify_local_merge_subject", lambda *_args: {})
    monkeypatch.setattr(fence_controller.RetainedRootControllerSession,
                        "_current_process_observations",
                        lambda _self: fixture_preimage["process_instance_observations"])
    monkeypatch.setattr(fence_controller.RetainedRootControllerSession,
                        "_current_substrate_service",
                        lambda _self: fixture_preimage["substrate_service"])
    monkeypatch.setattr(root_admin, "inspect_uninitialized_root",
                        lambda _path, *, expected_fence_row, deployment_session_id: (
                            fixture_preimage["root_state_observation"]
                            if expected_fence_row == fence and deployment_session_id == session_id
                            else pytest.fail("S builder used a different root/session subject")))
    reviewed = fixture_preimage["genesis_review_record"]
    binding = fixture_preimage["post_merge_binding"]
    observation = make_github_observation(
        reviewed, merge_commit_sha=binding["preimage"]["merge_commit_sha"],
    )
    monkeypatch.setattr(fence_controller.sys, "stdin", _TestInput(
        f"STAGE_B {stage_b_subject_digest(reviewed, binding)}\n", is_tty=True,
    ))
    controller = fence_controller.RetainedRootControllerSession.launch(
        genesis_review_record=reviewed, post_merge_binding=binding,
        github_observation=observation,
    )
    assert controller.deployment_session_id == session_id
    assert controller.controller_identity == derive_external_root_controller_identity(_TEST_ROOT_PROFILE)
    attestation = controller.build_deployment_attestation(expected_fence_row=fence)
    assert root_admin._validate_deployment_attestation(attestation, fence, session_id)
    assert root_admin._is_exact_utc(attestation["preimage"]["observed_at"])
    assert attestation["preimage"]["genesis_review_record"] == reviewed
    assert attestation["preimage"]["post_merge_binding"] == binding
    assert attestation["preimage"]["fixture_substrate_dependency_id"] == (
        candidate_build_definition["fixture_substrate_dependency_id"]
    )
    assert attestation["preimage"]["staged_external_material"] == (
        candidate_build_definition["external_tcb_material"]
    )
    assert controller._retained is not None
    controller._retained.assert_live()


class _TestInput(io.StringIO):
    def __init__(self, value: str, *, is_tty: bool):
        super().__init__(value)
        self._is_tty = is_tty

    def isatty(self) -> bool:
        return self._is_tty


@pytest.mark.parametrize(("is_tty", "response", "expected_message"), (
    (False, "STAGE_B " + "d" * 64, "interactive local console"),
    (True, "STAGE_B " + "0" * 64, "exact Stage-B subject confirmation did not match"),
))
def test_controller_rejects_non_tty_or_wrong_stage_b_subject_before_role_launch(
        monkeypatch, is_tty, response, expected_message):
    import windows_role_runner

    session_id = "d" * 64
    fixture_preimage = _fixture_attestation(_test_fence_row(), session_id)["preimage"]
    reviewed = fixture_preimage["genesis_review_record"]
    binding = fixture_preimage["post_merge_binding"]
    observation = make_github_observation(
        reviewed, merge_commit_sha=binding["preimage"]["merge_commit_sha"],
    )
    events = []
    launches = []

    monkeypatch.setattr(windows_role_runner, "_host_profiles", lambda: (
        _TEST_ROOT_PROFILE, _TEST_SUBSTRATE_PROFILE, ANCHOR, _TEST_DEPENDENCIES,
    ))
    monkeypatch.setattr(root_admin, "_current_token_facts", lambda: (
        events.append("root_admin_authentication") or (ADMIN_SID, True, True, True)
    ))
    monkeypatch.setattr(root_admin, "new_deployment_session_id", lambda: session_id)

    validate_review = fence_controller.validate_genesis_exact_head_review_record
    validate_binding = fence_controller.validate_post_merge_binding

    def checked_review(record):
        events.append("review_record_validation")
        return validate_review(record)

    def checked_binding(record, review_record):
        events.append("post_merge_binding_validation")
        return validate_binding(record, review_record)

    monkeypatch.setattr(fence_controller, "validate_genesis_exact_head_review_record", checked_review)
    monkeypatch.setattr(fence_controller, "validate_post_merge_binding", checked_binding)
    monkeypatch.setattr(fence_controller, "revalidate_post_merge_binding",
                        lambda *_args: events.append("local_subject_revalidation") or {})
    monkeypatch.setattr(windows_role_runner, "_launch_retained_deployment_processes",
                        lambda *_args: launches.append("role_launch"))
    monkeypatch.setattr(fence_controller.sys, "stdin", _TestInput(response + "\n", is_tty=is_tty))

    with pytest.raises(PermissionError, match=expected_message):
        fence_controller.RetainedRootControllerSession.launch(
            genesis_review_record=reviewed,
            post_merge_binding=binding,
            github_observation=observation,
        )

    assert events == [
        "root_admin_authentication",
        "review_record_validation",
        "post_merge_binding_validation",
        "local_subject_revalidation",
    ]
    assert launches == []


@pytest.mark.parametrize("token_facts", (
    ("S-1-5-21-711519901-190585334-3846127459-9999", True, True, True),
    (ADMIN_SID, False, True, True),
    (ADMIN_SID, True, False, True),
    (ADMIN_SID, True, True, False),
))
def test_controller_authentication_failure_precedes_stage_b_and_role_launch(
        monkeypatch, token_facts):
    import windows_role_runner

    monkeypatch.setattr(windows_role_runner, "_host_profiles", lambda: (
        _TEST_ROOT_PROFILE, _TEST_SUBSTRATE_PROFILE, ANCHOR, _TEST_DEPENDENCIES,
    ))
    monkeypatch.setattr(root_admin, "_current_token_facts", lambda: token_facts)
    launches = []
    confirmations = []
    monkeypatch.setattr(windows_role_runner, "_launch_retained_deployment_processes",
                        lambda _session: launches.append("launched"))
    monkeypatch.setattr(fence_controller, "_confirm_stage_b_subject",
                        lambda _digest: confirmations.append("confirmed"))
    with pytest.raises(PermissionError, match="profile-bound elevated external root administrator"):
        fence_controller.RetainedRootControllerSession.launch(
            genesis_review_record={}, post_merge_binding={}, github_observation={},
        )
    assert confirmations == []
    assert launches == []


@pytest.mark.parametrize("failure", (
    ValueError("local main is stale"),
    ValueError("regenerated CP2 differs from the reviewed subject"),
))
def test_controller_stale_or_conflicting_post_merge_proof_stops_before_confirmation_and_launch(
        monkeypatch, failure):
    import windows_role_runner

    session = "d" * 64
    fixture = _fixture_attestation(_test_fence_row(), session)["preimage"]
    monkeypatch.setattr(windows_role_runner, "_host_profiles", lambda: (
        _TEST_ROOT_PROFILE, _TEST_SUBSTRATE_PROFILE, ANCHOR, _TEST_DEPENDENCIES,
    ))
    monkeypatch.setattr(root_admin, "_current_token_facts", lambda: (
        ADMIN_SID, True, True, True,
    ))
    monkeypatch.setattr(root_admin, "new_deployment_session_id", lambda: session)
    monkeypatch.setattr(fence_controller, "revalidate_post_merge_binding",
                        lambda *_args: (_ for _ in ()).throw(failure))
    confirmations, launches = [], []
    monkeypatch.setattr(fence_controller, "_confirm_stage_b_subject",
                        lambda _digest: confirmations.append("confirmed"))
    monkeypatch.setattr(windows_role_runner, "_launch_retained_deployment_processes",
                        lambda _session: launches.append("launched"))
    with pytest.raises(type(failure), match=str(failure)):
        fence_controller.RetainedRootControllerSession.launch(
            genesis_review_record=fixture["genesis_review_record"],
            post_merge_binding=fixture["post_merge_binding"],
            github_observation=make_github_observation(
                fixture["genesis_review_record"],
                merge_commit_sha=fixture["post_merge_binding"]["preimage"]["merge_commit_sha"],
            ),
        )
    assert confirmations == []
    assert launches == []


@pytest.mark.parametrize("role", ("P", "M"))
def test_fresh_effect_probe_is_role_bound_and_fails_closed(role):
    package_id = "a" * 64

    class Substrate:
        def read_publication_fence(self):
            return {"fence": "FENCED", "revision": 0,
                    "candidate_package_id": package_id}

        def read_merge_fence(self):
            return {"fence": "FENCED", "revision": 0,
                    "candidate_package_id": package_id}

        def prepare_publication(self, effect_id, payload):
            assert effect_id == "root-release-readiness-probe" and payload == b""
            return {"accepted": False, "reason": "TARGET_FENCED",
                    "candidate_package_id": package_id}

        def prepare_merge(self, effect_id, payload):
            assert effect_id == "root-release-readiness-probe" and payload == b""
            return {"accepted": False, "reason": "TARGET_FENCED",
                    "candidate_package_id": package_id}

    assert role_worker._fresh_protected_effect_probe(role, Substrate(), package_id) == {
        "control_probe": "PROTECTED_EFFECT", "role": role, "fence": "FENCED",
        "revision": 0, "protected_effect_accepted": False,
        "candidate_package_id": package_id,
    }

    class Released(Substrate):
        def read_publication_fence(self):
            return {"fence": "RELEASED", "revision": 1,
                    "candidate_package_id": package_id}

        def read_merge_fence(self):
            return {"fence": "RELEASED", "revision": 1,
                    "candidate_package_id": package_id}

    with pytest.raises(PermissionError, match="exact frozen denied state"):
        role_worker._fresh_protected_effect_probe(role, Released(), package_id)


@pytest.mark.parametrize("role", ("T", "C", "P", "M"))
def test_role_fence_release_probe_is_closed_and_never_authorizes_release(role):
    assert role_worker._fence_release_probe(role) == {
        "control_probe": "FENCE_RELEASE", "role": role,
        "accepted": False, "reason": "NO_RELEASE_CAPABILITY",
    }
    with pytest.raises(ValueError, match="unsupported"):
        role_worker._fence_release_probe("S")


def test_token_groups_native_layout_aligns_the_flexible_array_for_win64():
    import ctypes

    pointer_alignment = ctypes.alignment(root_admin._SidAndAttributes)
    expected_offset = ((ctypes.sizeof(ctypes.c_ulong) + pointer_alignment - 1)
                       // pointer_alignment) * pointer_alignment
    assert root_admin._TokenGroups.groups.offset == expected_offset
    if ctypes.sizeof(ctypes.c_void_p) == 8:
        assert root_admin._TokenGroups.groups.offset == 8


@pytest.mark.parametrize(("attributes", "expected"), (
    (0x4, True),
    (0x0, False),
    (0x10, False),
    (0x4 | 0x10, False),
))
def test_admin_group_must_be_enabled_and_not_deny_only(attributes, expected):
    assert root_admin._group_attributes_are_enabled_admin(attributes) is expected


def test_root_acl_uses_protected_not_conflicting_unprotected_dacl_flag():
    assert root_admin._ROOT_ACL_SECURITY_INFORMATION & 0x80000000
    assert not (root_admin._ROOT_ACL_SECURITY_INFORMATION
                & root_admin._UNPROTECTED_DACL_SECURITY_INFORMATION)


@pytest.mark.skipif(sys.platform != "win32", reason="requires native Windows token APIs")
def test_native_current_token_reports_exact_sid_and_elevation_boolean():
    sid, primary, elevated, enabled_admin = root_admin._current_token_facts()
    assert sid.startswith("S-1-")
    assert primary is True
    assert type(elevated) is bool
    assert type(enabled_admin) is bool
    assert root_admin._current_token_identity() == (sid, primary and elevated and enabled_admin)


@pytest.mark.skipif(sys.platform != "win32", reason="requires native Windows security descriptor APIs")
def test_native_protected_acl_application_and_readback_use_temporary_directory_only():
    sid, _ = root_admin._current_token_identity()
    with tempfile.TemporaryDirectory(prefix="g9-acl-native-") as directory:
        namespace = Path(directory)
        sddl = f"O:{sid}G:{sid}D:P(A;;FA;;;{sid})(A;;FA;;;S-1-5-18)"
        root_admin._set_and_verify_root_acl(namespace, sddl)
        assert namespace.is_dir()


@pytest.mark.skipif(sys.platform != "win32", reason="requires native Windows filesystem generic mapping")
def test_native_filesystem_generic_read_and_file_generic_read_are_effectively_equal():
    import ctypes

    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    assert root_admin._filesystem_effective_access_mask(0x80000000, advapi) == 0x00120089
    assert root_admin._filesystem_effective_access_mask(0x00120089, advapi) == 0x00120089


@pytest.mark.skipif(sys.platform != "win32", reason="requires native Windows security descriptor APIs")
def test_native_gr_acl_readback_as_fr_passes_root_acl_verifier():
    import ctypes

    admin_sid, _ = root_admin._current_token_identity()
    substrate_sid = _TEST_ROOT_PROFILE["root_namespace_acl_profile"]["substrate_sid"]
    sddl = (f"O:{admin_sid}G:S-1-5-18D:P(A;;FA;;;S-1-5-18)"
            f"(A;;FA;;;{admin_sid})(A;;GR;;;{substrate_sid})")
    with tempfile.TemporaryDirectory(prefix="g9-acl-gr-fr-") as directory:
        namespace = Path(directory)
        # This calls the real setter and read-back verifier; it does not replace
        # or bypass ACL verification and touches only this temporary directory.
        root_admin._set_and_verify_root_acl(namespace, sddl)
        advapi, kernel = (ctypes.WinDLL("advapi32", use_last_error=True),
                          ctypes.WinDLL("kernel32", use_last_error=True))
        flags = root_admin._ROOT_ACL_SECURITY_INFORMATION
        needed = ctypes.c_ulong()
        advapi.GetFileSecurityW.argtypes = [ctypes.c_wchar_p, ctypes.c_ulong, ctypes.c_void_p,
                                            ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
        advapi.GetFileSecurityW.restype = ctypes.c_int
        advapi.GetFileSecurityW(str(namespace), flags, None, 0, ctypes.byref(needed))
        assert needed.value
        descriptor = ctypes.create_string_buffer(needed.value)
        assert advapi.GetFileSecurityW(str(namespace), flags, descriptor, needed.value,
                                       ctypes.byref(needed))
        to_sddl = advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW
        to_sddl.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong,
                            ctypes.POINTER(ctypes.c_wchar_p), ctypes.POINTER(ctypes.c_ulong)]
        to_sddl.restype = ctypes.c_int
        rendered, chars = ctypes.c_wchar_p(), ctypes.c_ulong()
        assert to_sddl(descriptor, 1, flags, ctypes.byref(rendered), ctypes.byref(chars))
        try:
            assert f"(A;;FR;;;{substrate_sid})" in rendered.value
            assert f"(A;;GR;;;{substrate_sid})" not in rendered.value
        finally:
            kernel.LocalFree.argtypes = [ctypes.c_void_p]
            kernel.LocalFree.restype = ctypes.c_void_p
            kernel.LocalFree(rendered)


def _native_descriptor_equal(expected_sddl, actual_sddl):
    import ctypes

    advapi, kernel = ctypes.WinDLL("advapi32", use_last_error=True), ctypes.WinDLL("kernel32", use_last_error=True)
    descriptor = ctypes.c_void_p()
    convert = advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW
    convert.argtypes = [ctypes.c_wchar_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_void_p),
                        ctypes.POINTER(ctypes.c_ulong)]
    convert.restype = ctypes.c_int
    if not convert(actual_sddl, 1, ctypes.byref(descriptor), None):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return root_admin._filesystem_security_descriptors_equal(
            descriptor_expected_sddl=expected_sddl, actual_descriptor=descriptor,
        )
    finally:
        kernel.LocalFree.argtypes = [ctypes.c_void_p]
        kernel.LocalFree.restype = ctypes.c_void_p
        kernel.LocalFree(descriptor)


@pytest.mark.skipif(sys.platform != "win32", reason="requires native Windows security descriptor APIs")
@pytest.mark.parametrize(("actual_sddl", "expected"), (
    ("SAME", True),
    ("FR", True),
    ("WRITE", False),
    ("MODIFY", False),
    ("FULL", False),
    ("EXTRA_ACE", False),
    ("MISSING_ACE", False),
    ("REORDERED_ACE", False),
    ("WRONG_SID", False),
    ("INHERITED", False),
    ("WRONG_OWNER", False),
    ("WRONG_GROUP", False),
))
def test_native_root_acl_structural_comparison_rejects_non_equivalent_profiles(actual_sddl, expected):
    admin_sid, _ = root_admin._current_token_identity()
    substrate_sid = _TEST_ROOT_PROFILE["root_namespace_acl_profile"]["substrate_sid"]
    expected_sddl = (f"O:{admin_sid}G:S-1-5-18D:P(A;;FA;;;S-1-5-18)"
                     f"(A;;FA;;;{admin_sid})(A;;GR;;;{substrate_sid})")
    actual = {
        "SAME": expected_sddl,
        "FR": (f"O:{admin_sid}G:S-1-5-18D:P(A;;FA;;;S-1-5-18)"
               f"(A;;FA;;;{admin_sid})(A;;FR;;;{substrate_sid})"),
        "WRITE": (f"O:{admin_sid}G:S-1-5-18D:P(A;;FA;;;S-1-5-18)"
                  f"(A;;FA;;;{admin_sid})(A;;GW;;;{substrate_sid})"),
        "MODIFY": (f"O:{admin_sid}G:S-1-5-18D:P(A;;FA;;;S-1-5-18)"
                   f"(A;;FA;;;{admin_sid})(A;;0x1301bf;;;{substrate_sid})"),
        "FULL": (f"O:{admin_sid}G:S-1-5-18D:P(A;;FA;;;S-1-5-18)"
                 f"(A;;FA;;;{admin_sid})(A;;GA;;;{substrate_sid})"),
        "EXTRA_ACE": (f"O:{admin_sid}G:S-1-5-18D:P(A;;FA;;;S-1-5-18)"
                      f"(A;;FA;;;{admin_sid})(A;;GR;;;{substrate_sid})"
                      f"(A;;GR;;;{_TEST_ROOT_PROFILE['root_namespace_acl_profile']['root_admin_sid']})"),
        "MISSING_ACE": f"O:{admin_sid}G:S-1-5-18D:P(A;;FA;;;S-1-5-18)(A;;FA;;;{admin_sid})",
        "REORDERED_ACE": (f"O:{admin_sid}G:S-1-5-18D:P(A;;FA;;;{admin_sid})"
                          f"(A;;FA;;;S-1-5-18)(A;;GR;;;{substrate_sid})"),
        "WRONG_SID": (f"O:{admin_sid}G:S-1-5-18D:P(A;;FA;;;S-1-5-18)"
                      f"(A;;FA;;;{admin_sid})(A;;GR;;;S-1-5-19)"),
        "INHERITED": (f"O:{admin_sid}G:S-1-5-18D:P(A;;FA;;;S-1-5-18)"
                      f"(A;;FA;;;{admin_sid})(A;CI;GR;;;{substrate_sid})"),
        "WRONG_OWNER": f"O:S-1-5-19G:S-1-5-18D:P(A;;FA;;;S-1-5-18)(A;;FA;;;{admin_sid})(A;;GR;;;{substrate_sid})",
        "WRONG_GROUP": f"O:{admin_sid}G:S-1-5-19D:P(A;;FA;;;S-1-5-18)(A;;FA;;;{admin_sid})(A;;GR;;;{substrate_sid})",
    }[actual_sddl]
    assert _native_descriptor_equal(expected_sddl, actual) is expected


@pytest.mark.skipif(sys.platform != "win32", reason="requires native Windows security descriptor APIs")
def test_native_root_acl_structural_comparison_rejects_unsupported_ace_types():
    admin_sid, _ = root_admin._current_token_identity()
    substrate_sid = _TEST_ROOT_PROFILE["root_namespace_acl_profile"]["substrate_sid"]
    expected_sddl = (f"O:{admin_sid}G:S-1-5-18D:P(A;;FA;;;S-1-5-18)"
                     f"(A;;FA;;;{admin_sid})(A;;GR;;;{substrate_sid})")
    actual_sddl = (f"O:{admin_sid}G:S-1-5-18D:P(A;;FA;;;S-1-5-18)"
                   f"(A;;FA;;;{admin_sid})(D;;GR;;;{substrate_sid})")
    with pytest.raises(PermissionError, match="unsupported ACE"):
        _native_descriptor_equal(expected_sddl, actual_sddl)


@pytest.mark.skipif(sys.platform != "win32", reason="requires native Windows security descriptor APIs")
@pytest.mark.parametrize("actual_sddl", (
    "O:S-1-5-19G:S-1-5-18",  # missing DACL
    "O:S-1-5-19G:S-1-5-18D:NO_ACCESS_CONTROL",  # null DACL
    "O:S-1-5-19G:S-1-5-18D:(A;;FA;;;S-1-5-18)",  # unprotected DACL
))
def test_native_root_acl_structural_comparison_fails_closed_on_unsupported_dacl_shape(actual_sddl):
    admin_sid, _ = root_admin._current_token_identity()
    substrate_sid = _TEST_ROOT_PROFILE["root_namespace_acl_profile"]["substrate_sid"]
    expected_sddl = (f"O:{admin_sid}G:S-1-5-18D:P(A;;FA;;;S-1-5-18)"
                     f"(A;;FA;;;{admin_sid})(A;;GR;;;{substrate_sid})")
    with pytest.raises(PermissionError, match="descriptor shape"):
        _native_descriptor_equal(expected_sddl, actual_sddl)


def _authorize_temp_root_mutation(monkeypatch):
    class _FixtureRetainedSession:
        def __init__(self, deployment_session_id, process_instances):
            self.deployment_session_id = deployment_session_id
            self.process_instances = process_instances

        def verify(self, attestation, session_id):
            observations = attestation["preimage"]["process_instance_observations"]
            return (session_id == self.deployment_session_id
                    and set(self.process_instances) == set(observations)
                    and all(self.process_instances[role].pid == observations[role]["pid"]
                            and self.process_instances[role].creation_time_100ns
                                == observations[role]["creation_time_100ns"]
                            and self.process_instances[role].is_live() is True
                            for role in observations))

    monkeypatch.setattr(root_admin, "_is_canonical_path", lambda _: True)
    monkeypatch.setattr(root_admin, "_require_external_root_admin", lambda _: ADMIN_SID)
    monkeypatch.setattr(root_admin, "_set_and_verify_root_acl", lambda *_: None)
    monkeypatch.setattr(root_admin, "_confirm_human_action", lambda *_: None)
    monkeypatch.setattr(root_admin, "RetainedDeploymentSession", _FixtureRetainedSession)


def _test_retained_session(attestation):
    observations = attestation["preimage"]["process_instance_observations"]
    return root_admin.RetainedDeploymentSession(
        attestation["preimage"]["deployment_session_id"],
        {role: SimpleNamespace(
            pid=record["pid"], creation_time_100ns=record["creation_time_100ns"],
            is_live=lambda: True,
        ) for role, record in observations.items()},
    )


def test_external_root_admin_genesis_initializes_while_fence_remains_fenced_zero(tmp_path, monkeypatch):
    database = tmp_path / "fixture.sqlite3"
    fence = _root_fixture(database)
    _authorize_temp_root_mutation(monkeypatch)
    session = "e" * 64
    attestation = _fixture_attestation(fence, session)
    retained_session = _test_retained_session(attestation)
    accepted = root_admin.append_acceptance(
        database, expected_admin_sid=ADMIN_SID, approver_account=r"ray\zhang",
        acceptance_profile_id=_TEST_ACCEPTANCE_ID, expected_fence_row=fence,
        deployment_attestation=attestation, deployment_session_id=session,
        retained_session=retained_session,
        explicit_acceptance=True, expected_acl_sddl="test-acl",
    )
    repeated_acceptance = root_admin.append_acceptance(
        database, expected_admin_sid=ADMIN_SID, approver_account=r"ray\zhang",
        acceptance_profile_id=_TEST_ACCEPTANCE_ID, expected_fence_row=fence,
        deployment_attestation=attestation, deployment_session_id=session,
        retained_session=retained_session,
        explicit_acceptance=True, expected_acl_sddl="test-acl",
    )
    assert repeated_acceptance == accepted
    historical = root_admin.inspect_uninitialized_root(
        database, expected_fence_row=fence, deployment_session_id="a" * 64,
    )
    assert historical["acceptance_history_count"] == 1
    assert historical["acceptance_history_digest"] == hashlib.sha256(
        b"autodev.genesis-acceptance-history/v1\0"
        + canonical_json_bytes([accepted["acceptance_id"]])
    ).hexdigest()
    assert historical["applicable_acceptance_for_this_deployment_session"] is None
    with pytest.raises(PermissionError, match="explicit"):
        root_admin.initialize_genesis_state(
            database, expected_admin_sid=ADMIN_SID, expected_fence_row=fence,
            acceptance_id=accepted["acceptance_id"], deployment_attestation=attestation,
            deployment_session_id=session, explicit_initialization=False,
            retained_session=retained_session, expected_acl_sddl="test-acl",
        )
    initialized = root_admin.initialize_genesis_state(
        database, expected_admin_sid=ADMIN_SID, expected_fence_row=fence,
        acceptance_id=accepted["acceptance_id"], deployment_attestation=attestation,
        deployment_session_id=session, explicit_initialization=True,
        retained_session=retained_session, expected_acl_sddl="test-acl",
    )
    assert initialized["root_state"] == {
        "format": root_admin.ROOT_STATE_FORMAT, "root_anchor_id": ANCHOR,
        "active_manifest_id": MANIFEST, "transition": "open", "revision": 1,
    }
    assert initialized["fence_state"] == "FENCED" and initialized["fence_revision"] == 0
    repeated = root_admin.initialize_genesis_state(
        database, expected_admin_sid=ADMIN_SID, expected_fence_row=fence,
        acceptance_id=accepted["acceptance_id"], deployment_attestation=attestation,
        deployment_session_id=session, explicit_initialization=True,
        retained_session=retained_session, expected_acl_sddl="test-acl",
    )
    assert repeated["result"] == "ALREADY_INITIALIZED_EXACT"
    assert repeated["initialization_record"] == initialized["initialization_record"]
    connection = sqlite3.connect(database)
    try:
        assert connection.execute("SELECT transition, revision FROM root_state").fetchall() == [("open", 1)]
        assert connection.execute("SELECT state, revision FROM capability_fence").fetchall() == [("FENCED", 0)]
        assert connection.execute("SELECT COUNT(*) FROM genesis_root_initialization").fetchone()[0] == 1
    finally:
        connection.close()


def test_external_root_admin_release_is_atomic_and_exactly_reconciled_read_only(tmp_path, monkeypatch):
    database = tmp_path / "release-fixture.sqlite3"
    fence = _root_fixture(database)
    _authorize_temp_root_mutation(monkeypatch)
    session = "f" * 64
    attestation = _fixture_attestation(fence, session)
    retained_session = _test_retained_session(attestation)
    accepted = root_admin.append_acceptance(
        database, expected_admin_sid=ADMIN_SID, approver_account=r"ray\zhang",
        acceptance_profile_id=_TEST_ACCEPTANCE_ID, expected_fence_row=fence,
        deployment_attestation=attestation, deployment_session_id=session,
        retained_session=retained_session, explicit_acceptance=True, expected_acl_sddl="test-acl",
    )
    initialized = root_admin.initialize_genesis_state(
        database, expected_admin_sid=ADMIN_SID, expected_fence_row=fence,
        acceptance_id=accepted["acceptance_id"], deployment_attestation=attestation,
        deployment_session_id=session, explicit_initialization=True,
        retained_session=retained_session, expected_acl_sddl="test-acl",
    )
    observation = _fixture_live_observation(attestation)
    release_args = dict(
        expected_admin_sid=ADMIN_SID, expected_fence_row=fence,
        acceptance_id=accepted["acceptance_id"],
        initialization_record_id=initialized["initialization_record"]["record_id"],
        deployment_attestation=attestation, deployment_session_id=session,
        explicit_release=True, retained_session=retained_session,
        expected_acl_sddl="test-acl",
    )
    stale_observation = json.loads(json.dumps(observation))
    stale_observation["process_instance_identities"]["T"] = "0" * 64
    with pytest.raises(ValueError, match="fresh live deployment observation"):
        root_admin.release_capability_fence(
            database, live_observation=stale_observation, **release_args,
        )
    connection = sqlite3.connect(database)
    try:
        assert connection.execute("SELECT state,revision FROM capability_fence").fetchall() == [("FENCED", 0)]
        assert connection.execute("SELECT COUNT(*) FROM genesis_release_verification").fetchone()[0] == 0
    finally:
        connection.close()
    released = root_admin.release_capability_fence(
        database, live_observation=observation, **release_args,
    )
    assert released["result"] == "RELEASED"
    assert released["fence_state"] == "RELEASED" and released["fence_revision"] == 1
    record = released["release_verification"]
    assert record["preimage"]["initialization_record_id"] == initialized["initialization_record"]["record_id"]
    assert record["preimage"]["release_operation_id"] == root_admin.release_operation_id(
        initialization_record_id=initialized["initialization_record"]["record_id"],
        acceptance_id=accepted["acceptance_id"], deployment_attestation_id=attestation["record_id"],
        deployment_session_id=session, root_state_identity=hashlib.sha256(
            b"autodev.g9-root-state-identity/v1\0" + canonical_json_bytes(initialized["root_state"])
        ).hexdigest(), fence_row=fence,
    )
    reconciled = root_admin.release_capability_fence(
        database, live_observation=observation, **release_args,
    )
    assert reconciled == {
        "result": "ALREADY_RELEASED_EXACT", "fence_state": "RELEASED", "fence_revision": 1,
        "release_verification": record,
    }
    connection = sqlite3.connect(database)
    try:
        assert connection.execute("SELECT state,revision FROM capability_fence").fetchall() == [("RELEASED", 1)]
        assert connection.execute("SELECT COUNT(*) FROM genesis_release_verification").fetchone()[0] == 1
        for table in ("genesis_acceptance", "genesis_root_initialization", "genesis_release_verification"):
            columns = [row[1] for row in connection.execute(f"PRAGMA table_info({table})")]
            stored_rows = connection.execute(f"SELECT * FROM {table}").fetchall()
            assert len(stored_rows) == 1
            placeholders = ",".join("?" for _ in columns)
            column_sql = ",".join(columns)
            with pytest.raises(sqlite3.IntegrityError):
                connection.execute(f"UPDATE {table} SET {columns[0]}={columns[0]}")
            with pytest.raises(sqlite3.IntegrityError):
                connection.execute(f"DELETE FROM {table}")
            with pytest.raises(sqlite3.IntegrityError):
                connection.execute(
                    f"INSERT OR REPLACE INTO {table}({column_sql}) VALUES({placeholders})",
                    stored_rows[0],
                )
    finally:
        connection.close()


def test_generic_external_fence_cas_surface_is_removed():
    assert not hasattr(fence_controller, "set_fence")
    assert callable(fence_controller.release_first_genesis)


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
        runtime_run_id = "f" * 64
        t_state_key = b"t" * 32
        for role in ("C", "T", "P", "M"):
            adapter = RoleSubstrateAdapter(
                role=role, address=service.address, key=keys[role],
                candidate_package_id=PACKAGE,
            )
            assert adapter.verify_resource("runtime", hashlib.sha256(resource).hexdigest())
            if role == "C":
                state_bootstrap = {"role": "C", "t_key_hex": t_state_key.hex()}
            else:
                canonical = observations["C"]["canonical_state"]
                state_bootstrap = {"role": role, "projection": canonical["projection"]}
                if role == "T":
                    state_bootstrap.update(endpoint=canonical["channel_endpoint"],
                                           t_key_hex=t_state_key.hex())
            prepared = construct_candidate_runtime(
                role=role, candidate_package_id=PACKAGE, substrate_adapter=adapter,
                runtime_run_id=runtime_run_id,
                canonical_state_bootstrap=state_bootstrap,
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
        assert observations["C"]["canonical_state"]["direct_backend_object"] is True
        for role in ("T", "P", "M"):
            assert observations[role]["canonical_state"]["direct_backend_object"] is False
            assert observations[role]["canonical_state"]["projection"] == observations["C"]["canonical_state"]["projection"]
        assert observations["T"]["canonical_state"]["authenticated_t_to_c_client"] is True
    finally:
        from role_adapter import close_canonical_state_owner
        close_canonical_state_owner("f" * 64)
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
    manifest_id = "3" * 64
    fence = _test_fence_row(manifest_id=manifest_id, runtime_sha256="d" * 64)
    projection = {
        "format": "autodev.g9-canonical-state-channel/v1", "owner_role": "C",
        "owner_process_id": 1002, "owner_instance_id": "c" * 64,
        "backend_generation": 1,
        "state_record_counts": {name: 0 for name in (
            "contracts", "authorizations", "tasks", "candidates", "candidate_materializations",
            "operations", "memberships", "attempts", "evidence", "histories", "supersessions")},
        "resolved_target_registration_ids": [],
    }
    projection["projection_digest"] = hashlib.sha256(
        b"autodev.g9-canonical-state-projection/v1\0"
        + __import__("external_profiles").canonical_json_bytes(projection)
    ).hexdigest()
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
            "canonical_state": {
                "role": role, "backend_owner_role": "C", "backend_owner_instance_id": "c" * 64,
                "projection_digest": projection["projection_digest"], "backend_generation": 1,
                "projection": projection, "direct_backend_object": role == "C",
                "authenticated_t_to_c_client": role == "T", "read_only_projection": role != "C",
                **({"channel_endpoint": ["127.0.0.1", 54321]} if role == "C" else {}),
                **({"channel_identity": "d" * 64} if role == "T" else {}),
            },
        }
    return {
        "format": "autodev.genesis-deployment-readiness/v1",
        "deployment_session_id": "9" * 64,
        "candidate_package_id": PACKAGE,
        "genesis_manifest_id": manifest_id,
        "deterministic_evidence_ids": ["D-001", "D-002"],
        "repository_source_commit": "4" * 40,
        "runtime_artifact_sha256": "d" * 64,
        "python_runtime": {"identity": "CPython", "version": "3.13.14",
                           "path": r"C:\AutodevG9\shared\python313\python.exe", "sha256": "5" * 64},
        "execution_isolation_dependency_id": _TEST_ISOLATION_DEPENDENCY,
        "execution_isolation_profile_sha256": hashlib.sha256(
            canonical_json_bytes(_TEST_ISOLATION_PROFILE)).hexdigest(),
        "root_fence_dependency_id": _TEST_DEPENDENCIES[0],
        "root_fence_profile_sha256": hashlib.sha256(canonical_json_bytes(_TEST_ROOT_PROFILE)).hexdigest(),
        "fixture_substrate_dependency_id": _TEST_DEPENDENCIES[1],
        "fixture_substrate_profile_sha256": hashlib.sha256(
            canonical_json_bytes(_TEST_SUBSTRATE_PROFILE)).hexdigest(),
        "root_anchor_id": ANCHOR,
        "root_state_observation": {
            "status": "UNINITIALIZED", "root_anchor_id": ANCHOR,
            "candidate_package_id": PACKAGE, "manifest_id": manifest_id, "root_state_row_count": 0,
            "capability_fence_row_count": 1, "fence_id": fence["fence_id"],
            "fence_state": "FENCED", "fence_revision": 0, "capability_fence": fence,
            "acceptance_history_count": 0, "initialization_record_count": 0,
            "acceptance_history_digest": hashlib.sha256(
                b"autodev.genesis-acceptance-history/v1\0[]"
            ).hexdigest(),
            "applicable_acceptance_for_this_deployment_session": None,
            "deployment_session_id": "9" * 64,
            "release_verification_count": 0, "schema_sha256": root_admin.ROOT_STORE_SCHEMA_SHA256,
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
        "host_profile_id": derive_host_profile_id(
            root_fence_profile_sha256=hashlib.sha256(canonical_json_bytes(_TEST_ROOT_PROFILE)).hexdigest(),
            fixture_substrate_profile_sha256=hashlib.sha256(
                canonical_json_bytes(_TEST_SUBSTRATE_PROFILE)).hexdigest(),
            execution_isolation_profile_sha256=hashlib.sha256(
                canonical_json_bytes(_TEST_ISOLATION_PROFILE)).hexdigest(),
        ),
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
            "canonical_state": _readiness_preimage()["roles"]["T"]["canonical_state"],
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
        "canonical_state": _readiness_preimage()["roles"]["T"]["canonical_state"],
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
    lambda p: p.update(execution_isolation_profile_sha256="0" * 64),
    lambda p: p.update(host_profile_id="0" * 64),
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
