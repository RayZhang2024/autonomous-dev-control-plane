"""Small external-TCB adapter executed once under one dedicated Windows role."""

from __future__ import annotations

import hashlib
import importlib
import json
import os
from pathlib import Path
import sys
from enum import Enum

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ipc import decode_message, encode_ack

_ENTRY = {
    "T": "TrustedControllerRuntime",
    "C": "ControlStateGateRuntime",
    "P": "PublicationGateRuntime",
    "M": "MergeGateRuntime",
}


class _StartupStage(str, Enum):
    BOOTSTRAP_VALIDATION = "BOOTSTRAP_VALIDATION"
    RUNTIME_ARTIFACT_READ = "RUNTIME_ARTIFACT_READ"
    PYTHON_IDENTITY_READ = "PYTHON_IDENTITY_READ"
    RUNTIME_IMPORT = "RUNTIME_IMPORT"
    ADAPTER_IMPORT = "ADAPTER_IMPORT"
    SUBSTRATE_SETUP = "SUBSTRATE_SETUP"
    SUBSTRATE_RESOURCE_VERIFY = "SUBSTRATE_RESOURCE_VERIFY"
    SUBSTRATE_CONNECT = "SUBSTRATE_CONNECT"
    SUBSTRATE_SEND = "SUBSTRATE_SEND"
    SUBSTRATE_RECEIVE = "SUBSTRATE_RECEIVE"
    RUNTIME_CONSTRUCTION = "RUNTIME_CONSTRUCTION"
    CHANNEL_SETUP = "CHANNEL_SETUP"
    ACCESS_PROBE = "ACCESS_PROBE"
    REPORT_BUILD = "REPORT_BUILD"
    REPORT_WRITE = "REPORT_WRITE"


_TRANSPORT_STARTUP_STAGES = {
    "CONNECT": _StartupStage.SUBSTRATE_CONNECT,
    "SEND": _StartupStage.SUBSTRATE_SEND,
    "RECEIVE": _StartupStage.SUBSTRATE_RECEIVE,
}
_GITHUB_CREDENTIAL_KEY_MARKERS = (
    "TOKEN", "PAT", "SECRET", "PASSWORD", "PRIVATE_KEY", "CREDENTIAL", "ACCESS_KEY",
)


def _github_mutation_credential_names(environment: object) -> tuple[str, ...]:
    if not hasattr(environment, "items"):
        raise TypeError("environment mapping is required")
    found = []
    for name, value in environment.items():
        if type(name) is not str or type(value) is not str:
            raise TypeError("environment names and values must be strings")
        upper_name = name.upper()
        github_name = upper_name.startswith(("GH_", "GITHUB_"))
        credential_name = any(marker in upper_name for marker in _GITHUB_CREDENTIAL_KEY_MARKERS)
        if github_name and credential_name and value:
            found.append(name)
    return tuple(sorted(found, key=str.casefold))


def _startup_failure_evidence(
        exc: Exception, stage: _StartupStage,
        transport_error_type: type[BaseException] | None) -> dict[str, object]:
    if transport_error_type is not None and type(exc) is transport_error_type:
        phase = getattr(exc, "phase", None)
        mapped_stage = _TRANSPORT_STARTUP_STAGES.get(phase) if type(phase) is str else None
        if mapped_stage is not None:
            if phase == "CONNECT":
                failure_class = getattr(exc, "failure_class", None)
                if type(failure_class) is str:
                    return {"startup_failure": {
                        "type": "SubstrateTransportError", "stage": mapped_stage.value,
                        "class": failure_class,
                        "os_code": getattr(exc, "os_code", None),
                    }}
            return {"startup_failure": {
                "type": "SubstrateTransportError", "stage": mapped_stage.value,
            }}
        # Defensive closed fallback: never render the phase or exception details.
        return {"startup_failure": {
            "type": "SubstrateTransportError", "stage": stage.value,
        }}
    return {"startup_failure": {"type": type(exc).__name__, "stage": stage.value}}


def _json_line() -> dict[str, object]:
    line = sys.stdin.buffer.readline(64 * 1024 + 1)
    if not line or len(line) > 64 * 1024 or not line.endswith(b"\n"):
        raise ValueError("invalid bounded control frame")
    value = json.loads(line)
    if type(value) is not dict:
        raise ValueError("control frame must be an object")
    return value


def _write(value: dict[str, object]) -> None:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")
    if len(raw) > 64 * 1024:
        raise ValueError("worker response exceeds bound")
    sys.stdout.buffer.write(raw + b"\n")
    sys.stdout.buffer.flush()


def _fresh_protected_effect_probe(role: str, substrate: object,
                                  candidate_package_id: str) -> dict[str, object]:
    """Repeat only P/M's already-bound read/fenced-prepare denial observations."""
    if role == "P":
        fence = substrate.read_publication_fence()
        response = substrate.prepare_publication("root-release-readiness-probe", b"")
    elif role == "M":
        fence = substrate.read_merge_fence()
        response = substrate.prepare_merge("root-release-readiness-probe", b"")
    else:
        raise ValueError("protected-effect probe is limited to P/M")
    expected_fence = {"fence": "FENCED", "revision": 0,
                      "candidate_package_id": candidate_package_id}
    expected_response = {"accepted": False, "reason": "TARGET_FENCED",
                         "candidate_package_id": candidate_package_id}
    if fence != expected_fence or response != expected_response:
        raise PermissionError("protected target is not in the exact frozen denied state")
    return {"control_probe": "PROTECTED_EFFECT", "role": role,
            "fence": fence["fence"], "revision": fence["revision"],
            "protected_effect_accepted": False,
            "candidate_package_id": candidate_package_id}


def _fence_release_probe(role: str) -> dict[str, object]:
    if role not in _ENTRY:
        raise ValueError("fence-release probe role is unsupported")
    return {"control_probe": "FENCE_RELEASE", "role": role,
            "accepted": False, "reason": "NO_RELEASE_CAPABILITY"}


def _probe_access(role: str, shared_runtime: Path, private: dict[str, Path],
                  root_probe: Path) -> dict[str, object]:
    own = private[role] / f"probe-{os.getpid()}-{role}.tmp"
    own.write_bytes(b"G9-ROLE-ACL-PROBE\n")
    own_result = own.read_bytes() == b"G9-ROLE-ACL-PROBE\n"
    own.unlink()

    try:
        shared_fd = os.open(shared_runtime, os.O_WRONLY | os.O_APPEND)
    except OSError:
        shared_write_denied = True
    else:
        os.close(shared_fd)
        shared_write_denied = False

    private_denials: dict[str, bool] = {}
    for other, directory in private.items():
        if other == role:
            continue
        path = directory / f"cross-probe-{os.getpid()}-{role}.tmp"
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except OSError:
            private_denials[other] = True
        else:
            os.close(fd)
            try:
                path.unlink()
            except OSError:
                pass
            private_denials[other] = False

    root_path = root_probe / f"unauthorized-{os.getpid()}-{role}.tmp"
    try:
        fd = os.open(root_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError:
        root_write_denied = True
    else:
        os.close(fd)
        try:
            root_path.unlink()
        except OSError:
            pass
        root_write_denied = False
    return {
        "own_private_write": own_result,
        "shared_runtime_write_denied": shared_write_denied,
        "other_private_write_denied": private_denials,
        "root_store_write_denied": root_write_denied,
    }


def main() -> int:
    stage = _StartupStage.BOOTSTRAP_VALIDATION
    transport_error_type: type[BaseException] | None = None
    try:
        if _github_mutation_credential_names(os.environ):
            raise RuntimeError("role profile environment contains GitHub mutation credentials")
        bootstrap = _json_line()
        role = bootstrap.get("role")
        fields = {"role", "runtime_zip", "runtime_sha256", "candidate_package_id",
                  "runtime_generation", "endpoint_identity", "private_directory",
                  "private_directories", "security_context_identity", "entrypoint_identity",
                  "shared_directory", "root_store_probe", "substrate_endpoint",
                  "substrate_channel_key_hex", "substrate_resource_id",
                  "substrate_resource_sha256", "runtime_run_id", "canonical_state_bootstrap"}
        if role in ("C", "P", "M"):
            fields.add("channel_key_hex")
        if type(role) is not str or role not in _ENTRY or set(bootstrap) != fields:
            raise ValueError("invalid closed role bootstrap")
        runtime_zip = Path(bootstrap["runtime_zip"])
        shared_directory = Path(bootstrap["shared_directory"])
        private_directory = Path(bootstrap["private_directory"])
        private_directories = {key: Path(value) for key, value in bootstrap["private_directories"].items()}
        if (set(private_directories) != set(_ENTRY) or private_directory != private_directories[role]
                or Path.cwd() != private_directory):
            raise ValueError("role-private directory binding mismatch")

        stage = _StartupStage.RUNTIME_ARTIFACT_READ
        runtime_bytes = runtime_zip.read_bytes()
        runtime_digest = hashlib.sha256(runtime_bytes).hexdigest()

        stage = _StartupStage.PYTHON_IDENTITY_READ
        executable = Path(sys.executable).resolve()
        executable_digest = hashlib.sha256(executable.read_bytes()).hexdigest()
        if runtime_digest != bootstrap["runtime_sha256"]:
            raise ValueError("candidate runtime digest mismatch")
        if not str(executable).lower().endswith("\\python.exe"):
            raise ValueError("unexpected Python executable")

        stage = _StartupStage.RUNTIME_IMPORT
        sys.path.insert(0, str(runtime_zip))
        entry_module = importlib.import_module("autodev_control.trusted.runtime_roles")
        if not callable(getattr(entry_module, _ENTRY[role], None)):
            raise ValueError("candidate role entry point missing")

        stage = _StartupStage.ADAPTER_IMPORT
        from role_adapter import (
            RoleSubstrateAdapter, SubstrateTransportError, construct_candidate_runtime,
            close_canonical_state_owner,
        )
        transport_error_type = SubstrateTransportError

        stage = _StartupStage.SUBSTRATE_SETUP
        endpoint_value = bootstrap["substrate_endpoint"]
        if (type(endpoint_value) is not list or len(endpoint_value) != 2
                or endpoint_value[0] != "127.0.0.1" or type(endpoint_value[1]) is not int
                or not 1 <= endpoint_value[1] <= 65535):
            raise ValueError("external substrate endpoint is not exact loopback")
        substrate_key_hex = bootstrap["substrate_channel_key_hex"]
        if (type(substrate_key_hex) is not str or len(substrate_key_hex) != 64
                or any(char not in "0123456789abcdef" for char in substrate_key_hex)):
            raise ValueError("role substrate key is malformed")
        substrate = RoleSubstrateAdapter(
            role=role, address=(endpoint_value[0], endpoint_value[1]),
            key=bytes.fromhex(substrate_key_hex),
            candidate_package_id=bootstrap["candidate_package_id"],
        )

        stage = _StartupStage.SUBSTRATE_RESOURCE_VERIFY
        if not substrate.verify_resource(
                bootstrap["substrate_resource_id"], bootstrap["substrate_resource_sha256"]):
            raise ValueError("external substrate did not verify the CP-bound resource")

        stage = _StartupStage.RUNTIME_CONSTRUCTION
        runtime_preparation = construct_candidate_runtime(
            role=role, candidate_package_id=bootstrap["candidate_package_id"],
            substrate_adapter=substrate, runtime_run_id=bootstrap["runtime_run_id"],
            canonical_state_bootstrap=bootstrap["canonical_state_bootstrap"],
        )

        stage = _StartupStage.CHANNEL_SETUP
        key = None
        if role in ("C", "P", "M"):
            key = bytes.fromhex(bootstrap["channel_key_hex"])
            if len(key) != 32:
                raise ValueError("role channel key is not 256-bit")
        if "channel_key_hex" in bootstrap and role == "T":
            raise ValueError("controller must not receive destination channel credentials")

        stage = _StartupStage.ACCESS_PROBE
        access = _probe_access(role, shared_directory / "runtime.zip",
                               private_directories, Path(bootstrap["root_store_probe"]))

        stage = _StartupStage.REPORT_BUILD
        report = {
            "role": role,
            "pid": os.getpid(),
            "ppid": os.getppid(),
            "python_executable": str(executable),
            "python_sha256": executable_digest,
            "runtime_sha256": runtime_digest,
            "candidate_package_id": bootstrap["candidate_package_id"],
            "runtime_generation": bootstrap["runtime_generation"],
            "endpoint_identity": bootstrap["endpoint_identity"],
            "private_directory": str(private_directory),
            "security_context_identity": bootstrap["security_context_identity"],
            "entrypoint_identity": bootstrap["entrypoint_identity"],
            "runtime_preparation": runtime_preparation,
            "access": access,
            "destination_channel_credentials": "NONE" if role == "T" else "ROLE_LOCAL_ONLY",
            "production_github_mutation_credentials": "NONE",
        }
        stage = _StartupStage.REPORT_WRITE
        _write(report)

        while True:
            line = sys.stdin.buffer.readline(64 * 1024 + 1)
            if not line or len(line) > 64 * 1024:
                close_canonical_state_owner(bootstrap["runtime_run_id"])
                return 0
            if line == b'{"control":"FENCE_RELEASE_PROBE"}\n':
                _write(_fence_release_probe(role))
                continue
            if role == "T":
                if line == b'{"control":"STOP"}\n':
                    close_canonical_state_owner(bootstrap["runtime_run_id"])
                    return 0
                if line == b'{"control":"PROTECTED_EFFECT_PROBE"}\n':
                    _write({"accepted": False, "reason": "PROBE_NOT_APPLICABLE", "role": "T"})
                    continue
                if line == b'{"control":"ROOT_ACCESS_PROBE"}\n':
                    access = _probe_access(role, shared_directory / "runtime.zip",
                                           private_directories, Path(bootstrap["root_store_probe"]))
                    _write({"role": role, "access": access})
                    continue
                _write({"accepted": False, "reason": "NO_DESTINATION_CHANNEL_CREDENTIALS"})
                continue
            if line == b'{"control":"STOP"}\n':
                close_canonical_state_owner(bootstrap["runtime_run_id"])
                return 0
            if line == b'{"control":"PROTECTED_EFFECT_PROBE"}\n':
                if role not in ("P", "M"):
                    _write({"accepted": False, "reason": "PROBE_NOT_APPLICABLE", "role": role})
                else:
                    _write(_fresh_protected_effect_probe(
                        role, substrate, bootstrap["candidate_package_id"],
                    ))
                continue
            if line == b'{"control":"ROOT_ACCESS_PROBE"}\n':
                access = _probe_access(role, shared_directory / "runtime.zip",
                                       private_directories, Path(bootstrap["root_store_probe"]))
                _write({"role": role, "access": access})
                continue
            try:
                decoded = decode_message(line.rstrip(b"\r\n"), expected_role=role, key=key)
                acknowledgment = encode_ack(
                    role=role, request_id=decoded["request_id"],
                    nonce=decoded["payload"]["nonce"], key=key,
                )
                _write({"accepted": True, "ack": acknowledgment.decode("ascii")})
            except (TypeError, ValueError, KeyError):
                _write({"accepted": False, "reason": "IPC_REJECTED"})
    except Exception as exc:
        # Never echo bootstrap data or exception details that could carry secrets.
        _write(_startup_failure_evidence(exc, stage, transport_error_type))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
