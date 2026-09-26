"""Small external-TCB adapter executed once under one dedicated Windows role."""

from __future__ import annotations

import hashlib
import importlib
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ipc import decode_message, encode_ack

_ENTRY = {
    "T": "TrustedControllerRuntime",
    "C": "ControlStateGateRuntime",
    "P": "PublicationGateRuntime",
    "M": "MergeGateRuntime",
}


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
    try:
        bootstrap = _json_line()
        role = bootstrap.get("role")
        fields = {"role", "runtime_zip", "runtime_sha256", "candidate_package_id",
                  "runtime_generation", "endpoint_identity", "private_directory",
                  "private_directories", "security_context_identity", "entrypoint_identity",
                  "shared_directory", "root_store_probe"}
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
        runtime_digest = hashlib.sha256(runtime_zip.read_bytes()).hexdigest()
        executable = Path(sys.executable).resolve()
        executable_digest = hashlib.sha256(executable.read_bytes()).hexdigest()
        if runtime_digest != bootstrap["runtime_sha256"]:
            raise ValueError("candidate runtime digest mismatch")
        if not str(executable).lower().endswith("\\python.exe"):
            raise ValueError("unexpected Python executable")

        sys.path.insert(0, str(runtime_zip))
        entry_module = importlib.import_module("autodev_control.trusted.runtime_roles")
        if not callable(getattr(entry_module, _ENTRY[role], None)):
            raise ValueError("candidate role entry point missing")

        key = None
        if role in ("C", "P", "M"):
            key = bytes.fromhex(bootstrap["channel_key_hex"])
            if len(key) != 32:
                raise ValueError("role channel key is not 256-bit")
        if "channel_key_hex" in bootstrap and role == "T":
            raise ValueError("controller must not receive destination channel credentials")

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
            "access": _probe_access(role, shared_directory / "runtime.zip",
                                    private_directories, Path(bootstrap["root_store_probe"])),
            "destination_channel_credentials": "NONE" if role == "T" else "ROLE_LOCAL_ONLY",
        }
        _write(report)

        while True:
            line = sys.stdin.buffer.readline(64 * 1024 + 1)
            if not line or len(line) > 64 * 1024:
                return 0
            if role == "T":
                if line == b'{"control":"STOP"}\n':
                    return 0
                _write({"accepted": False, "reason": "NO_DESTINATION_CHANNEL_CREDENTIALS"})
                continue
            if line == b'{"control":"STOP"}\n':
                return 0
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
        _write({"startup_failure": type(exc).__name__})
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
