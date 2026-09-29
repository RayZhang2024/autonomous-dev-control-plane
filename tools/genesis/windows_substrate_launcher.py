"""Launch the external fixture substrate as its dedicated non-admin user.

The account password and channel keys travel only through the native logon
buffer and an inherited anonymous pipe, respectively. Neither is put in argv,
environment variables, files, or output.
"""

from __future__ import annotations

import ctypes
import getpass
import hashlib
import json
import msvcrt
import os
from pathlib import Path
import socket
import subprocess
import sys
from typing import Mapping
from ctypes import wintypes

sys.path.insert(0, str(Path(__file__).resolve().parent))
from windows_role_launcher import (
    _CREATE_UNICODE_ENVIRONMENT, _HANDLE_FLAG_INHERIT, _LOGON_WITH_PROFILE,
    _STARTF_USESTDHANDLES, _NativeTokenApi, _ProcessInformation, _SecurityAttributes,
    _StartupInfo, _TOKEN_PRIMARY, _primary_token_evidence,
    process_creation_time_100ns,
)


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def _probe_ready_endpoint(endpoint: tuple[str, int]) -> None:
    """Check only launcher-side TCP reachability; this grants no role authority."""
    try:
        with socket.create_connection(endpoint, timeout=2):
            pass
    except OSError:
        raise RuntimeError("SUBSTRATE_LAUNCHER_REACHABILITY_FAIL") from None


def _validate_and_probe_readiness(
    startup: object, *, process_id: int, candidate_package_id: object,
) -> tuple[str, int]:
    if (type(startup) is not dict or set(startup) != {
            "format", "pid", "endpoint", "candidate_package_id", "endpoint_identity"}
            or startup["format"] != "autodev.g9-fixture-substrate-ready/v1"
            or startup["pid"] != process_id
            or startup["candidate_package_id"] != candidate_package_id
            or type(startup["endpoint"]) is not list or len(startup["endpoint"]) != 2
            or startup["endpoint"][0] != "127.0.0.1"
            or type(startup["endpoint"][1]) is not int
            or not 1 <= startup["endpoint"][1] <= 65535
            or type(startup["endpoint_identity"]) is not str
            or len(startup["endpoint_identity"]) != 64
            or any(char not in "0123456789abcdef" for char in startup["endpoint_identity"])):
        raise RuntimeError("substrate service readiness does not bind exact process and endpoint")
    expected_endpoint_identity = hashlib.sha256(_canonical_bytes((
        "autodev.g9-fixture-substrate-endpoint/v1", startup["endpoint"][0],
        startup["endpoint"][1], startup["candidate_package_id"],
    ))).hexdigest()
    if startup["endpoint_identity"] != expected_endpoint_identity:
        raise RuntimeError("substrate service endpoint digest differs from its exact readiness tuple")
    ready_endpoint = (startup["endpoint"][0], startup["endpoint"][1])
    _probe_ready_endpoint(ready_endpoint)
    return ready_endpoint


class SubstrateProcess:
    __slots__ = ("role", "pid", "sid", "token_type", "is_administrator", "creation_time_100ns",
                 "endpoint", "endpoint_identity",
                 "candidate_package_id", "stdin", "stdout", "_kernel", "_process", "_thread")

    def __init__(self, pid: int, sid: str, token_type: int, is_administrator: bool,
                 endpoint: tuple[str, int], endpoint_identity: str, candidate_package_id: str,
                 creation_time_100ns: int, stdin: object, stdout: object, kernel: ctypes.WinDLL,
                 process: int, thread: int) -> None:
        self.role = "S"
        self.pid, self.sid = pid, sid
        self.token_type, self.is_administrator = token_type, is_administrator
        self.creation_time_100ns = creation_time_100ns
        self.endpoint, self.endpoint_identity = endpoint, endpoint_identity
        self.candidate_package_id = candidate_package_id
        self.stdin, self.stdout = stdin, stdout
        self._kernel, self._process, self._thread = kernel, process, thread

    def is_live(self) -> bool:
        self._kernel.GetProcessId.argtypes = [wintypes.HANDLE]
        self._kernel.GetProcessId.restype = wintypes.DWORD
        if (self._kernel.GetProcessId(self._process) != self.pid
                or self._kernel.WaitForSingleObject(self._process, 0) != 258
                or process_creation_time_100ns(self._process, self._kernel) != self.creation_time_100ns):
            return False
        evidence = _primary_token_evidence(self._process)
        return (evidence.user_sid == self.sid and evidence.token_type == self.token_type
                and evidence.is_administrator is self.is_administrator)

    @property
    def process_handle(self) -> int:
        return self._process

    def stop(self) -> int:
        if not self.stdin.closed:
            self.stdin.write(b'{"control":"STOP"}\n')
            self.stdin.flush()
            self.stdin.close()
        self.stdout.close()
        result = self._kernel.WaitForSingleObject(self._process, 10000)
        if result != 0:
            self._kernel.TerminateProcess(self._process, 123)
            self._kernel.WaitForSingleObject(self._process, 5000)
            raise TimeoutError("external fixture substrate did not stop within its bound")
        code = wintypes.DWORD()
        if not self._kernel.GetExitCodeProcess(self._process, ctypes.byref(code)):
            raise ctypes.WinError(ctypes.get_last_error())
        return code.value

    def close(self) -> None:
        for stream in (self.stdin, self.stdout):
            try:
                stream.close()
            except Exception:
                pass
        self._kernel.CloseHandle(self._thread)
        self._kernel.CloseHandle(self._process)


def launch_substrate(
    *, account: str, expected_sid: str, python_executable: Path,
    service_script: Path, bootstrap: Mapping[str, object],
) -> SubstrateProcess:
    """Start one external service under the exact profile-bound user token."""
    if sys.platform != "win32" or "\\" not in account or not expected_sid.startswith("S-1-"):
        raise RuntimeError("a Windows domain/local substrate identity is required")
    if type(bootstrap) not in (dict,):
        raise TypeError("exact closed service bootstrap mapping required")
    raw = json.dumps(dict(bootstrap), ensure_ascii=True, sort_keys=True,
                     separators=(",", ":"), allow_nan=False).encode("ascii") + b"\n"
    if len(raw) > 64 * 1024:
        raise ValueError("service bootstrap exceeds the bound")
    domain, username = account.split("\\", 1)
    password = getpass.getpass(f"Password for {account} (input hidden): ")
    if not password:
        raise ValueError("empty substrate credential is refused")
    password_buffer = ctypes.create_unicode_buffer(password)
    del password
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    pipes: list[int] = []
    child_stdin_read = parent_stdin_write = parent_stdout_read = child_stdout_write = 0
    process_info = _ProcessInformation()

    def create_pipe() -> tuple[int, int]:
        read_handle, write_handle = wintypes.HANDLE(), wintypes.HANDLE()
        attributes = _SecurityAttributes(ctypes.sizeof(_SecurityAttributes), None, True)
        create = kernel.CreatePipe
        create.argtypes = [ctypes.POINTER(wintypes.HANDLE), ctypes.POINTER(wintypes.HANDLE),
                           ctypes.POINTER(_SecurityAttributes), wintypes.DWORD]
        create.restype = wintypes.BOOL
        if not create(ctypes.byref(read_handle), ctypes.byref(write_handle), ctypes.byref(attributes), 0):
            raise ctypes.WinError(ctypes.get_last_error())
        pipes.extend((read_handle.value, write_handle.value))
        return read_handle.value, write_handle.value

    try:
        child_stdin_read, parent_stdin_write = create_pipe()
        parent_stdout_read, child_stdout_write = create_pipe()
        set_info = kernel.SetHandleInformation
        set_info.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD]
        set_info.restype = wintypes.BOOL
        for handle in (parent_stdin_write, parent_stdout_read):
            if not set_info(handle, _HANDLE_FLAG_INHERIT, 0):
                raise ctypes.WinError(ctypes.get_last_error())
        startup = _StartupInfo()
        startup.cb = ctypes.sizeof(_StartupInfo)
        startup.dwFlags = _STARTF_USESTDHANDLES
        startup.hStdInput = child_stdin_read
        startup.hStdOutput = child_stdout_write
        startup.hStdError = child_stdout_write
        command = subprocess.list2cmdline([
            str(python_executable), "-I", "-S", "-B", str(service_script), "--service",
        ])
        command_buffer = ctypes.create_unicode_buffer(command)
        environment_text = "\0".join((
            f"SystemRoot={os.environ.get('SystemRoot', r'C:\Windows')}",
            f"PATH={python_executable.parent};{os.environ.get('SystemRoot', r'C:\Windows')}\\System32",
        )) + "\0\0"
        environment_buffer = ctypes.create_unicode_buffer(environment_text)
        create = advapi.CreateProcessWithLogonW
        create.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD,
                           wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD, wintypes.LPVOID,
                           wintypes.LPCWSTR, ctypes.POINTER(_StartupInfo),
                           ctypes.POINTER(_ProcessInformation)]
        create.restype = wintypes.BOOL
        if not create(username, domain, password_buffer, _LOGON_WITH_PROFILE,
                      str(python_executable), command_buffer, _CREATE_UNICODE_ENVIRONMENT,
                      ctypes.cast(environment_buffer, wintypes.LPVOID), str(service_script.parent),
                      ctypes.byref(startup), ctypes.byref(process_info)):
            raise ctypes.WinError(ctypes.get_last_error())
        ctypes.memset(ctypes.addressof(password_buffer), 0, ctypes.sizeof(password_buffer))
        for handle in (child_stdin_read, child_stdout_write):
            kernel.CloseHandle(handle)
            pipes.remove(handle)
        evidence = _primary_token_evidence(process_info.hProcess)
        if evidence.user_sid != expected_sid or evidence.token_type != _TOKEN_PRIMARY or evidence.is_administrator:
            kernel.TerminateProcess(process_info.hProcess, 121)
            raise PermissionError("substrate process identity is not the dedicated non-admin principal")
        creation_time = process_creation_time_100ns(int(process_info.hProcess), kernel)
        stdin_fd = msvcrt.open_osfhandle(parent_stdin_write, os.O_WRONLY | os.O_BINARY)
        pipes.remove(parent_stdin_write)
        stdout_fd = msvcrt.open_osfhandle(parent_stdout_read, os.O_RDONLY | os.O_BINARY)
        pipes.remove(parent_stdout_read)
        stdin = os.fdopen(stdin_fd, "wb", buffering=0)
        stdout = os.fdopen(stdout_fd, "rb", buffering=0)
        stdin.write(raw)
        startup_line = stdout.readline(64 * 1024 + 1)
        if (not startup_line or len(startup_line) > 64 * 1024
                or not startup_line.endswith(b"\n")):
            kernel.TerminateProcess(process_info.hProcess, 122)
            raise RuntimeError("substrate service did not emit a bounded readiness response")
        try:
            startup = json.loads(startup_line)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            kernel.TerminateProcess(process_info.hProcess, 122)
            raise RuntimeError("substrate service readiness is malformed") from exc
        try:
            ready_endpoint = _validate_and_probe_readiness(
                startup, process_id=int(process_info.dwProcessId),
                candidate_package_id=bootstrap.get("candidate_package_id"),
            )
        except RuntimeError:
            kernel.TerminateProcess(process_info.hProcess, 122)
            raise
        return SubstrateProcess(int(process_info.dwProcessId), evidence.user_sid,
                                evidence.token_type, evidence.is_administrator,
                                ready_endpoint,
                                startup["endpoint_identity"], startup["candidate_package_id"],
                                creation_time, stdin, stdout, kernel,
                                int(process_info.hProcess), int(process_info.hThread))
    finally:
        if password_buffer is not None:
            ctypes.memset(ctypes.addressof(password_buffer), 0, ctypes.sizeof(password_buffer))
        for handle in pipes:
            kernel.CloseHandle(handle)
