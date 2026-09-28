"""External-TCB Windows launcher for the four G9 role principals.

Passwords are read from an interactive no-echo prompt, passed only to the
native logon API, and wiped from the temporary native buffer immediately.
They are never part of argv, the environment, generated resources, or output.
"""

from __future__ import annotations

from dataclasses import dataclass
import getpass
import json
import msvcrt
import os
from pathlib import Path
import subprocess
import sys
from typing import Mapping, Protocol
import ctypes
from ctypes import wintypes

_DOMAIN = "Ray"
ROLE_PRINCIPALS = {
    "T": ("autodev-g9-t", "S-1-5-21-711519901-190585334-3846127459-1016"),
    "C": ("autodev-g9-c", "S-1-5-21-711519901-190585334-3846127459-1017"),
    "P": ("autodev-g9-p", "S-1-5-21-711519901-190585334-3846127459-1018"),
    "M": ("autodev-g9-m", "S-1-5-21-711519901-190585334-3846127459-1019"),
}
_LOGON_WITH_PROFILE = 0x00000000
_CREATE_UNICODE_ENVIRONMENT = 0x00000400
_STARTF_USESTDHANDLES = 0x00000100
_HANDLE_FLAG_INHERIT = 0x00000001
_TOKEN_QUERY = 0x0008
_TOKEN_DUPLICATE = 0x0002
_TOKEN_IMPERSONATE = 0x0004
_TOKEN_USER = 1
_TOKEN_TYPE = 8
_TOKEN_PRIMARY = 1
_TOKEN_IMPERSONATION = 2
_SECURITY_IMPERSONATION = 2
_ADMINISTRATORS_SID = "S-1-5-32-544"
_ERROR_INSUFFICIENT_BUFFER = 122


@dataclass(frozen=True, slots=True)
class ChildTokenEvidence:
    user_sid: str
    token_type: int
    is_administrator: bool


class _TokenApi(Protocol):
    def open_process_token(self, process: int, access: int) -> int: ...
    def token_information(self, token: int, info_class: int) -> str | int: ...
    def duplicate_token_ex(self, token: int, access: int, level: int, token_type: int) -> int: ...
    def is_administrator(self, token: int) -> bool: ...
    def close_handle(self, handle: int) -> None: ...


class _SIDAndAttributes(ctypes.Structure):
    _fields_ = [("Sid", wintypes.LPVOID), ("Attributes", wintypes.DWORD)]


class _TokenUser(ctypes.Structure):
    _fields_ = [("User", _SIDAndAttributes)]


class _SecurityAttributes(ctypes.Structure):
    _fields_ = [("nLength", wintypes.DWORD), ("lpSecurityDescriptor", wintypes.LPVOID),
                ("bInheritHandle", wintypes.BOOL)]


class _StartupInfo(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD), ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR), ("lpTitle", wintypes.LPWSTR),
        ("dwX", wintypes.DWORD), ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD), ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD), ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD), ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD), ("cbReserved2", wintypes.WORD),
        ("lpReserved2", wintypes.LPVOID), ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE), ("hStdError", wintypes.HANDLE),
    ]


class _ProcessInformation(ctypes.Structure):
    _fields_ = [("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE),
                ("dwProcessId", wintypes.DWORD), ("dwThreadId", wintypes.DWORD)]


def _api() -> tuple[ctypes.WinDLL, ctypes.WinDLL]:
    if sys.platform != "win32":
        raise RuntimeError("dedicated G9 role principals require Windows")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    kernel.LocalFree.argtypes = [wintypes.HLOCAL]
    kernel.LocalFree.restype = wintypes.HLOCAL
    kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel.WaitForSingleObject.restype = wintypes.DWORD
    kernel.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel.GetExitCodeProcess.restype = wintypes.BOOL
    kernel.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel.TerminateProcess.restype = wintypes.BOOL
    return kernel, ctypes.WinDLL("advapi32", use_last_error=True)


def _sid_string(kernel: ctypes.WinDLL, advapi: ctypes.WinDLL, sid: int) -> str:
    text = wintypes.LPWSTR()
    convert = advapi.ConvertSidToStringSidW
    convert.argtypes = [wintypes.LPVOID, ctypes.POINTER(wintypes.LPWSTR)]
    convert.restype = wintypes.BOOL
    if not convert(sid, ctypes.byref(text)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return text.value
    finally:
        kernel.LocalFree(text)


class _NativeTokenApi:
    """Narrow, explicitly typed Windows token API used for child-process evidence."""

    def __init__(self) -> None:
        self.kernel, self.advapi = _api()
        advapi = self.advapi
        advapi.OpenProcessToken.argtypes = [
            wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE),
        ]
        advapi.OpenProcessToken.restype = wintypes.BOOL
        advapi.GetTokenInformation.argtypes = [
            wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
        ]
        advapi.GetTokenInformation.restype = wintypes.BOOL
        advapi.DuplicateTokenEx.argtypes = [
            wintypes.HANDLE, wintypes.DWORD, wintypes.LPVOID, ctypes.c_int,
            ctypes.c_int, ctypes.POINTER(wintypes.HANDLE),
        ]
        advapi.DuplicateTokenEx.restype = wintypes.BOOL
        advapi.CheckTokenMembership.argtypes = [
            wintypes.HANDLE, wintypes.LPVOID, ctypes.POINTER(wintypes.BOOL),
        ]
        advapi.CheckTokenMembership.restype = wintypes.BOOL
        advapi.ConvertStringSidToSidW.argtypes = [
            wintypes.LPCWSTR, ctypes.POINTER(wintypes.LPVOID),
        ]
        advapi.ConvertStringSidToSidW.restype = wintypes.BOOL

    def open_process_token(self, process: int, access: int) -> int:
        token = wintypes.HANDLE()
        if not self.advapi.OpenProcessToken(process, access, ctypes.byref(token)):
            raise ctypes.WinError(ctypes.get_last_error())
        return int(token.value)

    def token_information(self, token: int, info_class: int) -> str | int:
        needed = wintypes.DWORD()
        if self.advapi.GetTokenInformation(token, info_class, None, 0, ctypes.byref(needed)):
            raise RuntimeError("GetTokenInformation unexpectedly succeeded without a buffer")
        error = ctypes.get_last_error()
        if error != _ERROR_INSUFFICIENT_BUFFER or needed.value == 0:
            raise ctypes.WinError(error)
        buffer = ctypes.create_string_buffer(needed.value)
        if not self.advapi.GetTokenInformation(
                token, info_class, buffer, needed.value, ctypes.byref(needed)):
            raise ctypes.WinError(ctypes.get_last_error())
        if info_class == _TOKEN_USER:
            user = ctypes.cast(buffer, ctypes.POINTER(_TokenUser)).contents
            return _sid_string(self.kernel, self.advapi, user.User.Sid)
        if info_class == _TOKEN_TYPE:
            if needed.value != ctypes.sizeof(wintypes.DWORD):
                raise RuntimeError("TokenType returned an unexpected byte size")
            return ctypes.cast(buffer, ctypes.POINTER(wintypes.DWORD)).contents.value
        raise ValueError("unsupported token information class")

    def duplicate_token_ex(self, token: int, access: int, level: int, token_type: int) -> int:
        duplicate = wintypes.HANDLE()
        if not self.advapi.DuplicateTokenEx(
                token, access, None, level, token_type, ctypes.byref(duplicate)):
            raise ctypes.WinError(ctypes.get_last_error())
        return int(duplicate.value)

    def is_administrator(self, token: int) -> bool:
        admin_sid = wintypes.LPVOID()
        if not self.advapi.ConvertStringSidToSidW(
                _ADMINISTRATORS_SID, ctypes.byref(admin_sid)):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            is_member = wintypes.BOOL()
            if not self.advapi.CheckTokenMembership(token, admin_sid, ctypes.byref(is_member)):
                raise ctypes.WinError(ctypes.get_last_error())
            return bool(is_member.value)
        finally:
            self.kernel.LocalFree(admin_sid)

    def close_handle(self, handle: int) -> None:
        if not self.kernel.CloseHandle(handle):
            raise ctypes.WinError(ctypes.get_last_error())


def _primary_token_evidence(process: int, api: _TokenApi | None = None) -> ChildTokenEvidence:
    """Read the child's primary token and test admins via an impersonation duplicate."""
    api = _NativeTokenApi() if api is None else api
    primary = api.open_process_token(process, _TOKEN_QUERY | _TOKEN_DUPLICATE)
    duplicate = None
    try:
        sid = api.token_information(primary, _TOKEN_USER)
        token_type = api.token_information(primary, _TOKEN_TYPE)
        if type(sid) is not str or not sid or type(token_type) is not int:
            raise RuntimeError("child primary-token evidence has invalid types")
        if token_type != _TOKEN_PRIMARY:
            raise RuntimeError("child process token is not TokenPrimary")
        duplicate = api.duplicate_token_ex(
            primary, _TOKEN_QUERY | _TOKEN_IMPERSONATE,
            _SECURITY_IMPERSONATION, _TOKEN_IMPERSONATION,
        )
        is_admin = api.is_administrator(duplicate)
        return ChildTokenEvidence(sid, token_type, is_admin)
    finally:
        if duplicate is not None:
            api.close_handle(duplicate)
        api.close_handle(primary)


def _validate_role_token(role: str, evidence: ChildTokenEvidence) -> None:
    if type(evidence) is not ChildTokenEvidence:
        raise TypeError("actual child-token evidence is required")
    if evidence.token_type != _TOKEN_PRIMARY:
        raise PermissionError("role process primary-token type mismatch")
    expected_sid = ROLE_PRINCIPALS[role][1]
    if evidence.user_sid != expected_sid:
        raise PermissionError(f"role {role} child SID did not match its frozen principal")
    if evidence.is_administrator:
        raise PermissionError(f"role {role} child token is an administrator")


@dataclass(slots=True)
class WindowsRoleProcess:
    role: str
    pid: int
    sid: str
    token_type: int
    is_administrator: bool
    process_handle: int
    thread_handle: int
    stdin: object
    stdout: object
    stderr: object
    _kernel: ctypes.WinDLL

    def send_json_line(self, value: Mapping[str, object]) -> None:
        raw = json.dumps(value, ensure_ascii=True, allow_nan=False,
                         separators=(",", ":")).encode("ascii") + b"\n"
        self.stdin.write(raw)
        self.stdin.flush()

    def read_json_line(self) -> dict[str, object]:
        line = self.stdout.readline(64 * 1024 + 1)
        if not line or len(line) > 64 * 1024 or not line.endswith(b"\n"):
            raise RuntimeError(f"role {self.role} did not emit one bounded JSON line")
        value = json.loads(line)
        if type(value) is not dict:
            raise RuntimeError(f"role {self.role} emitted a non-object response")
        return value

    def wait(self, timeout_ms: int = 15000) -> int:
        result = self._kernel.WaitForSingleObject(self.process_handle, timeout_ms)
        if result != 0:
            raise TimeoutError(f"role {self.role} did not exit within its bound")
        code = wintypes.DWORD()
        if not self._kernel.GetExitCodeProcess(self.process_handle, ctypes.byref(code)):
            raise ctypes.WinError(ctypes.get_last_error())
        return code.value

    def close(self) -> None:
        for stream in (self.stdin, self.stdout, self.stderr):
            try:
                stream.close()
            except Exception:
                pass
        self._kernel.CloseHandle(self.thread_handle)
        self._kernel.CloseHandle(self.process_handle)


def _profile_environment_arguments(role: str) -> tuple[int, int, None, None]:
    if role not in ROLE_PRINCIPALS:
        raise ValueError("unknown G9 role")
    return _LOGON_WITH_PROFILE, 0, None, None


def launch_role(role: str, *, python_executable: Path, worker_script: Path,
                working_directory: Path) -> WindowsRoleProcess:
    """Launch a role under its dedicated primary token after hidden input.

    Windows creates the target user's environment from its loaded profile.
    Only the standard input/output/error pipes are inherited. The password is
    entered with echo disabled and is never included in process arguments or
    environment variables.
    """
    if role not in ROLE_PRINCIPALS:
        raise ValueError("unknown G9 role")
    logon_flags, creation_flags, environment_buffer, environment_pointer = (
        _profile_environment_arguments(role)
    )
    account, _ = ROLE_PRINCIPALS[role]
    domain, username = _DOMAIN, account
    password = getpass.getpass(f"Password for {domain}\\{username} (input hidden): ")
    if not password:
        raise ValueError("empty local-role credential is refused")
    password_buffer = ctypes.create_unicode_buffer(password)
    del password
    kernel, advapi = _api()
    pipes: list[int] = []

    def pipe() -> tuple[int, int]:
        read_handle, write_handle = wintypes.HANDLE(), wintypes.HANDLE()
        attrs = _SecurityAttributes(ctypes.sizeof(_SecurityAttributes), None, True)
        create = kernel.CreatePipe
        create.argtypes = [ctypes.POINTER(wintypes.HANDLE), ctypes.POINTER(wintypes.HANDLE),
                           ctypes.POINTER(_SecurityAttributes), wintypes.DWORD]
        create.restype = wintypes.BOOL
        if not create(ctypes.byref(read_handle), ctypes.byref(write_handle), ctypes.byref(attrs), 0):
            raise ctypes.WinError(ctypes.get_last_error())
        pipes.extend((read_handle.value, write_handle.value))
        return read_handle.value, write_handle.value

    try:
        child_stdin_read, parent_stdin_write = pipe()
        parent_stdout_read, child_stdout_write = pipe()
        parent_stderr_read, child_stderr_write = pipe()
        set_info = kernel.SetHandleInformation
        set_info.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD]
        set_info.restype = wintypes.BOOL
        for parent_end in (parent_stdin_write, parent_stdout_read, parent_stderr_read):
            if not set_info(parent_end, _HANDLE_FLAG_INHERIT, 0):
                raise ctypes.WinError(ctypes.get_last_error())
        startup = _StartupInfo()
        startup.cb = ctypes.sizeof(_StartupInfo)
        startup.dwFlags = _STARTF_USESTDHANDLES
        startup.hStdInput = child_stdin_read
        startup.hStdOutput = child_stdout_write
        startup.hStdError = child_stderr_write
        process_info = _ProcessInformation()
        command = subprocess.list2cmdline([str(python_executable), "-I", "-S", "-B",
                                           str(worker_script)])
        command_buffer = ctypes.create_unicode_buffer(command)
        create = advapi.CreateProcessWithLogonW
        create.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD,
                           wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD, wintypes.LPVOID,
                           wintypes.LPCWSTR, ctypes.POINTER(_StartupInfo),
                           ctypes.POINTER(_ProcessInformation)]
        create.restype = wintypes.BOOL
        ok = create(username, domain, password_buffer, logon_flags,
                    str(python_executable), command_buffer, creation_flags,
                    environment_pointer, str(working_directory),
                    ctypes.byref(startup), ctypes.byref(process_info))
        ctypes.memset(ctypes.addressof(password_buffer), 0, ctypes.sizeof(password_buffer))
        if not ok:
            raise ctypes.WinError(ctypes.get_last_error())
        # Parent closes the three child-only pipe ends immediately after launch.
        for child_end in (child_stdin_read, child_stdout_write, child_stderr_write):
            kernel.CloseHandle(child_end)
            pipes.remove(child_end)
        try:
            evidence = _primary_token_evidence(process_info.hProcess)
            _validate_role_token(role, evidence)
        except BaseException:
            kernel.TerminateProcess(process_info.hProcess, 120)
            kernel.CloseHandle(process_info.hThread)
            kernel.CloseHandle(process_info.hProcess)
            raise
        stdin_fd = msvcrt.open_osfhandle(parent_stdin_write, os.O_WRONLY | os.O_BINARY)
        pipes.remove(parent_stdin_write)
        stdout_fd = msvcrt.open_osfhandle(parent_stdout_read, os.O_RDONLY | os.O_BINARY)
        pipes.remove(parent_stdout_read)
        stderr_fd = msvcrt.open_osfhandle(parent_stderr_read, os.O_RDONLY | os.O_BINARY)
        pipes.remove(parent_stderr_read)
        return WindowsRoleProcess(
            role, int(process_info.dwProcessId), evidence.user_sid,
            evidence.token_type, evidence.is_administrator,
            process_info.hProcess, process_info.hThread,
            os.fdopen(stdin_fd, "wb", buffering=0),
            os.fdopen(stdout_fd, "rb", buffering=0),
            os.fdopen(stderr_fd, "rb", buffering=0), kernel,
        )
    finally:
        if password_buffer is not None:
            ctypes.memset(ctypes.addressof(password_buffer), 0, ctypes.sizeof(password_buffer))
        for handle in pipes:
            kernel.CloseHandle(handle)
