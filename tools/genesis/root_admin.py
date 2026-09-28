"""External root-admin inspection/CAS tooling for G9.

Only human-invoked commands in this module can mutate the canonical root store.
All automated tests use explicitly non-authoritative temporary SQLite files.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import sqlite3
import sys
from pathlib import Path

from external_profiles import canonical_json_bytes

ROOT_STORE_PATH = Path(r"C:\AutodevG9\root\root.sqlite3")
ROOT_STATE_FORMAT = "autodev.g9-root-state/v1"
FENCE_FORMAT = "autodev.g9-capability-fence/v1"
_SCHEMA_STATEMENTS = (
    "CREATE TABLE root_state (format TEXT NOT NULL CHECK(format = 'autodev.g9-root-state/v1'), "
    "root_anchor_id TEXT NOT NULL PRIMARY KEY, active_manifest_id TEXT NOT NULL, "
    "transition TEXT NOT NULL CHECK(transition = 'G_OPEN'), "
    "revision INTEGER NOT NULL CHECK(revision >= 1)) WITHOUT ROWID",
    "CREATE TABLE capability_fence (candidate_package_id TEXT NOT NULL PRIMARY KEY, "
    "root_anchor_id TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('FENCED','RELEASED')), "
    "revision INTEGER NOT NULL CHECK(revision >= 0)) WITHOUT ROWID",
)
ROOT_STORE_SCHEMA_SHA256 = hashlib.sha256(
    canonical_json_bytes(("autodev.g9-canonical-root-store-schema/v1", _SCHEMA_STATEMENTS))
).hexdigest()
_EXPECTED_SCHEMA = {
    ("table", "capability_fence"): _SCHEMA_STATEMENTS[1],
    ("table", "root_state"): _SCHEMA_STATEMENTS[0],
}


def _readonly_connection(path: Path) -> sqlite3.Connection:
    uri = path.resolve().as_uri() + "?mode=ro"
    return sqlite3.connect(uri, uri=True, isolation_level=None, timeout=2)


def _schema_is_exact(connection: sqlite3.Connection) -> bool:
    objects = connection.execute(
        "SELECT type, name, sql FROM sqlite_master "
        "WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"
    ).fetchall()
    return (len(objects) == len(_EXPECTED_SCHEMA)
            and all(_EXPECTED_SCHEMA.get((kind, name)) == sql for kind, name, sql in objects))


def inspect_uninitialized_root(
    path: Path, *, expected_anchor_id: str, expected_candidate_package_id: str,
    expected_schema_sha256: str = ROOT_STORE_SCHEMA_SHA256,
) -> dict[str, object]:
    """Read-only proof of exact schema, zero active rows and one fenced CP row."""
    if not isinstance(path, Path) or not path.is_absolute():
        raise ValueError("root-store path must be an absolute Path")
    if (expected_schema_sha256 != ROOT_STORE_SCHEMA_SHA256
            or not _is_hex_digest(expected_anchor_id)
            or not _is_hex_digest(expected_candidate_package_id)):
        raise ValueError("expected root identity is malformed or schema is unsupported")
    connection = _readonly_connection(path)
    try:
        if not _schema_is_exact(connection):
            raise ValueError("root-store schema is missing, malformed, or not exact")
        root_rows = connection.execute(
            "SELECT format, root_anchor_id, active_manifest_id, transition, revision FROM root_state"
        ).fetchall()
        fence_rows = connection.execute(
            "SELECT candidate_package_id, root_anchor_id, state, revision FROM capability_fence"
        ).fetchall()
        if root_rows:
            raise ValueError("root store is already initialized")
        if len(fence_rows) != 1:
            raise ValueError("canonical pre-genesis fence row is missing or ambiguous")
        package_id, anchor_id, state, revision = fence_rows[0]
        if (package_id != expected_candidate_package_id or anchor_id != expected_anchor_id
                or state != "FENCED" or type(revision) is not int or revision != 0):
            raise ValueError("canonical fence row does not exactly bind the expected CP in FENCED/0")
        return {
            "status": "UNINITIALIZED",
            "root_anchor_id": expected_anchor_id,
            "candidate_package_id": expected_candidate_package_id,
            "root_state_row_count": 0,
            "capability_fence_row_count": 1,
            "fence_state": "FENCED",
            "fence_revision": 0,
            "schema_sha256": ROOT_STORE_SCHEMA_SHA256,
        }
    finally:
        connection.close()


def initialize_genesis_state(
    path: Path, *, expected_anchor_id: str, expected_candidate_package_id: str,
    active_manifest_id: str, explicit_initialization: bool,
    expected_admin_sid: str,
) -> int:
    """Insert the first G/open/revision-1 root row after explicit external action."""
    _require_external_root_admin(expected_admin_sid)
    if explicit_initialization is not True:
        raise PermissionError("root initialization requires explicit human action")
    if not _is_canonical_path(path):
        raise PermissionError("root-admin mutations are restricted to the canonical root DB")
    if any(type(value) is not str or not value for value in (
            expected_anchor_id, expected_candidate_package_id, active_manifest_id)):
        raise ValueError("root initialization identities must be non-empty strings")
    connection = sqlite3.connect(path, isolation_level=None, timeout=2)
    try:
        connection.execute("BEGIN IMMEDIATE")
        if not _schema_is_exact(connection):
            raise ValueError("canonical root schema is not exact")
        fence = connection.execute(
            "SELECT root_anchor_id, state, revision FROM capability_fence "
            "WHERE candidate_package_id = ?", (expected_candidate_package_id,),
        ).fetchall()
        count = connection.execute("SELECT COUNT(*) FROM root_state").fetchone()[0]
        if (len(fence) != 1 or fence[0] != (expected_anchor_id, "RELEASED", 1)
                or count != 0):
            raise ValueError("root initialization precondition is not the exact released CP fence")
        connection.execute(
            "INSERT INTO root_state(format, root_anchor_id, active_manifest_id, transition, revision) "
            "VALUES (?, ?, ?, 'G_OPEN', 1)",
            (ROOT_STATE_FORMAT, expected_anchor_id, active_manifest_id),
        )
        connection.execute("COMMIT")
        return 1
    except BaseException:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    finally:
        connection.close()


def compare_and_swap_fence(
    path: Path, *, expected_admin_sid: str, candidate_package_id: str,
    expected_revision: int, new_state: str,
) -> int:
    """CAS the external capability fence; never callable by candidate roles."""
    _require_external_root_admin(expected_admin_sid)
    if not _is_canonical_path(path):
        raise PermissionError("fence mutation is restricted to the canonical root DB")
    if (type(expected_revision) is not int or expected_revision < 0
            or new_state not in ("FENCED", "RELEASED") or not _is_hex_digest(candidate_package_id)):
        raise ValueError("invalid fence CAS request")
    connection = sqlite3.connect(path, isolation_level=None, timeout=2)
    try:
        connection.execute("BEGIN IMMEDIATE")
        if not _schema_is_exact(connection):
            raise ValueError("canonical root schema is not exact")
        cursor = connection.execute(
            "UPDATE capability_fence SET state = ?, revision = revision + 1 "
            "WHERE candidate_package_id = ? AND state = 'FENCED' AND revision = ?",
            (new_state, candidate_package_id, expected_revision),
        )
        if cursor.rowcount != 1:
            raise ValueError("fence CAS is stale or the exact FENCED row is absent")
        next_revision = expected_revision + 1
        connection.execute("COMMIT")
        return next_revision
    except BaseException:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    finally:
        connection.close()


def _is_canonical_path(path: Path) -> bool:
    return type(path) is Path and str(path.resolve()).casefold() == str(ROOT_STORE_PATH).casefold()


def _is_hex_digest(value: object) -> bool:
    return (type(value) is str and len(value) == 64
            and all(character in "0123456789abcdef" for character in value))


def _current_token_identity() -> tuple[str, bool]:
    if sys.platform != "win32":
        raise PermissionError("external root administration requires Windows")
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    token = ctypes.c_void_p()
    kernel.GetCurrentProcess.restype = ctypes.c_void_p
    advapi.OpenProcessToken.argtypes = [ctypes.c_void_p, ctypes.c_ulong,
                                       ctypes.POINTER(ctypes.c_void_p)]
    advapi.OpenProcessToken.restype = ctypes.c_int
    advapi.GetTokenInformation.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p,
                                          ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
    advapi.GetTokenInformation.restype = ctypes.c_int
    advapi.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_wchar_p)]
    advapi.ConvertSidToStringSidW.restype = ctypes.c_int
    advapi.ConvertStringSidToSidW.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_void_p)]
    advapi.ConvertStringSidToSidW.restype = ctypes.c_int
    advapi.CheckTokenMembership.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                           ctypes.POINTER(ctypes.c_int)]
    advapi.CheckTokenMembership.restype = ctypes.c_int
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel.CloseHandle.restype = ctypes.c_int
    if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 0x0008, ctypes.byref(token)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        needed = ctypes.c_ulong()
        advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(needed))
        if needed.value == 0:
            raise ctypes.WinError(ctypes.get_last_error())
        buffer = ctypes.create_string_buffer(needed.value)
        if not advapi.GetTokenInformation(token, 1, buffer, needed.value, ctypes.byref(needed)):
            raise ctypes.WinError(ctypes.get_last_error())
        sid_ptr = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p)).contents.value
        sid_text = ctypes.c_wchar_p()
        if not advapi.ConvertSidToStringSidW(sid_ptr, ctypes.byref(sid_text)):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            sid = sid_text.value
        finally:
            kernel.LocalFree(sid_text)
        admin_sid = ctypes.c_void_p()
        if not advapi.ConvertStringSidToSidW("S-1-5-32-544", ctypes.byref(admin_sid)):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            member = ctypes.c_int()
            if not advapi.CheckTokenMembership(None, admin_sid, ctypes.byref(member)):
                raise ctypes.WinError(ctypes.get_last_error())
            is_admin = bool(member.value)
        finally:
            kernel.LocalFree(admin_sid)
        return sid, is_admin
    finally:
        kernel.CloseHandle(token)


def _require_external_root_admin(expected_admin_sid: str) -> None:
    if not _is_hex_sid(expected_admin_sid):
        raise PermissionError("expected external root-admin SID is invalid")
    actual_sid, is_admin = _current_token_identity()
    if actual_sid != expected_admin_sid or not is_admin:
        raise PermissionError("caller is not the profile-bound external root administrator")


def _is_hex_sid(value: object) -> bool:
    return type(value) is str and value.startswith("S-1-") and all(
        part.isdecimal() for part in value.split("-")[1:]
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only G9 root-state inspection")
    parser.add_argument("--candidate-package-id", required=True)
    parser.add_argument("--root-anchor-id", required=True)
    parser.add_argument("--database", type=Path, default=ROOT_STORE_PATH)
    args = parser.parse_args()
    try:
        evidence = inspect_uninitialized_root(
            args.database, expected_anchor_id=args.root_anchor_id,
            expected_candidate_package_id=args.candidate_package_id,
        )
    except Exception as exc:
        print(json.dumps({"status": "FAILED_CLOSED", "failure_type": type(exc).__name__},
                         sort_keys=True, separators=(",", ":")))
        return 2
    print(json.dumps(evidence, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
