"""External Root Authority for the frozen G9 first-genesis ceremony.

All mutation APIs require the profile-bound elevated Windows root principal and
an explicit human action.  Tests use isolated temporary databases only.
"""

from __future__ import annotations

import argparse
import ctypes
from datetime import datetime, timezone
import hashlib
import json
import secrets
import sqlite3
import sys
from pathlib import Path
from typing import Any, Callable, Mapping

from external_profiles import (
    canonical_json_bytes, derive_root_anchor_id, derive_root_store_profile_id,
    derive_execution_isolation_dependency_id, derive_external_root_controller_identity,
    derive_host_profile_id,
    validate_fixture_substrate_profile,
    validate_root_fence_profile,
)

ROOT_STORE_PATH = Path(r"C:\AutodevG9\root\root.sqlite3")
ROOT_STATE_FORMAT = "autodev.g9-root-state/v1"
FENCE_FORMAT = "autodev.g9-capability-fence/v1"
ACCEPTANCE_FORMAT = "autodev.genesis-acceptance-record/v1"
INITIALIZATION_FORMAT = "autodev.genesis-root-initialization-record/v1"
RELEASE_FORMAT = "autodev.genesis-release-verification/v1"
ROOT_STORE_PROFILE = "autodev.g9-canonical-root-store/v1"
_ROOT_ACL_SECURITY_INFORMATION = 0x00000001 | 0x00000002 | 0x00000004 | 0x80000000
_UNPROTECTED_DACL_SECURITY_INFORMATION = 0x20000000
BOOTSTRAP_APPROVER_ACCOUNT = r"ray\zhang"
BOOTSTRAP_APPROVER_SID = "S-1-5-21-711519901-190585334-3846127459-1001"

FENCE_BINDING_FIELDS = (
    "format", "fence_id", "root_anchor_id", "candidate_package_id", "manifest_id",
    "runtime_artifact_sha256", "runtime_generation", "execution_isolation_dependency_id",
    "fixture_effect_substrate_dependency_id", "security_context_t_identity",
    "security_context_c_identity", "security_context_p_identity", "security_context_m_identity",
    "prepared_endpoint_c_identity", "prepared_endpoint_p_identity",
    "prepared_endpoint_m_identity", "state", "revision",
)
FENCE_STABLE_FIELDS = tuple(
    field for field in FENCE_BINDING_FIELDS if field not in {"fence_id", "state", "revision"}
)
ACCEPTANCE_FIELDS = (
    "format", "acceptance_profile_id", "authenticated_approver", "candidate_package_id",
    "genesis_manifest_id", "runtime_artifact_sha256", "root_anchor_id",
    "deployment_attestation_id", "deployment_session_id", "activation_subject", "decision",
    "accepted_at", "valid_until",
)
INITIALIZATION_FIELDS = (
    "format", "initialization_operation_id", "acceptance_id", "deployment_attestation_id",
    "deployment_session_id", "candidate_package_id", "genesis_manifest_id", "root_anchor_id",
    "resulting_root_state", "initialized_by", "initialized_at",
)
RELEASE_FIELDS = (
    "format", "release_operation_id", "initialization_record_id", "acceptance_id",
    "deployment_attestation_id", "deployment_session_id", "candidate_package_id",
    "genesis_manifest_id", "runtime_artifact_sha256", "root_anchor_id",
    "root_state_identity", "pre_release_fence_identity", "process_instance_identities",
    "external_material_identities", "protected_effect_denial_observation",
    "resulting_release_fence_identity", "released_by", "released_at",
)


class _SidAndAttributes(ctypes.Structure):
    _fields_ = [("sid", ctypes.c_void_p), ("attributes", ctypes.c_ulong)]


class _TokenGroups(ctypes.Structure):
    # TOKEN_GROUPS contains a DWORD followed by SID_AND_ATTRIBUTES[ANYSIZE_ARRAY].
    # ctypes supplies the native pointer-alignment padding required on Win64.
    _fields_ = [("group_count", ctypes.c_ulong),
                ("groups", _SidAndAttributes * 1)]


def _group_attributes_are_enabled_admin(attributes: int) -> bool:
    return type(attributes) is int and bool(attributes & 0x4) and not bool(attributes & 0x10)
ATTESTATION_FIELDS = frozenset({
    "format", "candidate_package_id", "genesis_manifest_id", "deterministic_evidence_ids",
    "review_record_id", "repository_source_commit", "runtime_artifact_sha256", "python_runtime",
    "execution_isolation_dependency_id", "execution_isolation_profile_sha256",
    "execution_isolation_profile", "root_fence_dependency_id", "root_fence_profile_sha256",
    "root_fence_profile", "root_store_profile_id",
    "root_store_schema_sha256", "root_namespace_acl_profile_id", "acceptance_profile_id",
    "fixture_substrate_dependency_id", "fixture_substrate_profile_sha256",
    "fixture_substrate_profile", "root_anchor_id",
    "deployment_session_id", "root_state_observation", "roles", "process_instance_observations",
    "external_root_controller_identity", "staged_external_material", "substrate_service",
    "shared_runtime_read_only", "cross_role_private_write_denial",
    "candidate_root_store_write_denial", "protected_endpoint_state",
    "recovery_fence_inventory", "production_github_mutation_credentials",
    "host_profile_id", "observed_at",
})

_SCHEMA_STATEMENTS = (
    "CREATE TABLE root_state (format TEXT NOT NULL CHECK(format = 'autodev.g9-root-state/v1'), "
    "root_anchor_id TEXT NOT NULL PRIMARY KEY, active_manifest_id TEXT NOT NULL, "
    "transition TEXT NOT NULL CHECK(transition = 'open'), revision INTEGER NOT NULL CHECK(revision = 1)) WITHOUT ROWID",
    "CREATE TABLE capability_fence (format TEXT NOT NULL CHECK(format = 'autodev.g9-capability-fence/v1'), "
    "fence_id TEXT NOT NULL PRIMARY KEY, root_anchor_id TEXT NOT NULL, candidate_package_id TEXT NOT NULL, "
    "manifest_id TEXT NOT NULL, runtime_artifact_sha256 TEXT NOT NULL, runtime_generation TEXT NOT NULL, "
    "execution_isolation_dependency_id TEXT NOT NULL, fixture_effect_substrate_dependency_id TEXT NOT NULL, "
    "security_context_t_identity TEXT NOT NULL, security_context_c_identity TEXT NOT NULL, "
    "security_context_p_identity TEXT NOT NULL, security_context_m_identity TEXT NOT NULL, "
    "prepared_endpoint_c_identity TEXT NOT NULL, prepared_endpoint_p_identity TEXT NOT NULL, "
    "prepared_endpoint_m_identity TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('FENCED','RELEASED')), "
    "revision INTEGER NOT NULL CHECK(revision IN (0,1))) WITHOUT ROWID",
    "CREATE TABLE genesis_acceptance (acceptance_id TEXT NOT NULL PRIMARY KEY, "
    "deployment_attestation_id TEXT NOT NULL UNIQUE, deployment_session_id TEXT NOT NULL, "
    "preimage_json BLOB NOT NULL, record_json BLOB NOT NULL) WITHOUT ROWID",
    "CREATE TABLE genesis_root_initialization (record_id TEXT NOT NULL PRIMARY KEY, "
    "initialization_operation_id TEXT NOT NULL UNIQUE, acceptance_id TEXT NOT NULL, "
    "deployment_attestation_id TEXT NOT NULL, deployment_session_id TEXT NOT NULL, "
    "preimage_json BLOB NOT NULL, record_json BLOB NOT NULL) WITHOUT ROWID",
    "CREATE TABLE genesis_release_verification (release_verification_id TEXT NOT NULL PRIMARY KEY, "
    "release_operation_id TEXT NOT NULL UNIQUE, initialization_record_id TEXT NOT NULL, "
    "acceptance_id TEXT NOT NULL, deployment_attestation_id TEXT NOT NULL, deployment_session_id TEXT NOT NULL, "
    "preimage_json BLOB NOT NULL, record_json BLOB NOT NULL) WITHOUT ROWID",
    "CREATE TRIGGER acceptance_no_update BEFORE UPDATE ON genesis_acceptance BEGIN SELECT RAISE(ABORT, 'append-only'); END",
    "CREATE TRIGGER acceptance_no_delete BEFORE DELETE ON genesis_acceptance BEGIN SELECT RAISE(ABORT, 'append-only'); END",
    "CREATE TRIGGER init_no_update BEFORE UPDATE ON genesis_root_initialization BEGIN SELECT RAISE(ABORT, 'append-only'); END",
    "CREATE TRIGGER init_no_delete BEFORE DELETE ON genesis_root_initialization BEGIN SELECT RAISE(ABORT, 'append-only'); END",
    "CREATE TRIGGER release_no_update BEFORE UPDATE ON genesis_release_verification BEGIN SELECT RAISE(ABORT, 'append-only'); END",
    "CREATE TRIGGER release_no_delete BEFORE DELETE ON genesis_release_verification BEGIN SELECT RAISE(ABORT, 'append-only'); END",
    "CREATE TRIGGER acceptance_no_replace BEFORE INSERT ON genesis_acceptance WHEN EXISTS("
    "SELECT 1 FROM genesis_acceptance WHERE acceptance_id=NEW.acceptance_id OR "
    "deployment_attestation_id=NEW.deployment_attestation_id) BEGIN SELECT RAISE(ABORT, 'append-only'); END",
    "CREATE TRIGGER init_no_replace BEFORE INSERT ON genesis_root_initialization WHEN EXISTS("
    "SELECT 1 FROM genesis_root_initialization WHERE record_id=NEW.record_id OR "
    "initialization_operation_id=NEW.initialization_operation_id) BEGIN SELECT RAISE(ABORT, 'append-only'); END",
    "CREATE TRIGGER release_no_replace BEFORE INSERT ON genesis_release_verification WHEN EXISTS("
    "SELECT 1 FROM genesis_release_verification WHERE release_verification_id=NEW.release_verification_id OR "
    "release_operation_id=NEW.release_operation_id) BEGIN SELECT RAISE(ABORT, 'append-only'); END",
)
ROOT_STORE_SCHEMA_SHA256 = hashlib.sha256(
    canonical_json_bytes(("autodev.g9-canonical-root-store-schema/v2", _SCHEMA_STATEMENTS))
).hexdigest()
_EXPECTED_SCHEMA = {
    ("table", name): sql for name, sql in zip((
        "root_state", "capability_fence", "genesis_acceptance",
        "genesis_root_initialization", "genesis_release_verification",
    ), _SCHEMA_STATEMENTS[:5])
}
_EXPECTED_SCHEMA.update({
    ("trigger", name): sql for name, sql in zip((
        "acceptance_no_update", "acceptance_no_delete", "init_no_update",
        "init_no_delete", "release_no_update", "release_no_delete",
        "acceptance_no_replace", "init_no_replace", "release_no_replace",
    ), _SCHEMA_STATEMENTS[5:])
})


def _digest(value: object) -> bool:
    return type(value) is str and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def _require_exact_true_map(value: object, keys: set[str]) -> None:
    if type(value) is not dict or set(value) != keys or any(item is not True for item in value.values()):
        raise ValueError("deployment attestation lacks an exact all-true denial map")


def _is_hex_sid(value: object) -> bool:
    return type(value) is str and value.startswith("S-1-") and all(
        part.isdecimal() for part in value.split("-")[1:]
    )


def _is_canonical_path(path: Path) -> bool:
    return type(path) is Path and str(path.resolve()).casefold() == str(ROOT_STORE_PATH).casefold()


def fence_identity(binding: Mapping[str, object]) -> str:
    if type(binding) is not dict or set(binding) != set(FENCE_STABLE_FIELDS):
        raise ValueError("capability-fence stable binding is not closed")
    return hashlib.sha256(b"autodev.g9-capability-fence-row/v1\0" +
                          canonical_json_bytes(dict(binding))).hexdigest()


def build_fence_row(*, root_anchor_id: str, candidate_package_id: str, manifest_id: str,
                    runtime_artifact_sha256: str, runtime_generation: str,
                    execution_isolation_dependency_id: str,
                    fixture_effect_substrate_dependency_id: str,
                    security_context_identities: dict[str, str],
                    prepared_endpoint_identities: dict[str, str]) -> dict[str, object]:
    """Derive the one closed stable deployment fence subject from CP2 facts."""
    if (type(security_context_identities) is not dict
            or set(security_context_identities) != {"T", "C", "P", "M"}
            or type(prepared_endpoint_identities) is not dict
            or set(prepared_endpoint_identities) != {"C", "P", "M"}):
        raise ValueError("exact T/C/P/M contexts and C/P/M endpoint identities are required")
    stable: dict[str, object] = {
        "format": FENCE_FORMAT,
        "root_anchor_id": root_anchor_id,
        "candidate_package_id": candidate_package_id,
        "manifest_id": manifest_id,
        "runtime_artifact_sha256": runtime_artifact_sha256,
        "runtime_generation": runtime_generation,
        "execution_isolation_dependency_id": execution_isolation_dependency_id,
        "fixture_effect_substrate_dependency_id": fixture_effect_substrate_dependency_id,
        "security_context_t_identity": security_context_identities["T"],
        "security_context_c_identity": security_context_identities["C"],
        "security_context_p_identity": security_context_identities["P"],
        "security_context_m_identity": security_context_identities["M"],
        "prepared_endpoint_c_identity": prepared_endpoint_identities["C"],
        "prepared_endpoint_p_identity": prepared_endpoint_identities["P"],
        "prepared_endpoint_m_identity": prepared_endpoint_identities["M"],
    }
    row = {**stable, "fence_id": fence_identity(stable), "state": "FENCED", "revision": 0}
    return _validate_fence_row(row)


def _validate_fence_row(row: Mapping[str, object], *, require_fenced: bool = True) -> dict[str, object]:
    if type(row) is not dict or set(row) != set(FENCE_BINDING_FIELDS):
        raise ValueError("capability-fence row has an open or incomplete field set")
    stable = {field: row[field] for field in FENCE_STABLE_FIELDS}
    if row["format"] != FENCE_FORMAT or row["fence_id"] != fence_identity(stable):
        raise ValueError("capability-fence identity is inconsistent")
    for field in ("root_anchor_id", "candidate_package_id", "manifest_id", "runtime_artifact_sha256",
                  "security_context_t_identity", "security_context_c_identity",
                  "security_context_p_identity", "security_context_m_identity",
                  "prepared_endpoint_c_identity", "prepared_endpoint_p_identity",
                  "prepared_endpoint_m_identity"):
        if not _digest(row[field]):
            raise ValueError(f"capability-fence {field} is malformed")
    for field in ("runtime_generation", "execution_isolation_dependency_id",
                  "fixture_effect_substrate_dependency_id"):
        if type(row[field]) is not str or not row[field]:
            raise ValueError(f"capability-fence {field} is malformed")
    if row["state"] not in (("FENCED",) if require_fenced else ("FENCED", "RELEASED")):
        raise ValueError("capability-fence state is not the exact permitted state")
    if type(row["revision"]) is not int or row["revision"] != (0 if row["state"] == "FENCED" else 1):
        raise ValueError("capability-fence revision is inconsistent")
    return dict(row)


def fence_row_identity(row: Mapping[str, object]) -> str:
    """Content-address the complete observed fence row, including state/revision."""
    exact = _validate_fence_row(row, require_fenced=False)
    return hashlib.sha256(b"autodev.g9-capability-fence-complete-row/v1\0" +
                          canonical_json_bytes(exact)).hexdigest()


def _insert_fence(connection: sqlite3.Connection, row: dict[str, object]) -> None:
    exact = _validate_fence_row(row)
    columns = ", ".join(FENCE_BINDING_FIELDS)
    placeholders = ", ".join("?" for _ in FENCE_BINDING_FIELDS)
    connection.execute(
        f"INSERT INTO capability_fence({columns}) VALUES ({placeholders})",
        tuple(exact[field] for field in FENCE_BINDING_FIELDS),
    )


def _schema_is_exact(connection: sqlite3.Connection) -> bool:
    objects = connection.execute(
        "SELECT type, name, sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"
    ).fetchall()
    return len(objects) == len(_EXPECTED_SCHEMA) and all(
        _EXPECTED_SCHEMA.get((kind, name)) == sql for kind, name, sql in objects
    )


def _readonly_connection(path: Path) -> sqlite3.Connection:
    return sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True,
                            isolation_level=None, timeout=2)


def _now_utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def new_deployment_session_id() -> str:
    """Generate a controller-owned public 256-bit session identity."""
    return secrets.token_hex(32)


def _is_exact_utc(value: object) -> bool:
    if type(value) is not str or len(value) != 27 or value[19] != "." or not value.endswith("Z"):
        return False
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return False
    return parsed.strftime("%Y-%m-%dT%H:%M:%S.%fZ") == value


def _canonical_record(domain: bytes, preimage: dict[str, object], id_key: str) -> dict[str, object]:
    identity = hashlib.sha256(domain + canonical_json_bytes(preimage)).hexdigest()
    return {id_key: identity, "preimage": preimage}


def _record_is_exact(record: object, domain: bytes, id_key: str, fields: tuple[str, ...]) -> bool:
    if type(record) is not dict or set(record) != {id_key, "preimage"}:
        return False
    preimage = record["preimage"]
    return (type(preimage) is dict and set(preimage) == set(fields)
            and record[id_key] == hashlib.sha256(domain + canonical_json_bytes(preimage)).hexdigest())


def _validate_acceptance_record(record: object, *, expected_fence: dict[str, object],
                                expected_session_id: str,
                                expected_attestation_id: str | None = None,
                                expected_acceptance_profile_id: str | None = None) -> dict[str, object]:
    if not _record_is_exact(record, b"autodev.genesis-acceptance/v1\0",
                            "acceptance_id", ACCEPTANCE_FIELDS):
        raise ValueError("Acceptance record is not an exact content-addressed record")
    preimage = record["preimage"]
    approver = preimage["authenticated_approver"]
    if (preimage["format"] != ACCEPTANCE_FORMAT
            or not _digest(preimage["acceptance_profile_id"])
            or (expected_acceptance_profile_id is not None
                and preimage["acceptance_profile_id"] != expected_acceptance_profile_id)
            or type(approver) is not dict or set(approver) != {"account", "sid"}
            or type(approver["account"]) is not str
            or approver["account"] != BOOTSTRAP_APPROVER_ACCOUNT
            or approver["sid"] != BOOTSTRAP_APPROVER_SID
            or preimage["candidate_package_id"] != expected_fence["candidate_package_id"]
            or preimage["genesis_manifest_id"] != expected_fence["manifest_id"]
            or preimage["runtime_artifact_sha256"] != expected_fence["runtime_artifact_sha256"]
            or preimage["root_anchor_id"] != expected_fence["root_anchor_id"]
            or preimage["deployment_session_id"] != expected_session_id
            or (expected_attestation_id is not None
                and preimage["deployment_attestation_id"] != expected_attestation_id)
            or preimage["activation_subject"] != {
                "kind": "GENESIS_BOOTSTRAP", "manifest_id": expected_fence["manifest_id"]}
            or preimage["decision"] != "ACCEPT" or preimage["valid_until"] is not None
            or not _is_exact_utc(preimage["accepted_at"])
            or any(not _digest(preimage[key]) for key in (
                "acceptance_profile_id", "candidate_package_id", "genesis_manifest_id",
                "runtime_artifact_sha256", "root_anchor_id", "deployment_attestation_id",
                "deployment_session_id"))):
        raise ValueError("Acceptance record is stale, malformed, or not applicable to this exact session")
    return preimage


def provision_root_store(
    path: Path, *, fence_row: dict[str, object], expected_admin_sid: str,
    explicit_provision: bool, expected_acl_sddl: str,
) -> dict[str, object]:
    """Create the future canonical schema and one exact FENCED/0 CP2 row.

    This must be explicitly invoked by the elevated external root administrator.
    The PR's rehearsal and tests use temporary databases and never call the
    canonical path.
    """
    _require_external_root_admin(expected_admin_sid)
    if explicit_provision is not True:
        raise PermissionError("root-store provisioning requires explicit human action")
    if not _is_canonical_path(path):
        raise PermissionError("root-store provisioning is restricted to the canonical path")
    exact_fence = _validate_fence_row(fence_row)
    _confirm_human_action("PROVISION", exact_fence["fence_id"], explicit_provision)
    if path.exists() or path.parent.exists():
        raise FileExistsError("canonical root namespace must be absent for create-if-absent provisioning")
    path.parent.mkdir(parents=True, exist_ok=False)
    _set_and_verify_root_acl(path.parent, expected_acl_sddl)
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(path, isolation_level=None, timeout=2)
        connection.execute("BEGIN IMMEDIATE")
        for statement in _SCHEMA_STATEMENTS:
            connection.execute(statement)
        _insert_fence(connection, fence_row)
        connection.execute("COMMIT")
        _set_and_verify_root_acl(path.parent, expected_acl_sddl)
        if not _schema_is_exact(connection):
            raise ValueError("provisioned schema failed exact read-back")
        return {"status": "PROVISIONED_UNINITIALIZED", "schema_sha256": ROOT_STORE_SCHEMA_SHA256,
                "fence_id": fence_row["fence_id"], "state": "FENCED", "revision": 0}
    except BaseException:
        if connection is not None and connection.in_transaction:
            connection.execute("ROLLBACK")
        # Do not remove partially created canonical state automatically; external
        # root recovery is required if provisioning fails after namespace creation.
        raise
    finally:
        if connection is not None:
            connection.close()


def inspect_uninitialized_root(
    path: Path, *, expected_fence_row: dict[str, object],
    deployment_session_id: str,
    expected_schema_sha256: str = ROOT_STORE_SCHEMA_SHA256,
) -> dict[str, object]:
    """Read-only exact pre-genesis inspection; historical Acceptance is allowed."""
    if not isinstance(path, Path) or not path.is_absolute():
        raise ValueError("root-store path must be an absolute Path")
    expected = _validate_fence_row(expected_fence_row)
    if not _digest(deployment_session_id):
        raise ValueError("deployment session identity is malformed")
    if expected_schema_sha256 != ROOT_STORE_SCHEMA_SHA256:
        raise ValueError("expected root schema is unsupported")
    connection = _readonly_connection(path)
    try:
        if not _schema_is_exact(connection):
            raise ValueError("root-store schema is missing, malformed, or not exact")
        root_count = connection.execute("SELECT COUNT(*) FROM root_state").fetchone()[0]
        fences = connection.execute("SELECT " + ",".join(FENCE_BINDING_FIELDS) +
                                    " FROM capability_fence").fetchall()
        if root_count != 0 or len(fences) != 1:
            raise ValueError("root is initialized or canonical fence is ambiguous")
        actual = dict(zip(FENCE_BINDING_FIELDS, fences[0]))
        _validate_fence_row(actual)
        if actual != expected:
            raise ValueError("canonical fence does not bind the exact current CP2 deployment subject")
        init_count = connection.execute("SELECT COUNT(*) FROM genesis_root_initialization").fetchone()[0]
        release_count = connection.execute("SELECT COUNT(*) FROM genesis_release_verification").fetchone()[0]
        acceptance_rows = connection.execute(
            "SELECT acceptance_id,deployment_attestation_id,deployment_session_id,preimage_json,record_json "
            "FROM genesis_acceptance ORDER BY acceptance_id"
        ).fetchall()
        if init_count or release_count:
            raise ValueError("uninitialized root has conflicting ceremony provenance")
        acceptance_ids: list[str] = []
        for acceptance_id, attestation_id, session_id, preimage_bytes, record_bytes in acceptance_rows:
            preimage, record = json.loads(preimage_bytes), json.loads(record_bytes)
            if (canonical_json_bytes(record.get("preimage")) != bytes(preimage_bytes)
                    or canonical_json_bytes(record) != bytes(record_bytes)
                    or preimage != record.get("preimage")
                    or record.get("acceptance_id") != acceptance_id):
                raise ValueError("Acceptance history contains malformed immutable evidence")
            _validate_acceptance_record(
                record, expected_fence=expected, expected_session_id=session_id,
                expected_attestation_id=attestation_id,
            )
            acceptance_ids.append(acceptance_id)
        if len(acceptance_ids) != len(set(acceptance_ids)):
            raise ValueError("Acceptance history contains duplicate identities")
        applicable = [row for row in acceptance_rows if row[2] == deployment_session_id]
        if applicable:
            raise ValueError("a Stage-B Acceptance for the new deployment session already exists")
        acceptance_digest = hashlib.sha256(
            b"autodev.genesis-acceptance-history/v1\0" + canonical_json_bytes(acceptance_ids)
        ).hexdigest()
        return {"status": "UNINITIALIZED", "root_anchor_id": expected["root_anchor_id"],
                "candidate_package_id": expected["candidate_package_id"], "manifest_id": expected["manifest_id"],
                "root_state_row_count": 0, "capability_fence_row_count": 1,
                "fence_id": expected["fence_id"], "fence_state": "FENCED", "fence_revision": 0,
                "capability_fence": expected,
                "acceptance_history_count": len(acceptance_ids),
                "acceptance_history_digest": acceptance_digest,
                "applicable_acceptance_for_this_deployment_session": None,
                "deployment_session_id": deployment_session_id,
                "initialization_record_count": 0,
                "release_verification_count": 0, "schema_sha256": ROOT_STORE_SCHEMA_SHA256}
    finally:
        connection.close()


def acceptance_preimage(*, acceptance_profile_id: str, approver_account: str,
                        approver_sid: str, candidate_package_id: str,
                        genesis_manifest_id: str, runtime_artifact_sha256: str,
                        root_anchor_id: str, deployment_attestation_id: str,
                        deployment_session_id: str) -> dict[str, object]:
    """Build the frozen closed A/v1 subject; id and timestamp are not caller IDs."""
    for value in (candidate_package_id, genesis_manifest_id, runtime_artifact_sha256,
                  root_anchor_id, deployment_attestation_id, deployment_session_id):
        if not _digest(value):
            raise ValueError("Acceptance identity binding is malformed")
    if (not _digest(acceptance_profile_id) or type(approver_account) is not str
            or approver_account != BOOTSTRAP_APPROVER_ACCOUNT
            or approver_sid != BOOTSTRAP_APPROVER_SID):
        raise ValueError("Acceptance approver SID is malformed")
    timestamp = _now_utc()
    if not _is_exact_utc(timestamp):
        raise ValueError("Acceptance timestamp must use canonical UTC Z serialization")
    preimage = {
        "format": ACCEPTANCE_FORMAT, "acceptance_profile_id": acceptance_profile_id,
        "authenticated_approver": {"account": approver_account, "sid": approver_sid},
        "candidate_package_id": candidate_package_id, "genesis_manifest_id": genesis_manifest_id,
        "runtime_artifact_sha256": runtime_artifact_sha256, "root_anchor_id": root_anchor_id,
        "activation_subject": {"kind": "GENESIS_BOOTSTRAP", "manifest_id": genesis_manifest_id},
        "decision": "ACCEPT", "deployment_attestation_id": deployment_attestation_id,
        "deployment_session_id": deployment_session_id, "accepted_at": timestamp,
        "valid_until": None,
    }
    if set(preimage) != set(ACCEPTANCE_FIELDS):
        raise AssertionError("frozen Acceptance field set drift")
    return preimage


def acceptance_confirmation_subject(preimage: dict[str, object]) -> str:
    """Stable human-confirmation digest; excludes the audit timestamp and record ID."""
    required = set(ACCEPTANCE_FIELDS)
    if type(preimage) is not dict or set(preimage) != required:
        raise ValueError("Acceptance confirmation preimage is not closed")
    if (preimage.get("format") != ACCEPTANCE_FORMAT or preimage.get("decision") != "ACCEPT"
            or preimage.get("valid_until") is not None
            or not _is_exact_utc(preimage.get("accepted_at"))
            or type(preimage.get("activation_subject")) is not dict
            or set(preimage["activation_subject"]) != {"kind", "manifest_id"}
            or preimage["activation_subject"].get("kind") != "GENESIS_BOOTSTRAP"
            or preimage["activation_subject"].get("manifest_id") != preimage["genesis_manifest_id"]):
        raise ValueError("Acceptance confirmation subject is inconsistent")
    stable = {key: value for key, value in preimage.items() if key != "accepted_at"}
    return hashlib.sha256(b"autodev.genesis-acceptance-subject/v1\0" +
                          canonical_json_bytes(stable)).hexdigest()


def _validate_deployment_attestation(record: object, fence: dict[str, object], session_id: str) -> str:
    """Validate the exact closed S/v1 pre-acceptance record and its CP-bound observations."""
    if type(record) is not dict or set(record) != {"record_id", "preimage"}:
        raise ValueError("deployment attestation record is not closed")
    preimage = record["preimage"]
    if (type(preimage) is not dict or set(preimage) != ATTESTATION_FIELDS
            or preimage.get("format") != "autodev.genesis-deployment-attestation/v1"):
        raise ValueError("deployment attestation format is unsupported")
    if record["record_id"] != hashlib.sha256(canonical_json_bytes(preimage)).hexdigest():
        raise ValueError("deployment attestation identity is invalid")
    if (any(preimage[field] != fence[other] for field, other in (
            ("candidate_package_id", "candidate_package_id"),
            ("genesis_manifest_id", "manifest_id"),
            ("runtime_artifact_sha256", "runtime_artifact_sha256"),
            ("root_anchor_id", "root_anchor_id")))
            or preimage["deployment_session_id"] != session_id
            or preimage["execution_isolation_dependency_id"] != fence["execution_isolation_dependency_id"]
            or preimage["fixture_substrate_dependency_id"]
               != fence["fixture_effect_substrate_dependency_id"]):
        raise ValueError("deployment attestation is stale or belongs to another session")
    for field in ("review_record_id", "runtime_artifact_sha256", "execution_isolation_profile_sha256",
                  "root_fence_profile_sha256", "root_store_profile_id", "root_store_schema_sha256",
                  "root_namespace_acl_profile_id", "acceptance_profile_id",
                  "fixture_substrate_profile_sha256", "root_anchor_id", "deployment_session_id",
                  "host_profile_id"):
        if not _digest(preimage[field]):
            raise ValueError(f"deployment attestation {field} is malformed")
    if (type(preimage["repository_source_commit"]) is not str
            or len(preimage["repository_source_commit"]) != 40
            or any(c not in "0123456789abcdef" for c in preimage["repository_source_commit"])):
        raise ValueError("deployment attestation repository provenance is malformed")
    for field in ("execution_isolation_dependency_id", "root_fence_dependency_id",
                  "fixture_substrate_dependency_id"):
        value = preimage[field]
        if (type(value) is not str or not value.startswith("dep-")
                or not _digest(value.rsplit("-", 1)[-1])):
            raise ValueError("deployment attestation dependency identity is malformed")
    evidence_ids = preimage["deterministic_evidence_ids"]
    if (type(evidence_ids) is not list or not evidence_ids
            or any(type(item) is not str or not item for item in evidence_ids)
            or evidence_ids != sorted(set(evidence_ids))):
        raise ValueError("deployment attestation deterministic evidence set is not canonical")
    python_runtime = preimage["python_runtime"]
    if (type(python_runtime) is not dict
            or set(python_runtime) != {"identity", "version", "path", "sha256"}
            or python_runtime["identity"] != "CPython"
            or any(type(python_runtime[key]) is not str or not python_runtime[key]
                   for key in ("version", "path"))
            or not _digest(python_runtime["sha256"])):
        raise ValueError("deployment attestation Python runtime binding is malformed")
    if preimage["root_store_schema_sha256"] != ROOT_STORE_SCHEMA_SHA256:
        raise ValueError("deployment attestation root-store schema is stale")
    root_profile = preimage["root_fence_profile"]
    substrate_profile = preimage["fixture_substrate_profile"]
    isolation_profile = preimage["execution_isolation_profile"]
    if (type(root_profile) is not dict or type(substrate_profile) is not dict
            or type(isolation_profile) is not dict):
        raise ValueError("deployment attestation external profiles are not closed objects")
    if python_runtime != root_profile["python_runtime"]:
        raise ValueError("deployment attestation CPython differs from the root-admin profile")
    if (hashlib.sha256(canonical_json_bytes(root_profile)).hexdigest()
            != preimage["root_fence_profile_sha256"]
            or hashlib.sha256(canonical_json_bytes(substrate_profile)).hexdigest()
            != preimage["fixture_substrate_profile_sha256"]
            or validate_root_fence_profile(root_profile) != preimage["root_fence_dependency_id"]
            or validate_fixture_substrate_profile(substrate_profile)
               != preimage["fixture_substrate_dependency_id"]):
        raise ValueError("deployment attestation root/substrate profile binding is stale")
    if (hashlib.sha256(canonical_json_bytes(isolation_profile)).hexdigest()
            != preimage["execution_isolation_profile_sha256"]
            or derive_execution_isolation_dependency_id(isolation_profile)
               != preimage["execution_isolation_dependency_id"]):
        raise ValueError("deployment attestation execution-isolation profile binding is stale")
    if (root_profile["root_store_profile_id"] != preimage["root_store_profile_id"]
            or root_profile["root_store_schema_sha256"] != preimage["root_store_schema_sha256"]
            or root_profile["root_namespace_acl_profile"]["profile_id"]
               != preimage["root_namespace_acl_profile_id"]
            or root_profile["acceptance_profile"]["profile_id"]
               != preimage["acceptance_profile_id"]):
        raise ValueError("deployment attestation root subordinate profiles do not match")
    if derive_root_store_profile_id(
            schema_sha256=preimage["root_store_schema_sha256"],
            acl_profile_id=preimage["root_namespace_acl_profile_id"],
    ) != preimage["root_store_profile_id"]:
        raise ValueError("deployment attestation root-store profile identity is inconsistent")
    if derive_root_anchor_id({
            "repository": "RayZhang2024/autonomous-dev-control-plane",
            "root_store_profile": preimage["root_store_profile_id"],
            "design_lineage": "issue-55-g9-completion-repair-v0.5",
            "namespace": "autodev-v2-first-genesis-root",
    }) != fence["root_anchor_id"]:
        raise ValueError("deployment attestation anchor/profile binding is inconsistent")
    if (preimage["root_anchor_id"] != fence["root_anchor_id"]
            or substrate_profile["service_principal"]["sid"]
               != preimage["substrate_service"]["sid"]
            or preimage["recovery_fence_inventory"] != [
                substrate_profile["external_recovery_endpoint"]["endpoint_id"]]):
        raise ValueError("deployment attestation root/substrate identity closure is inconsistent")
    if preimage["production_github_mutation_credentials"] != "NONE":
        raise ValueError("deployment attestation contains prohibited production credentials")
    if preimage["shared_runtime_read_only"] is not True:
        raise ValueError("deployment attestation does not prove a read-only shared runtime")
    _require_exact_true_map(preimage["cross_role_private_write_denial"], {"T", "C", "P", "M"})
    _require_exact_true_map(preimage["candidate_root_store_write_denial"], {"T", "C", "P", "M"})
    if not _is_exact_utc(preimage["observed_at"]):
        raise ValueError("deployment attestation timestamp is not canonical UTC")
    roles = preimage["roles"]
    role_fields = {
        "sid", "token_type", "administrator", "pid", "ppid", "candidate_package_id",
        "runtime_sha256", "entrypoint_identity", "security_context_identity", "wiring_identity",
        "endpoint_identity", "private_directory", "destination_channel_credentials", "runtime_type",
        "runtime_role_identity", "runtime_binding_id", "runtime_active", "canonical_state",
    }
    if type(roles) is not dict or set(roles) != {"T", "C", "P", "M"}:
        raise ValueError("deployment attestation role set is not exact")
    for role, value in roles.items():
        expected_role_type = {
            "T": "TrustedControllerRuntime", "C": "ControlStateGateRuntime",
            "P": "PublicationGateRuntime", "M": "MergeGateRuntime",
        }[role]
        if (type(value) is not dict or set(value) != role_fields
                or value["candidate_package_id"] != fence["candidate_package_id"]
                or value["runtime_sha256"] != fence["runtime_artifact_sha256"]
                or value["security_context_identity"]
                   != fence[f"security_context_{role.lower()}_identity"]
                or type(value["sid"]) is not str or not value["sid"]
                or type(value["pid"]) is not int or value["pid"] <= 0
                or value["token_type"] != 1 or value["administrator"] is not False
                or value["runtime_type"] != expected_role_type
                or value["runtime_active"] is not (role in ("T", "C"))
                or value["destination_channel_credentials"]
                   != ("NONE" if role == "T" else "ROLE_LOCAL_ONLY")
                or not all(_digest(value[key]) for key in (
                    "entrypoint_identity", "security_context_identity", "wiring_identity",
                    "endpoint_identity", "runtime_role_identity", "runtime_binding_id"))):
            raise ValueError(f"deployment attestation role {role} is incomplete or stale")
    isolation_principals = isolation_profile["role_principals"]
    if (type(isolation_principals) is not list
            or {item.get("role"): item.get("sid") for item in isolation_principals
                if type(item) is dict}
               != {role: roles[role]["sid"] for role in ("T", "C", "P", "M")}):
        raise ValueError("deployment attestation role SIDs differ from execution-isolation profile")
    observations = preimage["process_instance_observations"]
    process_fields = {
        "role", "pid", "creation_time_100ns", "sid", "token_type", "administrator",
        "deployment_session_id", "security_context_identity", "entrypoint_identity",
        "wiring_identity", "endpoint_identity", "runtime_role_identity", "runtime_binding_id",
        "process_instance_id",
    }
    if type(observations) is not dict or set(observations) != {"S", "T", "C", "P", "M"}:
        raise ValueError("deployment attestation lacks exact S/T/C/P/M process observations")
    process_ids: set[int] = set()
    for role, value in observations.items():
        if (type(value) is not dict or set(value) != process_fields or value["role"] != role
                or value["deployment_session_id"] != session_id
                or type(value["pid"]) is not int or value["pid"] <= 0
                or value["pid"] in process_ids or type(value["creation_time_100ns"]) is not int
                or value["creation_time_100ns"] <= 0 or value["token_type"] != 1
                or value["administrator"] is not False
                or type(value["sid"]) is not str or not value["sid"]
                or not all(_digest(value[key]) for key in (
                    "security_context_identity", "entrypoint_identity", "wiring_identity",
                    "endpoint_identity", "runtime_role_identity", "runtime_binding_id"))):
            raise ValueError(f"deployment attestation process observation for {role} is malformed")
        process_subject = {key: item for key, item in value.items() if key != "process_instance_id"}
        expected_process_id = hashlib.sha256(
            b"autodev.g9-process-instance/v1\0" + canonical_json_bytes(process_subject)
        ).hexdigest()
        if value["process_instance_id"] != expected_process_id:
            raise ValueError(f"deployment attestation process instance {role} has a stale identity")
        process_ids.add(value["pid"])
        if role != "S":
            role_evidence = roles[role]
            for key in ("pid", "sid", "security_context_identity", "entrypoint_identity",
                        "wiring_identity", "endpoint_identity", "runtime_role_identity",
                        "runtime_binding_id"):
                if value[key] != role_evidence[key]:
                    raise ValueError(f"deployment attestation process and role {role} facts differ")
    service = preimage["substrate_service"]
    if (type(service) is not dict or set(service) != {
            "sid", "token_type", "administrator", "pid", "endpoint_identity",
            "implementation_identity", "configuration_identity", "working_directory",
    } or service["sid"] != observations["S"]["sid"]
            or service["pid"] != observations["S"]["pid"]
            or service["token_type"] != observations["S"]["token_type"]
            or service["administrator"] is not observations["S"]["administrator"]
            or service["endpoint_identity"] != observations["S"]["endpoint_identity"]
            or not all(_digest(service[key]) for key in (
                "endpoint_identity", "implementation_identity", "configuration_identity"))
            or type(service["working_directory"]) is not str or not service["working_directory"]):
        raise ValueError("deployment attestation substrate service does not bind S process identity")
    if (service["sid"] != substrate_profile["service_principal"]["sid"]
            or service["implementation_identity"] != next(
                (item["sha256"] for item in substrate_profile["implementation_material"]
                 if item["path"] == "tools/genesis/fixture_substrate.py"), None)
            or service["configuration_identity"]
               != hashlib.sha256(canonical_json_bytes(substrate_profile)).hexdigest()
            or preimage["host_profile_id"] != derive_host_profile_id(
                root_fence_profile_sha256=preimage["root_fence_profile_sha256"],
                fixture_substrate_profile_sha256=preimage["fixture_substrate_profile_sha256"],
                execution_isolation_profile_sha256=preimage["execution_isolation_profile_sha256"],
            )):
        raise ValueError("deployment attestation host/profile identity is stale")
    recovery = preimage["recovery_fence_inventory"]
    if (type(recovery) is not list or not recovery
            or recovery != sorted(set(recovery))
            or any(type(item) is not str or not item for item in recovery)):
        raise ValueError("deployment attestation recovery-fence inventory is not exact")
    root_observation = preimage["root_state_observation"]
    root_fields = {
        "status", "root_anchor_id", "candidate_package_id", "manifest_id",
        "root_state_row_count", "capability_fence_row_count", "fence_id", "fence_state",
        "fence_revision", "capability_fence", "acceptance_history_count",
        "acceptance_history_digest", "applicable_acceptance_for_this_deployment_session",
        "deployment_session_id", "initialization_record_count", "release_verification_count",
        "schema_sha256",
    }
    if (type(root_observation) is not dict or set(root_observation) != root_fields
            or root_observation["status"] != "UNINITIALIZED"
            or root_observation["root_anchor_id"] != fence["root_anchor_id"]
            or root_observation["candidate_package_id"] != fence["candidate_package_id"]
            or root_observation["manifest_id"] != fence["manifest_id"]
            or root_observation["deployment_session_id"] != session_id
            or root_observation["root_state_row_count"] != 0
            or root_observation["capability_fence_row_count"] != 1
            or root_observation["fence_id"] != fence["fence_id"]
            or root_observation["fence_state"] != "FENCED"
            or root_observation["fence_revision"] != 0
            or root_observation["capability_fence"] != fence
            or type(root_observation["acceptance_history_count"]) is not int
            or root_observation["acceptance_history_count"] < 0
            or not _digest(root_observation["acceptance_history_digest"])
            or root_observation["applicable_acceptance_for_this_deployment_session"] is not None
            or root_observation["initialization_record_count"] != 0
            or root_observation["release_verification_count"] != 0
            or root_observation["schema_sha256"] != ROOT_STORE_SCHEMA_SHA256):
        raise ValueError("deployment attestation root observation is not exact pre-acceptance state")
    endpoints = preimage["protected_endpoint_state"]
    endpoint_expectations = {
        "C_WRITER": ("prepared_endpoint_c_identity",),
        "P_PUBLICATION": ("prepared_endpoint_p_identity",),
        "M_MERGE": ("prepared_endpoint_m_identity",),
    }
    if type(endpoints) is not dict or set(endpoints) != set(endpoint_expectations):
        raise ValueError("deployment attestation protected endpoint set is not exact")
    for name, (field,) in endpoint_expectations.items():
        item = endpoints[name]
        if (type(item) is not dict or set(item) != {"state", "identity", "credential_withheld"}
                or item["state"] != "FENCED" or item["identity"] != fence[field]
                or item["credential_withheld"] is not True):
            raise ValueError("deployment attestation protected endpoint binding is stale")
    material = preimage["staged_external_material"]
    if (type(material) is not list or not material
            or any(type(item) is not dict or set(item) != {"path", "sha256"}
                   or type(item["path"]) is not str or not item["path"]
                   or not _digest(item["sha256"]) for item in material)
            or [item["path"] for item in material] != sorted({item["path"] for item in material})):
        raise ValueError("deployment attestation staged material is not exact")
    expected_material: dict[str, str] = {}
    for collection in (
        root_profile["root_admin_tool_material"], root_profile["fence_controller_material"],
        substrate_profile["implementation_material"], isolation_profile["role_interpreter_modules"],
    ):
        for item in collection:
            path, digest = item["path"], item["sha256"]
            if path in expected_material and expected_material[path] != digest:
                raise ValueError("deployment attestation profiles disagree on staged source bytes")
            expected_material[path] = digest
    if material != [{"path": path, "sha256": expected_material[path]}
                    for path in sorted(expected_material)]:
        raise ValueError("deployment attestation staged material differs from bound profiles")
    controller = preimage["external_root_controller_identity"]
    if (type(controller) is not dict
            or set(controller) != {"implementation_sha256", "configuration_sha256"}
            or controller != derive_external_root_controller_identity(root_profile)):
        raise ValueError("deployment attestation root-controller identity is not the exact bound controller")
    return record["record_id"]


def build_deployment_attestation(preimage: dict[str, object], fence_row: dict[str, object],
                                 deployment_session_id: str) -> dict[str, object]:
    """Content-address a supplied Stage-B evidence preimage and verify its closed bindings."""
    fence = _validate_fence_row(fence_row)
    if type(preimage) is not dict or set(preimage) != ATTESTATION_FIELDS:
        raise ValueError("deployment attestation preimage has an open or incomplete field set")
    record = {
        "record_id": hashlib.sha256(canonical_json_bytes(preimage)).hexdigest(),
        "preimage": preimage,
    }
    _validate_deployment_attestation(record, fence, deployment_session_id)
    return record


class RetainedDeploymentSession:
    """In-memory continuity lease retaining the actual S/T/C/P/M process handles.

    The controller creates this object directly from the native launcher results
    and keeps it alive through Acceptance, initialization, and release.  It is
    deliberately not serializable: a PID or reconstructed object cannot restore
    continuity after the controller/session is lost.
    """

    __slots__ = ("deployment_session_id", "_processes", "_captured")

    def __init__(self, deployment_session_id: str, process_instances: dict[str, object]) -> None:
        if (not _digest(deployment_session_id) or type(process_instances) is not dict
                or set(process_instances) != {"S", "T", "C", "P", "M"}):
            raise ValueError("retained deployment session is not the exact S/T/C/P/M set")
        from windows_role_launcher import WindowsRoleProcess
        from windows_substrate_launcher import SubstrateProcess
        captured: dict[str, tuple[object, ...]] = {}
        for role, process in process_instances.items():
            expected_type = SubstrateProcess if role == "S" else WindowsRoleProcess
            if type(process) is not expected_type:
                raise TypeError(f"role {role} is not the exact retained native launcher process type")
            required = ("role", "pid", "sid", "token_type", "is_administrator",
                        "creation_time_100ns", "process_handle", "is_live")
            if any(not hasattr(process, name) for name in required):
                raise ValueError(f"role {role} has no retained native process identity")
            if (process.role != role or type(process.pid) is not int or process.pid <= 0
                    or type(process.sid) is not str or not process.sid
                    or type(process.token_type) is not int or process.token_type != 1
                    or process.is_administrator is not False
                    or type(process.creation_time_100ns) is not int
                    or process.creation_time_100ns <= 0
                    or type(process.process_handle) is not int or process.process_handle <= 0
                    or not callable(process.is_live)):
                raise ValueError(f"role {role} retained process identity is malformed")
            captured[role] = (
                process, process.pid, process.sid, process.token_type,
                process.is_administrator, process.creation_time_100ns,
                process.process_handle,
            )
        if len({item[1] for item in captured.values()}) != 5:
            raise ValueError("retained process set contains duplicate PIDs")
        self.deployment_session_id = deployment_session_id
        self._processes = dict(process_instances)
        self._captured = captured

    def verify(self, attestation: dict[str, object], session_id: str) -> bool:
        if session_id != self.deployment_session_id:
            return False
        try:
            observations = attestation["preimage"]["process_instance_observations"]
            if set(observations) != set(self._processes):
                return False
            for role, captured in self._captured.items():
                process, pid, sid, token_type, administrator, creation, handle = captured
                observation = observations[role]
                if (process is not self._processes[role] or process.pid != pid
                        or process.sid != sid or process.token_type != token_type
                        or process.is_administrator is not administrator
                        or process.creation_time_100ns != creation
                        or process.process_handle != handle
                        or observation["role"] != role or observation["pid"] != pid
                        or observation["sid"] != sid or observation["token_type"] != token_type
                        or observation["administrator"] is not administrator
                        or observation["creation_time_100ns"] != creation
                        or observation["deployment_session_id"] != session_id
                        or process.is_live() is not True):
                    return False
            return True
        except (AttributeError, KeyError, TypeError):
            return False

    def assert_live(self) -> None:
        """Fail closed unless the original exact native process handles remain live."""
        for role, captured in self._captured.items():
            process, pid, sid, token_type, administrator, creation, handle = captured
            if (process is not self._processes[role] or process.pid != pid
                    or process.sid != sid or process.token_type != token_type
                    or process.is_administrator is not administrator
                    or process.creation_time_100ns != creation
                    or process.process_handle != handle or process.is_live() is not True):
                raise PermissionError("retained root-controller process/session continuity was lost")


def append_acceptance(
    path: Path, *, expected_admin_sid: str, approver_account: str,
    acceptance_profile_id: str, expected_fence_row: dict[str, object],
    deployment_attestation: dict[str, object], deployment_session_id: str,
    retained_session: RetainedDeploymentSession,
    explicit_acceptance: bool, expected_acl_sddl: str,
) -> dict[str, object]:
    """Append an immutable Acceptance only for the exact current S/session."""
    _require_external_root_admin(expected_admin_sid)
    if explicit_acceptance is not True or not _is_canonical_path(path):
        raise PermissionError("Acceptance requires explicit external root action at the canonical store")
    fence = _validate_fence_row(expected_fence_row)
    _set_and_verify_root_acl(path.parent, expected_acl_sddl)
    sid = _require_external_root_admin(expected_admin_sid)
    deployment_id = _validate_deployment_attestation(deployment_attestation, fence, deployment_session_id)
    if (type(retained_session) is not RetainedDeploymentSession
            or not retained_session.verify(deployment_attestation, deployment_session_id)):
        raise PermissionError("Acceptance requires the same live retained Stage-B process session")
    if acceptance_profile_id != deployment_attestation["preimage"]["acceptance_profile_id"]:
        raise ValueError("Acceptance profile differs from the exact Stage-B attestation binding")
    preimage = acceptance_preimage(
        acceptance_profile_id=acceptance_profile_id, approver_account=approver_account,
        approver_sid=sid, candidate_package_id=fence["candidate_package_id"],
        genesis_manifest_id=fence["manifest_id"], runtime_artifact_sha256=fence["runtime_artifact_sha256"],
        root_anchor_id=fence["root_anchor_id"], deployment_attestation_id=deployment_id,
        deployment_session_id=deployment_session_id,
    )
    record = _canonical_record(b"autodev.genesis-acceptance/v1\0", preimage, "acceptance_id")
    _confirm_human_action("ACCEPT", acceptance_confirmation_subject(preimage), explicit_acceptance)
    connection = sqlite3.connect(path, isolation_level=None, timeout=2)
    try:
        connection.execute("BEGIN IMMEDIATE")
        _require_external_root_admin(expected_admin_sid)
        _set_and_verify_root_acl(path.parent, expected_acl_sddl)
        _require_exact_uninitialized_fence(connection, fence)
        existing = connection.execute(
            "SELECT acceptance_id, preimage_json, record_json FROM genesis_acceptance "
            "WHERE deployment_attestation_id=?", (deployment_id,),
        ).fetchall()
        if existing:
            existing_record = json.loads(existing[0][2]) if len(existing) == 1 else None
            if (len(existing) != 1
                    or bytes(existing[0][2]) != canonical_json_bytes(existing_record)):
                raise ValueError("conflicting Acceptance already exists for this exact S")
            existing_preimage = _validate_acceptance_record(
                existing_record, expected_fence=fence, expected_session_id=deployment_session_id,
                expected_attestation_id=deployment_id,
                expected_acceptance_profile_id=deployment_attestation["preimage"]["acceptance_profile_id"],
            )
            if (bytes(existing[0][1]) != canonical_json_bytes(existing_preimage)
                    or {key: value for key, value in existing_preimage.items() if key != "accepted_at"} != {
                        key: value for key, value in preimage.items() if key != "accepted_at"}):
                raise ValueError("conflicting Acceptance already exists for this exact S")
            if not retained_session.verify(deployment_attestation, deployment_session_id):
                raise PermissionError("retained Stage-B session changed during Acceptance reconciliation")
            connection.execute("COMMIT")
            return existing_record
        if not retained_session.verify(deployment_attestation, deployment_session_id):
            raise PermissionError("retained Stage-B session changed before Acceptance append")
        connection.execute(
            "INSERT INTO genesis_acceptance(acceptance_id,deployment_attestation_id,deployment_session_id,preimage_json,record_json) "
            "VALUES(?,?,?,?,?)", (record["acceptance_id"], deployment_id, deployment_session_id,
                                 canonical_json_bytes(preimage), canonical_json_bytes(record)),
        )
        connection.execute("COMMIT")
        return record
    except BaseException:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    finally:
        connection.close()


def initialization_operation_id(*, acceptance_id: str, deployment_attestation_id: str,
                                deployment_session_id: str, fence_row: dict[str, object]) -> str:
    fence = _validate_fence_row(fence_row)
    preimage = {"format": "autodev.genesis-root-initialization-operation/v1",
                "acceptance_id": acceptance_id, "deployment_attestation_id": deployment_attestation_id,
                "deployment_session_id": deployment_session_id, "candidate_package_id": fence["candidate_package_id"],
                "genesis_manifest_id": fence["manifest_id"], "root_anchor_id": fence["root_anchor_id"],
                "stable_fenced_row_identity": fence["fence_id"]}
    return hashlib.sha256(b"autodev.genesis-root-initialization-operation/v1\0" +
                          canonical_json_bytes(preimage)).hexdigest()


def release_operation_id(*, initialization_record_id: str, acceptance_id: str,
                         deployment_attestation_id: str, deployment_session_id: str,
                         root_state_identity: str, fence_row: dict[str, object]) -> str:
    fence = _validate_fence_row(fence_row)
    preimage = {"format": "autodev.genesis-release-operation/v1",
                "initialization_record_id": initialization_record_id, "acceptance_id": acceptance_id,
                "deployment_attestation_id": deployment_attestation_id,
                "deployment_session_id": deployment_session_id,
                "candidate_package_id": fence["candidate_package_id"],
                "genesis_manifest_id": fence["manifest_id"], "root_anchor_id": fence["root_anchor_id"],
                "exact_root_state_identity": root_state_identity,
                "stable_fenced_row_identity": fence["fence_id"]}
    return hashlib.sha256(b"autodev.genesis-release-operation/v1\0" +
                          canonical_json_bytes(preimage)).hexdigest()


def _validate_initialization_record(record: object, *, record_id: str, operation_id: str,
                                    acceptance_id: str, deployment_attestation_id: str,
                                    deployment_session_id: str, fence: dict[str, object],
                                    initialized_by: str) -> bool:
    if not _record_is_exact(record, b"autodev.genesis-root-initialization-record/v1\0",
                            "record_id", INITIALIZATION_FIELDS):
        return False
    pre = record["preimage"]
    return (
        record["record_id"] == record_id
        and pre["format"] == INITIALIZATION_FORMAT
        and pre["initialization_operation_id"] == operation_id
        and pre["acceptance_id"] == acceptance_id
        and pre["deployment_attestation_id"] == deployment_attestation_id
        and pre["deployment_session_id"] == deployment_session_id
        and pre["candidate_package_id"] == fence["candidate_package_id"]
        and pre["genesis_manifest_id"] == fence["manifest_id"]
        and pre["root_anchor_id"] == fence["root_anchor_id"]
        and pre["resulting_root_state"] == {
            "format": ROOT_STATE_FORMAT, "root_anchor_id": fence["root_anchor_id"],
            "active_manifest_id": fence["manifest_id"], "transition": "open", "revision": 1,
        }
        and pre["initialized_by"] == initialized_by
        and _is_exact_utc(pre["initialized_at"])
    )


def _validate_release_record(record: object, *, operation_id: str, initialization_record_id: str,
                             acceptance_id: str, deployment_attestation_id: str,
                             deployment_session_id: str, fence: dict[str, object],
                             root_state_identity: str, live_observation: dict[str, object],
                             released_by: str) -> bool:
    """Check exact durable release evidence for a same-operation read-only retry."""
    if not _record_is_exact(record, b"autodev.genesis-release-verification/v1\0",
                            "release_verification_id", RELEASE_FIELDS):
        return False
    pre = record["preimage"]
    released_fence = dict(fence, state="RELEASED", revision=1)
    return (
        pre["format"] == RELEASE_FORMAT
        and pre["release_operation_id"] == operation_id
        and pre["initialization_record_id"] == initialization_record_id
        and pre["acceptance_id"] == acceptance_id
        and pre["deployment_attestation_id"] == deployment_attestation_id
        and pre["deployment_session_id"] == deployment_session_id
        and pre["candidate_package_id"] == fence["candidate_package_id"]
        and pre["genesis_manifest_id"] == fence["manifest_id"]
        and pre["runtime_artifact_sha256"] == fence["runtime_artifact_sha256"]
        and pre["root_anchor_id"] == fence["root_anchor_id"]
        and pre["root_state_identity"] == root_state_identity
        and pre["pre_release_fence_identity"] == fence_row_identity(fence)
        and pre["process_instance_identities"] == live_observation["process_instance_identities"]
        and pre["external_material_identities"] == live_observation["external_material_identities"]
        and pre["protected_effect_denial_observation"]
            == live_observation["protected_effect_denial_observation"]
        and pre["pre_release_fence_identity"] == fence_row_identity(fence)
        and pre["resulting_release_fence_identity"] == fence_row_identity(released_fence)
        and pre["released_by"] == released_by
        and _is_exact_utc(pre["released_at"])
    )


def _require_exact_uninitialized_fence(connection: sqlite3.Connection, expected: dict[str, object]) -> None:
    if not _schema_is_exact(connection):
        raise ValueError("canonical root schema is not exact")
    root_count = connection.execute("SELECT COUNT(*) FROM root_state").fetchone()[0]
    rows = connection.execute("SELECT " + ",".join(FENCE_BINDING_FIELDS) + " FROM capability_fence").fetchall()
    actual = [dict(zip(FENCE_BINDING_FIELDS, row)) for row in rows]
    if root_count != 0 or len(actual) != 1 or _validate_fence_row(actual[0]) != expected:
        raise ValueError("canonical root is not exact uninitialized CP-bound FENCED/0 state")
    if (connection.execute("SELECT COUNT(*) FROM genesis_root_initialization").fetchone()[0] != 0
            or connection.execute("SELECT COUNT(*) FROM genesis_release_verification").fetchone()[0] != 0):
        raise ValueError("uninitialized root contains conflicting initialization/release history")


def initialize_genesis_state(
    path: Path, *, expected_admin_sid: str, expected_fence_row: dict[str, object],
    acceptance_id: str, deployment_attestation: dict[str, object], deployment_session_id: str,
    explicit_initialization: bool, retained_session: RetainedDeploymentSession,
    expected_acl_sddl: str,
) -> dict[str, object]:
    """Atomically initialize G/open/rev1 plus immutable exact provenance, while FENCED/0."""
    if explicit_initialization is not True:
        raise PermissionError("root initialization requires explicit human action")
    if not _is_canonical_path(path):
        raise PermissionError("root-admin mutations are restricted to the canonical root DB")
    _set_and_verify_root_acl(path.parent, expected_acl_sddl)
    sid = _require_external_root_admin(expected_admin_sid)
    fence = _validate_fence_row(expected_fence_row)
    deployment_id = _validate_deployment_attestation(deployment_attestation, fence, deployment_session_id)
    if (type(retained_session) is not RetainedDeploymentSession
            or not retained_session.verify(deployment_attestation, deployment_session_id)):
        raise PermissionError("live Stage-B retained process session is not current")
    operation_id = initialization_operation_id(
        acceptance_id=acceptance_id, deployment_attestation_id=deployment_id,
        deployment_session_id=deployment_session_id, fence_row=fence,
    )
    _confirm_human_action("INITIALIZE", operation_id, explicit_initialization)
    connection = sqlite3.connect(path, isolation_level=None, timeout=2)
    try:
        connection.execute("BEGIN IMMEDIATE")
        if not _schema_is_exact(connection):
            raise ValueError("canonical root schema is not exact")
        existing_roots = connection.execute(
            "SELECT format,root_anchor_id,active_manifest_id,transition,revision FROM root_state"
        ).fetchall()
        if existing_roots:
            expected_root_state = (ROOT_STATE_FORMAT, fence["root_anchor_id"],
                                   fence["manifest_id"], "open", 1)
            rows = connection.execute(
                "SELECT " + ",".join(FENCE_BINDING_FIELDS) + " FROM capability_fence"
            ).fetchall()
            actual_fences = [dict(zip(FENCE_BINDING_FIELDS, row)) for row in rows]
            accepts = connection.execute(
                "SELECT preimage_json,record_json FROM genesis_acceptance WHERE acceptance_id=? "
                "AND deployment_attestation_id=? AND deployment_session_id=?",
                (acceptance_id, deployment_id, deployment_session_id),
            ).fetchall()
            initializations = connection.execute(
                "SELECT record_id,preimage_json,record_json FROM genesis_root_initialization "
                "WHERE initialization_operation_id=?",
                (operation_id,),
            ).fetchall()
            if (existing_roots != [expected_root_state] or len(actual_fences) != 1
                    or _validate_fence_row(actual_fences[0]) != fence
                    or len(accepts) != 1 or len(initializations) != 1
                    or connection.execute("SELECT COUNT(*) FROM genesis_root_initialization").fetchone()[0] != 1):
                raise ValueError("pre-existing root state conflicts with exact initialization reconciliation")
            acceptance_pre, acceptance_rec = json.loads(accepts[0][0]), json.loads(accepts[0][1])
            if (not _record_is_exact(acceptance_rec, b"autodev.genesis-acceptance/v1\0",
                                     "acceptance_id", ACCEPTANCE_FIELDS)
                    or acceptance_rec["acceptance_id"] != acceptance_id
                    or bytes(accepts[0][0]) != canonical_json_bytes(acceptance_pre)
                    or bytes(accepts[0][1]) != canonical_json_bytes(acceptance_rec)
                    or acceptance_pre != acceptance_rec["preimage"]):
                raise ValueError("Acceptance record is malformed or identity-inconsistent")
            _validate_acceptance_record(
                acceptance_rec, expected_fence=fence, expected_session_id=deployment_session_id,
                expected_attestation_id=deployment_id,
                expected_acceptance_profile_id=deployment_attestation["preimage"]["acceptance_profile_id"],
            )
            init_record_id, init_pre_bytes, init_rec_bytes = initializations[0]
            init_pre, init_rec = json.loads(init_pre_bytes), json.loads(init_rec_bytes)
            if (not _record_is_exact(init_rec, b"autodev.genesis-root-initialization-record/v1\0",
                                     "record_id", INITIALIZATION_FIELDS)
                    or init_rec["record_id"] != init_record_id
                    or bytes(init_pre_bytes) != canonical_json_bytes(init_pre)
                    or bytes(init_rec_bytes) != canonical_json_bytes(init_rec)
                    or init_pre != init_rec["preimage"]
                    or not _validate_initialization_record(
                        init_rec, record_id=init_record_id, operation_id=operation_id,
                        acceptance_id=acceptance_id, deployment_attestation_id=deployment_id,
                        deployment_session_id=deployment_session_id, fence=fence,
                        initialized_by=sid)):
                raise ValueError("initialization provenance conflicts with exact operation reconciliation")
            root_state = {"format": ROOT_STATE_FORMAT, "root_anchor_id": fence["root_anchor_id"],
                          "active_manifest_id": fence["manifest_id"], "transition": "open", "revision": 1}
            root_state_id = hashlib.sha256(b"autodev.g9-root-state-identity/v1\0" +
                                           canonical_json_bytes(root_state)).hexdigest()
            connection.execute("COMMIT")
            return {"result": "ALREADY_INITIALIZED_EXACT", "root_state": root_state,
                    "root_state_identity": root_state_id,
                    "initialization_record": init_rec, "fence_state": "FENCED", "fence_revision": 0}
        _require_exact_uninitialized_fence(connection, fence)
        selected = connection.execute(
            "SELECT preimage_json, record_json FROM genesis_acceptance WHERE acceptance_id=? "
            "AND deployment_attestation_id=? AND deployment_session_id=?",
            (acceptance_id, deployment_id, deployment_session_id),
        ).fetchall()
        if len(selected) != 1:
            raise ValueError("exact current Acceptance is absent")
        acceptance_pre = json.loads(selected[0][0])
        acceptance_rec = json.loads(selected[0][1])
        if (not _record_is_exact(acceptance_rec, b"autodev.genesis-acceptance/v1\0", "acceptance_id",
                                 ACCEPTANCE_FIELDS)
                or acceptance_rec["acceptance_id"] != acceptance_id
                or bytes(selected[0][0]) != canonical_json_bytes(acceptance_pre)
                or bytes(selected[0][1]) != canonical_json_bytes(acceptance_rec)
                or acceptance_pre != acceptance_rec["preimage"]):
            raise ValueError("Acceptance record is malformed or identity-inconsistent")
        _validate_acceptance_record(
            acceptance_rec, expected_fence=fence, expected_session_id=deployment_session_id,
            expected_attestation_id=deployment_id,
            expected_acceptance_profile_id=deployment_attestation["preimage"]["acceptance_profile_id"],
        )
        if not retained_session.verify(deployment_attestation, deployment_session_id):
            raise PermissionError("live Stage-B session was lost before root initialization")
        root_state = {"format": ROOT_STATE_FORMAT, "root_anchor_id": fence["root_anchor_id"],
                      "active_manifest_id": fence["manifest_id"], "transition": "open", "revision": 1}
        root_state_id = hashlib.sha256(b"autodev.g9-root-state-identity/v1\0" +
                                       canonical_json_bytes(root_state)).hexdigest()
        preimage = {
            "format": INITIALIZATION_FORMAT, "initialization_operation_id": operation_id,
            "acceptance_id": acceptance_id, "deployment_attestation_id": deployment_id,
            "deployment_session_id": deployment_session_id,
            "candidate_package_id": fence["candidate_package_id"],
            "genesis_manifest_id": fence["manifest_id"], "root_anchor_id": fence["root_anchor_id"],
            "resulting_root_state": root_state, "initialized_by": sid, "initialized_at": _now_utc(),
        }
        record = _canonical_record(b"autodev.genesis-root-initialization-record/v1\0",
                                   preimage, "record_id")
        connection.execute(
            "INSERT INTO root_state(format,root_anchor_id,active_manifest_id,transition,revision) "
            "VALUES(?,?,?,'open',1)", (ROOT_STATE_FORMAT, fence["root_anchor_id"], fence["manifest_id"]),
        )
        connection.execute(
            "INSERT INTO genesis_root_initialization(record_id,initialization_operation_id,acceptance_id,"
            "deployment_attestation_id,deployment_session_id,preimage_json,record_json) VALUES(?,?,?,?,?,?,?)",
            (record["record_id"], operation_id, acceptance_id, deployment_id, deployment_session_id,
             canonical_json_bytes(preimage), canonical_json_bytes(record)),
        )
        # Verify both sides of the atomic pair from SQLite before making the
        # transaction visible.  A malformed/partial write must never commit.
        root_readback = connection.execute(
            "SELECT format,root_anchor_id,active_manifest_id,transition,revision FROM root_state"
        ).fetchall()
        init_readback = connection.execute(
            "SELECT record_id,initialization_operation_id,acceptance_id,deployment_attestation_id,"
            "deployment_session_id,preimage_json,record_json FROM genesis_root_initialization"
        ).fetchall()
        if (root_readback != [(ROOT_STATE_FORMAT, fence["root_anchor_id"], fence["manifest_id"], "open", 1)]
                or len(init_readback) != 1):
            raise ValueError("atomic initialization pair failed exact transaction read-back")
        stored_id, stored_op, stored_a, stored_s, stored_session, stored_pre, stored_record = init_readback[0]
        if (stored_id != record["record_id"] or stored_op != operation_id
                or stored_a != acceptance_id or stored_s != deployment_id
                or stored_session != deployment_session_id
                or bytes(stored_pre) != canonical_json_bytes(preimage)
                or bytes(stored_record) != canonical_json_bytes(record)):
            raise ValueError("atomic initialization provenance failed exact transaction read-back")
        connection.execute("COMMIT")
        return {"result": "INITIALIZED", "root_state": root_state,
                "root_state_identity": root_state_id, "initialization_record": record,
                "fence_state": "FENCED", "fence_revision": 0}
    except BaseException:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    finally:
        connection.close()


def release_capability_fence(
    path: Path, *, expected_admin_sid: str, expected_fence_row: dict[str, object],
    acceptance_id: str, initialization_record_id: str,
    deployment_attestation: dict[str, object], deployment_session_id: str,
    live_observation: dict[str, object], explicit_release: bool,
    retained_session: RetainedDeploymentSession, expected_acl_sddl: str,
) -> dict[str, object]:
    """Freshly verify one live session, then atomically release and seal its proof."""
    if explicit_release is not True or not _is_canonical_path(path):
        raise PermissionError("release requires explicit external root action at canonical store")
    _set_and_verify_root_acl(path.parent, expected_acl_sddl)
    sid = _require_external_root_admin(expected_admin_sid)
    fence = _validate_fence_row(expected_fence_row)
    deployment_id = _validate_deployment_attestation(deployment_attestation, fence, deployment_session_id)
    if not _verify_live_observation(
            live_observation, fence, deployment_session_id, deployment_attestation):
        raise ValueError("fresh live deployment observation does not match frozen Stage-B identities")
    if (type(retained_session) is not RetainedDeploymentSession
            or not retained_session.verify(deployment_attestation, deployment_session_id)):
        raise PermissionError("retained deployment process/session is not live")
    expected_root_state = {"format": ROOT_STATE_FORMAT, "root_anchor_id": fence["root_anchor_id"],
                           "active_manifest_id": fence["manifest_id"], "transition": "open", "revision": 1}
    expected_root_state_identity = hashlib.sha256(
        b"autodev.g9-root-state-identity/v1\0" + canonical_json_bytes(expected_root_state)
    ).hexdigest()
    expected_release_operation_id = release_operation_id(
        initialization_record_id=initialization_record_id, acceptance_id=acceptance_id,
        deployment_attestation_id=deployment_id, deployment_session_id=deployment_session_id,
        root_state_identity=expected_root_state_identity, fence_row=fence,
    )
    expected_initialization_operation_id = initialization_operation_id(
        acceptance_id=acceptance_id, deployment_attestation_id=deployment_id,
        deployment_session_id=deployment_session_id, fence_row=fence,
    )
    connection = sqlite3.connect(path, isolation_level=None, timeout=2)
    try:
        connection.execute("BEGIN IMMEDIATE")
        _require_external_root_admin(expected_admin_sid)
        _set_and_verify_root_acl(path.parent, expected_acl_sddl)
        if not _schema_is_exact(connection):
            raise ValueError("canonical root schema is not exact")
        roots = connection.execute("SELECT format,root_anchor_id,active_manifest_id,transition,revision FROM root_state").fetchall()
        if roots != [(ROOT_STATE_FORMAT, fence["root_anchor_id"], fence["manifest_id"], "open", 1)]:
            raise ValueError("release requires exact G/open/revision-1 root state")
        fences = connection.execute("SELECT " + ",".join(FENCE_BINDING_FIELDS) + " FROM capability_fence").fetchall()
        if len(fences) != 1:
            raise ValueError("release requires exactly one stable CP-bound fence row")
        stored_fence = _validate_fence_row(
            dict(zip(FENCE_BINDING_FIELDS, fences[0])), require_fenced=False,
        )
        released_fence = dict(fence, state="RELEASED", revision=1)
        if stored_fence == released_fence:
            # A retry is read-only and recognized only by the exact stable
            # operation id, durable RELEASED/1 postcondition, and immutable
            # record whose full live/session provenance still matches.
            init_rows = connection.execute(
                "SELECT record_id,preimage_json,record_json FROM genesis_root_initialization "
                "WHERE record_id=? AND initialization_operation_id=? AND acceptance_id=? "
                "AND deployment_attestation_id=? AND deployment_session_id=?",
                (initialization_record_id, expected_initialization_operation_id, acceptance_id,
                 deployment_id, deployment_session_id),
            ).fetchall()
            accepts = connection.execute(
                "SELECT preimage_json,record_json FROM genesis_acceptance WHERE acceptance_id=? "
                "AND deployment_attestation_id=? AND deployment_session_id=?",
                (acceptance_id, deployment_id, deployment_session_id),
            ).fetchall()
            release_rows = connection.execute(
                "SELECT release_verification_id,release_operation_id,initialization_record_id,acceptance_id,"
                "deployment_attestation_id,deployment_session_id,preimage_json,record_json "
                "FROM genesis_release_verification WHERE release_operation_id=?",
                (expected_release_operation_id,),
            ).fetchall()
            if (len(init_rows) != 1 or len(accepts) != 1 or len(release_rows) != 1
                    or connection.execute("SELECT COUNT(*) FROM genesis_root_initialization").fetchone()[0] != 1
                    or connection.execute("SELECT COUNT(*) FROM genesis_release_verification").fetchone()[0] != 1):
                raise ValueError("RELEASED/1 state lacks exact initialization, Acceptance, or release provenance")
            init_id, init_pre_bytes, init_rec_bytes = init_rows[0]
            init_pre, init_rec = json.loads(init_pre_bytes), json.loads(init_rec_bytes)
            if (not _record_is_exact(init_rec, b"autodev.genesis-root-initialization-record/v1\0",
                                     "record_id", INITIALIZATION_FIELDS)
                    or init_id != initialization_record_id or init_rec["record_id"] != initialization_record_id
                    or bytes(init_pre_bytes) != canonical_json_bytes(init_pre)
                    or bytes(init_rec_bytes) != canonical_json_bytes(init_rec)
                    or init_pre != init_rec["preimage"]
                    or not _validate_initialization_record(
                        init_rec, record_id=initialization_record_id,
                        operation_id=expected_initialization_operation_id,
                        acceptance_id=acceptance_id, deployment_attestation_id=deployment_id,
                        deployment_session_id=deployment_session_id, fence=fence,
                        initialized_by=deployment_attestation["preimage"]["root_fence_profile"]
                            ["root_admin_principal"]["sid"])):
                raise ValueError("RELEASED/1 initialization record does not match the exact operation")
            acceptance_pre, acceptance_record = json.loads(accepts[0][0]), json.loads(accepts[0][1])
            if (bytes(accepts[0][0]) != canonical_json_bytes(acceptance_pre)
                    or bytes(accepts[0][1]) != canonical_json_bytes(acceptance_record)
                    or acceptance_pre != acceptance_record.get("preimage")
                    or acceptance_record.get("acceptance_id") != acceptance_id):
                raise ValueError("RELEASED/1 Acceptance record is malformed")
            _validate_acceptance_record(
                acceptance_record, expected_fence=fence, expected_session_id=deployment_session_id,
                expected_attestation_id=deployment_id,
                expected_acceptance_profile_id=deployment_attestation["preimage"]["acceptance_profile_id"],
            )
            (release_record_id, stored_operation_id, stored_init_id, stored_acceptance_id,
             stored_deployment_id, stored_session_id, release_pre_bytes, release_record_bytes) = release_rows[0]
            release_pre, release_record = json.loads(release_pre_bytes), json.loads(release_record_bytes)
            if (release_record.get("release_verification_id") != release_record_id
                    or stored_operation_id != expected_release_operation_id
                    or stored_init_id != initialization_record_id or stored_acceptance_id != acceptance_id
                    or stored_deployment_id != deployment_id or stored_session_id != deployment_session_id
                    or bytes(release_pre_bytes) != canonical_json_bytes(release_pre)
                    or bytes(release_record_bytes) != canonical_json_bytes(release_record)
                    or release_pre != release_record.get("preimage")
                    or not _validate_release_record(
                        release_record, operation_id=expected_release_operation_id,
                        initialization_record_id=initialization_record_id, acceptance_id=acceptance_id,
                        deployment_attestation_id=deployment_id, deployment_session_id=deployment_session_id,
                        fence=fence, root_state_identity=expected_root_state_identity,
                        live_observation=live_observation, released_by=sid)):
                raise ValueError("RELEASED/1 release-verification record is not the exact completed operation")
            if not retained_session.verify(deployment_attestation, deployment_session_id) or not _verify_live_observation(
                    live_observation, fence, deployment_session_id, deployment_attestation):
                raise PermissionError("live deployment session changed during release reconciliation")
            connection.execute("COMMIT")
            return {"result": "ALREADY_RELEASED_EXACT", "fence_state": "RELEASED", "fence_revision": 1,
                    "release_verification": release_record}
        if stored_fence != fence:
            raise ValueError("release requires exact stable CP-bound FENCED/0 row")
        if (connection.execute("SELECT COUNT(*) FROM genesis_root_initialization").fetchone()[0] != 1
                or connection.execute("SELECT COUNT(*) FROM genesis_release_verification").fetchone()[0] != 0):
            raise ValueError("first-genesis release requires exactly one initialization and no prior release")
        init_rows = connection.execute(
            "SELECT record_id, preimage_json, record_json FROM genesis_root_initialization "
            "WHERE record_id=? AND acceptance_id=? AND deployment_attestation_id=? AND deployment_session_id=?",
            (initialization_record_id, acceptance_id, deployment_id, deployment_session_id),
        ).fetchall()
        if len(init_rows) != 1:
            raise ValueError("exact root-initialization provenance is absent")
        init_pre, init_rec = json.loads(init_rows[0][1]), json.loads(init_rows[0][2])
        if (not _record_is_exact(init_rec, b"autodev.genesis-root-initialization-record/v1\0",
                                 "record_id", INITIALIZATION_FIELDS)
                or bytes(init_rows[0][1]) != canonical_json_bytes(init_pre)
                or bytes(init_rows[0][2]) != canonical_json_bytes(init_rec)
                or init_rec["record_id"] != initialization_record_id
                or init_pre != init_rec["preimage"]
                or not _validate_initialization_record(
                    init_rec, record_id=initialization_record_id,
                    operation_id=expected_initialization_operation_id,
                    acceptance_id=acceptance_id, deployment_attestation_id=deployment_id,
                    deployment_session_id=deployment_session_id, fence=fence,
                    initialized_by=deployment_attestation["preimage"]["root_fence_profile"]
                        ["root_admin_principal"]["sid"])):
            raise ValueError("root-initialization provenance is malformed")
        accepts = connection.execute(
            "SELECT preimage_json,record_json FROM genesis_acceptance WHERE acceptance_id=? "
            "AND deployment_attestation_id=? AND deployment_session_id=?",
            (acceptance_id, deployment_id, deployment_session_id),
        ).fetchall()
        if len(accepts) != 1:
            raise ValueError("exact Acceptance for the live deployment session is absent")
        acceptance_pre = json.loads(accepts[0][0])
        acceptance_rec = json.loads(accepts[0][1])
        if (not _record_is_exact(acceptance_rec, b"autodev.genesis-acceptance/v1\0",
                                 "acceptance_id", ACCEPTANCE_FIELDS)
                or bytes(accepts[0][0]) != canonical_json_bytes(acceptance_pre)
                or bytes(accepts[0][1]) != canonical_json_bytes(acceptance_rec)
                or acceptance_pre != acceptance_rec["preimage"]):
            raise ValueError("Acceptance evidence is malformed")
        _validate_acceptance_record(
            acceptance_rec, expected_fence=fence, expected_session_id=deployment_session_id,
            expected_attestation_id=deployment_id,
            expected_acceptance_profile_id=deployment_attestation["preimage"]["acceptance_profile_id"],
        )
        root_state = {"format": ROOT_STATE_FORMAT, "root_anchor_id": fence["root_anchor_id"],
                      "active_manifest_id": fence["manifest_id"], "transition": "open", "revision": 1}
        root_state_id = hashlib.sha256(b"autodev.g9-root-state-identity/v1\0" +
                                       canonical_json_bytes(root_state)).hexdigest()
        released = dict(fence, state="RELEASED", revision=1)
        preimage = {
            "format": RELEASE_FORMAT,
            "release_operation_id": release_operation_id(
                initialization_record_id=initialization_record_id, acceptance_id=acceptance_id,
                deployment_attestation_id=deployment_id, deployment_session_id=deployment_session_id,
                root_state_identity=root_state_id, fence_row=fence),
            "initialization_record_id": initialization_record_id, "acceptance_id": acceptance_id,
            "deployment_attestation_id": deployment_id, "deployment_session_id": deployment_session_id,
            "candidate_package_id": fence["candidate_package_id"], "genesis_manifest_id": fence["manifest_id"],
            "runtime_artifact_sha256": fence["runtime_artifact_sha256"], "root_anchor_id": fence["root_anchor_id"],
            "root_state_identity": root_state_id,
            "pre_release_fence_identity": fence_row_identity(fence),
            "process_instance_identities": live_observation["process_instance_identities"],
            "external_material_identities": live_observation["external_material_identities"],
            "protected_effect_denial_observation": live_observation["protected_effect_denial_observation"],
            "resulting_release_fence_identity": fence_row_identity(released),
            "released_by": sid, "released_at": _now_utc(),
        }
        if set(preimage) != set(RELEASE_FIELDS):
            raise AssertionError("frozen release record field set drift")
        record = _canonical_record(b"autodev.genesis-release-verification/v1\0",
                                   preimage, "release_verification_id")
        _confirm_human_action("RELEASE", preimage["release_operation_id"], explicit_release)
        # Session/process freshness is sampled immediately before the CAS.
        if not retained_session.verify(deployment_attestation, deployment_session_id) or not _verify_live_observation(
                live_observation, fence, deployment_session_id, deployment_attestation):
            raise PermissionError("live deployment session changed before release linearization")
        cursor = connection.execute(
            "UPDATE capability_fence SET state='RELEASED',revision=1 WHERE fence_id=? "
            "AND state='FENCED' AND revision=0", (fence["fence_id"],),
        )
        if cursor.rowcount != 1:
            raise ValueError("exact FENCED/0 row changed before release")
        connection.execute(
            "INSERT INTO genesis_release_verification(release_verification_id,release_operation_id,"
            "initialization_record_id,acceptance_id,deployment_attestation_id,deployment_session_id,"
            "preimage_json,record_json) VALUES(?,?,?,?,?,?,?,?)",
            (record["release_verification_id"], preimage["release_operation_id"],
             initialization_record_id, acceptance_id, deployment_id, deployment_session_id,
             canonical_json_bytes(preimage), canonical_json_bytes(record)),
        )
        # Verify the FENCED/0 -> RELEASED/1 CAS and its immutable provenance
        # together from the same transaction before committing either fact.
        fence_readback = connection.execute(
            "SELECT " + ",".join(FENCE_BINDING_FIELDS) + " FROM capability_fence"
        ).fetchall()
        release_readback = connection.execute(
            "SELECT release_verification_id,release_operation_id,initialization_record_id,acceptance_id,"
            "deployment_attestation_id,deployment_session_id,preimage_json,record_json "
            "FROM genesis_release_verification"
        ).fetchall()
        expected_released = dict(fence, state="RELEASED", revision=1)
        if (len(fence_readback) != 1
                or _validate_fence_row(dict(zip(FENCE_BINDING_FIELDS, fence_readback[0])),
                                       require_fenced=False) != expected_released
                or len(release_readback) != 1):
            raise ValueError("atomic release pair failed exact transaction read-back")
        (stored_record_id, stored_operation_id, stored_init_id, stored_acceptance_id,
         stored_deployment_id, stored_session_id, stored_preimage, stored_record) = release_readback[0]
        if (stored_record_id != record["release_verification_id"]
                or stored_operation_id != expected_release_operation_id
                or stored_init_id != initialization_record_id or stored_acceptance_id != acceptance_id
                or stored_deployment_id != deployment_id or stored_session_id != deployment_session_id
                or bytes(stored_preimage) != canonical_json_bytes(preimage)
                or bytes(stored_record) != canonical_json_bytes(record)):
            raise ValueError("atomic release provenance failed exact transaction read-back")
        connection.execute("COMMIT")
        return {"result": "RELEASED", "fence_state": "RELEASED", "fence_revision": 1,
                "release_verification": record}
    except BaseException:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    finally:
        connection.close()


def _verify_live_observation(value: object, fence: dict[str, object], session_id: str,
                             deployment_attestation: dict[str, object]) -> bool:
    required = {"deployment_session_id", "deployment_attestation_id", "candidate_package_id",
                "genesis_manifest_id", "runtime_artifact_sha256", "root_anchor_id",
                "root_profile_identities", "security_context_identities", "role_bindings",
                "process_instance_identities", "external_material_identities",
                "substrate_endpoint_identity", "protected_effect_denial_observation"}
    if type(value) is not dict or set(value) != required:
        return False
    if any(value[field] != expected for field, expected in (
        ("deployment_session_id", session_id), ("candidate_package_id", fence["candidate_package_id"]),
        ("genesis_manifest_id", fence["manifest_id"]),
        ("runtime_artifact_sha256", fence["runtime_artifact_sha256"]),
        ("root_anchor_id", fence["root_anchor_id"]),
    )):
        return False
    if not _digest(value["deployment_attestation_id"]):
        return False
    attestation = deployment_attestation["preimage"]
    identities = value["security_context_identities"]
    expected_contexts = {role: fence[f"security_context_{role.lower()}_identity"]
                         for role in ("T", "C", "P", "M")}
    if type(identities) is not dict or identities != expected_contexts:
        return False
    expected_roles = attestation["roles"]
    role_bindings = value["role_bindings"]
    role_binding_fields = {
        "security_context_identity", "entrypoint_identity", "wiring_identity",
        "endpoint_identity", "runtime_role_identity", "runtime_binding_id",
    }
    if type(role_bindings) is not dict or set(role_bindings) != {"T", "C", "P", "M"}:
        return False
    for role in ("T", "C", "P", "M"):
        if (type(role_bindings[role]) is not dict or set(role_bindings[role]) != role_binding_fields
                or any(role_bindings[role][field] != expected_roles[role][field]
                       for field in role_binding_fields)):
            return False
    expected_processes = {
        role: item["process_instance_id"]
        for role, item in attestation["process_instance_observations"].items()
    }
    process_ids = value["process_instance_identities"]
    if type(process_ids) is not dict or process_ids != expected_processes:
        return False
    expected_material = {item["path"]: item["sha256"] for item in attestation["staged_external_material"]}
    if value["external_material_identities"] != expected_material:
        return False
    service = attestation["substrate_service"]
    if value["substrate_endpoint_identity"] != service["endpoint_identity"]:
        return False
    expected_profiles = {
        "root_store_profile_id": attestation["root_store_profile_id"],
        "root_namespace_acl_profile_id": attestation["root_namespace_acl_profile_id"],
        "acceptance_profile_id": attestation["acceptance_profile_id"],
        "root_fence_dependency_id": attestation["root_fence_dependency_id"],
        "execution_isolation_dependency_id": attestation["execution_isolation_dependency_id"],
        "fixture_substrate_dependency_id": attestation["fixture_substrate_dependency_id"],
        "root_anchor_id": fence["root_anchor_id"],
    }
    if value["root_profile_identities"] != expected_profiles:
        return False
    denial = value["protected_effect_denial_observation"]
    return (type(denial) is dict and set(denial) == {
                "p_target_fence_state", "m_target_fence_state",
                "p_protected_effect_denied", "m_protected_effect_denied",
                "candidate_root_store_write_denied", "candidate_fence_release_denied",
                "production_github_mutation_credentials",
            }
            and denial["p_target_fence_state"] == "FENCED"
            and denial["m_target_fence_state"] == "FENCED"
            and denial["p_protected_effect_denied"] is True
            and denial["m_protected_effect_denied"] is True
            and denial["candidate_root_store_write_denied"] is True
            and denial["candidate_fence_release_denied"] is True
            and denial["production_github_mutation_credentials"] == "NONE")


def _confirm_human_action(action: str, subject_digest: str, authorized: bool) -> None:
    if authorized is not True or not sys.stdin.isatty():
        raise PermissionError("external root operation requires interactive local human confirmation")
    if not _digest(subject_digest):
        raise ValueError("human confirmation subject digest is malformed")
    expected = f"{action} {subject_digest}"
    print(f"Type exactly: {expected}")
    if input().strip() != expected:
        raise PermissionError("external root operation confirmation did not match")


def _set_and_verify_root_acl(namespace: Path, expected_sddl: str) -> None:
    """Set/verify the content-bound protected root namespace ACL on Windows."""
    if sys.platform != "win32" or type(expected_sddl) is not str or not expected_sddl.startswith("O:"):
        raise PermissionError("bound Windows root ACL profile is required")
    advapi, kernel = ctypes.WinDLL("advapi32", use_last_error=True), ctypes.WinDLL("kernel32", use_last_error=True)
    descriptor = ctypes.c_void_p()
    convert = advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW
    convert.argtypes = [ctypes.c_wchar_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_void_p),
                        ctypes.POINTER(ctypes.c_ulong)]
    convert.restype = ctypes.c_int
    # Set and read the exact protected owner/group/DACL only. PROTECTED and
    # UNPROTECTED are opposing inheritance controls and must never be combined.
    flags = _ROOT_ACL_SECURITY_INFORMATION
    to_sddl = advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW
    to_sddl.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong,
                        ctypes.POINTER(ctypes.c_wchar_p), ctypes.POINTER(ctypes.c_ulong)]
    to_sddl.restype = ctypes.c_int
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    if not convert(expected_sddl, 1, ctypes.byref(descriptor), None):
        raise ctypes.WinError(ctypes.get_last_error())
    expected_normalized = ctypes.c_wchar_p()
    expected_chars = ctypes.c_ulong()
    try:
        if not to_sddl(descriptor, 1, flags, ctypes.byref(expected_normalized),
                       ctypes.byref(expected_chars)):
            raise ctypes.WinError(ctypes.get_last_error())
        normalized_sddl = expected_normalized.value
        kernel.LocalFree(expected_normalized)
        expected_normalized = ctypes.c_wchar_p()
        set_security = advapi.SetFileSecurityW
        set_security.argtypes = [ctypes.c_wchar_p, ctypes.c_ulong, ctypes.c_void_p]
        set_security.restype = ctypes.c_int
        if not set_security(str(namespace), flags, descriptor):
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        if expected_normalized:
            kernel.LocalFree(expected_normalized)
        kernel.LocalFree.argtypes = [ctypes.c_void_p]
        kernel.LocalFree.restype = ctypes.c_void_p
        kernel.LocalFree(descriptor)
    needed = ctypes.c_ulong()
    advapi.GetFileSecurityW.argtypes = [ctypes.c_wchar_p, ctypes.c_ulong, ctypes.c_void_p,
                                        ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
    advapi.GetFileSecurityW.restype = ctypes.c_int
    advapi.GetFileSecurityW(str(namespace), flags, None, 0, ctypes.byref(needed))
    if not needed.value:
        raise ctypes.WinError(ctypes.get_last_error())
    buffer = ctypes.create_string_buffer(needed.value)
    if not advapi.GetFileSecurityW(str(namespace), flags, buffer, needed.value, ctypes.byref(needed)):
        raise ctypes.WinError(ctypes.get_last_error())
    actual = ctypes.c_wchar_p()
    out_chars = ctypes.c_ulong()
    if not to_sddl(buffer, 1, flags, ctypes.byref(actual), ctypes.byref(out_chars)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        if actual.value != normalized_sddl:
            raise PermissionError("canonical root namespace ACL differs from its bound profile")
    finally:
        kernel.LocalFree(actual)


def _current_token_facts() -> tuple[str, bool, bool, bool]:
    """Read TokenUser, primary type, elevation, and enabled non-deny-only Admin SID."""
    if sys.platform != "win32":
        raise PermissionError("external root administration requires Windows")
    advapi, kernel = ctypes.WinDLL("advapi32", use_last_error=True), ctypes.WinDLL("kernel32", use_last_error=True)
    token = ctypes.c_void_p()
    kernel.GetCurrentProcess.restype = ctypes.c_void_p
    advapi.OpenProcessToken.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_void_p)]
    advapi.OpenProcessToken.restype = ctypes.c_int
    advapi.GetTokenInformation.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p,
                                           ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
    advapi.GetTokenInformation.restype = ctypes.c_int
    advapi.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_wchar_p)]
    advapi.ConvertSidToStringSidW.restype = ctypes.c_int
    advapi.ConvertStringSidToSidW.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_void_p)]
    advapi.ConvertStringSidToSidW.restype = ctypes.c_int
    advapi.EqualSid.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    advapi.EqualSid.restype = ctypes.c_int
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel.CloseHandle.restype = ctypes.c_int
    if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 0x0008, ctypes.byref(token)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        def token_buffer(info_class: int) -> ctypes.Array:
            needed = ctypes.c_ulong()
            advapi.GetTokenInformation(token, info_class, None, 0, ctypes.byref(needed))
            if not needed.value:
                raise ctypes.WinError(ctypes.get_last_error())
            buf = ctypes.create_string_buffer(needed.value)
            if not advapi.GetTokenInformation(token, info_class, buf, needed.value, ctypes.byref(needed)):
                raise ctypes.WinError(ctypes.get_last_error())
            return buf
        user = token_buffer(1)
        sid_ptr = ctypes.cast(user, ctypes.POINTER(ctypes.c_void_p)).contents.value
        sid_text = ctypes.c_wchar_p()
        if not advapi.ConvertSidToStringSidW(sid_ptr, ctypes.byref(sid_text)):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            sid = sid_text.value
        finally:
            kernel.LocalFree(sid_text)
        token_type = token_buffer(8)
        elevation = token_buffer(20)
        primary = ctypes.cast(token_type, ctypes.POINTER(ctypes.c_ulong)).contents.value == 1
        elevated = bool(ctypes.cast(elevation, ctypes.POINTER(ctypes.c_ulong)).contents.value)
        groups = token_buffer(2)
        token_groups = ctypes.cast(groups, ctypes.POINTER(_TokenGroups)).contents
        count = token_groups.group_count
        group_ptr = ctypes.cast(ctypes.addressof(groups) + _TokenGroups.groups.offset,
                                ctypes.POINTER(_SidAndAttributes))
        admin_sid = ctypes.c_void_p()
        if not advapi.ConvertStringSidToSidW("S-1-5-32-544", ctypes.byref(admin_sid)):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            enabled = any(advapi.EqualSid(group_ptr[i].sid, admin_sid)
                          and _group_attributes_are_enabled_admin(group_ptr[i].attributes)
                          for i in range(count))
        finally:
            kernel.LocalFree(admin_sid)
        return sid, primary, elevated, enabled
    finally:
        kernel.CloseHandle(token)


def _current_token_identity() -> tuple[str, bool]:
    """Return exact SID and conjunction of the frozen elevated-primary-admin facts."""
    sid, primary, elevated, enabled_admin = _current_token_facts()
    return sid, bool(primary and elevated and enabled_admin)


def _require_external_root_admin(expected_admin_sid: str) -> str:
    if not _is_hex_sid(expected_admin_sid):
        raise PermissionError("expected external root-admin SID is invalid")
    actual_sid, is_elevated_admin = _current_token_identity()
    if actual_sid != expected_admin_sid or not is_elevated_admin:
        raise PermissionError("caller is not the profile-bound elevated external root administrator")
    return actual_sid


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only G9 root-state inspection")
    parser.add_argument("--database", type=Path, default=ROOT_STORE_PATH)
    parser.add_argument("--fence-json", type=Path, required=True)
    parser.add_argument("--deployment-session-id", required=True)
    args = parser.parse_args()
    try:
        evidence = inspect_uninitialized_root(
            args.database, expected_fence_row=json.loads(args.fence_json.read_bytes()),
            deployment_session_id=args.deployment_session_id,
        )
    except Exception as exc:
        print(json.dumps({"status": "FAILED_CLOSED", "failure_type": type(exc).__name__},
                         sort_keys=True, separators=(",", ":")))
        return 2
    print(json.dumps(evidence, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
