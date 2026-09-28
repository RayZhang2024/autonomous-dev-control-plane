"""Closed, content-addressed identities for the external G9 boundary.

This module is external-TCB build tooling. It is deliberately not included in
the 26-module candidate runtime. It contains no credentials and performs no
host or root-store mutation.
"""

from __future__ import annotations

import hashlib
import json
from typing import Mapping


ROOT_ANCHOR_DOMAIN = b"autodev.g9-root-trust-anchor/v1\0"
ROOT_FENCE_DOMAIN = b"autodev.g9-root-activation-fence-dependency/v1\0"
FIXTURE_SUBSTRATE_DOMAIN = b"autodev.g9-fixture-effect-substrate-dependency/v1\0"
ROOT_STORE_PROFILE_DOMAIN = b"autodev.g9-canonical-root-store-profile/v2\0"
ACL_PROFILE_DOMAIN = b"autodev.g9-root-namespace-acl-profile/v1\0"
ACCEPTANCE_PROFILE_DOMAIN = b"autodev.g9-acceptance-profile/v1\0"
EXECUTION_ISOLATION_DOMAIN = b"autodev.g9-execution-isolation-dependency/v1\0"
HOST_PROFILE_DOMAIN = b"autodev.g9-host-profile/v1\0"
ROOT_STORE_PROFILE_NAME = "autodev.g9-canonical-root-store/v1"
_EXECUTION_PROFILE_FIELDS = (
    "format", "host_profile", "role_principals", "python_runtime", "staging_profile",
    "channel_profile", "external_adapter_material", "role_interpreter_modules",
    "production_github_mutation_credentials",
)
EXECUTION_ISOLATION_PROFILE_FIELDS = _EXECUTION_PROFILE_FIELDS
_EXECUTION_RECORD_FIELDS = {
    "host_profile": ("profile_id", "platform", "architecture", "domain"),
    "python_runtime": ("identity", "version", "path", "sha256"),
    "staging_profile": (
        "profile_id", "root", "shared_role_access", "shared_operator_administrator_system_access",
        "private_role_access", "root_store_role_access", "external_fence_release",
    ),
    "channel_profile": (
        "profile_id", "format", "directions", "destination_credentials",
        "controller_destination_credentials", "cross_role_messages",
    ),
}
_EXECUTION_ROLES = ("T", "C", "P", "M")

ROOT_ANCHOR_FIELDS = frozenset({
    "repository", "root_store_profile", "design_lineage", "namespace",
})
ROOT_FENCE_FIELDS = frozenset({
    "format", "repository", "design_lineage", "root_anchor_namespace",
    "root_store_profile", "root_store_profile_id", "root_store_schema_sha256",
    "root_namespace_acl_profile", "acceptance_profile", "root_admin_tool_material",
    "fence_controller_material", "python_runtime", "root_admin_principal",
    "canonical_root_store", "candidate_role_access", "capability_release_authority",
    "production_github_mutation_credentials",
})
SUBSTRATE_FIELDS = frozenset({
    "format", "implementation_material", "f_read_verify_endpoint",
    "publication_authority_endpoint", "merge_authority_endpoint", "p_target_fence",
    "m_target_fence", "target_fence_namespace", "external_recovery_endpoint",
    "service_principal", "role_exposure", "production_github_mutation_credentials",
})
_MATERIAL_FIELDS = ("path", "sha256")
_IDENTITY_FIELDS = ("identity", "version", "path", "sha256")
_PRINCIPAL_FIELDS = ("account", "sid", "administrator")
_STORE_FIELDS = ("profile_id", "path")
_ENDPOINT_FIELDS = ("endpoint_id", "transport", "authority")
_FENCE_FIELDS = ("fence_id", "namespace", "endpoint_id", "initial_state")
_SERVICE_PRINCIPAL_FIELDS = ("account", "sid", "token_type", "administrator")
_ROLE_EXPOSURE = {
    "T": ["F_READ_VERIFY"],
    "C": ["F_READ_VERIFY"],
    "P": ["F_READ_VERIFY", "P_TARGET_FENCE", "PUBLICATION_AUTHORITY"],
    "M": ["F_READ_VERIFY", "M_TARGET_FENCE", "MERGE_AUTHORITY"],
    "ORDINARY": [],
}


def canonical_json_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _closed_record(value: object, fields: frozenset[str] | tuple[str, ...]) -> bool:
    return type(value) is dict and set(value) == set(fields)


def _valid_digest(value: object) -> bool:
    return (type(value) is str and len(value) == 64
            and all(char in "0123456789abcdef" for char in value))


def _is_sid(value: object) -> bool:
    return type(value) is str and value.startswith("S-1-") and all(
        part.isdecimal() for part in value.split("-")[1:]
    )


def derive_root_namespace_acl_profile_id(profile: dict[str, object]) -> str:
    if type(profile) is not dict or set(profile) != {
            "format", "security_descriptor_sddl", "root_admin_sid", "substrate_sid",
            "system_sid", "candidate_role_sids", "inherited_acl", "candidate_role_access"}:
        raise ValueError("root ACL profile is not closed")
    if (profile["format"] != "autodev.g9-root-namespace-acl-profile/v1"
            or type(profile["security_descriptor_sddl"]) is not str
            or not profile["security_descriptor_sddl"].startswith("O:")
            or not _is_sid(profile["root_admin_sid"]) or not _is_sid(profile["substrate_sid"])
            or profile["system_sid"] != "S-1-5-18"
            or type(profile["candidate_role_sids"]) is not dict
            or set(profile["candidate_role_sids"]) != {"T", "C", "P", "M"}
            or any(not _is_sid(sid) for sid in profile["candidate_role_sids"].values())
            or set(profile["candidate_role_sids"].values()) & {
                profile["root_admin_sid"], profile["substrate_sid"], "S-1-5-18"}
            or profile["inherited_acl"] != "DENY"
            or profile["candidate_role_access"] != "NO_ACCESS"):
        raise ValueError("root ACL profile semantics are invalid")
    return _sha256(ACL_PROFILE_DOMAIN + canonical_json_bytes(profile))


def derive_acceptance_profile_id(profile: dict[str, object]) -> str:
    if type(profile) is not dict or set(profile) != {
            "format", "authority_model", "eligible_bootstrap_approver", "authentication_method",
            "acceptance_record_format", "acceptance_storage", "decision_domain", "validity_model",
            "interactive_confirmation", "acceptance_tool_material",
            "production_github_mutation_credentials"}:
        raise ValueError("Genesis Acceptance profile is not closed")
    approver = profile["eligible_bootstrap_approver"]
    if (type(approver) is not dict or set(approver) != {"account", "sid", "administrator_required"}
            or type(approver["account"]) is not str or not approver["account"]
            or not _is_sid(approver["sid"]) or approver["administrator_required"] is not True):
        raise ValueError("Genesis Acceptance eligible approver is invalid")
    _validate_material(profile["acceptance_tool_material"])
    if (profile["format"] != "autodev.g9-acceptance-profile/v1"
            or profile["authority_model"] != "WINDOWS_EXTERNAL_ROOT_AUTHORITY"
            or profile["authentication_method"] != "CURRENT_PROCESS_PRIMARY_TOKEN_EXACT_SID_ELEVATED_ADMIN"
            or profile["acceptance_record_format"] != "autodev.genesis-acceptance-record/v1"
            or profile["acceptance_storage"] != "CANONICAL_ROOT_DB_APPEND_ONLY"
            or profile["decision_domain"] != "GENESIS_BOOTSTRAP"
            or profile["validity_model"] != "IDENTITY_AND_SESSION_BOUND_NO_TIME_TTL"
            or profile["interactive_confirmation"] != "LOCAL_CONSOLE_EXACT_SUBJECT_CONFIRMATION"
            or profile["production_github_mutation_credentials"] != "NONE"):
        raise ValueError("Genesis Acceptance profile semantics are invalid")
    return _sha256(ACCEPTANCE_PROFILE_DOMAIN + canonical_json_bytes(profile))


def derive_root_store_profile_id(*, schema_sha256: str, acl_profile_id: str,
                                 acceptance_profile_id: str) -> str:
    if not all(_valid_digest(value) for value in
               (schema_sha256, acl_profile_id, acceptance_profile_id)):
        raise ValueError("root-store profile inputs are malformed")
    preimage = {
        "format": ROOT_STORE_PROFILE_NAME, "schema_sha256": schema_sha256,
        "canonical_path": r"C:\AutodevG9\root\root.sqlite3",
        "storage_semantics": "SQLITE_CREATE_IF_ABSENT_IMMEDIATE_TRANSACTIONS_APPEND_ONLY_HISTORY_V2",
        "root_namespace_acl_profile_id": acl_profile_id,
        "acceptance_profile_id": acceptance_profile_id,
    }
    return _sha256(ROOT_STORE_PROFILE_DOMAIN + canonical_json_bytes(preimage))


def _validate_material(value: object) -> None:
    if type(value) is not list or not value:
        raise ValueError("external material must be a non-empty list")
    paths: list[str] = []
    for item in value:
        if not _closed_record(item, _MATERIAL_FIELDS):
            raise ValueError("external material record has an open field set")
        if (type(item["path"]) is not str or not item["path"] or "\\" in item["path"]
                or item["path"].startswith("/") or ".." in item["path"].split("/")):
            raise ValueError("external material path is invalid")
        if not _valid_digest(item["sha256"]):
            raise ValueError("external material digest is invalid")
        paths.append(item["path"])
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        raise ValueError("external material must be uniquely sorted by path")


def derive_root_anchor_id(preimage: dict[str, object]) -> str:
    """Derive the deterministic public anchor ID from its exact closed tuple."""
    if not _closed_record(preimage, ROOT_ANCHOR_FIELDS):
        raise ValueError("root-anchor identity preimage has an open field set")
    if any(type(preimage[field]) is not str or not preimage[field]
           for field in ROOT_ANCHOR_FIELDS):
        raise ValueError("root-anchor identity preimage has an invalid value")
    if preimage["repository"] != "RayZhang2024/autonomous-dev-control-plane":
        raise ValueError("root-anchor repository identity is not the frozen repository")
    return _sha256(ROOT_ANCHOR_DOMAIN + canonical_json_bytes(preimage))


def derive_execution_isolation_dependency_id(profile: dict[str, object]) -> str:
    """Validate and content-address the closed role-isolation dependency profile."""
    if type(profile) is not dict or set(profile) != set(_EXECUTION_PROFILE_FIELDS):
        raise ValueError("execution-isolation profile has an open field set")
    if profile["format"] != "autodev.g9-execution-isolation-profile/v1":
        raise ValueError("execution-isolation profile format is unsupported")
    for field, expected_fields in _EXECUTION_RECORD_FIELDS.items():
        value = profile[field]
        if type(value) is not dict or set(value) != set(expected_fields):
            raise ValueError(f"execution-isolation {field} has an open field set")
        non_direction_values = (
            [item for key, item in value.items() if key != "directions"]
            if field == "channel_profile" else list(value.values())
        )
        if any(type(item) is not str or not item for item in non_direction_values):
            raise ValueError(f"execution-isolation {field} contains an invalid value")
    principals = profile["role_principals"]
    if (type(principals) is not list or len(principals) != 4
            or tuple(item.get("role") for item in principals if type(item) is dict) != _EXECUTION_ROLES
            or any(type(item) is not dict
                   or set(item) != {"role", "account", "sid", "token_type", "administrator"}
                   or any(type(item[key]) is not str or not item[key]
                          for key in ("role", "account", "sid", "token_type"))
                   or type(item["administrator"]) is not bool for item in principals)):
        raise ValueError("execution-isolation role-principal set is not closed")
    if profile["production_github_mutation_credentials"] != "NONE":
        raise ValueError("execution-isolation profile admits production GitHub credentials")
    adapters = profile["external_adapter_material"]
    if (type(adapters) is not list or len(adapters) != 7
            or any(type(item) is not dict or set(item) != {"path", "sha256"} for item in adapters)):
        raise ValueError("execution-isolation adapter material is not closed")
    expected_paths = tuple(sorted({
        "tools/genesis/ipc.py", "tools/genesis/role_worker.py",
        "tools/genesis/windows_role_launcher.py", "tools/genesis/windows_role_runner.py",
        "tools/genesis/role_adapter.py", "tools/genesis/substrate_client.py",
        "tools/genesis/canonical_state_channel.py",
    }))
    if tuple(item["path"] for item in adapters) != expected_paths:
        raise ValueError("execution-isolation adapter material has unexpected paths or order")
    if any(not _valid_digest(item["sha256"]) for item in adapters):
        raise ValueError("execution-isolation adapter material digest is invalid")
    modules = profile["role_interpreter_modules"]
    expected_modules = (
        ("ipc", "IMPORTED", "tools/genesis/ipc.py"),
        ("role_worker", "SCRIPT", "tools/genesis/role_worker.py"),
        ("role_adapter", "IMPORTED", "tools/genesis/role_adapter.py"),
        ("substrate_client", "IMPORTED", "tools/genesis/substrate_client.py"),
        ("canonical_state_channel", "IMPORTED", "tools/genesis/canonical_state_channel.py"),
    )
    if (type(modules) is not list or len(modules) != len(expected_modules)
            or any(type(item) is not dict
                   or set(item) != {"module_name", "execution", "path", "sha256"} for item in modules)):
        raise ValueError("execution-isolation role-interpreter module set is not closed")
    for item, expected in zip(modules, expected_modules, strict=True):
        if (tuple(item[key] for key in ("module_name", "execution", "path")) != expected
                or item["sha256"] != next(record["sha256"] for record in adapters
                                           if record["path"] == item["path"])):
            raise ValueError("execution-isolation module identity is not bound to adapter material")
    if (type(profile["channel_profile"].get("directions")) is not list
            or not all(type(direction) is str for direction in profile["channel_profile"]["directions"])):
        raise ValueError("execution-isolation channel direction set is invalid")
    return "dep-execution-isolation-" + _sha256(
        EXECUTION_ISOLATION_DOMAIN + canonical_json_bytes(profile)
    )


def derive_host_profile_id(*, root_fence_profile_sha256: str,
                           fixture_substrate_profile_sha256: str,
                           execution_isolation_profile_sha256: str) -> str:
    identities = (root_fence_profile_sha256, fixture_substrate_profile_sha256,
                  execution_isolation_profile_sha256)
    if not all(_valid_digest(item) for item in identities):
        raise ValueError("host profile external-profile identities are malformed")
    return _sha256(HOST_PROFILE_DOMAIN + canonical_json_bytes({
        "format": "autodev.g9-host-profile/v1",
        "root_fence_profile_sha256": root_fence_profile_sha256,
        "fixture_substrate_profile_sha256": fixture_substrate_profile_sha256,
        "execution_isolation_profile_sha256": execution_isolation_profile_sha256,
    }))


def validate_root_fence_profile(profile: dict[str, object]) -> str:
    """Validate the exact external fence profile and return its dependency ID."""
    if not _closed_record(profile, ROOT_FENCE_FIELDS):
        raise ValueError("root-fence profile has an open field set")
    if profile["format"] != "autodev.g9-root-activation-fence-profile/v1":
        raise ValueError("root-fence profile format is unsupported")
    for name in ("repository", "design_lineage", "root_anchor_namespace",
                 "root_store_profile", "root_store_profile_id", "capability_release_authority"):
        if type(profile[name]) is not str or not profile[name]:
            raise ValueError(f"root-fence {name} is invalid")
    if profile["repository"] != "RayZhang2024/autonomous-dev-control-plane":
        raise ValueError("root-fence repository identity is not frozen")
    if not _valid_digest(profile["root_store_schema_sha256"]):
        raise ValueError("root-store schema digest is invalid")
    acl = profile["root_namespace_acl_profile"]
    if (type(acl) is not dict or set(acl) != {"profile_id", "security_descriptor_sddl",
            "root_admin_sid", "substrate_sid", "system_sid", "candidate_role_sids"}
            or not _valid_digest(acl["profile_id"])):
        raise ValueError("root namespace ACL identity is not exact")
    acl_semantics = {"format": "autodev.g9-root-namespace-acl-profile/v1",
                     "security_descriptor_sddl": acl["security_descriptor_sddl"],
                     "root_admin_sid": acl["root_admin_sid"], "substrate_sid": acl["substrate_sid"],
                     "system_sid": acl["system_sid"], "candidate_role_sids": acl["candidate_role_sids"],
                     "inherited_acl": "DENY", "candidate_role_access": "NO_ACCESS"}
    if derive_root_namespace_acl_profile_id(acl_semantics) != acl["profile_id"]:
        raise ValueError("root ACL profile ID is stale")
    acceptance = profile["acceptance_profile"]
    acceptance_fields = {"profile_id", "authority_model", "eligible_bootstrap_approver",
                         "authentication_method", "acceptance_record_format", "acceptance_storage",
                         "decision_domain", "validity_model", "interactive_confirmation",
                         "production_github_mutation_credentials"}
    if (type(acceptance) is not dict or set(acceptance) != acceptance_fields
            or not _valid_digest(acceptance["profile_id"])):
        raise ValueError("Genesis Acceptance profile identity is not exact")
    acceptance_preimage = {
        "format": "autodev.g9-acceptance-profile/v1",
        **{key: value for key, value in acceptance.items() if key != "profile_id"},
        "acceptance_tool_material": profile["root_admin_tool_material"],
    }
    if derive_acceptance_profile_id(acceptance_preimage) != acceptance["profile_id"]:
        raise ValueError("Genesis Acceptance profile ID is stale")
    _validate_material(profile["root_admin_tool_material"])
    _validate_material(profile["fence_controller_material"])
    if [item["path"] for item in profile["root_admin_tool_material"]] != [
            "tools/genesis/external_profiles.py", "tools/genesis/root_admin.py"]:
        raise ValueError("root-admin tool source closure is not the exact implementation dependency set")
    if [item["path"] for item in profile["fence_controller_material"]] != [
            "tools/genesis/fence_controller.py"]:
        raise ValueError("fence-controller source closure is not exact")
    runtime = profile["python_runtime"]
    principal = profile["root_admin_principal"]
    store = profile["canonical_root_store"]
    if not _closed_record(runtime, _IDENTITY_FIELDS) or not _valid_digest(runtime["sha256"]):
        raise ValueError("root-admin Python runtime record is invalid")
    if any(type(runtime[key]) is not str or not runtime[key]
           for key in ("identity", "version", "path")):
        raise ValueError("root-admin Python runtime identity is incomplete")
    if not _closed_record(principal, _PRINCIPAL_FIELDS):
        raise ValueError("root-admin principal record is invalid")
    if (type(principal["account"]) is not str or not principal["account"]
            or type(principal["sid"]) is not str or not principal["sid"].startswith("S-1-")
            or principal.get("administrator") is not True):
        raise ValueError("root-admin principal identity is invalid")
    if not _closed_record(store, _STORE_FIELDS):
        raise ValueError("canonical root-store record is invalid")
    if (store["profile_id"] != profile["root_store_profile_id"]
            or store["path"] != r"C:\AutodevG9\root\root.sqlite3"):
        raise ValueError("canonical root-store path/profile is not frozen")
    if profile["root_store_profile"] != ROOT_STORE_PROFILE_NAME:
        raise ValueError("root-store profile name is not frozen")
    if derive_root_store_profile_id(
            schema_sha256=profile["root_store_schema_sha256"], acl_profile_id=acl["profile_id"],
            acceptance_profile_id=acceptance["profile_id"]) != profile["root_store_profile_id"]:
        raise ValueError("root-store profile identity is stale")
    if profile["candidate_role_access"] != "NO_WRITE":
        raise ValueError("candidate roles must have no root-store write access")
    if profile["capability_release_authority"] != "EXTERNAL_ROOT_ADMIN_ONLY":
        raise ValueError("capability release must remain external")
    if profile["production_github_mutation_credentials"] != "NONE":
        raise ValueError("production GitHub mutation credentials are forbidden")
    return "dep-root-activation-fence-" + _sha256(
        ROOT_FENCE_DOMAIN + canonical_json_bytes(profile)
    )


def validate_fixture_substrate_profile(profile: dict[str, object]) -> str:
    """Validate the closed fixture-only substrate profile and derive its ID."""
    if not _closed_record(profile, SUBSTRATE_FIELDS):
        raise ValueError("fixture-substrate profile has an open field set")
    if profile["format"] != "autodev.g9-fixture-effect-substrate-profile/v1":
        raise ValueError("fixture-substrate profile format is unsupported")
    _validate_material(profile["implementation_material"])
    if [item["path"] for item in profile["implementation_material"]] != [
            "tools/genesis/fixture_substrate.py", "tools/genesis/windows_substrate_launcher.py"]:
        raise ValueError("fixture-substrate implementation closure is not exact")
    for name in ("f_read_verify_endpoint", "publication_authority_endpoint",
                 "merge_authority_endpoint", "external_recovery_endpoint"):
        value = profile[name]
        if not _closed_record(value, _ENDPOINT_FIELDS):
            raise ValueError(f"{name} endpoint record has an open field set")
        if any(type(value[field]) is not str or not value[field]
               for field in _ENDPOINT_FIELDS):
            raise ValueError(f"{name} endpoint record is incomplete")
        if value["transport"] != "LOOPBACK_HMAC_JSON":
            raise ValueError("fixture substrate transport must be closed loopback HMAC/JSON")
    for name in ("p_target_fence", "m_target_fence"):
        value = profile[name]
        if not _closed_record(value, _FENCE_FIELDS):
            raise ValueError(f"{name} record has an open field set")
        if any(type(value[field]) is not str or not value[field] for field in _FENCE_FIELDS):
            raise ValueError(f"{name} record is incomplete")
        if value["initial_state"] != "FENCED":
            raise ValueError("target effect fences must begin FENCED")
    if type(profile["target_fence_namespace"]) is not str or not profile["target_fence_namespace"]:
        raise ValueError("target-fence namespace is invalid")
    exposure = profile["role_exposure"]
    if (not _closed_record(exposure, tuple(_ROLE_EXPOSURE))
            or any(type(exposure[role]) is not list for role in _ROLE_EXPOSURE)
            or exposure != _ROLE_EXPOSURE):
        raise ValueError("role-to-endpoint exposure differs from the frozen closed matrix")
    principal = profile["service_principal"]
    if (not _closed_record(principal, _SERVICE_PRINCIPAL_FIELDS)
            or type(principal["account"]) is not str or not principal["account"]
            or type(principal["sid"]) is not str or not principal["sid"].startswith("S-1-")
            or principal["token_type"] != "PRIMARY" or principal["administrator"] is not False):
        raise ValueError("fixture-substrate service principal must be exact, PRIMARY and non-admin")
    if profile["production_github_mutation_credentials"] != "NONE":
        raise ValueError("production GitHub mutation credentials are forbidden")
    return "dep-fixture-effect-substrate-" + _sha256(
        FIXTURE_SUBSTRATE_DOMAIN + canonical_json_bytes(profile)
    )


def source_material(root: str, paths: tuple[str, ...]) -> list[dict[str, str]]:
    """Hash exact external source bytes and return a path-sorted public inventory."""
    from pathlib import Path

    base = Path(root)
    result = [{"path": path, "sha256": _sha256((base / Path(path)).read_bytes())}
              for path in paths]
    result.sort(key=lambda item: item["path"])
    _validate_material(result)
    return result


def build_external_profiles(
    repository_root: str, *, root_admin_principal: dict[str, object],
    substrate_principal: dict[str, object], python_runtime: dict[str, object],
) -> tuple[dict[str, object], dict[str, object], str, tuple[str, str]]:
    """Build closed host-bound external profiles; no credentials enter the result."""
    from pathlib import Path
    from root_admin import ROOT_STORE_SCHEMA_SHA256
    from windows_role_launcher import ROLE_PRINCIPALS

    root = Path(repository_root)
    expected_python = {"identity", "version", "path", "sha256"}
    if not _closed_record(python_runtime, expected_python) or python_runtime["identity"] != "CPython":
        raise ValueError("staged Python runtime identity is not exact")
    root_tools = source_material(root, (
        "tools/genesis/external_profiles.py", "tools/genesis/fence_controller.py",
        "tools/genesis/root_admin.py",
    ))
    substrate_tools = source_material(root, (
        "tools/genesis/fixture_substrate.py", "tools/genesis/windows_substrate_launcher.py",
    ))
    from windows_role_launcher import ROLE_PRINCIPALS
    role_sids = {role: item[1] for role, item in ROLE_PRINCIPALS.items()}
    root_admin_material = [item for item in root_tools
                           if item["path"].endswith(("external_profiles.py", "root_admin.py"))]
    acl_semantics = {
        "format": "autodev.g9-root-namespace-acl-profile/v1",
        "security_descriptor_sddl": (
            f"O:{root_admin_principal['sid']}G:S-1-5-18D:P"
            f"(A;;FA;;;S-1-5-18)(A;;FA;;;{root_admin_principal['sid']})"
            f"(A;;GR;;;{substrate_principal['sid']})"
        ),
        "root_admin_sid": root_admin_principal["sid"], "substrate_sid": substrate_principal["sid"],
        "system_sid": "S-1-5-18", "candidate_role_sids": role_sids,
        "inherited_acl": "DENY", "candidate_role_access": "NO_ACCESS",
    }
    acl_id = derive_root_namespace_acl_profile_id(acl_semantics)
    acceptance_semantics = {
        "format": "autodev.g9-acceptance-profile/v1",
        "authority_model": "WINDOWS_EXTERNAL_ROOT_AUTHORITY",
        "eligible_bootstrap_approver": {
            "account": root_admin_principal["account"], "sid": root_admin_principal["sid"],
            "administrator_required": True,
        },
        "authentication_method": "CURRENT_PROCESS_PRIMARY_TOKEN_EXACT_SID_ELEVATED_ADMIN",
        "acceptance_record_format": "autodev.genesis-acceptance-record/v1",
        "acceptance_storage": "CANONICAL_ROOT_DB_APPEND_ONLY",
        "decision_domain": "GENESIS_BOOTSTRAP",
        "validity_model": "IDENTITY_AND_SESSION_BOUND_NO_TIME_TTL",
        "interactive_confirmation": "LOCAL_CONSOLE_EXACT_SUBJECT_CONFIRMATION",
        "acceptance_tool_material": root_admin_material,
        "production_github_mutation_credentials": "NONE",
    }
    acceptance_id = derive_acceptance_profile_id(acceptance_semantics)
    store_id = derive_root_store_profile_id(schema_sha256=ROOT_STORE_SCHEMA_SHA256,
                                            acl_profile_id=acl_id,
                                            acceptance_profile_id=acceptance_id)
    anchor_preimage = {
        "repository": "RayZhang2024/autonomous-dev-control-plane",
        "root_store_profile": store_id,
        "design_lineage": "issue-55-g9-completion-repair-v0.5",
        "namespace": "autodev-v2-first-genesis-root",
    }
    anchor_id = derive_root_anchor_id(anchor_preimage)
    root_profile: dict[str, object] = {
        "format": "autodev.g9-root-activation-fence-profile/v1",
        "repository": anchor_preimage["repository"],
        "design_lineage": anchor_preimage["design_lineage"],
        "root_anchor_namespace": anchor_preimage["namespace"],
        "root_store_profile": ROOT_STORE_PROFILE_NAME,
        "root_store_profile_id": store_id,
        "root_store_schema_sha256": ROOT_STORE_SCHEMA_SHA256,
        "root_namespace_acl_profile": {
            "profile_id": acl_id,
            "security_descriptor_sddl": acl_semantics["security_descriptor_sddl"],
            "root_admin_sid": acl_semantics["root_admin_sid"],
            "substrate_sid": acl_semantics["substrate_sid"],
            "system_sid": acl_semantics["system_sid"],
            "candidate_role_sids": role_sids,
        },
        "acceptance_profile": {
            "profile_id": acceptance_id,
            **{key: value for key, value in acceptance_semantics.items()
               if key not in ("format", "acceptance_tool_material")},
        },
        "root_admin_tool_material": root_admin_material,
        "fence_controller_material": [item for item in root_tools
                                      if item["path"].endswith("fence_controller.py")],
        "python_runtime": dict(python_runtime),
        "root_admin_principal": dict(root_admin_principal),
        "canonical_root_store": {
            "profile_id": store_id,
            "path": r"C:\AutodevG9\root\root.sqlite3",
        },
        "candidate_role_access": "NO_WRITE",
        "capability_release_authority": "EXTERNAL_ROOT_ADMIN_ONLY",
        "production_github_mutation_credentials": "NONE",
    }
    substrate_profile: dict[str, object] = {
        "format": "autodev.g9-fixture-effect-substrate-profile/v1",
        "implementation_material": substrate_tools,
        "f_read_verify_endpoint": {
            "endpoint_id": "g9-f-read-verify-loopback-v1",
            "transport": "LOOPBACK_HMAC_JSON", "authority": "READ_VERIFY_ONLY",
        },
        "publication_authority_endpoint": {
            "endpoint_id": "g9-publication-authority-loopback-v1",
            "transport": "LOOPBACK_HMAC_JSON", "authority": "PUBLICATION_ONLY",
        },
        "merge_authority_endpoint": {
            "endpoint_id": "g9-merge-authority-loopback-v1",
            "transport": "LOOPBACK_HMAC_JSON", "authority": "MERGE_ONLY",
        },
        "p_target_fence": {
            "fence_id": "g9-p-target-fence-v1", "namespace": "g9-first-genesis-target-fences",
            "endpoint_id": "g9-p-target-loopback-v1", "initial_state": "FENCED",
        },
        "m_target_fence": {
            "fence_id": "g9-m-target-fence-v1", "namespace": "g9-first-genesis-target-fences",
            "endpoint_id": "g9-m-target-loopback-v1", "initial_state": "FENCED",
        },
        "target_fence_namespace": "g9-first-genesis-target-fences",
        "external_recovery_endpoint": {
            "endpoint_id": "g9-start-held-recovery-loopback-v1",
            "transport": "LOOPBACK_HMAC_JSON", "authority": "START_HELD_RECOVERY_ONLY",
        },
        "service_principal": dict(substrate_principal),
        "role_exposure": {role: list(values) for role, values in _ROLE_EXPOSURE.items()},
        "production_github_mutation_credentials": "NONE",
    }
    root_dependency = validate_root_fence_profile(root_profile)
    substrate_dependency = validate_fixture_substrate_profile(substrate_profile)
    role_sids = {identity[1] for identity in ROLE_PRINCIPALS.values()}
    if (root_profile["root_admin_principal"]["sid"] in role_sids
            or substrate_profile["service_principal"]["sid"] in role_sids
            or substrate_profile["service_principal"]["sid"]
            == root_profile["root_admin_principal"]["sid"]):
        raise ValueError("external human/service principals must be distinct from candidate roles")
    return root_profile, substrate_profile, anchor_id, (root_dependency, substrate_dependency)
