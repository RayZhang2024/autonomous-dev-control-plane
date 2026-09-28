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

ROOT_ANCHOR_FIELDS = frozenset({
    "repository", "root_store_profile", "design_lineage", "namespace",
})
ROOT_FENCE_FIELDS = frozenset({
    "format", "repository", "design_lineage", "root_anchor_namespace",
    "root_store_profile", "root_store_schema_sha256", "root_admin_tool_material",
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


def validate_root_fence_profile(profile: dict[str, object]) -> str:
    """Validate the exact external fence profile and return its dependency ID."""
    if not _closed_record(profile, ROOT_FENCE_FIELDS):
        raise ValueError("root-fence profile has an open field set")
    if profile["format"] != "autodev.g9-root-activation-fence-profile/v1":
        raise ValueError("root-fence profile format is unsupported")
    for name in ("repository", "design_lineage", "root_anchor_namespace",
                 "root_store_profile", "capability_release_authority"):
        if type(profile[name]) is not str or not profile[name]:
            raise ValueError(f"root-fence {name} is invalid")
    if profile["repository"] != "RayZhang2024/autonomous-dev-control-plane":
        raise ValueError("root-fence repository identity is not frozen")
    if not _valid_digest(profile["root_store_schema_sha256"]):
        raise ValueError("root-store schema digest is invalid")
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
    if (store["profile_id"] != "autodev.g9-canonical-root-store/v1"
            or store["path"] != r"C:\AutodevG9\root\root.sqlite3"):
        raise ValueError("canonical root-store path/profile is not frozen")
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
            "tools/genesis/fixture_substrate.py", "tools/genesis/role_adapter.py",
            "tools/genesis/windows_role_launcher.py",
            "tools/genesis/windows_substrate_launcher.py"]:
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
        "tools/genesis/fixture_substrate.py", "tools/genesis/role_adapter.py",
        "tools/genesis/windows_role_launcher.py", "tools/genesis/windows_substrate_launcher.py",
    ))
    anchor_preimage = {
        "repository": "RayZhang2024/autonomous-dev-control-plane",
        "root_store_profile": "autodev.g9-canonical-root-store/v1",
        "design_lineage": "issue-55-g9-completion-repair-v0.2",
        "namespace": "autodev-v2-first-genesis-root",
    }
    anchor_id = derive_root_anchor_id(anchor_preimage)
    root_profile: dict[str, object] = {
        "format": "autodev.g9-root-activation-fence-profile/v1",
        "repository": anchor_preimage["repository"],
        "design_lineage": anchor_preimage["design_lineage"],
        "root_anchor_namespace": anchor_preimage["namespace"],
        "root_store_profile": anchor_preimage["root_store_profile"],
        "root_store_schema_sha256": ROOT_STORE_SCHEMA_SHA256,
        "root_admin_tool_material": [item for item in root_tools
                                     if item["path"].endswith(("external_profiles.py", "root_admin.py"))],
        "fence_controller_material": [item for item in root_tools
                                      if item["path"].endswith("fence_controller.py")],
        "python_runtime": dict(python_runtime),
        "root_admin_principal": dict(root_admin_principal),
        "canonical_root_store": {
            "profile_id": "autodev.g9-canonical-root-store/v1",
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
