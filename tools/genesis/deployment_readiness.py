"""Non-authoritative pre-review deployment-readiness record (DR)."""

from __future__ import annotations

import hashlib
from typing import Any

from external_profiles import canonical_json_bytes

FORMAT = "autodev.genesis-deployment-readiness/v1"
_PREIMAGE_FIELDS = frozenset({
    "format", "candidate_package_id", "genesis_manifest_id", "deterministic_evidence_ids",
    "repository_source_commit", "runtime_artifact_sha256", "python_runtime",
    "execution_isolation_dependency_id", "root_fence_dependency_id",
    "root_fence_profile_sha256", "fixture_substrate_dependency_id",
    "fixture_substrate_profile_sha256", "root_anchor_id", "root_state_observation",
    "roles", "staged_external_material", "substrate_service", "shared_runtime_read_only",
    "cross_role_private_write_denial", "candidate_root_store_write_denial",
    "protected_endpoint_state", "recovery_fence_inventory",
    "production_github_mutation_credentials", "host_profile_id", "observed_at",
})
_ROLES = ("T", "C", "P", "M")


def _digest(value: object) -> bool:
    return (type(value) is str and len(value) == 64
            and all(character in "0123456789abcdef" for character in value))


def _exact_true_map(value: object, keys: set[str]) -> bool:
    return type(value) is dict and set(value) == keys and all(item is True for item in value.values())


def build_deployment_readiness(preimage: dict[str, Any]) -> dict[str, Any]:
    """Validate complete CP-bound fenced rehearsal facts and derive DR non-recursively."""
    if type(preimage) is not dict or set(preimage) != _PREIMAGE_FIELDS:
        raise ValueError("deployment-readiness preimage has an open or incomplete field set")
    if preimage["format"] != FORMAT:
        raise ValueError("deployment-readiness format is unsupported")
    for field in ("candidate_package_id", "genesis_manifest_id", "runtime_artifact_sha256",
                  "root_fence_profile_sha256", "fixture_substrate_profile_sha256",
                  "root_anchor_id"):
        if not _digest(preimage[field]):
            raise ValueError(f"deployment-readiness {field} is malformed")
    if not isinstance(preimage["repository_source_commit"], str) or len(preimage["repository_source_commit"]) != 40:
        raise ValueError("deployment-readiness source commit is malformed")
    for field in ("execution_isolation_dependency_id", "root_fence_dependency_id",
                  "fixture_substrate_dependency_id", "host_profile_id", "observed_at"):
        if type(preimage[field]) is not str or not preimage[field]:
            raise ValueError(f"deployment-readiness {field} is invalid")
    evidence_ids = preimage["deterministic_evidence_ids"]
    if (type(evidence_ids) is not list or not evidence_ids
            or any(type(item) is not str or not item for item in evidence_ids)
            or evidence_ids != sorted(set(evidence_ids))):
        raise ValueError("deployment-readiness evidence identity set is not closed/canonical")
    python_runtime = preimage["python_runtime"]
    if (type(python_runtime) is not dict
            or set(python_runtime) != {"identity", "version", "path", "sha256"}
            or python_runtime["identity"] != "CPython" or not _digest(python_runtime["sha256"])
            or any(type(python_runtime[key]) is not str or not python_runtime[key]
                   for key in ("version", "path"))):
        raise ValueError("deployment-readiness CPython identity is invalid")
    root_state = preimage["root_state_observation"]
    if (type(root_state) is not dict or set(root_state) != {
            "status", "root_anchor_id", "candidate_package_id", "root_state_row_count",
            "capability_fence_row_count", "fence_state", "fence_revision", "schema_sha256",
            "observation_scope", "canonical_root_database", "fixture_database_sha256",
    } or root_state["status"] != "UNINITIALIZED"
            or root_state["root_anchor_id"] != preimage["root_anchor_id"]
            or root_state["candidate_package_id"] != preimage["candidate_package_id"]
            or root_state["root_state_row_count"] != 0
            or root_state["capability_fence_row_count"] != 1
            or root_state["fence_state"] != "FENCED" or root_state["fence_revision"] != 0
            or not _digest(root_state["schema_sha256"])
            or root_state["observation_scope"] != "NON_AUTHORITATIVE_TEMPORARY_FIXTURE_ONLY"
            or root_state["canonical_root_database"] != "ABSENT_UNTOUCHED"
            or not _digest(root_state["fixture_database_sha256"])):
        raise ValueError("root observation is not the exact CP-bound uninitialized fenced state")
    roles = preimage["roles"]
    if type(roles) is not dict or set(roles) != set(_ROLES):
        raise ValueError("role evidence is not the exact T/C/P/M set")
    sids: set[str] = set()
    pids: set[int] = set()
    for role in _ROLES:
        record = roles[role]
        if (type(record) is not dict or set(record) != {
                "sid", "token_type", "administrator", "pid", "ppid", "candidate_package_id",
                "runtime_sha256", "entrypoint_identity", "security_context_identity",
                "wiring_identity", "endpoint_identity", "private_directory",
                "destination_channel_credentials", "runtime_type", "runtime_role_identity",
                "runtime_binding_id", "runtime_active",
        }):
            raise ValueError(f"role {role} evidence is not closed")
        if (not isinstance(record["sid"], str) or not record["sid"]
                or record["sid"] in sids or record["token_type"] != 1
                or record["administrator"] is not False
                or type(record["pid"]) is not int or record["pid"] <= 0
                or record["pid"] in pids or type(record["ppid"]) is not int
                or record["candidate_package_id"] != preimage["candidate_package_id"]
                or record["runtime_sha256"] != preimage["runtime_artifact_sha256"]
                or any(not _digest(record[field]) for field in (
                    "entrypoint_identity", "security_context_identity", "wiring_identity", "endpoint_identity",
                    "runtime_role_identity", "runtime_binding_id"))
                or type(record["private_directory"]) is not str or not record["private_directory"]
                or record["runtime_type"] != {
                    "T": "TrustedControllerRuntime", "C": "ControlStateGateRuntime",
                    "P": "PublicationGateRuntime", "M": "MergeGateRuntime",
                }[role]
                or record["runtime_active"] is not (role in ("T", "C"))
                or record["destination_channel_credentials"] != (
                    "NONE" if role == "T" else "ROLE_LOCAL_ONLY")):
            raise ValueError(f"role {role} evidence does not bind a distinct non-admin CP2 process")
        sids.add(record["sid"])
        pids.add(record["pid"])
    if preimage["shared_runtime_read_only"] is not True:
        raise ValueError("shared candidate runtime is not proved read-only")
    if not _exact_true_map(preimage["cross_role_private_write_denial"], set(_ROLES)):
        raise ValueError("cross-role private-write denials are incomplete")
    if not _exact_true_map(preimage["candidate_root_store_write_denial"], set(_ROLES)):
        raise ValueError("candidate root-store write denials are incomplete")
    endpoint_state = preimage["protected_endpoint_state"]
    if (type(endpoint_state) is not dict or set(endpoint_state) != {"C_WRITER", "P_PUBLICATION", "M_MERGE"}
            or any(type(value) is not dict or set(value) != {"state", "identity", "credential_withheld"}
                   or value["state"] != "FENCED" or not _digest(value["identity"])
                   or value["credential_withheld"] is not True
                   for value in endpoint_state.values())):
        raise ValueError("protected endpoint set is not exactly present and FENCED")
    if preimage["production_github_mutation_credentials"] != "NONE":
        raise ValueError("production GitHub mutation credentials are forbidden")
    service = preimage["substrate_service"]
    if (type(service) is not dict or set(service) != {
            "sid", "token_type", "administrator", "pid", "endpoint_identity",
            "implementation_identity", "configuration_identity", "working_directory",
    } or type(service["sid"]) is not str or not service["sid"] or service["sid"] in sids
            or service["token_type"] != 1 or service["administrator"] is not False
            or type(service["pid"]) is not int or service["pid"] <= 0
            or not _digest(service["endpoint_identity"])
            or not _digest(service["implementation_identity"])
            or not _digest(service["configuration_identity"])
            or type(service["working_directory"]) is not str or not service["working_directory"]):
        raise ValueError("dedicated substrate service identity is invalid or overlaps a candidate role")
    staged = preimage["staged_external_material"]
    if (type(staged) is not list or not staged
            or any(type(item) is not dict or set(item) != {"path", "sha256"}
                   or type(item["path"]) is not str or not item["path"] or not _digest(item["sha256"])
                   for item in staged)
            or [item["path"] for item in staged] != sorted({item["path"] for item in staged})):
        raise ValueError("staged external adapter material inventory is invalid")
    recovery = preimage["recovery_fence_inventory"]
    if (type(recovery) is not list or recovery != sorted(set(recovery))
            or any(type(item) is not str or not item for item in recovery)):
        raise ValueError("recovery-fence inventory must be canonical and duplicate-free")
    digest = hashlib.sha256(canonical_json_bytes(preimage)).hexdigest()
    return {"record_id": digest, "preimage": preimage}


def verify_deployment_readiness(record: dict[str, Any]) -> bool:
    if type(record) is not dict or set(record) != {"record_id", "preimage"}:
        return False
    try:
        rebuilt = build_deployment_readiness(record["preimage"])
    except (TypeError, ValueError, KeyError):
        return False
    return record["record_id"] == rebuilt["record_id"]
