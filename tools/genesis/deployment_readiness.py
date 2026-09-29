"""Non-authoritative pre-review deployment-readiness record (DR)."""

from __future__ import annotations

import hashlib
from typing import Any

from external_profiles import canonical_json_bytes, derive_host_profile_id

FORMAT = "autodev.genesis-deployment-readiness/v1"
_PREIMAGE_FIELDS = frozenset({
    "format", "deployment_session_id", "candidate_package_id", "genesis_manifest_id", "deterministic_evidence_ids",
    "repository_source_commit", "runtime_artifact_sha256", "python_runtime",
    "execution_isolation_dependency_id", "root_fence_dependency_id",
    "root_fence_profile_sha256", "execution_isolation_profile_sha256",
    "fixture_substrate_dependency_id",
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
    for field in ("deployment_session_id", "candidate_package_id", "genesis_manifest_id", "runtime_artifact_sha256",
                  "root_fence_profile_sha256", "execution_isolation_profile_sha256",
                  "fixture_substrate_profile_sha256",
                  "root_anchor_id"):
        if not _digest(preimage[field]):
            raise ValueError(f"deployment-readiness {field} is malformed")
    if not isinstance(preimage["repository_source_commit"], str) or len(preimage["repository_source_commit"]) != 40:
        raise ValueError("deployment-readiness source commit is malformed")
    for field in ("execution_isolation_dependency_id", "root_fence_dependency_id",
                  "fixture_substrate_dependency_id", "observed_at"):
        if type(preimage[field]) is not str or not preimage[field]:
            raise ValueError(f"deployment-readiness {field} is invalid")
    if (type(preimage["execution_isolation_dependency_id"]) is not str
            or not preimage["execution_isolation_dependency_id"].startswith("dep-execution-isolation-")
            or not _digest(preimage["execution_isolation_dependency_id"].rsplit("-", 1)[-1])
            or type(preimage["root_fence_dependency_id"]) is not str
            or not preimage["root_fence_dependency_id"].startswith("dep-root-activation-fence-")
            or not _digest(preimage["root_fence_dependency_id"].rsplit("-", 1)[-1])
            or type(preimage["fixture_substrate_dependency_id"]) is not str
            or not preimage["fixture_substrate_dependency_id"].startswith("dep-fixture-effect-substrate-")
            or not _digest(preimage["fixture_substrate_dependency_id"].rsplit("-", 1)[-1])):
        raise ValueError("deployment-readiness dependency identities are malformed")
    expected_host_id = derive_host_profile_id(
        root_fence_profile_sha256=preimage["root_fence_profile_sha256"],
        fixture_substrate_profile_sha256=preimage["fixture_substrate_profile_sha256"],
        execution_isolation_profile_sha256=preimage["execution_isolation_profile_sha256"],
    )
    if preimage["host_profile_id"] != expected_host_id:
        raise ValueError("deployment-readiness host profile does not bind all three external profiles")
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
            "status", "root_anchor_id", "candidate_package_id", "manifest_id", "root_state_row_count",
            "capability_fence_row_count", "fence_id", "fence_state", "fence_revision",
            "capability_fence", "acceptance_history_count", "initialization_record_count",
            "acceptance_history_digest", "applicable_acceptance_for_this_deployment_session",
            "deployment_session_id", "release_verification_count", "schema_sha256", "observation_scope",
            "canonical_root_database", "fixture_database_sha256",
    } or root_state["status"] != "UNINITIALIZED"
            or root_state["root_anchor_id"] != preimage["root_anchor_id"]
            or root_state["deployment_session_id"] != preimage["deployment_session_id"]
            or root_state["applicable_acceptance_for_this_deployment_session"] is not None
            or root_state["candidate_package_id"] != preimage["candidate_package_id"]
            or root_state["manifest_id"] != preimage["genesis_manifest_id"]
            or root_state["root_state_row_count"] != 0
            or root_state["capability_fence_row_count"] != 1
            or root_state["fence_state"] != "FENCED" or root_state["fence_revision"] != 0
            or type(root_state["capability_fence"]) is not dict
            or set(root_state["capability_fence"]) != {
                "format", "fence_id", "root_anchor_id", "candidate_package_id", "manifest_id",
                "runtime_artifact_sha256", "runtime_generation", "execution_isolation_dependency_id",
                "fixture_effect_substrate_dependency_id", "security_context_t_identity",
                "security_context_c_identity", "security_context_p_identity", "security_context_m_identity",
                "prepared_endpoint_c_identity", "prepared_endpoint_p_identity", "prepared_endpoint_m_identity",
                "state", "revision",
            }
            or root_state["capability_fence"].get("fence_id") != root_state["fence_id"]
            or root_state["capability_fence"].get("candidate_package_id") != preimage["candidate_package_id"]
            or root_state["capability_fence"].get("manifest_id") != preimage["genesis_manifest_id"]
            or root_state["capability_fence"].get("runtime_artifact_sha256") != preimage["runtime_artifact_sha256"]
            or root_state["capability_fence"].get("state") != "FENCED"
            or root_state["capability_fence"].get("revision") != 0
            or type(root_state["acceptance_history_count"]) is not int
            or root_state["acceptance_history_count"] < 0
            or not _digest(root_state["acceptance_history_digest"])
            or root_state["initialization_record_count"] != 0
            or root_state["release_verification_count"] != 0
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
    common_c_projection: dict[str, object] | None = None
    for role in _ROLES:
        record = roles[role]
        if (type(record) is not dict or set(record) != {
                "sid", "token_type", "administrator", "pid", "ppid", "candidate_package_id",
                "runtime_sha256", "entrypoint_identity", "security_context_identity",
                "wiring_identity", "endpoint_identity", "private_directory",
                "destination_channel_credentials", "runtime_type", "runtime_role_identity",
                "runtime_binding_id", "runtime_active", "canonical_state",
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
        canonical_state = record["canonical_state"]
        expected_state_fields = {
            "role", "backend_owner_role", "backend_owner_instance_id", "projection_digest",
            "backend_generation", "projection", "direct_backend_object",
            "authenticated_t_to_c_client", "read_only_projection",
        }
        if role == "C":
            expected_state_fields.add("channel_endpoint")
        if role == "T":
            expected_state_fields.add("channel_identity")
        if (type(canonical_state) is not dict or set(canonical_state) != expected_state_fields
                or canonical_state["role"] != role or canonical_state["backend_owner_role"] != "C"
                or not _digest(canonical_state["backend_owner_instance_id"])
                or not _digest(canonical_state["projection_digest"])
                or type(canonical_state["backend_generation"]) is not int
                or canonical_state["backend_generation"] < 1
                or canonical_state["direct_backend_object"] is not (role == "C")
                or canonical_state["authenticated_t_to_c_client"] is not (role == "T")
                or canonical_state["read_only_projection"] is not (role != "C")):
            raise ValueError(f"role {role} canonical-state topology is not exact")
        projection = canonical_state["projection"]
        projection_fields = {"format", "owner_role", "owner_process_id", "owner_instance_id",
                             "backend_generation", "state_record_counts",
                             "resolved_target_registration_ids", "projection_digest"}
        if (type(projection) is not dict or set(projection) != projection_fields
                or projection["format"] != "autodev.g9-canonical-state-channel/v1"
                or projection["owner_role"] != "C"
                or projection["owner_process_id"] != roles["C"]["pid"]
                or projection["owner_instance_id"] != canonical_state["backend_owner_instance_id"]
                or projection["backend_generation"] != canonical_state["backend_generation"]
                or projection["projection_digest"] != canonical_state["projection_digest"]
                or type(projection["state_record_counts"]) is not dict
                or set(projection["state_record_counts"]) != {
                    "contracts", "authorizations", "tasks", "candidates", "candidate_materializations",
                    "operations", "memberships", "attempts", "evidence", "histories", "supersessions"}
                or any(type(count) is not int or count != 0
                       for count in projection["state_record_counts"].values())
                or projection["resolved_target_registration_ids"] != []):
            raise ValueError(f"role {role} canonical-state projection is not C-owned or closed")
        projection_preimage = {key: value for key, value in projection.items()
                               if key != "projection_digest"}
        if projection["projection_digest"] != hashlib.sha256(
                b"autodev.g9-canonical-state-projection/v1\0"
                + canonical_json_bytes(projection_preimage)).hexdigest():
            raise ValueError(f"role {role} canonical-state projection digest is invalid")
        if common_c_projection is None:
            common_c_projection = projection
        elif projection != common_c_projection:
            raise ValueError(f"role {role} projection differs from C's canonical backend")
        if role == "C":
            endpoint = canonical_state["channel_endpoint"]
            if (type(endpoint) is not list or len(endpoint) != 2 or endpoint[0] != "127.0.0.1"
                    or type(endpoint[1]) is not int or not 1 <= endpoint[1] <= 65535):
                raise ValueError("C-owned state endpoint is not exact loopback")
        if role == "T" and not _digest(canonical_state["channel_identity"]):
            raise ValueError("T authenticated C-channel identity is malformed")
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
