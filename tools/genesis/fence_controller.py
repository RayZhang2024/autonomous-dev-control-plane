"""External-root controller retaining one exact first-genesis process session."""

from __future__ import annotations

import hashlib
from pathlib import Path
import sys
from typing import Any

import root_admin
from external_profiles import canonical_json_bytes, derive_external_root_controller_identity
from genesis_provenance import (
    stage_b_subject_digest, validate_genesis_exact_head_review_record,
    validate_post_merge_binding,
)
from post_merge_binding import revalidate_post_merge_binding, verify_local_merge_subject
from root_admin import ROOT_STORE_PATH, RetainedDeploymentSession, release_capability_fence


class RetainedRootControllerSession:
    """Live external controller lease; native handles remain owned until explicitly closed.

    The only constructor path is :meth:`launch`, which generates the session ID,
    launches the frozen S/T/C/P/M realization, and binds the exact controller
    source/configuration from the active ROOT_ACTIVATION_FENCE profile.
    """

    __slots__ = (
        "_retained", "_launch", "_profile", "_controller_identity", "_controller_security_context",
        "_genesis_review_record", "_post_merge_binding", "_github_observation",
        "_stage_b_subject_digest", "_attestation",
    )

    def __init__(self, *args: object) -> None:
        raise TypeError("use RetainedRootControllerSession.launch()")

    @classmethod
    def launch(
        cls, *, genesis_review_record: dict[str, object], post_merge_binding: dict[str, object],
        github_observation: dict[str, object],
    ) -> "RetainedRootControllerSession":
        from build_definition import sha256
        from windows_role_runner import REPOSITORY, _host_profiles, _launch_retained_deployment_processes

        root_profile, _, _, _ = _host_profiles()
        security_context = root_admin._require_external_root_admin_context(
            root_profile["root_admin_principal"]["sid"],
        )
        identity = derive_external_root_controller_identity(root_profile)
        implementation = sha256(Path(__file__).read_bytes())
        if identity["implementation_sha256"] != implementation:
            raise PermissionError("running root-controller bytes differ from the bound fence profile")
        validate_genesis_exact_head_review_record(genesis_review_record)
        validate_post_merge_binding(post_merge_binding, genesis_review_record)
        revalidate_post_merge_binding(
            REPOSITORY, genesis_review_record, post_merge_binding, github_observation,
        )
        session_id = root_admin.new_deployment_session_id()
        subject_digest = stage_b_subject_digest(genesis_review_record, post_merge_binding)
        _confirm_stage_b_subject(subject_digest)
        launched = _launch_retained_deployment_processes(session_id)
        if (launched.get("_root_fence_profile") != root_profile
                or launched.get("_deployment_session_id") != session_id):
            _close_launched_processes(launched)
            raise PermissionError("role launcher returned a different controller/session binding")
        processes = launched.get("_retained_process_instances")
        try:
            retained = RetainedDeploymentSession(session_id, processes)
            retained.assert_live()
        except BaseException:
            _close_launched_processes(launched)
            raise
        instance = object.__new__(cls)
        instance._retained = retained
        instance._launch = launched
        instance._profile = root_profile
        instance._controller_identity = identity
        instance._controller_security_context = {
            **security_context,
            "controller_implementation_identity": identity["implementation_sha256"],
            "controller_configuration_identity": identity["configuration_sha256"],
            "deployment_session_id": session_id,
        }
        instance._genesis_review_record = genesis_review_record
        instance._post_merge_binding = post_merge_binding
        instance._github_observation = github_observation
        instance._stage_b_subject_digest = subject_digest
        instance._attestation = None
        return instance

    @property
    def deployment_session_id(self) -> str:
        return self._retained.deployment_session_id

    @property
    def controller_identity(self) -> dict[str, str]:
        return dict(self._controller_identity)

    def assert_live(self) -> None:
        self._retained.assert_live()
        sid, primary, elevated, enabled_admin = root_admin._current_token_facts()
        context = self._controller_security_context
        if (sid != context["root_admin_sid"] or primary is not True or elevated is not True
                or enabled_admin is not True):
            raise PermissionError("profile-bound root-controller security context continuity was lost")
        if derive_external_root_controller_identity(self._profile) != self._controller_identity:
            raise PermissionError("root-controller configuration continuity was lost")
        if hashlib.sha256(Path(__file__).read_bytes()).hexdigest() != self._controller_identity[
                "implementation_sha256"]:
            raise PermissionError("root-controller implementation continuity was lost")
        from windows_role_runner import REPOSITORY
        verify_local_merge_subject(REPOSITORY, self._genesis_review_record, self._github_observation)

    def build_deployment_attestation(
        self, *, expected_fence_row: dict[str, object],
    ) -> dict[str, object]:
        """Construct S from current retained process facts and exact bound staged evidence."""
        self.assert_live()
        readiness = self._launch["_deployment_readiness_preimage"]
        build = self._launch["_candidate_build_definition"]
        substrate_profile = self._launch["_fixture_substrate_profile"]
        session_id = self.deployment_session_id
        observations = self._current_process_observations()
        root_observation = root_admin.inspect_uninitialized_root(
            ROOT_STORE_PATH, expected_fence_row=expected_fence_row,
            deployment_session_id=session_id,
        )
        preimage: dict[str, object] = {
            "format": "autodev.genesis-deployment-attestation/v1",
            "candidate_package_id": self._launch["candidate_package_id"],
            "genesis_manifest_id": self._launch["manifest_id"],
            "deterministic_evidence_ids": [self._launch["deterministic_evidence_id"]],
            "genesis_review_record": self._genesis_review_record,
            "post_merge_binding": self._post_merge_binding,
            "stage_b_subject_digest": self._stage_b_subject_digest,
            "external_root_controller_security_context": self._controller_security_context,
            "runtime_artifact_sha256": self._launch["runtime_sha256"],
            "python_runtime": self._profile["python_runtime"],
            "execution_isolation_dependency_id": build["execution_isolation_dependency_id"],
            "execution_isolation_profile_sha256": hashlib.sha256(
                canonical_json_bytes(build["execution_isolation_profile"])).hexdigest(),
            "execution_isolation_profile": build["execution_isolation_profile"],
            "root_fence_dependency_id": build["root_fence_dependency_id"],
            "root_fence_profile_sha256": hashlib.sha256(canonical_json_bytes(self._profile)).hexdigest(),
            "root_fence_profile": self._profile,
            "root_store_profile_id": self._profile["root_store_profile_id"],
            "root_store_schema_sha256": self._profile["root_store_schema_sha256"],
            "root_namespace_acl_profile_id": self._profile["root_namespace_acl_profile"]["profile_id"],
            "acceptance_profile_id": self._profile["acceptance_profile"]["profile_id"],
            "fixture_substrate_dependency_id": build["fixture_substrate_dependency_id"],
            "fixture_substrate_profile_sha256": hashlib.sha256(
                canonical_json_bytes(substrate_profile)).hexdigest(),
            "fixture_substrate_profile": substrate_profile,
            "root_anchor_id": self._launch["root_anchor_id"],
            "deployment_session_id": session_id,
            "root_state_observation": root_observation,
            "roles": readiness["roles"],
            "process_instance_observations": observations,
            "external_root_controller_identity": dict(self._controller_identity),
            "staged_external_material": build["external_tcb_material"],
            "substrate_service": self._current_substrate_service(),
            "shared_runtime_read_only": readiness["shared_runtime_read_only"],
            "cross_role_private_write_denial": readiness["cross_role_private_write_denial"],
            "candidate_root_store_write_denial": readiness["candidate_root_store_write_denial"],
            "protected_endpoint_state": readiness["protected_endpoint_state"],
            "recovery_fence_inventory": [substrate_profile["external_recovery_endpoint"]["endpoint_id"]],
            "production_github_mutation_credentials": "NONE",
            "host_profile_id": readiness["host_profile_id"],
            "observed_at": root_admin._now_utc(),
        }
        attestation = root_admin.build_deployment_attestation(
            preimage, expected_fence_row, self,
        )
        if not self._retained.verify(attestation, session_id):
            raise PermissionError("live process observations do not match retained controller handles")
        self._attestation = attestation
        return attestation

    def _current_process_observations(self) -> dict[str, dict[str, object]]:
        self.assert_live()
        launch = self._launch
        readiness = launch["_deployment_readiness_preimage"]
        substrate_profile = launch["_fixture_substrate_profile"]
        processes = launch["_retained_process_instances"]
        result: dict[str, dict[str, object]] = {}
        for role, process in processes.items():
            if role == "S":
                service_principal = substrate_profile["service_principal"]
                entry = next(item for item in substrate_profile["implementation_material"]
                             if item["path"] == "tools/genesis/fixture_substrate.py")
                facts = {
                    "role": "S", "pid": process.pid,
                    "creation_time_100ns": process.creation_time_100ns,
                    "sid": process.sid, "token_type": process.token_type,
                    "administrator": process.is_administrator,
                    "deployment_session_id": self.deployment_session_id,
                    "security_context_identity": hashlib.sha256(canonical_json_bytes(service_principal)).hexdigest(),
                    "entrypoint_identity": entry["sha256"],
                    "wiring_identity": hashlib.sha256(canonical_json_bytes(substrate_profile)).hexdigest(),
                    "endpoint_identity": process.endpoint_identity,
                    "runtime_role_identity": hashlib.sha256(canonical_json_bytes(
                        ("S", launch["runtime_sha256"], launch["candidate_package_id"]))).hexdigest(),
                    "runtime_binding_id": hashlib.sha256(canonical_json_bytes(
                        (launch["fixture_substrate_dependency_id"], process.endpoint_identity,
                         launch["candidate_package_id"]))).hexdigest(),
                }
            else:
                evidence = readiness["roles"][role]
                facts = {
                    "role": role, "pid": process.pid,
                    "creation_time_100ns": process.creation_time_100ns,
                    "sid": process.sid, "token_type": process.token_type,
                    "administrator": process.is_administrator,
                    "deployment_session_id": self.deployment_session_id,
                    **{key: evidence[key] for key in (
                        "security_context_identity", "entrypoint_identity", "wiring_identity",
                        "endpoint_identity", "runtime_role_identity", "runtime_binding_id")},
                }
            facts["process_instance_id"] = hashlib.sha256(
                b"autodev.g9-process-instance/v1\0" + canonical_json_bytes(facts)
            ).hexdigest()
            result[role] = facts
        if set(result) != {"S", "T", "C", "P", "M"}:
            raise PermissionError("controller process observation set is incomplete")
        return result

    def _current_substrate_service(self) -> dict[str, object]:
        self.assert_live()
        process = self._launch["_retained_process_instances"]["S"]
        return {
            "sid": process.sid, "token_type": process.token_type,
            "administrator": process.is_administrator, "pid": process.pid,
            "endpoint_identity": process.endpoint_identity,
            "implementation_identity": next(item["sha256"] for item in
                self._launch["_fixture_substrate_profile"]["implementation_material"]
                if item["path"] == "tools/genesis/fixture_substrate.py"),
            "configuration_identity": hashlib.sha256(canonical_json_bytes(
                self._launch["_fixture_substrate_profile"])).hexdigest(),
            "working_directory": str(Path(self._launch["substrate_process"]["working_directory"])),
        }

    def append_acceptance(self, path: Path, **values: Any) -> dict[str, object]:
        attestation = self._require_attestation()
        return root_admin.append_acceptance(
            path, deployment_attestation=attestation,
            deployment_session_id=self.deployment_session_id, retained_session=self._retained,
            **values,
        )

    def initialize_genesis_state(self, path: Path, **values: Any) -> dict[str, object]:
        attestation = self._require_attestation()
        return root_admin.initialize_genesis_state(
            path, deployment_attestation=attestation,
            deployment_session_id=self.deployment_session_id, retained_session=self._retained,
            **values,
        )

    def release_first_genesis(self, path: Path, **values: Any) -> dict[str, object]:
        attestation = self._require_attestation()
        if "live_observation" in values:
            raise TypeError("live observations are constructed by the retained controller")
        return release_capability_fence(
            path, deployment_attestation=attestation,
            deployment_session_id=self.deployment_session_id, retained_session=self._retained,
            live_observation=self._fresh_live_observation(),
            **values,
        )

    def _fresh_live_observation(self) -> dict[str, object]:
        """Re-observe process, material, root-access, and target-fence facts at release time."""
        attestation = self._require_attestation()
        preimage = attestation["preimage"]
        self.assert_live()
        repo = Path(__file__).resolve().parents[2]
        material = {item["path"]: item["sha256"]
                    for item in preimage["staged_external_material"]}
        for relative, expected in material.items():
            path = repo.joinpath(*relative.split("/"))
            if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
                raise PermissionError("staged external material changed after Stage B")

        processes = self._launch["_retained_process_instances"]
        process_observations = self._current_process_observations()
        access_denial: dict[str, bool] = {}
        for role in ("T", "C", "P", "M"):
            process = processes[role]
            process.send_json_line({"control": "ROOT_ACCESS_PROBE"})
            response = process.read_json_line()
            access = response.get("access") if type(response) is dict else None
            if type(response) is not dict or set(response) != {"role", "access"} or response["role"] != role:
                raise PermissionError("fresh candidate root-access observation is malformed")
            if (type(access) is not dict or not access.get("own_private_write")
                    or not access.get("shared_runtime_write_denied")
                    or not access.get("root_store_write_denied")
                    or set(access.get("other_private_write_denied", {})) != {"T", "C", "P", "M"} - {role}
                    or not all(access["other_private_write_denied"].values())):
                raise PermissionError("candidate role root/shared/private access boundary changed")
            access_denial[role] = access["root_store_write_denied"] is True

        effect_denials: dict[str, bool] = {}
        for role in ("P", "M"):
            process = processes[role]
            process.send_json_line({"control": "PROTECTED_EFFECT_PROBE"})
            response = process.read_json_line()
            if (response != {"control_probe": "PROTECTED_EFFECT", "role": role,
                             "fence": "FENCED", "revision": 0,
                             "protected_effect_accepted": False,
                             "candidate_package_id": preimage["candidate_package_id"]}):
                raise PermissionError("fresh protected-effect denial observation changed")
            effect_denials[role] = response["protected_effect_accepted"] is False
        release_denials: dict[str, bool] = {}
        for role in ("T", "C", "P", "M"):
            process = processes[role]
            process.send_json_line({"control": "FENCE_RELEASE_PROBE"})
            response = process.read_json_line()
            if response != {"control_probe": "FENCE_RELEASE", "role": role,
                            "accepted": False, "reason": "NO_RELEASE_CAPABILITY"}:
                raise PermissionError("candidate fence-release denial observation changed")
            release_denials[role] = True

        roles = preimage["roles"]
        return {
            "deployment_session_id": self.deployment_session_id,
            "deployment_attestation_id": attestation["record_id"],
            "candidate_package_id": preimage["candidate_package_id"],
            "genesis_manifest_id": preimage["genesis_manifest_id"],
            "runtime_artifact_sha256": preimage["runtime_artifact_sha256"],
            "root_anchor_id": preimage["root_anchor_id"],
            "root_profile_identities": {
                "root_store_profile_id": preimage["root_store_profile_id"],
                "root_namespace_acl_profile_id": preimage["root_namespace_acl_profile_id"],
                "acceptance_profile_id": preimage["acceptance_profile_id"],
                "root_fence_dependency_id": preimage["root_fence_dependency_id"],
                "execution_isolation_dependency_id": preimage["execution_isolation_dependency_id"],
                "fixture_substrate_dependency_id": preimage["fixture_substrate_dependency_id"],
                "root_anchor_id": preimage["root_anchor_id"],
            },
            "security_context_identities": {
                role: roles[role]["security_context_identity"] for role in ("T", "C", "P", "M")
            },
            "role_bindings": {
                role: {field: roles[role][field] for field in (
                    "security_context_identity", "entrypoint_identity", "wiring_identity",
                    "endpoint_identity", "runtime_role_identity", "runtime_binding_id")}
                for role in ("T", "C", "P", "M")
            },
            "process_instance_identities": {
                role: facts["process_instance_id"]
                for role, facts in process_observations.items()
            },
            "external_material_identities": material,
            "substrate_endpoint_identity": preimage["substrate_service"]["endpoint_identity"],
            "protected_effect_denial_observation": {
                "p_target_fence_state": "FENCED", "m_target_fence_state": "FENCED",
                "p_protected_effect_denied": effect_denials["P"],
                "m_protected_effect_denied": effect_denials["M"],
                "candidate_root_store_write_denied": all(access_denial.values()),
                "candidate_fence_release_denied": all(release_denials.values()),
                "production_github_mutation_credentials": "NONE",
            },
        }

    def _require_attestation(self) -> dict[str, object]:
        self.assert_live()
        if type(self._attestation) is not dict:
            raise PermissionError("same-session deployment attestation has not been built")
        if not self._retained.verify(self._attestation, self.deployment_session_id):
            raise PermissionError("deployment controller/session continuity was lost")
        return self._attestation

    def close(self) -> None:
        processes = self._launch["_retained_process_instances"]
        for role in ("T", "C", "P", "M"):
            process = processes[role]
            if process.is_live():
                process.send_json_line({"control": "STOP"})
        for role in ("T", "C", "P", "M"):
            process = processes[role]
            if process.wait() != 0:
                raise RuntimeError(f"role {role} did not stop cleanly")
        substrate = processes["S"]
        if substrate.stop() != 0:
            raise RuntimeError("substrate service did not stop cleanly")
        for process in processes.values():
            process.close()


def _confirm_stage_b_subject(subject_digest: str) -> None:
    if (type(subject_digest) is not str or len(subject_digest) != 64
            or any(char not in "0123456789abcdef" for char in subject_digest)):
        raise ValueError("Stage-B subject digest is malformed")
    if not sys.stdin.isatty():
        raise PermissionError("Stage-B confirmation requires an interactive local console")
    expected = f"STAGE_B {subject_digest}"
    response = input(f"Confirm exact authenticated Stage-B subject by typing {expected}: ")
    if response != expected:
        raise PermissionError("exact Stage-B subject confirmation did not match")


def _close_launched_processes(launched: dict[str, object]) -> None:
    processes = launched.get("_retained_process_instances")
    if type(processes) is not dict:
        return
    for role in ("T", "C", "P", "M"):
        process = processes.get(role)
        if process is not None and process.is_live():
            process.send_json_line({"control": "STOP"})
    for role in ("T", "C", "P", "M"):
        process = processes.get(role)
        if process is not None:
            try:
                process.wait()
            except Exception:
                pass
    substrate = processes.get("S")
    if substrate is not None:
        try:
            substrate.stop()
        except Exception:
            pass
    for process in processes.values():
        try:
            process.close()
        except Exception:
            pass


def release_first_genesis(
    database: Path = ROOT_STORE_PATH, *, expected_admin_sid: str,
    expected_fence_row: dict[str, object], acceptance_id: str,
    initialization_record_id: str, deployment_attestation: dict[str, object],
    deployment_session_id: str, live_observation: dict[str, object],
    explicit_release: bool, retained_session: RetainedDeploymentSession,
    expected_acl_sddl: str,
) -> dict[str, object]:
    """Perform only the frozen atomic FENCED/0 -> RELEASED/1 ceremony."""
    return release_capability_fence(
        database, expected_admin_sid=expected_admin_sid,
        expected_fence_row=expected_fence_row, acceptance_id=acceptance_id,
        initialization_record_id=initialization_record_id,
        deployment_attestation=deployment_attestation,
        deployment_session_id=deployment_session_id, live_observation=live_observation,
        explicit_release=explicit_release, retained_session=retained_session,
        expected_acl_sddl=expected_acl_sddl,
    )
