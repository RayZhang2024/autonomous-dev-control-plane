"""Stage and exercise the four-role Windows G9 isolation realization.

This external-TCB tool is intentionally not part of the 26-member runtime.
Role credentials are obtained only by the launcher's hidden console prompts.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import sqlite3
import sys
import tempfile
import zipfile
from datetime import datetime, timezone

REPOSITORY = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(REPOSITORY / "src"))
sys.path.insert(0, str(HERE))
from assemble_candidate import assemble_candidate, write_package
from build_definition import sha256
from ipc import encode_message
from windows_role_launcher import ROLE_PRINCIPALS, launch_role
from external_profiles import build_external_profiles, canonical_json_bytes
from fixture_substrate import new_channel_keys
from root_admin import inspect_uninitialized_root
from deployment_readiness import build_deployment_readiness, verify_deployment_readiness
from windows_substrate_launcher import launch_substrate

STAGING = Path(r"C:\AutodevG9")
SHARED = STAGING / "shared"
PRIVATE = STAGING / "private"
PYTHON = SHARED / "python313" / "python.exe"
ROOT_PROBE = STAGING
ROLE_ORDER = ("T", "C", "P", "M")
CHANNEL = {"C": "authenticated-t-to-c", "P": "authenticated-t-to-p",
           "M": "authenticated-t-to-m"}
_ROLE_IDENTITY_REPORT_FIELDS = frozenset({
    "role", "pid", "ppid", "python_executable", "python_sha256", "runtime_sha256",
    "candidate_package_id", "runtime_generation", "endpoint_identity", "private_directory",
    "security_context_identity", "entrypoint_identity", "access",
    "destination_channel_credentials", "runtime_preparation",
    "production_github_mutation_credentials",
})
_SAFE_EXCEPTION_TYPE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z", re.ASCII)
_STARTUP_STAGES = frozenset({
    "BOOTSTRAP_VALIDATION", "RUNTIME_ARTIFACT_READ", "PYTHON_IDENTITY_READ",
    "RUNTIME_IMPORT", "ADAPTER_IMPORT", "SUBSTRATE_SETUP",
    "SUBSTRATE_RESOURCE_VERIFY", "SUBSTRATE_CONNECT", "SUBSTRATE_SEND",
    "SUBSTRATE_RECEIVE", "RUNTIME_CONSTRUCTION", "CHANNEL_SETUP", "ACCESS_PROBE",
    "REPORT_BUILD", "REPORT_WRITE",
})
_CONNECT_FAILURE_CLASSES = frozenset({
    "CONNECTION_REFUSED", "ACCESS_DENIED", "TIMED_OUT", "NETWORK_UNREACHABLE",
    "HOST_UNREACHABLE", "OTHER_CONNECT_FAILURE",
})


def _validate_role_identity_report(role: str, report: object) -> dict[str, object]:
    """Recognize closed startup failure evidence before accepting a success report."""
    if type(report) is dict and "startup_failure" in report:
        if set(report) != {"startup_failure"}:
            raise AssertionError(f"role {role} returned malformed startup failure evidence")
        failure = report["startup_failure"]
        if type(failure) is not dict or "stage" not in failure:
            raise AssertionError(f"role {role} returned malformed startup failure evidence")
        stage = failure["stage"]
        if type(stage) is not str or stage not in _STARTUP_STAGES:
            raise AssertionError(f"role {role} returned malformed startup failure evidence")
        expected_fields = ({"type", "stage", "class", "os_code"}
                           if stage == "SUBSTRATE_CONNECT" else {"type", "stage"})
        if set(failure) != expected_fields:
            raise AssertionError(f"role {role} returned malformed startup failure evidence")
        exception_type = failure["type"]
        failure_class = failure.get("class")
        os_code = failure.get("os_code")
        if (type(exception_type) is not str
                or _SAFE_EXCEPTION_TYPE.fullmatch(exception_type) is None
                or (stage == "SUBSTRATE_CONNECT" and (
                    exception_type != "SubstrateTransportError"
                    or type(failure_class) is not str
                    or failure_class not in _CONNECT_FAILURE_CLASSES
                    or (os_code is not None and type(os_code) is not int)
                ))
                or (stage in {"SUBSTRATE_SEND", "SUBSTRATE_RECEIVE"}
                    and exception_type != "SubstrateTransportError")):
            raise AssertionError(f"role {role} returned malformed startup failure evidence")
        if stage == "SUBSTRATE_CONNECT":
            raise AssertionError(
                f"role {role} worker startup failed at {stage}: {exception_type} "
                f"({failure_class}, os_code={os_code})"
            )
        raise AssertionError(f"role {role} worker startup failed at {stage}: {exception_type}")
    if type(report) is not dict or set(report) != _ROLE_IDENTITY_REPORT_FIELDS:
        raise AssertionError("role worker returned an open or incomplete identity report")
    return report


def _deployment_role_evidence(
    role: str,
    process: object,
    report: dict[str, object],
    *,
    candidate_package_id: str,
    runtime_sha256: str,
    wiring_identity: str,
) -> dict[str, object]:
    """Project a successful role report into the exact closed DR role record."""
    preparation = report["runtime_preparation"]
    if type(preparation) is not dict:
        raise ValueError("role runtime preparation is not closed")
    return {
        "sid": process.sid, "token_type": process.token_type,
        "administrator": process.is_administrator,
        "pid": process.pid, "ppid": report["ppid"],
        "candidate_package_id": candidate_package_id,
        "runtime_sha256": runtime_sha256,
        "entrypoint_identity": report["entrypoint_identity"],
        "security_context_identity": report["security_context_identity"],
        "wiring_identity": wiring_identity,
        "endpoint_identity": report["endpoint_identity"],
        "private_directory": report["private_directory"],
        "destination_channel_credentials": report["destination_channel_credentials"],
        "runtime_type": preparation["runtime_type"],
        "runtime_role_identity": preparation["runtime_role_identity"],
        "runtime_binding_id": preparation["runtime_binding_id"],
        "runtime_active": preparation["runtime_active"],
    }


def _host_profiles() -> tuple[dict[str, object], dict[str, object], str, tuple[str, str]]:
    if not PYTHON.is_file():
        raise RuntimeError("the frozen staged CPython interpreter is unavailable")
    if sha256(PYTHON.read_bytes()) != "081786173866d86cda1b06aa671848217fa0d635edb6dcd2218644466f4229cd":
        raise RuntimeError("staged CPython executable identity differs from the frozen host binding")
    python_runtime = {
        "identity": "CPython", "version": "3.13.14", "path": str(PYTHON),
        "sha256": sha256(PYTHON.read_bytes()),
    }
    return build_external_profiles(
        str(REPOSITORY),
        root_admin_principal={
            "account": r"ray\zhang",
            "sid": "S-1-5-21-711519901-190585334-3846127459-1001",
            "administrator": True,
        },
        substrate_principal={
            "account": r"Ray\autodev-g9-s",
            "sid": "S-1-5-21-711519901-190585334-3846127459-1020",
            "token_type": "PRIMARY", "administrator": False,
        },
        python_runtime=python_runtime,
    )


def _stage(package) -> tuple[Path, Path, Path]:
    if Path(sys.executable).resolve() != PYTHON.resolve():
        raise RuntimeError("candidate generation and role launch must use staged CPython 3.13")
    expected_python = "081786173866d86cda1b06aa671848217fa0d635edb6dcd2218644466f4229cd"
    if sha256(PYTHON.read_bytes()) != expected_python or sys.version_info[:3] != (3, 13, 14):
        raise RuntimeError("staged CPython runtime identity mismatch")
    SHARED.mkdir(parents=True, exist_ok=True)
    candidate = SHARED / f"candidate-{package.candidate_package_id}"
    if candidate.exists():
        # Never overwrite bytes in the reviewed shared area; only reuse an exact image.
        package_file = candidate / "candidate-package.zip"
        runtime_file = candidate / "runtime.zip"
        if (not package_file.is_file() or package_file.read_bytes() != package.candidate_package
                or not runtime_file.is_file() or runtime_file.read_bytes() != package.runtime_artifact):
            raise RuntimeError("staged candidate identity path contains altered bytes")
    else:
        write_package(package, candidate)
        (candidate / "runtime.zip").write_bytes(package.runtime_artifact)
    external_material = json.loads(package.build_definition)["external_tcb_material"]
    external_id = hashlib.sha256(json.dumps(
        external_material, sort_keys=True, separators=(",", ":")
    ).encode("ascii")).hexdigest()[:24]
    external = SHARED / f"external-g9-v02-{external_id}"
    external.mkdir(exist_ok=True)
    external_material = json.loads(package.build_definition)["external_tcb_material"]
    names = tuple(item["path"].removeprefix("tools/genesis/") for item in external_material)
    for name in names:
        destination = external / name
        source = HERE / name
        if destination.exists():
            if destination.read_bytes() != source.read_bytes():
                raise RuntimeError(f"staged external-TCB file differs: {name}")
        else:
            shutil.copyfile(source, destination)
    return candidate, external / "role_worker.py", external


def _role_bootstrap(package, graph: dict[str, object], candidate: Path, worker: Path,
                    role: str, keys: dict[str, bytes], endpoint: str,
                    substrate_endpoint: tuple[str, int], substrate_key: bytes,
                    runtime_run_id: str) -> dict[str, object]:
    member = next(item for item in graph["members"] if item["role"] == role)
    raw = package.raw_resources
    security = raw[member["security_context_config_resource"]]
    entrypoint = raw[member["entry_point_config_resource"]]
    value: dict[str, object] = {
        "role": role,
        "runtime_zip": str(candidate / "runtime.zip"),
        "runtime_sha256": sha256(package.runtime_artifact),
        "candidate_package_id": package.candidate_package_id,
        "runtime_generation": f"g9-generation-{package.runtime_sha256[:24]}",
        "endpoint_identity": endpoint,
        "private_directory": str(PRIVATE / role),
        "private_directories": {item: str(PRIVATE / item) for item in ROLE_ORDER},
        "security_context_identity": sha256(security),
        "entrypoint_identity": sha256(entrypoint),
        "shared_directory": str(candidate),
        "root_store_probe": str(ROOT_PROBE),
        "substrate_endpoint": [substrate_endpoint[0], substrate_endpoint[1]],
        "substrate_channel_key_hex": substrate_key.hex(),
        "substrate_resource_id": "runtime",
        "substrate_resource_sha256": sha256(package.runtime_artifact),
        "runtime_run_id": runtime_run_id,
    }
    if role in keys:
        value["channel_key_hex"] = keys[role].hex()
    return value


def run_realized_roles() -> dict[str, object]:
    from root_admin import ROOT_STORE_PATH

    canonical_root_namespace = ROOT_STORE_PATH.parent
    if ROOT_STORE_PATH.exists() or canonical_root_namespace.exists():
        raise RuntimeError("canonical root namespace/DB must remain absent during this implementation run")
    root_profile, substrate_profile, root_anchor_id, (root_dependency_id,
                                                       substrate_dependency_id) = _host_profiles()
    package = assemble_candidate(
        git_cwd=str(REPOSITORY), root_fence_profile=root_profile,
        fixture_substrate_profile=substrate_profile, root_anchor_id=root_anchor_id,
    )
    candidate, worker, external = _stage(package)
    graph = json.loads(package.graph)
    keys = {role: secrets.token_bytes(32) for role in ("C", "P", "M")}
    substrate_keys = new_channel_keys()
    endpoints = {role: secrets.token_hex(32) for role in ROLE_ORDER}
    processes = {}
    reports = {}
    runtime_run_id = secrets.token_hex(32)
    substrate_process = None
    substrate_state: dict[str, object] | None = None
    try:
        resources = [
            {"resource_id": resource_id, "sha256": sha256(raw),
             "path": str(candidate / "resources" / resource_id)}
            for resource_id, raw in sorted(package.raw_resources.items())
        ]
        substrate_bootstrap = {
            "format": "autodev.g9-fixture-substrate-bootstrap/v1",
            "candidate_package_id": package.candidate_package_id,
            "resources": resources,
            "channel_keys_hex": {role: substrate_keys[role].hex()
                                 for role in sorted(substrate_keys)},
        }
        substrate_process = launch_substrate(
            account=r"Ray\autodev-g9-s",
            expected_sid="S-1-5-21-711519901-190585334-3846127459-1020",
            python_executable=PYTHON,
            service_script=external / "fixture_substrate.py",
            bootstrap=substrate_bootstrap,
        )
        if (substrate_process.candidate_package_id != package.candidate_package_id
                or substrate_process.sid != substrate_profile["service_principal"]["sid"]
                or substrate_process.token_type != 1 or substrate_process.is_administrator):
            raise AssertionError("external substrate process does not match the profile-bound identity")
        for role in ROLE_ORDER:
            process = launch_role(
                role, python_executable=PYTHON, worker_script=worker,
                working_directory=PRIVATE / role,
            )
            processes[role] = process
            if process.sid != ROLE_PRINCIPALS[role][1] or process.is_administrator:
                raise AssertionError("native token evidence did not match the exact role profile")
            process.send_json_line(_role_bootstrap(
                package, graph, candidate, worker, role, keys, endpoints[role],
                substrate_process.endpoint, substrate_keys[role], runtime_run_id,
            ))
            report = process.read_json_line()
            report = _validate_role_identity_report(role, report)
            if (report["role"] != role or report["pid"] != process.pid
                    or report["python_sha256"] != "081786173866d86cda1b06aa671848217fa0d635edb6dcd2218644466f4229cd"
                    or Path(report["python_executable"]).resolve() != PYTHON.resolve()
                    or report["runtime_sha256"] != package.runtime_sha256
                    or report["candidate_package_id"] != package.candidate_package_id
                    or report["endpoint_identity"] != endpoints[role]
                    or Path(report["private_directory"]).resolve() != (PRIVATE / role).resolve()):
                raise AssertionError(f"role {role} runtime/process binding mismatch")
            role_preparation = report["runtime_preparation"]
            expected_runtime_type = {
                "T": "TrustedControllerRuntime", "C": "ControlStateGateRuntime",
                "P": "PublicationGateRuntime", "M": "MergeGateRuntime",
            }[role]
            if (type(role_preparation) is not dict
                    or role_preparation.get("role") != role
                    or role_preparation.get("runtime_type") != expected_runtime_type
                    or role_preparation.get("independent_process_local_composition") is not True
                    or role_preparation.get("runtime_active") is not (role in ("T", "C"))
                    or type(role_preparation.get("runtime_role_identity")) is not str
                    or len(role_preparation["runtime_role_identity"]) != 64):
                raise AssertionError(f"role {role} did not construct the exact frozen candidate runtime")
            if role in ("P", "M") and (
                    role_preparation.get("protected_fence") != {
                        "fence": "FENCED", "revision": 0,
                        "candidate_package_id": package.candidate_package_id,
                    }
                    or role_preparation.get("fenced_effect_probe_accepted") is not False):
                raise AssertionError(f"role {role} protected effect did not fail closed behind its fence")
            if role in ("T", "C") and role_preparation.get("protected_fence") is not None:
                raise AssertionError(f"role {role} unexpectedly received a P/M target fence")
            access = report["access"]
            if (not access["own_private_write"] or not access["shared_runtime_write_denied"]
                    or not access["root_store_write_denied"]
                    or set(access["other_private_write_denied"]) != set(ROLE_ORDER) - {role}
                    or not all(access["other_private_write_denied"].values())):
                raise AssertionError(f"role {role} filesystem isolation probe failed")
            if report["destination_channel_credentials"] != (
                    "NONE" if role == "T" else "ROLE_LOCAL_ONLY"):
                raise AssertionError(f"role {role} credential boundary mismatch")
            if report["production_github_mutation_credentials"] != "NONE":
                raise AssertionError(f"role {role} environment contains production GitHub credentials")
            reports[role] = report

        if len({process.pid for process in processes.values()}) != 4:
            raise AssertionError("role PIDs are not distinct")
        if len({process.sid for process in processes.values()}) != 4:
            raise AssertionError("role token SIDs are not distinct")
        if len(set(endpoints.values())) != 4:
            raise AssertionError("role IPC endpoints are not distinct")

        # Each destination independently rejects messages signed for another role.
        request = secrets.token_hex(12)
        nonce = secrets.token_hex(16)
        negative_results = {}
        for role in ("C", "P", "M"):
            other = next(item for item in ("C", "P", "M") if item != role)
            wrong = encode_message(
                channel=CHANNEL[other], request_id=request,
                payload={"command": "BOOTSTRAP_PROBE", "nonce": nonce}, key=keys[other],
            )
            processes[role].stdin.write(wrong + b"\n")
            processes[role].stdin.flush()
            response = processes[role].read_json_line()
            if response != {"accepted": False, "reason": "IPC_REJECTED"}:
                raise AssertionError(f"role {role} accepted another role's authenticated frame")
            correct = encode_message(
                channel=CHANNEL[role], request_id=request,
                payload={"command": "BOOTSTRAP_PROBE", "nonce": nonce}, key=keys[role],
            )
            processes[role].stdin.write(correct + b"\n")
            processes[role].stdin.flush()
            response = processes[role].read_json_line()
            if response.get("accepted") is not True:
                raise AssertionError(f"role {role} rejected its bound channel")
            from ipc import decode_ack
            decode_ack(response["ack"].encode("ascii"), expected_role=role,
                       expected_request_id=request, expected_nonce=nonce, key=keys[role])
            negative_results[role] = "cross-role rejected; bound channel accepted"

        # T has no C/P/M channel key and therefore cannot mint a protected request.
        processes["T"].send_json_line({"command": "RELEASE_ROOT", "role": "T"})
        if processes["T"].read_json_line() != {
            "accepted": False, "reason": "NO_DESTINATION_CHANNEL_CREDENTIALS",
        }:
            raise AssertionError("T accepted a protected operation without a channel credential")

        # No capability-release command exists in the closed encoder.
        try:
            encode_message(channel=CHANNEL["M"], request_id=request,
                           payload={"command": "RELEASE_ROOT", "nonce": nonce}, key=keys["M"])
        except ValueError:
            fence_release_denied = True
        else:
            fence_release_denied = False
        if not fence_release_denied:
            raise AssertionError("closed IPC admitted external fence release")

        for process in processes.values():
            process.send_json_line({"control": "STOP"})
        exit_codes = {role: process.wait() for role, process in processes.items()}
        if any(exit_code != 0 for exit_code in exit_codes.values()):
            raise AssertionError("one or more role workers did not stop cleanly")
        if substrate_process.stop() != 0:
            raise AssertionError("external substrate service did not stop cleanly")
        substrate_state = {
            "sid": substrate_process.sid, "token_type": substrate_process.token_type,
            "administrator": substrate_process.is_administrator,
            "pid": substrate_process.pid,
            "endpoint_identity": substrate_process.endpoint_identity,
            "implementation_identity": sha256((external / "fixture_substrate.py").read_bytes()),
            "configuration_identity": sha256(canonical_json_bytes(substrate_profile)),
            "working_directory": str(external),
        }
        with tempfile.TemporaryDirectory(prefix="g9-root-readiness-") as temp_root:
            fixture_database = Path(temp_root) / "non-authoritative-root.sqlite3"
            connection = sqlite3.connect(fixture_database)
            try:
                from root_admin import _SCHEMA_STATEMENTS
                for statement in _SCHEMA_STATEMENTS:
                    connection.execute(statement)
                connection.execute(
                    "INSERT INTO capability_fence(candidate_package_id, root_anchor_id, state, revision) "
                    "VALUES (?, ?, 'FENCED', 0)",
                    (package.candidate_package_id, root_anchor_id),
                )
                connection.commit()
            finally:
                connection.close()
            observed_root = inspect_uninitialized_root(
                fixture_database, expected_anchor_id=root_anchor_id,
                expected_candidate_package_id=package.candidate_package_id,
            )
            observed_root["observation_scope"] = "NON_AUTHORITATIVE_TEMPORARY_FIXTURE_ONLY"
            observed_root["canonical_root_database"] = "ABSENT_UNTOUCHED"
            observed_root["fixture_database_sha256"] = sha256(fixture_database.read_bytes())
        if ROOT_STORE_PATH.exists() or canonical_root_namespace.exists():
            raise RuntimeError("canonical root namespace/DB changed during the rehearsal")

        member_by_role = {item["role"]: item for item in graph["members"]}
        role_evidence = {}
        for role, report in reports.items():
            member = member_by_role[role]
            role_evidence[role] = _deployment_role_evidence(
                role, processes[role], report,
                candidate_package_id=package.candidate_package_id,
                runtime_sha256=package.runtime_sha256,
                wiring_identity=sha256(package.raw_resources[member["capability_wiring_resource"]]),
            )
        root_profile_sha = sha256(canonical_json_bytes(root_profile))
        substrate_profile_sha = sha256(canonical_json_bytes(substrate_profile))
        readiness_preimage = {
            "format": "autodev.genesis-deployment-readiness/v1",
            "candidate_package_id": package.candidate_package_id,
            "genesis_manifest_id": package.manifest_id,
            "deterministic_evidence_ids": [package.deterministic_evidence_id],
            "repository_source_commit": json.loads(package.build_definition)["repository_application_base"],
            "runtime_artifact_sha256": package.runtime_sha256,
            "python_runtime": {"identity": "CPython", "version": "3.13.14",
                               "path": str(PYTHON), "sha256": sha256(PYTHON.read_bytes())},
            "execution_isolation_dependency_id": json.loads(package.build_definition)["execution_isolation_dependency_id"],
            "root_fence_dependency_id": root_dependency_id,
            "root_fence_profile_sha256": root_profile_sha,
            "fixture_substrate_dependency_id": substrate_dependency_id,
            "fixture_substrate_profile_sha256": substrate_profile_sha,
            "root_anchor_id": root_anchor_id,
            "root_state_observation": observed_root,
            "roles": role_evidence,
            "staged_external_material": json.loads(package.build_definition)["external_tcb_material"],
            "substrate_service": substrate_state,
            "shared_runtime_read_only": all(
                reports[role]["access"]["shared_runtime_write_denied"] for role in ROLE_ORDER
            ),
            "cross_role_private_write_denial": {
                role: all(reports[role]["access"]["other_private_write_denied"].values())
                for role in ROLE_ORDER
            },
            "candidate_root_store_write_denial": {
                role: reports[role]["access"]["root_store_write_denied"] for role in ROLE_ORDER
            },
            "protected_endpoint_state": {
                "C_WRITER": {"state": "FENCED", "identity": sha256(
                    canonical_json_bytes(("C_WRITER", package.candidate_package_id))),
                    "credential_withheld": True},
                "P_PUBLICATION": {"state": "FENCED", "identity": sha256(
                    canonical_json_bytes(("P_PUBLICATION", substrate_profile_sha))),
                    "credential_withheld": True},
                "M_MERGE": {"state": "FENCED", "identity": sha256(
                    canonical_json_bytes(("M_MERGE", substrate_profile_sha))),
                    "credential_withheld": True},
            },
            "recovery_fence_inventory": [substrate_profile["external_recovery_endpoint"]["endpoint_id"]],
            "production_github_mutation_credentials": "NONE",
            "host_profile_id": sha256(canonical_json_bytes((root_profile, substrate_profile))),
            "observed_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        }
        readiness = build_deployment_readiness(readiness_preimage)
        if not verify_deployment_readiness(readiness):
            raise AssertionError("Deployment Readiness content-address validation failed")
        (candidate / "deployment-readiness.json").write_bytes(canonical_json_bytes(readiness))
        return {
            "candidate_package_id": package.candidate_package_id,
            "runtime_sha256": package.runtime_sha256,
            "manifest_id": package.manifest_id,
            "deterministic_evidence_id": package.deterministic_evidence_id,
            "root_anchor_id": root_anchor_id,
            "root_fence_dependency_id": root_dependency_id,
            "fixture_substrate_dependency_id": substrate_dependency_id,
            "deployment_readiness_id": readiness["record_id"],
            "deployment_readiness_path": str(candidate / "deployment-readiness.json"),
            "python_executable": str(PYTHON),
            "python_sha256": "081786173866d86cda1b06aa671848217fa0d635edb6dcd2218644466f4229cd",
            "roles": {
                role: {"pid": process.pid, "sid": process.sid,
                       "token_type": process.token_type,
                       "administrator": process.is_administrator, "report": reports[role]}
                for role, process in processes.items()
            },
            "cross_role_ipc": negative_results,
            "root_store_write_denial": all(
                reports[role]["access"]["root_store_write_denied"] for role in ROLE_ORDER
            ),
            "external_fence_release_denial": fence_release_denied,
            "substrate_process": substrate_state,
            "root_database": "ABSENT / UNTOUCHED",
            "production_github_mutation_credentials": "NONE",
        }
    finally:
        for process in processes.values():
            try:
                process.close()
            except Exception:
                pass
        if substrate_process is not None:
            try:
                if not substrate_process.stdin.closed:
                    substrate_process.stop()
            except Exception:
                substrate_process.close()


if __name__ == "__main__":
    if sys.argv[1:] == ["--stage-only"]:
        root_profile, substrate_profile, root_anchor_id, _ = _host_profiles()
        staged_package = assemble_candidate(
            git_cwd=str(REPOSITORY), root_fence_profile=root_profile,
            fixture_substrate_profile=substrate_profile, root_anchor_id=root_anchor_id,
        )
        candidate_directory, worker_path, external_directory = _stage(staged_package)
        staged = {item["path"]: item["sha256"]
                  for item in json.loads(staged_package.build_definition)["external_tcb_material"]}
        if ((candidate_directory / "runtime.zip").read_bytes() != staged_package.runtime_artifact
                or (candidate_directory / "candidate-package.zip").read_bytes()
                != staged_package.candidate_package):
            raise RuntimeError("staged candidate artifact bytes differ from regenerated package")
        print(json.dumps({
            "candidate_package_id": staged_package.candidate_package_id,
            "runtime_sha256": staged_package.runtime_sha256,
            "candidate_directory": str(candidate_directory),
            "worker": str(worker_path),
            "external_directory": str(external_directory),
            "external_tcb_sha256": staged,
            "staged_runtime_matches": True,
        }, sort_keys=True, separators=(",", ":")))
    elif not sys.argv[1:]:
        print(json.dumps(run_realized_roles(), sort_keys=True, separators=(",", ":")))
    else:
        raise SystemExit("usage: windows_role_runner.py [--stage-only]")
