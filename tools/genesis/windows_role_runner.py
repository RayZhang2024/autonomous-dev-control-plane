"""Stage and exercise the four-role Windows G9 isolation realization.

This external-TCB tool is intentionally not part of the 26-member runtime.
Role credentials are obtained only by the launcher's hidden console prompts.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import sys
import zipfile

REPOSITORY = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(REPOSITORY / "src"))
sys.path.insert(0, str(HERE))
from assemble_candidate import assemble_candidate, write_package
from build_definition import sha256
from ipc import encode_message
from windows_role_launcher import ROLE_PRINCIPALS, launch_role

STAGING = Path(r"C:\AutodevG9")
SHARED = STAGING / "shared"
PRIVATE = STAGING / "private"
PYTHON = SHARED / "python313" / "python.exe"
ROOT_PROBE = STAGING
ROLE_ORDER = ("T", "C", "P", "M")
CHANNEL = {"C": "authenticated-t-to-c", "P": "authenticated-t-to-p",
           "M": "authenticated-t-to-m"}


def _stage(package) -> tuple[Path, Path]:
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
    external = SHARED / f"external-g9-v03-{external_id}"
    external.mkdir(exist_ok=True)
    for name in ("ipc.py", "role_worker.py", "windows_role_launcher.py", "windows_role_runner.py"):
        destination = external / name
        source = HERE / name
        if destination.exists():
            if destination.read_bytes() != source.read_bytes():
                raise RuntimeError(f"staged external-TCB file differs: {name}")
        else:
            shutil.copyfile(source, destination)
    return candidate, external / "role_worker.py"


def _role_bootstrap(package, graph: dict[str, object], candidate: Path, worker: Path,
                    role: str, keys: dict[str, bytes], endpoint: str) -> dict[str, object]:
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
    }
    if role in keys:
        value["channel_key_hex"] = keys[role].hex()
    return value


def run_realized_roles() -> dict[str, object]:
    package = assemble_candidate(git_cwd=str(REPOSITORY))
    candidate, worker = _stage(package)
    graph = json.loads(package.graph)
    keys = {role: secrets.token_bytes(32) for role in ("C", "P", "M")}
    endpoints = {role: secrets.token_hex(32) for role in ROLE_ORDER}
    processes = {}
    reports = {}
    try:
        for role in ROLE_ORDER:
            process = launch_role(
                role, python_executable=PYTHON, worker_script=worker,
                working_directory=PRIVATE / role,
                environment={"PYTHONDONTWRITEBYTECODE": "1"},
            )
            processes[role] = process
            if process.sid != ROLE_PRINCIPALS[role][1] or process.is_administrator:
                raise AssertionError("native token evidence did not match the exact role profile")
            process.send_json_line(_role_bootstrap(
                package, graph, candidate, worker, role, keys, endpoints[role],
            ))
            report = process.read_json_line()
            if set(report) != {
                "role", "pid", "ppid", "python_executable", "python_sha256", "runtime_sha256",
                "candidate_package_id", "runtime_generation", "endpoint_identity", "private_directory",
                "security_context_identity", "entrypoint_identity", "access",
                "destination_channel_credentials",
            }:
                raise AssertionError("role worker returned an open or incomplete identity report")
            if (report["role"] != role or report["pid"] != process.pid
                    or report["python_sha256"] != "081786173866d86cda1b06aa671848217fa0d635edb6dcd2218644466f4229cd"
                    or Path(report["python_executable"]).resolve() != PYTHON.resolve()
                    or report["runtime_sha256"] != package.runtime_sha256
                    or report["candidate_package_id"] != package.candidate_package_id
                    or report["endpoint_identity"] != endpoints[role]
                    or Path(report["private_directory"]).resolve() != (PRIVATE / role).resolve()):
                raise AssertionError(f"role {role} runtime/process binding mismatch")
            access = report["access"]
            if (not access["own_private_write"] or not access["shared_runtime_write_denied"]
                    or not access["root_store_write_denied"]
                    or set(access["other_private_write_denied"]) != set(ROLE_ORDER) - {role}
                    or not all(access["other_private_write_denied"].values())):
                raise AssertionError(f"role {role} filesystem isolation probe failed")
            if report["destination_channel_credentials"] != (
                    "NONE" if role == "T" else "ROLE_LOCAL_ONLY"):
                raise AssertionError(f"role {role} credential boundary mismatch")
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
        return {
            "candidate_package_id": package.candidate_package_id,
            "runtime_sha256": package.runtime_sha256,
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
            "production_github_mutation_credentials": "NONE",
        }
    finally:
        for process in processes.values():
            try:
                process.close()
            except Exception:
                pass


if __name__ == "__main__":
    if sys.argv[1:] == ["--stage-only"]:
        staged_package = assemble_candidate(git_cwd=str(REPOSITORY))
        candidate_directory, worker_path = _stage(staged_package)
        staged = {name: sha256((HERE / name).read_bytes())
                  for name in ("ipc.py", "role_worker.py", "windows_role_launcher.py", "windows_role_runner.py")}
        if ((candidate_directory / "runtime.zip").read_bytes() != staged_package.runtime_artifact
                or (candidate_directory / "candidate-package.zip").read_bytes()
                != staged_package.candidate_package):
            raise RuntimeError("staged candidate artifact bytes differ from regenerated package")
        print(json.dumps({
            "candidate_package_id": staged_package.candidate_package_id,
            "runtime_sha256": staged_package.runtime_sha256,
            "candidate_directory": str(candidate_directory),
            "worker": str(worker_path),
            "external_tcb_sha256": staged,
            "staged_runtime_matches": True,
        }, sort_keys=True, separators=(",", ":")))
    elif not sys.argv[1:]:
        print(json.dumps(run_realized_roles(), sort_keys=True, separators=(",", ":")))
    else:
        raise SystemExit("usage: windows_role_runner.py [--stage-only]")
