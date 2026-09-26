"""Deterministic R2 source bundle and runtime archive builder (G9 external TCB)."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import io
import json
from pathlib import PurePosixPath
import subprocess
from zipfile import ZIP_STORED, ZipFile, ZipInfo

APPLICATION_BASE = "fd0cf5d910bf59e6f28aa36ae7b34a3b00eb3001"
R2_EXECUTABLE_BASE = "1c859faad04978a341a3527e034b41c0a849da1f"
# Kept as the single public spelling consumed by the assembler: this is the
# repository/application provenance base, not the reviewed executable base.
AUTHORIZED_BASE = APPLICATION_BASE
SOURCE_MEMBERS = (
    "src/autodev_control/trusted/errors.py",
    "src/autodev_control/trusted/identity.py",
    "src/autodev_control/trusted/parsing.py",
    "src/autodev_control/trusted/scope.py",
    "src/autodev_control/trusted/resources.py",
    "src/autodev_control/trusted/manifest.py",
    "src/autodev_control/trusted/genesis_resource_graph.py",
    "src/autodev_control/trusted/decision.py",
    "src/autodev_control/trusted/contract.py",
    "src/autodev_control/trusted/target_registration.py",
    "src/autodev_control/trusted/authorization.py",
    "src/autodev_control/trusted/operation.py",
    "src/autodev_control/trusted/state.py",
    "src/autodev_control/trusted/evidence.py",
    "src/autodev_control/trusted/review.py",
    "src/autodev_control/trusted/semantic_config.py",
    "src/autodev_control/trusted/semantic_context.py",
    "src/autodev_control/trusted/current_semantic_review.py",
    "src/autodev_control/trusted/__init__.py",
    "src/autodev_control/trusted/audit.py",
    "src/autodev_control/trusted/backend.py",
    "src/autodev_control/trusted/state_reader.py",
    "src/autodev_control/trusted/materialization.py",
    "src/autodev_control/trusted/protected_effect.py",
    "src/autodev_control/trusted/runtime_authority.py",
    "src/autodev_control/trusted/runtime_roles.py",
)
RUNTIME_MEMBERS = tuple(path.removeprefix("src/") for path in SOURCE_MEMBERS)


@dataclass(frozen=True, slots=True)
class BuiltArtifacts:
    source_bundle: bytes
    runtime_artifact: bytes
    source_manifest: bytes
    source_hashes: tuple[tuple[str, str], ...]


def canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _valid_source_path(path: str) -> bool:
    parsed = PurePosixPath(path)
    return (
        path.startswith("src/")
        and "\\" not in path
        and not parsed.is_absolute()
        and all(part not in ("", ".", "..") for part in parsed.parts)
    )


def _zip_info(path: str) -> ZipInfo:
    info = ZipInfo(path, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = ZIP_STORED
    info.create_system = 3
    info.external_attr = (0o100444 & 0xFFFF) << 16
    info.flag_bits = 0
    info.extra = b""
    info.comment = b""
    return info


def _archive(entries: tuple[tuple[str, bytes], ...]) -> bytes:
    names = tuple(name for name, _ in entries)
    if names != tuple(sorted(names)) or len(names) != len(set(names)):
        raise ValueError("archive members must be unique and sorted")
    stream = io.BytesIO()
    with ZipFile(stream, "w", compression=ZIP_STORED, allowZip64=False) as archive:
        for name, raw in entries:
            if not name or "\\" in name or name.startswith("/") or ".." in PurePosixPath(name).parts:
                raise ValueError("unsafe archive path")
            archive.writestr(_zip_info(name), raw)
    return stream.getvalue()


def deterministic_archive(entries: tuple[tuple[str, bytes], ...]) -> bytes:
    """Return the exact G9 ZIP encoding used for source/runtime/package images."""
    return _archive(entries)


def build_from_git(base: str = APPLICATION_BASE, *, git_cwd: str = ".") -> BuiltArtifacts:
    """Read only frozen Git blobs and derive exact source/runtime byte images."""
    if base != APPLICATION_BASE:
        raise ValueError("G9 source base must be the exact authorized commit")
    if len(SOURCE_MEMBERS) != 26 or len(set(SOURCE_MEMBERS)) != 26:
        raise ValueError("frozen source closure is not exactly 26 unique paths")
    source_entries: list[tuple[str, bytes]] = []
    runtime_entries: list[tuple[str, bytes]] = []
    manifest_members: list[dict[str, str]] = []
    hashes: list[tuple[str, str]] = []
    for source_path, runtime_path in zip(SOURCE_MEMBERS, RUNTIME_MEMBERS, strict=True):
        if not _valid_source_path(source_path) or runtime_path != source_path.removeprefix("src/"):
            raise ValueError("source/runtime mapping is not exact one-prefix removal")
        raw = subprocess.run(
            ["git", "show", f"{APPLICATION_BASE}:{source_path}"], cwd=git_cwd,
            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        ).stdout
        reviewed = subprocess.run(
            ["git", "show", f"{R2_EXECUTABLE_BASE}:{source_path}"], cwd=git_cwd,
            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        ).stdout
        if raw != reviewed:
            raise ValueError(f"current repository source differs from reviewed R2 bytes: {source_path}")
        digest = sha256(raw)
        source_entries.append((source_path, raw))
        runtime_entries.append((runtime_path, raw))
        manifest_members.append({
            "source_path": source_path,
            "runtime_path": runtime_path,
            "sha256": digest,
        })
        hashes.append((source_path, digest))
    source_manifest = canonical_json_bytes({
        "format": "autodev.genesis-source-bundle/v1",
        "repository_application_base": APPLICATION_BASE,
        "r2_executable_baseline": R2_EXECUTABLE_BASE,
        "member_count": 26,
        "members": manifest_members,
    })
    source_bundle = _archive(tuple(sorted((
        ("source_manifest.json", source_manifest), *source_entries,
    ))))
    runtime_artifact = _archive(tuple(sorted((
        ("autodev_control/", b""),
        ("autodev_control/trusted/", b""),
        *runtime_entries,
    ))))
    if len(runtime_entries) != 26 or len({name for name, _ in runtime_entries}) != 26:
        raise ValueError("runtime closure is not bijective and exact")
    if any(name.startswith("autodev_control/__init__") for name, _ in runtime_entries):
        raise ValueError("non-member top-level initializer entered runtime image")
    return BuiltArtifacts(
        source_bundle=source_bundle,
        runtime_artifact=runtime_artifact,
        source_manifest=source_manifest,
        source_hashes=tuple(hashes),
    )
