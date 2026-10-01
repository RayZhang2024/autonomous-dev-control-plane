"""Deterministic in-memory fixture materialization of untrusted proposals.

This work-plane result is not trusted candidate truth. It performs no repository
or control-state access, and grants no authorization or lifecycle consequence.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import struct
from typing import Protocol

from .candidate_producer import (
    CandidateProposal,
    ProposedChangeKind,
    ProposedFileChange,
)


MAX_BASE_LEAVES = 4096
MAX_PROPOSAL_CHANGES = 1024
MAX_TREE_DEPTH = 32
MAX_PATH_BYTES = 4096
MAX_TOTAL_PATH_BYTES = 1_048_576
MAX_NEW_CONTENT_BYTES = 16_777_216
MAX_MATERIALIZED_TREE_OBJECTS = 4096

BLOB_DOMAIN = "autodev.o2b.fixture-blob/v1"
TREE_ENTRY_DOMAIN = "autodev.o2b.fixture-tree-entry/v1"
TREE_DOMAIN = "autodev.o2b.fixture-tree/v1"
COMMIT_DOMAIN = "autodev.o2b.fixture-commit/v1"
SUPPORTED_FILE_MODES = ("100644", "100755")


class MaterializationStatus(Enum):
    MATERIALIZED = "MATERIALIZED"
    BASE_MISMATCH = "BASE_MISMATCH"
    BASE_SNAPSHOT_INVALID = "BASE_SNAPSHOT_INVALID"
    INVALID_PATH = "INVALID_PATH"
    DUPLICATE_PATH = "DUPLICATE_PATH"
    TREE_SHAPE_CONFLICT = "TREE_SHAPE_CONFLICT"
    INVALID_MODE = "INVALID_MODE"
    ADD_CONFLICT = "ADD_CONFLICT"
    REPLACE_MISSING = "REPLACE_MISSING"
    DELETE_MISSING = "DELETE_MISSING"
    LIMIT_EXCEEDED = "LIMIT_EXCEEDED"
    INVALID_PROPOSAL = "INVALID_PROPOSAL"


class FixtureObjectKind(Enum):
    BLOB = "BLOB"
    TREE = "TREE"


@dataclass(frozen=True)
class FixtureBaseLeaf:
    path: str
    mode: str
    object_id: str

    def __post_init__(self) -> None:
        if type(self.path) is not str or type(self.mode) is not str or type(self.object_id) is not str:
            raise TypeError("base leaf fields must be exact strings")


@dataclass(frozen=True)
class FixtureBaseSnapshot:
    repository_id: str
    expected_base_revision: str
    leaves: tuple[FixtureBaseLeaf, ...]

    def __post_init__(self) -> None:
        if type(self.repository_id) is not str or type(self.expected_base_revision) is not str:
            raise TypeError("base snapshot identities must be exact strings")
        if type(self.leaves) is not tuple or any(type(leaf) is not FixtureBaseLeaf for leaf in self.leaves):
            raise TypeError("base snapshot leaves must be an exact FixtureBaseLeaf tuple")


@dataclass(frozen=True)
class FixtureMaterializedTreeEntry:
    name: str
    object_kind: FixtureObjectKind
    mode: str
    object_id: str


@dataclass(frozen=True)
class FixtureMaterializedTree:
    directory_path: str
    tree_id: str
    entries: tuple[FixtureMaterializedTreeEntry, ...]


@dataclass(frozen=True)
class FixtureMaterializedBlob:
    object_id: str
    content_bytes: bytes


@dataclass(frozen=True)
class FixtureMaterializedCandidate:
    repository_id: str
    base_revision: str
    candidate_commit_id: str
    result_tree_id: str
    candidate_trees: tuple[FixtureMaterializedTree, ...]
    created_blobs: tuple[FixtureMaterializedBlob, ...]


@dataclass(frozen=True)
class MaterializationResult:
    status: MaterializationStatus
    candidate: FixtureMaterializedCandidate | None = None

    def __post_init__(self) -> None:
        if type(self.status) is not MaterializationStatus:
            raise TypeError("status must be an exact materialization status")
        if self.status is MaterializationStatus.MATERIALIZED:
            if type(self.candidate) is not FixtureMaterializedCandidate:
                raise ValueError("MATERIALIZED requires exactly one candidate")
        elif self.candidate is not None:
            raise ValueError("non-success cannot carry a candidate")


class FixtureCandidateMaterializer(Protocol):
    def materialize(
        self, proposal: CandidateProposal, base_snapshot: FixtureBaseSnapshot
    ) -> MaterializationResult: ...


def u64be(value: int) -> bytes:
    if type(value) is not int:
        raise TypeError("u64be value must be an exact integer")
    if not 0 <= value < 1 << 64:
        raise ValueError("u64be value is out of range")
    return struct.pack(">Q", value)


def fixture_digest(domain: str, *parts: bytes) -> str:
    if type(domain) is not str:
        raise TypeError("digest domain must be an exact string")
    domain_bytes = domain.encode("ascii")
    if any(type(part) is not bytes for part in parts):
        raise TypeError("digest parts must be exact bytes")
    framed = bytearray(u64be(len(domain_bytes)))
    framed.extend(domain_bytes)
    framed.extend(u64be(len(parts)))
    for part in parts:
        framed.extend(u64be(len(part)))
        framed.extend(part)
    return hashlib.sha256(framed).hexdigest()


def _is_lower_hex(value: str, lengths: tuple[int, ...]) -> bool:
    return (
        type(value) is str
        and len(value) in lengths
        and all(character in "0123456789abcdef" for character in value)
    )


def _valid_repository_id(value: str) -> bool:
    return (
        type(value) is str
        and 1 <= len(value) <= 20
        and value[0] != "0"
        and all("0" <= character <= "9" for character in value)
    )


def _path_encoding(path: str) -> tuple[bytes | None, MaterializationStatus | None]:
    if type(path) is not str or not path or path.startswith("/") or path.endswith("/"):
        return None, MaterializationStatus.INVALID_PATH
    if "\x00" in path or "\\" in path:
        return None, MaterializationStatus.INVALID_PATH
    components = path.split("/")
    if any(component in ("", ".", "..") for component in components):
        return None, MaterializationStatus.INVALID_PATH
    try:
        encoded = path.encode("utf-8")
    except UnicodeEncodeError:
        return None, MaterializationStatus.INVALID_PATH
    if len(encoded) > MAX_PATH_BYTES or len(components) > MAX_TREE_DEPTH:
        return encoded, MaterializationStatus.LIMIT_EXCEEDED
    return encoded, None


def _tree_shape_conflict(paths: set[str]) -> bool:
    for path in paths:
        components = path.split("/")
        for count in range(1, len(components)):
            if "/".join(components[:count]) in paths:
                return True
    return False


def _entry_digest(entry: FixtureMaterializedTreeEntry) -> str:
    return fixture_digest(
        TREE_ENTRY_DOMAIN,
        entry.name.encode("utf-8"),
        b"blob" if entry.object_kind is FixtureObjectKind.BLOB else b"tree",
        entry.mode.encode("ascii"),
        entry.object_id.encode("ascii"),
    )


def _failed(status: MaterializationStatus) -> MaterializationResult:
    return MaterializationResult(status)


class DeterministicFixtureCandidateMaterializer:
    """Apply a proposal to caller-supplied fixture leaves in memory only."""

    def materialize(
        self, proposal: CandidateProposal, base_snapshot: FixtureBaseSnapshot
    ) -> MaterializationResult:
        if type(proposal) is not CandidateProposal or type(base_snapshot) is not FixtureBaseSnapshot:
            raise TypeError("exact proposal and fixture base snapshot required")
        if (
            type(proposal.claimed_base_revision) is not str
            or type(proposal.changes) is not tuple
            or any(type(change) is not ProposedFileChange for change in proposal.changes)
        ):
            return _failed(MaterializationStatus.INVALID_PROPOSAL)

        if not _valid_repository_id(base_snapshot.repository_id):
            return _failed(MaterializationStatus.BASE_SNAPSHOT_INVALID)
        if not _is_lower_hex(base_snapshot.expected_base_revision, (40, 64)):
            return _failed(MaterializationStatus.BASE_SNAPSHOT_INVALID)
        if len(base_snapshot.leaves) > MAX_BASE_LEAVES:
            return _failed(MaterializationStatus.LIMIT_EXCEEDED)

        base_files: dict[str, tuple[str, str]] = {}
        base_total_path_bytes = 0
        for leaf in base_snapshot.leaves:
            encoded, path_status = _path_encoding(leaf.path)
            if path_status is not None:
                return _failed(path_status)
            if not _is_lower_hex(leaf.object_id, (40, 64)):
                return _failed(MaterializationStatus.BASE_SNAPSHOT_INVALID)
            if leaf.mode not in SUPPORTED_FILE_MODES:
                return _failed(MaterializationStatus.INVALID_MODE)
            if leaf.path in base_files:
                return _failed(MaterializationStatus.DUPLICATE_PATH)
            base_files[leaf.path] = (leaf.mode, leaf.object_id)
            base_total_path_bytes += len(encoded)
            if base_total_path_bytes > MAX_TOTAL_PATH_BYTES:
                return _failed(MaterializationStatus.LIMIT_EXCEEDED)
        if _tree_shape_conflict(set(base_files)):
            return _failed(MaterializationStatus.TREE_SHAPE_CONFLICT)

        if proposal.claimed_base_revision != base_snapshot.expected_base_revision:
            return _failed(MaterializationStatus.BASE_MISMATCH)
        if len(proposal.changes) > MAX_PROPOSAL_CHANGES:
            return _failed(MaterializationStatus.LIMIT_EXCEEDED)

        proposal_total_path_bytes = 0
        seen_proposal_paths: set[str] = set()
        new_content_bytes = 0
        for change in proposal.changes:
            if (
                type(change.kind) is not ProposedChangeKind
                or type(change.path) is not str
                or (change.content_bytes is not None and type(change.content_bytes) is not bytes)
                or (change.mode is not None and type(change.mode) is not str)
            ):
                return _failed(MaterializationStatus.INVALID_PROPOSAL)
            encoded, path_status = _path_encoding(change.path)
            if path_status is not None:
                return _failed(path_status)
            proposal_total_path_bytes += len(encoded)
            if proposal_total_path_bytes > MAX_TOTAL_PATH_BYTES:
                return _failed(MaterializationStatus.LIMIT_EXCEEDED)
            if change.path in seen_proposal_paths:
                return _failed(MaterializationStatus.DUPLICATE_PATH)
            seen_proposal_paths.add(change.path)
            if change.kind is ProposedChangeKind.DELETE:
                if change.content_bytes is not None or change.mode is not None:
                    return _failed(MaterializationStatus.INVALID_PROPOSAL)
            else:
                if type(change.content_bytes) is not bytes:
                    return _failed(MaterializationStatus.INVALID_PROPOSAL)
                new_content_bytes += len(change.content_bytes)
                if new_content_bytes > MAX_NEW_CONTENT_BYTES:
                    return _failed(MaterializationStatus.LIMIT_EXCEEDED)

        final_files = dict(base_files)
        created_content: dict[str, bytes] = {}
        for change in proposal.changes:
            present = change.path in final_files
            if change.kind is ProposedChangeKind.ADD:
                if present:
                    return _failed(MaterializationStatus.ADD_CONFLICT)
                if change.mode not in SUPPORTED_FILE_MODES:
                    return _failed(MaterializationStatus.INVALID_MODE)
                mode = change.mode
            elif change.kind is ProposedChangeKind.REPLACE:
                if not present:
                    return _failed(MaterializationStatus.REPLACE_MISSING)
                if change.mode is not None and change.mode not in SUPPORTED_FILE_MODES:
                    return _failed(MaterializationStatus.INVALID_MODE)
                mode = final_files[change.path][0] if change.mode is None else change.mode
            else:
                if not present:
                    return _failed(MaterializationStatus.DELETE_MISSING)
                del final_files[change.path]
                continue

            blob_id = fixture_digest(BLOB_DOMAIN, change.content_bytes)
            final_files[change.path] = (mode, blob_id)
            created_content.setdefault(blob_id, change.content_bytes)

        final_total_path_bytes = 0
        for path in final_files:
            encoded, path_status = _path_encoding(path)
            if path_status is not None:
                return _failed(path_status)
            final_total_path_bytes += len(encoded)
            if final_total_path_bytes > MAX_TOTAL_PATH_BYTES:
                return _failed(MaterializationStatus.LIMIT_EXCEEDED)
        if _tree_shape_conflict(set(final_files)):
            return _failed(MaterializationStatus.TREE_SHAPE_CONFLICT)

        directories: set[str] = {""}
        files_by_directory: dict[str, list[str]] = {}
        for path in final_files:
            components = path.split("/")
            parent = ""
            for component in components[:-1]:
                parent = component if not parent else parent + "/" + component
                directories.add(parent)
            files_by_directory.setdefault(
                "" if len(components) == 1 else "/".join(components[:-1]), []
            ).append(path)
        if len(directories) > MAX_MATERIALIZED_TREE_OBJECTS:
            return _failed(MaterializationStatus.LIMIT_EXCEEDED)

        directories_by_parent: dict[str, list[str]] = {}
        for directory in directories:
            if directory:
                parent = directory.rsplit("/", 1)[0] if "/" in directory else ""
                directories_by_parent.setdefault(parent, []).append(directory)

        tree_ids: dict[str, str] = {}
        tree_values: dict[str, FixtureMaterializedTree] = {}
        for directory in sorted(
            directories,
            key=lambda value: (-(0 if not value else value.count("/") + 1), value.encode("utf-8")),
        ):
            entries: list[FixtureMaterializedTreeEntry] = []
            for path in files_by_directory.get(directory, ()):
                name = path.rsplit("/", 1)[-1]
                mode, object_id = final_files[path]
                entries.append(FixtureMaterializedTreeEntry(
                    name, FixtureObjectKind.BLOB, mode, object_id
                ))
            for child_directory in directories_by_parent.get(directory, ()):
                name = child_directory.rsplit("/", 1)[-1]
                entries.append(FixtureMaterializedTreeEntry(
                    name,
                    FixtureObjectKind.TREE,
                    "040000",
                    tree_ids[child_directory],
                ))
            entries.sort(key=lambda entry: entry.name.encode("utf-8"))
            entry_hashes = tuple(_entry_digest(entry).encode("ascii") for entry in entries)
            tree_id = fixture_digest(
                TREE_DOMAIN, directory.encode("utf-8"), *entry_hashes
            )
            tree_ids[directory] = tree_id
            tree_values[directory] = FixtureMaterializedTree(
                directory, tree_id, tuple(entries)
            )

        root_tree_id = tree_ids[""]
        candidate_commit_id = fixture_digest(
            COMMIT_DOMAIN,
            base_snapshot.expected_base_revision.encode("ascii"),
            root_tree_id.encode("ascii"),
        )
        candidate = FixtureMaterializedCandidate(
            base_snapshot.repository_id,
            base_snapshot.expected_base_revision,
            candidate_commit_id,
            root_tree_id,
            tuple(
                tree_values[path]
                for path in sorted(directories, key=lambda value: value.encode("utf-8"))
            ),
            tuple(
                FixtureMaterializedBlob(blob_id, created_content[blob_id])
                for blob_id in sorted(created_content, key=lambda value: value.encode("ascii"))
            ),
        )
        return MaterializationResult(MaterializationStatus.MATERIALIZED, candidate)
