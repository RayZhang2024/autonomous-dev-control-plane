"""Unit tests for deterministic fixture proposal materialization."""

import ast
import builtins
import os
from pathlib import Path
import socket
import subprocess
import threading
import time
from unittest.mock import patch

import pytest

from autodev_control.workplane.candidate_producer import (
    CandidateProposal,
    ProposedChangeKind,
    ProposedFileChange,
)
from autodev_control.workplane.fixture_candidate_materializer import (
    BLOB_DOMAIN,
    COMMIT_DOMAIN,
    MAX_BASE_LEAVES,
    MAX_MATERIALIZED_TREE_OBJECTS,
    MAX_NEW_CONTENT_BYTES,
    MAX_PATH_BYTES,
    MAX_PROPOSAL_CHANGES,
    MAX_TOTAL_PATH_BYTES,
    MAX_TREE_DEPTH,
    TREE_DOMAIN,
    TREE_ENTRY_DOMAIN,
    DeterministicFixtureCandidateMaterializer,
    FixtureBaseLeaf,
    FixtureBaseSnapshot,
    FixtureObjectKind,
    FixtureMaterializedBlob,
    FixtureMaterializedCandidate,
    FixtureMaterializedTree,
    FixtureMaterializedTreeEntry,
    MaterializationResult,
    MaterializationStatus,
    fixture_digest,
    u64be,
)


BASE = "a" * 40
MATERIALIZER = DeterministicFixtureCandidateMaterializer()


def leaf(path: str, object_id: str = "1" * 40, mode: str = "100644") -> FixtureBaseLeaf:
    return FixtureBaseLeaf(path, mode, object_id)


def snapshot(
    leaves: tuple[FixtureBaseLeaf, ...] = (),
    *,
    repository_id: str = "1",
    revision: str = BASE,
) -> FixtureBaseSnapshot:
    return FixtureBaseSnapshot(repository_id, revision, leaves)


def change(
    kind: ProposedChangeKind,
    path: str,
    content: bytes | None = None,
    mode: str | None = None,
) -> ProposedFileChange:
    return ProposedFileChange(kind, path, content, mode)


def proposal(*changes: ProposedFileChange, revision: str = BASE) -> CandidateProposal:
    return CandidateProposal(revision, tuple(changes))


def run(
    value: CandidateProposal,
    base: FixtureBaseSnapshot | None = None,
) -> MaterializationResult:
    return MATERIALIZER.materialize(value, snapshot() if base is None else base)


def expect_status(status: MaterializationStatus, result: MaterializationResult) -> None:
    assert result.status is status
    assert result.candidate is None


def success(result: MaterializationResult) -> FixtureMaterializedCandidate:
    assert result.status is MaterializationStatus.MATERIALIZED
    assert result.candidate is not None
    return result.candidate


def test_u64be_and_all_frozen_golden_vectors() -> None:
    assert u64be(0) == b"\x00" * 8
    assert u64be((1 << 64) - 1) == b"\xff" * 8
    with pytest.raises(ValueError):
        u64be(1 << 64)

    empty_blob = fixture_digest(BLOB_DOMAIN, b"")
    assert empty_blob == "347713c761a18a787fdec70f52ef6ae5c881160535c457ea2ec513356971c41c"
    assert fixture_digest(TREE_DOMAIN, b"") == "0b36169b7373673d2a90a679d6f520a1caa2a0dd469efef43070e7402148986b"

    entry_id = fixture_digest(
        TREE_ENTRY_DOMAIN,
        b"a.txt",
        b"blob",
        b"100644",
        empty_blob.encode("ascii"),
    )
    assert entry_id == "7a959fe2c093f282e648e5246894b64376b7d275b73c52b4cfb7139b4669eb4a"
    root_id = fixture_digest(TREE_DOMAIN, b"", entry_id.encode("ascii"))
    assert root_id == "d17625089c96ddb33f54da0d39bf31c515c1f1f595c4f8d72b0ebaf509b5aa61"
    assert fixture_digest(COMMIT_DOMAIN, b"a" * 40, root_id.encode("ascii")) == (
        "d50ef5f6549de2397e2e17fd9604e06742aaa3e7caf3943098c177401d911585"
    )

    result = success(run(proposal(change(ProposedChangeKind.ADD, "a.txt", b"", "100644"))))
    assert result.result_tree_id == root_id


@pytest.mark.parametrize(
    ("base", "status"),
    [
        (snapshot(repository_id="0"), MaterializationStatus.BASE_SNAPSHOT_INVALID),
        (snapshot(repository_id="１２"), MaterializationStatus.BASE_SNAPSHOT_INVALID),
        (snapshot(repository_id="1" * 21), MaterializationStatus.BASE_SNAPSHOT_INVALID),
        (snapshot(revision="A" * 40), MaterializationStatus.BASE_SNAPSHOT_INVALID),
        (snapshot(revision="a" * 39), MaterializationStatus.BASE_SNAPSHOT_INVALID),
        (snapshot((leaf("f.txt", "A" * 40),)), MaterializationStatus.BASE_SNAPSHOT_INVALID),
        (snapshot((leaf("f.txt", "z" * 40),)), MaterializationStatus.BASE_SNAPSHOT_INVALID),
        (snapshot((leaf("f.txt", mode="100600"),)), MaterializationStatus.INVALID_MODE),
    ],
)
def test_base_scalar_and_mode_validation(
    base: FixtureBaseSnapshot, status: MaterializationStatus
) -> None:
    expect_status(status, run(proposal(), base))


def test_repository_id_accepts_ascii_decimal_shape_only() -> None:
    assert success(run(proposal(), snapshot(repository_id="1"))).repository_id == "1"
    assert success(run(proposal(), snapshot(repository_id="12345678901234567890"))).repository_id == "12345678901234567890"
    for invalid in ("", "0", "01", "+1", "-1", "1.0", "١"):
        expect_status(
            MaterializationStatus.BASE_SNAPSHOT_INVALID,
            run(proposal(), snapshot(repository_id=invalid)),
        )


@pytest.mark.parametrize(
    "path",
    ["", "/root", "tail/", "a//b", "./a", "a/.", "../a", "a/../b", "a\\b", "a\x00b", "\ud800"],
)
def test_invalid_git_path_grammar(path: str) -> None:
    expect_status(
        MaterializationStatus.INVALID_PATH,
        run(proposal(), snapshot((leaf(path),))),
    )


def test_paths_are_literal_utf8_not_host_normalized() -> None:
    paths = ("C:/name", "é.txt", "e\u0301.txt")
    result = success(run(proposal(*(
        change(ProposedChangeKind.ADD, path, path.encode("utf-8"), "100644")
        for path in paths
    ))))
    emitted = {
        tree.directory_path + ("/" if tree.directory_path else "") + entry.name
        for tree in result.candidate_trees
        for entry in tree.entries
        if entry.object_kind is FixtureObjectKind.BLOB
    }
    assert emitted == set(paths)
    assert "é.txt" in emitted and "e\u0301.txt" in emitted


def test_base_revision_mismatch_has_no_candidate() -> None:
    expect_status(
        MaterializationStatus.BASE_MISMATCH,
        run(proposal(revision="b" * 40)),
    )


def test_base_duplicate_paths_and_file_directory_collisions() -> None:
    expect_status(
        MaterializationStatus.DUPLICATE_PATH,
        run(proposal(), snapshot((leaf("same"), leaf("same", "2" * 40)))),
    )
    expect_status(
        MaterializationStatus.TREE_SHAPE_CONFLICT,
        run(proposal(), snapshot((leaf("a"), leaf("a/b", "2" * 40)))),
    )


def test_proposal_duplicate_paths_and_change_semantics() -> None:
    expect_status(
        MaterializationStatus.DUPLICATE_PATH,
        run(proposal(
            change(ProposedChangeKind.ADD, "x", b"1", "100644"),
            change(ProposedChangeKind.ADD, "x", b"2", "100644"),
        )),
    )
    expect_status(
        MaterializationStatus.ADD_CONFLICT,
        run(proposal(change(ProposedChangeKind.ADD, "x", b"new", "100644")), snapshot((leaf("x"),))),
    )
    expect_status(
        MaterializationStatus.INVALID_MODE,
        run(proposal(change(ProposedChangeKind.ADD, "x", b"new"))),
    )
    expect_status(
        MaterializationStatus.INVALID_MODE,
        run(proposal(change(ProposedChangeKind.REPLACE, "x", b"new", "100600")), snapshot((leaf("x"),))),
    )
    expect_status(
        MaterializationStatus.REPLACE_MISSING,
        run(proposal(change(ProposedChangeKind.REPLACE, "missing", b"new"))),
    )
    expect_status(
        MaterializationStatus.DELETE_MISSING,
        run(proposal(change(ProposedChangeKind.DELETE, "missing"))),
    )
    expect_status(
        MaterializationStatus.INVALID_PROPOSAL,
        run(proposal(change(ProposedChangeKind.DELETE, "x", mode="100644")), snapshot((leaf("x"),))),
    )


def test_delete_with_forged_content_payload_is_rejected() -> None:
    # O2a's public constructor rejects this shape; forge it to exercise O2b's
    # defensive boundary if an invalid proposal object arrives by other means.
    invalid_delete = object.__new__(ProposedFileChange)
    object.__setattr__(invalid_delete, "kind", ProposedChangeKind.DELETE)
    object.__setattr__(invalid_delete, "path", "x")
    object.__setattr__(invalid_delete, "content_bytes", b"unexpected")
    object.__setattr__(invalid_delete, "mode", None)
    invalid_proposal = CandidateProposal(BASE, (invalid_delete,))
    expect_status(
        MaterializationStatus.INVALID_PROPOSAL,
        run(invalid_proposal, snapshot((leaf("x"),))),
    )


def test_materialization_does_not_mutate_the_proposal() -> None:
    original = proposal(
        change(ProposedChangeKind.ADD, "x", b"new", "100644"),
        change(ProposedChangeKind.ADD, "y", b"other", "100755"),
    )
    before = original
    success(run(original))
    assert original is before
    assert original.changes == before.changes


def test_replace_preserves_or_explicitly_changes_base_mode() -> None:
    base = snapshot((leaf("run.sh", "1" * 40, "100755"),))
    preserved = success(run(proposal(change(ProposedChangeKind.REPLACE, "run.sh", b"new")), base))
    changed = success(run(proposal(change(ProposedChangeKind.REPLACE, "run.sh", b"new", "100644")), base))

    def file_entry(candidate: FixtureMaterializedCandidate) -> FixtureMaterializedTreeEntry:
        return next(entry for tree in candidate.candidate_trees for entry in tree.entries if entry.name == "run.sh")

    assert file_entry(preserved).mode == "100755"
    assert file_entry(changed).mode == "100644"
    assert preserved.result_tree_id != changed.result_tree_id


def test_final_prefix_conflict_fails_closed() -> None:
    expect_status(
        MaterializationStatus.TREE_SHAPE_CONFLICT,
        run(proposal(change(ProposedChangeKind.ADD, "a/b", b"nested", "100644")), snapshot((leaf("a"),))),
    )
    expect_status(
        MaterializationStatus.TREE_SHAPE_CONFLICT,
        run(proposal(change(ProposedChangeKind.ADD, "a", b"file", "100644")), snapshot((leaf("a/b"),))),
    )


def test_empty_proposal_preserves_base_and_has_root_tree_only() -> None:
    base = snapshot((leaf("keep", "1" * 40),))
    candidate = success(run(proposal(), base))
    assert candidate.created_blobs == ()
    assert tuple(tree.directory_path for tree in candidate.candidate_trees) == ("",)
    keep_entry = next(entry for entry in candidate.candidate_trees[0].entries if entry.name == "keep")
    assert keep_entry.object_id == "1" * 40


def test_unchanged_ids_and_created_blob_deduplication() -> None:
    base = snapshot((leaf("keep", "1" * 40),))
    candidate = success(run(proposal(
        change(ProposedChangeKind.ADD, "a/one", b"same", "100644"),
        change(ProposedChangeKind.ADD, "b/two", b"same", "100755"),
    ), base))
    assert candidate.created_blobs == (
        FixtureMaterializedBlob(fixture_digest(BLOB_DOMAIN, b"same"), b"same"),
    )
    keep_entry = next(entry for entry in candidate.candidate_trees[0].entries if entry.name == "keep")
    assert keep_entry.object_id == "1" * 40


def test_proposal_and_base_order_do_not_change_materialization() -> None:
    first = proposal(
        change(ProposedChangeKind.ADD, "z/file", b"z", "100644"),
        change(ProposedChangeKind.ADD, "a/file", b"a", "100755"),
    )
    second = proposal(*reversed(first.changes))
    base_a = snapshot((leaf("base-z", "2" * 40), leaf("base-a", "3" * 40)))
    base_b = snapshot(tuple(reversed(base_a.leaves)))

    result_a = success(run(first, base_a))
    result_b = success(run(second, base_b))
    assert result_a == result_b
    assert tuple(tree.directory_path for tree in result_a.candidate_trees) == ("", "a", "z")
    assert tuple(blob.object_id for blob in result_a.created_blobs) == tuple(
        sorted((blob.object_id for blob in result_a.created_blobs), key=lambda value: value.encode("ascii"))
    )


def test_identical_subtree_content_is_bound_to_directory_path() -> None:
    candidate = success(run(proposal(
        change(ProposedChangeKind.ADD, "left/file", b"same", "100644"),
        change(ProposedChangeKind.ADD, "right/file", b"same", "100644"),
    )))
    trees = {tree.directory_path: tree.tree_id for tree in candidate.candidate_trees}
    assert trees["left"] != trees["right"]


def test_content_change_and_mode_change_change_tree_identity() -> None:
    base = snapshot((leaf("file", "1" * 40, "100644"),))
    original = success(run(proposal(change(ProposedChangeKind.REPLACE, "file", b"one")), base))
    changed_content = success(run(proposal(change(ProposedChangeKind.REPLACE, "file", b"two")), base))
    changed_mode = success(run(proposal(change(ProposedChangeKind.REPLACE, "file", b"one", "100755")), base))
    assert len({original.result_tree_id, changed_content.result_tree_id, changed_mode.result_tree_id}) == 3


def test_all_structural_limits() -> None:
    long_valid = "x" * MAX_PATH_BYTES
    assert run(proposal(change(ProposedChangeKind.ADD, long_valid, b"", "100644"))).status is MaterializationStatus.MATERIALIZED
    expect_status(
        MaterializationStatus.LIMIT_EXCEEDED,
        run(proposal(change(ProposedChangeKind.ADD, "x" * (MAX_PATH_BYTES + 1), b"", "100644"))),
    )
    assert run(proposal(change(ProposedChangeKind.ADD, "/".join(["d"] * (MAX_TREE_DEPTH - 1) + ["f"]), b"", "100644"))).status is MaterializationStatus.MATERIALIZED
    expect_status(
        MaterializationStatus.LIMIT_EXCEEDED,
        run(proposal(change(ProposedChangeKind.ADD, "/".join(["d"] * MAX_TREE_DEPTH + ["f"]), b"", "100644"))),
    )
    expect_status(
        MaterializationStatus.LIMIT_EXCEEDED,
        run(proposal(), snapshot(tuple(leaf(f"f{i:04d}") for i in range(MAX_BASE_LEAVES + 1)))),
    )
    expect_status(
        MaterializationStatus.LIMIT_EXCEEDED,
        run(proposal(*(change(ProposedChangeKind.ADD, f"f{i:04d}", b"", "100644") for i in range(MAX_PROPOSAL_CHANGES + 1)))),
    )
    expect_status(
        MaterializationStatus.LIMIT_EXCEEDED,
        run(proposal(change(ProposedChangeKind.ADD, "big", b"x" * (MAX_NEW_CONTENT_BYTES + 1), "100644"))),
    )
    assert run(proposal(change(ProposedChangeKind.ADD, "big", b"x" * MAX_NEW_CONTENT_BYTES, "100644"))).status is MaterializationStatus.MATERIALIZED


def _long_paths(count: int, length: int, prefix: str) -> tuple[str, ...]:
    return tuple(f"{prefix}{index:04d}/" + "x" * (length - len(f"{prefix}{index:04d}/")) for index in range(count))


def test_base_proposal_and_final_path_totals_are_independent() -> None:
    base_paths = _long_paths(257, MAX_PATH_BYTES, "b")
    expect_status(
        MaterializationStatus.LIMIT_EXCEEDED,
        run(proposal(), snapshot(tuple(leaf(path) for path in base_paths))),
    )
    proposal_paths = _long_paths(257, MAX_PATH_BYTES, "p")
    expect_status(
        MaterializationStatus.LIMIT_EXCEEDED,
        run(proposal(*(change(ProposedChangeKind.ADD, path, b"", "100644") for path in proposal_paths))),
    )
    old_paths = _long_paths(150, 3500, "o")
    new_paths = _long_paths(150, 3500, "n")
    expect_status(
        MaterializationStatus.LIMIT_EXCEEDED,
        run(
            proposal(*(change(ProposedChangeKind.ADD, path, b"", "100644") for path in new_paths)),
            snapshot(tuple(leaf(path) for path in old_paths)),
        ),
    )
    assert MAX_TOTAL_PATH_BYTES == 1_048_576


def test_materialized_tree_object_limit() -> None:
    paths = []
    for index in range(133):
        components = [f"d{index:03d}"] + [f"l{level:02d}" for level in range(MAX_TREE_DEPTH - 2)] + [f"f{index:03d}"]
        paths.append("/".join(components))
    expect_status(
        MaterializationStatus.LIMIT_EXCEEDED,
        run(proposal(*(change(ProposedChangeKind.ADD, path, b"", "100644") for path in paths))),
    )


def test_no_runtime_external_side_effects() -> None:
    materializer = DeterministicFixtureCandidateMaterializer()
    request = proposal(change(ProposedChangeKind.ADD, "file", b"content", "100644"))
    forbidden = AssertionError("materializer attempted external side effects")
    with (
        patch.object(socket, "socket", side_effect=forbidden),
        patch.object(socket, "create_connection", side_effect=forbidden),
        patch.object(subprocess, "Popen", side_effect=forbidden),
        patch.object(subprocess, "run", side_effect=forbidden),
        patch.object(os, "system", side_effect=forbidden),
        patch.object(os, "open", side_effect=forbidden),
        patch.object(builtins, "open", side_effect=forbidden),
        patch.object(Path, "open", side_effect=forbidden),
        patch.object(Path, "write_bytes", side_effect=forbidden),
        patch.object(Path, "write_text", side_effect=forbidden),
        patch.object(time, "sleep", side_effect=forbidden),
        patch.object(threading, "Thread", side_effect=forbidden),
    ):
        assert MATERIALIZER.materialize(request, snapshot()).status is MaterializationStatus.MATERIALIZED


def test_materializer_import_surface_is_work_plane_only() -> None:
    source = Path(__file__).resolve().parents[2] / "src" / "autodev_control" / "workplane" / "fixture_candidate_materializer.py"
    imports = set()
    for node in ast.walk(ast.parse(source.read_text(encoding="utf-8"))):
        if isinstance(node, ast.ImportFrom):
            imports.add(node.module)
        elif isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
    assert imports == {
        "__future__",
        "dataclasses",
        "enum",
        "hashlib",
        "struct",
        "typing",
        "candidate_producer",
    }
