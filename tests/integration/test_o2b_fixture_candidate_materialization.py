"""Independent O2b verification and trusted fixture admission proof."""

from __future__ import annotations

from dataclasses import replace
import hashlib



import pytest

from autodev_control.trusted.gates import ControlStateGate, GateResultCode
from autodev_control.trusted.identity import GitSha, RawSha256
from autodev_control.trusted.materialization import (
    FixtureGitCommit,
    FixtureGitObjectStore,
    FixtureGitTree,
    FixtureGitTreeEntry,
    GitBlobMode,
    GitObjectKind,
    MutationFact,
    MutationKind,
)
from autodev_control.trusted.operation import CandidateId
from autodev_control.trusted.scope import CanonicalGitPath, GitHubRepositoryId
from autodev_control.workplane.candidate_producer import (
    CandidateProposal,
    ProposedChangeKind,
    ProposedFileChange,
)
from autodev_control.workplane.fixture_candidate_materializer import (
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
)

from tests.trusted import test_gates as gates_fixture


BASE = gates_fixture.SHA
TEST_MAX_BASE_LEAVES = 4096
TEST_MAX_PROPOSAL_CHANGES = 1024
TEST_MAX_TREE_DEPTH = 32
TEST_MAX_PATH_BYTES = 4096
TEST_MAX_TOTAL_PATH_BYTES = 1_048_576
TEST_MAX_NEW_CONTENT_BYTES = 16_777_216
TEST_MAX_MATERIALIZED_TREE_OBJECTS = 4096
TEST_BLOB_DOMAIN = "autodev.o2b.fixture-blob/v1"
TEST_TREE_ENTRY_DOMAIN = "autodev.o2b.fixture-tree-entry/v1"
TEST_TREE_DOMAIN = "autodev.o2b.fixture-tree/v1"
TEST_COMMIT_DOMAIN = "autodev.o2b.fixture-commit/v1"
REPOSITORY = gates_fixture.REPO
ROOT_TREE_ID = GitSha("d" * 40)
NESTED_TREE_ID = GitSha("e" * 40)
BASE_KEEP_BLOB = GitSha("1" * 40)
BASE_OLD_BLOB = GitSha("2" * 40)
UNAVAILABLE = GitSha("f" * 40)
_FIXTURE_GIT_OBJECT_STORE_TYPE = FixtureGitObjectStore


def base_only_store() -> FixtureGitObjectStore:
    """One base commit and only its reachable trees; no candidate objects."""
    return FixtureGitObjectStore(
        REPOSITORY,
        (FixtureGitCommit(BASE, (), ROOT_TREE_ID),),
        (
            FixtureGitTree(ROOT_TREE_ID, (
                FixtureGitTreeEntry("keep.txt", GitObjectKind.BLOB, "100644", BASE_KEEP_BLOB),
                FixtureGitTreeEntry("stay.txt", GitObjectKind.BLOB, "100644", GitSha("3" * 40)),
                FixtureGitTreeEntry("src", GitObjectKind.TREE, "040000", NESTED_TREE_ID),
            )),
            FixtureGitTree(NESTED_TREE_ID, (
                FixtureGitTreeEntry("old.txt", GitObjectKind.BLOB, "100755", BASE_OLD_BLOB),
            )),
        ),
        frozenset((UNAVAILABLE,)),
        False,
        RawSha256("9" * 64),
    )


def _independent_path(path: str) -> bytes:
    assert type(path) is str and path and not path.startswith("/") and not path.endswith("/")
    assert "\x00" not in path and "\\" not in path
    components = path.split("/")
    assert all(component not in ("", ".", "..") for component in components)
    encoded = path.encode("utf-8")
    assert len(encoded) <= TEST_MAX_PATH_BYTES
    assert len(components) <= TEST_MAX_TREE_DEPTH
    return encoded


def project_exact_base(
    store: FixtureGitObjectStore,
    expected_repository_id: GitHubRepositoryId,
    expected_base: GitSha,
) -> FixtureBaseSnapshot:
    """Project only reachable leaves from the exact base-only trusted fixture."""
    assert type(store) is _FIXTURE_GIT_OBJECT_STORE_TYPE
    assert store.repository_id == expected_repository_id
    assert len(store.commits) == 1
    commit = store.commit(expected_base)
    assert commit is not None and commit.commit_id == expected_base

    leaves: list[FixtureBaseLeaf] = []
    seen_trees: set[GitSha] = set()
    total_path_bytes = 0

    def visit(tree_id: GitSha, prefix: str) -> None:
        nonlocal total_path_bytes
        assert tree_id not in seen_trees
        seen_trees.add(tree_id)
        assert len(seen_trees) <= TEST_MAX_MATERIALIZED_TREE_OBJECTS
        tree = store.tree(tree_id)
        assert tree is not None
        for entry in tree.entries:
            assert entry.name and "/" not in entry.name and "\\" not in entry.name and "\x00" not in entry.name
            path = entry.name if not prefix else prefix + "/" + entry.name
            encoded = _independent_path(path)
            if entry.object_kind is GitObjectKind.TREE:
                assert entry.mode == "040000"
                visit(entry.object_id, path)
            else:
                assert entry.object_kind is GitObjectKind.BLOB
                assert entry.mode in ("100644", "100755")
                leaves.append(FixtureBaseLeaf(path, entry.mode, entry.object_id.value))
                total_path_bytes += len(encoded)
                assert total_path_bytes <= TEST_MAX_TOTAL_PATH_BYTES
                assert len(leaves) <= TEST_MAX_BASE_LEAVES

    visit(commit.tree_id, "")
    paths = [leaf.path for leaf in leaves]
    assert len(paths) == len(set(paths))
    leaves.sort(key=lambda item: item.path.encode("utf-8"))
    return FixtureBaseSnapshot(
        expected_repository_id.value,
        expected_base.value,
        tuple(leaves),
    )


def _independent_digest(domain: str, *parts: bytes) -> str:
    domain_bytes = domain.encode("ascii")
    body = bytearray(len(domain_bytes).to_bytes(8, "big"))
    body.extend(domain_bytes)
    body.extend(len(parts).to_bytes(8, "big"))
    for part in parts:
        assert type(part) is bytes
        body.extend(len(part).to_bytes(8, "big"))
        body.extend(part)
    return hashlib.sha256(body).hexdigest()


def _assert_independent_golden_vectors() -> None:
    empty_blob = _independent_digest("autodev.o2b.fixture-blob/v1", b"")
    assert empty_blob == "347713c761a18a787fdec70f52ef6ae5c881160535c457ea2ec513356971c41c"
    assert _independent_digest("autodev.o2b.fixture-tree/v1", b"") == (
        "0b36169b7373673d2a90a679d6f520a1caa2a0dd469efef43070e7402148986b"
    )
    entry = _independent_digest(
        "autodev.o2b.fixture-tree-entry/v1",
        b"a.txt", b"blob", b"100644", empty_blob.encode("ascii"),
    )
    assert entry == "7a959fe2c093f282e648e5246894b64376b7d275b73c52b4cfb7139b4669eb4a"
    root = _independent_digest("autodev.o2b.fixture-tree/v1", b"", entry.encode("ascii"))
    assert root == "d17625089c96ddb33f54da0d39bf31c515c1f1f595c4f8d72b0ebaf509b5aa61"
    commit = _independent_digest(
        "autodev.o2b.fixture-commit/v1",
        b"a" * 40,
        b"d17625089c96ddb33f54da0d39bf31c515c1f1f595c4f8d72b0ebaf509b5aa61",
    )
    assert commit == "d50ef5f6549de2397e2e17fd9604e06742aaa3e7caf3943098c177401d911585"


def _expected_materialization(
    base_snapshot: FixtureBaseSnapshot,
    proposal: CandidateProposal,
) -> tuple[dict[str, tuple[str, str]], dict[str, bytes], dict[str, tuple[str, tuple[tuple[str, str, str, str], ...]]]]:
    """Independent test-side proposal application and hierarchical object model."""
    assert len(base_snapshot.leaves) <= TEST_MAX_BASE_LEAVES
    assert len(proposal.changes) <= TEST_MAX_PROPOSAL_CHANGES
    base_files: dict[str, tuple[str, str]] = {}
    base_total = 0
    for leaf in base_snapshot.leaves:
        encoded = _independent_path(leaf.path)
        base_total += len(encoded)
        assert base_total <= TEST_MAX_TOTAL_PATH_BYTES
        assert leaf.mode in ("100644", "100755")
        assert leaf.path not in base_files
        base_files[leaf.path] = (leaf.mode, leaf.object_id)
    for path in tuple(base_files):
        parts = path.split("/")
        assert all("/".join(parts[:index]) not in base_files for index in range(1, len(parts)))

    assert proposal.claimed_base_revision == base_snapshot.expected_base_revision
    final_files = dict(base_files)
    created: dict[str, bytes] = {}
    seen: set[str] = set()
    proposal_total = 0
    content_total = 0
    for change in proposal.changes:
        encoded = _independent_path(change.path)
        proposal_total += len(encoded)
        assert proposal_total <= TEST_MAX_TOTAL_PATH_BYTES
        assert change.path not in seen
        seen.add(change.path)
        exists = change.path in final_files
        if change.kind is ProposedChangeKind.ADD:
            assert not exists and change.mode in ("100644", "100755")
            assert type(change.content_bytes) is bytes
            content_total += len(change.content_bytes)
            blob_id = _independent_digest(TEST_BLOB_DOMAIN, change.content_bytes)
            created[blob_id] = change.content_bytes
            final_files[change.path] = (change.mode, blob_id)
        elif change.kind is ProposedChangeKind.REPLACE:
            assert exists and type(change.content_bytes) is bytes
            content_total += len(change.content_bytes)
            blob_id = _independent_digest(TEST_BLOB_DOMAIN, change.content_bytes)
            created[blob_id] = change.content_bytes
            mode = final_files[change.path][0] if change.mode is None else change.mode
            assert mode in ("100644", "100755")
            final_files[change.path] = (mode, blob_id)
        else:
            assert change.kind is ProposedChangeKind.DELETE
            assert exists and change.content_bytes is None and change.mode is None
            del final_files[change.path]
        assert content_total <= TEST_MAX_NEW_CONTENT_BYTES

    final_total = 0
    for path in final_files:
        final_total += len(_independent_path(path))
        assert final_total <= TEST_MAX_TOTAL_PATH_BYTES
    for path in tuple(final_files):
        parts = path.split("/")
        assert all("/".join(parts[:index]) not in final_files for index in range(1, len(parts)))

    directories = {""}
    for path in final_files:
        parts = path.split("/")
        for index in range(1, len(parts)):
            directories.add("/".join(parts[:index]))
    assert len(directories) <= TEST_MAX_MATERIALIZED_TREE_OBJECTS

    expected_trees: dict[str, tuple[str, tuple[tuple[str, str, str, str], ...]]] = {}
    for directory in sorted(
        directories,
        key=lambda path: (-(0 if not path else path.count("/") + 1), path.encode("utf-8")),
    ):
        specs: list[tuple[str, str, str, str]] = []
        for path, (mode, object_id) in final_files.items():
            parent, _, name = path.rpartition("/")
            if parent == directory:
                specs.append((name, "BLOB", mode, object_id))
        for child in directories:
            parent, _, name = child.rpartition("/")
            if child and parent == directory:
                specs.append((name, "TREE", "040000", expected_trees[child][0]))
        specs.sort(key=lambda item: item[0].encode("utf-8"))
        entry_hashes = []
        for name, kind, mode, object_id in specs:
            entry_hashes.append(_independent_digest(
                TEST_TREE_ENTRY_DOMAIN,
                name.encode("utf-8"),
                b"blob" if kind == "BLOB" else b"tree",
                mode.encode("ascii"),
                object_id.encode("ascii"),
            ).encode("ascii"))
        tree_id = _independent_digest(
            TEST_TREE_DOMAIN,
            directory.encode("utf-8"),
            *entry_hashes,
        )
        expected_trees[directory] = (tree_id, tuple(specs))
    return final_files, created, expected_trees


def _independent_mutation_facts(
    base_snapshot: FixtureBaseSnapshot,
    proposal: CandidateProposal,
) -> tuple[MutationFact, ...]:
    """Build complete expected facts from fixture inputs without trusted derivation."""
    base_files = {
        leaf.path: (leaf.mode, leaf.object_id)
        for leaf in base_snapshot.leaves
    }
    final_files, _, _ = _expected_materialization(base_snapshot, proposal)
    facts: list[MutationFact] = []
    for path in sorted(base_files.keys() | final_files.keys()):
        before = base_files.get(path)
        after = final_files.get(path)
        if before == after:
            continue
        if before is None:
            assert after is not None
            facts.append(MutationFact(
                CanonicalGitPath(path),
                MutationKind.ADDED,
                None,
                GitSha(after[1]),
                None,
                GitBlobMode(after[0]),
            ))
        elif after is None:
            facts.append(MutationFact(
                CanonicalGitPath(path),
                MutationKind.DELETED,
                GitSha(before[1]),
                None,
                GitBlobMode(before[0]),
                None,
            ))
        else:
            facts.append(MutationFact(
                CanonicalGitPath(path),
                MutationKind.MODIFIED,
                GitSha(before[1]),
                GitSha(after[1]),
                GitBlobMode(before[0]),
                GitBlobMode(after[0]),
            ))
    return tuple(facts)


def independently_verify_and_combine(
    base_store: FixtureGitObjectStore,
    base_snapshot: FixtureBaseSnapshot,
    proposal: CandidateProposal,
    result: MaterializationResult,
) -> FixtureGitObjectStore:
    """Verify content, reachable trees, identities and closure before conversion."""
    assert type(result) is MaterializationResult
    assert type(result.status) is MaterializationStatus
    assert result.status is MaterializationStatus.MATERIALIZED
    assert type(result.candidate) is FixtureMaterializedCandidate
    candidate = result.candidate
    assert type(candidate.repository_id) is str
    assert type(candidate.base_revision) is str
    assert type(candidate.candidate_commit_id) is str
    assert type(candidate.result_tree_id) is str
    assert type(candidate.candidate_trees) is tuple
    assert type(candidate.created_blobs) is tuple
    for tree in candidate.candidate_trees:
        assert type(tree) is FixtureMaterializedTree
        assert type(tree.directory_path) is str
        assert type(tree.tree_id) is str
        assert type(tree.entries) is tuple
        for entry in tree.entries:
            assert type(entry) is FixtureMaterializedTreeEntry
            assert type(entry.name) is str
            assert type(entry.mode) is str
            assert type(entry.object_id) is str
            if type(entry.object_kind) is not FixtureObjectKind:
                raise AssertionError("entry object kind must be exact FixtureObjectKind")
            if entry.object_kind is not FixtureObjectKind.BLOB and entry.object_kind is not FixtureObjectKind.TREE:
                raise AssertionError("entry object kind is outside the frozen O2b enum")
    for blob in candidate.created_blobs:
        assert type(blob) is FixtureMaterializedBlob
        assert type(blob.object_id) is str
        assert type(blob.content_bytes) is bytes
    assert base_store.repository_id.value == base_snapshot.repository_id
    assert candidate.repository_id == base_snapshot.repository_id
    assert candidate.base_revision == base_snapshot.expected_base_revision
    assert proposal.claimed_base_revision == base_snapshot.expected_base_revision
    assert project_exact_base(
        base_store,
        GitHubRepositoryId(base_snapshot.repository_id),
        GitSha(base_snapshot.expected_base_revision),
    ) == base_snapshot

    expected_files, expected_created, expected_trees = _expected_materialization(
        base_snapshot, proposal
    )
    assert candidate.result_tree_id == expected_trees[""][0]
    assert candidate.candidate_commit_id == _independent_digest(
        TEST_COMMIT_DOMAIN,
        base_snapshot.expected_base_revision.encode("ascii"),
        expected_trees[""][0].encode("ascii"),
    )

    tree_paths = tuple(tree.directory_path for tree in candidate.candidate_trees)
    canonical_paths = tuple(sorted(expected_trees, key=lambda path: path.encode("utf-8")))
    assert tree_paths == canonical_paths
    actual_trees_by_path = {tree.directory_path: tree for tree in candidate.candidate_trees}
    assert len(actual_trees_by_path) == len(candidate.candidate_trees)
    actual_trees_by_id: dict[str, FixtureMaterializedTree] = {}
    id_to_path: dict[str, str] = {}
    for directory, (expected_id, expected_entries) in expected_trees.items():
        tree = actual_trees_by_path[directory]
        assert tree.directory_path == directory
        assert tree.tree_id == expected_id
        assert tree.tree_id not in id_to_path
        id_to_path[tree.tree_id] = directory
        actual_trees_by_id[tree.tree_id] = tree
        actual_specs: list[tuple[str, str, str, str]] = []
        prior_name_bytes: bytes | None = None
        entry_hashes: list[bytes] = []
        for entry in tree.entries:
            name_bytes = entry.name.encode("utf-8")
            assert prior_name_bytes is None or prior_name_bytes < name_bytes
            prior_name_bytes = name_bytes
            if entry.object_kind is FixtureObjectKind.BLOB:
                kind = "BLOB"
            elif entry.object_kind is FixtureObjectKind.TREE:
                kind = "TREE"
            else:
                raise AssertionError("entry object kind is outside the frozen O2b enum")
            actual_specs.append((entry.name, kind, entry.mode, entry.object_id))
            entry_hashes.append(_independent_digest(
                TEST_TREE_ENTRY_DOMAIN,
                name_bytes,
                b"blob" if kind == "BLOB" else b"tree",
                entry.mode.encode("ascii"),
                entry.object_id.encode("ascii"),
            ).encode("ascii"))
        assert tuple(actual_specs) == expected_entries
        independently_computed = _independent_digest(
            TEST_TREE_DOMAIN,
            directory.encode("utf-8"),
            *entry_hashes,
        )
        assert tree.tree_id == independently_computed

    assert set(actual_trees_by_path) == set(expected_trees)
    assert len(actual_trees_by_id) == len(candidate.candidate_trees)

    reachable_ids: set[str] = set()
    actual_leaves: dict[str, tuple[str, str]] = {}

    def visit_tree(tree_id: str, directory: str) -> None:
        assert tree_id not in reachable_ids
        reachable_ids.add(tree_id)
        tree = actual_trees_by_id.get(tree_id)
        assert tree is not None
        assert tree.directory_path == directory
        for entry in tree.entries:
            path = entry.name if not directory else directory + "/" + entry.name
            _independent_path(path)
            if entry.object_kind is FixtureObjectKind.TREE:
                assert entry.mode == "040000"
                visit_tree(entry.object_id, path)
            elif entry.object_kind is FixtureObjectKind.BLOB:
                assert entry.mode in ("100644", "100755")
                assert path not in actual_leaves
                actual_leaves[path] = (entry.mode, entry.object_id)
            else:
                raise AssertionError("entry object kind is outside the frozen O2b enum")

    visit_tree(candidate.result_tree_id, "")
    assert reachable_ids == set(actual_trees_by_id)
    assert len(reachable_ids) == len(candidate.candidate_trees)
    assert actual_leaves == expected_files

    referenced_blob_ids = {object_id for _, object_id in actual_leaves.values()}
    blob_ids = tuple(blob.object_id for blob in candidate.created_blobs)
    assert blob_ids == tuple(sorted(expected_created, key=lambda value: value.encode("ascii")))
    assert len(blob_ids) == len(set(blob_ids))
    assert set(blob_ids) == set(expected_created)
    for blob in candidate.created_blobs:
        assert _independent_digest(TEST_BLOB_DOMAIN, blob.content_bytes) == blob.object_id
        assert blob.content_bytes == expected_created[blob.object_id]
        assert blob.object_id in referenced_blob_ids

    # No combined store is constructed until every independent assertion above succeeds.
    commit_id = GitSha(candidate.candidate_commit_id)
    base_id = GitSha(candidate.base_revision)
    converted_commit = FixtureGitCommit(
        commit_id=commit_id,
        parents=(base_id,),
        tree_id=GitSha(candidate.result_tree_id),
    )
    commits_by_id = {item.commit_id: item for item in base_store.commits}
    prior_commit = commits_by_id.get(converted_commit.commit_id)
    assert prior_commit is None or prior_commit == converted_commit
    commits_by_id.setdefault(converted_commit.commit_id, converted_commit)

    trees_by_id = {item.tree_id: item for item in base_store.trees}
    for materialized in candidate.candidate_trees:
        converted_entries = []
        for entry in materialized.entries:
            if type(entry.object_kind) is not FixtureObjectKind:
                raise AssertionError("entry object kind must be exact FixtureObjectKind")
            if entry.object_kind is FixtureObjectKind.BLOB:
                trusted_kind = GitObjectKind.BLOB
            elif entry.object_kind is FixtureObjectKind.TREE:
                trusted_kind = GitObjectKind.TREE
            else:
                raise AssertionError("entry object kind is outside the frozen O2b enum")
            converted_entries.append(FixtureGitTreeEntry(
                entry.name,
                trusted_kind,
                entry.mode,
                GitSha(entry.object_id),
            ))
        converted = FixtureGitTree(
            tree_id=GitSha(materialized.tree_id),
            entries=tuple(converted_entries),
        )
        existing = trees_by_id.get(converted.tree_id)
        assert existing is None or existing == converted
        trees_by_id.setdefault(converted.tree_id, converted)

    combined = FixtureGitObjectStore(
        repository_id=base_store.repository_id,
        commits=tuple(commits_by_id.values()),
        trees=tuple(trees_by_id.values()),
        unavailable_object_ids=base_store.unavailable_object_ids,
        provider_failure=base_store.provider_failure,
        observation_instance_id=base_store.observation_instance_id,
    )
    assert combined.unavailable_object_ids is base_store.unavailable_object_ids
    assert combined.provider_failure is base_store.provider_failure
    assert combined.observation_instance_id is base_store.observation_instance_id
    assert all(commits_by_id[commit.commit_id] == commit for commit in base_store.commits)
    assert all(
        trees_by_id[tree.tree_id] == tree
        for tree in base_store.trees
    )
    return combined


def test_projection_rejects_missing_unavailable_and_reused_reachable_trees() -> None:
    original = base_only_store()
    unavailable = replace(original, unavailable_object_ids=frozenset((ROOT_TREE_ID,)))
    with pytest.raises(AssertionError):
        project_exact_base(unavailable, REPOSITORY, BASE)

    missing = replace(original, trees=original.trees[:1])
    with pytest.raises(AssertionError):
        project_exact_base(missing, REPOSITORY, BASE)


    repeated_root = replace(
        original.trees[0],
        entries=original.trees[0].entries + (
            FixtureGitTreeEntry("other", GitObjectKind.TREE, "040000", NESTED_TREE_ID),
        ),
    )
    reused = replace(original, trees=(repeated_root, original.trees[1]))
    with pytest.raises(AssertionError):
        project_exact_base(reused, REPOSITORY, BASE)

def proposal_for_integration() -> CandidateProposal:
    return CandidateProposal(
        BASE.value,
        (
            ProposedFileChange(ProposedChangeKind.ADD, "new.txt", b"new bytes", "100644"),
            ProposedFileChange(ProposedChangeKind.REPLACE, "src/old.txt", b"updated", "100644"),
            ProposedFileChange(ProposedChangeKind.DELETE, "keep.txt", None, None),
            ProposedFileChange(ProposedChangeKind.ADD, "src/new.txt", b"new bytes", "100755"),
        ),
    )


def successful_fixture() -> tuple[
    FixtureGitObjectStore, FixtureBaseSnapshot, CandidateProposal, MaterializationResult
]:
    store = base_only_store()
    projected = project_exact_base(store, REPOSITORY, BASE)
    configured_proposal = proposal_for_integration()
    outcome = DeterministicFixtureCandidateMaterializer().materialize(
        configured_proposal, projected
    )
    assert outcome.status is MaterializationStatus.MATERIALIZED
    return store, projected, configured_proposal, outcome


def _replace_candidate(
    result: MaterializationResult,
    *,
    trees: tuple[FixtureMaterializedTree, ...] | None = None,
    blobs: tuple[FixtureMaterializedBlob, ...] | None = None,
    result_tree_id: str | None = None,
    candidate_commit_id: str | None = None,
) -> MaterializationResult:
    assert result.candidate is not None
    candidate = replace(
        result.candidate,
        candidate_trees=result.candidate.candidate_trees if trees is None else trees,
        created_blobs=result.candidate.created_blobs if blobs is None else blobs,
        result_tree_id=result.candidate.result_tree_id if result_tree_id is None else result_tree_id,
        candidate_commit_id=(
            result.candidate.candidate_commit_id
            if candidate_commit_id is None
            else candidate_commit_id
        ),
    )
    return MaterializationResult(MaterializationStatus.MATERIALIZED, candidate)


def tamper_content(result: MaterializationResult) -> MaterializationResult:
    blobs = list(result.candidate.created_blobs)
    blobs[0] = replace(blobs[0], content_bytes=b"tampered content")
    return _replace_candidate(result, blobs=tuple(blobs))


def tamper_blob_id(result: MaterializationResult) -> MaterializationResult:
    blobs = list(result.candidate.created_blobs)
    blobs[0] = replace(blobs[0], object_id="f" * 64)
    return _replace_candidate(result, blobs=tuple(blobs))


def tamper_blob_entry_id(result: MaterializationResult) -> MaterializationResult:
    trees = []
    for tree in result.candidate.candidate_trees:
        entries = tuple(
            replace(entry, object_id="f" * 64)
            if entry.object_kind is FixtureObjectKind.BLOB and entry.name == "new.txt"
            else entry
            for entry in tree.entries
        )
        trees.append(replace(tree, entries=entries))
    return _replace_candidate(result, trees=tuple(trees))


def tamper_blob_entry_mode(result: MaterializationResult) -> MaterializationResult:
    trees = []
    for tree in result.candidate.candidate_trees:
        entries = tuple(
            replace(entry, mode="100755")
            if entry.object_kind is FixtureObjectKind.BLOB and entry.name == "new.txt"
            else entry
            for entry in tree.entries
        )
        trees.append(replace(tree, entries=entries))
    return _replace_candidate(result, trees=tuple(trees))


def tamper_tree_child_id(result: MaterializationResult) -> MaterializationResult:
    trees = []
    for tree in result.candidate.candidate_trees:
        entries = tuple(
            replace(entry, object_id="f" * 64)
            if entry.object_kind is FixtureObjectKind.TREE
            else entry
            for entry in tree.entries
        )
        trees.append(replace(tree, entries=entries))
    return _replace_candidate(result, trees=tuple(trees))


def tamper_tree_id(result: MaterializationResult) -> MaterializationResult:
    trees = list(result.candidate.candidate_trees)
    trees[-1] = replace(trees[-1], tree_id="f" * 64)
    return _replace_candidate(result, trees=tuple(trees))


def tamper_tree_path(result: MaterializationResult) -> MaterializationResult:
    trees = list(result.candidate.candidate_trees)
    trees[-1] = replace(trees[-1], directory_path="wrong")
    return _replace_candidate(result, trees=tuple(trees))


def tamper_root_id(result: MaterializationResult) -> MaterializationResult:
    return _replace_candidate(result, result_tree_id="f" * 64)


def tamper_commit_id(result: MaterializationResult) -> MaterializationResult:
    return _replace_candidate(result, candidate_commit_id="f" * 64)


def tamper_extra_tree(result: MaterializationResult) -> MaterializationResult:
    extra = FixtureMaterializedTree("unreachable", "f" * 64, ())
    return _replace_candidate(result, trees=result.candidate.candidate_trees + (extra,))


def tamper_extra_blob(result: MaterializationResult) -> MaterializationResult:
    extra = FixtureMaterializedBlob("f" * 64, b"unused")
    return _replace_candidate(result, blobs=result.candidate.created_blobs + (extra,))


def tamper_lookalike_object_kind(result: MaterializationResult) -> MaterializationResult:
    class LookalikeBlobKind:
        name = "BLOB"

    trees = []
    for tree in result.candidate.candidate_trees:
        entries = tuple(
            replace(entry, object_kind=LookalikeBlobKind())
            if entry.object_kind is FixtureObjectKind.BLOB and entry.name == "new.txt"
            else entry
            for entry in tree.entries
        )
        trees.append(replace(tree, entries=entries))
    return _replace_candidate(result, trees=tuple(trees))


@pytest.mark.parametrize(
    "tamper",
    [
        tamper_content,
        tamper_blob_id,
        tamper_blob_entry_id,
        tamper_blob_entry_mode,
        tamper_tree_child_id,
        tamper_tree_id,
        tamper_tree_path,
        tamper_root_id,
        tamper_commit_id,
        tamper_extra_tree,
        tamper_extra_blob,
    ],
)
def test_independent_installation_rejects_each_tampered_result_category(tamper) -> None:
    store, projected, proposal, result = successful_fixture()
    tampered = tamper(result)

    with pytest.raises(AssertionError):
        independently_verify_and_combine(store, projected, proposal, tampered)


def test_independent_installation_rejects_lookalike_object_kind_before_store_construction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, projected, proposal, result = successful_fixture()
    tampered = tamper_lookalike_object_kind(result)

    def unexpected_store_construction(**kwargs):
        raise RuntimeError("unverified graph reached combined-store construction")

    monkeypatch.setitem(globals(), "FixtureGitObjectStore", unexpected_store_construction)
    with pytest.raises(AssertionError, match="exact FixtureObjectKind"):
        independently_verify_and_combine(store, projected, proposal, tampered)


def _trusted_admit_candidate(
    base_store: FixtureGitObjectStore,
    combined_store: FixtureGitObjectStore,
    candidate_commit_id: str,
    candidate_id_value: str,
):
    runtime = gates_fixture.runtime(object_store=base_store)
    gates_fixture.initialize_task(runtime)
    with runtime.registry.lock:
        assert not runtime.registry._live
        runtime._object_store = combined_store
        restarted_runtime = runtime.restart()
    assert restarted_runtime is not None
    runtime = restarted_runtime

    candidate_id = CandidateId(candidate_id_value)
    request = runtime.boundary.record_candidate_truth(
        task_id=gates_fixture.TASK,
        candidate_id=candidate_id,
        candidate_commit_id=GitSha(candidate_commit_id),
    )
    commit_result = ControlStateGate(runtime.control_state_client).commit(
        request, gates_fixture.independent_lease(runtime)
    )
    assert commit_result.code is GateResultCode.COMMITTED

    recorded_candidate = runtime.backend.read_candidate(candidate_id)
    assert recorded_candidate is not None
    admitted = runtime.backend.read_candidate_materialization(
        recorded_candidate.materialization_id
    )
    assert admitted is not None
    return admitted


def test_o2b_linkage_to_existing_trusted_exhaustive_admission() -> None:
    _assert_independent_golden_vectors()
    base_store = base_only_store()
    assert len(base_store.commits) == 1
    base_snapshot = project_exact_base(base_store, REPOSITORY, BASE)
    proposal = proposal_for_integration()
    result = DeterministicFixtureCandidateMaterializer().materialize(
        proposal, base_snapshot
    )
    assert result.status is MaterializationStatus.MATERIALIZED
    combined_store = independently_verify_and_combine(
        base_store, base_snapshot, proposal, result
    )

    admitted = _trusted_admit_candidate(
        base_store,
        combined_store,
        result.candidate.candidate_commit_id,
        "issue67-o2b-candidate",
    )
    assert admitted.candidate_commit == GitSha(result.candidate.candidate_commit_id)
    expected_inventory = _independent_mutation_facts(base_snapshot, proposal)
    actual_inventory = admitted.mutation_inventory.mutations
    assert len(actual_inventory) == len(expected_inventory)
    assert tuple(fact.path.value for fact in actual_inventory) == tuple(
        fact.path.value for fact in expected_inventory
    )
    assert actual_inventory == expected_inventory


def test_empty_proposal_has_exactly_empty_trusted_inventory() -> None:
    base_store = base_only_store()
    base_snapshot = project_exact_base(base_store, REPOSITORY, BASE)
    proposal = CandidateProposal(BASE.value, ())
    result = DeterministicFixtureCandidateMaterializer().materialize(
        proposal, base_snapshot
    )
    assert result.status is MaterializationStatus.MATERIALIZED
    assert result.candidate is not None
    combined_store = independently_verify_and_combine(
        base_store, base_snapshot, proposal, result
    )

    admitted = _trusted_admit_candidate(
        base_store,
        combined_store,
        result.candidate.candidate_commit_id,
        "issue67-o2b-empty-candidate",
    )

    assert admitted.candidate_commit == GitSha(result.candidate.candidate_commit_id)
    # Empty inventory is a fixture observation only; this asserts no completion or success state.
    assert admitted.mutation_inventory.mutations == ()
