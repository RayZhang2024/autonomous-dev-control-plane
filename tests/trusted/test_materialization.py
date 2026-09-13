from dataclasses import FrozenInstanceError

import pytest

from autodev_control.trusted.identity import GitSha
from autodev_control.trusted.materialization import (
    GitObjectKind, GitTreeEntry, MutationKind,
    build_candidate_materialization, derive_mutation_inventory,
)
from autodev_control.trusted.operation import CandidateId
from autodev_control.trusted.scope import CanonicalGitPath


def sha(char):
    return GitSha(char * 40)


def entry(path, value="a", mode="100644", kind=GitObjectKind.BLOB):
    return GitTreeEntry(CanonicalGitPath(path), kind, mode, sha(value))


def test_empty_tree_delta_is_deterministic():
    assert derive_mutation_inventory((), ()) == derive_mutation_inventory((), ())


def test_added_path_is_derived_from_object_truth():
    fact = derive_mutation_inventory((), (entry("a.txt"),)).mutations[0]
    assert fact.kind is MutationKind.ADDED and fact.candidate_object_id == sha("a")


def test_deleted_path_is_derived_from_object_truth():
    fact = derive_mutation_inventory((entry("a.txt"),), ()).mutations[0]
    assert fact.kind is MutationKind.DELETED and fact.base_object_id == sha("a")


def test_modified_content_is_derived_from_object_truth():
    fact = derive_mutation_inventory((entry("a.txt"),), (entry("a.txt", "b"),)).mutations[0]
    assert fact.kind is MutationKind.MODIFIED


def test_mode_only_change_is_a_modification():
    fact = derive_mutation_inventory((entry("a.txt"),), (entry("a.txt", mode="100755"),)).mutations[0]
    assert fact.kind is MutationKind.MODIFIED


def test_rename_like_change_is_delete_plus_add():
    facts = derive_mutation_inventory((entry("old"),), (entry("new"),)).mutations
    assert [(f.path.value, f.kind) for f in facts] == [("new", MutationKind.ADDED), ("old", MutationKind.DELETED)]


@pytest.mark.parametrize("mode", ["100600", "100664", "120000", "160000", "040000", "", "regular"])
def test_unknown_or_forbidden_modes_fail_closed(mode):
    with pytest.raises(ValueError):
        derive_mutation_inventory((), (entry("bad", mode=mode),))


@pytest.mark.parametrize("kind", [GitObjectKind.TREE, GitObjectKind.SYMLINK, GitObjectKind.GITLINK])
def test_non_blob_objects_fail_closed(kind):
    with pytest.raises(ValueError):
        derive_mutation_inventory((), (entry("bad", kind=kind),))


def test_duplicate_tree_path_fails_closed():
    with pytest.raises(ValueError):
        derive_mutation_inventory((), (entry("a"), entry("a", "b")))


def test_inventory_is_canonical_path_ordered():
    facts = derive_mutation_inventory((), (entry("z"), entry("a"))).mutations
    assert tuple(f.path.value for f in facts) == ("a", "z")


def test_materialization_requires_exact_single_base_parent():
    with pytest.raises(ValueError):
        build_candidate_materialization(CandidateId("c"), sha("a"), sha("b"), (), (), ())


def test_materialization_id_and_branch_are_deterministic():
    value = build_candidate_materialization(CandidateId("c"), sha("a"), sha("b"), (sha("a"),), (), (entry("x"),))
    assert value.candidate_branch.value == "refs/heads/autodev/candidates/" + value.materialization_id.value


def test_materialization_identity_changes_with_commit():
    one = build_candidate_materialization(CandidateId("c"), sha("a"), sha("b"), (sha("a"),), (), ())
    two = build_candidate_materialization(CandidateId("c"), sha("a"), sha("c"), (sha("a"),), (), ())
    assert one.materialization_id != two.materialization_id


def test_materialization_is_deeply_immutable():
    value = build_candidate_materialization(CandidateId("c"), sha("a"), sha("b"), (sha("a"),), (), (entry("x"),))
    with pytest.raises(FrozenInstanceError):
        value.commit = sha("c")
    with pytest.raises(TypeError):
        value.inventory.mutations[0] = None
