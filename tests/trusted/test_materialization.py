from dataclasses import FrozenInstanceError, replace

import pytest

from autodev_control.trusted.identity import GitSha, ImmutableConfigId, RawSha256
from autodev_control.trusted.materialization import (
    GitObjectKind, GitTreeEntry, MutationKind,
    build_candidate_materialization, derive_mutation_inventory,
)
from autodev_control.trusted.manifest import PolicyEpochIdentity, TrustedManifestId
from autodev_control.trusted.operation import CandidateId
from autodev_control.trusted.scope import (
    AuthorizationId, CanonicalGitPath, ContractId, GitHubRepositoryId,
    TargetRegistrationId, TaskId,
)


def sha(char):
    return GitSha(char * 40)


def entry(path, value="a", mode="100644", kind=GitObjectKind.BLOB):
    return GitTreeEntry(CanonicalGitPath(path), kind, mode, sha(value))


def materialization(*, commit=None, parents=None, base_tree=(), candidate_tree=(), task="task"):
    base = sha("a")
    return build_candidate_materialization(
        repository_id=GitHubRepositoryId("1"), task_id=TaskId(task),
        candidate_id=CandidateId("c"), contract_id=ContractId("contract"),
        contract_raw_sha256=RawSha256("1" * 64),
        authorization_id=AuthorizationId(RawSha256("2" * 64)),
        target_registration_id=TargetRegistrationId(RawSha256("3" * 64)),
        policy_epoch_identity=PolicyEpochIdentity(TrustedManifestId(RawSha256("4" * 64))),
        base=base, base_tree_id=sha("d"), commit=commit or sha("b"),
        result_tree_id=sha("e"), parent_commits=(base,) if parents is None else parents,
        base_tree=base_tree, candidate_tree=candidate_tree,
        materialization_profile_id=ImmutableConfigId("fixture-materialization"),
    )


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
        materialization(parents=())


def test_materialization_id_and_branch_are_deterministic():
    value = materialization(candidate_tree=(entry("x"),))
    assert value.candidate_branch.value == "refs/heads/autodev/candidates/" + value.materialization_id.raw_sha256.value


def test_materialization_identity_changes_with_commit():
    one = materialization()
    two = materialization(commit=sha("c"))
    assert one.materialization_id != two.materialization_id


def test_materialization_is_deeply_immutable():
    value = materialization(candidate_tree=(entry("x"),))
    with pytest.raises(FrozenInstanceError):
        value.commit = sha("c")
    with pytest.raises(TypeError):
        value.inventory.mutations[0] = None


def test_materialization_identity_binds_complete_security_context():
    assert materialization(task="one").materialization_id != materialization(task="two").materialization_id


def test_materialization_and_inventory_reject_content_change_under_same_identity():
    value = materialization(candidate_tree=(entry("x"),))
    with pytest.raises(ValueError):
        replace(value, task_id=TaskId("different"))
    with pytest.raises(ValueError):
        replace(value.inventory, mutations=())
