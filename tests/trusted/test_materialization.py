import hashlib
from dataclasses import FrozenInstanceError, replace

import pytest

from autodev_control.trusted.backend import canonical_json_bytes
from autodev_control.trusted.identity import (
    GitObjectObservationBindingId, GitSha, ImmutableConfigId, RawSha256,
)
from autodev_control.trusted.materialization import (
    GitObjectKind, GitTreeEntry, MutationInventory, MutationKind,
    build_candidate_materialization, derive_mutation_inventory,
    CandidateMaterializationAdmissionReason, CandidateMaterializationAdmissionStatus,
    FixtureGitCommit, FixtureGitObjectStore, FixtureGitTree, FixtureGitTreeEntry,
    MAX_LEAF_ENTRIES, MAX_TREE_DEPTH, TrustedCandidateMaterializationContext,
    admit_candidate_materialization, inventory_is_authorized,
)
from autodev_control.trusted.manifest import PolicyEpochIdentity, TrustedManifestId
from autodev_control.trusted.operation import CandidateId
from autodev_control.trusted.scope import (
    AuthorizationId, CanonicalGitPath, ContractId, GitHubRepositoryId,
    ExactPathSelector, MutationScope, MutationScopeRule, ChangeType,
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


def trusted_context():
    value = object.__new__(TrustedCandidateMaterializationContext)
    for name, field in (
        ("repository_id", GitHubRepositoryId("1")), ("task_id", TaskId("task")),
        ("contract_id", ContractId("contract")), ("contract_raw_sha256", RawSha256("1" * 64)),
        ("authorization_id", AuthorizationId(RawSha256("2" * 64))),
        ("target_registration_id", TargetRegistrationId(RawSha256("3" * 64))),
        ("policy_epoch_identity", PolicyEpochIdentity(TrustedManifestId(RawSha256("4" * 64)))),
        ("base_commit", sha("a")),
    ):
        object.__setattr__(value, name, field)
    return value


def observed_store(*, candidate_entries=(), parents=None, unavailable=frozenset(), provider_failure=False):
    base, candidate = sha("a"), sha("b")
    base_tree, candidate_tree = sha("d"), sha("e")
    base_entries = (FixtureGitTreeEntry("base.txt", GitObjectKind.BLOB, "100644", sha("1")),)
    return FixtureGitObjectStore(
        GitHubRepositoryId("1"),
        (FixtureGitCommit(base, (), base_tree), FixtureGitCommit(candidate, (base,) if parents is None else parents, candidate_tree)),
        (FixtureGitTree(base_tree, base_entries), FixtureGitTree(candidate_tree, candidate_entries)),
        unavailable, provider_failure,
    )


def admitted_variant(*, base="a", candidate="b", base_tree="d", result_tree="e", entries=()):
    base_id, candidate_id = sha(base), sha(candidate)
    context = trusted_context()
    object.__setattr__(context, "base_commit", base_id)
    result = admit_candidate_materialization(
        store=FixtureGitObjectStore(
            GitHubRepositoryId("1"),
            (FixtureGitCommit(base_id, (), sha(base_tree)), FixtureGitCommit(candidate_id, (base_id,), sha(result_tree))),
            (
                FixtureGitTree(sha(base_tree), (FixtureGitTreeEntry("base", GitObjectKind.BLOB, "100644", sha("1")),)),
                FixtureGitTree(sha(result_tree), entries),
            ),
        ), context=context, candidate_id=CandidateId("identity"), candidate_commit_id=candidate_id,
    )
    assert result.status is CandidateMaterializationAdmissionStatus.ADMITTED
    return result.admitted_materialization


def test_issue30_admission_derives_exhaustive_candidate_inventory_not_caller_claims():
    store = observed_store(candidate_entries=(
        FixtureGitTreeEntry("base.txt", GitObjectKind.BLOB, "100644", sha("1")),
        FixtureGitTreeEntry("hidden.txt", GitObjectKind.BLOB, "100644", sha("2")),
    ))
    result = admit_candidate_materialization(
        store=store, context=trusted_context(), candidate_id=CandidateId("c"), candidate_commit_id=sha("b"),
    )
    assert result.status is CandidateMaterializationAdmissionStatus.ADMITTED
    assert tuple(item.path.value for item in result.admitted_materialization.mutation_inventory.mutations) == ("hidden.txt",)
    assert result.git_object_observation_binding_id is not None
    assert not hasattr(result.admitted_materialization, "git_object_observation_binding_id")


@pytest.mark.parametrize(("parents", "reason"), [
    ((), CandidateMaterializationAdmissionReason.INVALID_PARENT_TOPOLOGY),
    ((sha("a"), sha("c")), CandidateMaterializationAdmissionReason.INVALID_PARENT_TOPOLOGY),
    ((sha("c"),), CandidateMaterializationAdmissionReason.BASE_PARENT_MISMATCH),
])
def test_issue30_parent_topology_is_denied_only_after_complete_observation(parents, reason):
    result = admit_candidate_materialization(
        store=observed_store(parents=parents), context=trusted_context(), candidate_id=CandidateId("c"), candidate_commit_id=sha("b"),
    )
    assert (result.status, result.reason) == (CandidateMaterializationAdmissionStatus.DENIED, reason)
    assert result.git_object_observation_binding_id is not None


def test_issue30_missing_object_is_indeterminate_without_fabricated_observation_binding():
    result = admit_candidate_materialization(
        store=observed_store(unavailable=frozenset((sha("a"),))), context=trusted_context(), candidate_id=CandidateId("c"), candidate_commit_id=sha("b"),
    )
    assert result.status is CandidateMaterializationAdmissionStatus.INDETERMINATE
    assert result.git_object_observation_binding_id is None


def test_issue30_observation_provenance_does_not_change_admitted_materialization():
    one = admit_candidate_materialization(
        store=observed_store(), context=trusted_context(), candidate_id=CandidateId("c"), candidate_commit_id=sha("b"),
    )
    alternate = FixtureGitObjectStore(
        observed_store().repository_id, observed_store().commits, observed_store().trees,
        observation_instance_id=RawSha256("9" * 64),
    )
    two = admit_candidate_materialization(
        store=alternate, context=trusted_context(), candidate_id=CandidateId("c"), candidate_commit_id=sha("b"),
    )
    assert one.git_object_observation_binding_id != two.git_object_observation_binding_id
    assert one.admitted_materialization == two.admitted_materialization


@pytest.mark.parametrize(("unavailable", "reason"), [
    (sha("a"), CandidateMaterializationAdmissionReason.BASE_COMMIT_UNAVAILABLE),
    (sha("b"), CandidateMaterializationAdmissionReason.CANDIDATE_COMMIT_UNAVAILABLE),
    (sha("d"), CandidateMaterializationAdmissionReason.BASE_TREE_UNAVAILABLE),
    (sha("e"), CandidateMaterializationAdmissionReason.CANDIDATE_TREE_UNAVAILABLE),
])
def test_issue30_required_unavailable_observations_are_indeterminate_without_binding(unavailable, reason):
    result = admit_candidate_materialization(
        store=observed_store(unavailable=frozenset((unavailable,))),
        context=trusted_context(), candidate_id=CandidateId("c"), candidate_commit_id=sha("b"),
    )
    assert (result.status, result.reason) == (
        CandidateMaterializationAdmissionStatus.INDETERMINATE, reason,
    )
    assert result.admitted_materialization is None
    assert result.git_object_observation_binding_id is None


def test_issue30_provider_failure_and_observation_conflict_are_indeterminate_without_binding():
    provider = admit_candidate_materialization(
        store=observed_store(provider_failure=True), context=trusted_context(),
        candidate_id=CandidateId("c"), candidate_commit_id=sha("b"),
    )
    assert (provider.status, provider.reason, provider.git_object_observation_binding_id) == (
        CandidateMaterializationAdmissionStatus.INDETERMINATE,
        CandidateMaterializationAdmissionReason.OBSERVATION_PROVIDER_FAILURE, None,
    )
    base, candidate, tree = sha("a"), sha("b"), sha("d")
    conflict = FixtureGitObjectStore(
        GitHubRepositoryId("1"),
        (FixtureGitCommit(base, (), tree), FixtureGitCommit(candidate, (base,), tree)),
        (FixtureGitTree(tree, (FixtureGitTreeEntry("loop", GitObjectKind.TREE, "040000", tree),)),),
    )
    result = admit_candidate_materialization(
        store=conflict, context=trusted_context(), candidate_id=CandidateId("c"), candidate_commit_id=candidate,
    )
    assert (result.status, result.reason, result.git_object_observation_binding_id) == (
        CandidateMaterializationAdmissionStatus.INDETERMINATE,
        CandidateMaterializationAdmissionReason.OBSERVATION_CONFLICT, None,
    )


@pytest.mark.parametrize(("entry_value", "reason"), [
    (FixtureGitTreeEntry("link", GitObjectKind.SYMLINK, "120000", sha("1")), CandidateMaterializationAdmissionReason.TREE_OBJECT_UNSUPPORTED),
    (FixtureGitTreeEntry("submodule", GitObjectKind.GITLINK, "160000", sha("1")), CandidateMaterializationAdmissionReason.TREE_OBJECT_UNSUPPORTED),
    (FixtureGitTreeEntry("bad-mode", GitObjectKind.BLOB, "100600", sha("1")), CandidateMaterializationAdmissionReason.TREE_MODE_UNSUPPORTED),
])
def test_issue30_unsupported_leaf_truth_is_denied_after_complete_observation(entry_value, reason):
    result = admit_candidate_materialization(
        store=observed_store(candidate_entries=(entry_value,)), context=trusted_context(),
        candidate_id=CandidateId("c"), candidate_commit_id=sha("b"),
    )
    assert (result.status, result.reason) == (CandidateMaterializationAdmissionStatus.DENIED, reason)
    assert result.git_object_observation_binding_id is None


def test_issue30_duplicate_normalized_path_is_denied_and_caller_values_cannot_enter_inventory():
    result = admit_candidate_materialization(
        store=observed_store(candidate_entries=(
            FixtureGitTreeEntry("same", GitObjectKind.BLOB, "100644", sha("1")),
            FixtureGitTreeEntry("same", GitObjectKind.BLOB, "100644", sha("2")),
        )), context=trusted_context(), candidate_id=CandidateId("c"), candidate_commit_id=sha("b"),
    )
    assert (result.status, result.reason) == (
        CandidateMaterializationAdmissionStatus.DENIED,
        CandidateMaterializationAdmissionReason.TREE_PATH_DUPLICATE,
    )
    assert result.admitted_materialization is None


def test_issue30_exact_tree_exceeding_frozen_depth_limit_is_denied():
    base, candidate, base_tree = sha("a"), sha("b"), sha("d")
    tree_ids = tuple(GitSha(f"{index:040x}") for index in range(MAX_TREE_DEPTH + 2))
    trees = [FixtureGitTree(base_tree, ())]
    for index, tree_id in enumerate(tree_ids):
        next_id = tree_ids[index + 1] if index + 1 < len(tree_ids) else sha("1")
        trees.append(FixtureGitTree(tree_id, (FixtureGitTreeEntry(
            "d", GitObjectKind.TREE, "040000", next_id,
        ),)))
    result = admit_candidate_materialization(
        store=FixtureGitObjectStore(
            GitHubRepositoryId("1"),
            (FixtureGitCommit(base, (), base_tree), FixtureGitCommit(candidate, (base,), tree_ids[0])),
            tuple(trees),
        ), context=trusted_context(), candidate_id=CandidateId("depth"), candidate_commit_id=candidate,
    )
    assert (result.status, result.reason) == (
        CandidateMaterializationAdmissionStatus.DENIED,
        CandidateMaterializationAdmissionReason.OBSERVATION_LIMIT_EXCEEDED,
    )


def test_issue30_exact_tree_exceeding_frozen_leaf_limit_is_denied():
    entries = tuple(
        FixtureGitTreeEntry(f"entry-{index}", GitObjectKind.BLOB, "100644", sha("1"))
        for index in range(MAX_LEAF_ENTRIES + 1)
    )
    result = admit_candidate_materialization(
        store=observed_store(candidate_entries=entries), context=trusted_context(),
        candidate_id=CandidateId("entry-limit"), candidate_commit_id=sha("b"),
    )
    assert (result.status, result.reason) == (
        CandidateMaterializationAdmissionStatus.DENIED,
        CandidateMaterializationAdmissionReason.OBSERVATION_LIMIT_EXCEEDED,
    )


def test_issue30_admitted_identity_moves_only_with_fresh_trusted_git_facts():
    same_one = admitted_variant()
    same_two = admitted_variant()
    assert same_one.mutation_inventory.inventory_id == same_two.mutation_inventory.inventory_id
    assert same_one.materialization_id == same_two.materialization_id
    candidate_moved = admitted_variant(candidate="c")
    base_moved = admitted_variant(base="f")
    result_tree_moved = admitted_variant(result_tree="9")
    inventory_moved = admitted_variant(
        result_tree="8", entries=(FixtureGitTreeEntry("changed", GitObjectKind.BLOB, "100644", sha("2")),),
    )
    assert candidate_moved.materialization_id != same_one.materialization_id
    assert base_moved.materialization_id != same_one.materialization_id
    assert result_tree_moved.materialization_id != same_one.materialization_id
    assert inventory_moved.mutation_inventory.inventory_id != same_one.mutation_inventory.inventory_id
    assert inventory_moved.materialization_id != same_one.materialization_id


def test_issue30_admission_result_binding_exists_only_after_complete_observation():
    admitted = admit_candidate_materialization(
        store=observed_store(), context=trusted_context(), candidate_id=CandidateId("shape"), candidate_commit_id=sha("b"),
    )
    assert admitted.status is CandidateMaterializationAdmissionStatus.ADMITTED
    assert admitted.admitted_materialization is not None
    assert admitted.git_object_observation_binding_id is not None
    topology = admit_candidate_materialization(
        store=observed_store(parents=()), context=trusted_context(), candidate_id=CandidateId("shape"), candidate_commit_id=sha("b"),
    )
    assert topology.status is CandidateMaterializationAdmissionStatus.DENIED
    assert topology.admitted_materialization is None
    assert topology.git_object_observation_binding_id is not None
    wrong_context = trusted_context()
    object.__setattr__(wrong_context, "repository_id", GitHubRepositoryId("2"))
    early = admit_candidate_materialization(
        store=observed_store(), context=wrong_context, candidate_id=CandidateId("shape"), candidate_commit_id=sha("b"),
    )
    assert early.status is CandidateMaterializationAdmissionStatus.DENIED
    assert early.admitted_materialization is None
    assert early.git_object_observation_binding_id is None


def test_issue30_trusted_nested_tree_observation_is_exhaustive_and_excludes_invented_paths():
    base, candidate = sha("a"), sha("b")
    base_root, candidate_root = sha("d"), sha("e")
    base_nested, candidate_nested, second = sha("f"), sha("7"), sha("8")
    base_leaves = (
        GitTreeEntry(CanonicalGitPath("nested/modified.txt"), GitObjectKind.BLOB, "100644", sha("3")),
        GitTreeEntry(CanonicalGitPath("nested/retained.txt"), GitObjectKind.BLOB, "100644", sha("2")),
        GitTreeEntry(CanonicalGitPath("root.txt"), GitObjectKind.BLOB, "100644", sha("1")),
        GitTreeEntry(CanonicalGitPath("second/leaf.txt"), GitObjectKind.BLOB, "100644", sha("4")),
    )
    candidate_leaves = (
        GitTreeEntry(CanonicalGitPath("nested/added.txt"), GitObjectKind.BLOB, "100644", sha("6")),
        GitTreeEntry(CanonicalGitPath("nested/modified.txt"), GitObjectKind.BLOB, "100644", sha("5")),
        GitTreeEntry(CanonicalGitPath("nested/retained.txt"), GitObjectKind.BLOB, "100644", sha("2")),
        GitTreeEntry(CanonicalGitPath("root.txt"), GitObjectKind.BLOB, "100644", sha("1")),
        GitTreeEntry(CanonicalGitPath("second/leaf.txt"), GitObjectKind.BLOB, "100644", sha("4")),
    )
    store = FixtureGitObjectStore(
        GitHubRepositoryId("1"),
        (FixtureGitCommit(base, (), base_root), FixtureGitCommit(candidate, (base,), candidate_root)),
        (
            FixtureGitTree(base_root, (
                FixtureGitTreeEntry("root.txt", GitObjectKind.BLOB, "100644", sha("1")),
                FixtureGitTreeEntry("nested", GitObjectKind.TREE, "040000", base_nested),
                FixtureGitTreeEntry("second", GitObjectKind.TREE, "040000", second),
            )),
            FixtureGitTree(candidate_root, (
                FixtureGitTreeEntry("root.txt", GitObjectKind.BLOB, "100644", sha("1")),
                FixtureGitTreeEntry("nested", GitObjectKind.TREE, "040000", candidate_nested),
                FixtureGitTreeEntry("second", GitObjectKind.TREE, "040000", second),
            )),
            FixtureGitTree(base_nested, (
                FixtureGitTreeEntry("retained.txt", GitObjectKind.BLOB, "100644", sha("2")),
                FixtureGitTreeEntry("modified.txt", GitObjectKind.BLOB, "100644", sha("3")),
            )),
            FixtureGitTree(candidate_nested, (
                FixtureGitTreeEntry("retained.txt", GitObjectKind.BLOB, "100644", sha("2")),
                FixtureGitTreeEntry("modified.txt", GitObjectKind.BLOB, "100644", sha("5")),
                FixtureGitTreeEntry("added.txt", GitObjectKind.BLOB, "100644", sha("6")),
            )),
            FixtureGitTree(second, (FixtureGitTreeEntry("leaf.txt", GitObjectKind.BLOB, "100644", sha("4")),)),
        ),
        observation_instance_id=RawSha256("9" * 64),
    )
    result = admit_candidate_materialization(
        store=store, context=trusted_context(), candidate_id=CandidateId("nested"), candidate_commit_id=candidate,
    )
    assert result.status is CandidateMaterializationAdmissionStatus.ADMITTED
    expected_binding_preimage = (
        "autodev.git-object-observation/v1", store.observation_instance_id, store.repository_id,
        base, candidate, base_root, candidate_root,
        RawSha256(hashlib.sha256(canonical_json_bytes(base_leaves)).hexdigest()),
        RawSha256(hashlib.sha256(canonical_json_bytes(candidate_leaves)).hexdigest()),
    )
    expected_binding = GitObjectObservationBindingId(RawSha256(
        hashlib.sha256(canonical_json_bytes(expected_binding_preimage)).hexdigest()
    ))
    assert result.git_object_observation_binding_id == expected_binding
    inventory = result.admitted_materialization.mutation_inventory
    assert inventory == derive_mutation_inventory(base_leaves, candidate_leaves)
    assert [(fact.path.value, fact.kind) for fact in inventory.mutations] == [
        ("nested/added.txt", MutationKind.ADDED),
        ("nested/modified.txt", MutationKind.MODIFIED),
    ]
    assert all(fact.path != CanonicalGitPath("invented/path.txt") for fact in inventory.mutations)


def test_issue30_materialization_admission_does_not_grant_scope_authorization():
    result = admit_candidate_materialization(
        store=observed_store(candidate_entries=(FixtureGitTreeEntry(
            "outside.txt", GitObjectKind.BLOB, "100644", sha("2"),
        ),)), context=trusted_context(), candidate_id=CandidateId("scope"), candidate_commit_id=sha("b"),
    )
    assert result.status is CandidateMaterializationAdmissionStatus.ADMITTED
    narrow_scope = MutationScope((MutationScopeRule(
        ExactPathSelector(CanonicalGitPath("inside.txt")), (ChangeType.ADD,),
    ),))
    assert not inventory_is_authorized(
        result.admitted_materialization.mutation_inventory, narrow_scope, MutationScope(()),
    )


def test_empty_tree_delta_is_deterministic():
    inventory = derive_mutation_inventory((), ())
    assert type(inventory) is MutationInventory
    assert inventory.mutations == ()
    assert inventory == derive_mutation_inventory((), ())


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
