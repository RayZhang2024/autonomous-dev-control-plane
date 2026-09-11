import pytest

from autodev_control.trusted.identity import RawSha256
from autodev_control.trusted.scope import (
    AuthenticationEventId,
    AuthorizationId,
    AuthorizationKind,
    CanonicalBranchRef,
    CanonicalGitPath,
    ChangeType,
    ContractId,
    ExactPathSelector,
    GitHubRepositoryId,
    HumanPrincipalId,
    MutationScope,
    MutationScopeRule,
    PathPrefixSelector,
    RepositorySelector,
    RiskRelation,
    RiskTier,
    ServicePrincipalId,
    TargetRegistrationId,
    TaskCapability,
    TaskId,
    scope_contains,
    scopes_overlap,
)


def rule(selector, *changes: ChangeType) -> MutationScopeRule:
    return MutationScopeRule(selector, changes)


def scope(*rules: MutationScopeRule) -> MutationScope:
    return MutationScope(rules)


def test_nominal_identity_domains_and_repository_id() -> None:
    identity_types = (HumanPrincipalId, ServicePrincipalId, TaskId, ContractId, AuthenticationEventId)
    for identity_type in identity_types:
        assert identity_type(" é ").value == " é "
        with pytest.raises(ValueError):
            identity_type("")
    assert HumanPrincipalId("x") != ServicePrincipalId("x")
    assert GitHubRepositoryId("1363823008").value == "1363823008"
    for invalid in ("0", "00123", "+123", 123, "1" * 21):
        with pytest.raises(ValueError):
            GitHubRepositoryId(invalid)
    raw = RawSha256("a" * 64)
    assert TargetRegistrationId(raw) != AuthorizationId(raw)


def test_exact_closed_enum_domains_are_nominal() -> None:
    assert {item.value for item in TaskCapability} == {
        "implementation", "candidate_materialization", "target_publish", "deterministic_validation",
        "semantic_review", "controlled_runtime", "external_observation", "repair", "merge",
    }
    assert TaskCapability.MERGE != "merge"
    assert {item.value for item in AuthorizationKind} == {"direct_human", "delegated"}
    assert {item.value for item in RiskTier} == {"routine", "supervised"}
    assert {item.value for item in ChangeType} == {"add", "modify", "delete", "mode_change"}


def test_canonical_git_paths_preserve_spelling() -> None:
    assert CanonicalGitPath("src/É.py").value == "src/É.py"
    assert CanonicalGitPath("src/é.py") != CanonicalGitPath("src/é.py")
    assert CanonicalGitPath("A.py") != CanonicalGitPath("a.py")
    for invalid in ("", "/a", "a/", "a//b", "./a", "a/../b", "a\\b", "a\x00b"):
        with pytest.raises(ValueError):
            CanonicalGitPath(invalid)


def test_scope_containment_supports_boundaries_facets_and_split_rules() -> None:
    parent = scope(
        rule(PathPrefixSelector(CanonicalGitPath("src")), ChangeType.ADD),
        rule(RepositorySelector(), ChangeType.MODIFY),
    )
    child = scope(rule(ExactPathSelector(CanonicalGitPath("src/a.py")), ChangeType.ADD, ChangeType.MODIFY))
    assert scope_contains(parent, child)
    assert not scope_contains(
        scope(rule(PathPrefixSelector(CanonicalGitPath("src/app")), ChangeType.ADD)),
        scope(rule(ExactPathSelector(CanonicalGitPath("src/application.py")), ChangeType.ADD)),
    )
    assert not scope_contains(parent, scope(rule(ExactPathSelector(CanonicalGitPath("src/a.py")), ChangeType.DELETE)))


def test_overlap_is_selector_and_change_type_sensitive() -> None:
    left = scope(rule(PathPrefixSelector(CanonicalGitPath("src")), ChangeType.MODIFY))
    same_path_other_facet = scope(rule(ExactPathSelector(CanonicalGitPath("src/a.py")), ChangeType.ADD))
    same_facet = scope(rule(ExactPathSelector(CanonicalGitPath("src/a.py")), ChangeType.MODIFY))
    assert not scopes_overlap(left, same_path_other_facet)
    assert scopes_overlap(left, same_facet)


def test_semantic_duplicate_scope_rules_reject_change_order_variants() -> None:
    selector = ExactPathSelector(CanonicalGitPath("a.py"))
    with pytest.raises(ValueError):
        MutationScope((
            rule(selector, ChangeType.ADD, ChangeType.MODIFY),
            rule(selector, ChangeType.MODIFY, ChangeType.ADD),
        ))


def test_canonical_branch_ref_acceptance_and_rejections() -> None:
    assert CanonicalBranchRef("refs/heads/main").value == "refs/heads/main"
    for invalid in (
        "main", "refs/tags/main", "HEAD", "refs/heads/", "refs/heads/a.lock",
        "refs/heads/a/.hidden", "refs/heads/a..b", "refs/heads/a@{b", "refs/heads/a//b",
        "refs/heads/a b", "refs/heads/a~b", "refs/heads/a\x7fb",
    ):
        with pytest.raises(ValueError):
            CanonicalBranchRef(invalid)


def test_risk_relation_requires_preorder_and_does_not_infer_edges() -> None:
    total = RiskRelation((
        (RiskTier.ROUTINE, RiskTier.ROUTINE),
        (RiskTier.SUPERVISED, RiskTier.SUPERVISED),
        (RiskTier.ROUTINE, RiskTier.SUPERVISED),
    ))
    assert total.leq(RiskTier.ROUTINE, RiskTier.SUPERVISED)
    assert not total.leq(RiskTier.SUPERVISED, RiskTier.ROUTINE)
    with pytest.raises(ValueError):
        RiskRelation(((RiskTier.ROUTINE, RiskTier.ROUTINE),))
