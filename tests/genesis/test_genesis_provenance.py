"""Exact, non-authoritative G9 review and post-merge provenance regressions."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

import genesis_provenance as provenance
import post_merge_binding
from external_profiles import canonical_json_bytes
from provenance_fixtures import (
    make_github_observation, make_post_merge_binding, make_review_record,
)


def _valid_review(**changes):
    values = {
        "package_id": "a" * 64,
        "manifest_id": "b" * 64,
        "evidence_id": "D-" + "c" * 24,
        "runtime_sha256": "d" * 64,
        "root_anchor_id": "e" * 64,
        "dependencies": {
            "ROOT_ACTIVATION_FENCE": "dep-root-activation-fence-" + "1" * 64,
            "EXECUTION_ISOLATION": "dep-execution-isolation-" + "2" * 64,
            "FIXTURE_EFFECT_SUBSTRATE": "dep-fixture-effect-substrate-" + "3" * 64,
        },
    }
    values.update(changes)
    return make_review_record(**values)


def _readdress_review(record):
    record["review_record_id"] = provenance.review_record_identity(record["preimage"])
    return record


def _readdress_binding(record):
    record["post_merge_binding_id"] = hashlib.sha256(
        provenance.POST_MERGE_BINDING_DOMAIN + canonical_json_bytes(record["preimage"])
    ).hexdigest()
    return record


def test_review_record_uses_exact_closed_domain_separated_content_identity():
    record = _valid_review()
    assert provenance.validate_genesis_exact_head_review_record(record) == record
    assert record["review_record_id"] == hashlib.sha256(
        b"autodev.genesis-exact-head-review-record/v1\0"
        + canonical_json_bytes(record["preimage"])
    ).hexdigest()


@pytest.mark.parametrize("mutate", (
    lambda p: p.update(repository="other/repository"),
    lambda p: p.update(issue_number=54),
    lambda p: p.update(pr_number=55),
    lambda p: p.update(review_decision="FAIL"),
    lambda p: p.update(review_provenance={"github_pull_request_review_id": 2}),
    lambda p: p.update(reviewed_at="2026-09-29T12:00:00Z"),
))
def test_review_record_rejects_wrong_fixed_subject_or_open_or_malformed_fields(mutate):
    record = json.loads(json.dumps(_valid_review()))
    mutate(record["preimage"])
    _readdress_review(record)
    with pytest.raises(ValueError):
        provenance.validate_genesis_exact_head_review_record(record)


def test_review_record_may_be_well_formed_for_another_subject_but_local_merge_proof_rejects_it(tmp_path):
    repo, base, head, tree, merge = _git_repo(tmp_path)
    # Content-addressed review validation checks the record grammar and fixed Issue/PR,
    # while exact local Git binding is established only by the merge-subject verifier.
    review = _valid_review(base_sha=base, head_sha=base, tree_sha=tree)
    assert provenance.validate_genesis_exact_head_review_record(review) == review
    observation = make_github_observation(review, merge_commit_sha=merge)
    with pytest.raises(ValueError, match="tree|parent|commit|merge"):
        post_merge_binding.verify_local_merge_subject(repo, review, observation)


def test_review_record_rejects_wrong_content_id_and_unknown_fields():
    record = _valid_review()
    changed = json.loads(json.dumps(record))
    changed["review_record_id"] = "9" * 64
    with pytest.raises(ValueError, match="content identity"):
        provenance.validate_genesis_exact_head_review_record(changed)
    changed = json.loads(json.dumps(record))
    changed["unexpected"] = True
    with pytest.raises(ValueError, match="not closed"):
        provenance.validate_genesis_exact_head_review_record(changed)


def test_post_merge_binding_binds_review_and_exact_merge_candidate():
    review = _valid_review()
    binding = make_post_merge_binding(review)
    assert provenance.validate_post_merge_binding(binding, review) == binding
    pre = binding["preimage"]
    assert pre["merge_parent_shas"] == [
        review["preimage"]["authorized_base_sha"], review["preimage"]["reviewed_head_sha"]
    ]
    assert pre["current_main_sha"] == pre["merge_commit_sha"]
    assert pre["current_main_tree_sha"] == review["preimage"]["reviewed_head_tree_sha"]
    assert pre["regeneration"]["run_count"] == 2


@pytest.mark.parametrize("mutate", (
    lambda p: p.update(repository="elsewhere/repo"),
    lambda p: p.update(pr_number=57),
    lambda p: p.update(reviewed_head_sha="9" * 40),
    lambda p: p.update(authorized_base_sha="9" * 40),
    lambda p: p.update(merge_method="SQUASH"),
    lambda p: p.update(merge_parent_shas=["1" * 40, "0" * 40]),
    lambda p: p.update(current_main_sha="9" * 40),
    lambda p: p.update(current_main_tree_sha="9" * 40),
    lambda p: p["post_merge_candidate"].update(candidate_package_id="9" * 64),
    lambda p: p["post_merge_candidate"].update(candidate_package_zip_sha256="9" * 64),
    lambda p: p["post_merge_candidate"].update(genesis_manifest_id="9" * 64),
    lambda p: p["post_merge_candidate"].update(manifest_sha256="9" * 64),
    lambda p: p["post_merge_candidate"].update(deterministic_evidence_id="D-" + "9" * 24),
    lambda p: p["post_merge_candidate"].update(deterministic_evidence_sha256="9" * 64),
    lambda p: p["post_merge_candidate"].update(runtime_artifact_sha256="9" * 64),
    lambda p: p["post_merge_candidate"].update(root_anchor_id="9" * 64),
    lambda p: p["post_merge_candidate"].update(ROOT_ACTIVATION_FENCE="dep-root-activation-fence-" + "9" * 64),
    lambda p: p["post_merge_candidate"].update(EXECUTION_ISOLATION="dep-execution-isolation-" + "9" * 64),
    lambda p: p["post_merge_candidate"].update(FIXTURE_EFFECT_SUBSTRATE="dep-fixture-effect-substrate-" + "9" * 64),
    lambda p: p["regeneration"].update(run_b_candidate_package_zip_sha256="9" * 64),
))
def test_binding_rejects_conflict_with_exact_review_and_merge_subject(mutate):
    review = _valid_review()
    binding = make_post_merge_binding(review)
    mutate(binding["preimage"])
    _readdress_binding(binding)
    with pytest.raises(ValueError):
        provenance.validate_post_merge_binding(binding, review)


def test_binding_rejects_other_review_record_and_unknown_fields():
    review = _valid_review()
    binding = make_post_merge_binding(review)
    other = _valid_review(package_id="f" * 64)
    with pytest.raises(ValueError, match="conflicts"):
        provenance.validate_post_merge_binding(binding, other)
    binding["preimage"]["extra"] = True
    _readdress_binding(binding)
    with pytest.raises(ValueError, match="not closed"):
        provenance.validate_post_merge_binding(binding, review)


def test_external_github_observation_is_closed_and_must_match_review_and_merge():
    review = _valid_review()
    observation = make_github_observation(review)
    assert provenance.validate_github_state_observation(observation, review) == observation
    for field, value in (
        ("pr_number", 57), ("reviewed_head_sha", "9" * 40), ("merged", False),
        ("merge_commit_sha", "9" * 40), ("current_main_sha", "8" * 40),
        ("observed_at", "2026-09-29T12:00:00Z"),
    ):
        changed = dict(observation, **{field: value})
        with pytest.raises(ValueError):
            provenance.validate_github_state_observation(changed, review)
    changed = dict(observation, extra=True)
    with pytest.raises(ValueError, match="not closed"):
        provenance.validate_github_state_observation(changed, review)


def test_stage_b_digest_exactly_binds_all_frozen_provenance_subjects():
    review = _valid_review()
    binding = make_post_merge_binding(review)
    digest = provenance.stage_b_subject_digest(review, binding)
    assert len(digest) == 64
    assert digest == provenance.stage_b_subject_digest(review, binding)
    changed_review = json.loads(json.dumps(review))
    changed_review["preimage"]["reviewed_head_sha"] = "9" * 40
    _readdress_review(changed_review)
    assert digest != provenance.stage_b_subject_digest(
        changed_review, make_post_merge_binding(changed_review),
    )


def _git(repo: Path, *args: str, input: bytes | None = None) -> str:
    result = subprocess.run(
        ["git", *args], cwd=repo, input=input, check=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=input is None,
    )
    return result.stdout.decode("ascii").strip() if input is not None else result.stdout.strip()


def _git_repo(tmp_path: Path, *, reverse_parents: bool = False, different_tree: bool = False):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "--initial-branch=main")
    _git(repo, "config", "user.name", "Fixture")
    _git(repo, "config", "user.email", "fixture@example.invalid")
    _git(repo, "remote", "add", "origin", "https://github.com/RayZhang2024/autonomous-dev-control-plane.git")
    (repo / "tracked.txt").write_text("base\n", encoding="utf-8")
    _git(repo, "add", "tracked.txt")
    _git(repo, "commit", "-m", "base")
    base = _git(repo, "rev-parse", "HEAD")
    (repo / "tracked.txt").write_text("reviewed\n", encoding="utf-8")
    _git(repo, "add", "tracked.txt")
    tree = _git(repo, "write-tree")
    env = os.environ.copy()
    env.update({"GIT_AUTHOR_NAME": "Fixture", "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
                "GIT_COMMITTER_NAME": "Fixture", "GIT_COMMITTER_EMAIL": "fixture@example.invalid"})
    head = subprocess.run(["git", "commit-tree", tree, "-p", base], cwd=repo, env=env,
                          check=True, stdout=subprocess.PIPE, text=True).stdout.strip()
    merge_tree = tree
    if different_tree:
        (repo / "merged.txt").write_text("different\n", encoding="utf-8")
        _git(repo, "add", "merged.txt")
        merge_tree = _git(repo, "write-tree")
    parents = [head, base] if reverse_parents else [base, head]
    merge = subprocess.run(["git", "commit-tree", merge_tree, "-p", parents[0], "-p", parents[1]],
                           cwd=repo, env=env, check=True, stdout=subprocess.PIPE,
                           text=True).stdout.strip()
    _git(repo, "update-ref", "refs/heads/main", merge)
    _git(repo, "reset", "--hard", merge)
    return repo, base, head, tree, merge


def test_git_provenance_reestablishes_exact_two_parent_tree_main_and_ignores_untracked(tmp_path):
    repo, base, head, tree, merge = _git_repo(tmp_path)
    review = _valid_review(base_sha=base, head_sha=head, tree_sha=tree)
    observation = make_github_observation(review, merge_commit_sha=merge)
    (repo / "untracked-proof-artifact.txt").write_text("ignored by subject\n", encoding="utf-8")
    facts = post_merge_binding.verify_local_merge_subject(repo, review, observation)
    assert facts == {
        "merge_commit_sha": merge,
        "merge_parent_shas": [base, head],
        "current_main_sha": merge,
        "current_main_tree_sha": tree,
        "reviewed_head_tree_sha": tree,
    }


@pytest.mark.parametrize("options", ({"reverse_parents": True}, {"different_tree": True}))
def test_git_provenance_rejects_wrong_parent_order_or_merge_tree(tmp_path, options):
    repo, base, head, tree, merge = _git_repo(tmp_path, **options)
    review = _valid_review(base_sha=base, head_sha=head, tree_sha=tree)
    observation = make_github_observation(review, merge_commit_sha=merge)
    with pytest.raises(ValueError, match="merge|tree"):
        post_merge_binding.verify_local_merge_subject(repo, review, observation)


def test_git_provenance_rejects_stale_main_dirty_tracked_tree_and_wrong_branch(tmp_path):
    repo, base, head, tree, merge = _git_repo(tmp_path)
    review = _valid_review(base_sha=base, head_sha=head, tree_sha=tree)
    observation = make_github_observation(review, merge_commit_sha=merge)
    (repo / "tracked.txt").write_text("modified\n", encoding="utf-8")
    with pytest.raises(ValueError, match="tracked modifications"):
        post_merge_binding.verify_local_merge_subject(repo, review, observation)
    _git(repo, "checkout", "--", "tracked.txt")
    _git(repo, "branch", "reviewed", head)
    _git(repo, "checkout", "reviewed")
    with pytest.raises(ValueError, match="local main"):
        post_merge_binding.verify_local_merge_subject(repo, review, observation)


def test_git_provenance_rejects_main_moved_after_merge(tmp_path):
    repo, base, head, tree, merge = _git_repo(tmp_path)
    review = _valid_review(base_sha=base, head_sha=head, tree_sha=tree)
    observation = make_github_observation(review, merge_commit_sha=merge)
    _git(repo, "reset", "--hard", base)
    with pytest.raises(ValueError, match="HEAD/main is stale"):
        post_merge_binding.verify_local_merge_subject(repo, review, observation)


def test_post_merge_regeneration_compares_exact_reviewed_candidate_and_package_bytes(tmp_path, monkeypatch):
    repo, base, head, tree, merge = _git_repo(tmp_path)
    package_bytes = b"candidate package bytes"
    manifest = b"manifest bytes"
    evidence = b"deterministic evidence bytes"
    graph = b"graph bytes"
    build = {
        "root_anchor_id": "e" * 64,
        "root_fence_dependency_id": "dep-root-activation-fence-" + "1" * 64,
        "execution_isolation_dependency_id": "dep-execution-isolation-" + "2" * 64,
        "fixture_substrate_dependency_id": "dep-fixture-effect-substrate-" + "3" * 64,
    }
    package = SimpleNamespace(
        candidate_package=package_bytes, candidate_package_id="a" * 64,
        manifest_id="b" * 64, manifest=manifest,
        deterministic_evidence_id="D-" + "c" * 24, deterministic_evidence=evidence,
        runtime_sha256="d" * 64, source_bundle_sha256="4" * 64,
        build_definition_sha256="5" * 64, dependency_lock_sha256="6" * 64,
        graph=graph, build_definition=json.dumps(build).encode("utf-8"),
    )
    review = _valid_review(
        package_id=package.candidate_package_id, manifest_id=package.manifest_id,
        evidence_id=package.deterministic_evidence_id, runtime_sha256=package.runtime_sha256,
        root_anchor_id=build["root_anchor_id"],
        dependencies={
            "ROOT_ACTIVATION_FENCE": build["root_fence_dependency_id"],
            "EXECUTION_ISOLATION": build["execution_isolation_dependency_id"],
            "FIXTURE_EFFECT_SUBSTRATE": build["fixture_substrate_dependency_id"],
        },
        package_zip_sha256=hashlib.sha256(package_bytes).hexdigest(),
        manifest_sha256=hashlib.sha256(manifest).hexdigest(),
        evidence_sha256=hashlib.sha256(evidence).hexdigest(),
        base_sha=base, head_sha=head, tree_sha=tree,
    )
    monkeypatch.setattr(post_merge_binding, "_host_bound_candidate", lambda _repo: package)
    binding = post_merge_binding.generate_post_merge_binding(
        repo, review, make_github_observation(review, merge_commit_sha=merge),
    )
    assert binding["preimage"]["post_merge_candidate"]["candidate_package_id"] == package.candidate_package_id
    assert binding["preimage"]["regeneration"]["run_count"] == 2
    assert provenance.validate_post_merge_binding(binding, review) == binding


def test_post_merge_regeneration_rejects_nonidentical_a_b_package_bytes(tmp_path, monkeypatch):
    repo, base, head, tree, merge = _git_repo(tmp_path)
    package_bytes = b"candidate package bytes"
    build = {
        "root_anchor_id": "e" * 64,
        "root_fence_dependency_id": "dep-root-activation-fence-" + "1" * 64,
        "execution_isolation_dependency_id": "dep-execution-isolation-" + "2" * 64,
        "fixture_substrate_dependency_id": "dep-fixture-effect-substrate-" + "3" * 64,
    }
    package_a = SimpleNamespace(
        candidate_package=package_bytes, candidate_package_id="a" * 64,
        manifest_id="b" * 64, manifest=b"manifest", deterministic_evidence_id="D-" + "c" * 24,
        deterministic_evidence=b"evidence", runtime_sha256="d" * 64,
        source_bundle_sha256="4" * 64, build_definition_sha256="5" * 64,
        dependency_lock_sha256="6" * 64, graph=b"graph",
        build_definition=json.dumps(build).encode("utf-8"),
    )
    package_b = SimpleNamespace(**vars(package_a))
    package_b.candidate_package = b"different candidate package bytes"
    review = _valid_review(
        package_id=package_a.candidate_package_id, manifest_id=package_a.manifest_id,
        evidence_id=package_a.deterministic_evidence_id, runtime_sha256=package_a.runtime_sha256,
        root_anchor_id=build["root_anchor_id"],
        dependencies={
            "ROOT_ACTIVATION_FENCE": build["root_fence_dependency_id"],
            "EXECUTION_ISOLATION": build["execution_isolation_dependency_id"],
            "FIXTURE_EFFECT_SUBSTRATE": build["fixture_substrate_dependency_id"],
        },
        package_zip_sha256=hashlib.sha256(package_bytes).hexdigest(),
        manifest_sha256=hashlib.sha256(package_a.manifest).hexdigest(),
        evidence_sha256=hashlib.sha256(package_a.deterministic_evidence).hexdigest(),
        base_sha=base, head_sha=head, tree_sha=tree,
    )
    packages = iter((package_a, package_b))
    monkeypatch.setattr(post_merge_binding, "_host_bound_candidate", lambda _repo: next(packages))
    observation = make_github_observation(review, merge_commit_sha=merge)
    with pytest.raises(ValueError, match="regenerations are not byte-identical"):
        post_merge_binding.generate_post_merge_binding(repo, review, observation)
