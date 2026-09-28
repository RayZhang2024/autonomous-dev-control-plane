"""Deterministically verify and bind first-genesis post-merge provenance."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

REPOSITORY_ID = "RayZhang2024/autonomous-dev-control-plane"
REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY_ROOT / "src"))
sys.path.insert(0, str(REPOSITORY_ROOT / "tools" / "genesis"))

from assemble_candidate import CandidatePackage, assemble_candidate  # noqa: E402
from build_definition import sha256  # noqa: E402
from external_profiles import canonical_json_bytes  # noqa: E402
from genesis_provenance import (  # noqa: E402
    POST_MERGE_BINDING_DOMAIN,
    POST_MERGE_BINDING_FORMAT,
    validate_genesis_exact_head_review_record,
    validate_github_state_observation,
    validate_post_merge_binding,
)
from root_admin import _now_utc  # noqa: E402


def _git(repository: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", *args], cwd=repository, check=True, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, encoding="ascii",
    )
    return completed.stdout.strip()


def _require_exact_repository(repository: Path) -> Path:
    root = Path(_git(repository, "rev-parse", "--show-toplevel")).resolve()
    if root != repository.resolve():
        raise ValueError("post-merge verification path is not the exact repository root")
    remote = _git(root, "remote", "get-url", "origin").rstrip("/")
    accepted = {
        "https://github.com/RayZhang2024/autonomous-dev-control-plane",
        "https://github.com/RayZhang2024/autonomous-dev-control-plane.git",
        "git@github.com:RayZhang2024/autonomous-dev-control-plane",
        "git@github.com:RayZhang2024/autonomous-dev-control-plane.git",
        "ssh://git@github.com/RayZhang2024/autonomous-dev-control-plane",
        "ssh://git@github.com/RayZhang2024/autonomous-dev-control-plane.git",
    }
    if remote not in accepted:
        raise ValueError("post-merge repository remote identity is not the frozen repository")
    if _git(root, "symbolic-ref", "--short", "HEAD") != "main":
        raise ValueError("post-merge verification requires a checkout of local main")
    if _git(root, "status", "--porcelain", "--untracked-files=no"):
        raise ValueError("post-merge repository has tracked modifications")
    return root


def verify_local_merge_subject(
    repository: Path, review_record: dict[str, Any], github_observation: dict[str, Any],
) -> dict[str, str | list[str]]:
    """Re-establish the exact merge graph/tree and current-main binding from Git objects."""
    validate_genesis_exact_head_review_record(review_record)
    validate_github_state_observation(github_observation, review_record)
    review = review_record["preimage"]
    root = _require_exact_repository(repository)
    merge = github_observation["merge_commit_sha"]
    if github_observation["current_main_sha"] != merge:
        raise ValueError("externally observed current main is not the exact merge commit")
    head = _git(root, "rev-parse", "HEAD")
    main = _git(root, "rev-parse", "refs/heads/main")
    if head != merge or main != merge:
        raise ValueError("local HEAD/main is stale against the externally observed merge commit")
    for name, commit in (("reviewed head", review["reviewed_head_sha"]),
                         ("merge commit", merge), ("authorized base", review["authorized_base_sha"])):
        if _git(root, "cat-file", "-t", f"{commit}^{{commit}}") != "commit":
            raise ValueError(f"{name} Git object is unavailable")
    reviewed_tree = _git(root, "rev-parse", f"{review['reviewed_head_sha']}^{{tree}}")
    main_tree = _git(root, "rev-parse", "HEAD^{tree}")
    if reviewed_tree != review["reviewed_head_tree_sha"]:
        raise ValueError("reviewed-head tree differs from the Genesis review record")
    if main_tree != reviewed_tree:
        raise ValueError("merged main tree differs from the reviewed-head tree")
    parents = _git(root, "rev-list", "--parents", "-n", "1", merge).split()
    expected_parents = [merge, review["authorized_base_sha"], review["reviewed_head_sha"]]
    if parents != expected_parents:
        raise ValueError("merge commit does not have the exact ordered two-parent first-genesis shape")
    return {
        "merge_commit_sha": merge,
        "merge_parent_shas": parents[1:],
        "current_main_sha": main,
        "current_main_tree_sha": main_tree,
        "reviewed_head_tree_sha": reviewed_tree,
    }


def _host_bound_candidate(repository: Path) -> CandidatePackage:
    from windows_role_runner import _host_profiles

    root_profile, substrate_profile, root_anchor_id, _ = _host_profiles()
    return assemble_candidate(
        git_cwd=str(repository), root_fence_profile=root_profile,
        fixture_substrate_profile=substrate_profile, root_anchor_id=root_anchor_id,
    )


def _candidate_subject(package: CandidatePackage) -> dict[str, str]:
    build = json.loads(package.build_definition)
    return {
        "candidate_package_id": package.candidate_package_id,
        "candidate_package_zip_sha256": sha256(package.candidate_package),
        "genesis_manifest_id": package.manifest_id,
        "manifest_sha256": sha256(package.manifest),
        "deterministic_evidence_id": package.deterministic_evidence_id,
        "deterministic_evidence_sha256": sha256(package.deterministic_evidence),
        "runtime_artifact_sha256": package.runtime_sha256,
        "source_bundle_sha256": package.source_bundle_sha256,
        "build_definition_sha256": package.build_definition_sha256,
        "dependency_lock_sha256": package.dependency_lock_sha256,
        "resource_graph_sha256": sha256(package.graph),
        "root_anchor_id": build["root_anchor_id"],
        "ROOT_ACTIVATION_FENCE": build["root_fence_dependency_id"],
        "EXECUTION_ISOLATION": build["execution_isolation_dependency_id"],
        "FIXTURE_EFFECT_SUBSTRATE": build["fixture_substrate_dependency_id"],
    }


def generate_post_merge_binding(
    repository: Path, review_record: dict[str, Any], github_observation: dict[str, Any],
) -> dict[str, Any]:
    """Build a non-authoritative binding only from exact local Git and fresh external facts."""
    validate_genesis_exact_head_review_record(review_record)
    observation = validate_github_state_observation(github_observation, review_record)
    git_subject = verify_local_merge_subject(repository, review_record, observation)
    root = _require_exact_repository(repository)
    run_a = _host_bound_candidate(root)
    run_b = _host_bound_candidate(root)
    if run_a.candidate_package != run_b.candidate_package:
        raise ValueError("two clean post-merge candidate regenerations are not byte-identical")
    candidate = _candidate_subject(run_a)
    review = review_record["preimage"]
    reviewed_candidate = {
        "candidate_package_id": review["candidate_package_id"],
        "candidate_package_zip_sha256": review["candidate_package_zip_sha256"],
        "genesis_manifest_id": review["genesis_manifest_id"],
        "manifest_sha256": review["manifest_sha256"],
        "deterministic_evidence_id": review["deterministic_evidence_id"],
        "deterministic_evidence_sha256": review["deterministic_evidence_sha256"],
        "runtime_artifact_sha256": review["runtime_artifact_sha256"],
        "root_anchor_id": review["root_anchor_id"],
        **review["external_dependencies"],
    }
    if any(candidate[key] != value for key, value in reviewed_candidate.items()):
        raise ValueError("post-merge regenerated candidate differs from independent reviewed subject")
    preimage: dict[str, Any] = {
        "format": POST_MERGE_BINDING_FORMAT,
        "genesis_review_record_id": review_record["review_record_id"],
        "repository": REPOSITORY_ID,
        "pr_number": 56,
        "reviewed_head_sha": review["reviewed_head_sha"],
        "reviewed_head_tree_sha": git_subject["reviewed_head_tree_sha"],
        "authorized_base_sha": review["authorized_base_sha"],
        "merge_method": "EXACT_TWO_PARENT_MERGE_COMMIT",
        "merge_commit_sha": git_subject["merge_commit_sha"],
        "merge_parent_shas": list(git_subject["merge_parent_shas"]),
        "main_ref": "refs/heads/main",
        "current_main_sha": git_subject["current_main_sha"],
        "current_main_tree_sha": git_subject["current_main_tree_sha"],
        "post_merge_candidate": candidate,
        "regeneration": {
            "run_count": 2,
            "run_a_candidate_package_zip_sha256": sha256(run_a.candidate_package),
            "run_b_candidate_package_zip_sha256": sha256(run_b.candidate_package),
        },
        "verified_at": _now_utc(),
    }
    record = {
        "post_merge_binding_id": hashlib.sha256(
            POST_MERGE_BINDING_DOMAIN + canonical_json_bytes(preimage)
        ).hexdigest(),
        "preimage": preimage,
    }
    return validate_post_merge_binding(record, review_record)


def revalidate_post_merge_binding(
    repository: Path, review_record: dict[str, Any], binding: dict[str, Any],
    github_observation: dict[str, Any],
) -> dict[str, Any]:
    """Recheck current local Git/object/tree and both package reproductions before Stage B."""
    validate_genesis_exact_head_review_record(review_record)
    validate_post_merge_binding(binding, review_record)
    observation = validate_github_state_observation(github_observation, review_record)
    git_subject = verify_local_merge_subject(repository, review_record, observation)
    preimage = binding["preimage"]
    for field, value in git_subject.items():
        if preimage[field] != value:
            raise ValueError(f"local Git {field} differs from Post-Merge Binding")
    root = _require_exact_repository(repository)
    run_a = _host_bound_candidate(root)
    run_b = _host_bound_candidate(root)
    if run_a.candidate_package != run_b.candidate_package:
        raise ValueError("Stage-B deterministic package regenerations differ")
    candidate = _candidate_subject(run_a)
    if candidate != preimage["post_merge_candidate"]:
        raise ValueError("Stage-B regenerated package facts differ from Post-Merge Binding")
    regeneration = preimage["regeneration"]
    package_digest = sha256(run_a.candidate_package)
    if (package_digest != regeneration["run_a_candidate_package_zip_sha256"]
            or sha256(run_b.candidate_package) != regeneration["run_b_candidate_package_zip_sha256"]):
        raise ValueError("Stage-B package bytes differ from bound deterministic regeneration")
    return {
        "review_record_id": review_record["review_record_id"],
        "post_merge_binding_id": binding["post_merge_binding_id"],
        "repository": REPOSITORY_ID,
        "current_main_sha": git_subject["current_main_sha"],
        "post_merge_candidate": candidate,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify first-genesis local Git and deterministic package provenance",
    )
    parser.add_argument("--review-record", type=Path, required=True)
    parser.add_argument("--github-observation", type=Path, required=True,
                        help="fresh human/GPT-observed closed JSON; this tool does not query or mutate GitHub")
    parser.add_argument("--output", type=Path, required=True,
                        help="non-authoritative output location for the content-addressed binding")
    args = parser.parse_args()
    review = json.loads(args.review_record.read_bytes())
    observation = json.loads(args.github_observation.read_bytes())
    binding = generate_post_merge_binding(REPOSITORY_ROOT, review, observation)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(canonical_json_bytes(binding))
    print(json.dumps({
        "post_merge_binding_id": binding["post_merge_binding_id"],
        "current_main_sha": binding["preimage"]["current_main_sha"],
        "candidate_package_id": binding["preimage"]["post_merge_candidate"]["candidate_package_id"],
        "output": str(args.output),
        "authority": "NON_BEARER_PROVENANCE_EVIDENCE",
    }, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
