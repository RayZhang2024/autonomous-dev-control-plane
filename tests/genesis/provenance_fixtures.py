"""Non-authoritative Genesis provenance records for isolated tests only."""

from __future__ import annotations

import hashlib

from external_profiles import canonical_json_bytes
from genesis_provenance import (
    POST_MERGE_BINDING_DOMAIN, POST_MERGE_BINDING_FORMAT,
    REVIEW_RECORD_DOMAIN, REVIEW_RECORD_FORMAT,
)


def make_review_record(*, package_id: str, manifest_id: str, evidence_id: str,
                       runtime_sha256: str, root_anchor_id: str,
                       dependencies: dict[str, str], package_zip_sha256: str = "c" * 64,
                       manifest_sha256: str = "d" * 64,
                       evidence_sha256: str = "e" * 64, base_sha: str = "0" * 40,
                       head_sha: str = "1" * 40, tree_sha: str = "2" * 40,
                       pr_number: int = 56,
                       deployment_readiness_id: str = "f" * 64) -> dict[str, object]:
    preimage = {
        "format": REVIEW_RECORD_FORMAT,
        "repository": "RayZhang2024/autonomous-dev-control-plane",
        "issue_number": 55,
        "pr_number": pr_number,
        "authorized_base_sha": base_sha,
        "reviewed_head_sha": head_sha,
        "reviewed_head_tree_sha": tree_sha,
        "candidate_package_id": package_id,
        "candidate_package_zip_sha256": package_zip_sha256,
        "genesis_manifest_id": manifest_id,
        "manifest_sha256": manifest_sha256,
        "deterministic_evidence_id": evidence_id,
        "deterministic_evidence_sha256": evidence_sha256,
        "runtime_artifact_sha256": runtime_sha256,
        "root_anchor_id": root_anchor_id,
        "external_dependencies": dict(dependencies),
        "deployment_readiness_id": deployment_readiness_id,
        "review_decision": "PASS",
        "review_provenance": {
            "github_pull_request_review_id": 123456,
            "github_pull_request_review_body_sha256": "a" * 64,
        },
        "reviewed_at": "2026-09-29T12:00:00.000000Z",
    }
    return {
        "review_record_id": hashlib.sha256(
            REVIEW_RECORD_DOMAIN + canonical_json_bytes(preimage)
        ).hexdigest(),
        "preimage": preimage,
    }


def make_post_merge_binding(review_record: dict[str, object], *,
                            merge_commit_sha: str = "3" * 40,
                            main_tree_sha: str | None = None,
                            merge_parent_shas: list[str] | None = None) -> dict[str, object]:
    review = review_record["preimage"]
    candidate = {
        "candidate_package_id": review["candidate_package_id"],
        "candidate_package_zip_sha256": review["candidate_package_zip_sha256"],
        "genesis_manifest_id": review["genesis_manifest_id"],
        "manifest_sha256": review["manifest_sha256"],
        "deterministic_evidence_id": review["deterministic_evidence_id"],
        "deterministic_evidence_sha256": review["deterministic_evidence_sha256"],
        "runtime_artifact_sha256": review["runtime_artifact_sha256"],
        "source_bundle_sha256": "4" * 64,
        "build_definition_sha256": "5" * 64,
        "dependency_lock_sha256": "6" * 64,
        "resource_graph_sha256": "7" * 64,
        "root_anchor_id": review["root_anchor_id"],
        **review["external_dependencies"],
    }
    tree = main_tree_sha or review["reviewed_head_tree_sha"]
    preimage = {
        "format": POST_MERGE_BINDING_FORMAT,
        "genesis_review_record_id": review_record["review_record_id"],
        "repository": "RayZhang2024/autonomous-dev-control-plane",
        "pr_number": review["pr_number"],
        "reviewed_head_sha": review["reviewed_head_sha"],
        "reviewed_head_tree_sha": review["reviewed_head_tree_sha"],
        "authorized_base_sha": review["authorized_base_sha"],
        "merge_method": "EXACT_TWO_PARENT_MERGE_COMMIT",
        "merge_commit_sha": merge_commit_sha,
        "merge_parent_shas": (merge_parent_shas if merge_parent_shas is not None else
                               [review["authorized_base_sha"], review["reviewed_head_sha"]]),
        "main_ref": "refs/heads/main",
        "current_main_sha": merge_commit_sha,
        "current_main_tree_sha": tree,
        "post_merge_candidate": candidate,
        "regeneration": {
            "run_count": 2,
            "run_a_candidate_package_zip_sha256": review["candidate_package_zip_sha256"],
            "run_b_candidate_package_zip_sha256": review["candidate_package_zip_sha256"],
        },
        "verified_at": "2026-09-29T12:00:00.000000Z",
    }
    return {
        "post_merge_binding_id": hashlib.sha256(
            POST_MERGE_BINDING_DOMAIN + canonical_json_bytes(preimage)
        ).hexdigest(),
        "preimage": preimage,
    }


def make_github_observation(review_record: dict[str, object], *,
                            merge_commit_sha: str = "3" * 40) -> dict[str, object]:
    return {
        "format": "autodev.genesis-github-state-observation/v1",
        "repository": "RayZhang2024/autonomous-dev-control-plane",
        "pr_number": review_record["preimage"]["pr_number"],
        "reviewed_head_sha": review_record["preimage"]["reviewed_head_sha"],
        "merged": True,
        "merge_commit_sha": merge_commit_sha,
        "current_main_sha": merge_commit_sha,
        "observed_at": "2026-09-29T12:00:00.000000Z",
    }
