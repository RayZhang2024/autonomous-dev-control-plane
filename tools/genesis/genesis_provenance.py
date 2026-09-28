"""Closed content-addressed Genesis review and post-merge provenance records.

These records are external bootstrap evidence, not credentials or authority.
This module validates their exact v1 grammars; only the independent review
path creates an authoritative PASS review record.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

from external_profiles import canonical_json_bytes


REPOSITORY = "RayZhang2024/autonomous-dev-control-plane"
ISSUE_NUMBER = 55
PR_NUMBER = 56
REVIEW_RECORD_FORMAT = "autodev.genesis-exact-head-review-record/v1"
POST_MERGE_BINDING_FORMAT = "autodev.genesis-post-merge-binding/v1"
REVIEW_RECORD_DOMAIN = REVIEW_RECORD_FORMAT.encode("ascii") + b"\0"
POST_MERGE_BINDING_DOMAIN = POST_MERGE_BINDING_FORMAT.encode("ascii") + b"\0"

REVIEW_RECORD_FIELDS = frozenset({
    "format", "repository", "issue_number", "pr_number", "authorized_base_sha",
    "reviewed_head_sha", "reviewed_head_tree_sha", "candidate_package_id",
    "candidate_package_zip_sha256", "genesis_manifest_id", "manifest_sha256",
    "deterministic_evidence_id", "deterministic_evidence_sha256",
    "runtime_artifact_sha256", "root_anchor_id", "external_dependencies",
    "deployment_readiness_id", "review_decision", "review_provenance", "reviewed_at",
})
REVIEW_PROVENANCE_FIELDS = frozenset({
    "github_pull_request_review_id", "github_pull_request_review_body_sha256",
})
EXTERNAL_DEPENDENCY_FIELDS = frozenset({
    "ROOT_ACTIVATION_FENCE", "EXECUTION_ISOLATION", "FIXTURE_EFFECT_SUBSTRATE",
})
POST_MERGE_BINDING_FIELDS = frozenset({
    "format", "genesis_review_record_id", "repository", "pr_number", "reviewed_head_sha",
    "reviewed_head_tree_sha", "authorized_base_sha", "merge_method", "merge_commit_sha",
    "merge_parent_shas", "main_ref", "current_main_sha", "current_main_tree_sha",
    "post_merge_candidate", "regeneration", "verified_at",
})
POST_MERGE_CANDIDATE_FIELDS = frozenset({
    "candidate_package_id", "candidate_package_zip_sha256", "genesis_manifest_id",
    "manifest_sha256", "deterministic_evidence_id", "deterministic_evidence_sha256",
    "runtime_artifact_sha256", "source_bundle_sha256", "build_definition_sha256",
    "dependency_lock_sha256", "resource_graph_sha256", "root_anchor_id",
    "ROOT_ACTIVATION_FENCE", "EXECUTION_ISOLATION", "FIXTURE_EFFECT_SUBSTRATE",
})
REGENERATION_FIELDS = frozenset({
    "run_count", "run_a_candidate_package_zip_sha256", "run_b_candidate_package_zip_sha256",
})
GITHUB_OBSERVATION_FIELDS = frozenset({
    "format", "repository", "pr_number", "reviewed_head_sha", "merged",
    "merge_commit_sha", "current_main_sha", "observed_at",
})
GITHUB_OBSERVATION_FORMAT = "autodev.genesis-github-state-observation/v1"
STAGE_B_SUBJECT_DOMAIN = b"autodev.genesis-stage-b-subject/v1\0"
HEX_40 = re.compile(r"[0-9a-f]{40}\Z", re.ASCII)
HEX_64 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
DEPENDENCY = re.compile(r"dep-[a-z0-9-]+-[0-9a-f]{64}\Z", re.ASCII)
EVIDENCE_ID = re.compile(r"D-[0-9a-f]{24}\Z", re.ASCII)


def _exact(value: object, fields: frozenset[str]) -> bool:
    return type(value) is dict and set(value) == set(fields)


def _hex(value: object, pattern: re.Pattern[str]) -> bool:
    return type(value) is str and pattern.fullmatch(value) is not None


def _timestamp(value: object) -> bool:
    # Reuse the canonical ceremony timestamp validator, avoiding a second format.
    import root_admin

    return root_admin._is_exact_utc(value)


def _dependency_map(value: object) -> bool:
    return (_exact(value, EXTERNAL_DEPENDENCY_FIELDS)
            and all(type(item) is str and DEPENDENCY.fullmatch(item) is not None
                    for item in value.values()))


def review_record_identity(preimage: dict[str, object]) -> str:
    return hashlib.sha256(REVIEW_RECORD_DOMAIN + canonical_json_bytes(preimage)).hexdigest()


def validate_genesis_exact_head_review_record(record: object) -> dict[str, Any]:
    """Validate a closed/content-addressed review record without creating one."""
    if not _exact(record, frozenset({"review_record_id", "preimage"})):
        raise ValueError("Genesis exact-head review record is not closed")
    preimage = record["preimage"]
    if not _exact(preimage, REVIEW_RECORD_FIELDS):
        raise ValueError("Genesis exact-head review preimage is not closed")
    if (preimage["format"] != REVIEW_RECORD_FORMAT or preimage["repository"] != REPOSITORY
            or type(preimage["issue_number"]) is not int or preimage["issue_number"] != ISSUE_NUMBER
            or type(preimage["pr_number"]) is not int or preimage["pr_number"] != PR_NUMBER):
        raise ValueError("Genesis review subject is not the exact first-genesis repository/PR")
    if not _hex(record["review_record_id"], HEX_64) or record["review_record_id"] != review_record_identity(preimage):
        raise ValueError("Genesis review record content identity is invalid")
    for field in ("authorized_base_sha", "reviewed_head_sha", "reviewed_head_tree_sha"):
        if not _hex(preimage[field], HEX_40):
            raise ValueError(f"Genesis review {field} is malformed")
    for field in (
        "candidate_package_id", "candidate_package_zip_sha256", "genesis_manifest_id",
        "manifest_sha256", "deterministic_evidence_sha256", "runtime_artifact_sha256",
        "root_anchor_id", "deployment_readiness_id",
    ):
        if not _hex(preimage[field], HEX_64):
            raise ValueError(f"Genesis review {field} is malformed")
    if not _hex(preimage["deterministic_evidence_id"], EVIDENCE_ID):
        raise ValueError("Genesis review deterministic evidence ID is malformed")
    if not _dependency_map(preimage["external_dependencies"]):
        raise ValueError("Genesis review external dependency map is malformed")
    provenance = preimage["review_provenance"]
    if (not _exact(provenance, REVIEW_PROVENANCE_FIELDS)
            or type(provenance["github_pull_request_review_id"]) is not int
            or provenance["github_pull_request_review_id"] <= 0
            or not _hex(provenance["github_pull_request_review_body_sha256"], HEX_64)):
        raise ValueError("Genesis review provenance is malformed")
    if preimage["review_decision"] != "PASS" or not _timestamp(preimage["reviewed_at"]):
        raise ValueError("Genesis review decision or timestamp is invalid")
    return record


def validate_github_state_observation(value: object, review_record: dict[str, Any]) -> dict[str, Any]:
    """Validate the exact external GPT/human GitHub observation used for binding."""
    if not _exact(value, GITHUB_OBSERVATION_FIELDS):
        raise ValueError("GitHub state observation is not closed")
    review = validate_genesis_exact_head_review_record(review_record)["preimage"]
    if (value["format"] != GITHUB_OBSERVATION_FORMAT
            or value["repository"] != REPOSITORY
            or type(value["pr_number"]) is not int or value["pr_number"] != PR_NUMBER
            or value["reviewed_head_sha"] != review["reviewed_head_sha"]
            or type(value["merged"]) is not bool or value["merged"] is not True
            or not _hex(value["merge_commit_sha"], HEX_40)
            or value["current_main_sha"] != value["merge_commit_sha"]
            or not _timestamp(value["observed_at"])):
        raise ValueError("GitHub state observation does not identify the exact merged review subject")
    return value


def validate_post_merge_binding(
    record: object, review_record: dict[str, Any],
) -> dict[str, Any]:
    """Validate exact record identity and all cross-bindings to the review record."""
    if not _exact(record, frozenset({"post_merge_binding_id", "preimage"})):
        raise ValueError("Genesis Post-Merge Binding is not closed")
    preimage = record["preimage"]
    if not _exact(preimage, POST_MERGE_BINDING_FIELDS):
        raise ValueError("Genesis Post-Merge Binding preimage is not closed")
    if (preimage["format"] != POST_MERGE_BINDING_FORMAT
            or not _hex(record["post_merge_binding_id"], HEX_64)
            or record["post_merge_binding_id"] != hashlib.sha256(
                POST_MERGE_BINDING_DOMAIN + canonical_json_bytes(preimage)).hexdigest()):
        raise ValueError("Genesis Post-Merge Binding content identity is invalid")
    review = validate_genesis_exact_head_review_record(review_record)["preimage"]
    for field in ("authorized_base_sha", "reviewed_head_sha", "reviewed_head_tree_sha"):
        if not _hex(preimage[field], HEX_40):
            raise ValueError(f"Post-Merge Binding {field} is malformed")
    if (preimage["repository"] != REPOSITORY or preimage["pr_number"] != PR_NUMBER
            or preimage["genesis_review_record_id"] != review_record["review_record_id"]
            or preimage["authorized_base_sha"] != review["authorized_base_sha"]
            or preimage["reviewed_head_sha"] != review["reviewed_head_sha"]
            or preimage["reviewed_head_tree_sha"] != review["reviewed_head_tree_sha"]):
        raise ValueError("Post-Merge Binding conflicts with its exact Genesis review record")
    merge = preimage["merge_commit_sha"]
    if (preimage["merge_method"] != "EXACT_TWO_PARENT_MERGE_COMMIT"
            or not _hex(merge, HEX_40)
            or preimage["merge_parent_shas"] != [review["authorized_base_sha"], review["reviewed_head_sha"]]
            or preimage["main_ref"] != "refs/heads/main"
            or preimage["current_main_sha"] != merge
            or preimage["current_main_tree_sha"] != review["reviewed_head_tree_sha"]):
        raise ValueError("Post-Merge Binding merge/main/tree shape is invalid")
    candidate = preimage["post_merge_candidate"]
    if not _exact(candidate, POST_MERGE_CANDIDATE_FIELDS):
        raise ValueError("Post-Merge candidate subject is not closed")
    review_candidate = {
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
    for field, value in review_candidate.items():
        if candidate[field] != value:
            raise ValueError(f"Post-Merge candidate {field} differs from reviewed subject")
    digest_fields = POST_MERGE_CANDIDATE_FIELDS - EXTERNAL_DEPENDENCY_FIELDS
    for field in digest_fields:
        if field == "deterministic_evidence_id":
            if not _hex(candidate[field], EVIDENCE_ID):
                raise ValueError("Post-Merge deterministic evidence ID is malformed")
        elif not _hex(candidate[field], HEX_64):
            raise ValueError(f"Post-Merge candidate {field} is malformed")
    if not _dependency_map({key: candidate[key] for key in EXTERNAL_DEPENDENCY_FIELDS}):
        raise ValueError("Post-Merge external dependency identities are malformed")
    regeneration = preimage["regeneration"]
    if (not _exact(regeneration, REGENERATION_FIELDS)
            or type(regeneration["run_count"]) is not int or regeneration["run_count"] != 2
            or not _hex(regeneration["run_a_candidate_package_zip_sha256"], HEX_64)
            or regeneration["run_a_candidate_package_zip_sha256"]
               != review["candidate_package_zip_sha256"]
            or regeneration["run_b_candidate_package_zip_sha256"]
               != regeneration["run_a_candidate_package_zip_sha256"]):
        raise ValueError("Post-Merge deterministic regeneration evidence is invalid")
    if not _timestamp(preimage["verified_at"]):
        raise ValueError("Post-Merge Binding timestamp is invalid")
    return record


def stage_b_subject_digest(
    review_record: dict[str, Any], post_merge_binding: dict[str, Any],
) -> str:
    review = validate_genesis_exact_head_review_record(review_record)
    binding = validate_post_merge_binding(post_merge_binding, review)
    candidate = binding["preimage"]["post_merge_candidate"]
    subject = {
        "review_record_id": review["review_record_id"],
        "post_merge_binding_id": binding["post_merge_binding_id"],
        "candidate_package_id": candidate["candidate_package_id"],
        "candidate_package_zip_sha256": candidate["candidate_package_zip_sha256"],
        "genesis_manifest_id": candidate["genesis_manifest_id"],
        "manifest_sha256": candidate["manifest_sha256"],
        "deterministic_evidence_id": candidate["deterministic_evidence_id"],
        "deterministic_evidence_sha256": candidate["deterministic_evidence_sha256"],
        "runtime_artifact_sha256": candidate["runtime_artifact_sha256"],
        "root_anchor_id": candidate["root_anchor_id"],
        "external_dependencies": {
            name: candidate[name] for name in sorted(EXTERNAL_DEPENDENCY_FIELDS)
        },
        "merge_commit_sha": binding["preimage"]["merge_commit_sha"],
        "current_main_sha": binding["preimage"]["current_main_sha"],
        "current_main_tree_sha": binding["preimage"]["current_main_tree_sha"],
    }
    return hashlib.sha256(STAGE_B_SUBJECT_DOMAIN + canonical_json_bytes(subject)).hexdigest()
