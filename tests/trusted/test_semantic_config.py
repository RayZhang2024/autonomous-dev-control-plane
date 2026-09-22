"""Focused adversarial coverage for Issue #33's pure semantic-config resolver."""

import hashlib
import json
from decimal import Decimal

import pytest

from autodev_control.trusted.contract import EvaluatorMechanism, ResolvedTrustedConfigBinding, TrustedConfigIdentity, TrustedEvaluatorConfigResolution, contract_json_value_digest
from autodev_control.trusted.identity import ImmutableConfigId, RawSha256, SemanticEvaluatorResolutionId
from autodev_control.trusted.manifest import PolicyEpochIdentity, TrustedManifestId
from autodev_control.trusted.resources import RootManagedResourceId
from autodev_control.trusted.review import (
    ToolMode, TrustedDisclosureAuthorizationBinding, TrustedReReviewAuthorization,
    TrustedReviewInvocationRecord, TrustedReviewProfileAdmissionContext,
)
from autodev_control.trusted.evidence import TrustedVerdictSchemaContext
import autodev_control.trusted.semantic_config as semantic_config
from autodev_control.trusted.semantic_config import (
    MAX_PROVIDER_METADATA_REQUIREMENTS_PER_PROFILE,
    MAX_REQUIRED_TRUSTED_CONTEXTS_PER_SEMANTIC_EVALUATOR,
    MAX_REVIEWER_SERVICE_CONSTRAINTS_PER_PROFILE,
    MAX_REVIEW_SLOTS_PER_SEMANTIC_EVALUATOR,
    SEMANTIC_EVALUATOR_CONFIG_MAX_BYTES,
    SemanticEvaluatorConfigResolutionReason as Reason,
    SemanticEvaluatorConfigResolutionStatus as Status,
    SemanticReviewContextRequirement,
    TrustedSemanticEvaluatorResolution,
    resolve_semantic_evaluator_config,
)
from autodev_control.trusted.scope import TaskCapability


def _mint(cls, **fields):
    value = object.__new__(cls)
    for name, field in fields.items():
        object.__setattr__(value, name, field)
    return value


def _config(**changes):
    value = {
        "format": "autodev.semantic-evaluator-config/v1",
        "mechanism": "semantic",
        "operational_prerequisites": [],
        "review_slots": [{
            "slot_id": "slot-a", "independence_binding_sha256": "a" * 64,
            "profile": {
                "profile_id": "profile-a", "service_id": "service-a", "verdict_schema_id": "schema-a",
                "raw_limits": {"max_bytes": 1024, "max_depth": 8}, "tool_mode": "NO_TOOLS",
                "service_constraint_ids": [], "provider_metadata_requirement_ids": [],
                "rereview_policy_id": "rereview-a", "disclosure_policy_id": "disclosure-a",
            },
        }],
        "composition": {"composition_rule_id": "composition-a", "mode": "SINGLE_REQUIRED_INVOCATION", "required_slot_ids": ["slot-a"]},
        "partition_rule": "SingleReviewPackage", "required_trusted_context_ids": [],
        "target_context_requirement": "NOT_APPLICABLE", "pr_context_requirement": "NOT_APPLICABLE",
    }
    value.update(changes)
    return value


def _raw(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode()


def _basic(raw, *, mechanism=EvaluatorMechanism.SEMANTIC, valid=True, applicable=True, prerequisites=(), epoch_char="b", config_id="config-a", resource_id="resource-a"):
    identity = TrustedConfigIdentity(ImmutableConfigId(config_id), RootManagedResourceId(resource_id), RawSha256(hashlib.sha256(raw).hexdigest()))
    epoch = PolicyEpochIdentity(TrustedManifestId(RawSha256(epoch_char * 64)))
    binding = _mint(ResolvedTrustedConfigBinding, policy_epoch_identity=epoch, config_identity=identity)
    return _mint(TrustedEvaluatorConfigResolution, binding=binding, mechanism=mechanism, parameters_valid=valid, applicable=applicable, operational_prerequisites=prerequisites)


def _resolve(value=None, **kwargs):
    raw = _raw(_config() if value is None else value)
    return resolve_semantic_evaluator_config(_basic(raw, **kwargs), raw)


def test_valid_resolution_derives_exact_g5_facts_and_is_deterministic():
    raw = _raw(_config())
    basic = _basic(raw)
    first = resolve_semantic_evaluator_config(basic, raw)
    second = resolve_semantic_evaluator_config(basic, raw)
    assert first.status is Status.RESOLVED and first.reason is Reason.RESOLVED and first == second
    resolved = first.resolution
    assert resolved is not None
    assert resolved.review_slots[0].profile.config_id == basic.binding.config_identity.config_id
    assert resolved.review_slots[0].profile.tool_mode is ToolMode.NO_TOOLS
    assert resolved.review_slots[0].independence_binding == RawSha256("a" * 64)
    assert resolved.target_context_requirement is SemanticReviewContextRequirement.NOT_APPLICABLE


@pytest.mark.parametrize(("mechanism", "valid", "applicable", "reason"), [
    (EvaluatorMechanism.DETERMINISTIC, True, True, Reason.BASIC_RESOLUTION_NOT_SEMANTIC),
    (EvaluatorMechanism.SEMANTIC, False, True, Reason.BASIC_RESOLUTION_NOT_USABLE),
    (EvaluatorMechanism.SEMANTIC, True, False, Reason.BASIC_RESOLUTION_NOT_USABLE),
])
def test_basic_g1_preconditions_win_before_byte_interpretation(mechanism, valid, applicable, reason):
    raw = _raw(_config())
    result = resolve_semantic_evaluator_config(_basic(raw, mechanism=mechanism, valid=valid, applicable=applicable), b"not-json")
    assert result.status is Status.DENIED and result.reason is reason and result.resolution is None


def test_byte_availability_and_exact_digest_precedence():
    raw = _raw(_config())
    basic = _basic(raw)
    missing = resolve_semantic_evaluator_config(basic, None)
    mismatch = resolve_semantic_evaluator_config(basic, b"{}")
    oversized = resolve_semantic_evaluator_config(basic, b"x" * (16 * 1024 * 1024 + 1))
    assert (missing.status, missing.reason) == (Status.INDETERMINATE, Reason.CONFIG_BYTES_UNAVAILABLE)
    assert (mismatch.status, mismatch.reason) == (Status.INDETERMINATE, Reason.CONFIG_BYTES_MISMATCH)
    assert (oversized.status, oversized.reason) == (Status.INDETERMINATE, Reason.CONFIG_BYTES_UNVERIFIABLE)
    assert mismatch.resource_failure_code.name == "DIGEST_MISMATCH"
    with pytest.raises(TypeError):
        resolve_semantic_evaluator_config(basic, "bytes")


@pytest.mark.parametrize(("mutate", "reason"), [
    (lambda v: v.update({"unknown": 1}), Reason.CONFIG_GRAMMAR_INVALID),
    (lambda v: v.pop("format"), Reason.CONFIG_GRAMMAR_INVALID),
    (lambda v: v.update({"format": "other"}), Reason.UNSUPPORTED_CONFIG_FORMAT),
    (lambda v: v.update({"mechanism": "deterministic"}), Reason.CONFIG_GRAMMAR_INVALID),
    (lambda v: v.update({"review_slots": []}), Reason.CONFIG_GRAMMAR_INVALID),
])
def test_closed_top_level_and_empty_slot_failures(mutate, reason):
    value = _config(); mutate(value)
    result = _resolve(value)
    assert result.status is Status.DENIED and result.reason is reason


def test_canonical_collections_and_tool_restriction_fail_closed():
    duplicate_slots = _config(); duplicate_slots["review_slots"].append(duplicate_slots["review_slots"][0].copy())
    unsorted_contexts = _config(required_trusted_context_ids=["z", "a"])
    tools = _config(); tools["review_slots"][0]["profile"]["tool_mode"] = "PERMITTED_TOOLS"
    assert _resolve(duplicate_slots).reason is Reason.NONCANONICAL_CONFIG
    assert _resolve(unsorted_contexts).reason is Reason.NONCANONICAL_CONFIG
    denied = _resolve(tools)
    assert denied.reason is Reason.UNSUPPORTED_TOOL_MODE and denied.resolution is None
    assert ToolMode.PERMITTED_TOOLS.value == "PERMITTED_TOOLS"


def test_profile_frozen_precedence_tool_mode_wins_over_later_policy_id():
    value = _config(); profile = value["review_slots"][0]["profile"]
    profile["tool_mode"] = "PERMITTED_TOOLS"; profile["rereview_policy_id"] = ""
    result = _resolve(value)
    assert (result.status, result.reason) == (Status.DENIED, Reason.UNSUPPORTED_TOOL_MODE)


def test_profile_frozen_precedence_raw_limits_win_over_later_policy_ids():
    value = _config(); profile = value["review_slots"][0]["profile"]
    profile["raw_limits"]["max_bytes"] = 0; profile["rereview_policy_id"] = ""; profile["disclosure_policy_id"] = ""
    assert _resolve(value).reason is Reason.CONFIG_GRAMMAR_INVALID


def test_profile_phase_lexical_policy_id_wins_over_noncanonical_service_constraints():
    value = _config(); profile = value["review_slots"][0]["profile"]
    profile["service_constraint_ids"] = ["z", "a"]; profile["rereview_policy_id"] = ""
    assert _resolve(value).reason is Reason.CONFIG_GRAMMAR_INVALID


def test_profile_phase_lexical_policy_id_wins_over_noncanonical_provider_metadata():
    value = _config(); profile = value["review_slots"][0]["profile"]
    profile["provider_metadata_requirement_ids"] = ["z", "a"]; profile["disclosure_policy_id"] = ""
    assert _resolve(value).reason is Reason.CONFIG_GRAMMAR_INVALID


@pytest.mark.parametrize("field", ["service_constraint_ids", "provider_metadata_requirement_ids"])
def test_profile_phase_lexical_collection_failure_precedes_later_policy_id(field):
    value = _config(); profile = value["review_slots"][0]["profile"]
    profile[field] = [""]; profile["rereview_policy_id"] = ""
    assert _resolve(value).reason is Reason.CONFIG_GRAMMAR_INVALID


@pytest.mark.parametrize("field", ["service_constraint_ids", "provider_metadata_requirement_ids"])
def test_profile_phase_canonical_collection_failure_follows_all_lexical_fields(field):
    value = _config(); value["review_slots"][0]["profile"][field] = ["z", "a"]
    assert _resolve(value).reason is Reason.NONCANONICAL_CONFIG


@pytest.mark.parametrize("field", ["service_constraint_ids", "provider_metadata_requirement_ids"])
def test_profile_phase_bounds_follow_canonical_validation(field):
    value = _config(); profile = value["review_slots"][0]["profile"]
    prefix = "service" if field == "service_constraint_ids" else "metadata"
    profile[field] = [f"{prefix}-{index:03}" for index in range(65)]
    assert _resolve(value).reason is Reason.RESOLUTION_LIMIT_EXCEEDED
    profile[field] = list(reversed(profile[field]))
    assert _resolve(value).reason is Reason.NONCANONICAL_CONFIG


def test_profile_frozen_precedence_rereview_is_checked_before_disclosure(monkeypatch):
    value = _config(); profile = value["review_slots"][0]["profile"]
    profile["rereview_policy_id"] = ""; profile["disclosure_policy_id"] = ""
    original = semantic_config.ImmutableConfigId
    observed = []

    def ordered_identity(item):
        observed.append(item)
        return original(item)

    monkeypatch.setattr(semantic_config, "ImmutableConfigId", ordered_identity)
    assert _resolve(value).reason is Reason.CONFIG_GRAMMAR_INVALID
    assert "" in observed and observed.count("") == 1


def test_raw_limits_are_exact_decimals_and_invalid_values_fail():
    value = _config(); value["review_slots"][0]["profile"]["raw_limits"] = {"max_bytes": 1024.5, "max_depth": 8}
    assert _resolve(value).reason is Reason.CONFIG_GRAMMAR_INVALID
    value = _config(); value["review_slots"][0]["profile"]["raw_limits"] = {"max_bytes": 0, "max_depth": 8}
    assert _resolve(value).reason is Reason.CONFIG_GRAMMAR_INVALID


def test_bounds_and_composition_exactness():
    value = _config(required_trusted_context_ids=[f"context-{i:03}" for i in range(MAX_REQUIRED_TRUSTED_CONTEXTS_PER_SEMANTIC_EVALUATOR)])
    assert _resolve(value).status is Status.RESOLVED
    value["required_trusted_context_ids"].append("context-999")
    assert _resolve(value).reason is Reason.RESOLUTION_LIMIT_EXCEEDED
    bad = _config(); bad["composition"]["required_slot_ids"] = []
    assert _resolve(bad).reason is Reason.CONFIG_GRAMMAR_INVALID


def test_slot_and_profile_collection_bounds_and_canonical_order():
    value = _config()
    profile = value["review_slots"][0]["profile"]
    profile["service_constraint_ids"] = [f"service-{i:03}" for i in range(MAX_REVIEWER_SERVICE_CONSTRAINTS_PER_PROFILE)]
    profile["provider_metadata_requirement_ids"] = [f"metadata-{i:03}" for i in range(MAX_PROVIDER_METADATA_REQUIREMENTS_PER_PROFILE)]
    assert _resolve(value).status is Status.RESOLVED
    profile["service_constraint_ids"].append("service-999")
    assert _resolve(value).reason is Reason.RESOLUTION_LIMIT_EXCEEDED
    value = _config(); profile = value["review_slots"][0]["profile"]
    profile["service_constraint_ids"] = ["b", "a"]
    assert _resolve(value).reason is Reason.NONCANONICAL_CONFIG
    profile["service_constraint_ids"] = []
    profile["provider_metadata_requirement_ids"] = ["b", "a"]
    assert _resolve(value).reason is Reason.NONCANONICAL_CONFIG


def test_exactly_sixteen_slots_resolve_and_seventeen_are_limited():
    value = _config()
    prototype = value["review_slots"][0]
    slots = []
    for index in range(MAX_REVIEW_SLOTS_PER_SEMANTIC_EVALUATOR):
        slot = json.loads(json.dumps(prototype))
        slot["slot_id"] = f"slot-{index:02}"
        slots.append(slot)
    value["review_slots"] = slots
    value["composition"]["mode"] = "ALL_REQUIRED_INVOCATIONS"
    value["composition"]["required_slot_ids"] = [slot["slot_id"] for slot in slots]
    assert _resolve(value).status is Status.RESOLVED
    extra = json.loads(json.dumps(prototype)); extra["slot_id"] = "slot-99"
    value["review_slots"].append(extra)
    value["composition"]["required_slot_ids"].append("slot-99")
    assert _resolve(value).reason is Reason.RESOLUTION_LIMIT_EXCEEDED


def test_basic_prerequisites_must_be_canonical_and_match_config():
    raw = _raw(_config())
    malformed = _basic(raw, prerequisites=(TaskCapability.MERGE, TaskCapability.MERGE))
    assert resolve_semantic_evaluator_config(malformed, raw).reason is Reason.BASIC_RESOLUTION_NONCANONICAL
    basic = _basic(raw, prerequisites=(TaskCapability.MERGE,))
    assert resolve_semantic_evaluator_config(basic, raw).reason is Reason.BASIC_RESOLUTION_MISMATCH


def test_operational_prerequisite_lexical_duplicate_and_order_rules():
    invalid = _config(operational_prerequisites=["not-a-capability"])
    assert _resolve(invalid).reason is Reason.CONFIG_GRAMMAR_INVALID
    duplicate = _config(operational_prerequisites=[TaskCapability.IMPLEMENTATION.value, TaskCapability.IMPLEMENTATION.value])
    assert _resolve(duplicate).reason is Reason.NONCANONICAL_CONFIG
    values = sorted((TaskCapability.IMPLEMENTATION.value, TaskCapability.MERGE.value), reverse=True)
    unordered = _config(operational_prerequisites=values)
    assert _resolve(unordered, prerequisites=tuple(TaskCapability(item) for item in values)).reason is Reason.BASIC_RESOLUTION_NONCANONICAL


def test_slot_order_duplicates_and_context_duplicates_are_separate_failures():
    value = _config()
    second = json.loads(json.dumps(value["review_slots"][0])); second["slot_id"] = "slot-0"
    value["review_slots"].append(second); value["composition"]["mode"] = "ALL_REQUIRED_INVOCATIONS"
    value["composition"]["required_slot_ids"] = ["slot-a", "slot-0"]
    assert _resolve(value).reason is Reason.NONCANONICAL_CONFIG
    contexts = _config(required_trusted_context_ids=["same", "same"])
    assert _resolve(contexts).reason is Reason.NONCANONICAL_CONFIG


def test_identity_has_frozen_preimage_and_moves_with_configured_independence():
    raw = _raw(_config()); basic = _basic(raw)
    resolved = resolve_semantic_evaluator_config(basic, raw).resolution
    assert resolved is not None
    slot = resolved.review_slots[0]; profile = slot.profile
    expected = SemanticEvaluatorResolutionId(contract_json_value_digest((
        "autodev.semantic-evaluator-resolution/v1", basic.binding.policy_epoch_identity.manifest_id.raw_sha256.value,
        basic.binding.config_identity.config_id.value, basic.binding.config_identity.resource_id.value,
        basic.binding.config_identity.resource_sha256.value, "semantic", True, True, (),
        ((slot.slot_id.value, slot.independence_binding.value, profile.profile_id.value, profile.config_id.value,
          profile.service_id.value, profile.verdict_schema_id.value, Decimal(profile.raw_limits.max_bytes),
          Decimal(profile.raw_limits.max_depth), profile.tool_mode.value, (), (), profile.rereview_policy_id.value,
          profile.disclosure_policy_id.value),), resolved.composition_rule.composition_rule_id.value,
        resolved.composition_rule.mode.value, (slot.slot_id.value,), resolved.partition_rule.value, (),
        resolved.target_context_requirement.value, resolved.pr_context_requirement.value,
    )))
    assert resolved.resolution_id == expected
    moved = _config(); moved["review_slots"][0]["independence_binding_sha256"] = "c" * 64
    assert _resolve(moved).resolution.resolution_id != resolved.resolution_id


@pytest.mark.parametrize("movement", [
    "epoch", "config_id", "resource_id", "resource_digest", "prerequisites", "slot_id",
    "raw_limits", "service_constraints", "metadata", "composition", "contexts", "target", "pr",
])
def test_every_supported_identity_bearing_fact_moves_resolution_id(movement):
    value = _config(); raw = _raw(value); baseline = resolve_semantic_evaluator_config(_basic(raw), raw).resolution
    assert baseline is not None
    kwargs = {}
    if movement == "epoch":
        kwargs["epoch_char"] = "c"
    elif movement == "config_id":
        kwargs["config_id"] = "config-b"
    elif movement == "resource_id":
        kwargs["resource_id"] = "resource-b"
    elif movement == "resource_digest":
        value["review_slots"][0]["profile"]["profile_id"] = "profile-digest-moved"
    elif movement == "prerequisites":
        capability = TaskCapability.IMPLEMENTATION
        value["operational_prerequisites"] = [capability.value]
        kwargs["prerequisites"] = (capability,)
    elif movement == "slot_id":
        value["review_slots"][0]["slot_id"] = "slot-b"; value["composition"]["required_slot_ids"] = ["slot-b"]
    elif movement == "raw_limits":
        value["review_slots"][0]["profile"]["raw_limits"]["max_bytes"] = 2048
    elif movement == "service_constraints":
        value["review_slots"][0]["profile"]["service_constraint_ids"] = ["service-constraint"]
    elif movement == "metadata":
        value["review_slots"][0]["profile"]["provider_metadata_requirement_ids"] = ["metadata-constraint"]
    elif movement == "composition":
        value["composition"]["composition_rule_id"] = "composition-b"; value["composition"]["mode"] = "ALL_REQUIRED_INVOCATIONS"
    elif movement == "contexts":
        value["required_trusted_context_ids"] = ["context-a"]
    elif movement == "target":
        value["target_context_requirement"] = "REQUIRED"
    elif movement == "pr":
        value["pr_context_requirement"] = "REQUIRED"
    raw = _raw(value)
    moved = resolve_semantic_evaluator_config(_basic(raw, **kwargs), raw).resolution
    assert moved is not None and moved.resolution_id != baseline.resolution_id


@pytest.mark.parametrize("change", [
    "service_id", "verdict_schema_id", "rereview_policy_id", "disclosure_policy_id",
])
def test_profile_selector_movement_changes_identity_without_downstream_authority(change):
    baseline = _resolve().resolution
    value = _config(); value["review_slots"][0]["profile"][change] += "-moved"
    moved = _resolve(value).resolution
    assert baseline is not None and moved is not None and moved.resolution_id != baseline.resolution_id
    assert not hasattr(moved, "disclosure_authorization")


@pytest.mark.parametrize("field", ["target_context_requirement", "pr_context_requirement"])
def test_context_requirements_accept_only_frozen_domain(field):
    valid = _config(**{field: "REQUIRED"})
    assert _resolve(valid).status is Status.RESOLVED
    invalid = _config(**{field: "OPTIONAL"})
    assert _resolve(invalid).reason is Reason.CONFIG_GRAMMAR_INVALID


def test_exact_verified_parse_failure_and_depth_provenance():
    raw = b"{"  # The basic identity binds these exact invalid bytes.
    result = resolve_semantic_evaluator_config(_basic(raw), raw)
    assert result.status is Status.DENIED and result.reason is Reason.CONFIG_RESOURCE_INVALID
    assert result.parse_failure_code is not None and result.resource_failure_code is None
    nested = b"[" * 17 + b"0" + b"]" * 17
    depth = resolve_semantic_evaluator_config(_basic(nested), nested)
    assert depth.reason is Reason.CONFIG_RESOURCE_INVALID and depth.parse_failure_code.name == "DEPTH_LIMIT_EXCEEDED"


def test_resource_digest_is_the_current_g1_selection_not_a_caller_resource_claim():
    raw = _raw(_config())
    selected = _basic(raw, resource_id="selected-resource")
    resolved = resolve_semantic_evaluator_config(selected, raw)
    assert resolved.status is Status.RESOLVED
    other = _basic(raw, resource_id="other-resource")
    assert resolve_semantic_evaluator_config(other, raw).resolution.config_identity.resource_id.value == "other-resource"
    # Each invocation receives only the opaque G1 resolution and bytes; there is
    # no resource-id/profile/slot authority parameter to substitute.
    assert resolve_semantic_evaluator_config.__code__.co_argcount == 2


def test_resolution_is_non_bearer_and_cannot_construct_named_g5_authorities():
    result = _resolve()
    assert result.resolution is not None
    profile = result.resolution.review_slots[0].profile
    with pytest.raises(TypeError):
        TrustedSemanticEvaluatorResolution()
    # The selected nominal IDs cannot substitute for the caller-unmintable G5
    # authority products: each must originate at its own trusted boundary.
    with pytest.raises(TypeError):
        TrustedVerdictSchemaContext(profile.verdict_schema_id, "1")
    with pytest.raises(TypeError):
        TrustedReviewProfileAdmissionContext(profile.config_id)
    with pytest.raises(TypeError):
        TrustedDisclosureAuthorizationBinding(profile.disclosure_policy_id)
    with pytest.raises(TypeError):
        TrustedReReviewAuthorization(profile.rereview_policy_id)
    with pytest.raises(TypeError):
        TrustedReviewInvocationRecord(result.resolution.review_slots[0])


def test_independence_binding_is_configured_identity_not_invocation_authority():
    resolution = _resolve().resolution
    assert resolution is not None
    slot = resolution.review_slots[0]
    assert type(slot.independence_binding) is RawSha256
    # Possession of the configured digest cannot mint trusted invocation
    # provenance or a downstream authorization record.
    with pytest.raises(TypeError):
        TrustedReviewInvocationRecord(slot.independence_binding)
    with pytest.raises(TypeError):
        TrustedReReviewAuthorization(slot.independence_binding)


def test_semantic_config_size_limit_is_applied_only_after_digest_verification():
    valid = _raw(_config())
    exact = valid + b" " * (SEMANTIC_EVALUATOR_CONFIG_MAX_BYTES - len(valid))
    assert len(exact) == SEMANTIC_EVALUATOR_CONFIG_MAX_BYTES
    assert resolve_semantic_evaluator_config(_basic(exact), exact).status is Status.RESOLVED
    over = exact + b" "
    assert len(over) == SEMANTIC_EVALUATOR_CONFIG_MAX_BYTES + 1
    result = resolve_semantic_evaluator_config(_basic(over), over)
    assert (result.status, result.reason) == (Status.DENIED, Reason.RESOLUTION_LIMIT_EXCEEDED)
