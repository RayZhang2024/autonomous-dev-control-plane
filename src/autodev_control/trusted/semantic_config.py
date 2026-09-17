"""Pure, bounded derivation of a semantic evaluator declaration from G1+G2 truth.

This module deliberately has no byte source, registry, persistence, or downstream
review/evidence authority.  The opaque G1 result selects the current config; the
supplied bytes can establish content only after matching that selection's digest.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from enum import Enum
from types import MappingProxyType

from .contract import (
    EvaluatorMechanism, ResolvedTrustedConfigBinding, TrustedConfigIdentity,
    TrustedEvaluatorConfigResolution, contract_json_value_digest,
)
from .errors import ParseFailure, ParseFailureCode, ResourceFailure, ResourceFailureCode
from .identity import ImmutableConfigId, RawSha256, SemanticEvaluatorResolutionId
from .manifest import PolicyEpochIdentity
from .parsing import ABSOLUTE_MAX_BYTES, ABSOLUTE_MAX_DEPTH, ParseLimits, parse_trusted_json
from .resources import RootManagedResourceKind, RootManagedResourceRef, verify_inline_resource_bytes
from .review import (
    CompositionMode, CompositionRuleId, ProviderMetadataRequirementId, ReviewPartitionRule,
    ReviewerProfileBinding, ReviewerProfileId, ReviewerServiceConstraintId, ReviewerServiceId,
    ReviewSlot, ReviewSlotId, SemanticReviewCompositionRule, ToolMode, TrustedContextId,
)
from .scope import TaskCapability


SEMANTIC_EVALUATOR_CONFIG_MAX_BYTES = 256 * 1024
SEMANTIC_EVALUATOR_CONFIG_MAX_DEPTH = 16
MAX_REVIEW_SLOTS_PER_SEMANTIC_EVALUATOR = 16
MAX_REQUIRED_TRUSTED_CONTEXTS_PER_SEMANTIC_EVALUATOR = 256
MAX_REVIEWER_SERVICE_CONSTRAINTS_PER_PROFILE = 64
MAX_PROVIDER_METADATA_REQUIREMENTS_PER_PROFILE = 64

_TOP_FIELDS = (
    "format", "mechanism", "operational_prerequisites", "review_slots", "composition",
    "partition_rule", "required_trusted_context_ids", "target_context_requirement",
    "pr_context_requirement",
)
_SLOT_FIELDS = ("slot_id", "independence_binding_sha256", "profile")
_PROFILE_FIELDS = (
    "profile_id", "service_id", "verdict_schema_id", "raw_limits", "tool_mode",
    "service_constraint_ids", "provider_metadata_requirement_ids", "rereview_policy_id",
    "disclosure_policy_id",
)
_RAW_LIMIT_FIELDS = ("max_bytes", "max_depth")
_COMPOSITION_FIELDS = ("composition_rule_id", "mode", "required_slot_ids")
_SUCCESS_KEY = object()


class SemanticEvaluatorConfigResolutionStatus(Enum):
    RESOLVED = "RESOLVED"
    INDETERMINATE = "INDETERMINATE"
    DENIED = "DENIED"


class SemanticEvaluatorConfigResolutionReason(Enum):
    RESOLVED = "RESOLVED"
    CONFIG_BYTES_UNAVAILABLE = "CONFIG_BYTES_UNAVAILABLE"
    CONFIG_BYTES_UNVERIFIABLE = "CONFIG_BYTES_UNVERIFIABLE"
    CONFIG_BYTES_MISMATCH = "CONFIG_BYTES_MISMATCH"
    BASIC_RESOLUTION_NOT_SEMANTIC = "BASIC_RESOLUTION_NOT_SEMANTIC"
    BASIC_RESOLUTION_NOT_USABLE = "BASIC_RESOLUTION_NOT_USABLE"
    BASIC_RESOLUTION_NONCANONICAL = "BASIC_RESOLUTION_NONCANONICAL"
    CONFIG_RESOURCE_INVALID = "CONFIG_RESOURCE_INVALID"
    UNSUPPORTED_CONFIG_FORMAT = "UNSUPPORTED_CONFIG_FORMAT"
    CONFIG_GRAMMAR_INVALID = "CONFIG_GRAMMAR_INVALID"
    BASIC_RESOLUTION_MISMATCH = "BASIC_RESOLUTION_MISMATCH"
    NONCANONICAL_CONFIG = "NONCANONICAL_CONFIG"
    UNSUPPORTED_PARTITION_RULE = "UNSUPPORTED_PARTITION_RULE"
    UNSUPPORTED_TOOL_MODE = "UNSUPPORTED_TOOL_MODE"
    RESOLUTION_LIMIT_EXCEEDED = "RESOLUTION_LIMIT_EXCEEDED"


class SemanticReviewContextRequirement(Enum):
    NOT_APPLICABLE = "NOT_APPLICABLE"
    REQUIRED = "REQUIRED"


@dataclass(frozen=True, slots=True, init=False)
class TrustedSemanticEvaluatorResolution:
    policy_epoch_identity: object
    config_identity: object
    mechanism: EvaluatorMechanism
    parameters_valid: bool
    applicable: bool
    operational_prerequisites: tuple[TaskCapability, ...]
    review_slots: tuple[ReviewSlot, ...]
    composition_rule: SemanticReviewCompositionRule
    partition_rule: ReviewPartitionRule
    required_trusted_context_ids: tuple[TrustedContextId, ...]
    target_context_requirement: SemanticReviewContextRequirement
    pr_context_requirement: SemanticReviewContextRequirement
    resolution_id: SemanticEvaluatorResolutionId

    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("semantic evaluator resolution must come from the trusted resolver")

    @classmethod
    def _from_validated(cls, key: object, **fields: object) -> "TrustedSemanticEvaluatorResolution":
        if key is not _SUCCESS_KEY:
            raise TypeError("internal validated construction only")
        value = object.__new__(cls)
        for name, field in fields.items():
            object.__setattr__(value, name, field)
        return value


@dataclass(frozen=True, slots=True)
class SemanticEvaluatorConfigResolutionResult:
    status: SemanticEvaluatorConfigResolutionStatus
    reason: SemanticEvaluatorConfigResolutionReason
    resolution: TrustedSemanticEvaluatorResolution | None = None
    resource_failure_code: ResourceFailureCode | None = None
    parse_failure_code: ParseFailureCode | None = None

    def __post_init__(self) -> None:
        if type(self.status) is not SemanticEvaluatorConfigResolutionStatus or type(self.reason) is not SemanticEvaluatorConfigResolutionReason:
            raise TypeError("invalid semantic resolution outcome")
        if self.status is SemanticEvaluatorConfigResolutionStatus.RESOLVED:
            if type(self.resolution) is not TrustedSemanticEvaluatorResolution or self.reason is not SemanticEvaluatorConfigResolutionReason.RESOLVED or self.resource_failure_code is not None or self.parse_failure_code is not None:
                raise ValueError("invalid resolved semantic outcome")
        elif self.resolution is not None or self.reason is SemanticEvaluatorConfigResolutionReason.RESOLVED:
            raise ValueError("failed semantic outcome cannot carry resolution or success reason")
        if self.resource_failure_code is not None and type(self.resource_failure_code) is not ResourceFailureCode:
            raise TypeError("invalid resource provenance")
        if self.parse_failure_code is not None and type(self.parse_failure_code) is not ParseFailureCode:
            raise TypeError("invalid parse provenance")
        if self.resource_failure_code is not None and self.parse_failure_code is not None:
            raise ValueError("outcome cannot have two parse provenances")


def _outcome(status: SemanticEvaluatorConfigResolutionStatus, reason: SemanticEvaluatorConfigResolutionReason, *, resource: ResourceFailureCode | None = None, parse: ParseFailureCode | None = None) -> SemanticEvaluatorConfigResolutionResult:
    return SemanticEvaluatorConfigResolutionResult(status, reason, resource_failure_code=resource, parse_failure_code=parse)


def _fields(value: object, names: tuple[str, ...]) -> bool:
    return type(value) is MappingProxyType and all(name in value for name in names) and all(name in names for name in value)


def _canonical(values: tuple[object, ...]) -> bool:
    return all(values[index - 1].value < values[index].value for index in range(1, len(values)))


def _identity_array(value: object, identity: type) -> tuple[object, ...] | None:
    if type(value) is not tuple:
        return None
    result: list[object] = []
    try:
        for item in value:
            if type(item) is not str:
                return None
            result.append(identity(item))
    except (TypeError, ValueError):
        return None
    return tuple(result)


def _parse_positive_decimal(value: object, maximum: int) -> int | None:
    if type(value) is not Decimal or not value.is_finite() or value != value.to_integral_value() or value < 1 or value > maximum:
        return None
    return int(value)


def _profile(value: object, config_id: ImmutableConfigId) -> tuple[ReviewerProfileBinding | None, SemanticEvaluatorConfigResolutionReason | None]:
    if not _fields(value, _PROFILE_FIELDS):
        return None, SemanticEvaluatorConfigResolutionReason.CONFIG_GRAMMAR_INVALID
    # First apply JSON field types in the frozen profile-field order.  The
    # following value checks deliberately repeat that order; do not coalesce
    # later policy IDs with earlier profile facts.
    if type(value["profile_id"]) is not str:
        return None, SemanticEvaluatorConfigResolutionReason.CONFIG_GRAMMAR_INVALID
    if type(value["service_id"]) is not str:
        return None, SemanticEvaluatorConfigResolutionReason.CONFIG_GRAMMAR_INVALID
    if type(value["verdict_schema_id"]) is not str:
        return None, SemanticEvaluatorConfigResolutionReason.CONFIG_GRAMMAR_INVALID
    if type(value["raw_limits"]) is not MappingProxyType:
        return None, SemanticEvaluatorConfigResolutionReason.CONFIG_GRAMMAR_INVALID
    if type(value["tool_mode"]) is not str:
        return None, SemanticEvaluatorConfigResolutionReason.CONFIG_GRAMMAR_INVALID
    if type(value["service_constraint_ids"]) is not tuple:
        return None, SemanticEvaluatorConfigResolutionReason.CONFIG_GRAMMAR_INVALID
    if type(value["provider_metadata_requirement_ids"]) is not tuple:
        return None, SemanticEvaluatorConfigResolutionReason.CONFIG_GRAMMAR_INVALID
    if type(value["rereview_policy_id"]) is not str:
        return None, SemanticEvaluatorConfigResolutionReason.CONFIG_GRAMMAR_INVALID
    if type(value["disclosure_policy_id"]) is not str:
        return None, SemanticEvaluatorConfigResolutionReason.CONFIG_GRAMMAR_INVALID
    try:
        profile_id = ReviewerProfileId(value["profile_id"])
    except (TypeError, ValueError):
        return None, SemanticEvaluatorConfigResolutionReason.CONFIG_GRAMMAR_INVALID
    try:
        service_id = ReviewerServiceId(value["service_id"])
    except (TypeError, ValueError):
        return None, SemanticEvaluatorConfigResolutionReason.CONFIG_GRAMMAR_INVALID
    try:
        verdict_schema_id = ImmutableConfigId(value["verdict_schema_id"])
    except (TypeError, ValueError):
        return None, SemanticEvaluatorConfigResolutionReason.CONFIG_GRAMMAR_INVALID
    limits = value["raw_limits"]
    if not _fields(limits, _RAW_LIMIT_FIELDS):
        return None, SemanticEvaluatorConfigResolutionReason.CONFIG_GRAMMAR_INVALID
    if type(limits["max_bytes"]) is not Decimal:
        return None, SemanticEvaluatorConfigResolutionReason.CONFIG_GRAMMAR_INVALID
    if type(limits["max_depth"]) is not Decimal:
        return None, SemanticEvaluatorConfigResolutionReason.CONFIG_GRAMMAR_INVALID
    maximum_bytes = _parse_positive_decimal(limits["max_bytes"], ABSOLUTE_MAX_BYTES)
    if maximum_bytes is None:
        return None, SemanticEvaluatorConfigResolutionReason.CONFIG_GRAMMAR_INVALID
    maximum_depth = _parse_positive_decimal(limits["max_depth"], ABSOLUTE_MAX_DEPTH)
    if maximum_depth is None:
        return None, SemanticEvaluatorConfigResolutionReason.CONFIG_GRAMMAR_INVALID
    try:
        tool_mode = ToolMode(value["tool_mode"])
    except ValueError:
        return None, SemanticEvaluatorConfigResolutionReason.CONFIG_GRAMMAR_INVALID
    if tool_mode is not ToolMode.NO_TOOLS:
        return None, SemanticEvaluatorConfigResolutionReason.UNSUPPORTED_TOOL_MODE
    services = _identity_array(value["service_constraint_ids"], ReviewerServiceConstraintId)
    if services is None:
        return None, SemanticEvaluatorConfigResolutionReason.CONFIG_GRAMMAR_INVALID
    metadata = _identity_array(value["provider_metadata_requirement_ids"], ProviderMetadataRequirementId)
    if metadata is None:
        return None, SemanticEvaluatorConfigResolutionReason.CONFIG_GRAMMAR_INVALID
    try:
        rereview_policy_id = ImmutableConfigId(value["rereview_policy_id"])
    except (TypeError, ValueError):
        return None, SemanticEvaluatorConfigResolutionReason.CONFIG_GRAMMAR_INVALID
    try:
        disclosure_policy_id = ImmutableConfigId(value["disclosure_policy_id"])
    except (TypeError, ValueError):
        return None, SemanticEvaluatorConfigResolutionReason.CONFIG_GRAMMAR_INVALID
    # All field lexical/enum/value checks have now passed.  Only now perform
    # the distinct duplicate/canonical phase, in frozen collection order.
    if len(set(services)) != len(services) or not _canonical(services):
        return None, SemanticEvaluatorConfigResolutionReason.NONCANONICAL_CONFIG
    if len(set(metadata)) != len(metadata) or not _canonical(metadata):
        return None, SemanticEvaluatorConfigResolutionReason.NONCANONICAL_CONFIG
    # Bounds are a final cross-field/bounded-work phase, after canonicality.
    if len(services) > MAX_REVIEWER_SERVICE_CONSTRAINTS_PER_PROFILE:
        return None, SemanticEvaluatorConfigResolutionReason.RESOLUTION_LIMIT_EXCEEDED
    if len(metadata) > MAX_PROVIDER_METADATA_REQUIREMENTS_PER_PROFILE:
        return None, SemanticEvaluatorConfigResolutionReason.RESOLUTION_LIMIT_EXCEEDED
    return ReviewerProfileBinding(profile_id, config_id, service_id, verdict_schema_id, ParseLimits(maximum_bytes, maximum_depth), tool_mode, services, metadata, rereview_policy_id, disclosure_policy_id), None


def _slot(value: object, config_id: ImmutableConfigId) -> tuple[ReviewSlot | None, SemanticEvaluatorConfigResolutionReason | None]:
    if not _fields(value, _SLOT_FIELDS) or type(value["slot_id"]) is not str or type(value["independence_binding_sha256"]) is not str:
        return None, SemanticEvaluatorConfigResolutionReason.CONFIG_GRAMMAR_INVALID
    try:
        slot_id = ReviewSlotId(value["slot_id"])
        binding = RawSha256(value["independence_binding_sha256"])
    except (TypeError, ValueError):
        return None, SemanticEvaluatorConfigResolutionReason.CONFIG_GRAMMAR_INVALID
    profile, error = _profile(value["profile"], config_id)
    if error is not None:
        return None, error
    assert profile is not None
    return ReviewSlot(slot_id, profile, binding), None


def _resolution_id(*, basic: TrustedEvaluatorConfigResolution, slots: tuple[ReviewSlot, ...], composition: SemanticReviewCompositionRule, partition: ReviewPartitionRule, contexts: tuple[TrustedContextId, ...], target: SemanticReviewContextRequirement, pr: SemanticReviewContextRequirement) -> SemanticEvaluatorResolutionId:
    flattened = tuple((
        slot.slot_id.value, slot.independence_binding.value, slot.profile.profile_id.value,
        slot.profile.config_id.value, slot.profile.service_id.value, slot.profile.verdict_schema_id.value,
        Decimal(slot.profile.raw_limits.max_bytes), Decimal(slot.profile.raw_limits.max_depth),
        slot.profile.tool_mode.value, tuple(item.value for item in slot.profile.service_constraint_ids),
        tuple(item.value for item in slot.profile.provider_metadata_requirement_ids),
        slot.profile.rereview_policy_id.value, slot.profile.disclosure_policy_id.value,
    ) for slot in slots)
    identity = basic.binding.config_identity
    digest = contract_json_value_digest((
        "autodev.semantic-evaluator-resolution/v1",
        basic.binding.policy_epoch_identity.manifest_id.raw_sha256.value,
        identity.config_id.value, identity.resource_id.value, identity.resource_sha256.value,
        EvaluatorMechanism.SEMANTIC.value, True, True,
        tuple(item.value for item in basic.operational_prerequisites), flattened,
        composition.composition_rule_id.value, composition.mode.value,
        tuple(slot.slot_id.value for slot in composition.required_slots), partition.value,
        tuple(item.value for item in contexts), target.value, pr.value,
    ))
    return SemanticEvaluatorResolutionId(digest)


def resolve_semantic_evaluator_config(basic_resolution: object, raw_config_bytes: object) -> SemanticEvaluatorConfigResolutionResult:
    """Derive one non-bearer config declaration from opaque G1 truth and exact bytes."""
    if type(basic_resolution) is not TrustedEvaluatorConfigResolution:
        return _outcome(SemanticEvaluatorConfigResolutionStatus.DENIED, SemanticEvaluatorConfigResolutionReason.BASIC_RESOLUTION_NOT_USABLE)
    basic = basic_resolution
    if (
        type(basic.binding) is not ResolvedTrustedConfigBinding
        or type(basic.binding.config_identity) is not TrustedConfigIdentity
        or type(basic.binding.policy_epoch_identity) is not PolicyEpochIdentity
        or type(basic.mechanism) is not EvaluatorMechanism
        or type(basic.parameters_valid) is not bool
        or type(basic.applicable) is not bool
    ):
        return _outcome(SemanticEvaluatorConfigResolutionStatus.DENIED, SemanticEvaluatorConfigResolutionReason.BASIC_RESOLUTION_NOT_USABLE)
    if basic.mechanism is not EvaluatorMechanism.SEMANTIC:
        return _outcome(SemanticEvaluatorConfigResolutionStatus.DENIED, SemanticEvaluatorConfigResolutionReason.BASIC_RESOLUTION_NOT_SEMANTIC)
    if basic.parameters_valid is not True or basic.applicable is not True:
        return _outcome(SemanticEvaluatorConfigResolutionStatus.DENIED, SemanticEvaluatorConfigResolutionReason.BASIC_RESOLUTION_NOT_USABLE)
    prerequisites = basic.operational_prerequisites
    if type(prerequisites) is not tuple or any(type(item) is not TaskCapability for item in prerequisites) or len(set(prerequisites)) != len(prerequisites) or not _canonical(prerequisites):
        return _outcome(SemanticEvaluatorConfigResolutionStatus.DENIED, SemanticEvaluatorConfigResolutionReason.BASIC_RESOLUTION_NONCANONICAL)
    if raw_config_bytes is None:
        return _outcome(SemanticEvaluatorConfigResolutionStatus.INDETERMINATE, SemanticEvaluatorConfigResolutionReason.CONFIG_BYTES_UNAVAILABLE)
    if type(raw_config_bytes) is not bytes:
        raise TypeError("raw_config_bytes must be exact bytes or None")
    try:
        identity = basic.binding.config_identity
        expected = RootManagedResourceRef(identity.resource_id, RootManagedResourceKind.TRUSTED_CONFIG, identity.resource_sha256)
    except (AttributeError, TypeError):
        return _outcome(SemanticEvaluatorConfigResolutionStatus.DENIED, SemanticEvaluatorConfigResolutionReason.BASIC_RESOLUTION_NOT_USABLE)
    verified = verify_inline_resource_bytes(expected, raw_config_bytes)
    if type(verified) is ResourceFailure:
        if verified.code is ResourceFailureCode.DIGEST_MISMATCH:
            reason = SemanticEvaluatorConfigResolutionReason.CONFIG_BYTES_MISMATCH
        else:
            reason = SemanticEvaluatorConfigResolutionReason.CONFIG_BYTES_UNVERIFIABLE
        return _outcome(SemanticEvaluatorConfigResolutionStatus.INDETERMINATE, reason, resource=verified.code)
    if len(raw_config_bytes) > SEMANTIC_EVALUATOR_CONFIG_MAX_BYTES:
        return _outcome(SemanticEvaluatorConfigResolutionStatus.DENIED, SemanticEvaluatorConfigResolutionReason.RESOLUTION_LIMIT_EXCEEDED)
    document = parse_trusted_json(raw_config_bytes, ParseLimits(SEMANTIC_EVALUATOR_CONFIG_MAX_BYTES, SEMANTIC_EVALUATOR_CONFIG_MAX_DEPTH))
    if type(document) is ParseFailure:
        return _outcome(SemanticEvaluatorConfigResolutionStatus.DENIED, SemanticEvaluatorConfigResolutionReason.CONFIG_RESOURCE_INVALID, parse=document.code)
    value = document.value
    if not _fields(value, _TOP_FIELDS):
        return _outcome(SemanticEvaluatorConfigResolutionStatus.DENIED, SemanticEvaluatorConfigResolutionReason.CONFIG_GRAMMAR_INVALID)
    if type(value["format"]) is not str or type(value["mechanism"]) is not str or type(value["operational_prerequisites"]) is not tuple or type(value["review_slots"]) is not tuple or type(value["composition"]) is not MappingProxyType or type(value["partition_rule"]) is not str or type(value["required_trusted_context_ids"]) is not tuple or type(value["target_context_requirement"]) is not str or type(value["pr_context_requirement"]) is not str:
        return _outcome(SemanticEvaluatorConfigResolutionStatus.DENIED, SemanticEvaluatorConfigResolutionReason.CONFIG_GRAMMAR_INVALID)
    if value["format"] != "autodev.semantic-evaluator-config/v1":
        return _outcome(SemanticEvaluatorConfigResolutionStatus.DENIED, SemanticEvaluatorConfigResolutionReason.UNSUPPORTED_CONFIG_FORMAT)
    if value["mechanism"] != EvaluatorMechanism.SEMANTIC.value:
        return _outcome(SemanticEvaluatorConfigResolutionStatus.DENIED, SemanticEvaluatorConfigResolutionReason.CONFIG_GRAMMAR_INVALID)
    parsed_prerequisites = _identity_array(value["operational_prerequisites"], TaskCapability)
    if parsed_prerequisites is None:
        return _outcome(SemanticEvaluatorConfigResolutionStatus.DENIED, SemanticEvaluatorConfigResolutionReason.CONFIG_GRAMMAR_INVALID)
    if len(set(parsed_prerequisites)) != len(parsed_prerequisites) or not _canonical(parsed_prerequisites):
        return _outcome(SemanticEvaluatorConfigResolutionStatus.DENIED, SemanticEvaluatorConfigResolutionReason.NONCANONICAL_CONFIG)
    if parsed_prerequisites != prerequisites:
        return _outcome(SemanticEvaluatorConfigResolutionStatus.DENIED, SemanticEvaluatorConfigResolutionReason.BASIC_RESOLUTION_MISMATCH)
    slots: list[ReviewSlot] = []
    for item in value["review_slots"]:
        slot, error = _slot(item, identity.config_id)
        if error is not None:
            return _outcome(SemanticEvaluatorConfigResolutionStatus.DENIED, error)
        assert slot is not None
        slots.append(slot)
    slot_tuple = tuple(slots)
    if len({slot.slot_id for slot in slot_tuple}) != len(slot_tuple) or not _canonical(tuple(slot.slot_id for slot in slot_tuple)):
        return _outcome(SemanticEvaluatorConfigResolutionStatus.DENIED, SemanticEvaluatorConfigResolutionReason.NONCANONICAL_CONFIG)
    if not slot_tuple:
        return _outcome(SemanticEvaluatorConfigResolutionStatus.DENIED, SemanticEvaluatorConfigResolutionReason.CONFIG_GRAMMAR_INVALID)
    if len(slot_tuple) > MAX_REVIEW_SLOTS_PER_SEMANTIC_EVALUATOR:
        return _outcome(SemanticEvaluatorConfigResolutionStatus.DENIED, SemanticEvaluatorConfigResolutionReason.RESOLUTION_LIMIT_EXCEEDED)
    composition_value = value["composition"]
    if not _fields(composition_value, _COMPOSITION_FIELDS) or type(composition_value["composition_rule_id"]) is not str or type(composition_value["mode"]) is not str or type(composition_value["required_slot_ids"]) is not tuple:
        return _outcome(SemanticEvaluatorConfigResolutionStatus.DENIED, SemanticEvaluatorConfigResolutionReason.CONFIG_GRAMMAR_INVALID)
    required_ids = _identity_array(composition_value["required_slot_ids"], ReviewSlotId)
    if required_ids is None:
        return _outcome(SemanticEvaluatorConfigResolutionStatus.DENIED, SemanticEvaluatorConfigResolutionReason.CONFIG_GRAMMAR_INVALID)
    try:
        composition = SemanticReviewCompositionRule(CompositionRuleId(composition_value["composition_rule_id"]), CompositionMode(composition_value["mode"]), slot_tuple)
    except (TypeError, ValueError):
        return _outcome(SemanticEvaluatorConfigResolutionStatus.DENIED, SemanticEvaluatorConfigResolutionReason.CONFIG_GRAMMAR_INVALID)
    if required_ids != tuple(slot.slot_id for slot in slot_tuple):
        return _outcome(SemanticEvaluatorConfigResolutionStatus.DENIED, SemanticEvaluatorConfigResolutionReason.CONFIG_GRAMMAR_INVALID)
    try:
        partition = ReviewPartitionRule(value["partition_rule"])
    except ValueError:
        return _outcome(SemanticEvaluatorConfigResolutionStatus.DENIED, SemanticEvaluatorConfigResolutionReason.UNSUPPORTED_PARTITION_RULE)
    contexts = _identity_array(value["required_trusted_context_ids"], TrustedContextId)
    if contexts is None:
        return _outcome(SemanticEvaluatorConfigResolutionStatus.DENIED, SemanticEvaluatorConfigResolutionReason.CONFIG_GRAMMAR_INVALID)
    if len(set(contexts)) != len(contexts) or not _canonical(contexts):
        return _outcome(SemanticEvaluatorConfigResolutionStatus.DENIED, SemanticEvaluatorConfigResolutionReason.NONCANONICAL_CONFIG)
    if len(contexts) > MAX_REQUIRED_TRUSTED_CONTEXTS_PER_SEMANTIC_EVALUATOR:
        return _outcome(SemanticEvaluatorConfigResolutionStatus.DENIED, SemanticEvaluatorConfigResolutionReason.RESOLUTION_LIMIT_EXCEEDED)
    try:
        target = SemanticReviewContextRequirement(value["target_context_requirement"])
        pr = SemanticReviewContextRequirement(value["pr_context_requirement"])
    except ValueError:
        return _outcome(SemanticEvaluatorConfigResolutionStatus.DENIED, SemanticEvaluatorConfigResolutionReason.CONFIG_GRAMMAR_INVALID)
    resolution_id = _resolution_id(basic=basic, slots=slot_tuple, composition=composition, partition=partition, contexts=contexts, target=target, pr=pr)
    resolution = TrustedSemanticEvaluatorResolution._from_validated(
        _SUCCESS_KEY, policy_epoch_identity=basic.binding.policy_epoch_identity,
        config_identity=identity, mechanism=basic.mechanism, parameters_valid=basic.parameters_valid,
        applicable=basic.applicable, operational_prerequisites=prerequisites,
        review_slots=slot_tuple, composition_rule=composition, partition_rule=partition,
        required_trusted_context_ids=contexts, target_context_requirement=target,
        pr_context_requirement=pr, resolution_id=resolution_id,
    )
    return SemanticEvaluatorConfigResolutionResult(SemanticEvaluatorConfigResolutionStatus.RESOLVED, SemanticEvaluatorConfigResolutionReason.RESOLVED, resolution)
