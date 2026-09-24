"""Validated test-only builders for otherwise closed trusted value records.

These helpers intentionally use ``object.__new__`` only inside the test tree;
production trusted modules do not expose fixture authority keys or bypass APIs.
"""

from autodev_control.trusted.authorization import (
    AuthorizationPolicyContext, AuthenticatedHumanAuthorizationApproval,
    ContractAuthorityCeiling, DirectIssuerAuthorityEnvelope,
    OrdinaryRootProtectionContext, OrdinaryRootProtectionState,
    AuthorizationOperationalConstraints, G3_MAX_CAPABILITIES,
    G3_MAX_DELEGATION_DEPTH, G3_MAX_PROFILE_IDS, _unique_exact,
)
from autodev_control.trusted.scope import (
    AuthenticationEventId, AuthorizationId, CanonicalBranchRef, ContractId,
    GitHubRepositoryId, HumanPrincipalId, MutationScope, RiskTier,
    ServicePrincipalId, TargetRegistrationId, TaskCapability, TaskId,
)
from autodev_control.trusted.identity import ImmutableConfigId, RawSha256
from autodev_control.trusted.manifest import PolicyEpochIdentity
from autodev_control.trusted.authorization import RiskRelation
from autodev_control.trusted.target_registration import (
    AuthenticatedTargetAdminApproval, TargetRegistrationPolicyContext,
    TargetRegistrationRootImpact, TargetRegistrationRootImpactAssessment,
    G3_MAX_PROTECTED_REFS, G3_MAX_PROFILE_IDS as TARGET_G3_MAX_PROFILE_IDS,
    _unique_exact as _target_unique_exact,
)


def _test_record(cls: type, **fields: object):
    value = object.__new__(cls)
    for name, item in fields.items():
        object.__setattr__(value, name, item)
    return value


def _require_fields(fields: dict[str, object], schema: dict[str, object]) -> None:
    if set(fields) != set(schema):
        raise TypeError("wrong authority context fields")
    for name, expected in schema.items():
        accepted = expected if type(expected) is tuple else (expected,)
        if type(fields[name]) not in accepted:
            raise TypeError(f"{name} has wrong exact type")


def _validated_policy_fields(fields: dict[str, object], *, issuer: bool) -> None:
    common: dict[str, object] = {
        "policy_epoch_identity": PolicyEpochIdentity,
        "target_registration_id": TargetRegistrationId,
        "task_id": TaskId, "contract_id": ContractId,
        "contract_raw_sha256": RawSha256,
        "maximum_capabilities": tuple,
        "maximum_mutation_scope": MutationScope,
        "maximum_operational_constraints": AuthorizationOperationalConstraints,
        "maximum_authorization_risk_ceiling": RiskTier,
        "maximum_delegation_depth": int,
        "maximum_delegable_capabilities": tuple,
        "maximum_delegable_mutation_scope": MutationScope,
        "maximum_delegable_operational_constraints": AuthorizationOperationalConstraints,
        "maximum_delegation_risk_ceiling": (RiskTier, type(None)),
    }
    if issuer:
        common["human_principal_id"] = HumanPrincipalId
    else:
        common.update({
            "mandatory_forbidden_mutation_scope": MutationScope,
            "effective_authoritative_risk": RiskTier,
            "risk_relation": RiskRelation,
        })
    _require_fields(fields, common)
    depth = fields["maximum_delegation_depth"]
    if type(depth) is not int or not 0 <= depth <= G3_MAX_DELEGATION_DEPTH:
        raise ValueError("invalid delegation depth")
    if depth == 0 and (fields["maximum_delegable_capabilities"]
                       or fields["maximum_delegation_risk_ceiling"] is not None):
        raise ValueError("zero-depth delegation ceiling must be empty")
    if depth > 0 and type(fields["maximum_delegation_risk_ceiling"]) is not RiskTier:
        raise ValueError("positive-depth delegation ceiling requires risk ceiling")


def _authenticated_human_approval_for_test(**fields: object) -> AuthenticatedHumanAuthorizationApproval:
    _require_fields(fields, {
        "human_principal_id": HumanPrincipalId,
        "authentication_event_id": AuthenticationEventId,
        "proposal_raw_sha256": RawSha256,
        "policy_epoch_identity": PolicyEpochIdentity,
    })
    return _test_record(AuthenticatedHumanAuthorizationApproval, **fields)


def _contract_authority_ceiling_for_test(**fields: object) -> ContractAuthorityCeiling:
    _require_fields(fields, {
        "task_id": TaskId, "contract_id": ContractId,
        "contract_raw_sha256": RawSha256,
        "target_registration_id": TargetRegistrationId,
        "requested_capabilities": tuple,
        "allowed_mutation_scope": MutationScope,
        "prohibited_mutation_scope": MutationScope,
        "risk_floor": RiskTier,
        "integration_ref": (CanonicalBranchRef, type(None)),
        "controlled_runtime_profile_ids": tuple,
        "repair_max_attempts": int, "delegation_max_depth": int,
        "delegable_capabilities": tuple,
        "delegation_risk_ceiling": (RiskTier, type(None)),
    })
    _unique_exact(fields["requested_capabilities"], TaskCapability, G3_MAX_CAPABILITIES)
    _unique_exact(fields["controlled_runtime_profile_ids"], ImmutableConfigId, G3_MAX_PROFILE_IDS)
    _unique_exact(fields["delegable_capabilities"], TaskCapability, G3_MAX_CAPABILITIES)
    if not fields["requested_capabilities"]:
        raise ValueError("requested capabilities required")
    caps = fields["requested_capabilities"]
    if (TaskCapability.MERGE in caps) != (fields["integration_ref"] is not None):
        raise ValueError("merge capability and integration ref disagree")
    if (TaskCapability.CONTROLLED_RUNTIME in caps) != bool(fields["controlled_runtime_profile_ids"]):
        raise ValueError("runtime capability and profiles disagree")
    attempts, depth = fields["repair_max_attempts"], fields["delegation_max_depth"]
    if type(attempts) is not int or attempts < 0 or ((TaskCapability.REPAIR in caps) != (attempts >= 1)):
        raise ValueError("repair capability and maximum disagree")
    if type(depth) is not int or not 0 <= depth <= G3_MAX_DELEGATION_DEPTH:
        raise ValueError("invalid delegation depth")
    if depth == 0 and (fields["delegable_capabilities"] or fields["delegation_risk_ceiling"] is not None):
        raise ValueError("zero-depth contract delegation must be empty")
    if depth > 0 and (not fields["delegable_capabilities"]
                      or type(fields["delegation_risk_ceiling"]) is not RiskTier):
        raise ValueError("positive-depth contract delegation invalid")
    return _test_record(ContractAuthorityCeiling, **fields)


def _authorization_policy_context_for_test(**fields: object) -> AuthorizationPolicyContext:
    _validated_policy_fields(fields, issuer=False)
    _unique_exact(fields["maximum_capabilities"], TaskCapability, G3_MAX_CAPABILITIES)
    _unique_exact(fields["maximum_delegable_capabilities"], TaskCapability, G3_MAX_CAPABILITIES)
    return _test_record(AuthorizationPolicyContext, **fields)


def _direct_issuer_envelope_for_test(**fields: object) -> DirectIssuerAuthorityEnvelope:
    _validated_policy_fields(fields, issuer=True)
    _unique_exact(fields["maximum_capabilities"], TaskCapability, G3_MAX_CAPABILITIES)
    _unique_exact(fields["maximum_delegable_capabilities"], TaskCapability, G3_MAX_CAPABILITIES)
    return _test_record(DirectIssuerAuthorityEnvelope, **fields)


def _ordinary_root_context_for_test(**fields: object) -> OrdinaryRootProtectionContext:
    _require_fields(fields, {
        "policy_epoch_identity": PolicyEpochIdentity,
        "repository_id": GitHubRepositoryId,
        "state": OrdinaryRootProtectionState,
        "root_protected_mutation_scope": (MutationScope, type(None)),
    })
    state, scope = fields["state"], fields["root_protected_mutation_scope"]
    if ((state is OrdinaryRootProtectionState.NO_ROOT_PROTECTED_MATERIAL and scope is not None)
            or (state is OrdinaryRootProtectionState.ROOT_PROTECTED_MUTATION_SCOPE
                and type(scope) is not MutationScope)):
        raise ValueError("invalid root context")
    return _test_record(OrdinaryRootProtectionContext, **fields)


def _authenticated_target_admin_approval_for_test(**fields: object) -> AuthenticatedTargetAdminApproval:
    _require_fields(fields, {
        "human_principal_id": HumanPrincipalId,
        "authentication_event_id": AuthenticationEventId,
        "target_registration_id": TargetRegistrationId,
        "policy_epoch_identity": PolicyEpochIdentity,
    })
    return _test_record(AuthenticatedTargetAdminApproval, **fields)


def _target_registration_root_assessment_for_test(**fields: object) -> TargetRegistrationRootImpactAssessment:
    _require_fields(fields, {
        "target_registration_id": TargetRegistrationId,
        "repository_id": GitHubRepositoryId,
        "policy_epoch_identity": PolicyEpochIdentity,
        "root_impact": TargetRegistrationRootImpact,
    })
    return _test_record(TargetRegistrationRootImpactAssessment, **fields)


def _target_registration_policy_context_for_test(**fields: object) -> TargetRegistrationPolicyContext:
    scalar_fields = {
        "policy_epoch_identity": PolicyEpochIdentity,
        "target_registration_id": TargetRegistrationId,
        "repository_id": GitHubRepositoryId,
        "maximum_ordinary_allowed_scope": MutationScope,
        "maximum_target_risk_ceiling": RiskTier,
        "risk_relation": RiskRelation,
    }
    collection_fields = {
        "permitted_admin_principals", "maximum_allowed_task_capabilities",
        "permitted_target_publication_service_identities", "permitted_merge_service_identities",
        "permitted_publication_profile_ids", "permitted_merge_profile_ids",
        "permitted_validation_profile_ids", "permitted_controlled_runtime_profile_ids",
        "permitted_event_state_profile_ids", "permitted_adapter_config_ids",
    }
    if set(fields) != set(scalar_fields) | collection_fields:
        raise TypeError("wrong target policy context fields")
    _require_fields({name: fields[name] for name in scalar_fields}, scalar_fields)
    for name, kind, maximum in (
        ("permitted_admin_principals", HumanPrincipalId, TARGET_G3_MAX_PROFILE_IDS),
        ("maximum_allowed_task_capabilities", TaskCapability, G3_MAX_CAPABILITIES),
        ("permitted_target_publication_service_identities", ServicePrincipalId, TARGET_G3_MAX_PROFILE_IDS),
        ("permitted_merge_service_identities", ServicePrincipalId, TARGET_G3_MAX_PROFILE_IDS),
        ("permitted_publication_profile_ids", ImmutableConfigId, TARGET_G3_MAX_PROFILE_IDS),
        ("permitted_merge_profile_ids", ImmutableConfigId, TARGET_G3_MAX_PROFILE_IDS),
        ("permitted_validation_profile_ids", ImmutableConfigId, TARGET_G3_MAX_PROFILE_IDS),
        ("permitted_controlled_runtime_profile_ids", ImmutableConfigId, TARGET_G3_MAX_PROFILE_IDS),
        ("permitted_event_state_profile_ids", ImmutableConfigId, TARGET_G3_MAX_PROFILE_IDS),
        ("permitted_adapter_config_ids", ImmutableConfigId, TARGET_G3_MAX_PROFILE_IDS),
    ):
        _target_unique_exact(fields[name], kind, maximum)
    return _test_record(TargetRegistrationPolicyContext, **fields)
