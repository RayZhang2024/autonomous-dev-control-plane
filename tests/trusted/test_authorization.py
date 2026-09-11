import copy
import hashlib
import json

import pytest
import autodev_control.trusted.authorization as authorization_module

from autodev_control.trusted.authorization import (
    G3_AUTHORIZATION_PROPOSAL_MAX_BYTES,
    AdmittedAuthorization,
    AuthorizationOperationalConstraints,
    CandidateAuthorizationProposal,
    DelegatedAuthoritySource,
    DelegationAllowance,
    DirectAuthoritySource,
    OrdinaryRootProtectionState,
    _authenticated_human_approval_for_test,
    _authorization_policy_context_for_test,
    _contract_authority_ceiling_for_test,
    _direct_issuer_envelope_for_test,
    _ordinary_root_context_for_test,
    _result,
    admit_delegated_authorization,
    admit_direct_authorization,
    load_candidate_authorization_proposal,
)
from autodev_control.trusted.decision import Decision
from autodev_control.trusted.errors import (
    AuthorizationAdmissionReasonCode,
    AuthorizationProposalFailureCode,
)
from autodev_control.trusted.identity import ImmutableConfigId, RawSha256
from autodev_control.trusted.manifest import PolicyEpochIdentity, TrustedManifestId
from autodev_control.trusted.scope import (
    AuthenticationEventId,
    AuthorizationId,
    AuthorizationKind,
    ChangeType,
    ContractId,
    GitHubRepositoryId,
    HumanPrincipalId,
    MutationScope,
    MutationScopeRule,
    RepositorySelector,
    RiskRelation,
    RiskTier,
    ServicePrincipalId,
    TargetRegistrationId,
    TaskCapability,
    TaskId,
)
from autodev_control.trusted.target_registration import (
    CandidateTargetRegistration,
    TargetRegistrationRootImpact,
    _authenticated_target_admin_approval_for_test,
    _target_registration_policy_context_for_test,
    _target_registration_root_assessment_for_test,
    admit_target_registration,
    load_candidate_target_registration,
)


def relation() -> RiskRelation:
    return RiskRelation((
        (RiskTier.ROUTINE, RiskTier.ROUTINE),
        (RiskTier.SUPERVISED, RiskTier.SUPERVISED),
        (RiskTier.ROUTINE, RiskTier.SUPERVISED),
    ))


def repo_scope() -> MutationScope:
    return MutationScope((MutationScopeRule(RepositorySelector(), tuple(ChangeType)),))


def proposal_scope() -> MutationScope:
    return MutationScope((MutationScopeRule(RepositorySelector(), (ChangeType.MODIFY,)),))


def epoch(char: str = "e") -> PolicyEpochIdentity:
    return PolicyEpochIdentity(TrustedManifestId(RawSha256(char * 64)))


def admitted_target(
    current_epoch: PolicyEpochIdentity | None = None, *, display_name: str = "owner/repo",
    capabilities: list[str] | None = None, runtime_profiles: list[str] | None = None,
    merge_ref: str | list[str] | None = None,
):
    capabilities = capabilities or ["implementation"]
    runtime_profiles = runtime_profiles or []
    merge_refs = [merge_ref] if type(merge_ref) is str else (merge_ref or [])
    value = {
        "format": "autodev.target-registration/v1",
        "repository": {"platform": "github", "repository_id": "1363823008", "display_name": display_name},
        "path_model": "git_utf8_regular_file/v1",
        "protected_refs": merge_refs,
        "allowed_task_capabilities": capabilities,
        "ordinary_allowed_scope": [{"selector": {"kind": "repository"}, "change_types": ["modify"]}],
        "ordinary_forbidden_scope": [],
        "risk_ceiling": "supervised",
        "target_publication": None,
        "merge": None if not merge_refs else {
            "service_identity": "merger", "merge_profile_id": "merge-profile",
            "allowed_integration_refs": merge_refs,
        },
        "validation_profile_ids": [],
        "controlled_runtime_profile_ids": runtime_profiles,
        "event_state_profile_ids": [],
        "adapter_config_id": "adapter",
    }
    loaded = load_candidate_target_registration(json.dumps(value, separators=(",", ":")).encode())
    assert isinstance(loaded, CandidateTargetRegistration)
    current_epoch = current_epoch or epoch()
    principal = HumanPrincipalId("admin")
    approval = _authenticated_target_admin_approval_for_test(
        human_principal_id=principal, authentication_event_id=AuthenticationEventId("target-auth"),
        target_registration_id=loaded.target_registration_id, policy_epoch_identity=current_epoch,
    )
    policy = _target_registration_policy_context_for_test(
        policy_epoch_identity=current_epoch, target_registration_id=loaded.target_registration_id,
        repository_id=loaded.repository_id, permitted_admin_principals=(principal,),
        maximum_allowed_task_capabilities=tuple(TaskCapability), maximum_ordinary_allowed_scope=repo_scope(),
        maximum_target_risk_ceiling=RiskTier.SUPERVISED,
        permitted_target_publication_service_identities=(), permitted_merge_service_identities=(ServicePrincipalId("merger"),),
        permitted_publication_profile_ids=(), permitted_merge_profile_ids=(ImmutableConfigId("merge-profile"),), permitted_validation_profile_ids=(),
        permitted_controlled_runtime_profile_ids=tuple(ImmutableConfigId(item) for item in runtime_profiles), permitted_event_state_profile_ids=(),
        permitted_adapter_config_ids=(ImmutableConfigId("adapter"),), risk_relation=relation(),
    )
    assessment = _target_registration_root_assessment_for_test(
        target_registration_id=loaded.target_registration_id, repository_id=loaded.repository_id,
        policy_epoch_identity=current_epoch, root_impact=TargetRegistrationRootImpact.NO_ROOT_IMPACT,
    )
    result = admit_target_registration(loaded, approval, policy, assessment)
    assert result.decision is Decision.ALLOW
    return result.admitted_registration


def proposal_json(target_id: TargetRegistrationId, *, delegated_parent=None, depth: int = 0) -> dict[str, object]:
    delegable = [] if depth == 0 else ["implementation"]
    delegable_scope = [] if depth == 0 else [{"selector": {"kind": "repository"}, "change_types": ["modify"]}]
    value = {
        "format": "autodev.authorization/v1",
        "kind": "delegated" if delegated_parent else "direct_human",
        "task_id": "task",
        "contract_id": "contract",
        "contract_sha256": "c" * 64,
        "target_registration_id": target_id.raw_sha256.value,
        "capabilities": ["implementation"],
        "mutation_scope": [{"selector": {"kind": "repository"}, "change_types": ["modify"]}],
        "operational_constraints": {"integration_refs": [], "controlled_runtime_profile_ids": [], "repair_max_attempts": 0},
        "risk_ceiling": "supervised",
        "delegation": {
            "remaining_depth": depth,
            "delegable_capabilities": delegable,
            "delegable_mutation_scope": delegable_scope,
            "delegable_operational_constraints": {"integration_refs": [], "controlled_runtime_profile_ids": [], "repair_max_attempts": 0},
            "risk_ceiling": None if depth == 0 else "supervised",
        },
    }
    if delegated_parent:
        value["parent_authorization_id"] = delegated_parent.raw_sha256.value
    else:
        value["issuer_principal_id"] = "issuer"
    return value


def load_proposal(target_id: TargetRegistrationId, **kwargs) -> CandidateAuthorizationProposal:
    raw = json.dumps(proposal_json(target_id, **kwargs), separators=(",", ":")).encode()
    result = load_candidate_authorization_proposal(raw)
    assert isinstance(result, CandidateAuthorizationProposal)
    return result


def load_operational_proposal(
    target_id: TargetRegistrationId, *, integration_ref: str | None = None,
    runtime_profiles: list[str] | None = None, repair_max_attempts: int = 0,
) -> CandidateAuthorizationProposal:
    value = proposal_json(target_id)
    capabilities = ["implementation"]
    if integration_ref is not None:
        capabilities.append("merge")
    if runtime_profiles:
        capabilities.append("controlled_runtime")
    if repair_max_attempts:
        capabilities.append("repair")
    value["capabilities"] = capabilities
    value["operational_constraints"] = {
        "integration_refs": [] if integration_ref is None else [integration_ref],
        "controlled_runtime_profile_ids": runtime_profiles or [],
        "repair_max_attempts": repair_max_attempts,
    }
    result = load_candidate_authorization_proposal(json.dumps(value).encode())
    assert isinstance(result, CandidateAuthorizationProposal)
    return result


def direct_contexts(proposal: CandidateAuthorizationProposal, target, current_epoch=None, auth_event="approval"):
    current_epoch = current_epoch or target.policy_epoch_identity
    principal = HumanPrincipalId("issuer")
    delegable_capabilities = proposal.delegation.delegable_capabilities or (TaskCapability.IMPLEMENTATION,)
    delegable_scope = (
        proposal.delegation.delegable_mutation_scope
        if proposal.delegation.delegable_mutation_scope.rules
        else repo_scope()
    )
    delegation_risk_ceiling = proposal.delegation.risk_ceiling or RiskTier.SUPERVISED
    contract = _contract_authority_ceiling_for_test(
        task_id=proposal.task_id, contract_id=proposal.contract_id,
        contract_raw_sha256=proposal.contract_raw_sha256, target_registration_id=proposal.target_registration_id,
        requested_capabilities=proposal.capabilities, allowed_mutation_scope=repo_scope(),
        prohibited_mutation_scope=MutationScope(()), risk_floor=RiskTier.ROUTINE,
        integration_ref=(None if not proposal.operational_constraints.integration_refs else proposal.operational_constraints.integration_refs[0]),
        controlled_runtime_profile_ids=proposal.operational_constraints.controlled_runtime_profile_ids,
        repair_max_attempts=proposal.operational_constraints.repair_max_attempts,
        delegation_max_depth=3, delegable_capabilities=delegable_capabilities,
        delegation_risk_ceiling=delegation_risk_ceiling,
    )
    policy = _authorization_policy_context_for_test(
        policy_epoch_identity=current_epoch, target_registration_id=proposal.target_registration_id,
        task_id=proposal.task_id, contract_id=proposal.contract_id, contract_raw_sha256=proposal.contract_raw_sha256,
        maximum_capabilities=proposal.capabilities, maximum_mutation_scope=repo_scope(),
        mandatory_forbidden_mutation_scope=MutationScope(()), maximum_operational_constraints=proposal.operational_constraints,
        maximum_authorization_risk_ceiling=RiskTier.SUPERVISED,
        effective_authoritative_risk=RiskTier.ROUTINE, risk_relation=relation(),
        maximum_delegation_depth=3, maximum_delegable_capabilities=delegable_capabilities,
        maximum_delegable_mutation_scope=delegable_scope,
        maximum_delegable_operational_constraints=proposal.delegation.delegable_operational_constraints,
        maximum_delegation_risk_ceiling=delegation_risk_ceiling,
    )
    issuer = _direct_issuer_envelope_for_test(
        policy_epoch_identity=current_epoch, human_principal_id=principal,
        target_registration_id=proposal.target_registration_id, task_id=proposal.task_id,
        contract_id=proposal.contract_id, contract_raw_sha256=proposal.contract_raw_sha256,
        maximum_capabilities=proposal.capabilities, maximum_mutation_scope=repo_scope(),
        maximum_operational_constraints=proposal.operational_constraints, maximum_authorization_risk_ceiling=RiskTier.SUPERVISED,
        maximum_delegation_depth=3, maximum_delegable_capabilities=delegable_capabilities,
        maximum_delegable_mutation_scope=delegable_scope,
        maximum_delegable_operational_constraints=proposal.delegation.delegable_operational_constraints,
        maximum_delegation_risk_ceiling=delegation_risk_ceiling,
    )
    approval = _authenticated_human_approval_for_test(
        human_principal_id=principal, authentication_event_id=AuthenticationEventId(auth_event),
        proposal_raw_sha256=proposal.proposal_raw_sha256, policy_epoch_identity=current_epoch,
    )
    root = _ordinary_root_context_for_test(
        policy_epoch_identity=current_epoch, repository_id=target.repository_id,
        state=OrdinaryRootProtectionState.NO_ROOT_PROTECTED_MATERIAL,
        root_protected_mutation_scope=None,
    )
    return contract, policy, approval, issuer, root


def test_authorization_loader_exact_identity_kind_and_precedence() -> None:
    target = admitted_target()
    value = proposal_json(target.target_registration_id)
    raw = json.dumps(value, separators=(",", ":")).encode()
    loaded = load_candidate_authorization_proposal(raw)
    assert isinstance(loaded, CandidateAuthorizationProposal)
    assert loaded.proposal_raw_sha256.value == hashlib.sha256(raw).hexdigest()
    assert loaded.kind is AuthorizationKind.DIRECT_HUMAN
    assert {item.value for item in AuthorizationProposalFailureCode} == {
        "INVALID_INPUT_TYPE", "BYTE_LIMIT_EXCEEDED", "PARSE_FAILED", "INVALID_TOP_LEVEL",
        "MISSING_FIELD", "UNKNOWN_FIELD", "INVALID_FIELD_TYPE", "INVALID_FIELD_VALUE",
        "DUPLICATE_IDENTITY", "EMPTY_REQUIRED_SET", "INCONSISTENT_CONFIGURATION",
    }
    assert load_candidate_authorization_proposal("bad").code is AuthorizationProposalFailureCode.INVALID_INPUT_TYPE
    assert load_candidate_authorization_proposal(b"x" * (G3_AUTHORIZATION_PROPOSAL_MAX_BYTES + 1)).code is AuthorizationProposalFailureCode.BYTE_LIMIT_EXCEEDED
    assert load_candidate_authorization_proposal(b"{").code is AuthorizationProposalFailureCode.PARSE_FAILED
    assert load_candidate_authorization_proposal(b"[]").code is AuthorizationProposalFailureCode.INVALID_TOP_LEVEL
    missing = dict(value)
    del missing["format"]
    assert load_candidate_authorization_proposal(json.dumps(missing).encode()).code is AuthorizationProposalFailureCode.MISSING_FIELD
    forbidden = dict(value)
    forbidden["parent_authorization_id"] = "a" * 64
    assert load_candidate_authorization_proposal(json.dumps(forbidden).encode()).code is AuthorizationProposalFailureCode.UNKNOWN_FIELD


def test_loader_duplicate_and_operational_zero_depth_consistency() -> None:
    target = admitted_target()
    value = proposal_json(target.target_registration_id)
    value["capabilities"].append("implementation")
    assert load_candidate_authorization_proposal(json.dumps(value).encode()).code is AuthorizationProposalFailureCode.DUPLICATE_IDENTITY
    value = proposal_json(target.target_registration_id)
    value["capabilities"] = []
    assert load_candidate_authorization_proposal(json.dumps(value).encode()).code is AuthorizationProposalFailureCode.EMPTY_REQUIRED_SET
    value = proposal_json(target.target_registration_id)
    value["capabilities"].append("merge")
    assert load_candidate_authorization_proposal(json.dumps(value).encode()).code is AuthorizationProposalFailureCode.EMPTY_REQUIRED_SET
    value = proposal_json(target.target_registration_id)
    value["operational_constraints"]["repair_max_attempts"] = 0.5
    assert load_candidate_authorization_proposal(json.dumps(value).encode()).code is AuthorizationProposalFailureCode.INVALID_FIELD_VALUE


def test_duplicate_candidate_operational_and_delegable_scope_return_failures() -> None:
    target = admitted_target()
    value = proposal_json(target.target_registration_id)
    value["capabilities"].append("controlled_runtime")
    value["operational_constraints"]["controlled_runtime_profile_ids"] = ["runtime", "runtime"]
    duplicate_profiles = load_candidate_authorization_proposal(json.dumps(value).encode())
    assert duplicate_profiles.code is AuthorizationProposalFailureCode.DUPLICATE_IDENTITY

    value = proposal_json(target.target_registration_id, depth=1)
    value["delegation"]["delegable_mutation_scope"] = [
        {"selector": {"kind": "repository"}, "change_types": ["add", "modify"]},
        {"selector": {"kind": "repository"}, "change_types": ["modify", "add"]},
    ]
    duplicate_scope = load_candidate_authorization_proposal(json.dumps(value).encode())
    assert duplicate_scope.code is AuthorizationProposalFailureCode.DUPLICATE_IDENTITY


def test_operational_collection_emptiness_consistency_and_ref_precedence() -> None:
    target = admitted_target()

    value = proposal_json(target.target_registration_id)
    value["capabilities"].append("controlled_runtime")
    assert load_candidate_authorization_proposal(json.dumps(value).encode()).code is AuthorizationProposalFailureCode.EMPTY_REQUIRED_SET

    for capability in ("merge", "controlled_runtime"):
        value = proposal_json(target.target_registration_id, depth=1)
        value["delegation"]["delegable_capabilities"].append(capability)
        assert load_candidate_authorization_proposal(json.dumps(value).encode()).code is AuthorizationProposalFailureCode.EMPTY_REQUIRED_SET

    value = proposal_json(target.target_registration_id)
    value["operational_constraints"]["integration_refs"] = ["refs/heads/main"]
    assert load_candidate_authorization_proposal(json.dumps(value).encode()).code is AuthorizationProposalFailureCode.INCONSISTENT_CONFIGURATION

    value = proposal_json(target.target_registration_id)
    value["operational_constraints"]["controlled_runtime_profile_ids"] = ["runtime"]
    assert load_candidate_authorization_proposal(json.dumps(value).encode()).code is AuthorizationProposalFailureCode.INCONSISTENT_CONFIGURATION

    value = proposal_json(target.target_registration_id)
    value["capabilities"].append("repair")
    assert load_candidate_authorization_proposal(json.dumps(value).encode()).code is AuthorizationProposalFailureCode.INCONSISTENT_CONFIGURATION
    value = proposal_json(target.target_registration_id)
    value["operational_constraints"]["repair_max_attempts"] = 1
    assert load_candidate_authorization_proposal(json.dumps(value).encode()).code is AuthorizationProposalFailureCode.INCONSISTENT_CONFIGURATION

    value = proposal_json(target.target_registration_id, depth=1)
    value["delegation"]["delegable_capabilities"].append("repair")
    assert load_candidate_authorization_proposal(json.dumps(value).encode()).code is AuthorizationProposalFailureCode.INCONSISTENT_CONFIGURATION
    value = proposal_json(target.target_registration_id, depth=1)
    value["delegation"]["delegable_operational_constraints"]["repair_max_attempts"] = 1
    assert load_candidate_authorization_proposal(json.dumps(value).encode()).code is AuthorizationProposalFailureCode.INCONSISTENT_CONFIGURATION

    value = proposal_json(target.target_registration_id)
    value["operational_constraints"]["integration_refs"] = ["refs/heads/main", "refs/heads/main"]
    assert load_candidate_authorization_proposal(json.dumps(value).encode()).code is AuthorizationProposalFailureCode.DUPLICATE_IDENTITY

    value = proposal_json(target.target_registration_id, depth=1)
    value["delegation"]["delegable_capabilities"].append("merge")
    value["delegation"]["delegable_operational_constraints"]["integration_refs"] = [
        "refs/heads/main", "refs/heads/main",
    ]
    assert load_candidate_authorization_proposal(json.dumps(value).encode()).code is AuthorizationProposalFailureCode.DUPLICATE_IDENTITY

    value = proposal_json(target.target_registration_id)
    value["capabilities"].append("merge")
    value["operational_constraints"]["integration_refs"] = ["refs/heads/main", "refs/heads/release"]
    assert load_candidate_authorization_proposal(json.dumps(value).encode()).code is AuthorizationProposalFailureCode.INVALID_FIELD_VALUE

    value = proposal_json(target.target_registration_id, depth=1)
    value["delegation"]["delegable_capabilities"].append("merge")
    value["delegation"]["delegable_operational_constraints"]["integration_refs"] = [
        "refs/heads/main", "refs/heads/release",
    ]
    assert load_candidate_authorization_proposal(json.dumps(value).encode()).code is AuthorizationProposalFailureCode.INVALID_FIELD_VALUE


def test_authorization_mutation_change_type_cardinality_precedence() -> None:
    target = admitted_target()
    value = proposal_json(target.target_registration_id)
    value["mutation_scope"][0]["change_types"] = []
    assert load_candidate_authorization_proposal(json.dumps(value).encode()).code is AuthorizationProposalFailureCode.EMPTY_REQUIRED_SET
    value["mutation_scope"][0]["change_types"] = [
        "add", "modify", "delete", "mode_change", "add",
    ]
    assert load_candidate_authorization_proposal(json.dumps(value).encode()).code is AuthorizationProposalFailureCode.INVALID_FIELD_VALUE


def test_canonical_authority_contexts_reject_duplicate_set_like_values() -> None:
    target = admitted_target()
    proposal = load_proposal(target.target_registration_id)
    contract, policy, _, issuer, _ = direct_contexts(proposal, target)
    contract_fields = {name: getattr(contract, name) for name in contract.__dataclass_fields__}
    contract_fields["requested_capabilities"] = (TaskCapability.IMPLEMENTATION, TaskCapability.IMPLEMENTATION)
    with pytest.raises(ValueError):
        _contract_authority_ceiling_for_test(**contract_fields)
    policy_fields = {name: getattr(policy, name) for name in policy.__dataclass_fields__}
    policy_fields["maximum_capabilities"] = (TaskCapability.IMPLEMENTATION, TaskCapability.IMPLEMENTATION)
    with pytest.raises(ValueError):
        _authorization_policy_context_for_test(**policy_fields)
    issuer_fields = {name: getattr(issuer, name) for name in issuer.__dataclass_fields__}
    issuer_fields["maximum_delegable_capabilities"] = (TaskCapability.IMPLEMENTATION, TaskCapability.IMPLEMENTATION)
    with pytest.raises(ValueError):
        _direct_issuer_envelope_for_test(**issuer_fields)
    value = proposal_json(target.target_registration_id)
    value["delegation"]["remaining_depth"] = 0
    value["delegation"]["risk_ceiling"] = "routine"
    assert load_candidate_authorization_proposal(json.dumps(value).encode()).code is AuthorizationProposalFailureCode.INCONSISTENT_CONFIGURATION


def test_direct_authorization_exact_bindings_id_and_non_bearer() -> None:
    target = admitted_target()
    proposal = load_proposal(target.target_registration_id, depth=2)
    contract, policy, approval, issuer, root = direct_contexts(proposal, target)
    result = admit_direct_authorization(proposal, target, contract, policy, approval, issuer, root)
    assert result.decision is Decision.ALLOW
    admitted = result.admitted_authorization
    assert isinstance(admitted, AdmittedAuthorization)
    assert isinstance(admitted.authority_source, DirectAuthoritySource)
    assert admitted.ancestry == ()
    expected = hashlib.sha256(
        b"autodev.authorization-id/v1\0"
        + bytes.fromhex(proposal.proposal_raw_sha256.value)
        + bytes.fromhex(policy.policy_epoch_identity.manifest_id.raw_sha256.value)
        + bytes.fromhex(target.target_registration_id.raw_sha256.value)
    ).hexdigest()
    assert admitted.authorization_id.raw_sha256.value == expected
    _, _, later_approval, _, _ = direct_contexts(proposal, target, auth_event="later")
    later = admit_direct_authorization(proposal, target, contract, policy, later_approval, issuer, root)
    assert later.admitted_authorization.authorization_id == admitted.authorization_id
    with pytest.raises(TypeError):
        AdmittedAuthorization()
    with pytest.raises(AttributeError):
        admitted.authorized_capabilities += (TaskCapability.MERGE,)
    with pytest.raises(AttributeError):
        admitted.delegation.remaining_depth = 0


def test_authorization_id_changes_with_proposal_policy_and_target_identity() -> None:
    target = admitted_target()
    proposal = load_proposal(target.target_registration_id)
    contract, policy, approval, issuer, root = direct_contexts(proposal, target)
    baseline = admit_direct_authorization(proposal, target, contract, policy, approval, issuer, root).admitted_authorization

    raw_value = proposal_json(target.target_registration_id)
    changed_proposal = load_candidate_authorization_proposal(json.dumps(raw_value, indent=2).encode())
    changed_contexts = direct_contexts(changed_proposal, target)
    changed_by_bytes = admit_direct_authorization(changed_proposal, target, *changed_contexts).admitted_authorization
    assert changed_by_bytes.authorization_id != baseline.authorization_id

    later_target = admitted_target(epoch("f"))
    later_proposal = load_proposal(later_target.target_registration_id)
    later_contexts = direct_contexts(later_proposal, later_target)
    changed_by_policy = admit_direct_authorization(later_proposal, later_target, *later_contexts).admitted_authorization
    assert changed_by_policy.authorization_id != baseline.authorization_id

    distinct_target = admitted_target(display_name="owner/renamed-display")
    distinct_proposal = load_proposal(distinct_target.target_registration_id)
    distinct_contexts = direct_contexts(distinct_proposal, distinct_target)
    changed_by_target = admit_direct_authorization(distinct_proposal, distinct_target, *distinct_contexts).admitted_authorization
    assert changed_by_target.authorization_id != baseline.authorization_id


def test_direct_context_availability_and_principal_digest_epoch_bindings() -> None:
    target = admitted_target()
    proposal = load_proposal(target.target_registration_id)
    contract, policy, approval, issuer, root = direct_contexts(proposal, target)
    args = (proposal, target, contract, policy, approval, issuer, root)
    for index, reason in (
        (1, AuthorizationAdmissionReasonCode.TARGET_CONTEXT_UNAVAILABLE),
        (2, AuthorizationAdmissionReasonCode.CONTRACT_CONTEXT_UNAVAILABLE),
        (3, AuthorizationAdmissionReasonCode.POLICY_CONTEXT_UNAVAILABLE),
        (4, AuthorizationAdmissionReasonCode.AUTHENTICATED_APPROVAL_UNAVAILABLE),
        (5, AuthorizationAdmissionReasonCode.ISSUER_AUTHORITY_UNAVAILABLE),
        (6, AuthorizationAdmissionReasonCode.ROOT_CONTEXT_UNAVAILABLE),
    ):
        changed = list(args)
        changed[index] = None
        assert admit_direct_authorization(*changed).reason_code is reason
    wrong_approval = _authenticated_human_approval_for_test(
        human_principal_id=HumanPrincipalId("other"), authentication_event_id=AuthenticationEventId("x"),
        proposal_raw_sha256=proposal.proposal_raw_sha256, policy_epoch_identity=policy.policy_epoch_identity,
    )
    assert admit_direct_authorization(proposal, target, contract, policy, wrong_approval, issuer, root).reason_code is AuthorizationAdmissionReasonCode.AUTHENTICATION_BINDING_MISMATCH
    wrong_digest = _authenticated_human_approval_for_test(
        human_principal_id=proposal.issuer_principal_id, authentication_event_id=AuthenticationEventId("x"),
        proposal_raw_sha256=RawSha256("f" * 64), policy_epoch_identity=policy.policy_epoch_identity,
    )
    assert admit_direct_authorization(proposal, target, contract, policy, wrong_digest, issuer, root).reason_code is AuthorizationAdmissionReasonCode.AUTHENTICATION_BINDING_MISMATCH
    stale_approval = _authenticated_human_approval_for_test(
        human_principal_id=proposal.issuer_principal_id, authentication_event_id=AuthenticationEventId("x"),
        proposal_raw_sha256=proposal.proposal_raw_sha256, policy_epoch_identity=epoch("f"),
    )
    assert admit_direct_authorization(proposal, target, contract, policy, stale_approval, issuer, root).reason_code is AuthorizationAdmissionReasonCode.POLICY_EPOCH_MISMATCH


def test_direct_intersection_prohibitions_root_and_risk() -> None:
    target = admitted_target()
    proposal = load_proposal(target.target_registration_id)
    contract, policy, approval, issuer, root = direct_contexts(proposal, target)
    policy_fields = {name: getattr(policy, name) for name in policy.__dataclass_fields__}
    policy_fields["maximum_capabilities"] = ()
    restrictive = _authorization_policy_context_for_test(**policy_fields)
    assert admit_direct_authorization(proposal, target, contract, restrictive, approval, issuer, root).reason_code is AuthorizationAdmissionReasonCode.CAPABILITY_NOT_PERMITTED
    contract_fields = {name: getattr(contract, name) for name in contract.__dataclass_fields__}
    contract_fields["prohibited_mutation_scope"] = proposal_scope()
    prohibited = _contract_authority_ceiling_for_test(**contract_fields)
    assert admit_direct_authorization(proposal, target, prohibited, policy, approval, issuer, root).reason_code is AuthorizationAdmissionReasonCode.MUTATION_SCOPE_NOT_PERMITTED
    protected_root = _ordinary_root_context_for_test(
        policy_epoch_identity=policy.policy_epoch_identity, repository_id=target.repository_id,
        state=OrdinaryRootProtectionState.ROOT_PROTECTED_MUTATION_SCOPE,
        root_protected_mutation_scope=proposal_scope(),
    )
    assert admit_direct_authorization(proposal, target, contract, policy, approval, issuer, protected_root).reason_code is AuthorizationAdmissionReasonCode.ROOT_SCOPE_OVERLAP
    wrong_repo_root = _ordinary_root_context_for_test(
        policy_epoch_identity=policy.policy_epoch_identity, repository_id=GitHubRepositoryId("1"),
        state=OrdinaryRootProtectionState.NO_ROOT_PROTECTED_MATERIAL, root_protected_mutation_scope=None,
    )
    assert admit_direct_authorization(proposal, target, contract, policy, approval, issuer, wrong_repo_root).reason_code is AuthorizationAdmissionReasonCode.TARGET_REGISTRATION_MISMATCH

    policy_fields = {name: getattr(policy, name) for name in policy.__dataclass_fields__}
    policy_fields["risk_relation"] = RiskRelation(((RiskTier.ROUTINE, RiskTier.ROUTINE), (RiskTier.SUPERVISED, RiskTier.SUPERVISED)))
    incomparable = _authorization_policy_context_for_test(**policy_fields)
    assert admit_direct_authorization(proposal, target, contract, incomparable, approval, issuer, root).reason_code is AuthorizationAdmissionReasonCode.RISK_RELATION_UNAVAILABLE
    policy_fields["risk_relation"] = relation()
    policy_fields["effective_authoritative_risk"] = RiskTier.SUPERVISED
    too_risky = _authorization_policy_context_for_test(**policy_fields)
    value = proposal_json(target.target_registration_id)
    value["risk_ceiling"] = "routine"
    narrow_proposal = load_candidate_authorization_proposal(json.dumps(value).encode())
    narrow_contract, _, narrow_approval, narrow_issuer, narrow_root = direct_contexts(narrow_proposal, target)
    assert admit_direct_authorization(narrow_proposal, target, narrow_contract, too_risky, narrow_approval, narrow_issuer, narrow_root).reason_code is AuthorizationAdmissionReasonCode.RISK_NOT_PERMITTED


def test_direct_capability_intersection_checks_policy_target_and_issuer() -> None:
    target = admitted_target(capabilities=["implementation", "deterministic_validation"])
    value = proposal_json(target.target_registration_id)
    value["capabilities"] = ["deterministic_validation"]
    proposal = load_candidate_authorization_proposal(json.dumps(value).encode())
    assert isinstance(proposal, CandidateAuthorizationProposal)
    contract, policy, approval, issuer, root = direct_contexts(proposal, target)
    policy_fields = {name: getattr(policy, name) for name in policy.__dataclass_fields__}
    policy_fields["maximum_capabilities"] = ()
    assert admit_direct_authorization(
        proposal, target, contract, _authorization_policy_context_for_test(**policy_fields), approval, issuer, root
    ).reason_code is AuthorizationAdmissionReasonCode.CAPABILITY_NOT_PERMITTED
    issuer_fields = {name: getattr(issuer, name) for name in issuer.__dataclass_fields__}
    issuer_fields["maximum_capabilities"] = ()
    assert admit_direct_authorization(
        proposal, target, contract, policy, approval, _direct_issuer_envelope_for_test(**issuer_fields), root
    ).reason_code is AuthorizationAdmissionReasonCode.CAPABILITY_NOT_PERMITTED

    target_without_capability = admitted_target()
    wrong_target_value = proposal_json(target_without_capability.target_registration_id)
    wrong_target_value["capabilities"] = ["deterministic_validation"]
    wrong_target_proposal = load_candidate_authorization_proposal(json.dumps(wrong_target_value).encode())
    wrong_contexts = direct_contexts(wrong_target_proposal, target_without_capability)
    assert admit_direct_authorization(
        wrong_target_proposal, target_without_capability, *wrong_contexts
    ).reason_code is AuthorizationAdmissionReasonCode.CAPABILITY_NOT_PERMITTED


def test_direct_operational_dimensions_precede_root_overlap() -> None:
    target = admitted_target(
        capabilities=["implementation", "merge", "controlled_runtime", "repair"],
        runtime_profiles=["runtime"], merge_ref="refs/heads/main",
    )
    value = proposal_json(target.target_registration_id)
    value["capabilities"] += ["merge", "controlled_runtime", "repair"]
    value["operational_constraints"] = {
        "integration_refs": ["refs/heads/main"],
        "controlled_runtime_profile_ids": ["runtime"], "repair_max_attempts": 2,
    }
    proposal = load_candidate_authorization_proposal(json.dumps(value).encode())
    assert isinstance(proposal, CandidateAuthorizationProposal)
    contract, policy, approval, issuer, _ = direct_contexts(proposal, target)
    protected_root = _ordinary_root_context_for_test(
        policy_epoch_identity=policy.policy_epoch_identity, repository_id=target.repository_id,
        state=OrdinaryRootProtectionState.ROOT_PROTECTED_MUTATION_SCOPE,
        root_protected_mutation_scope=proposal_scope(),
    )
    issuer_fields = {name: getattr(issuer, name) for name in issuer.__dataclass_fields__}
    issuer_fields["maximum_operational_constraints"] = AuthorizationOperationalConstraints((), (ImmutableConfigId("runtime"),), 2)
    no_ref = _direct_issuer_envelope_for_test(**issuer_fields)
    assert admit_direct_authorization(proposal, target, contract, policy, approval, no_ref, protected_root).reason_code is AuthorizationAdmissionReasonCode.INTEGRATION_REF_NOT_PERMITTED
    issuer_fields["maximum_operational_constraints"] = AuthorizationOperationalConstraints((proposal.operational_constraints.integration_refs[0],), (), 2)
    no_runtime = _direct_issuer_envelope_for_test(**issuer_fields)
    assert admit_direct_authorization(proposal, target, contract, policy, approval, no_runtime, protected_root).reason_code is AuthorizationAdmissionReasonCode.RUNTIME_PROFILE_NOT_PERMITTED
    issuer_fields["maximum_operational_constraints"] = AuthorizationOperationalConstraints(
        proposal.operational_constraints.integration_refs, proposal.operational_constraints.controlled_runtime_profile_ids, 1
    )
    low_repair = _direct_issuer_envelope_for_test(**issuer_fields)
    assert admit_direct_authorization(proposal, target, contract, policy, approval, low_repair, protected_root).reason_code is AuthorizationAdmissionReasonCode.REPAIR_ATTEMPTS_NOT_PERMITTED
    assert admit_direct_authorization(proposal, target, contract, policy, approval, issuer, protected_root).reason_code is AuthorizationAdmissionReasonCode.ROOT_SCOPE_OVERLAP


def test_target_operational_membership_uses_full_ref_and_runtime_allowlists_only() -> None:
    target = admitted_target(
        capabilities=["implementation", "merge", "controlled_runtime", "repair"],
        runtime_profiles=["runtime-a", "runtime-b"],
        merge_ref=["refs/heads/main", "refs/heads/release"],
    )
    for ref in ("refs/heads/main", "refs/heads/release"):
        proposal = load_operational_proposal(
            target.target_registration_id, integration_ref=ref,
            runtime_profiles=["runtime-b"], repair_max_attempts=3,
        )
        result = admit_direct_authorization(proposal, target, *direct_contexts(proposal, target))
        assert result.decision is Decision.ALLOW

    outside = load_operational_proposal(
        target.target_registration_id, integration_ref="refs/heads/other",
        runtime_profiles=["runtime-a"], repair_max_attempts=3,
    )
    assert admit_direct_authorization(
        outside, target, *direct_contexts(outside, target)
    ).reason_code is AuthorizationAdmissionReasonCode.INTEGRATION_REF_NOT_PERMITTED

    unbounded_by_target = load_operational_proposal(
        target.target_registration_id,
        repair_max_attempts=2**80,
    )
    result = admit_direct_authorization(
        unbounded_by_target, target, *direct_contexts(unbounded_by_target, target)
    )
    assert result.decision is Decision.ALLOW


def test_delegated_repair_intersection_has_no_target_repair_ceiling() -> None:
    target = admitted_target(capabilities=["implementation", "repair"])
    attempts = 2**80
    parent_value = proposal_json(target.target_registration_id, depth=2)
    parent_value["capabilities"] = ["implementation", "repair"]
    parent_value["operational_constraints"]["repair_max_attempts"] = attempts
    parent_value["delegation"]["delegable_capabilities"] = ["implementation", "repair"]
    parent_value["delegation"]["delegable_operational_constraints"]["repair_max_attempts"] = attempts
    parent = load_candidate_authorization_proposal(json.dumps(parent_value).encode())
    assert isinstance(parent, CandidateAuthorizationProposal)
    admitted_parent = admit_direct_authorization(parent, target, *direct_contexts(parent, target)).admitted_authorization

    child_value = proposal_json(
        target.target_registration_id, delegated_parent=admitted_parent.authorization_id
    )
    child_value["capabilities"] = ["implementation", "repair"]
    child_value["operational_constraints"]["repair_max_attempts"] = attempts
    child = load_candidate_authorization_proposal(json.dumps(child_value).encode())
    assert isinstance(child, CandidateAuthorizationProposal)
    contract, policy, _, _, root = direct_contexts(child, target)
    result = admit_delegated_authorization(child, target, contract, policy, admitted_parent, root)
    assert result.decision is Decision.ALLOW


def test_direct_delegation_risk_cannot_exceed_own_authorization_ceiling() -> None:
    target = admitted_target()
    value = proposal_json(target.target_registration_id, depth=1)
    value["risk_ceiling"] = "routine"
    proposal = load_candidate_authorization_proposal(json.dumps(value).encode())
    assert isinstance(proposal, CandidateAuthorizationProposal)
    contexts = direct_contexts(proposal, target)
    assert admit_direct_authorization(proposal, target, *contexts).reason_code is AuthorizationAdmissionReasonCode.DELEGATION_NOT_PERMITTED


def test_delegated_authorization_parent_non_amplification_and_ancestry() -> None:
    target = admitted_target()
    parent_proposal = load_proposal(target.target_registration_id, depth=2)
    contract, policy, approval, issuer, root = direct_contexts(parent_proposal, target)
    parent_result = admit_direct_authorization(parent_proposal, target, contract, policy, approval, issuer, root)
    parent = parent_result.admitted_authorization
    child_proposal = load_proposal(target.target_registration_id, delegated_parent=parent.authorization_id, depth=1)
    child_contract, child_policy, _, _, child_root = direct_contexts(child_proposal, target)
    child = admit_delegated_authorization(child_proposal, target, child_contract, child_policy, parent, child_root)
    assert child.decision is Decision.ALLOW
    admitted = child.admitted_authorization
    assert isinstance(admitted.authority_source, DelegatedAuthoritySource)
    assert admitted.authority_source.parent_authorization_id == parent.authorization_id
    assert admitted.ancestry == (parent.authorization_id,)
    assert admit_delegated_authorization(child_proposal, target, child_contract, child_policy, None, child_root).reason_code is AuthorizationAdmissionReasonCode.PARENT_AUTHORIZATION_UNAVAILABLE
    wrong_parent_value = proposal_json(target.target_registration_id, delegated_parent=type(parent.authorization_id)(RawSha256("9" * 64)))
    wrong_parent = load_candidate_authorization_proposal(json.dumps(wrong_parent_value).encode())
    assert admit_delegated_authorization(wrong_parent, target, child_contract, child_policy, parent, child_root).reason_code is AuthorizationAdmissionReasonCode.PARENT_AUTHORIZATION_MISMATCH

    protected_root = _ordinary_root_context_for_test(
        policy_epoch_identity=child_policy.policy_epoch_identity, repository_id=target.repository_id,
        state=OrdinaryRootProtectionState.ROOT_PROTECTED_MUTATION_SCOPE,
        root_protected_mutation_scope=proposal_scope(),
    )
    assert admit_delegated_authorization(
        child_proposal, target, child_contract, child_policy, parent, protected_root
    ).reason_code is AuthorizationAdmissionReasonCode.ROOT_SCOPE_OVERLAP


def test_delegated_capability_contract_depth_and_ancestry_guards(monkeypatch) -> None:
    target = admitted_target(capabilities=["implementation", "deterministic_validation"])
    parent_proposal = load_proposal(target.target_registration_id, depth=2)
    parent_contexts = direct_contexts(parent_proposal, target)
    parent = admit_direct_authorization(parent_proposal, target, *parent_contexts).admitted_authorization

    child_value = proposal_json(target.target_registration_id, delegated_parent=parent.authorization_id)
    child_value["capabilities"] = ["deterministic_validation"]
    unauthorized_child = load_candidate_authorization_proposal(json.dumps(child_value).encode())
    unauthorized_contexts = direct_contexts(unauthorized_child, target)
    assert admit_delegated_authorization(
        unauthorized_child, target, unauthorized_contexts[0], unauthorized_contexts[1], parent, unauthorized_contexts[4]
    ).reason_code is AuthorizationAdmissionReasonCode.CAPABILITY_NOT_PERMITTED

    child = load_proposal(target.target_registration_id, delegated_parent=parent.authorization_id, depth=1)
    child_contract, child_policy, _, _, child_root = direct_contexts(child, target)
    contract_fields = {name: getattr(child_contract, name) for name in child_contract.__dataclass_fields__}
    contract_fields.update(delegation_max_depth=0, delegable_capabilities=(), delegation_risk_ceiling=None)
    no_child_delegation = _contract_authority_ceiling_for_test(**contract_fields)
    assert admit_delegated_authorization(
        child, target, no_child_delegation, child_policy, parent, child_root
    ).reason_code is AuthorizationAdmissionReasonCode.DELEGATION_DEPTH_EXCEEDED

    corrupt_parent = copy.copy(parent)
    object.__setattr__(corrupt_parent, "ancestry", (parent.authorization_id, parent.authorization_id))
    assert admit_delegated_authorization(
        child, target, child_contract, child_policy, corrupt_parent, child_root
    ).reason_code is AuthorizationAdmissionReasonCode.ANCESTRY_INVALID

    monkeypatch.setattr(authorization_module, "_authorization_id", lambda *_: parent.authorization_id)
    assert admit_delegated_authorization(
        child, target, child_contract, child_policy, parent, child_root
    ).reason_code is AuthorizationAdmissionReasonCode.ANCESTRY_INVALID


def test_parent_ancestry_hard_bound_precedes_remaining_depth() -> None:
    target = admitted_target()
    parent_proposal = load_proposal(target.target_registration_id, depth=2)
    parent = admit_direct_authorization(
        parent_proposal, target, *direct_contexts(parent_proposal, target)
    ).admitted_authorization
    child = load_proposal(
        target.target_registration_id, delegated_parent=parent.authorization_id, depth=1
    )
    child_contract, child_policy, _, _, child_root = direct_contexts(child, target)
    ancestry = tuple(
        AuthorizationId(RawSha256(f"{index:064x}")) for index in range(1, 65)
    )

    parent_at_63 = copy.copy(parent)
    object.__setattr__(parent_at_63, "ancestry", ancestry[:63])
    admitted = admit_delegated_authorization(
        child, target, child_contract, child_policy, parent_at_63, child_root
    )
    assert admitted.decision is Decision.ALLOW
    assert len(admitted.admitted_authorization.ancestry) == 64

    parent_at_64 = copy.copy(parent)
    object.__setattr__(parent_at_64, "ancestry", ancestry)
    assert admit_delegated_authorization(
        child, target, child_contract, child_policy, parent_at_64, child_root
    ).reason_code is AuthorizationAdmissionReasonCode.ANCESTRY_INVALID

    zero_depth_parent = copy.copy(parent_at_64)
    zero_depth_allowance = copy.copy(parent.delegation)
    object.__setattr__(zero_depth_allowance, "remaining_depth", 0)
    object.__setattr__(zero_depth_parent, "delegation", zero_depth_allowance)
    assert admit_delegated_authorization(
        child, target, child_contract, child_policy, zero_depth_parent, child_root
    ).reason_code is AuthorizationAdmissionReasonCode.ANCESTRY_INVALID


def test_delegation_depth_cannot_replenish() -> None:
    target = admitted_target()
    parent_proposal = load_proposal(target.target_registration_id, depth=1)
    contract, policy, approval, issuer, root = direct_contexts(parent_proposal, target)
    parent = admit_direct_authorization(parent_proposal, target, contract, policy, approval, issuer, root).admitted_authorization
    child = load_proposal(target.target_registration_id, delegated_parent=parent.authorization_id, depth=1)
    child_contract, child_policy, _, _, child_root = direct_contexts(child, target)
    result = admit_delegated_authorization(child, target, child_contract, child_policy, parent, child_root)
    assert result.reason_code is AuthorizationAdmissionReasonCode.DELEGATION_DEPTH_EXCEEDED


def test_delegated_parent_target_and_epoch_are_independent_current_checks() -> None:
    old_target = admitted_target(epoch("d"))
    old_proposal = load_proposal(old_target.target_registration_id, depth=2)
    old_contexts = direct_contexts(old_proposal, old_target)
    old_parent = admit_direct_authorization(old_proposal, old_target, *old_contexts).admitted_authorization

    current_target = admitted_target(epoch("e"))
    stale_child = load_proposal(current_target.target_registration_id, delegated_parent=old_parent.authorization_id)
    stale_contract, stale_policy, _, _, stale_root = direct_contexts(stale_child, current_target)
    assert admit_delegated_authorization(
        stale_child, current_target, stale_contract, stale_policy, old_parent, stale_root
    ).reason_code is AuthorizationAdmissionReasonCode.PARENT_POLICY_EPOCH_MISMATCH

    other_target = admitted_target(display_name="different")
    other_proposal = load_proposal(other_target.target_registration_id, depth=2)
    other_contexts = direct_contexts(other_proposal, other_target)
    other_parent = admit_direct_authorization(other_proposal, other_target, *other_contexts).admitted_authorization
    wrong_target_child = load_proposal(current_target.target_registration_id, delegated_parent=other_parent.authorization_id)
    child_contract, child_policy, _, _, child_root = direct_contexts(wrong_target_child, current_target)
    assert admit_delegated_authorization(
        wrong_target_child, current_target, child_contract, child_policy, other_parent, child_root
    ).reason_code is AuthorizationAdmissionReasonCode.PARENT_TARGET_MISMATCH


def test_exact_authorization_reason_decision_mapping() -> None:
    escalations = {
        AuthorizationAdmissionReasonCode.AUTHENTICATED_APPROVAL_UNAVAILABLE,
        AuthorizationAdmissionReasonCode.TARGET_CONTEXT_UNAVAILABLE,
        AuthorizationAdmissionReasonCode.POLICY_CONTEXT_UNAVAILABLE,
        AuthorizationAdmissionReasonCode.CONTRACT_CONTEXT_UNAVAILABLE,
        AuthorizationAdmissionReasonCode.ISSUER_AUTHORITY_UNAVAILABLE,
        AuthorizationAdmissionReasonCode.PARENT_AUTHORIZATION_UNAVAILABLE,
        AuthorizationAdmissionReasonCode.ROOT_CONTEXT_UNAVAILABLE,
        AuthorizationAdmissionReasonCode.RISK_RELATION_UNAVAILABLE,
    }
    for reason in AuthorizationAdmissionReasonCode:
        if reason is AuthorizationAdmissionReasonCode.ADMITTED:
            continue
        result = _result(reason)
        assert result.admitted_authorization is None
        assert result.decision is (Decision.ESCALATE if reason in escalations else Decision.DENY)
