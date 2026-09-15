"""Test-only builders for canonical contract prerequisites."""

import json

from autodev_control.trusted.contract import (
    AdmittedIssueContract, ContractAcceptanceEvaluator, ContractAcceptancePlan,
    ContractAcceptanceRequirement, EvaluatorMechanism, ResolvedTrustedConfigBinding,
    TrustedConfigIdentity, TrustedContractBaseObservation,
    TrustedContractRootContext, TrustedEvaluatorConfigResolution,
    TrustedIssueContractAdmissionContext, TrustedIssueContractSchemaBinding,
    TrustedIssueIdentityObservation,
    contract_json_value_digest, load_candidate_issue_contract,
)
from autodev_control.trusted.identity import ImmutableConfigId, LogicalIdentifier, RawSha256
from autodev_control.trusted.operation import AuthoritativeStateBindingId
from autodev_control.trusted.resources import RootManagedResourceId, RootManagedResourceKind, RootManagedResourceRef
from autodev_control.trusted.scope import CanonicalBranchRef, ChangeType, ContractId, MutationScope, RiskTier, TargetRegistrationId, TaskCapability, TaskId


def canonical_contract_fixture(
    *, contract_id: ContractId, task_id: TaskId,
    target_registration_id: TargetRegistrationId, repository_id,
    policy_epoch_identity, base_sha, allowed_repository_scope: bool = False,
    requested_operations=(TaskCapability.IMPLEMENTATION,),
):
    allowed = []
    if allowed_repository_scope:
        allowed = [{
            "selector": {"kind": "repository"},
            "change_types": [item.value for item in ChangeType],
        }]
    target = {
        "target_registration_id": target_registration_id.raw_sha256.value,
        "base_ref": "refs/heads/main",
        "base_sha": base_sha.value,
    }
    if TaskCapability.MERGE in requested_operations:
        target["integration_ref"] = "refs/heads/main"
    value = {
        "schema_version": "1.0",
        "contract_id": contract_id.value,
        "task_id": task_id.value,
        "context_anchor": {"repository_id": repository_id.value, "issue_number": 1, "issue_id": "issue-1"},
        "objective": "fixture objective",
        "target": target,
        "scope": {"object_model": "regular_file_only", "allowed_changes": allowed, "prohibited_changes": []},
        "requested_operations": [item.value for item in requested_operations],
        "risk_floor": "routine",
        "acceptance_mode": "all",
        "acceptance_requirements": [{
            "requirement_id": "requirement",
            "statement": "fixture statement",
            "evaluation_mode": "all",
            "evaluators": [{
                "evaluation_id": "evaluation",
                "mechanism": "deterministic",
                "evaluator_ref": "evaluator-config",
                "parameters": {},
            }],
        }],
        "runtime_requirements": {"allowed_profile_ids": []},
        "repair_policy": {"max_attempts": 0},
        "human_approval_requirements": [],
        "delegation_limits": {"max_depth": 0, "delegable_operations": []},
    }
    raw = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    candidate = load_candidate_issue_contract(raw)
    digest = candidate.source_document.raw_sha256
    config = TrustedConfigIdentity(
        ImmutableConfigId("evaluator-config"), RootManagedResourceId("evaluator-resource"),
        RawSha256("e" * 64),
    )
    evaluator = candidate.acceptance_requirements[0].evaluators[0]
    plan = ContractAcceptancePlan(
        contract_id, digest,
        (ContractAcceptanceRequirement(
            candidate.acceptance_requirements[0].requirement_id,
            candidate.acceptance_requirements[0].statement,
            (ContractAcceptanceEvaluator(
                evaluator.evaluation_id, EvaluatorMechanism.DETERMINISTIC,
                evaluator.evaluator_ref, config,
                contract_json_value_digest(evaluator.parameters),
            ),),
        ),),
    )
    contract = object.__new__(AdmittedIssueContract)
    fields = dict(
        contract_id=contract_id, contract_raw_sha256=digest, raw_bytes=raw,
        task_id=task_id, context_anchor=candidate.context_anchor,
        contract_target_registration_ref=candidate.target.target_registration_ref,
        target_registration_id=target_registration_id,
        base_ref=CanonicalBranchRef("refs/heads/main"),
        base_sha=base_sha,
        integration_ref=(
            CanonicalBranchRef("refs/heads/main")
            if TaskCapability.MERGE in requested_operations else None
        ),
        allowed_mutation_scope=candidate.allowed_mutation_scope,
        prohibited_mutation_scope=candidate.prohibited_mutation_scope,
        requested_operations=tuple(requested_operations), risk_floor=RiskTier.ROUTINE,
        acceptance_plan=plan, runtime_profile_identities=(), repair_max_attempts=0,
        human_approval_requirements=(), delegation_limits=candidate.delegation_limits,
        schema_resource_id=RootManagedResourceId("issue-contract-schema"),
        schema_resource_sha256=RawSha256("05fa0aa4a4a8efe813a0a6e03bdbe451a5c980835645190828f351919c08a51f"),
        schema_version="1.0", admission_policy_epoch_identity=policy_epoch_identity,
        admission_event_identity=LogicalIdentifier("contract-admission"),
    )
    for name, item in fields.items():
        object.__setattr__(contract, name, item)
    return raw, digest, contract


def trusted_admission_context_for_fixture(
    raw, target, epoch, issue_binding: AuthoritativeStateBindingId,
    base_binding: AuthoritativeStateBindingId,
):
    candidate = load_candidate_issue_contract(raw)

    def mint(cls, **fields):
        value = object.__new__(cls)
        for name, item in fields.items():
            object.__setattr__(value, name, item)
        return value

    config = TrustedConfigIdentity(
        ImmutableConfigId("evaluator-config"), RootManagedResourceId("evaluator-resource"),
        RawSha256("e" * 64),
    )
    binding = mint(ResolvedTrustedConfigBinding, policy_epoch_identity=epoch, config_identity=config)
    evaluator = mint(
        TrustedEvaluatorConfigResolution, binding=binding,
        mechanism=EvaluatorMechanism.DETERMINISTIC, parameters_valid=True,
        applicable=True, operational_prerequisites=(),
    )
    schema = mint(
        TrustedIssueContractSchemaBinding, policy_epoch_identity=epoch,
        schema_resource=RootManagedResourceRef(
            RootManagedResourceId("issue-contract-schema"), RootManagedResourceKind.TRUSTED_SCHEMA,
            RawSha256("05fa0aa4a4a8efe813a0a6e03bdbe451a5c980835645190828f351919c08a51f"),
        ), schema_version="1.0",
    )
    issue = mint(
        TrustedIssueIdentityObservation, repository_id=target.repository_id,
        issue_number=1, issue_id=LogicalIdentifier("issue-1"),
        authoritative_state_binding_id=issue_binding,
    )
    base = mint(
        TrustedContractBaseObservation, repository_id=target.repository_id,
        ref=CanonicalBranchRef("refs/heads/main"), sha=candidate.target.base_sha,
        authoritative_state_binding_id=base_binding,
    )
    root = mint(
        TrustedContractRootContext, policy_epoch_identity=epoch,
        repository_id=target.repository_id, root_protected_mutation_scope=MutationScope(()),
        determinate=True,
    )
    return mint(
        TrustedIssueContractAdmissionContext, policy_epoch_identity=epoch,
        schema_binding=schema, resolved_target=target, issue_identity=issue,
        base_observation=base, evaluator_resolutions=(evaluator,), approval_resolutions=(),
        runtime_resolutions=(), root_context=root, repair_policy_context=None,
        operation_approval_enforcement_available=False,
        admission_event_identity=LogicalIdentifier("contract-admission"),
    )
