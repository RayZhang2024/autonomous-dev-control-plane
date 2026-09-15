from dataclasses import FrozenInstanceError, replace
from decimal import Decimal
import hashlib
import json
from types import MappingProxyType

import pytest

from autodev_control.trusted.backend import (
    CanonicalNamespace, CanonicalStateRootManifest, CanonicalTransaction,
    CanonicalWriteStatus, CreateContract, InMemoryCanonicalStateBackend,
)
import autodev_control.trusted.contract as contract_module
from autodev_control.trusted.contract import *
from autodev_control.trusted.decision import Decision
from autodev_control.trusted.errors import IssueContractAdmissionReasonCode, IssueContractFailure, IssueContractFailureCode
from autodev_control.trusted.identity import GitSha, ImmutableConfigId, LogicalIdentifier, RawSha256
from autodev_control.trusted.manifest import PolicyEpochIdentity, TrustedManifestId
from autodev_control.trusted.operation import AuthoritativeStateBindingId
from autodev_control.trusted.resources import RootManagedResourceId, RootManagedResourceKind, RootManagedResourceRef
from autodev_control.trusted.scope import (
    CanonicalBranchRef, CanonicalGitPath, ChangeType, ExactPathSelector,
    GitHubRepositoryId, MutationScope, MutationScopeRule, RepositorySelector,
    RiskTier, TargetRegistrationId, TaskCapability,
)
from autodev_control.trusted.target_registration import AdmittedTargetRegistration


REPOSITORY = GitHubRepositoryId("123")
TARGET_ID = TargetRegistrationId(RawSha256("a" * 64))
EPOCH = PolicyEpochIdentity(TrustedManifestId(RawSha256("b" * 64)))
LATER_EPOCH = PolicyEpochIdentity(TrustedManifestId(RawSha256("c" * 64)))
BASE_SHA = GitSha("d" * 40)
BASE_REF = CanonicalBranchRef("refs/heads/main")


def raw_value(**changes):
    value = {
        "schema_version": "1.0",
        "contract_id": "contract",
        "task_id": "task",
        "context_anchor": {"repository_id": REPOSITORY.value, "issue_number": 27, "issue_id": "I_kwDO27"},
        "objective": "Human prose says merge and root, but creates no such semantics.",
        "target": {
            "target_registration_id": TARGET_ID.raw_sha256.value,
            "base_ref": BASE_REF.value,
            "base_sha": BASE_SHA.value,
        },
        "scope": {
            "object_model": "regular_file_only",
            "allowed_changes": [{
                "selector": {"kind": "exact_path", "path": "src/app.py"},
                "change_types": ["modify"],
            }],
            "prohibited_changes": [],
        },
        "requested_operations": ["implementation", "target_publish"],
        "risk_floor": "routine",
        "acceptance_mode": "all",
        "acceptance_requirements": [{
            "requirement_id": "required",
            "statement": "Prose mentions controlled_runtime but cannot select it.",
            "evaluation_mode": "all",
            "evaluators": [{
                "evaluation_id": "evaluation",
                "mechanism": "deterministic",
                "evaluator_ref": "evaluator-v1",
                "parameters": {"flag": True, "threshold": 1.0},
            }],
        }],
        "runtime_requirements": {"allowed_profile_ids": []},
        "repair_policy": {"max_attempts": 0},
        "human_approval_requirements": [],
        "delegation_limits": {"max_depth": 0, "delegable_operations": []},
    }
    value.update(changes)
    return value


def raw_bytes(value=None, *, indent=None):
    return json.dumps(value or raw_value(), ensure_ascii=False, separators=(",", ":") if indent is None else None, indent=indent).encode()


def mint(cls, **fields):
    value = object.__new__(cls)
    for name, item in fields.items():
        object.__setattr__(value, name, item)
    return value


def target(epoch=EPOCH, profiles=()):
    return mint(
        AdmittedTargetRegistration,
        target_registration_id=TARGET_ID,
        repository_id=REPOSITORY,
        policy_epoch_identity=epoch,
        controlled_runtime_profile_ids=tuple(profiles),
    )


def config_identity(config_id, marker="1"):
    return TrustedConfigIdentity(
        ImmutableConfigId(config_id), RootManagedResourceId("resource-" + config_id),
        RawSha256(marker * 64),
    )


def resolved_binding(config_id, *, epoch=EPOCH, marker="1"):
    return mint(
        ResolvedTrustedConfigBinding,
        policy_epoch_identity=epoch,
        config_identity=config_identity(config_id, marker),
    )


def evaluator_resolution(config_id="evaluator-v1", *, epoch=EPOCH, marker="1", mechanism=EvaluatorMechanism.DETERMINISTIC, valid=True, applicable=True, prerequisites=()):
    return mint(
        TrustedEvaluatorConfigResolution,
        binding=resolved_binding(config_id, epoch=epoch, marker=marker),
        mechanism=mechanism,
        parameters_valid=valid,
        applicable=applicable,
        operational_prerequisites=tuple(prerequisites),
    )


def runtime_resolution(config_id, *, epoch=EPOCH, marker="1", applicable=True):
    return mint(
        TrustedRuntimeConfigResolution,
        binding=resolved_binding(config_id, epoch=epoch, marker=marker),
        applicable=applicable,
    )


def schema_binding(epoch=EPOCH, *, digest=SUPPORTED_ISSUE_CONTRACT_SCHEMA_RAW_SHA256, kind=RootManagedResourceKind.TRUSTED_SCHEMA, version="1.0"):
    return mint(
        TrustedIssueContractSchemaBinding,
        policy_epoch_identity=epoch,
        schema_resource=RootManagedResourceRef(
            RootManagedResourceId("issue-contract-schema"), kind, RawSha256(digest),
        ),
        schema_version=version,
    )


def admission_context(candidate, *, epoch=EPOCH, schema=None, resolved_target=None, issue=True, base=True, root=True, evaluators=None, approvals=(), runtimes=(), repair=None, enforcement=False):
    issue_value = None if not issue else mint(
        TrustedIssueIdentityObservation,
        repository_id=REPOSITORY, issue_number=27, issue_id=LogicalIdentifier("I_kwDO27"),
        authoritative_state_binding_id=AuthoritativeStateBindingId("issue-binding"),
    )
    base_value = None if not base else mint(
        TrustedContractBaseObservation,
        repository_id=REPOSITORY, ref=BASE_REF, sha=BASE_SHA,
        authoritative_state_binding_id=AuthoritativeStateBindingId("base-binding"),
    )
    root_value = None if not root else mint(
        TrustedContractRootContext,
        policy_epoch_identity=epoch, repository_id=REPOSITORY,
        root_protected_mutation_scope=MutationScope((MutationScopeRule(
            ExactPathSelector(CanonicalGitPath("trusted/core.py")), tuple(ChangeType),
        ),)), determinate=True,
    )
    if evaluators is None:
        evaluators = tuple(evaluator_resolution(item.evaluator_ref.value, epoch=epoch)
                           for requirement in candidate.acceptance_requirements for item in requirement.evaluators)
    return mint(
        TrustedIssueContractAdmissionContext,
        policy_epoch_identity=epoch,
        schema_binding=schema_binding(epoch) if schema is None else schema,
        resolved_target=target(epoch) if resolved_target is None else resolved_target,
        issue_identity=issue_value, base_observation=base_value,
        evaluator_resolutions=tuple(evaluators), approval_resolutions=tuple(approvals),
        runtime_resolutions=tuple(runtimes), root_context=root_value,
        repair_policy_context=repair, operation_approval_enforcement_available=enforcement,
        admission_event_identity=LogicalIdentifier("contract-admission"),
    )


def admitted(value=None, **context_changes):
    candidate = load_candidate_issue_contract(raw_bytes(value))
    result = admit_issue_contract(candidate, admission_context(candidate, **context_changes))
    assert result.reason_code is IssueContractAdmissionReasonCode.ADMITTED
    return candidate, result.proposed_contract


def applicability_context(contract, *, epoch=EPOCH, base_sha=BASE_SHA, evaluator_epoch=None, evaluator_marker="1", target_value=None, root_value=None, runtimes=(), repair=None):
    evaluator_epoch = epoch if evaluator_epoch is None else evaluator_epoch
    evaluators = tuple(
        evaluator_resolution(item.evaluator_ref.value, epoch=evaluator_epoch, marker=evaluator_marker, mechanism=item.mechanism)
        for requirement in contract.acceptance_plan.requirements for item in requirement.evaluators
    )
    base = mint(
        TrustedContractBaseObservation, repository_id=REPOSITORY, ref=BASE_REF, sha=base_sha,
        authoritative_state_binding_id=AuthoritativeStateBindingId("base-binding-current"),
    )
    root = root_value or mint(
        TrustedContractRootContext, policy_epoch_identity=epoch, repository_id=REPOSITORY,
        root_protected_mutation_scope=MutationScope(()), determinate=True,
    )
    return mint(
        TrustedIssueContractApplicabilityContext,
        policy_epoch_identity=epoch, schema_binding=schema_binding(epoch),
        resolved_target=target(epoch) if target_value is None else target_value,
        base_observation=base, evaluator_resolutions=evaluators,
        runtime_resolutions=tuple(runtimes), root_context=root,
        repair_policy_context=repair, operation_approval_enforcement_available=False,
    )


def test_exact_schema_literal_and_raw_byte_identity_are_frozen():
    assert SUPPORTED_ISSUE_CONTRACT_SCHEMA_RAW_SHA256 == "05fa0aa4a4a8efe813a0a6e03bdbe451a5c980835645190828f351919c08a51f"
    compact = load_candidate_issue_contract(raw_bytes())
    indented = load_candidate_issue_contract(raw_bytes(indent=2))
    assert compact.contract_id == indented.contract_id
    assert compact.source_document.value == indented.source_document.value
    assert compact.source_document.raw_sha256 != indented.source_document.raw_sha256
    assert compact.source_document.raw_bytes != indented.source_document.raw_bytes


@pytest.mark.parametrize("raw,code", [
    ("not-bytes", IssueContractFailureCode.INVALID_INPUT_TYPE),
    (b"[", IssueContractFailureCode.PARSE_FAILED),
    (b"[]", IssueContractFailureCode.INVALID_TOP_LEVEL),
    (b"{}", IssueContractFailureCode.MISSING_FIELD),
])
def test_closed_structural_failures(raw, code):
    failure = load_candidate_issue_contract(raw)
    assert type(failure) is IssueContractFailure
    assert failure.code is code
    assert set(IssueContractFailureCode) == {
        IssueContractFailureCode.INVALID_INPUT_TYPE, IssueContractFailureCode.BYTE_LIMIT_EXCEEDED,
        IssueContractFailureCode.PARSE_FAILED, IssueContractFailureCode.INVALID_TOP_LEVEL,
        IssueContractFailureCode.MISSING_FIELD, IssueContractFailureCode.UNKNOWN_FIELD,
        IssueContractFailureCode.INVALID_FIELD_TYPE, IssueContractFailureCode.INVALID_FIELD_VALUE,
        IssueContractFailureCode.DUPLICATE_IDENTITY, IssueContractFailureCode.EMPTY_REQUIRED_SET,
        IssueContractFailureCode.INCONSISTENT_CONFIGURATION,
    }


def test_structural_failure_precedence_is_not_implementation_accidental():
    value = raw_value()
    value.pop("schema_version")
    value["unknown"] = 1
    value["contract_id"] = 1
    assert load_candidate_issue_contract(raw_bytes(value)).code is IssueContractFailureCode.MISSING_FIELD
    value["schema_version"] = "wrong"
    assert load_candidate_issue_contract(raw_bytes(value)).code is IssueContractFailureCode.UNKNOWN_FIELD
    value.pop("unknown")
    assert load_candidate_issue_contract(raw_bytes(value)).code is IssueContractFailureCode.INVALID_FIELD_TYPE
    value["contract_id"] = "contract"
    assert load_candidate_issue_contract(raw_bytes(value)).code is IssueContractFailureCode.INVALID_FIELD_VALUE


@pytest.mark.parametrize("mutation", ["requirement", "evaluation", "approval"])
def test_duplicate_global_identities_are_rejected_after_values(mutation):
    value = raw_value()
    if mutation == "requirement":
        value["acceptance_requirements"].append(dict(value["acceptance_requirements"][0]))
    elif mutation == "evaluation":
        value["acceptance_requirements"][0]["evaluators"].append(dict(value["acceptance_requirements"][0]["evaluators"][0]))
    else:
        value["human_approval_requirements"] = [
            {"approval_id": "same", "before_operation": "implementation", "approval_ref": "approval"},
            {"approval_id": "same", "before_operation": "implementation", "approval_ref": "approval"},
        ]
    assert load_candidate_issue_contract(raw_bytes(value)).code is IssueContractFailureCode.DUPLICATE_IDENTITY


def test_scope_rule_array_duplicates_are_accepted_but_rule_change_type_duplicates_are_not():
    value = raw_value()
    allowed = dict(value["scope"]["allowed_changes"][0])
    value["scope"]["allowed_changes"].append(allowed)
    prohibited = {
        "selector": {"kind": "exact_path", "path": "blocked.py"},
        "change_types": ["modify"],
    }
    value["scope"]["prohibited_changes"] = [prohibited, dict(prohibited)]
    candidate = load_candidate_issue_contract(raw_bytes(value))
    assert type(candidate) is CandidateIssueContract
    assert len(candidate.allowed_mutation_scope.rules) == 1
    assert len(candidate.prohibited_mutation_scope.rules) == 1

    value = raw_value()
    value["scope"]["allowed_changes"][0]["change_types"] = ["modify", "modify"]
    assert load_candidate_issue_contract(raw_bytes(value)).code is IssueContractFailureCode.DUPLICATE_IDENTITY


@pytest.mark.parametrize("max_depth", [65, 1_000_000])
def test_positive_delegation_depth_has_no_implementation_only_schema_ceiling(max_depth):
    value = raw_value()
    value["delegation_limits"] = {
        "max_depth": max_depth,
        "delegable_operations": ["implementation"],
        "risk_ceiling": "routine",
    }
    candidate = load_candidate_issue_contract(raw_bytes(value))
    assert type(candidate) is CandidateIssueContract
    assert candidate.delegation_limits.max_depth == max_depth


def test_required_empty_and_cross_field_rules_are_exact():
    empty = raw_value(requested_operations=[])
    assert load_candidate_issue_contract(raw_bytes(empty)).code is IssueContractFailureCode.EMPTY_REQUIRED_SET
    merge = raw_value(requested_operations=["merge"])
    assert load_candidate_issue_contract(raw_bytes(merge)).code is IssueContractFailureCode.INCONSISTENT_CONFIGURATION
    runtime = raw_value(requested_operations=["controlled_runtime"])
    assert load_candidate_issue_contract(raw_bytes(runtime)).code is IssueContractFailureCode.EMPTY_REQUIRED_SET
    repair = raw_value(requested_operations=["repair"])
    assert load_candidate_issue_contract(raw_bytes(repair)).code is IssueContractFailureCode.INCONSISTENT_CONFIGURATION


def test_candidate_is_deeply_immutable_and_prose_has_no_structured_effect():
    candidate = load_candidate_issue_contract(raw_bytes())
    assert candidate.requested_operations == (TaskCapability.IMPLEMENTATION, TaskCapability.TARGET_PUBLISH)
    assert candidate.runtime_profile_ids == () and candidate.repair_max_attempts == 0
    with pytest.raises(FrozenInstanceError):
        candidate.objective = "changed"
    with pytest.raises(TypeError):
        candidate.acceptance_requirements[0].evaluators[0].parameters["new"] = True


@pytest.mark.parametrize("value,expected_hex", [
    (None, "00"), (False, "01"), (True, "02"),
    ("", "030000000000000000"),
    ("雪", "030000000000000003e99baa"),
    (Decimal("1"), "04000000000000000001010000000000000000"),
    (Decimal("1.0"), "040000000000000000020100ffffffffffffffff"),
    (Decimal("-0"), "04010000000000000001000000000000000000"),
    (Decimal("1E+3"), "04000000000000000001010000000000000003"),
    ((), "050000000000000000"),
    (MappingProxyType({}), "060000000000000000"),
])
def test_exact_parameter_encoding_fixed_vectors(value, expected_hex):
    assert encode_contract_json_value(value).hex() == expected_hex


def test_parameter_digest_object_order_array_order_decimal_representation():
    left = MappingProxyType({"b": Decimal("2"), "a": (Decimal("1"), True)})
    right = MappingProxyType({"a": (Decimal("1"), True), "b": Decimal("2")})
    assert contract_json_value_digest(left) == contract_json_value_digest(right)
    assert contract_json_value_digest(("a", "b")) != contract_json_value_digest(("b", "a"))
    assert contract_json_value_digest(Decimal("1")) != contract_json_value_digest(Decimal("1.0"))
    nested = MappingProxyType({"x": (MappingProxyType({"雪": None}), False)})
    assert contract_json_value_digest(nested).value == hashlib.sha256(
        b"autodev.contract-json-value/v1\0" + encode_contract_json_value(nested)
    ).hexdigest()


def test_admission_preserves_independent_target_publish_ceiling_and_exact_projection():
    candidate, contract = admitted()
    assert TaskCapability.TARGET_PUBLISH not in target().allowed_task_capabilities if hasattr(target(), "allowed_task_capabilities") else True
    ceiling = derive_contract_authority_ceiling(contract)
    assert ceiling.requested_capabilities == candidate.requested_operations
    assert ceiling.integration_ref is None
    assert contract.acceptance_plan.requirements[0].evaluators[0].parameter_value_digest == contract_json_value_digest(
        candidate.acceptance_requirements[0].evaluators[0].parameters
    )


def test_schema_target_epoch_anchor_base_and_root_precedence():
    candidate = load_candidate_issue_contract(raw_bytes())
    bad_schema = schema_binding(digest="f" * 64)
    assert admit_issue_contract(candidate, admission_context(candidate, schema=bad_schema)).reason_code is IssueContractAdmissionReasonCode.UNSUPPORTED_SCHEMA_BINDING
    assert admit_issue_contract(candidate, admission_context(candidate, resolved_target=target(LATER_EPOCH))).reason_code is IssueContractAdmissionReasonCode.TARGET_POLICY_EPOCH_MISMATCH
    wrong_issue = admission_context(candidate)
    object.__setattr__(wrong_issue.issue_identity, "issue_id", LogicalIdentifier("other"))
    assert admit_issue_contract(candidate, wrong_issue).reason_code is IssueContractAdmissionReasonCode.CONTEXT_ANCHOR_MISMATCH
    wrong_base = admission_context(candidate)
    object.__setattr__(wrong_base.base_observation, "sha", GitSha("e" * 40))
    assert admit_issue_contract(candidate, wrong_base).reason_code is IssueContractAdmissionReasonCode.BASE_BINDING_MISMATCH
    wrong_root = admission_context(candidate)
    object.__setattr__(wrong_root.root_context, "repository_id", GitHubRepositoryId("999"))
    assert admit_issue_contract(candidate, wrong_root).reason_code is IssueContractAdmissionReasonCode.ROOT_CONTEXT_BINDING_MISMATCH


def test_root_carveout_is_exact_and_partial_overlap_denies():
    broad = MutationScope((MutationScopeRule(RepositorySelector(), (ChangeType.MODIFY,)),))
    root = MutationScope((MutationScopeRule(ExactPathSelector(CanonicalGitPath("trusted/core.py")), (ChangeType.MODIFY,)),))
    exact_carveout = MutationScope((MutationScopeRule(ExactPathSelector(CanonicalGitPath("trusted/core.py")), (ChangeType.MODIFY,)),))
    assert evaluate_effective_root_overlap(broad, exact_carveout, root) is EffectiveRootOverlap.PROVEN_DISJOINT
    assert evaluate_effective_root_overlap(broad, MutationScope(()), root) is EffectiveRootOverlap.EFFECTIVE_OVERLAP


def test_config_freshness_rebinding_and_base_movement_are_closed():
    _, contract = admitted()
    assert evaluate_issue_contract_applicability(contract, applicability_context(contract)).outcome is IssueContractApplicabilityCode.APPLICABLE
    moved = evaluate_issue_contract_applicability(contract, applicability_context(contract, base_sha=GitSha("e" * 40)))
    assert moved.outcome is IssueContractApplicabilityCode.BASE_CHANGED
    stale = evaluate_issue_contract_applicability(contract, applicability_context(contract, evaluator_epoch=LATER_EPOCH))
    assert stale.outcome is IssueContractApplicabilityCode.CONFIG_POLICY_EPOCH_MISMATCH
    rebound = evaluate_issue_contract_applicability(contract, applicability_context(contract, evaluator_marker="2"))
    assert rebound.outcome is IssueContractApplicabilityCode.CONFIG_BINDING_CHANGED
    fresh_same = applicability_context(contract, epoch=LATER_EPOCH, evaluator_epoch=LATER_EPOCH)
    assert evaluate_issue_contract_applicability(contract, fresh_same).outcome is IssueContractApplicabilityCode.APPLICABLE


def test_current_schema_epoch_mismatch_denies_instead_of_escalating():
    _, contract = admitted()
    current = applicability_context(contract, epoch=LATER_EPOCH, evaluator_epoch=LATER_EPOCH)
    object.__setattr__(current.schema_binding, "policy_epoch_identity", EPOCH)
    result = evaluate_issue_contract_applicability(contract, current)
    assert result.decision is Decision.DENY
    assert result.outcome is IssueContractApplicabilityCode.SCHEMA_BINDING_MISMATCH


def test_current_indeterminate_root_context_escalates():
    _, contract = admitted()
    indeterminate_root = mint(
        TrustedContractRootContext,
        policy_epoch_identity=EPOCH,
        repository_id=REPOSITORY,
        root_protected_mutation_scope=MutationScope(()),
        determinate=False,
    )
    result = evaluate_issue_contract_applicability(
        contract, applicability_context(contract, root_value=indeterminate_root),
    )
    assert result.decision is Decision.ESCALATE
    assert result.outcome is IssueContractApplicabilityCode.ROOT_CONTEXT_UNAVAILABLE


def test_current_indeterminate_root_overlap_escalates(monkeypatch):
    _, contract = admitted()
    monkeypatch.setattr(
        contract_module,
        "evaluate_effective_root_overlap",
        lambda *_: EffectiveRootOverlap.INDETERMINATE,
    )
    result = evaluate_issue_contract_applicability(contract, applicability_context(contract))
    assert result.decision is Decision.ESCALATE
    assert result.outcome is IssueContractApplicabilityCode.ROOT_CONTEXT_UNAVAILABLE


def test_current_proven_root_overlap_denies():
    _, contract = admitted()
    overlapping_root = mint(
        TrustedContractRootContext,
        policy_epoch_identity=EPOCH,
        repository_id=REPOSITORY,
        root_protected_mutation_scope=MutationScope((MutationScopeRule(
            ExactPathSelector(CanonicalGitPath("src/app.py")), (ChangeType.MODIFY,),
        ),)),
        determinate=True,
    )
    result = evaluate_issue_contract_applicability(
        contract, applicability_context(contract, root_value=overlapping_root),
    )
    assert result.decision is Decision.DENY
    assert result.outcome is IssueContractApplicabilityCode.ROOT_SCOPE_OVERLAP


def test_evaluator_parameter_mechanism_and_prerequisite_fail_closed():
    candidate = load_candidate_issue_contract(raw_bytes())
    cases = (
        (evaluator_resolution(mechanism=EvaluatorMechanism.SEMANTIC), IssueContractAdmissionReasonCode.EVALUATOR_CONFIG_MISMATCH),
        (evaluator_resolution(valid=False), IssueContractAdmissionReasonCode.EVALUATOR_PARAMETERS_INVALID),
        (evaluator_resolution(prerequisites=(TaskCapability.MERGE,)), IssueContractAdmissionReasonCode.EVALUATOR_OPERATION_OUTSIDE_CONTRACT),
    )
    for resolution, expected in cases:
        assert admit_issue_contract(candidate, admission_context(candidate, evaluators=(resolution,))).reason_code is expected


def test_operation_approval_and_delegation_fail_at_admission_not_from_prose():
    value = raw_value()
    value["human_approval_requirements"] = [{
        "approval_id": "approval", "before_operation": "implementation", "approval_ref": "approval-v1",
    }]
    candidate = load_candidate_issue_contract(raw_bytes(value))
    approval = mint(TrustedApprovalConfigResolution, binding=resolved_binding("approval-v1"), applicable=True)
    result = admit_issue_contract(candidate, admission_context(candidate, approvals=(approval,)))
    assert result.reason_code is IssueContractAdmissionReasonCode.APPROVAL_ENFORCEMENT_UNAVAILABLE
    value = raw_value()
    value["delegation_limits"] = {"max_depth": 1, "delegable_operations": ["merge"], "risk_ceiling": "routine"}
    candidate = load_candidate_issue_contract(raw_bytes(value))
    assert admit_issue_contract(candidate, admission_context(candidate)).reason_code is IssueContractAdmissionReasonCode.DELEGATION_NOT_PERMITTED


def test_canonical_create_replay_conflict_and_raw_projection_forgery():
    _, contract = admitted()
    backend = InMemoryCanonicalStateBackend()
    result = backend.apply(CanonicalTransaction(backend.occurrence, (), (CreateContract(contract),)))
    assert result.status is CanonicalWriteStatus.APPLIED
    assert backend.read_contract(contract.contract_id) is contract
    assert backend.apply(CanonicalTransaction(backend.occurrence, (), (CreateContract(contract),))).status is CanonicalWriteStatus.ALREADY_PRESENT
    forged = mint(AdmittedIssueContract, **{
        field: getattr(contract, field) for field in contract.__slots__
    })
    object.__setattr__(forged, "base_sha", GitSha("e" * 40))
    other = InMemoryCanonicalStateBackend()
    assert other.apply(CanonicalTransaction(other.occurrence, (), (CreateContract(forged),))).status is CanonicalWriteStatus.INVALID_TRANSACTION


def test_same_contract_id_with_byte_distinct_valid_representation_is_a_canonical_conflict():
    compact_candidate, compact = admitted()
    indented_raw = raw_bytes(indent=2)
    indented_candidate = load_candidate_issue_contract(indented_raw)
    indented_result = admit_issue_contract(indented_candidate, admission_context(indented_candidate))
    assert indented_result.reason_code is IssueContractAdmissionReasonCode.ADMITTED
    assert compact.contract_id == indented_result.proposed_contract.contract_id
    assert compact.contract_raw_sha256 != indented_result.proposed_contract.contract_raw_sha256
    backend = InMemoryCanonicalStateBackend()
    assert backend.apply(CanonicalTransaction(backend.occurrence, (), (CreateContract(compact),))).status is CanonicalWriteStatus.APPLIED
    assert backend.apply(CanonicalTransaction(
        backend.occurrence, (), (CreateContract(indented_result.proposed_contract),)
    )).status is CanonicalWriteStatus.IDENTITY_CONFLICT


def test_current_schema_resource_identity_is_not_rebound_by_equal_version_or_digest():
    _, contract = admitted()
    current = applicability_context(contract)
    object.__setattr__(current.schema_binding.schema_resource, "resource_id", RootManagedResourceId("other-schema"))
    assert evaluate_issue_contract_applicability(contract, current).outcome is IssueContractApplicabilityCode.UNSUPPORTED_SCHEMA_BINDING


def test_state_root_v2_requires_contract_index_and_rejects_v1():
    root = CanonicalStateRootManifest("2", None, (), (), (), (), (), (), (), (), (), ())
    assert root.contract_index == () and root.indexes[0] is root.contract_index
    with pytest.raises(ValueError):
        CanonicalStateRootManifest("1", None, (), (), (), (), (), (), (), (), (), ())


def test_trusted_contexts_contracts_and_ceilings_are_not_caller_constructible():
    with pytest.raises(TypeError):
        TrustedIssueContractAdmissionContext()
    with pytest.raises(TypeError):
        TrustedIssueContractApplicabilityContext()
    with pytest.raises(TypeError):
        TrustedIssueContractSchemaBinding()
    with pytest.raises(TypeError):
        TrustedRepairPolicyContext()
    with pytest.raises(TypeError):
        AdmittedIssueContract()
    with pytest.raises(TypeError):
        derive_contract_authority_ceiling(object())


def test_unsupported_ref_model_is_structurally_retained_then_escalated():
    value = raw_value()
    value["target"]["base_ref"] = "refs/tags/v1"
    candidate = load_candidate_issue_contract(raw_bytes(value))
    assert type(candidate) is CandidateIssueContract
    assert admit_issue_contract(candidate, admission_context(candidate)).reason_code is IssueContractAdmissionReasonCode.UNSUPPORTED_REF_MODEL


def test_runtime_exact_binding_epoch_rebinding_and_target_applicability():
    value = raw_value(requested_operations=["implementation", "controlled_runtime"])
    value["runtime_requirements"] = {"allowed_profile_ids": ["runtime-v1"]}
    candidate = load_candidate_issue_contract(raw_bytes(value))
    resolution = runtime_resolution("runtime-v1")
    result = admit_issue_contract(candidate, admission_context(
        candidate, resolved_target=target(profiles=(ImmutableConfigId("runtime-v1"),)),
        runtimes=(resolution,),
    ))
    assert result.reason_code is IssueContractAdmissionReasonCode.ADMITTED
    contract = result.proposed_contract
    assert contract.runtime_profile_identities == (resolution.binding.config_identity,)
    current = applicability_context(
        contract, target_value=target(profiles=(ImmutableConfigId("runtime-v1"),)),
        runtimes=(runtime_resolution("runtime-v1"),),
    )
    assert evaluate_issue_contract_applicability(contract, current).outcome is IssueContractApplicabilityCode.APPLICABLE
    object.__setattr__(current.runtime_resolutions[0], "binding", resolved_binding("runtime-v1", marker="2"))
    assert evaluate_issue_contract_applicability(contract, current).outcome is IssueContractApplicabilityCode.CONFIG_BINDING_CHANGED


def test_repair_policy_is_exact_subject_bound_and_bounded():
    value = raw_value(requested_operations=["implementation", "repair"])
    value["repair_policy"] = {"max_attempts": 2}
    candidate = load_candidate_issue_contract(raw_bytes(value))
    repair = mint(
        TrustedRepairPolicyContext,
        policy_epoch_identity=EPOCH, target_registration_id=TARGET_ID,
        task_id=candidate.task_id, contract_id=candidate.contract_id,
        contract_raw_sha256=candidate.source_document.raw_sha256,
        repair_eligible=True, maximum_contract_repair_attempts=2,
    )
    assert admit_issue_contract(candidate, admission_context(candidate, repair=repair)).reason_code is IssueContractAdmissionReasonCode.ADMITTED
    wrong = mint(TrustedRepairPolicyContext, **{
        name: getattr(repair, name) for name in repair.__slots__
    })
    object.__setattr__(wrong, "contract_raw_sha256", RawSha256("f" * 64))
    assert admit_issue_contract(candidate, admission_context(candidate, repair=wrong)).reason_code is IssueContractAdmissionReasonCode.REPAIR_POLICY_BINDING_MISMATCH
    object.__setattr__(wrong, "contract_raw_sha256", candidate.source_document.raw_sha256)
    object.__setattr__(wrong, "repair_eligible", False)
    assert admit_issue_contract(candidate, admission_context(candidate, repair=wrong)).reason_code is IssueContractAdmissionReasonCode.REPAIR_NOT_PERMITTED
    object.__setattr__(wrong, "repair_eligible", True)
    object.__setattr__(wrong, "maximum_contract_repair_attempts", 1)
    assert admit_issue_contract(candidate, admission_context(candidate, repair=wrong)).reason_code is IssueContractAdmissionReasonCode.REPAIR_ATTEMPTS_NOT_PERMITTED


def test_frozen_35_stage_availability_precedence_is_explicit():
    candidate = load_candidate_issue_contract(raw_bytes())
    context = admission_context(candidate, issue=False, base=False, root=False, evaluators=())
    object.__setattr__(context, "schema_binding", None)
    object.__setattr__(context, "policy_epoch_identity", None)
    object.__setattr__(context, "resolved_target", None)
    object.__setattr__(context, "evaluator_resolutions", None)
    assert admit_issue_contract(candidate, context).reason_code is IssueContractAdmissionReasonCode.SCHEMA_CONTEXT_UNAVAILABLE
    object.__setattr__(context, "schema_binding", schema_binding())
    assert admit_issue_contract(candidate, context).reason_code is IssueContractAdmissionReasonCode.POLICY_CONTEXT_UNAVAILABLE
    object.__setattr__(context, "policy_epoch_identity", EPOCH)
    assert admit_issue_contract(candidate, context).reason_code is IssueContractAdmissionReasonCode.TARGET_CONTEXT_UNAVAILABLE
    object.__setattr__(context, "resolved_target", target())
    assert admit_issue_contract(candidate, context).reason_code is IssueContractAdmissionReasonCode.CONTEXT_ANCHOR_UNAVAILABLE


def test_merge_implication_only_and_inert_integration_ref_projection():
    value = raw_value()
    value["target"]["integration_ref"] = "refs/heads/release"
    candidate, contract = admitted(value)
    assert candidate.target.integration_ref.value == "refs/heads/release"
    assert contract.integration_ref.value == "refs/heads/release"
    assert derive_contract_authority_ceiling(contract).integration_ref is None


def test_requested_operations_are_only_an_unordered_ceiling():
    _, contract = admitted()
    assert contract.requested_operations == (TaskCapability.IMPLEMENTATION, TaskCapability.TARGET_PUBLISH)
    assert not hasattr(contract, "required_protected_operation_ids")
    assert not hasattr(contract, "operation_ids")
    assert not hasattr(contract, "next_integration_operation_id")
