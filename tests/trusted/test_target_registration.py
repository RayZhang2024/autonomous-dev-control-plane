import copy
import hashlib
import json

import pytest

from autodev_control.trusted.decision import Decision
from autodev_control.trusted.errors import (
    TargetRegistrationAdmissionReasonCode,
    TargetRegistrationFailure,
    TargetRegistrationFailureCode,
)
from autodev_control.trusted.identity import ImmutableConfigId, RawSha256
from autodev_control.trusted.manifest import PolicyEpochIdentity, TrustedManifestId
from autodev_control.trusted.scope import (
    AuthenticationEventId,
    ChangeType,
    GitHubRepositoryId,
    HumanPrincipalId,
    MutationScope,
    MutationScopeRule,
    RepositorySelector,
    RiskRelation,
    RiskTier,
    ServicePrincipalId,
    TaskCapability,
)
from autodev_control.trusted.target_registration import (
    G3_MAX_DEPTH,
    G3_TARGET_REGISTRATION_MAX_BYTES,
    AdmittedTargetRegistration,
    CandidateTargetRegistration,
    TargetRegistrationRootImpact,
    _authenticated_target_admin_approval_for_test,
    _target_registration_policy_context_for_test,
    _target_registration_root_assessment_for_test,
    _target_result,
    admit_target_registration,
    load_candidate_target_registration,
)


def registration() -> dict[str, object]:
    return {
        "format": "autodev.target-registration/v1",
        "repository": {"platform": "github", "repository_id": "1363823008", "display_name": "owner/repo"},
        "path_model": "git_utf8_regular_file/v1",
        "protected_refs": ["refs/heads/main"],
        "allowed_task_capabilities": ["implementation", "deterministic_validation"],
        "ordinary_allowed_scope": [{"selector": {"kind": "repository"}, "change_types": ["add", "modify"]}],
        "ordinary_forbidden_scope": [],
        "risk_ceiling": "supervised",
        "target_publication": None,
        "merge": None,
        "validation_profile_ids": ["validation"],
        "controlled_runtime_profile_ids": [],
        "event_state_profile_ids": ["event"],
        "adapter_config_id": "adapter",
    }


def encode(value: object, *, pretty: bool = False) -> bytes:
    return json.dumps(value, ensure_ascii=False, indent=2 if pretty else None, separators=None if pretty else (",", ":")).encode()


def candidate(value: dict[str, object] | None = None) -> CandidateTargetRegistration:
    result = load_candidate_target_registration(encode(value or registration()))
    assert isinstance(result, CandidateTargetRegistration)
    return result


def epoch(char: str = "e") -> PolicyEpochIdentity:
    return PolicyEpochIdentity(TrustedManifestId(RawSha256(char * 64)))


def all_scope() -> MutationScope:
    return MutationScope((MutationScopeRule(RepositorySelector(), tuple(ChangeType)),))


def risk_relation(*, comparable: bool = True) -> RiskRelation:
    edges = [
        (RiskTier.ROUTINE, RiskTier.ROUTINE),
        (RiskTier.SUPERVISED, RiskTier.SUPERVISED),
    ]
    if comparable:
        edges.append((RiskTier.ROUTINE, RiskTier.SUPERVISED))
    return RiskRelation(tuple(edges))


def contexts(item: CandidateTargetRegistration, impact=TargetRegistrationRootImpact.NO_ROOT_IMPACT):
    principal = HumanPrincipalId("admin")
    current_epoch = epoch()
    approval = _authenticated_target_admin_approval_for_test(
        human_principal_id=principal,
        authentication_event_id=AuthenticationEventId("auth-event"),
        target_registration_id=item.target_registration_id,
        policy_epoch_identity=current_epoch,
    )
    assessment = _target_registration_root_assessment_for_test(
        target_registration_id=item.target_registration_id,
        repository_id=item.repository_id,
        policy_epoch_identity=current_epoch,
        root_impact=impact,
    )
    policy = _target_registration_policy_context_for_test(
        policy_epoch_identity=current_epoch,
        target_registration_id=item.target_registration_id,
        repository_id=item.repository_id,
        permitted_admin_principals=(principal,),
        maximum_allowed_task_capabilities=tuple(TaskCapability),
        maximum_ordinary_allowed_scope=all_scope(),
        maximum_target_risk_ceiling=RiskTier.SUPERVISED,
        permitted_target_publication_service_identities=(ServicePrincipalId("publisher"),),
        permitted_merge_service_identities=(ServicePrincipalId("merger"),),
        permitted_publication_profile_ids=(ImmutableConfigId("publish-profile"),),
        permitted_merge_profile_ids=(ImmutableConfigId("merge-profile"),),
        permitted_validation_profile_ids=(ImmutableConfigId("validation"),),
        permitted_controlled_runtime_profile_ids=(ImmutableConfigId("runtime"),),
        permitted_event_state_profile_ids=(ImmutableConfigId("event"),),
        permitted_adapter_config_ids=(ImmutableConfigId("adapter"),),
        risk_relation=risk_relation(),
    )
    return approval, policy, assessment


def test_exact_parser_limits_and_raw_identity() -> None:
    raw = encode(registration())
    first = load_candidate_target_registration(raw)
    second = load_candidate_target_registration(raw)
    pretty = load_candidate_target_registration(encode(registration(), pretty=True))
    assert isinstance(first, CandidateTargetRegistration)
    assert first.target_registration_id.raw_sha256 == first.source_document.raw_sha256
    assert first.target_registration_id.raw_sha256.value == hashlib.sha256(raw).hexdigest()
    assert first.target_registration_id == second.target_registration_id
    assert first.target_registration_id != pretty.target_registration_id
    assert not hasattr(first, "policy_epoch_identity")
    assert G3_TARGET_REGISTRATION_MAX_BYTES == 1024 * 1024
    assert G3_MAX_DEPTH == 32
    assert {item.value for item in TargetRegistrationFailureCode} == {
        "INVALID_INPUT_TYPE", "BYTE_LIMIT_EXCEEDED", "PARSE_FAILED", "INVALID_TOP_LEVEL",
        "MISSING_FIELD", "UNKNOWN_FIELD", "INVALID_FIELD_TYPE", "INVALID_FIELD_VALUE",
        "DUPLICATE_IDENTITY", "EMPTY_REQUIRED_SET", "INCONSISTENT_CONFIGURATION",
    }


def test_loader_failure_precedence_and_closed_grammar() -> None:
    assert load_candidate_target_registration("bad").code is TargetRegistrationFailureCode.INVALID_INPUT_TYPE
    assert load_candidate_target_registration(b"x" * (G3_TARGET_REGISTRATION_MAX_BYTES + 1)).code is TargetRegistrationFailureCode.BYTE_LIMIT_EXCEEDED
    assert load_candidate_target_registration(b"{").code is TargetRegistrationFailureCode.PARSE_FAILED
    assert load_candidate_target_registration(b"[]").code is TargetRegistrationFailureCode.INVALID_TOP_LEVEL
    value = registration()
    del value["format"]
    value["unknown"] = True
    assert load_candidate_target_registration(encode(value)).code is TargetRegistrationFailureCode.MISSING_FIELD
    value = registration()
    value["unknown"] = True
    value["format"] = 1
    assert load_candidate_target_registration(encode(value)).code is TargetRegistrationFailureCode.UNKNOWN_FIELD
    value = registration()
    value["format"] = 1
    value["repository"] = []
    assert load_candidate_target_registration(encode(value)).code is TargetRegistrationFailureCode.INVALID_FIELD_TYPE
    value = registration()
    del value["repository"]["platform"]
    value["repository"]["unknown"] = True
    assert load_candidate_target_registration(encode(value)).code is TargetRegistrationFailureCode.MISSING_FIELD


def test_duplicate_source_order_and_configuration_consistency() -> None:
    accepted = candidate()
    assert accepted.allowed_task_capabilities == (
        TaskCapability.IMPLEMENTATION, TaskCapability.DETERMINISTIC_VALIDATION,
    )
    value = registration()
    value["protected_refs"].append("refs/heads/main")
    assert load_candidate_target_registration(encode(value)).code is TargetRegistrationFailureCode.DUPLICATE_IDENTITY
    value = registration()
    value["ordinary_allowed_scope"].append({"selector": {"kind": "repository"}, "change_types": ["modify", "add"]})
    assert load_candidate_target_registration(encode(value)).code is TargetRegistrationFailureCode.DUPLICATE_IDENTITY
    value = registration()
    value["allowed_task_capabilities"].append("target_publish")
    assert load_candidate_target_registration(encode(value)).code is TargetRegistrationFailureCode.INCONSISTENT_CONFIGURATION
    value = registration()
    value["allowed_task_capabilities"].append("controlled_runtime")
    assert load_candidate_target_registration(encode(value)).code is TargetRegistrationFailureCode.EMPTY_REQUIRED_SET


def test_publication_merge_and_ref_consistency() -> None:
    value = registration()
    value["allowed_task_capabilities"] += ["target_publish", "merge"]
    value["target_publication"] = {"service_identity": "same", "publication_profile_id": "publish-profile"}
    value["merge"] = {"service_identity": "same", "merge_profile_id": "merge-profile", "allowed_integration_refs": ["refs/heads/main"]}
    assert load_candidate_target_registration(encode(value)).code is TargetRegistrationFailureCode.INCONSISTENT_CONFIGURATION
    value["merge"]["service_identity"] = "merger"
    value["merge"]["allowed_integration_refs"] = []
    assert load_candidate_target_registration(encode(value)).code is TargetRegistrationFailureCode.EMPTY_REQUIRED_SET
    value["merge"]["allowed_integration_refs"] = ["refs/heads/release"]
    assert load_candidate_target_registration(encode(value)).code is TargetRegistrationFailureCode.INCONSISTENT_CONFIGURATION


def test_deferred_merge_duplicate_and_canonical_context_validation() -> None:
    value = registration()
    value["allowed_task_capabilities"].append("merge")
    value["merge"] = {
        "service_identity": "merger", "merge_profile_id": "merge-profile",
        "allowed_integration_refs": ["refs/heads/main", "refs/heads/main"],
    }
    value["adapter_config_id"] = ""
    assert load_candidate_target_registration(encode(value)).code is TargetRegistrationFailureCode.INVALID_FIELD_VALUE
    item = candidate()
    approval, policy, _ = contexts(item)
    fields = {name: getattr(policy, name) for name in policy.__dataclass_fields__}
    fields["permitted_admin_principals"] = (approval.human_principal_id, approval.human_principal_id)
    with pytest.raises(ValueError):
        _target_registration_policy_context_for_test(**fields)


def test_candidate_and_admitted_records_are_deeply_immutable_non_bearer() -> None:
    item = candidate()
    with pytest.raises(TypeError):
        CandidateTargetRegistration()
    with pytest.raises(AttributeError):
        item.protected_refs.append(object())
    with pytest.raises(AttributeError):
        item.ordinary_allowed_scope.rules[0].change_types += (ChangeType.DELETE,)
    approval, policy, assessment = contexts(item)
    result = admit_target_registration(item, approval, policy, assessment)
    assert result.decision is Decision.ALLOW
    admitted = result.admitted_registration
    assert isinstance(admitted, AdmittedTargetRegistration)
    assert admitted.policy_epoch_identity == policy.policy_epoch_identity
    assert admitted.approved_human_principal_id == approval.human_principal_id
    with pytest.raises(TypeError):
        AdmittedTargetRegistration()
    with pytest.raises(AttributeError):
        admitted.adapter_config_id = ImmutableConfigId("changed")


def test_target_admission_availability_root_and_identity_precedence() -> None:
    item = candidate()
    approval, policy, assessment = contexts(item)
    assert admit_target_registration(item, None, None, None).reason_code is TargetRegistrationAdmissionReasonCode.AUTHENTICATED_APPROVAL_UNAVAILABLE
    assert admit_target_registration(item, approval, None, None).reason_code is TargetRegistrationAdmissionReasonCode.POLICY_CONTEXT_UNAVAILABLE
    assert admit_target_registration(item, approval, policy, None).reason_code is TargetRegistrationAdmissionReasonCode.ROOT_ASSESSMENT_UNAVAILABLE
    _, _, root_impact = contexts(item, TargetRegistrationRootImpact.ROOT_IMPACT)
    denied = admit_target_registration(item, approval, policy, root_impact)
    assert denied.reason_code is TargetRegistrationAdmissionReasonCode.ROOT_IMPACT
    assert denied.decision is Decision.DENY
    _, _, indeterminate = contexts(item, TargetRegistrationRootImpact.INDETERMINATE)
    escalated = admit_target_registration(item, approval, policy, indeterminate)
    assert escalated.reason_code is TargetRegistrationAdmissionReasonCode.ROOT_IMPACT_INDETERMINATE
    assert escalated.decision is Decision.ESCALATE
    mismatched = _target_registration_root_assessment_for_test(
        target_registration_id=item.target_registration_id,
        repository_id=GitHubRepositoryId("1"),
        policy_epoch_identity=policy.policy_epoch_identity,
        root_impact=TargetRegistrationRootImpact.NO_ROOT_IMPACT,
    )
    assert admit_target_registration(item, approval, policy, mismatched).reason_code is TargetRegistrationAdmissionReasonCode.REPOSITORY_MISMATCH


def test_target_risk_relation_unavailable_and_policy_violation() -> None:
    item = candidate()
    approval, policy, assessment = contexts(item)
    unavailable_fields = {name: getattr(policy, name) for name in policy.__dataclass_fields__}
    unavailable_fields["maximum_target_risk_ceiling"] = RiskTier.ROUTINE
    unavailable_fields["risk_relation"] = risk_relation(comparable=False)
    unavailable = _target_registration_policy_context_for_test(**unavailable_fields)
    assert admit_target_registration(item, approval, unavailable, assessment).reason_code is TargetRegistrationAdmissionReasonCode.RISK_RELATION_UNAVAILABLE
    denying_fields = dict(unavailable_fields)
    denying_fields["risk_relation"] = risk_relation()
    denying = _target_registration_policy_context_for_test(**denying_fields)
    assert admit_target_registration(item, approval, denying, assessment).reason_code is TargetRegistrationAdmissionReasonCode.POLICY_RISK_VIOLATION


def test_target_service_and_profile_failures_are_distinct() -> None:
    value = registration()
    value["allowed_task_capabilities"].append("target_publish")
    value["target_publication"] = {
        "service_identity": "publisher", "publication_profile_id": "publish-profile",
    }
    item = candidate(value)
    approval, policy, assessment = contexts(item)
    fields = {name: getattr(policy, name) for name in policy.__dataclass_fields__}
    fields["permitted_target_publication_service_identities"] = ()
    no_service = _target_registration_policy_context_for_test(**fields)
    assert admit_target_registration(item, approval, no_service, assessment).reason_code is TargetRegistrationAdmissionReasonCode.POLICY_SERVICE_IDENTITY_VIOLATION
    fields = {name: getattr(policy, name) for name in policy.__dataclass_fields__}
    fields["permitted_publication_profile_ids"] = ()
    no_profile = _target_registration_policy_context_for_test(**fields)
    assert admit_target_registration(item, approval, no_profile, assessment).reason_code is TargetRegistrationAdmissionReasonCode.POLICY_CONFIG_VIOLATION


def test_exact_target_reason_decision_mapping() -> None:
    escalations = {
        TargetRegistrationAdmissionReasonCode.AUTHENTICATED_APPROVAL_UNAVAILABLE,
        TargetRegistrationAdmissionReasonCode.POLICY_CONTEXT_UNAVAILABLE,
        TargetRegistrationAdmissionReasonCode.ROOT_ASSESSMENT_UNAVAILABLE,
        TargetRegistrationAdmissionReasonCode.ROOT_IMPACT_INDETERMINATE,
        TargetRegistrationAdmissionReasonCode.RISK_RELATION_UNAVAILABLE,
    }
    for reason in TargetRegistrationAdmissionReasonCode:
        if reason is TargetRegistrationAdmissionReasonCode.ADMITTED:
            continue
        result = _target_result(reason)
        assert result.admitted_registration is None
        assert result.decision is (Decision.ESCALATE if reason in escalations else Decision.DENY)
