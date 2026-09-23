"""Focused Issue #32 v0.14 regressions.

The durable criterion-by-criterion authority and exact-test matrix is
``ISSUE32_V014_CRITERION_MATRIX.md`` beside this module.
"""

import inspect
import json
import hashlib
from dataclasses import fields, replace
from types import MappingProxyType

import pytest
import autodev_control.trusted.current_semantic_review as current_semantic_review
import autodev_control.trusted.backend as backend_module

from autodev_control.trusted.contract import (
    AdmittedIssueContract, CandidateIssueContract, ContractAcceptanceEvaluator,
    ContractAcceptancePlan, ContractAcceptanceRequirement, EvaluatorMechanism,
    ResolvedTrustedConfigBinding, TrustedConfigIdentity, TrustedContractBaseObservation,
    TrustedContractRootContext, TrustedEvaluatorConfigResolution,
    TrustedIssueContractApplicabilityContext, TrustedIssueContractSchemaBinding,
    IssueContextAnchor,
    contract_json_value_digest,
    load_candidate_issue_contract,
)
from autodev_control.trusted.current_semantic_review import (
    CurrentSemanticReviewResolutionReason, CurrentSemanticReviewResolutionStatus,
    SemanticEvaluatorObligationResolutionStatus,
    SemanticEvaluatorObligation,
    derive_current_review_materials, recover_semantic_evaluator_parameters, semantic_evaluator_obligation_id,
    resolve_current_semantic_review,
    semantic_requirement_id,
)
from autodev_control.trusted.semantic_config import (
    SemanticEvaluatorConfigResolutionReason, SemanticEvaluatorConfigResolutionStatus,
    SemanticEvaluatorConfigResolutionResult, TrustedSemanticEvaluatorResolution,
    SemanticReviewContextRequirement,
)
from autodev_control.trusted.authorization import AdmittedAuthorization
from autodev_control.trusted.backend import (
    BackendGeneration, CanonicalCurrentSemanticReviewInputs, CanonicalStateOccurrenceBinding,
    InMemoryCanonicalStateBackend, ResolvedTargetRegistration,
)
from autodev_control.trusted.identity import CandidateMaterializationId, ImmutableConfigId, LogicalIdentifier, RawSha256, SemanticEvaluatorObligationId
from autodev_control.trusted.operation import AdmissionEventId, EvidenceId
from autodev_control.trusted.resources import RootManagedResourceId, RootManagedResourceKind, RootManagedResourceRef
from tests.trusted.contract_fixtures import canonical_contract_fixture
from autodev_control.trusted.identity import GitSha
from autodev_control.trusted.manifest import PolicyEpochIdentity, TrustedManifestId
from autodev_control.trusted.scope import AuthorizationId, CanonicalBranchRef, ContractId, GitHubRepositoryId, MutationScope, TargetRegistrationId, TaskCapability, TaskId
from autodev_control.trusted.operation import CandidateId
from autodev_control.trusted.materialization import (
    FixtureGitCommit, FixtureGitObjectStore, FixtureGitTree, FixtureGitTreeEntry,
    GitObjectKind, MutationKind, TrustedCandidateMaterializationContext,
    admit_candidate_materialization,
)
from autodev_control.trusted.operation import AdmissionEventId
from autodev_control.trusted.state import CandidateRecord, RepairBudget, TaskRecord, TaskState
from autodev_control.trusted.target_registration import AdmittedTargetRegistration
from autodev_control.trusted.semantic_context import (
    CurrentSemanticPullRequestContextReason, CurrentSemanticPullRequestContextResolution,
    CurrentSemanticTargetContextReason, CurrentSemanticTargetContextResolution,
    SemanticContextResolutionStatus,
)
from autodev_control.trusted.state_reader import AuthoritativeStateDependency, StateReadFailure
from autodev_control.trusted.errors import ParseFailureCode, ResourceFailureCode
from autodev_control.trusted.evidence import EvidenceClass, EvidenceRecord, EvidenceSubject, SemanticEvidencePayload, SemanticReviewEvidenceBinding
from autodev_control.trusted.review import MaterialIdentity, PullRequestIdentity, ReviewInvocationId, ReviewSlotId, SemanticReviewAssignment, SemanticReviewEffectiveSubject, TargetContextId, SemanticRequirement, SemanticRequirementId, TrustedContextId
from autodev_control.trusted.operation import AuthoritativeStateBindingId


RAW = RawSha256("a" * 64)
CONTRACT_ID = ContractId("contract")
REPOSITORY = GitHubRepositoryId("123")
TARGET = TargetRegistrationId(RAW)
EPOCH = PolicyEpochIdentity(TrustedManifestId(RAW))
BASE = GitSha("b" * 40)


def _mint(cls, **values):
    result = object.__new__(cls)
    for name, value in values.items():
        object.__setattr__(result, name, value)
    return result


def _clone(value, **updates):
    values = {item.name: getattr(value, item.name) for item in fields(type(value))}
    values.update(updates)
    return _mint(type(value), **values)


def _semantic_config_bytes(*, target="NOT_APPLICABLE", pr="NOT_APPLICABLE", prerequisites=()):
    return json.dumps({
        "format": "autodev.semantic-evaluator-config/v1", "mechanism": "semantic",
        "operational_prerequisites": list(prerequisites),
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
        "target_context_requirement": target, "pr_context_requirement": pr,
    }, separators=(",", ":")).encode()


def _semantic_contract(*, statement="exact statement", evaluator_id="evaluation", evaluator_ref="evaluator-config", parameters=None, config_bytes=None, extra_evaluation_ids=()):
    raw, _, baseline = canonical_contract_fixture(
        contract_id=CONTRACT_ID, task_id=TaskId("task"), target_registration_id=TARGET,
        repository_id=REPOSITORY, policy_epoch_identity=EPOCH, base_sha=BASE,
    )
    value = json.loads(raw)
    value["acceptance_requirements"][0]["statement"] = statement
    item = value["acceptance_requirements"][0]["evaluators"][0]
    item["evaluation_id"] = evaluator_id
    item["evaluator_ref"] = evaluator_ref
    item["mechanism"] = "semantic"
    item["parameters"] = {} if parameters is None else parameters
    for extra_id in extra_evaluation_ids:
        extra = dict(item)
        extra["evaluation_id"] = extra_id
        value["acceptance_requirements"][0]["evaluators"].append(extra)
    raw = json.dumps(value, separators=(",", ":")).encode()
    parsed = load_candidate_issue_contract(raw)
    assert type(parsed) is CandidateIssueContract
    contract = object.__new__(AdmittedIssueContract)
    for item in fields(AdmittedIssueContract):
        object.__setattr__(contract, item.name, getattr(baseline, item.name))
    object.__setattr__(contract, "contract_raw_sha256", parsed.source_document.raw_sha256)
    object.__setattr__(contract, "raw_bytes", raw)
    config = TrustedConfigIdentity(
        ImmutableConfigId(evaluator_ref), RootManagedResourceId("resource"),
        RawSha256("c" * 64) if config_bytes is None else RawSha256(hashlib.sha256(config_bytes).hexdigest()),
    )
    evaluators = tuple(ContractAcceptanceEvaluator(
        item.evaluation_id, EvaluatorMechanism.SEMANTIC, ImmutableConfigId(evaluator_ref), config,
        contract_json_value_digest(item.parameters),
    ) for item in parsed.acceptance_requirements[0].evaluators)
    evaluator = evaluators[0]
    plan = ContractAcceptancePlan(
        CONTRACT_ID, parsed.source_document.raw_sha256,
        (ContractAcceptanceRequirement(
            parsed.acceptance_requirements[0].requirement_id,
            parsed.acceptance_requirements[0].statement, evaluators,
        ),),
    )
    object.__setattr__(contract, "acceptance_plan", plan)
    return contract, parsed, evaluator


def _semantic_contract_many(configs):
    """Build one admitted structural contract with independently addressed semantic configs."""
    raw, _, baseline = canonical_contract_fixture(
        contract_id=CONTRACT_ID, task_id=TaskId("task"), target_registration_id=TARGET,
        repository_id=REPOSITORY, policy_epoch_identity=EPOCH, base_sha=BASE,
    )
    value = json.loads(raw)
    entries = []
    for evaluation_id, evaluator_ref, config_bytes in configs:
        entries.append({
            "evaluation_id": evaluation_id, "mechanism": "semantic", "evaluator_ref": evaluator_ref,
            "parameters": {"evaluation": evaluation_id},
        })
    value["acceptance_requirements"][0]["evaluators"] = entries
    raw = json.dumps(value, separators=(",", ":")).encode()
    parsed = load_candidate_issue_contract(raw)
    assert type(parsed) is CandidateIssueContract
    contract = object.__new__(AdmittedIssueContract)
    for field in fields(AdmittedIssueContract):
        object.__setattr__(contract, field.name, getattr(baseline, field.name))
    object.__setattr__(contract, "contract_raw_sha256", parsed.source_document.raw_sha256)
    object.__setattr__(contract, "raw_bytes", raw)
    evaluator_by_ref = {ref: config for _, ref, config in configs}
    evaluators = tuple(
        ContractAcceptanceEvaluator(
            item.evaluation_id, EvaluatorMechanism.SEMANTIC, ImmutableConfigId(item.evaluator_ref.value),
            TrustedConfigIdentity(
                ImmutableConfigId(item.evaluator_ref.value), RootManagedResourceId("resource-" + item.evaluator_ref.value),
                RawSha256(hashlib.sha256(evaluator_by_ref[item.evaluator_ref.value]).hexdigest()),
            ), contract_json_value_digest(item.parameters),
        ) for item in parsed.acceptance_requirements[0].evaluators
    )
    plan = ContractAcceptancePlan(
        CONTRACT_ID, parsed.source_document.raw_sha256,
        (ContractAcceptanceRequirement(parsed.acceptance_requirements[0].requirement_id,
                                       parsed.acceptance_requirements[0].statement, evaluators),),
    )
    object.__setattr__(contract, "acceptance_plan", plan)
    return contract, parsed, evaluators


def _semantic_contract_matrix(configs):
    """Build up to 256 obligations without exceeding #27's 16-evaluator-per-requirement schema bound."""
    raw, _, baseline = canonical_contract_fixture(
        contract_id=CONTRACT_ID, task_id=TaskId("task"), target_registration_id=TARGET,
        repository_id=REPOSITORY, policy_epoch_identity=EPOCH, base_sha=BASE,
    )
    value = json.loads(raw)
    template = value["acceptance_requirements"][0]
    requirements = []
    for chunk_index in range(0, len(configs), 16):
        requirement = dict(template)
        requirement["requirement_id"] = f"requirement-{chunk_index // 16:03}"
        requirement["evaluators"] = [
            {"evaluation_id": evaluation_id, "mechanism": "semantic", "evaluator_ref": evaluator_ref,
             "parameters": {"evaluation": evaluation_id}}
            for evaluation_id, evaluator_ref, _ in configs[chunk_index:chunk_index + 16]
        ]
        requirements.append(requirement)
    value["acceptance_requirements"] = requirements
    raw = json.dumps(value, separators=(",", ":")).encode()
    parsed = load_candidate_issue_contract(raw)
    assert type(parsed) is CandidateIssueContract
    contract = object.__new__(AdmittedIssueContract)
    for field in fields(AdmittedIssueContract):
        object.__setattr__(contract, field.name, getattr(baseline, field.name))
    object.__setattr__(contract, "contract_raw_sha256", parsed.source_document.raw_sha256)
    object.__setattr__(contract, "raw_bytes", raw)
    bytes_by_ref = {ref: config for _, ref, config in configs}
    plan_requirements = []
    all_evaluators = []
    for raw_requirement in parsed.acceptance_requirements:
        evaluators = tuple(
            ContractAcceptanceEvaluator(
                evaluator.evaluation_id, EvaluatorMechanism.SEMANTIC,
                ImmutableConfigId(evaluator.evaluator_ref.value),
                TrustedConfigIdentity(
                    ImmutableConfigId(evaluator.evaluator_ref.value),
                    RootManagedResourceId("resource-" + evaluator.evaluator_ref.value),
                    RawSha256(hashlib.sha256(bytes_by_ref[evaluator.evaluator_ref.value]).hexdigest()),
                ),
                contract_json_value_digest(evaluator.parameters),
            ) for evaluator in raw_requirement.evaluators
        )
        all_evaluators.extend(evaluators)
        plan_requirements.append(ContractAcceptanceRequirement(
            raw_requirement.requirement_id, raw_requirement.statement, evaluators,
        ))
    plan = ContractAcceptancePlan(CONTRACT_ID, parsed.source_document.raw_sha256, tuple(plan_requirements))
    object.__setattr__(contract, "acceptance_plan", plan)
    return contract, parsed, tuple(all_evaluators)


def _trusted_reader(contract, raw_config_bytes):
    if type(raw_config_bytes) is dict:
        bytes_by_ref = raw_config_bytes
    else:
        bytes_by_ref = {item.evaluator_ref.value: raw_config_bytes
                        for requirement in contract.acceptance_plan.requirements
                        for item in requirement.evaluators}
    values = {}
    for requirement in contract.acceptance_plan.requirements:
        for evaluator in requirement.evaluators:
            resource = RootManagedResourceRef(
                evaluator.config_identity.resource_id, RootManagedResourceKind.TRUSTED_CONFIG,
                evaluator.config_identity.resource_sha256,
            )
            if evaluator.evaluator_ref.value in bytes_by_ref:
                values[resource] = bytes_by_ref[evaluator.evaluator_ref.value]
    return current_semantic_review._assemble_trusted_semantic_config_byte_reader(
        current_semantic_review._READER_KEY, MappingProxyType(values),
    )


def _dependency(marker="a"):
    return AuthoritativeStateDependency(
        REPOSITORY, ImmutableConfigId("profile-" + marker), ImmutableConfigId("transport-" + marker),
        AuthoritativeStateBindingId("binding-" + marker),
    )


def _resolved_product(*, contract=None, config_bytes=None, evaluation_id="evaluation"):
    config_bytes = _semantic_config_bytes() if config_bytes is None else config_bytes
    contract = _semantic_contract(config_bytes=config_bytes, evaluator_id=evaluation_id)[0] if contract is None else contract
    materialization = _materialization(CandidateId("current"), contract_raw=contract.contract_raw_sha256)
    result = resolve_current_semantic_review(
        _canonical_inputs(contract, candidate=_candidate(materialization, contract=contract), materialization=materialization),
        applicability_context=_current_applicability_context(contract), byte_reader=_trusted_reader(contract, config_bytes),
        semantic_context_source=None,
    )
    assert result.status is CurrentSemanticReviewResolutionStatus.RESOLVED
    assert len(result.obligation_outcomes) >= 1
    return result, contract, materialization


def _historical_evidence(current_outcome, *, evidence_id="historical-evidence", obligation_id=None,
                         materialization_id=None, slot_id=None, invocation_id=None,
                         nonsemantic=False, missing_binding=False):
    from tests.trusted.test_evidence import admit_semantic_review, fixture as g5_fixture

    admitted = admit_semantic_review(g5_fixture())
    assert admitted.proposed_evidence_record is not None
    record = admitted.proposed_evidence_record
    trusted = current_outcome.trusted_evaluator_resolution
    effective = current_outcome.effective_subject
    assert trusted is not None and effective is not None
    slot = trusted.review_slots[0]
    invocation_id = ReviewInvocationId("historical-invocation") if invocation_id is None else invocation_id
    slot_id = slot.slot_id if slot_id is None else slot_id
    current_subject = current_semantic_review.build_current_semantic_evidence_subject(
        current_outcome.resolved_obligation, slot, invocation_id,
    )
    obligation_id = current_outcome.obligation.obligation_id if obligation_id is None else obligation_id
    materialization_id = CandidateMaterializationId(RawSha256("9" * 64)) if materialization_id is None else materialization_id
    subject = replace(
        current_subject,
        repository_id=GitHubRepositoryId("999"),
        contract_id=ContractId("historical-contract"),
        contract_raw_sha256=RawSha256("7" * 64),
        task_admission_event_id=AdmissionEventId("historical-admission"),
        authorization_id=AuthorizationId(RawSha256("6" * 64)),
        target_registration_id=TargetRegistrationId(RawSha256("5" * 64)),
        policy_epoch_identity=PolicyEpochIdentity(TrustedManifestId(RawSha256("4" * 64))),
        base=GitSha("d" * 40),
        candidate_id=CandidateId("historical-candidate"),
        target_context_id=TargetContextId("historical-target"),
        pr_id=PullRequestIdentity("historical-pr"),
        required_material_ids=(MaterialIdentity("historical-material"),),
        required_context_ids=(TrustedContextId("historical-context"),),
        requirement_ids=(SemanticRequirementId("historical-requirement"),),
        profile_id=type(current_subject.profile_id)("historical-profile"),
        profile_config_id=ImmutableConfigId("historical-profile-config"),
        verdict_schema_id=ImmutableConfigId("historical-schema"),
        slot_id=slot_id,
        semantic_review_binding=SemanticReviewEvidenceBinding(obligation_id, materialization_id),
    )
    payload = replace(
        record.payload,
        effective_subject_id=type(record.payload.effective_subject_id)("historical-effective-subject"),
        slot_id=slot_id,
        invocation_id=invocation_id,
    )
    if nonsemantic:
        subject = replace(subject, semantic_review_binding=None)
        return replace(record, evidence_id=EvidenceId(evidence_id), evidence_class=EvidenceClass.DETERMINISTIC, subject=subject, payload=payload)
    if missing_binding:
        subject = replace(subject, semantic_review_binding=None)
        values = {item.name: getattr(record, item.name) for item in fields(EvidenceRecord)}
        values.update(evidence_id=EvidenceId(evidence_id), subject=subject, payload=payload)
        return _mint(EvidenceRecord, **values)
    return replace(record, evidence_id=EvidenceId(evidence_id), subject=subject, payload=payload)


def _reconstruction_backend(monkeypatch, evidence_record, inputs):
    store = InMemoryCanonicalStateBackend()
    evidence_id = evidence_record.evidence_id
    monkeypatch.setattr(
        InMemoryCanonicalStateBackend, "read_evidence",
        lambda self, requested: evidence_record if requested == evidence_id else None,
    )
    monkeypatch.setattr(
        InMemoryCanonicalStateBackend, "read_current_semantic_review_inputs",
        lambda self, task_id: inputs if task_id == inputs.task.task_id else None,
    )
    return store


def _canonical_backend_with_candidate(contract, candidate, materialization):
    from tests.trusted.test_backend import admitted_authorization, apply as g6_apply, task as g6_task
    from autodev_control.trusted.backend import (
        CreateAuthorization, CreateCandidateWithMaterialization, CreateContract,
        CreateTaskAndInitialOperationMembership, ReplaceTask,
    )

    target = _canonical_inputs(contract).resolved_target
    store = InMemoryCanonicalStateBackend((target,))
    authorization = _clone(
        admitted_authorization(), authorization_id=AuthorizationId(RAW),
        contract_id=contract.contract_id, contract_raw_sha256=contract.contract_raw_sha256,
        target_registration_id=contract.target_registration_id,
        policy_epoch_identity=contract.admission_policy_epoch_identity,
    )
    initial_task = _clone(
        g6_task(), contract_id=contract.contract_id, contract_raw_sha256=contract.contract_raw_sha256,
        authorization_id=authorization.authorization_id, target_registration_id=contract.target_registration_id,
        last_evaluated_policy_epoch_identity=contract.admission_policy_epoch_identity,
    )
    created = g6_apply(
        store, CreateContract(contract), CreateAuthorization(authorization),
        CreateTaskAndInitialOperationMembership(initial_task),
    )
    assert created.status.name == "APPLIED"
    evaluating = _clone(
        initial_task, revision=type(initial_task.revision)(2), state=TaskState.EVALUATING,
        current_candidate_id=candidate.candidate_id,
    )
    adopted = g6_apply(
        store, ReplaceTask(1, evaluating), CreateCandidateWithMaterialization(candidate, materialization),
    )
    assert adopted.status.name == "APPLIED"
    return store


def _target_success(dependencies=None):
    return CurrentSemanticTargetContextResolution(
        SemanticContextResolutionStatus.RESOLVED, CurrentSemanticTargetContextReason.RESOLVED,
        TargetContextId("target-context"), (_dependency(),) if dependencies is None else dependencies,
    )


def _pr_success(dependencies=None):
    return CurrentSemanticPullRequestContextResolution(
        SemanticContextResolutionStatus.RESOLVED, CurrentSemanticPullRequestContextReason.RESOLVED,
        PullRequestIdentity("pr-context"), (_dependency("p"),) if dependencies is None else dependencies,
    )


def _resolve_with_context_products(monkeypatch, *, target="NOT_APPLICABLE", pr="NOT_APPLICABLE", target_product=None, pr_product=None):
    config_bytes = _semantic_config_bytes(target=target, pr=pr)
    contract, _, _ = _semantic_contract(config_bytes=config_bytes)
    materialization = _materialization(CandidateId("current"), contract_raw=contract.contract_raw_sha256)
    calls = {"target": 0, "pr": 0}

    def target_resolver(*_):
        calls["target"] += 1
        return _target_success() if target_product is None else target_product

    def pr_resolver(*_):
        calls["pr"] += 1
        return _pr_success() if pr_product is None else pr_product

    monkeypatch.setattr(current_semantic_review, "resolve_current_semantic_target_context", target_resolver)
    monkeypatch.setattr(current_semantic_review, "resolve_current_semantic_pull_request_context", pr_resolver)
    result = resolve_current_semantic_review(
        _canonical_inputs(contract, candidate=_candidate(materialization, contract=contract), materialization=materialization),
        applicability_context=_current_applicability_context(contract), byte_reader=_trusted_reader(contract, config_bytes),
        semantic_context_source=None,
    )
    return result, calls


def _current_applicability_context(contract):
    """A complete G1 applicability input, deliberately independent of #33/B1."""
    target = _mint(
        AdmittedTargetRegistration, target_registration_id=TARGET,
        repository_id=REPOSITORY, policy_epoch_identity=EPOCH,
        controlled_runtime_profile_ids=(),
    )
    schema = _mint(
        TrustedIssueContractSchemaBinding, policy_epoch_identity=EPOCH,
        schema_resource=RootManagedResourceRef(
            contract.schema_resource_id, RootManagedResourceKind.TRUSTED_SCHEMA,
            contract.schema_resource_sha256,
        ), schema_version=contract.schema_version,
    )
    base = _mint(
        TrustedContractBaseObservation, repository_id=REPOSITORY,
        ref=CanonicalBranchRef("refs/heads/main"), sha=contract.base_sha,
        authoritative_state_binding_id=__import__("autodev_control.trusted.operation", fromlist=["AuthoritativeStateBindingId"]).AuthoritativeStateBindingId("base-current"),
    )
    root = _mint(
        TrustedContractRootContext, policy_epoch_identity=EPOCH, repository_id=REPOSITORY,
        root_protected_mutation_scope=MutationScope(()), determinate=True,
    )
    unique = {}
    for requirement in contract.acceptance_plan.requirements:
        for evaluator in requirement.evaluators:
            unique.setdefault(evaluator.evaluator_ref, evaluator)
    resolutions = tuple(
        _mint(
            TrustedEvaluatorConfigResolution,
            binding=_mint(ResolvedTrustedConfigBinding, policy_epoch_identity=EPOCH, config_identity=evaluator.config_identity),
            mechanism=evaluator.mechanism, parameters_valid=True, applicable=True,
            operational_prerequisites=(),
        ) for evaluator in unique.values()
    )
    return _mint(
        TrustedIssueContractApplicabilityContext,
        policy_epoch_identity=EPOCH, schema_binding=schema, resolved_target=target,
        base_observation=base, evaluator_resolutions=resolutions, runtime_resolutions=(),
        root_context=root, repair_policy_context=None,
        operation_approval_enforcement_available=False,
    )


def _canonical_inputs(contract, *, candidate=None, materialization=None, authorization=None,
                      task_contract_id=None, task_raw=None, target_id=TARGET, epoch=EPOCH):
    authorization = authorization or _mint(
        AdmittedAuthorization, authorization_id=AuthorizationId(RAW), task_id=TaskId("task"),
        contract_id=CONTRACT_ID, contract_raw_sha256=contract.contract_raw_sha256,
        target_registration_id=TARGET, policy_epoch_identity=EPOCH,
    )
    task = _mint(
        TaskRecord, task_id=TaskId("task"), revision=1, state=TaskState.ADMITTED,
        contract_id=CONTRACT_ID if task_contract_id is None else task_contract_id,
        contract_raw_sha256=contract.contract_raw_sha256 if task_raw is None else task_raw,
        authorization_id=authorization.authorization_id, admission_event_id=AdmissionEventId("admission"),
        target_registration_id=target_id, last_evaluated_policy_epoch_identity=epoch,
        current_candidate_id=None if candidate is None else candidate.candidate_id,
        next_integration_operation_id=None, supporting_evidence_refs=(), repair_budget=RepairBudget(0),
    )
    registration = _mint(
        AdmittedTargetRegistration, target_registration_id=target_id,
        repository_id=REPOSITORY, policy_epoch_identity=epoch, controlled_runtime_profile_ids=(),
    )
    target = _mint(
        ResolvedTargetRegistration, registration=registration, target_registration_id=target_id,
        root_config_id=ImmutableConfigId("root-target"), policy_epoch_identity=epoch,
    )
    return _mint(
        CanonicalCurrentSemanticReviewInputs,
        canonical_state_occurrence_binding=CanonicalStateOccurrenceBinding(BackendGeneration(1)),
        contract=contract, authorization=authorization, task=task,
        candidate=candidate, materialization=materialization, resolved_target=target,
    )


def _materialization(candidate_id: CandidateId, variant: str = "", *, base_entries=(), candidate_entries=None,
                     contract_raw=RAW, authorization_id=None, target_id=TARGET, epoch=EPOCH):
    commit = GitSha(("c" if not variant else "d") * 40)
    base_tree, result_tree = GitSha("e" * 40), GitSha("f" * 40)
    if candidate_entries is None:
        candidate_entries = (
            FixtureGitTreeEntry("candidate-" + variant + ".txt", GitObjectKind.BLOB, "100644", GitSha("1" * 40)),
        )
    store = FixtureGitObjectStore(
        REPOSITORY,
        (FixtureGitCommit(BASE, (), base_tree), FixtureGitCommit(commit, (BASE,), result_tree)),
        (FixtureGitTree(base_tree, base_entries), FixtureGitTree(result_tree, candidate_entries)),
    )
    context = object.__new__(TrustedCandidateMaterializationContext)
    for name, value in {
        "repository_id": REPOSITORY, "task_id": TaskId("task"), "contract_id": CONTRACT_ID,
        "contract_raw_sha256": contract_raw,
        "authorization_id": AuthorizationId(RAW) if authorization_id is None else authorization_id,
        "target_registration_id": target_id, "policy_epoch_identity": epoch, "base_commit": BASE,
    }.items():
        object.__setattr__(context, name, value)
    result = admit_candidate_materialization(store=store, context=context, candidate_id=candidate_id, candidate_commit_id=commit)
    assert result.admitted_materialization is not None
    return result.admitted_materialization


def _candidate(materialization, *, candidate_id=None, contract=None, authorization_id=None, target_id=TARGET, epoch=EPOCH):
    contract = contract or _semantic_contract()[0]
    candidate_id = materialization.candidate_id if candidate_id is None else candidate_id
    return CandidateRecord(
        candidate_id, TaskId("task"), BASE, CONTRACT_ID, contract.contract_raw_sha256,
        AuthorizationId(RAW) if authorization_id is None else authorization_id,
        AdmissionEventId("admission"), target_id, epoch, materialization.materialization_id, (),
    )


def test_semantic_requirement_id_uses_the_exact_frozen_digest_preimage():
    contract, parsed, _ = _semantic_contract()
    actual = semantic_requirement_id(contract, parsed.acceptance_requirements[0].requirement_id)
    expected = contract_json_value_digest((
        "autodev.contract-semantic-requirement/v1", contract.contract_id.value,
        contract.contract_raw_sha256.value, parsed.acceptance_requirements[0].requirement_id.value,
    )).value
    assert actual.value == expected


def test_semantic_evaluator_obligation_id_uses_the_exact_frozen_digest_preimage():
    contract, parsed, evaluator = _semantic_contract()
    actual = semantic_evaluator_obligation_id(contract, parsed.acceptance_requirements[0].requirement_id, evaluator)
    expected = contract_json_value_digest((
        "autodev.contract-semantic-evaluator-obligation/v1", contract.contract_id.value,
        contract.contract_raw_sha256.value, parsed.acceptance_requirements[0].requirement_id.value,
        evaluator.evaluation_id.value, evaluator.evaluator_ref.value,
        evaluator.config_identity.config_id.value, evaluator.config_identity.resource_id.value,
        evaluator.config_identity.resource_sha256.value, evaluator.parameter_value_digest.value,
    ))
    assert actual.raw_sha256 == expected


def test_one_requirement_two_evaluators_share_requirement_but_not_obligation_identity():
    contract, parsed, evaluator = _semantic_contract()
    alternate = ContractAcceptanceEvaluator(
        LogicalIdentifier("evaluation-two"), evaluator.mechanism, evaluator.evaluator_ref,
        evaluator.config_identity, evaluator.parameter_value_digest,
    )
    requirement = parsed.acceptance_requirements[0].requirement_id
    assert semantic_requirement_id(contract, requirement) == semantic_requirement_id(contract, requirement)
    assert semantic_evaluator_obligation_id(contract, requirement, evaluator) != semantic_evaluator_obligation_id(contract, requirement, alternate)


def test_statement_binding_is_exact_and_text_distinct_statement_moves_it():
    first, first_parsed, _ = _semantic_contract(statement="statement")
    second, second_parsed, _ = _semantic_contract(statement="statement ")
    first_obligations = current_semantic_review.derive_semantic_obligations(first, _current_applicability_context(first))
    second_obligations = current_semantic_review.derive_semantic_obligations(second, _current_applicability_context(second))
    assert first_obligations[0].semantic_requirement.statement_binding == contract_json_value_digest(first_parsed.acceptance_requirements[0].statement)
    assert second_obligations[0].semantic_requirement.statement_binding == contract_json_value_digest(second_parsed.acceptance_requirements[0].statement)
    assert first_obligations[0].semantic_requirement.statement_binding != second_obligations[0].semantic_requirement.statement_binding
    assert first.contract_raw_sha256 != second.contract_raw_sha256


def test_one_semantic_requirement_derives_one_requirement_identity_and_two_obligations():
    contract, _, _ = _semantic_contract(extra_evaluation_ids=("evaluation-two",))
    obligations = current_semantic_review.derive_semantic_obligations(contract, _current_applicability_context(contract))
    assert len({item.semantic_requirement.requirement_id for item in obligations}) == 1
    assert len({item.obligation_id for item in obligations}) == 2


def test_complete_obligation_outcomes_are_sorted_by_id_independent_of_resolver_iteration(monkeypatch):
    config_bytes = _semantic_config_bytes()
    contract, _, _ = _semantic_contract(config_bytes=config_bytes, extra_evaluation_ids=("evaluation-two",))
    materialization = _materialization(CandidateId("current"), contract_raw=contract.contract_raw_sha256)
    inputs = _canonical_inputs(contract, candidate=_candidate(materialization, contract=contract), materialization=materialization)
    context = _current_applicability_context(contract)
    reader = _trusted_reader(contract, config_bytes)
    canonical = resolve_current_semantic_review(inputs, applicability_context=context, byte_reader=reader, semantic_context_source=None)
    original = current_semantic_review.derive_semantic_obligations
    monkeypatch.setattr(current_semantic_review, "derive_semantic_obligations", lambda c, x: tuple(reversed(original(c, x))))
    reversed_input = resolve_current_semantic_review(inputs, applicability_context=context, byte_reader=reader, semantic_context_source=None)
    assert tuple(x.obligation.obligation_id for x in canonical.obligation_outcomes) == tuple(sorted(
        (x.obligation.obligation_id for x in canonical.obligation_outcomes), key=lambda item: item.raw_sha256.value,
    ))
    assert tuple(x.obligation.obligation_id for x in reversed_input.obligation_outcomes) == tuple(
        x.obligation.obligation_id for x in canonical.obligation_outcomes
    )


@pytest.mark.parametrize("count", (256, 257))
def test_global_semantic_obligation_bound_accepts_256_and_denies_257(count):
    config_bytes = _semantic_config_bytes()
    configurations = tuple(
        (f"evaluation-{index:03}", "shared-config", config_bytes) for index in range(count)
    )
    contract, _, _ = _semantic_contract_matrix(configurations)
    if count == 256:
        materialization = _materialization(CandidateId("current"), contract_raw=contract.contract_raw_sha256)
        inputs = _canonical_inputs(contract, candidate=_candidate(materialization, contract=contract), materialization=materialization)
        result = resolve_current_semantic_review(
            inputs, applicability_context=_current_applicability_context(contract),
            byte_reader=_trusted_reader(contract, config_bytes), semantic_context_source=None,
        )
        assert result.status is CurrentSemanticReviewResolutionStatus.RESOLVED
        assert len(result.obligation_outcomes) == 256
    else:
        # The global count bound precedes candidate/materialization and byte-source requirements.
        result = resolve_current_semantic_review(
            _canonical_inputs(contract), applicability_context=_current_applicability_context(contract),
            byte_reader=None, semantic_context_source=None,
        )
        assert result.status is CurrentSemanticReviewResolutionStatus.DENIED
        assert result.reason is CurrentSemanticReviewResolutionReason.RESOLUTION_LIMIT_EXCEEDED


def test_parameter_recovery_uses_only_admitted_raw_bytes_and_exact_digest():
    contract, parsed, evaluator = _semantic_contract(parameters={"exact": [True, 1]})
    recovered = recover_semantic_evaluator_parameters(contract, parsed.acceptance_requirements[0].requirement_id, evaluator)
    assert recovered == parsed.acceptance_requirements[0].evaluators[0].parameters
    assert contract_json_value_digest(recovered) == evaluator.parameter_value_digest
    assert "parameters" not in inspect.signature(recover_semantic_evaluator_parameters).parameters


@pytest.mark.parametrize("mutation", ("sha", "requirement", "evaluation", "mechanism", "ref", "digest"))
def test_parameter_recovery_fails_closed_for_moved_or_inconsistent_admitted_bindings(mutation):
    contract, parsed, evaluator = _semantic_contract()
    requirement = parsed.acceptance_requirements[0].requirement_id
    if mutation == "sha":
        object.__setattr__(contract, "contract_raw_sha256", RawSha256("d" * 64))
    elif mutation == "requirement":
        requirement = LogicalIdentifier("missing")
    elif mutation == "evaluation":
        evaluator = ContractAcceptanceEvaluator(LogicalIdentifier("missing"), evaluator.mechanism, evaluator.evaluator_ref, evaluator.config_identity, evaluator.parameter_value_digest)
    elif mutation == "mechanism":
        evaluator = ContractAcceptanceEvaluator(evaluator.evaluation_id, EvaluatorMechanism.DETERMINISTIC, evaluator.evaluator_ref, evaluator.config_identity, evaluator.parameter_value_digest)
    elif mutation == "ref":
        evaluator = ContractAcceptanceEvaluator(evaluator.evaluation_id, evaluator.mechanism, ImmutableConfigId("other"), evaluator.config_identity, evaluator.parameter_value_digest)
    else:
        evaluator = ContractAcceptanceEvaluator(evaluator.evaluation_id, evaluator.mechanism, evaluator.evaluator_ref, evaluator.config_identity, RawSha256("d" * 64))
    assert recover_semantic_evaluator_parameters(contract, requirement, evaluator) is None


def test_duplicate_raw_evaluation_identity_fails_closed_during_parameter_recovery():
    contract, parsed, evaluator = _semantic_contract(extra_evaluation_ids=("evaluation-two",))
    value = json.loads(contract.raw_bytes)
    value["acceptance_requirements"][0]["evaluators"][1]["evaluation_id"] = evaluator.evaluation_id.value
    duplicate_raw = json.dumps(value, separators=(",", ":")).encode()
    object.__setattr__(contract, "raw_bytes", duplicate_raw)
    object.__setattr__(contract, "contract_raw_sha256", RawSha256(hashlib.sha256(duplicate_raw).hexdigest()))
    assert type(load_candidate_issue_contract(duplicate_raw)) is not CandidateIssueContract
    assert recover_semantic_evaluator_parameters(
        contract, parsed.acceptance_requirements[0].requirement_id, evaluator,
    ) is None


def test_nonsemantic_contract_evaluator_creates_no_semantic_obligation_and_needs_no_resolver(monkeypatch):
    _, _, contract = canonical_contract_fixture(
        contract_id=CONTRACT_ID, task_id=TaskId("task"), target_registration_id=TARGET,
        repository_id=REPOSITORY, policy_epoch_identity=EPOCH, base_sha=BASE,
    )
    monkeypatch.setattr(current_semantic_review, "resolve_semantic_evaluator_config", lambda *_: pytest.fail("no semantic config"))
    monkeypatch.setattr(current_semantic_review.TrustedSemanticConfigByteReader, "read_exact", lambda *_: pytest.fail("no byte read"))
    monkeypatch.setattr(current_semantic_review, "resolve_current_semantic_target_context", lambda *_: pytest.fail("no target read"))
    monkeypatch.setattr(current_semantic_review, "resolve_current_semantic_pull_request_context", lambda *_: pytest.fail("no PR read"))
    result = resolve_current_semantic_review(
        _canonical_inputs(contract), applicability_context=_current_applicability_context(contract),
        byte_reader=None, semantic_context_source=None,
    )
    assert result.status is CurrentSemanticReviewResolutionStatus.RESOLVED
    assert result.reason is CurrentSemanticReviewResolutionReason.NO_SEMANTIC_EVALUATORS
    assert result.obligation_outcomes == () and result.authoritative_dependencies == ()


def test_exact_admitted_semantic_evaluator_facts_repeat_exact_obligation_identity():
    contract, parsed, evaluator = _semantic_contract()
    requirement_id = parsed.acceptance_requirements[0].requirement_id
    assert semantic_evaluator_obligation_id(contract, requirement_id, evaluator) == semantic_evaluator_obligation_id(contract, requirement_id, evaluator)


@pytest.mark.parametrize("movement", ("evaluation", "ref", "resource", "digest", "parameter_digest"))
def test_each_frozen_semantic_evaluator_obligation_identity_input_moves_identity(movement):
    contract, parsed, evaluator = _semantic_contract()
    requirement_id = parsed.acceptance_requirements[0].requirement_id
    if movement == "evaluation":
        moved = _clone(evaluator, evaluation_id=LogicalIdentifier("evaluation-moved"))
    elif movement == "ref":
        moved = _clone(evaluator, evaluator_ref=ImmutableConfigId("evaluator-moved"))
    elif movement == "resource":
        moved = _clone(evaluator, config_identity=TrustedConfigIdentity(
            evaluator.config_identity.config_id, RootManagedResourceId("resource-moved"),
            evaluator.config_identity.resource_sha256,
        ))
    elif movement == "digest":
        moved = _clone(evaluator, config_identity=TrustedConfigIdentity(
            evaluator.config_identity.config_id, evaluator.config_identity.resource_id,
            RawSha256("d" * 64),
        ))
    else:
        moved = _clone(evaluator, parameter_value_digest=RawSha256("e" * 64))
    assert semantic_evaluator_obligation_id(contract, requirement_id, evaluator) != semantic_evaluator_obligation_id(contract, requirement_id, moved)


def test_current_review_material_is_complete_exact_candidate_truth_in_canonical_path_order():
    materialization = _materialization(CandidateId("material-a"))
    materials = derive_current_review_materials(materialization)
    assert materials is not None
    assert tuple(item.path for item in materials) == tuple(
        item.path for item in materialization.mutation_inventory.mutations
    )
    assert len(materials) == len(materialization.mutation_inventory.mutations)
    material = materials[0]
    assert material.kind is MutationKind.ADDED
    assert material.base_object_id is None and material.base_mode is None
    assert material.candidate_object_id is not None and material.candidate_mode is not None
    assert material.candidate_materialization_id == materialization.materialization_id


def test_current_review_material_identity_binds_candidate_materialization_not_candidate_id_alone():
    first = _materialization(CandidateId("same-candidate"), variant="one")
    second = _materialization(CandidateId("same-candidate"), variant="two")
    first_material = derive_current_review_materials(first)[0]
    second_material = derive_current_review_materials(second)[0]
    assert first.candidate_id == second.candidate_id
    assert first.materialization_id != second.materialization_id
    assert first_material.material_id != second_material.material_id


@pytest.mark.parametrize(("base_entries", "candidate_entries", "kind"), (
    ((FixtureGitTreeEntry("deleted.txt", GitObjectKind.BLOB, "100755", GitSha("2" * 40)),), (), MutationKind.DELETED),
    ((FixtureGitTreeEntry("modified.txt", GitObjectKind.BLOB, "100644", GitSha("3" * 40)),),
     (FixtureGitTreeEntry("modified.txt", GitObjectKind.BLOB, "100755", GitSha("4" * 40)),), MutationKind.MODIFIED),
))
def test_current_review_material_preserves_exact_deleted_and_modified_topology(base_entries, candidate_entries, kind):
    materialization = _materialization(CandidateId("topology-" + kind.value), base_entries=base_entries, candidate_entries=candidate_entries)
    material = derive_current_review_materials(materialization)[0]
    assert material.kind is kind
    if kind is MutationKind.DELETED:
        assert material.base_object_id is not None and material.base_mode is not None
        assert material.candidate_object_id is None and material.candidate_mode is None
    else:
        assert material.base_object_id is not None and material.base_mode is not None
        assert material.candidate_object_id is not None and material.candidate_mode is not None


@pytest.mark.parametrize(("left", "right"), (
    ((FixtureGitTreeEntry("path-a.txt", GitObjectKind.BLOB, "100644", GitSha("1" * 40)),),
     (FixtureGitTreeEntry("path-b.txt", GitObjectKind.BLOB, "100644", GitSha("1" * 40)),)),
    ((FixtureGitTreeEntry("object.txt", GitObjectKind.BLOB, "100644", GitSha("1" * 40)),),
     (FixtureGitTreeEntry("object.txt", GitObjectKind.BLOB, "100644", GitSha("2" * 40)),)),
    ((FixtureGitTreeEntry("mode.txt", GitObjectKind.BLOB, "100644", GitSha("1" * 40)),),
     (FixtureGitTreeEntry("mode.txt", GitObjectKind.BLOB, "100755", GitSha("1" * 40)),)),
))
def test_current_review_material_identity_moves_when_exact_mutation_truth_moves(left, right):
    first = _materialization(CandidateId("movement"), candidate_entries=left)
    second = _materialization(CandidateId("movement"), candidate_entries=right)
    assert derive_current_review_materials(first)[0].material_id != derive_current_review_materials(second)[0].material_id


def test_current_semantic_resolver_accepts_no_caller_material_subset_or_invented_material_list():
    parameters = inspect.signature(resolve_current_semantic_review).parameters
    assert "materials" not in parameters
    assert "changed_files" not in parameters
    assert "materialization" not in parameters


def test_zero_semantic_obligations_resolve_before_candidate_config_or_context_machinery():
    _, _, contract = canonical_contract_fixture(
        contract_id=CONTRACT_ID, task_id=TaskId("task"), target_registration_id=TARGET,
        repository_id=REPOSITORY, policy_epoch_identity=EPOCH, base_sha=BASE,
    )
    result = resolve_current_semantic_review(
        _canonical_inputs(contract), applicability_context=_current_applicability_context(contract),
        byte_reader=None, semantic_context_source=None,
    )
    assert result.status is CurrentSemanticReviewResolutionStatus.RESOLVED
    assert result.reason is CurrentSemanticReviewResolutionReason.NO_SEMANTIC_EVALUATORS
    assert result.obligation_outcomes == ()
    assert result.authoritative_dependencies == ()


@pytest.mark.parametrize(("decision", "code", "status", "reason"), (
    (
        "DENY", "ROOT_SCOPE_OVERLAP",
        CurrentSemanticReviewResolutionStatus.NOT_APPLICABLE,
        CurrentSemanticReviewResolutionReason.CONTRACT_NOT_APPLICABLE,
    ),
    (
        "ESCALATE", "ROOT_CONTEXT_UNAVAILABLE",
        CurrentSemanticReviewResolutionStatus.INDETERMINATE,
        CurrentSemanticReviewResolutionReason.CONTRACT_APPLICABILITY_INDETERMINATE,
    ),
))
def test_global_applicability_outcome_preserves_exact_g1_code(monkeypatch, decision, code, status, reason):
    from autodev_control.trusted.contract import IssueContractApplicabilityCode, IssueContractApplicabilityResult
    from autodev_control.trusted.decision import Decision

    contract, _, _ = _semantic_contract()
    inputs = _canonical_inputs(contract)
    g1 = IssueContractApplicabilityResult(getattr(Decision, decision), getattr(IssueContractApplicabilityCode, code))
    monkeypatch.setattr(current_semantic_review, "evaluate_issue_contract_applicability", lambda *_: g1)
    monkeypatch.setattr(current_semantic_review, "derive_semantic_obligations", lambda *_: pytest.fail("G1 non-allow must return first"))
    result = resolve_current_semantic_review(
        inputs, applicability_context=_current_applicability_context(contract),
        byte_reader=None, semantic_context_source=None,
    )
    assert result.status is status
    assert result.reason is reason
    assert result.applicability_code is g1.outcome
    assert result.obligation_outcomes == () and result.authoritative_dependencies == ()


def test_per_obligation_status_domain_excludes_global_not_applicable():
    assert {item.value for item in SemanticEvaluatorObligationResolutionStatus} == {
        "RESOLVED", "INDETERMINATE", "DENIED",
    }
    result, _, _ = _resolved_product()
    with pytest.raises(TypeError, match="closed enums"):
        replace(result.obligation_outcomes[0], status=CurrentSemanticReviewResolutionStatus.NOT_APPLICABLE)


@pytest.mark.parametrize("missing", ("candidate", "materialization"))
def test_semantic_obligation_requires_current_candidate_and_exact_materialization(missing):
    config_bytes = _semantic_config_bytes()
    contract, _, _ = _semantic_contract(config_bytes=config_bytes)
    materialization = _materialization(CandidateId("current"), contract_raw=contract.contract_raw_sha256)
    candidate = _candidate(materialization, contract=contract)
    result = resolve_current_semantic_review(
        _canonical_inputs(
            contract,
            candidate=None if missing == "candidate" else candidate,
            materialization=None if missing == "materialization" else materialization,
        ),
        applicability_context=_current_applicability_context(contract),
        byte_reader=None, semantic_context_source=None,
    )
    assert result.status is CurrentSemanticReviewResolutionStatus.INDETERMINATE
    assert result.reason is CurrentSemanticReviewResolutionReason.CANONICAL_INPUT_INDETERMINATE
    assert result.obligation_outcomes == ()


def test_candidate_materialization_mismatch_fails_before_config_or_context_sources():
    contract, _, _ = _semantic_contract()
    first = _materialization(CandidateId("current"), variant="one", contract_raw=contract.contract_raw_sha256)
    second = _materialization(CandidateId("current"), variant="two", contract_raw=contract.contract_raw_sha256)
    result = resolve_current_semantic_review(
        _canonical_inputs(contract, candidate=_candidate(first, contract=contract), materialization=second),
        applicability_context=_current_applicability_context(contract),
        byte_reader=None, semantic_context_source=None,
    )
    assert result.status is CurrentSemanticReviewResolutionStatus.DENIED
    assert result.reason is CurrentSemanticReviewResolutionReason.CANDIDATE_MATERIALIZATION_MISMATCH
    assert result.obligation_outcomes == ()


@pytest.mark.parametrize("mismatch", ("contract_id", "contract_raw", "target", "policy_epoch"))
def test_canonical_task_contract_target_and_epoch_continuity_fail_closed_before_config_resolution(mismatch):
    contract, _, _ = _semantic_contract()
    values = {}
    if mismatch == "contract_id":
        values["task_contract_id"] = ContractId("other-contract")
    elif mismatch == "contract_raw":
        values["task_raw"] = RawSha256("d" * 64)
    elif mismatch == "target":
        values["target_id"] = TargetRegistrationId(RawSha256("d" * 64))
    else:
        values["epoch"] = PolicyEpochIdentity(TrustedManifestId(RawSha256("d" * 64)))
    result = resolve_current_semantic_review(
        _canonical_inputs(contract, **values), applicability_context=_current_applicability_context(contract),
        byte_reader=None, semantic_context_source=None,
    )
    assert result.status is CurrentSemanticReviewResolutionStatus.DENIED
    assert result.reason is CurrentSemanticReviewResolutionReason.CANONICAL_INPUT_MISMATCH
    assert result.obligation_outcomes == ()


@pytest.mark.parametrize("mismatch", (
    "authorization", "candidate_contract", "materialization_contract",
    "candidate_epoch", "materialization_epoch", "candidate_target",
))
def test_candidate_chain_authorization_contract_and_epoch_movement_fails_closed(mismatch):
    contract, _, _ = _semantic_contract()
    materialization = _materialization(CandidateId("current"), contract_raw=contract.contract_raw_sha256)
    candidate = _candidate(materialization, contract=contract)
    authorization = None
    if mismatch == "authorization":
        authorization = _mint(
            AdmittedAuthorization, authorization_id=AuthorizationId(RawSha256("d" * 64)), task_id=TaskId("task"),
            contract_id=CONTRACT_ID, contract_raw_sha256=contract.contract_raw_sha256,
            target_registration_id=TARGET, policy_epoch_identity=EPOCH,
        )
    elif mismatch == "candidate_contract":
        candidate = replace(candidate, contract_raw_sha256=RawSha256("d" * 64))
    elif mismatch == "materialization_contract":
        materialization = _materialization(CandidateId("current"), variant="other", contract_raw=RAW)
        candidate = _candidate(materialization, contract=contract)
    elif mismatch == "candidate_epoch":
        candidate = replace(candidate, policy_epoch_identity=PolicyEpochIdentity(TrustedManifestId(RawSha256("d" * 64))))
    elif mismatch == "materialization_epoch":
        materialization = _materialization(
            CandidateId("current"), variant="other", contract_raw=contract.contract_raw_sha256,
            epoch=PolicyEpochIdentity(TrustedManifestId(RawSha256("d" * 64))),
        )
        candidate = _candidate(materialization, contract=contract)
    else:
        candidate = replace(candidate, target_registration_id=TargetRegistrationId(RawSha256("d" * 64)))
    result = resolve_current_semantic_review(
        _canonical_inputs(contract, candidate=candidate, materialization=materialization, authorization=authorization),
        applicability_context=_current_applicability_context(contract), byte_reader=None, semantic_context_source=None,
    )
    assert result.status is CurrentSemanticReviewResolutionStatus.DENIED
    assert result.reason is CurrentSemanticReviewResolutionReason.CANDIDATE_MATERIALIZATION_MISMATCH
    assert result.obligation_outcomes == ()


def test_candidate_base_mismatch_fails_closed_before_config_or_context_resolution():
    contract, _, _ = _semantic_contract()
    materialization = _materialization(CandidateId("current"), contract_raw=contract.contract_raw_sha256)
    candidate = replace(_candidate(materialization, contract=contract), base=GitSha("d" * 40))
    result = resolve_current_semantic_review(
        _canonical_inputs(contract, candidate=candidate, materialization=materialization),
        applicability_context=_current_applicability_context(contract), byte_reader=None, semantic_context_source=None,
    )
    assert result.status is CurrentSemanticReviewResolutionStatus.DENIED
    assert result.reason is CurrentSemanticReviewResolutionReason.CANDIDATE_MATERIALIZATION_MISMATCH
    assert result.obligation_outcomes == ()


def test_target_registration_is_the_repository_authority_not_issue_context_anchor():
    _, _, baseline = canonical_contract_fixture(
        contract_id=CONTRACT_ID, task_id=TaskId("task"), target_registration_id=TARGET,
        repository_id=REPOSITORY, policy_epoch_identity=EPOCH, base_sha=BASE,
    )
    contract = object.__new__(AdmittedIssueContract)
    for item in fields(AdmittedIssueContract):
        object.__setattr__(contract, item.name, getattr(baseline, item.name))
    object.__setattr__(contract, "context_anchor", IssueContextAnchor(GitHubRepositoryId("999"), 1, LogicalIdentifier("issue-1")))
    success = resolve_current_semantic_review(
        _canonical_inputs(contract), applicability_context=_current_applicability_context(contract),
        byte_reader=None, semantic_context_source=None,
    )
    assert success.status is CurrentSemanticReviewResolutionStatus.RESOLVED
    assert success.reason is CurrentSemanticReviewResolutionReason.NO_SEMANTIC_EVALUATORS

    semantic, _, _ = _semantic_contract()
    object.__setattr__(semantic, "context_anchor", IssueContextAnchor(GitHubRepositoryId("999"), 1, LogicalIdentifier("issue-1")))
    materialization = _materialization(CandidateId("current"), contract_raw=semantic.contract_raw_sha256)
    candidate = _candidate(materialization, contract=semantic)
    object.__setattr__(materialization, "repository_id", GitHubRepositoryId("999"))
    rejected = resolve_current_semantic_review(
        _canonical_inputs(semantic, candidate=candidate, materialization=materialization),
        applicability_context=_current_applicability_context(semantic), byte_reader=None, semantic_context_source=None,
    )
    assert rejected.status is CurrentSemanticReviewResolutionStatus.DENIED
    assert rejected.reason is CurrentSemanticReviewResolutionReason.CANDIDATE_MATERIALIZATION_MISMATCH


def test_current_semantic_config_resolution_retains_exact_current_issue33_product():
    config_bytes = _semantic_config_bytes()
    contract, _, evaluator = _semantic_contract(config_bytes=config_bytes)
    materialization = _materialization(CandidateId("current"), contract_raw=contract.contract_raw_sha256)
    candidate = _candidate(materialization, contract=contract)
    result = resolve_current_semantic_review(
        _canonical_inputs(contract, candidate=candidate, materialization=materialization),
        applicability_context=_current_applicability_context(contract),
        byte_reader=_trusted_reader(contract, config_bytes), semantic_context_source=None,
    )
    assert (result.status, result.reason) == (
        CurrentSemanticReviewResolutionStatus.RESOLVED, CurrentSemanticReviewResolutionReason.RESOLVED,
    )
    assert len(result.obligation_outcomes) == 1
    outcome = result.obligation_outcomes[0]
    assert outcome.status is SemanticEvaluatorObligationResolutionStatus.RESOLVED
    assert outcome.semantic_config_status is SemanticEvaluatorConfigResolutionStatus.RESOLVED
    assert outcome.semantic_config_reason is SemanticEvaluatorConfigResolutionReason.RESOLVED
    trusted = outcome.trusted_evaluator_resolution
    assert trusted is not None
    assert trusted.config_identity == evaluator.config_identity
    assert trusted.policy_epoch_identity == EPOCH
    assert trusted.mechanism is EvaluatorMechanism.SEMANTIC
    assert trusted.parameters_valid is True and trusted.applicable is True
    assert trusted.operational_prerequisites == ()
    assert trusted.target_context_requirement is SemanticReviewContextRequirement.NOT_APPLICABLE
    assert trusted.pr_context_requirement is SemanticReviewContextRequirement.NOT_APPLICABLE
    assert len(trusted.review_slots) == 1
    assert trusted.required_trusted_context_ids == ()
    assert outcome.assignment is not None and outcome.effective_subject is not None


def test_issue33_config_byte_unavailability_is_isolated_to_its_semantic_obligation():
    config_bytes = _semantic_config_bytes()
    contract, _, _ = _semantic_contract(config_bytes=config_bytes)
    materialization = _materialization(CandidateId("current"), contract_raw=contract.contract_raw_sha256)
    result = resolve_current_semantic_review(
        _canonical_inputs(contract, candidate=_candidate(materialization, contract=contract), materialization=materialization),
        applicability_context=_current_applicability_context(contract),
        byte_reader=current_semantic_review._assemble_trusted_semantic_config_byte_reader(
            current_semantic_review._READER_KEY, MappingProxyType({}),
        ), semantic_context_source=None,
    )
    assert result.status is CurrentSemanticReviewResolutionStatus.RESOLVED
    assert len(result.obligation_outcomes) == 1
    outcome = result.obligation_outcomes[0]
    assert outcome.status is SemanticEvaluatorObligationResolutionStatus.INDETERMINATE
    assert outcome.reason.name == "EVALUATOR_RESOLUTION_UNAVAILABLE"
    assert outcome.semantic_config_status is SemanticEvaluatorConfigResolutionStatus.INDETERMINATE
    assert outcome.semantic_config_reason is SemanticEvaluatorConfigResolutionReason.CONFIG_BYTES_UNAVAILABLE
    assert outcome.trusted_evaluator_resolution is None


def test_issue33_invalid_current_config_is_isolated_without_constructing_subjects():
    invalid = b"{}"
    contract, _, _ = _semantic_contract(config_bytes=invalid)
    materialization = _materialization(CandidateId("current"), contract_raw=contract.contract_raw_sha256)
    result = resolve_current_semantic_review(
        _canonical_inputs(contract, candidate=_candidate(materialization, contract=contract), materialization=materialization),
        applicability_context=_current_applicability_context(contract),
        byte_reader=_trusted_reader(contract, invalid), semantic_context_source=None,
    )
    outcome = result.obligation_outcomes[0]
    assert result.status is CurrentSemanticReviewResolutionStatus.RESOLVED
    assert outcome.status is SemanticEvaluatorObligationResolutionStatus.DENIED
    assert outcome.reason.name == "EVALUATOR_RESOLUTION_INVALID"
    assert outcome.assignment is None and outcome.effective_subject is None


@pytest.mark.parametrize(("status", "config_reason", "expected_status", "expected_reason"), (
    (SemanticEvaluatorConfigResolutionStatus.INDETERMINATE, SemanticEvaluatorConfigResolutionReason.CONFIG_BYTES_UNAVAILABLE,
     SemanticEvaluatorObligationResolutionStatus.INDETERMINATE, "EVALUATOR_RESOLUTION_UNAVAILABLE"),
    (SemanticEvaluatorConfigResolutionStatus.INDETERMINATE, SemanticEvaluatorConfigResolutionReason.CONFIG_BYTES_MISMATCH,
     SemanticEvaluatorObligationResolutionStatus.INDETERMINATE, "EVALUATOR_RESOLUTION_UNAVAILABLE"),
    (SemanticEvaluatorConfigResolutionStatus.INDETERMINATE, SemanticEvaluatorConfigResolutionReason.CONFIG_BYTES_UNVERIFIABLE,
     SemanticEvaluatorObligationResolutionStatus.INDETERMINATE, "EVALUATOR_RESOLUTION_UNAVAILABLE"),
    (SemanticEvaluatorConfigResolutionStatus.DENIED, SemanticEvaluatorConfigResolutionReason.RESOLUTION_LIMIT_EXCEEDED,
     SemanticEvaluatorObligationResolutionStatus.DENIED, "EVALUATOR_RESOLUTION_LIMIT_EXCEEDED"),
    (SemanticEvaluatorConfigResolutionStatus.DENIED, SemanticEvaluatorConfigResolutionReason.BASIC_RESOLUTION_NONCANONICAL,
     SemanticEvaluatorObligationResolutionStatus.DENIED, "EVALUATOR_RESOLUTION_NONCANONICAL"),
    (SemanticEvaluatorConfigResolutionStatus.DENIED, SemanticEvaluatorConfigResolutionReason.NONCANONICAL_CONFIG,
     SemanticEvaluatorObligationResolutionStatus.DENIED, "EVALUATOR_RESOLUTION_NONCANONICAL"),
    (SemanticEvaluatorConfigResolutionStatus.DENIED, SemanticEvaluatorConfigResolutionReason.BASIC_RESOLUTION_NOT_SEMANTIC,
     SemanticEvaluatorObligationResolutionStatus.DENIED, "EVALUATOR_BINDING_MISMATCH"),
    (SemanticEvaluatorConfigResolutionStatus.DENIED, SemanticEvaluatorConfigResolutionReason.BASIC_RESOLUTION_NOT_USABLE,
     SemanticEvaluatorObligationResolutionStatus.DENIED, "EVALUATOR_BINDING_MISMATCH"),
    (SemanticEvaluatorConfigResolutionStatus.DENIED, SemanticEvaluatorConfigResolutionReason.BASIC_RESOLUTION_MISMATCH,
     SemanticEvaluatorObligationResolutionStatus.DENIED, "EVALUATOR_BINDING_MISMATCH"),
    (SemanticEvaluatorConfigResolutionStatus.DENIED, SemanticEvaluatorConfigResolutionReason.CONFIG_RESOURCE_INVALID,
     SemanticEvaluatorObligationResolutionStatus.DENIED, "EVALUATOR_RESOLUTION_INVALID"),
    (SemanticEvaluatorConfigResolutionStatus.DENIED, SemanticEvaluatorConfigResolutionReason.UNSUPPORTED_CONFIG_FORMAT,
     SemanticEvaluatorObligationResolutionStatus.DENIED, "EVALUATOR_RESOLUTION_INVALID"),
    (SemanticEvaluatorConfigResolutionStatus.DENIED, SemanticEvaluatorConfigResolutionReason.CONFIG_GRAMMAR_INVALID,
     SemanticEvaluatorObligationResolutionStatus.DENIED, "EVALUATOR_RESOLUTION_INVALID"),
    (SemanticEvaluatorConfigResolutionStatus.DENIED, SemanticEvaluatorConfigResolutionReason.UNSUPPORTED_PARTITION_RULE,
     SemanticEvaluatorObligationResolutionStatus.DENIED, "EVALUATOR_RESOLUTION_INVALID"),
    (SemanticEvaluatorConfigResolutionStatus.DENIED, SemanticEvaluatorConfigResolutionReason.UNSUPPORTED_TOOL_MODE,
     SemanticEvaluatorObligationResolutionStatus.DENIED, "EVALUATOR_RESOLUTION_INVALID"),
))
def test_issue33_failure_status_and_reason_map_exactly_to_obligation_domain(monkeypatch, status, config_reason, expected_status, expected_reason):
    config_bytes = _semantic_config_bytes()
    contract, _, _ = _semantic_contract(config_bytes=config_bytes)
    materialization = _materialization(CandidateId("current"), contract_raw=contract.contract_raw_sha256)
    result_from_33 = SemanticEvaluatorConfigResolutionResult(status, config_reason)
    calls = []
    monkeypatch.setattr(
        current_semantic_review, "resolve_semantic_evaluator_config",
        lambda basic, raw: calls.append((basic, raw)) or result_from_33,
    )
    result = resolve_current_semantic_review(
        _canonical_inputs(contract, candidate=_candidate(materialization, contract=contract), materialization=materialization),
        applicability_context=_current_applicability_context(contract), byte_reader=_trusted_reader(contract, config_bytes),
        semantic_context_source=None,
    )
    outcome = result.obligation_outcomes[0]
    assert len(calls) == 1
    assert result.status is CurrentSemanticReviewResolutionStatus.RESOLVED
    assert (outcome.status, outcome.reason.name) == (expected_status, expected_reason)
    assert (outcome.semantic_config_status, outcome.semantic_config_reason) == (status, config_reason)
    assert outcome.semantic_config_resource_failure_code is None
    assert outcome.semantic_config_parse_failure_code is None
    assert outcome.trusted_evaluator_resolution is None
    assert outcome.assignment is None and outcome.effective_subject is None


def test_same_failed_issue33_result_is_reused_for_every_obligation_sharing_config(monkeypatch):
    config_bytes = _semantic_config_bytes()
    contract, _, _ = _semantic_contract(config_bytes=config_bytes, extra_evaluation_ids=("evaluation-two",))
    materialization = _materialization(CandidateId("current"), contract_raw=contract.contract_raw_sha256)
    calls = []
    original = current_semantic_review.resolve_semantic_evaluator_config
    def resolve(basic, raw):
        calls.append(basic)
        return original(basic, None)
    monkeypatch.setattr(current_semantic_review, "resolve_semantic_evaluator_config", resolve)
    result = resolve_current_semantic_review(
        _canonical_inputs(contract, candidate=_candidate(materialization, contract=contract), materialization=materialization),
        applicability_context=_current_applicability_context(contract), byte_reader=_trusted_reader(contract, {}),
        semantic_context_source=None,
    )
    assert result.status is CurrentSemanticReviewResolutionStatus.RESOLVED
    assert len(calls) == 1
    assert len(result.obligation_outcomes) == 2
    assert all(item.status is SemanticEvaluatorObligationResolutionStatus.INDETERMINATE for item in result.obligation_outcomes)
    assert all(item.semantic_config_reason is SemanticEvaluatorConfigResolutionReason.CONFIG_BYTES_UNAVAILABLE for item in result.obligation_outcomes)


def test_issue33_one_config_identity_is_read_and_resolved_once_per_attempt(monkeypatch):
    config_bytes = _semantic_config_bytes()
    contract, _, _ = _semantic_contract(config_bytes=config_bytes, extra_evaluation_ids=("evaluation-two",))
    materialization = _materialization(CandidateId("current"), contract_raw=contract.contract_raw_sha256)
    reader = _trusted_reader(contract, config_bytes)
    calls = {"read": 0, "resolve": 0}
    original_read = current_semantic_review.TrustedSemanticConfigByteReader.read_exact
    original_resolve = current_semantic_review.resolve_semantic_evaluator_config

    def counted_read(self, ref):
        calls["read"] += 1
        return original_read(self, ref)

    def counted_resolve(basic, raw):
        calls["resolve"] += 1
        return original_resolve(basic, raw)

    monkeypatch.setattr(current_semantic_review.TrustedSemanticConfigByteReader, "read_exact", counted_read)
    monkeypatch.setattr(current_semantic_review, "resolve_semantic_evaluator_config", counted_resolve)
    result = resolve_current_semantic_review(
        _canonical_inputs(contract, candidate=_candidate(materialization, contract=contract), materialization=materialization),
        applicability_context=_current_applicability_context(contract), byte_reader=reader, semantic_context_source=None,
    )
    assert result.status is CurrentSemanticReviewResolutionStatus.RESOLVED
    assert len(result.obligation_outcomes) == 2
    assert calls == {"read": 1, "resolve": 1}


@pytest.mark.parametrize("substitute", ("none", "callable", "mapping", "lookalike"))
def test_semantic_byte_reader_requires_exact_trusted_assembly_type(monkeypatch, substitute):
    config_bytes = _semantic_config_bytes()
    contract, _, _ = _semantic_contract(config_bytes=config_bytes)
    materialization = _materialization(CandidateId("current"), contract_raw=contract.contract_raw_sha256)
    if substitute == "none":
        reader = None
    elif substitute == "callable":
        reader = lambda _ref: config_bytes
    elif substitute == "mapping":
        reader = {}
    else:
        class ReaderLookalike:
            def read_exact(self, _ref):
                return config_bytes
        reader = ReaderLookalike()
    monkeypatch.setattr(current_semantic_review, "resolve_semantic_evaluator_config", lambda *_: pytest.fail("untrusted reader substitute reached #33"))
    result = resolve_current_semantic_review(
        _canonical_inputs(contract, candidate=_candidate(materialization, contract=contract), materialization=materialization),
        applicability_context=_current_applicability_context(contract), byte_reader=reader, semantic_context_source=None,
    )
    assert result.status is CurrentSemanticReviewResolutionStatus.INDETERMINATE
    assert result.reason is CurrentSemanticReviewResolutionReason.SEMANTIC_CONFIG_BYTE_SOURCE_UNAVAILABLE


@pytest.mark.parametrize("bad_kind", ("bytearray", "memoryview", "string", "config_identity", "semantic_resolution"))
def test_exact_reader_rejects_non_bytes_without_coercion_or_issue33_call(monkeypatch, bad_kind):
    config_bytes = _semantic_config_bytes()
    contract, _, evaluator = _semantic_contract(config_bytes=config_bytes)
    materialization = _materialization(CandidateId("current"), contract_raw=contract.contract_raw_sha256)
    if bad_kind == "bytearray":
        bad_result = bytearray(b"{}")
    elif bad_kind == "memoryview":
        bad_result = memoryview(b"{}")
    elif bad_kind == "string":
        bad_result = "{}"
    elif bad_kind == "config_identity":
        bad_result = evaluator.config_identity
    else:
        basic = next(item for item in _current_applicability_context(contract).evaluator_resolutions)
        bad_result = current_semantic_review.resolve_semantic_evaluator_config(basic, config_bytes).resolution
        assert type(bad_result) is TrustedSemanticEvaluatorResolution
    reader = _trusted_reader(contract, config_bytes)
    queried = []
    monkeypatch.setattr(
        current_semantic_review.TrustedSemanticConfigByteReader, "read_exact",
        lambda self, ref: queried.append(ref) or bad_result,
    )
    monkeypatch.setattr(current_semantic_review, "resolve_semantic_evaluator_config", lambda *_: pytest.fail("invalid bytes must not reach #33"))
    result = resolve_current_semantic_review(
        _canonical_inputs(contract, candidate=_candidate(materialization, contract=contract), materialization=materialization),
        applicability_context=_current_applicability_context(contract), byte_reader=reader, semantic_context_source=None,
    )
    assert len(queried) == 1
    assert queried[0] == RootManagedResourceRef(
        evaluator.config_identity.resource_id, RootManagedResourceKind.TRUSTED_CONFIG,
        evaluator.config_identity.resource_sha256,
    )
    assert result.status is CurrentSemanticReviewResolutionStatus.DENIED
    assert result.reason is CurrentSemanticReviewResolutionReason.SEMANTIC_CONFIG_BYTE_SOURCE_INVALID


def test_config_reader_and_issue33_receive_exact_g1_selected_identity_in_sorted_order_and_reread_each_call(monkeypatch):
    config_bytes = _semantic_config_bytes()
    contract, _, _ = _semantic_contract_many((
        ("evaluation-z", "config-z", config_bytes),
        ("evaluation-a", "config-a", config_bytes),
    ))
    materialization = _materialization(CandidateId("current"), contract_raw=contract.contract_raw_sha256)
    applicability = _current_applicability_context(contract)
    reader = _trusted_reader(contract, {"config-z": config_bytes, "config-a": config_bytes})
    refs = []
    basic_values = []
    original_read = current_semantic_review.TrustedSemanticConfigByteReader.read_exact
    original_resolve = current_semantic_review.resolve_semantic_evaluator_config

    def read(self, ref):
        refs.append(ref)
        return original_read(self, ref)

    def resolve(basic, raw):
        basic_values.append(basic)
        return original_resolve(basic, raw)

    monkeypatch.setattr(current_semantic_review.TrustedSemanticConfigByteReader, "read_exact", read)
    monkeypatch.setattr(current_semantic_review, "resolve_semantic_evaluator_config", resolve)
    inputs = _canonical_inputs(contract, candidate=_candidate(materialization, contract=contract), materialization=materialization)
    first = resolve_current_semantic_review(inputs, applicability_context=applicability, byte_reader=reader, semantic_context_source=None)
    second = resolve_current_semantic_review(inputs, applicability_context=applicability, byte_reader=reader, semantic_context_source=None)
    expected_refs = tuple(
        RootManagedResourceRef(item.resource_id, RootManagedResourceKind.TRUSTED_CONFIG, item.resource_sha256)
        for item in sorted({e.config_identity for r in contract.acceptance_plan.requirements for e in r.evaluators},
                           key=lambda identity: (identity.config_id.value, identity.resource_id.value, identity.resource_sha256.value))
    )
    assert first.status is second.status is CurrentSemanticReviewResolutionStatus.RESOLVED
    assert refs == list(expected_refs) * 2
    assert len(basic_values) == 4
    for basic in basic_values:
        assert any(basic is current for current in applicability.evaluator_resolutions)


def test_distinct_trusted_readers_with_same_exact_bytes_produce_same_semantic_identity():
    config_bytes = _semantic_config_bytes()
    contract, _, _ = _semantic_contract(config_bytes=config_bytes)
    materialization = _materialization(CandidateId("current"), contract_raw=contract.contract_raw_sha256)
    inputs = _canonical_inputs(contract, candidate=_candidate(materialization, contract=contract), materialization=materialization)
    context = _current_applicability_context(contract)
    reader_a = _trusted_reader(contract, config_bytes)
    reader_b = _trusted_reader(contract, config_bytes)
    assert reader_a is not reader_b
    result_a = resolve_current_semantic_review(inputs, applicability_context=context, byte_reader=reader_a, semantic_context_source=None)
    result_b = resolve_current_semantic_review(inputs, applicability_context=context, byte_reader=reader_b, semantic_context_source=None)
    a, b = result_a.obligation_outcomes[0], result_b.obligation_outcomes[0]
    assert a.obligation.obligation_id == b.obligation.obligation_id
    assert a.trusted_evaluator_resolution.resolution_id == b.trusted_evaluator_resolution.resolution_id
    assert a.assignment.assignment_id == b.assignment.assignment_id
    assert a.effective_subject.subject_id == b.effective_subject.subject_id
    assert result_a.authoritative_dependencies == result_b.authoritative_dependencies


def test_semantic_config_identity_aggregate_limit_accepts_64_and_rejects_65_before_reads(monkeypatch):
    config_bytes = b""
    for count, expected in ((64, CurrentSemanticReviewResolutionStatus.RESOLVED), (65, CurrentSemanticReviewResolutionStatus.DENIED)):
        contract, _, _ = _semantic_contract_matrix(tuple(
            (f"evaluation-{index:03}", f"config-{index:03}", config_bytes) for index in range(count)
        ))
        materialization = _materialization(CandidateId("current"), contract_raw=contract.contract_raw_sha256)
        reader = _trusted_reader(contract, {})
        calls = {"read": 0, "resolve": 0}
        original_read = current_semantic_review.TrustedSemanticConfigByteReader.read_exact
        original_resolve = current_semantic_review.resolve_semantic_evaluator_config

        def read(self, ref):
            calls["read"] += 1
            return original_read(self, ref)

        def resolve(basic, raw):
            calls["resolve"] += 1
            return original_resolve(basic, raw)

        monkeypatch.setattr(current_semantic_review.TrustedSemanticConfigByteReader, "read_exact", read)
        monkeypatch.setattr(current_semantic_review, "resolve_semantic_evaluator_config", resolve)
        result = resolve_current_semantic_review(
            _canonical_inputs(contract, candidate=_candidate(materialization, contract=contract), materialization=materialization),
            applicability_context=_current_applicability_context(contract), byte_reader=reader, semantic_context_source=None,
        )
        assert result.status is expected
        if count == 64:
            assert result.reason is CurrentSemanticReviewResolutionReason.RESOLVED
            assert calls == {"read": 64, "resolve": 64}
        else:
            assert result.reason is CurrentSemanticReviewResolutionReason.SEMANTIC_CONFIG_AGGREGATE_LIMIT_EXCEEDED
            assert calls == {"read": 0, "resolve": 0}


def test_semantic_config_aggregate_bytes_accepts_8_mib_and_rejects_8_mib_plus_one_before_issue33(monkeypatch):
    base = _semantic_config_bytes()
    exact = base + b" " * (262_144 - len(base))
    assert len(exact) == 262_144
    cases = (
        (32, tuple((f"evaluation-{i:03}", f"config-{i:03}", exact) for i in range(32)),
         CurrentSemanticReviewResolutionStatus.RESOLVED),
        (33, tuple((f"evaluation-{i:03}", f"config-{i:03}", exact if i < 32 else b"x") for i in range(33)),
         CurrentSemanticReviewResolutionStatus.DENIED),
    )
    original_read = current_semantic_review.TrustedSemanticConfigByteReader.read_exact
    original_resolve = current_semantic_review.resolve_semantic_evaluator_config
    for count, configurations, expected_status in cases:
        contract, _, _ = _semantic_contract_matrix(configurations)
        materialization = _materialization(CandidateId("current"), contract_raw=contract.contract_raw_sha256)
        reader = _trusted_reader(contract, {ref: raw for _, ref, raw in configurations})
        reads = []
        resolves = []
        def read(self, ref):
            reads.append(ref.resource_id.value)
            return original_read(self, ref)

        def resolve(basic, raw):
            resolves.append(basic.binding.config_identity.config_id.value)
            return original_resolve(basic, raw)

        monkeypatch.setattr(current_semantic_review.TrustedSemanticConfigByteReader, "read_exact", read)
        monkeypatch.setattr(current_semantic_review, "resolve_semantic_evaluator_config", resolve)
        result = resolve_current_semantic_review(
            _canonical_inputs(contract, candidate=_candidate(materialization, contract=contract), materialization=materialization),
            applicability_context=_current_applicability_context(contract), byte_reader=reader, semantic_context_source=None,
        )
        assert result.status is expected_status
        if count == 32:
            assert result.reason is CurrentSemanticReviewResolutionReason.RESOLVED
            assert len(result.obligation_outcomes) == 32 and len(resolves) == 32
            assert len(reads) == 32
        else:
            assert result.reason is CurrentSemanticReviewResolutionReason.SEMANTIC_CONFIG_AGGREGATE_LIMIT_EXCEEDED
            assert len(reads) == 33 and resolves == []


def test_issue33_resource_and_parse_diagnostics_survive_per_obligation_projection():
    valid = _semantic_config_bytes()
    for config_bytes, reader_bytes, expected_status, expected_reason, expected_resource, expected_parse in (
        (valid, b"{}", SemanticEvaluatorObligationResolutionStatus.INDETERMINATE,
         current_semantic_review.SemanticEvaluatorObligationResolutionReason.EVALUATOR_RESOLUTION_UNAVAILABLE,
         ResourceFailureCode.DIGEST_MISMATCH, None),
        (b"{", b"{", SemanticEvaluatorObligationResolutionStatus.DENIED,
         current_semantic_review.SemanticEvaluatorObligationResolutionReason.EVALUATOR_RESOLUTION_INVALID,
         None, ParseFailureCode.INVALID_JSON),
    ):
        contract, _, _ = _semantic_contract(config_bytes=config_bytes)
        materialization = _materialization(CandidateId("current"), contract_raw=contract.contract_raw_sha256)
        result = resolve_current_semantic_review(
            _canonical_inputs(contract, candidate=_candidate(materialization, contract=contract), materialization=materialization),
            applicability_context=_current_applicability_context(contract),
            byte_reader=_trusted_reader(contract, reader_bytes), semantic_context_source=None,
        )
        outcome = result.obligation_outcomes[0]
        assert result.status is CurrentSemanticReviewResolutionStatus.RESOLVED
        assert outcome.status is expected_status
        assert outcome.reason is expected_reason
        assert outcome.semantic_config_resource_failure_code is expected_resource
        assert outcome.semantic_config_parse_failure_code is expected_parse


@pytest.mark.parametrize(("failed_ref", "failure"), (("config-two", "unavailable"), ("config-two", "invalid"), ("config-one", "unavailable"), ("config-one", "invalid")))
def test_distinct_issue33_config_failures_are_isolated_between_obligations(monkeypatch, failed_ref, failure):
    good_bytes = _semantic_config_bytes(target="REQUIRED")
    malformed_bytes = b"{}"
    configurations = (
        ("evaluation-one", "config-one", malformed_bytes if failed_ref == "config-one" and failure == "invalid" else good_bytes),
        ("evaluation-two", "config-two", malformed_bytes if failed_ref == "config-two" and failure == "invalid" else good_bytes),
    )
    contract, _, evaluators = _semantic_contract_many(configurations)
    materialization = _materialization(CandidateId("current"), contract_raw=contract.contract_raw_sha256)
    reader_values = {ref: raw for _, ref, raw in configurations if ref != failed_ref or failure == "invalid"}
    reader = _trusted_reader(contract, reader_values)
    calls = {"reads": [], "resolves": [], "target": 0}
    original_read = current_semantic_review.TrustedSemanticConfigByteReader.read_exact
    original_resolve = current_semantic_review.resolve_semantic_evaluator_config

    def counted_read(self, ref):
        calls["reads"].append(ref.resource_id.value)
        return original_read(self, ref)

    def counted_resolve(basic, raw):
        calls["resolves"].append(basic.binding.config_identity.config_id.value)
        return original_resolve(basic, raw)

    def target(*_):
        calls["target"] += 1
        return _target_success()

    monkeypatch.setattr(current_semantic_review.TrustedSemanticConfigByteReader, "read_exact", counted_read)
    monkeypatch.setattr(current_semantic_review, "resolve_semantic_evaluator_config", counted_resolve)
    monkeypatch.setattr(current_semantic_review, "resolve_current_semantic_target_context", target)
    result = resolve_current_semantic_review(
        _canonical_inputs(contract, candidate=_candidate(materialization, contract=contract), materialization=materialization),
        applicability_context=_current_applicability_context(contract), byte_reader=reader, semantic_context_source=None,
    )
    assert result.status is CurrentSemanticReviewResolutionStatus.RESOLVED
    by_evaluation = {outcome.obligation.evaluator.evaluation_id.value: outcome for outcome in result.obligation_outcomes}
    good_ref = "config-two" if failed_ref == "config-one" else "config-one"
    good_id = "evaluation-two" if failed_ref == "config-one" else "evaluation-one"
    failed_id = "evaluation-one" if failed_ref == "config-one" else "evaluation-two"
    good = by_evaluation[good_id]
    bad = by_evaluation[failed_id]
    assert good.status is SemanticEvaluatorObligationResolutionStatus.RESOLVED
    assert good.semantic_config_status is SemanticEvaluatorConfigResolutionStatus.RESOLVED
    assert good.semantic_config_reason is SemanticEvaluatorConfigResolutionReason.RESOLVED
    assert good.trusted_evaluator_resolution is not None
    assert good.target_context_id == TargetContextId("target-context")
    assert good.authoritative_dependencies == (_dependency(),)
    assert result.authoritative_dependencies == (_dependency(),)
    assert good.assignment is not None and good.effective_subject is not None
    assert bad.assignment is None and bad.effective_subject is None
    assert bad.target_context_id is None and bad.authoritative_dependencies == ()
    if failure == "unavailable":
        assert bad.status is SemanticEvaluatorObligationResolutionStatus.INDETERMINATE
        assert bad.reason.name == "EVALUATOR_RESOLUTION_UNAVAILABLE"
    else:
        assert bad.status is SemanticEvaluatorObligationResolutionStatus.DENIED
        assert bad.reason.name == "EVALUATOR_RESOLUTION_INVALID"
    assert len(evaluators) == 2 and evaluators[0].config_identity != evaluators[1].config_identity
    assert calls["reads"] == ["resource-config-one", "resource-config-two"]
    assert calls["resolves"] == ["config-one", "config-two"]
    assert calls["target"] == 1


@pytest.mark.parametrize("failed_config", ("config-one", "config-two"))
def test_issue33_current_binding_failure_isolated_to_its_obligation(monkeypatch, failed_config):
    config_bytes = _semantic_config_bytes(target="REQUIRED")
    contract, _, _ = _semantic_contract_many((
        ("evaluation-one", "config-one", config_bytes),
        ("evaluation-two", "config-two", config_bytes),
    ))
    materialization = _materialization(CandidateId("current"), contract_raw=contract.contract_raw_sha256)
    original = current_semantic_review.resolve_semantic_evaluator_config
    calls = {"reads": [], "resolves": [], "target": 0}
    original_read = current_semantic_review.TrustedSemanticConfigByteReader.read_exact
    def read(self, ref):
        calls["reads"].append(ref.resource_id.value)
        return original_read(self, ref)

    def resolver(basic, raw):
        calls["resolves"].append(basic.binding.config_identity.config_id.value)
        if basic.binding.config_identity.config_id.value == failed_config:
            return SemanticEvaluatorConfigResolutionResult(
                SemanticEvaluatorConfigResolutionStatus.DENIED,
                SemanticEvaluatorConfigResolutionReason.BASIC_RESOLUTION_MISMATCH,
            )
        return original(basic, raw)

    def target(*_):
        calls["target"] += 1
        return _target_success()

    monkeypatch.setattr(current_semantic_review.TrustedSemanticConfigByteReader, "read_exact", read)
    monkeypatch.setattr(current_semantic_review, "resolve_semantic_evaluator_config", resolver)
    monkeypatch.setattr(current_semantic_review, "resolve_current_semantic_target_context", target)
    result = resolve_current_semantic_review(
        _canonical_inputs(contract, candidate=_candidate(materialization, contract=contract), materialization=materialization),
        applicability_context=_current_applicability_context(contract), byte_reader=_trusted_reader(contract, config_bytes),
        semantic_context_source=None,
    )
    by_id = {item.obligation.evaluator.evaluation_id.value: item for item in result.obligation_outcomes}
    good_id = "evaluation-two" if failed_config == "config-one" else "evaluation-one"
    failed_id = "evaluation-one" if failed_config == "config-one" else "evaluation-two"
    assert result.status is CurrentSemanticReviewResolutionStatus.RESOLVED
    assert by_id[good_id].status is SemanticEvaluatorObligationResolutionStatus.RESOLVED
    assert by_id[good_id].semantic_config_status is SemanticEvaluatorConfigResolutionStatus.RESOLVED
    assert by_id[good_id].trusted_evaluator_resolution is not None
    assert by_id[good_id].assignment is not None and by_id[good_id].effective_subject is not None
    assert by_id[failed_id].status is SemanticEvaluatorObligationResolutionStatus.DENIED
    assert by_id[failed_id].reason.name == "EVALUATOR_BINDING_MISMATCH"
    assert by_id[failed_id].trusted_evaluator_resolution is None
    assert by_id[failed_id].assignment is None and by_id[failed_id].effective_subject is None
    assert by_id[failed_id].target_context_id is None
    assert by_id[failed_id].authoritative_dependencies == ()
    assert calls == {"reads": ["resource-config-one", "resource-config-two"], "resolves": ["config-one", "config-two"], "target": 1}


@pytest.mark.parametrize(("dimension", "requirement_field"), (("target", "target"), ("pr", "pr")))
def test_mixed_a7_valid_and_invalid_obligations_create_only_one_dimension_demand(monkeypatch, dimension, requirement_field):
    requirement = {"target": "NOT_APPLICABLE", "pr": "NOT_APPLICABLE"}
    requirement[requirement_field] = "REQUIRED"
    config_bytes = _semantic_config_bytes(**requirement)
    contract, _, _ = _semantic_contract_many((
        ("evaluation-one", "config-one", config_bytes),
        ("evaluation-two", "config-two", config_bytes),
    ))
    materialization = _materialization(CandidateId("current"), contract_raw=contract.contract_raw_sha256)
    original = current_semantic_review.resolve_semantic_evaluator_config
    calls = {"target": 0, "pr": 0}

    def a7_product(basic, raw):
        result = original(basic, raw)
        if basic.binding.config_identity.config_id.value != "config-two":
            return result
        trusted = result.resolution
        assert trusted is not None
        moved = {field.name: getattr(trusted, field.name) for field in fields(TrustedSemanticEvaluatorResolution)}
        moved["applicable"] = False
        return SemanticEvaluatorConfigResolutionResult(
            SemanticEvaluatorConfigResolutionStatus.RESOLVED,
            SemanticEvaluatorConfigResolutionReason.RESOLVED,
            _mint(TrustedSemanticEvaluatorResolution, **moved),
        )

    def target(*_):
        calls["target"] += 1
        return _target_success()

    def pr(*_):
        calls["pr"] += 1
        return _pr_success()

    monkeypatch.setattr(current_semantic_review, "resolve_semantic_evaluator_config", a7_product)
    monkeypatch.setattr(current_semantic_review, "resolve_current_semantic_target_context", target)
    monkeypatch.setattr(current_semantic_review, "resolve_current_semantic_pull_request_context", pr)
    result = resolve_current_semantic_review(
        _canonical_inputs(contract, candidate=_candidate(materialization, contract=contract), materialization=materialization),
        applicability_context=_current_applicability_context(contract),
        byte_reader=_trusted_reader(contract, {"config-one": config_bytes, "config-two": config_bytes}),
        semantic_context_source=None,
    )
    outcomes = {item.obligation.evaluator.evaluation_id.value: item for item in result.obligation_outcomes}
    assert outcomes["evaluation-one"].status is SemanticEvaluatorObligationResolutionStatus.RESOLVED
    assert outcomes["evaluation-one"].assignment is not None
    assert outcomes["evaluation-two"].status is SemanticEvaluatorObligationResolutionStatus.DENIED
    denied = outcomes["evaluation-two"]
    assert denied.reason.name == "EVALUATOR_BINDING_MISMATCH"
    assert denied.trusted_evaluator_resolution is None
    assert denied.target_context_id is None and denied.pr_id is None
    assert denied.authoritative_dependencies == ()
    assert denied.assignment is None and denied.effective_subject is None
    assert calls == {"target": 1 if dimension == "target" else 0, "pr": 1 if dimension == "pr" else 0}
    assert result.authoritative_dependencies == (_dependency() if dimension == "target" else _dependency("p"),)


def test_contract_derived_assignment_binds_exact_current_obligation_material_context_and_resolution():
    config = _semantic_config_bytes()
    result, contract, materialization = _resolved_product(config_bytes=config)
    outcome = result.obligation_outcomes[0]
    assignment = outcome.assignment
    trusted = outcome.trusted_evaluator_resolution
    assert assignment is not None and trusted is not None
    resolved = outcome.resolved_obligation
    assert type(resolved) is current_semantic_review.ResolvedSemanticEvaluatorObligation
    assert resolved.semantic_requirement == outcome.semantic_requirement
    assert resolved.obligation_id == outcome.obligation_id
    assert resolved.evaluator_parameters == outcome.obligation.parameters
    assert resolved.trusted_evaluator_resolution is trusted
    assert resolved.current_review_materials == derive_current_review_materials(materialization)
    assert resolved.authoritative_dependencies == outcome.authoritative_dependencies
    assert resolved.assignment is assignment and resolved.effective_subject is outcome.effective_subject
    assert assignment.repository_id == REPOSITORY
    assert assignment.task_id == TaskId("task")
    assert assignment.contract_id == contract.contract_id
    assert assignment.contract_raw_sha256 == contract.contract_raw_sha256
    assert assignment.target_registration_id == contract.target_registration_id
    assert assignment.policy_epoch_identity == EPOCH
    assert assignment.candidate_id == materialization.candidate_id
    assert assignment.candidate_materialization_id == materialization.materialization_id
    assert assignment.obligation_id == outcome.obligation.obligation_id
    assert assignment.semantic_evaluator_resolution_id == trusted.resolution_id
    assert assignment.requirements == (outcome.obligation.semantic_requirement,)
    assert len(assignment.requirements) == 1
    assert assignment.material_assignments[0].requirement_id == assignment.requirements[0].requirement_id
    assert assignment.material_assignments[0].required_material_ids == tuple(x.material_id for x in derive_current_review_materials(materialization))
    assert assignment.required_context_ids == trusted.required_trusted_context_ids
    assert assignment.composition_rule == trusted.composition_rule
    assert assignment.partition_rule == trusted.partition_rule
    assert assignment.composition_rule.required_slots == trusted.review_slots
    slot = assignment.composition_rule.required_slots[0]
    assert slot.profile == trusted.review_slots[0].profile
    expected = contract_json_value_digest((
        "autodev.contract-semantic-review-assignment/v1",
        outcome.obligation.obligation_id.raw_sha256.value, trusted.resolution_id.raw_sha256.value,
        REPOSITORY.value, TaskId("task").value, materialization.candidate_id.value,
        materialization.materialization_id.raw_sha256.value, contract.contract_id.value,
        contract.contract_raw_sha256.value, contract.target_registration_id.raw_sha256.value,
        EPOCH.manifest_id.raw_sha256.value, outcome.obligation.semantic_requirement.requirement_id.value,
        tuple(x.material_id.value for x in derive_current_review_materials(materialization)),
        tuple(x.value for x in trusted.required_trusted_context_ids),
        trusted.composition_rule.composition_rule_id.value, trusted.partition_rule.value,
    ))
    assert assignment.assignment_id.value == expected.value


def test_two_evaluator_obligations_receive_two_single_requirement_assignments():
    raw = _semantic_config_bytes()
    contract, _, _ = _semantic_contract_many((
        ("evaluation-one", "config-one", raw), ("evaluation-two", "config-two", raw),
    ))
    materialization = _materialization(CandidateId("current"), contract_raw=contract.contract_raw_sha256)
    result = resolve_current_semantic_review(
        _canonical_inputs(contract, candidate=_candidate(materialization, contract=contract), materialization=materialization),
        applicability_context=_current_applicability_context(contract),
        byte_reader=_trusted_reader(contract, {"config-one": raw, "config-two": raw}), semantic_context_source=None,
    )
    assert result.status is CurrentSemanticReviewResolutionStatus.RESOLVED
    first, second = result.obligation_outcomes
    assert first.status is second.status is SemanticEvaluatorObligationResolutionStatus.RESOLVED
    assert first.obligation.semantic_requirement == second.obligation.semantic_requirement
    assert first.obligation.obligation_id != second.obligation.obligation_id
    assert first.assignment is not None and second.assignment is not None
    assert first.resolved_obligation is not None and second.resolved_obligation is not None
    assert first.resolved_obligation.current_review_materials is second.resolved_obligation.current_review_materials
    assert first.assignment.requirements == second.assignment.requirements == (first.obligation.semantic_requirement,)
    assert first.assignment.assignment_id != second.assignment.assignment_id
    assert first.assignment.obligation_id != second.assignment.obligation_id


def test_assignment_identity_binds_all_frozen_inputs_and_excludes_authorization_and_admission_event():
    import autodev_control.trusted.current_semantic_review as current_module

    result, _, materialization = _resolved_product()
    baseline = result.obligation_outcomes[0]
    inputs = _canonical_inputs(_semantic_contract(config_bytes=_semantic_config_bytes())[0],
                               candidate=_candidate(materialization), materialization=materialization)
    # Use the exact inputs and obligation facts represented by the current resolver result.
    baseline_obligation = baseline.obligation
    resolution = baseline.trusted_evaluator_resolution
    assert resolution is not None
    materials = tuple(x.material_id for x in derive_current_review_materials(materialization))
    make = current_module._trusted_assignment
    baseline_assignment = make(inputs, materialization, baseline_obligation, resolution, materials)
    moved = []

    def changed_resolution(**updates):
        vals = {f.name: getattr(resolution, f.name) for f in fields(TrustedSemanticEvaluatorResolution)}
        vals.update(updates)
        return _mint(TrustedSemanticEvaluatorResolution, **vals)

    moved.append(make(inputs, _materialization(CandidateId("other"), contract_raw=inputs.contract.contract_raw_sha256), baseline_obligation, resolution, materials))
    moved.append(make(inputs, materialization, replace(baseline_obligation, obligation_id=type(baseline_obligation.obligation_id)(RawSha256("d" * 64))), resolution, materials))
    moved.append(make(inputs, materialization, replace(baseline_obligation, semantic_requirement=SemanticRequirement(
        SemanticRequirementId("moved-requirement"), RawSha256("d" * 64))), resolution, materials))
    moved.append(make(inputs, materialization, baseline_obligation, changed_resolution(
        resolution_id=type(resolution.resolution_id)(RawSha256("d" * 64))), materials))
    moved.append(make(inputs, materialization, baseline_obligation, changed_resolution(
        required_trusted_context_ids=(__import__("autodev_control.trusted.review", fromlist=["TrustedContextId"]).TrustedContextId("context-a"),)), materials))
    moved.append(make(inputs, materialization, baseline_obligation, changed_resolution(
        composition_rule=replace(resolution.composition_rule, composition_rule_id=type(resolution.composition_rule.composition_rule_id)("composition-moved"))), materials))
    moved.append(make(inputs, materialization, baseline_obligation, resolution, materials + (type(materials[0])("extra-material"),)))
    moved.append(make(inputs, materialization, baseline_obligation, resolution, ()))
    moved_inputs = _mint(CanonicalCurrentSemanticReviewInputs, **{
        f.name: getattr(inputs, f.name) for f in fields(CanonicalCurrentSemanticReviewInputs)
    })
    object.__setattr__(moved_inputs, "task", _canonical_inputs(inputs.contract, candidate=_candidate(materialization, contract=inputs.contract), materialization=materialization).task)
    object.__setattr__(moved_inputs, "contract", _clone(inputs.contract, target_registration_id=TargetRegistrationId(RawSha256("d" * 64))))
    moved.append(make(moved_inputs, materialization, baseline_obligation, resolution, materials))
    object.__setattr__(moved_inputs, "contract", _clone(inputs.contract, contract_raw_sha256=RawSha256("e" * 64)))
    moved.append(make(moved_inputs, materialization, baseline_obligation, resolution, materials))
    object.__setattr__(moved_inputs.task, "last_evaluated_policy_epoch_identity", PolicyEpochIdentity(TrustedManifestId(RawSha256("d" * 64))))
    moved.append(make(moved_inputs, materialization, baseline_obligation, resolution, materials))
    assert all(item.assignment_id != baseline_assignment.assignment_id for item in moved)

    # Authorization/admission-event values are intentionally absent from the frozen assignment preimage.
    excluded_inputs = _mint(CanonicalCurrentSemanticReviewInputs, **{
        f.name: getattr(inputs, f.name) for f in fields(CanonicalCurrentSemanticReviewInputs)
    })
    object.__setattr__(excluded_inputs, "task", _canonical_inputs(inputs.contract, candidate=_candidate(materialization, contract=inputs.contract), materialization=materialization).task)
    object.__setattr__(excluded_inputs, "authorization", _mint(
        AdmittedAuthorization, authorization_id=AuthorizationId(RawSha256("e" * 64)),
        task_id=TaskId("task"), contract_id=CONTRACT_ID,
        contract_raw_sha256=inputs.contract.contract_raw_sha256,
        target_registration_id=TARGET, policy_epoch_identity=EPOCH,
    ))
    object.__setattr__(excluded_inputs.task, "admission_event_id", AdmissionEventId("different-admission"))
    assert make(excluded_inputs, materialization, baseline_obligation, resolution, materials).assignment_id == baseline_assignment.assignment_id


def test_effective_subject_binds_exact_current_authority_and_candidate_materialization():
    import autodev_control.trusted.current_semantic_review as current_module

    result, contract, materialization = _resolved_product()
    outcome = result.obligation_outcomes[0]
    subject = outcome.effective_subject
    assignment = outcome.assignment
    assert subject is not None and assignment is not None
    inputs = _canonical_inputs(contract, candidate=_candidate(materialization, contract=contract), materialization=materialization)
    materials = tuple(x.material_id for x in derive_current_review_materials(materialization))
    exact = current_module._trusted_effective_subject(
        inputs, materialization, outcome.obligation, assignment,
        outcome.target_context_id, outcome.pr_id, materials,
        outcome.trusted_evaluator_resolution.required_trusted_context_ids,
    )
    assert subject == exact
    assert subject.repository_id == REPOSITORY
    assert subject.task_id == TaskId("task")
    assert subject.candidate_id == materialization.candidate_id
    assert subject.candidate_materialization_id == materialization.materialization_id
    assert subject.contract_id == contract.contract_id and subject.contract_raw_sha256 == contract.contract_raw_sha256
    assert subject.authorization_id == inputs.authorization.authorization_id
    assert subject.task_admission_event_id == inputs.task.admission_event_id
    assert subject.target_registration_id == TARGET and subject.policy_epoch_identity == EPOCH
    assert subject.base == contract.base_sha
    assert subject.target_context_id is None and subject.pr_id is None
    assert subject.requirement_ids == (outcome.obligation.semantic_requirement.requirement_id,)
    assert subject.required_material_ids == materials
    assert subject.required_context_ids == outcome.trusted_evaluator_resolution.required_trusted_context_ids
    assert subject.composition_rule_id == assignment.composition_rule.composition_rule_id
    assert subject.assignment_id == assignment.assignment_id
    assert subject.obligation_id == outcome.obligation.obligation_id
    expected = contract_json_value_digest((
        "autodev.current-semantic-review-effective-subject/v1",
        assignment.assignment_id.value, outcome.obligation.obligation_id.raw_sha256.value,
        REPOSITORY.value, TaskId("task").value, materialization.candidate_id.value,
        materialization.materialization_id.raw_sha256.value, contract.contract_id.value,
        contract.contract_raw_sha256.value, inputs.authorization.authorization_id.raw_sha256.value,
        inputs.task.admission_event_id.value, contract.target_registration_id.raw_sha256.value,
        EPOCH.manifest_id.raw_sha256.value, contract.base_sha.value, None, None,
        outcome.obligation.semantic_requirement.requirement_id.value,
        tuple(item.value for item in materials),
        tuple(item.value for item in outcome.trusted_evaluator_resolution.required_trusted_context_ids),
        assignment.composition_rule.composition_rule_id.value,
    ))
    assert subject.subject_id.value == expected.value


def test_effective_subject_identity_moves_with_each_frozen_current_subject_input():
    import autodev_control.trusted.current_semantic_review as current_module

    result, contract, materialization = _resolved_product()
    outcome = result.obligation_outcomes[0]
    assignment = outcome.assignment
    resolution = outcome.trusted_evaluator_resolution
    baseline = outcome.effective_subject
    assert assignment is not None and resolution is not None and baseline is not None
    inputs = _canonical_inputs(contract, candidate=_candidate(materialization, contract=contract), materialization=materialization)
    material_ids = tuple(item.material_id for item in derive_current_review_materials(materialization))
    contexts = resolution.required_trusted_context_ids
    build = current_module._trusted_effective_subject

    def changed_assignment(**updates):
        values = {field.name: getattr(assignment, field.name) for field in fields(type(assignment))}
        values.update(updates)
        return _mint(type(assignment), **values)

    variants = []
    variants.append(build(inputs, _materialization(CandidateId("current"), variant="second", contract_raw=contract.contract_raw_sha256), outcome.obligation, assignment, None, None, material_ids, contexts))
    variants.append(build(inputs, materialization, outcome.obligation, changed_assignment(assignment_id=type(assignment.assignment_id)("assignment-moved")), None, None, material_ids, contexts))
    variants.append(build(inputs, materialization, replace(outcome.obligation, obligation_id=type(outcome.obligation.obligation_id)(RawSha256("d" * 64))), assignment, None, None, material_ids, contexts))
    variants.append(build(inputs, _materialization(CandidateId("candidate-moved"), contract_raw=contract.contract_raw_sha256), outcome.obligation, assignment, None, None, material_ids, contexts))
    variants.append(build(inputs, materialization, outcome.obligation, assignment, TargetContextId("target-moved"), None, material_ids, contexts))
    variants.append(build(inputs, materialization, outcome.obligation, assignment, None, PullRequestIdentity("pr-moved"), material_ids, contexts))
    variants.append(build(inputs, materialization, outcome.obligation, assignment, None, None, material_ids + (type(material_ids[0])("material-moved"),), contexts))
    variants.append(build(inputs, materialization, outcome.obligation, assignment, None, None, material_ids, (TrustedContextId("context-moved"),)))
    moved_composition = replace(assignment.composition_rule, composition_rule_id=type(assignment.composition_rule.composition_rule_id)("composition-moved"))
    variants.append(build(inputs, materialization, outcome.obligation, changed_assignment(composition_rule=moved_composition), None, None, material_ids, contexts))

    moved_inputs = _mint(CanonicalCurrentSemanticReviewInputs, **{
        field.name: getattr(inputs, field.name) for field in fields(CanonicalCurrentSemanticReviewInputs)
    })
    object.__setattr__(moved_inputs, "authorization", _mint(
        AdmittedAuthorization, authorization_id=AuthorizationId(RawSha256("e" * 64)), task_id=TaskId("task"),
        contract_id=contract.contract_id, contract_raw_sha256=contract.contract_raw_sha256,
        target_registration_id=TARGET, policy_epoch_identity=EPOCH,
    ))
    variants.append(build(moved_inputs, materialization, outcome.obligation, assignment, None, None, material_ids, contexts))
    moved_task = _canonical_inputs(contract, candidate=_candidate(materialization, contract=contract), materialization=materialization).task
    object.__setattr__(moved_task, "admission_event_id", AdmissionEventId("admission-moved"))
    object.__setattr__(moved_inputs, "task", moved_task)
    variants.append(build(moved_inputs, materialization, outcome.obligation, assignment, None, None, material_ids, contexts))
    moved_contract = _clone(contract, base_sha=GitSha("d" * 40))
    object.__setattr__(moved_inputs, "contract", moved_contract)
    variants.append(build(moved_inputs, materialization, outcome.obligation, assignment, None, None, material_ids, contexts))
    moved_contract = _clone(contract, target_registration_id=TargetRegistrationId(RawSha256("d" * 64)))
    object.__setattr__(moved_inputs, "contract", moved_contract)
    variants.append(build(moved_inputs, materialization, outcome.obligation, assignment, None, None, material_ids, contexts))
    moved_task = _canonical_inputs(contract, candidate=_candidate(materialization, contract=contract), materialization=materialization).task
    object.__setattr__(moved_task, "last_evaluated_policy_epoch_identity", PolicyEpochIdentity(TrustedManifestId(RawSha256("d" * 64))))
    object.__setattr__(moved_inputs, "task", moved_task)
    variants.append(build(moved_inputs, materialization, outcome.obligation, assignment, None, None, material_ids, contexts))
    assert all(item.subject_id != baseline.subject_id for item in variants)


@pytest.mark.parametrize("mismatch", (
    "policy_epoch", "config_identity", "mechanism", "parameters_valid",
    "applicable", "operational_prerequisites", "prerequisite_outside_contract",
))
def test_a7_mismatch_is_per_obligation_denial_and_prevents_any_context_demand(monkeypatch, mismatch):
    config_bytes = _semantic_config_bytes(target="REQUIRED", pr="REQUIRED")
    contract, _, _ = _semantic_contract(config_bytes=config_bytes)
    materialization = _materialization(CandidateId("current"), contract_raw=contract.contract_raw_sha256)
    original = current_semantic_review.resolve_semantic_evaluator_config
    calls = {"target": 0, "pr": 0}

    def forged_resolution(basic, raw):
        original_result = original(basic, raw)
        assert original_result.resolution is not None
        values = {field.name: getattr(original_result.resolution, field.name) for field in fields(TrustedSemanticEvaluatorResolution)}
        if mismatch == "policy_epoch":
            values["policy_epoch_identity"] = PolicyEpochIdentity(TrustedManifestId(RawSha256("d" * 64)))
        elif mismatch == "config_identity":
            values["config_identity"] = TrustedConfigIdentity(ImmutableConfigId("other"), RootManagedResourceId("other-resource"), RawSha256("d" * 64))
        elif mismatch == "mechanism":
            values["mechanism"] = EvaluatorMechanism.DETERMINISTIC
        elif mismatch == "parameters_valid":
            values["parameters_valid"] = False
        elif mismatch == "applicable":
            values["applicable"] = False
        elif mismatch == "operational_prerequisites":
            values["operational_prerequisites"] = (TaskCapability.IMPLEMENTATION,)
        else:
            values["operational_prerequisites"] = (TaskCapability.MERGE,)
        return SemanticEvaluatorConfigResolutionResult(
            SemanticEvaluatorConfigResolutionStatus.RESOLVED,
            SemanticEvaluatorConfigResolutionReason.RESOLVED,
            _mint(TrustedSemanticEvaluatorResolution, **values),
        )

    def target_should_not_run(*_):
        calls["target"] += 1
        raise AssertionError("A7-denied obligation requested target context")

    def pr_should_not_run(*_):
        calls["pr"] += 1
        raise AssertionError("A7-denied obligation requested PR context")

    monkeypatch.setattr(current_semantic_review, "resolve_semantic_evaluator_config", forged_resolution)
    monkeypatch.setattr(current_semantic_review, "resolve_current_semantic_target_context", target_should_not_run)
    monkeypatch.setattr(current_semantic_review, "resolve_current_semantic_pull_request_context", pr_should_not_run)
    result = resolve_current_semantic_review(
        _canonical_inputs(contract, candidate=_candidate(materialization, contract=contract), materialization=materialization),
        applicability_context=_current_applicability_context(contract),
        byte_reader=_trusted_reader(contract, config_bytes), semantic_context_source=None,
    )
    outcome = result.obligation_outcomes[0]
    assert outcome.status is SemanticEvaluatorObligationResolutionStatus.DENIED
    assert outcome.reason.name == "EVALUATOR_BINDING_MISMATCH"
    assert outcome.trusted_evaluator_resolution is None
    assert outcome.target_context_id is None and outcome.pr_id is None
    assert outcome.authoritative_dependencies == ()
    assert outcome.assignment is None and outcome.effective_subject is None
    assert calls == {"target": 0, "pr": 0}


@pytest.mark.parametrize(("target_requirement", "pr_requirement", "expected_calls"), (
    ("NOT_APPLICABLE", "NOT_APPLICABLE", {"target": 0, "pr": 0}),
    ("REQUIRED", "NOT_APPLICABLE", {"target": 1, "pr": 0}),
    ("NOT_APPLICABLE", "REQUIRED", {"target": 0, "pr": 1}),
    ("REQUIRED", "REQUIRED", {"target": 1, "pr": 1}),
))
def test_b1_demand_is_exactly_per_current_resolved_requirement(monkeypatch, target_requirement, pr_requirement, expected_calls):
    config_bytes = _semantic_config_bytes(target=target_requirement, pr=pr_requirement)
    contract, _, _ = _semantic_contract(config_bytes=config_bytes)
    materialization = _materialization(CandidateId("current"), contract_raw=contract.contract_raw_sha256)
    calls = []

    def target(*_):
        calls.append("target")
        return _target_success()

    def pr(*_):
        calls.append("pr")
        return _pr_success()

    monkeypatch.setattr(current_semantic_review, "resolve_current_semantic_target_context", target)
    monkeypatch.setattr(current_semantic_review, "resolve_current_semantic_pull_request_context", pr)
    result = resolve_current_semantic_review(
        _canonical_inputs(contract, candidate=_candidate(materialization, contract=contract), materialization=materialization),
        applicability_context=_current_applicability_context(contract), byte_reader=_trusted_reader(contract, config_bytes),
        semantic_context_source=None,
    )
    assert result.status is CurrentSemanticReviewResolutionStatus.RESOLVED
    assert calls == (["target"] * expected_calls["target"] + ["pr"] * expected_calls["pr"])
    outcome = result.obligation_outcomes[0]
    assert outcome.status is SemanticEvaluatorObligationResolutionStatus.RESOLVED
    assert (outcome.target_context_id is not None) is (target_requirement == "REQUIRED")
    assert (outcome.pr_id is not None) is (pr_requirement == "REQUIRED")
    expected_dependencies = (
        (() if target_requirement == "NOT_APPLICABLE" else _target_success().dependencies)
        + (() if pr_requirement == "NOT_APPLICABLE" else _pr_success().dependencies)
    )
    assert outcome.authoritative_dependencies == expected_dependencies


@pytest.mark.parametrize("reason", (
    CurrentSemanticTargetContextReason.SOURCE_UNAVAILABLE,
    CurrentSemanticTargetContextReason.TARGET_PROFILE_SET_UNAVAILABLE,
    CurrentSemanticTargetContextReason.TARGET_PROFILE_SOURCE_UNAVAILABLE,
    CurrentSemanticTargetContextReason.TARGET_OBSERVATION_UNAVAILABLE,
))
def test_target_b1_indeterminate_products_map_only_target_required_obligation(monkeypatch, reason):
    product = CurrentSemanticTargetContextResolution(SemanticContextResolutionStatus.INDETERMINATE, reason)
    result, calls = _resolve_with_context_products(monkeypatch, target="REQUIRED", target_product=product)
    outcome = result.obligation_outcomes[0]
    assert calls == {"target": 1, "pr": 0}
    assert outcome.status is SemanticEvaluatorObligationResolutionStatus.INDETERMINATE
    assert outcome.reason.name == "TARGET_CONTEXT_UNAVAILABLE"
    assert outcome.target_context_id is None and outcome.authoritative_dependencies == ()


@pytest.mark.parametrize(("reason", "expected"), (
    (CurrentSemanticTargetContextReason.TARGET_CONTEXT_LIMIT_EXCEEDED, "TARGET_CONTEXT_LIMIT_EXCEEDED"),
    (CurrentSemanticTargetContextReason.SOURCE_INVALID, "TARGET_CONTEXT_CONFLICT"),
    (CurrentSemanticTargetContextReason.TARGET_PROFILE_BINDING_MISMATCH, "TARGET_CONTEXT_CONFLICT"),
    (CurrentSemanticTargetContextReason.TARGET_OBSERVATION_CONFLICT, "TARGET_CONTEXT_CONFLICT"),
))
def test_target_b1_denied_products_have_exact_issue32_projection(monkeypatch, reason, expected):
    product = CurrentSemanticTargetContextResolution(SemanticContextResolutionStatus.DENIED, reason)
    result, _ = _resolve_with_context_products(monkeypatch, target="REQUIRED", target_product=product)
    outcome = result.obligation_outcomes[0]
    assert outcome.status is SemanticEvaluatorObligationResolutionStatus.DENIED
    assert outcome.reason.name == expected
    assert outcome.target_context_id is None and outcome.authoritative_dependencies == ()


@pytest.mark.parametrize("malformed", (
    "wrong_reason", "nonresolved_success_reason", "missing_id", "state_failure",
    "wrong_id_type", "zero_dependencies", "too_many_dependencies", "noncanonical_order", "duplicate_locator",
    "mutable_dependencies",
))
def test_malformed_target_b1_products_fail_closed_without_leaking_context(monkeypatch, malformed):
    dependencies = (_dependency(),)
    values = dict(
        status=SemanticContextResolutionStatus.RESOLVED,
        reason=CurrentSemanticTargetContextReason.RESOLVED,
        target_context_id=TargetContextId("target-context"), dependencies=dependencies,
        state_read_failure=None,
    )
    if malformed == "wrong_reason":
        values["reason"] = CurrentSemanticTargetContextReason.SOURCE_INVALID
    elif malformed == "nonresolved_success_reason":
        values["status"] = SemanticContextResolutionStatus.DENIED
    elif malformed == "missing_id":
        values["target_context_id"] = None
    elif malformed == "wrong_id_type":
        values["target_context_id"] = "target-context"
    elif malformed == "state_failure":
        values["state_read_failure"] = StateReadFailure.UNAVAILABLE
    elif malformed == "zero_dependencies":
        values["dependencies"] = ()
    elif malformed == "too_many_dependencies":
        values["dependencies"] = tuple(_dependency(f"{item:03}") for item in range(65))
    elif malformed == "noncanonical_order":
        values["dependencies"] = (_dependency("z"), _dependency("a"))
    elif malformed == "mutable_dependencies":
        values["dependencies"] = [_dependency()]
    else:
        values["dependencies"] = (_dependency(), _dependency())
    product = _mint(CurrentSemanticTargetContextResolution, **values)
    result, _ = _resolve_with_context_products(monkeypatch, target="REQUIRED", target_product=product)
    outcome = result.obligation_outcomes[0]
    assert outcome.status is SemanticEvaluatorObligationResolutionStatus.DENIED
    assert outcome.reason.name == "TARGET_CONTEXT_CONFLICT"
    assert outcome.target_context_id is None and outcome.authoritative_dependencies == ()


@pytest.mark.parametrize("count", (1, 64))
def test_valid_target_b1_dependencies_are_copied_unchanged_at_frozen_bounds(monkeypatch, count):
    dependencies = tuple(_dependency(f"{item:03}") for item in range(count))
    result, _ = _resolve_with_context_products(monkeypatch, target="REQUIRED", target_product=_target_success(dependencies))
    outcome = result.obligation_outcomes[0]
    assert outcome.status is SemanticEvaluatorObligationResolutionStatus.RESOLVED
    assert outcome.target_context_id == TargetContextId("target-context")
    assert outcome.authoritative_dependencies == dependencies


@pytest.mark.parametrize("reason", (
    CurrentSemanticPullRequestContextReason.SOURCE_UNAVAILABLE,
    CurrentSemanticPullRequestContextReason.PR_CONTEXT_UNAVAILABLE,
    CurrentSemanticPullRequestContextReason.PR_OBSERVATION_UNAVAILABLE,
    CurrentSemanticPullRequestContextReason.PR_OBSERVATION_INCOMPLETE,
    CurrentSemanticPullRequestContextReason.PR_OBSERVATION_MOVED,
))
def test_pr_b1_indeterminate_products_map_only_pr_required_obligation(monkeypatch, reason):
    product = CurrentSemanticPullRequestContextResolution(SemanticContextResolutionStatus.INDETERMINATE, reason)
    result, calls = _resolve_with_context_products(monkeypatch, pr="REQUIRED", pr_product=product)
    outcome = result.obligation_outcomes[0]
    assert calls == {"target": 0, "pr": 1}
    assert outcome.status is SemanticEvaluatorObligationResolutionStatus.INDETERMINATE
    assert outcome.reason.name == "PR_CONTEXT_UNAVAILABLE"
    assert outcome.pr_id is None and outcome.authoritative_dependencies == ()


@pytest.mark.parametrize("reason", (
    CurrentSemanticPullRequestContextReason.SOURCE_INVALID,
    CurrentSemanticPullRequestContextReason.PR_CONTEXT_CONFLICT,
    CurrentSemanticPullRequestContextReason.PR_CONTEXT_LIMIT_EXCEEDED,
))
def test_pr_b1_denied_and_unreachable_limit_products_map_to_conflict(monkeypatch, reason):
    product = CurrentSemanticPullRequestContextResolution(SemanticContextResolutionStatus.DENIED, reason)
    result, _ = _resolve_with_context_products(monkeypatch, pr="REQUIRED", pr_product=product)
    outcome = result.obligation_outcomes[0]
    assert outcome.status is SemanticEvaluatorObligationResolutionStatus.DENIED
    assert outcome.reason.name == "PR_CONTEXT_CONFLICT"
    assert outcome.pr_id is None and outcome.authoritative_dependencies == ()


def test_pr_context_limit_reason_is_not_in_issue32_outcome_domain():
    names = {item.name for item in current_semantic_review.SemanticEvaluatorObligationResolutionReason}
    assert "PR_CONTEXT_LIMIT_EXCEEDED" not in names
    assert "PR_CONTEXT_UNAVAILABLE" in names
    assert "PR_CONTEXT_CONFLICT" in names


@pytest.mark.parametrize("malformed", (
    "wrong_reason", "nonresolved_success_reason", "missing_id", "state_failure",
    "wrong_id_type", "zero_dependencies", "two_dependencies", "invalid_dependency_type", "mutable_dependencies",
))
def test_malformed_pr_b1_products_fail_closed_without_leaking_context(monkeypatch, malformed):
    values = dict(
        status=SemanticContextResolutionStatus.RESOLVED,
        reason=CurrentSemanticPullRequestContextReason.RESOLVED,
        pull_request_identity=PullRequestIdentity("pr-context"), dependencies=(_dependency("p"),),
        state_read_failure=None,
    )
    if malformed == "wrong_reason":
        values["reason"] = CurrentSemanticPullRequestContextReason.SOURCE_INVALID
    elif malformed == "nonresolved_success_reason":
        values["status"] = SemanticContextResolutionStatus.DENIED
    elif malformed == "missing_id":
        values["pull_request_identity"] = None
    elif malformed == "wrong_id_type":
        values["pull_request_identity"] = "pr-context"
    elif malformed == "state_failure":
        values["state_read_failure"] = StateReadFailure.UNAVAILABLE
    elif malformed == "zero_dependencies":
        values["dependencies"] = ()
    elif malformed == "two_dependencies":
        values["dependencies"] = (_dependency("p"), _dependency("q"))
    elif malformed == "invalid_dependency_type":
        values["dependencies"] = ("not-a-dependency",)
    else:
        values["dependencies"] = [_dependency("p")]
    product = _mint(CurrentSemanticPullRequestContextResolution, **values)
    result, _ = _resolve_with_context_products(monkeypatch, pr="REQUIRED", pr_product=product)
    outcome = result.obligation_outcomes[0]
    assert outcome.status is SemanticEvaluatorObligationResolutionStatus.DENIED
    assert outcome.reason.name == "PR_CONTEXT_CONFLICT"
    assert outcome.pr_id is None and outcome.authoritative_dependencies == ()


def test_valid_pr_b1_identity_and_single_dependency_are_copied_unchanged(monkeypatch):
    dependency = _dependency("p")
    result, _ = _resolve_with_context_products(monkeypatch, pr="REQUIRED", pr_product=_pr_success((dependency,)))
    outcome = result.obligation_outcomes[0]
    assert outcome.status is SemanticEvaluatorObligationResolutionStatus.RESOLVED
    assert outcome.pr_id == PullRequestIdentity("pr-context")
    assert outcome.authoritative_dependencies == (dependency,)


@pytest.mark.parametrize("malformed_dimension", ("target", "pr"))
def test_malformed_b1_dimension_does_not_suppress_independent_demand_but_blocks_projection(monkeypatch, malformed_dimension):
    target_product = _mint(
        CurrentSemanticTargetContextResolution,
        status=SemanticContextResolutionStatus.RESOLVED,
        reason=CurrentSemanticTargetContextReason.RESOLVED,
        target_context_id=TargetContextId("target-context"),
        dependencies=() if malformed_dimension == "target" else (_dependency(),),
        state_read_failure=None,
    )
    pr_product = _pr_success(( _dependency("p"), ))
    if malformed_dimension == "pr":
        pr_product = _mint(
            CurrentSemanticPullRequestContextResolution,
            status=SemanticContextResolutionStatus.RESOLVED,
            reason=CurrentSemanticPullRequestContextReason.RESOLVED,
            pull_request_identity=PullRequestIdentity("pr-context"),
            dependencies=(_dependency("p"), _dependency("q")),
            state_read_failure=None,
        )
    result, calls = _resolve_with_context_products(
        monkeypatch, target="REQUIRED", pr="REQUIRED",
        target_product=target_product, pr_product=pr_product,
    )
    outcome = result.obligation_outcomes[0]
    assert calls == {"target": 1, "pr": 1}
    assert outcome.status is SemanticEvaluatorObligationResolutionStatus.DENIED
    assert outcome.reason.name == ("TARGET_CONTEXT_CONFLICT" if malformed_dimension == "target" else "PR_CONTEXT_CONFLICT")
    assert outcome.target_context_id is None and outcome.pr_id is None
    assert outcome.authoritative_dependencies == ()


def test_target_and_pr_dependencies_form_an_uncapped_exact_65_member_per_obligation_and_global_union(monkeypatch):
    target_dependencies = tuple(_dependency(f"{item:03}") for item in range(64))
    pr_dependency = _dependency("z")
    result, _ = _resolve_with_context_products(
        monkeypatch, target="REQUIRED", pr="REQUIRED",
        target_product=_target_success(target_dependencies), pr_product=_pr_success((pr_dependency,)),
    )
    outcome = result.obligation_outcomes[0]
    expected = target_dependencies + (pr_dependency,)
    assert outcome.status is SemanticEvaluatorObligationResolutionStatus.RESOLVED
    assert len(outcome.authoritative_dependencies) == 65
    assert outcome.authoritative_dependencies == expected
    assert len(result.authoritative_dependencies) == 65
    assert result.authoritative_dependencies == expected


def test_final_binding_cell_formula_counts_65_per_obligation_dependencies_and_65_global_f(monkeypatch):
    target_dependencies = tuple(_dependency(f"{item:03}") for item in range(64))
    pr_dependency = _dependency("z")
    result, _ = _resolve_with_context_products(
        monkeypatch, target="REQUIRED", pr="REQUIRED",
        target_product=_target_success(target_dependencies), pr_product=_pr_success((pr_dependency,)),
    )
    outcome = result.obligation_outcomes[0]
    resolution = outcome.trusted_evaluator_resolution
    assert result.status is CurrentSemanticReviewResolutionStatus.RESOLVED
    assert outcome.status is SemanticEvaluatorObligationResolutionStatus.RESOLVED
    assert len(outcome.authoritative_dependencies) == 65
    assert len(result.authoritative_dependencies) == 65
    assert resolution.target_context_requirement is SemanticReviewContextRequirement.REQUIRED
    assert resolution.pr_context_requirement is SemanticReviewContextRequirement.REQUIRED

    per_obligation_cells = (
        1 + len(outcome.resolved_obligation.current_review_materials)
        + len(resolution.review_slots) + len(resolution.required_trusted_context_ids)
        + len(outcome.authoritative_dependencies)
    )
    frozen_total = len(result.authoritative_dependencies) + per_obligation_cells
    stale_boolean_total = (
        len(result.authoritative_dependencies) + 1
        + len(outcome.resolved_obligation.current_review_materials)
        + len(resolution.review_slots) + len(resolution.required_trusted_context_ids) + 2
    )
    assert frozen_total == current_semantic_review._final_binding_cell_count(
        len(outcome.resolved_obligation.current_review_materials),
        (current_semantic_review._ObligationWork(
            outcome.obligation, CurrentSemanticReviewResolutionStatus.RESOLVED,
            outcome.reason, outcome.semantic_config_status, outcome.semantic_config_reason,
            resolution, outcome.target_context_id, outcome.pr_id, outcome.authoritative_dependencies,
        ),),
        len(result.authoritative_dependencies),
    )
    assert frozen_total == stale_boolean_total + (65 - 2)
    assert frozen_total - len(result.authoritative_dependencies) >= 65


@pytest.mark.parametrize(("material_count_delta", "expected_status", "expected_reason"), (
    (0, CurrentSemanticReviewResolutionStatus.RESOLVED, CurrentSemanticReviewResolutionReason.RESOLVED),
    (1, CurrentSemanticReviewResolutionStatus.DENIED, CurrentSemanticReviewResolutionReason.RESOLUTION_LIMIT_EXCEEDED),
))
def test_final_dependency_cardinality_formula_accepts_exact_limit_and_denies_plus_one(
    monkeypatch, material_count_delta, expected_status, expected_reason,
):
    target_dependencies = tuple(_dependency(f"{item:03}") for item in range(64))
    pr_dependency = _dependency("z")
    config_bytes = _semantic_config_bytes(target="REQUIRED", pr="REQUIRED")
    contract, _, _ = _semantic_contract(config_bytes=config_bytes)
    materialization = _materialization(CandidateId("current"), contract_raw=contract.contract_raw_sha256)
    inputs = _canonical_inputs(
        contract, candidate=_candidate(materialization, contract=contract), materialization=materialization,
    )
    monkeypatch.setattr(
        current_semantic_review, "resolve_current_semantic_target_context",
        lambda *_: _target_success(target_dependencies),
    )
    monkeypatch.setattr(
        current_semantic_review, "resolve_current_semantic_pull_request_context",
        lambda *_: _pr_success((pr_dependency,)),
    )
    applicability_context = _current_applicability_context(contract)
    reader = _trusted_reader(contract, config_bytes)

    # Resolve once with the ordinary one-material fixture to obtain the exact
    # frozen non-material cell contribution for this real semantic config.
    monkeypatch.setattr(current_semantic_review, "derive_current_review_materials", derive_current_review_materials)
    prototype = resolve_current_semantic_review(
        inputs, applicability_context=applicability_context, byte_reader=reader,
        semantic_context_source=None,
    )
    prototype_outcome = prototype.obligation_outcomes[0]
    prototype_resolution = prototype_outcome.trusted_evaluator_resolution
    fixed_cells = (
        len(prototype.authoritative_dependencies) + 1
        + len(prototype_resolution.review_slots)
        + len(prototype_resolution.required_trusted_context_ids)
        + len(prototype_outcome.authoritative_dependencies)
    )
    exact_material_count = current_semantic_review.MAX_SEMANTIC_RESOLUTION_BINDING_CELLS - fixed_cells
    material = derive_current_review_materials(materialization)[0]
    large_materials = tuple(
        _clone(material, material_id=MaterialIdentity(f"{index:064x}"))
        for index in range(exact_material_count + material_count_delta)
    )
    monkeypatch.setattr(current_semantic_review, "derive_current_review_materials", lambda *_: large_materials)
    # The count check precedes product construction; retain the already-valid
    # products to keep this adversarial boundary test bounded in work.
    monkeypatch.setattr(
        current_semantic_review, "_trusted_assignment",
        lambda *_: prototype_outcome.assignment,
    )
    monkeypatch.setattr(
        current_semantic_review, "_trusted_effective_subject",
        lambda *_: prototype_outcome.effective_subject,
    )

    result = resolve_current_semantic_review(
        inputs, applicability_context=applicability_context, byte_reader=reader,
        semantic_context_source=None,
    )
    actual_cells = (
        len(prototype.authoritative_dependencies) + 1 + len(large_materials)
        + len(prototype_resolution.review_slots)
        + len(prototype_resolution.required_trusted_context_ids)
        + len(prototype_outcome.authoritative_dependencies)
    )
    stale_boolean_cells = (
        len(prototype.authoritative_dependencies) + 1 + exact_material_count
        + len(prototype_resolution.review_slots)
        + len(prototype_resolution.required_trusted_context_ids) + 2
    )
    assert len(prototype_outcome.authoritative_dependencies) == 65
    assert len(prototype.authoritative_dependencies) == 65
    assert prototype_resolution.target_context_requirement is SemanticReviewContextRequirement.REQUIRED
    assert prototype_resolution.pr_context_requirement is SemanticReviewContextRequirement.REQUIRED
    assert len(large_materials) == exact_material_count + material_count_delta
    assert actual_cells == current_semantic_review.MAX_SEMANTIC_RESOLUTION_BINDING_CELLS + material_count_delta
    assert stale_boolean_cells < current_semantic_review.MAX_SEMANTIC_RESOLUTION_BINDING_CELLS
    assert current_semantic_review._static_binding_cell_count(1, len(large_materials)) <= current_semantic_review.MAX_SEMANTIC_RESOLUTION_BINDING_CELLS
    assert result.status is expected_status
    assert result.reason is expected_reason
    if material_count_delta == 0:
        assert current_semantic_review._final_binding_cell_count(
            len(large_materials), (current_semantic_review._ObligationWork(
                prototype_outcome.obligation, CurrentSemanticReviewResolutionStatus.RESOLVED,
                prototype_outcome.reason, prototype_outcome.semantic_config_status,
                prototype_outcome.semantic_config_reason, prototype_resolution,
                prototype_outcome.target_context_id, prototype_outcome.pr_id,
                prototype_outcome.authoritative_dependencies,
            ),), len(prototype.authoritative_dependencies),
        ) == current_semantic_review.MAX_SEMANTIC_RESOLUTION_BINDING_CELLS


def test_exact_duplicate_cross_dimension_dependency_is_deduplicated_without_rewriting(monkeypatch):
    dependency = _dependency()
    result, _ = _resolve_with_context_products(
        monkeypatch, target="REQUIRED", pr="REQUIRED",
        target_product=_target_success((dependency,)), pr_product=_pr_success((dependency,)),
    )
    outcome = result.obligation_outcomes[0]
    assert outcome.status is SemanticEvaluatorObligationResolutionStatus.RESOLVED
    assert outcome.authoritative_dependencies == (dependency,)
    assert result.authoritative_dependencies == (dependency,)


def test_global_f_canonicalizes_distinct_dependency_locators(monkeypatch):
    target_dependency = _dependency("z")
    pr_dependency = _dependency("a")
    result, _ = _resolve_with_context_products(
        monkeypatch, target="REQUIRED", pr="REQUIRED",
        target_product=_target_success((target_dependency,)), pr_product=_pr_success((pr_dependency,)),
    )
    outcome = result.obligation_outcomes[0]
    assert outcome.status is SemanticEvaluatorObligationResolutionStatus.RESOLVED
    assert outcome.authoritative_dependencies == (pr_dependency, target_dependency)
    assert result.authoritative_dependencies == (pr_dependency, target_dependency)


def test_same_dependency_locator_with_conflicting_binding_fails_global_closed(monkeypatch):
    target_dependency = _dependency()
    conflicting = AuthoritativeStateDependency(
        target_dependency.repository_id, target_dependency.observation_profile_id,
        target_dependency.transport_config_id, AuthoritativeStateBindingId("other-binding"),
    )
    result, _ = _resolve_with_context_products(
        monkeypatch, target="REQUIRED", pr="REQUIRED",
        target_product=_target_success((target_dependency,)), pr_product=_pr_success((conflicting,)),
    )
    assert result.status is CurrentSemanticReviewResolutionStatus.DENIED
    assert result.reason is CurrentSemanticReviewResolutionReason.CANONICAL_INPUT_MISMATCH
    assert result.obligation_outcomes == () and result.authoritative_dependencies == ()


def test_target_failure_does_not_suppress_independently_demanded_pr_observation(monkeypatch):
    target_failure = CurrentSemanticTargetContextResolution(
        SemanticContextResolutionStatus.INDETERMINATE,
        CurrentSemanticTargetContextReason.TARGET_OBSERVATION_UNAVAILABLE,
    )
    result, calls = _resolve_with_context_products(
        monkeypatch, target="REQUIRED", pr="REQUIRED",
        target_product=target_failure, pr_product=_pr_success(),
    )
    outcome = result.obligation_outcomes[0]
    assert calls == {"target": 1, "pr": 1}
    assert outcome.status is SemanticEvaluatorObligationResolutionStatus.INDETERMINATE
    assert outcome.reason.name == "TARGET_CONTEXT_UNAVAILABLE"
    assert outcome.authoritative_dependencies == ()
    assert result.authoritative_dependencies == ()


def test_pr_failure_does_not_suppress_target_only_obligation_or_its_f(monkeypatch):
    target_config = _semantic_config_bytes(target="REQUIRED")
    pr_config = _semantic_config_bytes(pr="REQUIRED")
    contract, _, _ = _semantic_contract_many((
        ("target-evaluation", "target-config", target_config),
        ("pr-evaluation", "pr-config", pr_config),
    ))
    materialization = _materialization(CandidateId("current"), contract_raw=contract.contract_raw_sha256)
    values = {
        "target-config": target_config,
        "pr-config": pr_config,
    }
    calls = []
    def target(*_):
        calls.append("target")
        return _target_success()
    def pr(*_):
        calls.append("pr")
        return CurrentSemanticPullRequestContextResolution(
            SemanticContextResolutionStatus.INDETERMINATE,
            CurrentSemanticPullRequestContextReason.PR_OBSERVATION_INCOMPLETE,
        )

    monkeypatch.setattr(current_semantic_review, "resolve_current_semantic_target_context", target)
    monkeypatch.setattr(current_semantic_review, "resolve_current_semantic_pull_request_context", pr)
    result = resolve_current_semantic_review(
        _canonical_inputs(contract, candidate=_candidate(materialization, contract=contract), materialization=materialization),
        applicability_context=_current_applicability_context(contract), byte_reader=_trusted_reader(contract, values),
        semantic_context_source=None,
    )
    by_id = {item.obligation.evaluator.evaluation_id.value: item for item in result.obligation_outcomes}
    target_outcome, pr_outcome = by_id["target-evaluation"], by_id["pr-evaluation"]
    assert calls == ["target", "pr"]
    assert target_outcome.status is SemanticEvaluatorObligationResolutionStatus.RESOLVED
    assert target_outcome.target_context_id == TargetContextId("target-context")
    assert target_outcome.pr_id is None
    assert target_outcome.authoritative_dependencies == _target_success().dependencies
    assert target_outcome.assignment is not None and target_outcome.effective_subject is not None
    assert pr_outcome.status is SemanticEvaluatorObligationResolutionStatus.INDETERMINATE
    assert pr_outcome.reason.name == "PR_CONTEXT_UNAVAILABLE"
    assert pr_outcome.target_context_id is None and pr_outcome.pr_id is None
    assert pr_outcome.authoritative_dependencies == ()
    assert pr_outcome.assignment is None and pr_outcome.effective_subject is None
    assert result.authoritative_dependencies == _target_success().dependencies


@pytest.mark.parametrize(("material_count", "expected_status", "expected_reason"), (
    (1022, CurrentSemanticReviewResolutionStatus.RESOLVED, CurrentSemanticReviewResolutionReason.RESOLVED),
    (1023, CurrentSemanticReviewResolutionStatus.DENIED, CurrentSemanticReviewResolutionReason.RESOLUTION_LIMIT_EXCEEDED),
    (1024, CurrentSemanticReviewResolutionStatus.DENIED, CurrentSemanticReviewResolutionReason.RESOLUTION_LIMIT_EXCEEDED),
))
def test_resolver_enforces_static_and_final_binding_cell_bounds(monkeypatch, material_count, expected_status, expected_reason):
    # 256 * (1 + 1023) is exactly the frozen static limit.  One review slot
    # per resolved obligation adds 256 final cells, so 1023 materials is the
    # first final-count overflow while remaining within the static bound.
    baseline, contract, materialization = _resolved_product()
    obligation = baseline.obligation_outcomes[0].obligation
    material = derive_current_review_materials(materialization)[0]
    obligations = (obligation,) * 256
    materials = tuple(
        _clone(material, material_id=MaterialIdentity(f"{index:064x}"))
        for index in range(material_count)
    )
    monkeypatch.setattr(current_semantic_review, "derive_semantic_obligations", lambda *_: obligations)
    monkeypatch.setattr(current_semantic_review, "derive_current_review_materials", lambda *_: materials)
    result = resolve_current_semantic_review(
        _canonical_inputs(contract, candidate=_candidate(materialization, contract=contract), materialization=materialization),
        applicability_context=_current_applicability_context(contract),
        byte_reader=_trusted_reader(contract, _semantic_config_bytes()), semantic_context_source=None,
    )
    assert result.status is expected_status
    assert result.reason is expected_reason
    if expected_status is CurrentSemanticReviewResolutionStatus.RESOLVED:
        assert len(result.obligation_outcomes) == 256
        assert current_semantic_review._static_binding_cell_count(256, material_count) <= 262_144
        expected_final_count = len(result.authoritative_dependencies) + sum(
            1 + material_count + len(outcome.trusted_evaluator_resolution.review_slots)
            + len(outcome.trusted_evaluator_resolution.required_trusted_context_ids)
            + len(outcome.authoritative_dependencies)
            for outcome in result.obligation_outcomes
            if outcome.status is SemanticEvaluatorObligationResolutionStatus.RESOLVED
        )
        assert current_semantic_review._final_binding_cell_count(
            material_count, result.obligation_outcomes, len(result.authoritative_dependencies),
        ) == expected_final_count == 262_144
    elif material_count == 1023:
        assert current_semantic_review._static_binding_cell_count(256, material_count) == 262_144
        assert result.obligation_outcomes == ()
    else:
        assert current_semantic_review._static_binding_cell_count(256, material_count) > 262_144
        assert result.obligation_outcomes == ()


def test_current_semantic_evidence_subject_binds_obligation_and_materialization():
    result, _, materialization = _resolved_product()
    outcome = result.obligation_outcomes[0]
    subject = current_semantic_review.build_current_semantic_evidence_subject(
        outcome.resolved_obligation, outcome.trusted_evaluator_resolution.review_slots[0],
        ReviewInvocationId("invocation-current"),
    )
    assert subject.semantic_review_binding.obligation_id == outcome.obligation.obligation_id
    assert subject.semantic_review_binding.candidate_materialization_id == materialization.materialization_id
    assert subject.candidate_id == materialization.candidate_id


@pytest.mark.parametrize("slot_change", ("removed_slot", "changed_profile"))
def test_evidence_subject_builder_rejects_slot_not_exactly_from_resolved_obligation(slot_change):
    result, _, _ = _resolved_product()
    outcome = result.obligation_outcomes[0]
    current_slot = outcome.trusted_evaluator_resolution.review_slots[0]
    if slot_change == "removed_slot":
        forged_slot = _clone(current_slot, slot_id=ReviewSlotId("not-current"))
    else:
        forged_profile = _clone(current_slot.profile, profile_id=type(current_slot.profile.profile_id)("different-profile"))
        forged_slot = _clone(current_slot, profile=forged_profile)
    with pytest.raises(ValueError, match="not from this current evaluator resolution"):
        current_semantic_review.build_current_semantic_evidence_subject(
            outcome.resolved_obligation, forged_slot, ReviewInvocationId("forged-slot"),
        )
    with pytest.raises(TypeError, match="current trusted resolution"):
        current_semantic_review.ResolvedSemanticEvaluatorObligation()


def test_reconstruction_uses_only_evidence_id_and_fails_closed_for_absent_or_nonsemantic_records(monkeypatch):
    result, contract, materialization = _resolved_product()
    semantic = _historical_evidence(result.obligation_outcomes[0])
    store = _reconstruction_backend(monkeypatch, semantic, _canonical_inputs(
        contract, candidate=_candidate(materialization, contract=contract), materialization=materialization,
    ))
    kwargs = dict(
        backend=store, applicability_context=_current_applicability_context(contract),
        byte_reader=_trusted_reader(contract, _semantic_config_bytes()), semantic_context_source=None,
    )
    assert current_semantic_review.reconstruct_current_semantic_evidence_subject(
        EvidenceId("absent"), **kwargs,
    ).status is current_semantic_review.SemanticEvidenceSubjectReconstructionStatus.NOT_FOUND
    nonsemantic = _historical_evidence(result.obligation_outcomes[0], evidence_id="deterministic", nonsemantic=True)
    monkeypatch.setattr(
        InMemoryCanonicalStateBackend, "read_evidence",
        lambda self, requested: nonsemantic if requested == nonsemantic.evidence_id else None,
    )
    assert current_semantic_review.reconstruct_current_semantic_evidence_subject(
        nonsemantic.evidence_id, **kwargs,
    ).status is current_semantic_review.SemanticEvidenceSubjectReconstructionStatus.NOT_SEMANTIC
    with pytest.raises(TypeError):
        current_semantic_review.reconstruct_current_semantic_evidence_subject("not-an-EvidenceId", **kwargs)


@pytest.mark.parametrize("selector", ("obligation", "slot", "missing_binding"))
def test_reconstruction_rejects_missing_current_obligation_slot_or_semantic_binding(monkeypatch, selector):
    result, contract, materialization = _resolved_product()
    outcome = result.obligation_outcomes[0]
    updates = {}
    if selector == "obligation":
        updates["obligation_id"] = SemanticEvaluatorObligationId(RawSha256("8" * 64))
    elif selector == "slot":
        updates["slot_id"] = type(outcome.trusted_evaluator_resolution.review_slots[0].slot_id)("removed-slot")
    else:
        updates["missing_binding"] = True
    record = _historical_evidence(outcome, **updates)
    store = _reconstruction_backend(monkeypatch, record, _canonical_inputs(
        contract, candidate=_candidate(materialization, contract=contract), materialization=materialization,
    ))
    reconstructed = current_semantic_review.reconstruct_current_semantic_evidence_subject(
        record.evidence_id, backend=store, applicability_context=_current_applicability_context(contract),
        byte_reader=_trusted_reader(contract, _semantic_config_bytes()), semantic_context_source=None,
    )
    assert reconstructed.subject is None
    assert reconstructed.status is current_semantic_review.SemanticEvidenceSubjectReconstructionStatus.DENIED


def test_reconstruction_fails_when_historical_slot_disappears_from_current_config(monkeypatch):
    current_config = _semantic_config_bytes().replace(b'"slot-a"', b'"slot-b"')
    contract, _, _ = _semantic_contract(config_bytes=current_config)
    materialization = _materialization(CandidateId("current"), contract_raw=contract.contract_raw_sha256)
    inputs = _canonical_inputs(contract, candidate=_candidate(materialization, contract=contract), materialization=materialization)
    current = resolve_current_semantic_review(
        inputs, applicability_context=_current_applicability_context(contract),
        byte_reader=_trusted_reader(contract, current_config), semantic_context_source=None,
    )
    record = _historical_evidence(current.obligation_outcomes[0], slot_id=ReviewSlotId("slot-a"))
    store = _reconstruction_backend(monkeypatch, record, inputs)
    reconstructed = current_semantic_review.reconstruct_current_semantic_evidence_subject(
        record.evidence_id, backend=store, applicability_context=_current_applicability_context(contract),
        byte_reader=_trusted_reader(contract, current_config), semantic_context_source=None,
    )
    assert reconstructed.status is current_semantic_review.SemanticEvidenceSubjectReconstructionStatus.DENIED
    assert reconstructed.subject is None


def test_historical_m1_selectors_reconstruct_fresh_m2_assignment_effective_subject_and_evidence_subject(monkeypatch):
    import autodev_control.trusted.evidence as evidence_module

    current, contract, materialization = _resolved_product()
    m1 = CandidateMaterializationId(RawSha256("1" * 64))
    record = _historical_evidence(current.obligation_outcomes[0], materialization_id=m1)
    inputs = _canonical_inputs(contract, candidate=_candidate(materialization, contract=contract), materialization=materialization)
    store = _reconstruction_backend(monkeypatch, record, inputs)
    calls = []
    original = current_semantic_review.resolve_current_semantic_review
    monkeypatch.setattr(evidence_module, "evaluate_evidence_applicability", lambda *_: pytest.fail("reconstruction does not decide applicability"))
    monkeypatch.setattr(evidence_module, "compose_semantic_evidence", lambda *_: pytest.fail("reconstruction does not compose evidence"))
    monkeypatch.setattr(InMemoryCanonicalStateBackend, "apply", lambda *_: pytest.fail("reconstruction is read-only"))
    def resolver(*args, **kwargs):
        calls.append(args[0].canonical_state_occurrence_binding)
        return original(*args, **kwargs)
    monkeypatch.setattr(current_semantic_review, "resolve_current_semantic_review", resolver)
    reconstructed = current_semantic_review.reconstruct_current_semantic_evidence_subject(
        EvidenceId("historical-evidence"), backend=store,
        applicability_context=_current_applicability_context(contract),
        byte_reader=_trusted_reader(contract, _semantic_config_bytes()), semantic_context_source=None,
    )
    assert reconstructed.status is current_semantic_review.SemanticEvidenceSubjectReconstructionStatus.RECONSTRUCTED
    assert calls == [inputs.canonical_state_occurrence_binding]
    current_outcome = original(
        inputs, applicability_context=_current_applicability_context(contract),
        byte_reader=_trusted_reader(contract, _semantic_config_bytes()), semantic_context_source=None,
    ).obligation_outcomes[0]
    assert current_outcome.assignment.candidate_materialization_id == materialization.materialization_id
    assert current_outcome.effective_subject.candidate_materialization_id == materialization.materialization_id
    assert reconstructed.subject.candidate_id == materialization.candidate_id
    assert reconstructed.subject.semantic_review_binding.obligation_id == current_outcome.obligation.obligation_id
    assert reconstructed.subject.semantic_review_binding.candidate_materialization_id == materialization.materialization_id
    assert record.subject.semantic_review_binding.candidate_materialization_id == m1
    assert reconstructed.subject.target_context_id is None and reconstructed.subject.pr_id is None
    assert reconstructed.subject.profile_config_id == current_outcome.trusted_evaluator_resolution.review_slots[0].profile.config_id
    assert reconstructed.subject.repository_id == materialization.repository_id
    assert reconstructed.subject.contract_id == contract.contract_id
    assert reconstructed.subject.contract_raw_sha256 == contract.contract_raw_sha256
    assert reconstructed.subject.task_admission_event_id == inputs.task.admission_event_id
    assert reconstructed.subject.authorization_id == inputs.authorization.authorization_id
    assert reconstructed.subject.target_registration_id == inputs.resolved_target.target_registration_id
    assert reconstructed.subject.policy_epoch_identity == inputs.task.last_evaluated_policy_epoch_identity
    assert reconstructed.subject.base == contract.base_sha
    assert reconstructed.subject.invocation_id == record.payload.invocation_id
    assert reconstructed.subject.slot_id == record.payload.slot_id


def test_reconstruction_reads_historical_evidence_and_current_candidate_from_g6_backend(monkeypatch):
    from tests.trusted.test_backend import apply as g6_apply, operation as g6_operation
    from tests.trusted.test_evidence import admit_semantic_review, fixture as g5_fixture
    from autodev_control.trusted.backend import (
        CreateEvidenceAndAdvanceHistory, CreateEvidenceHistory,
        CreateSemanticReviewOperationAndBinding,
    )

    config_bytes = _semantic_config_bytes()
    contract, _, _ = _semantic_contract(config_bytes=config_bytes)
    materialization = _materialization(
        CandidateId("current"), contract_raw=contract.contract_raw_sha256,
        authorization_id=AuthorizationId(RAW),
    )
    candidate = _candidate(materialization, contract=contract, authorization_id=AuthorizationId(RAW))
    store = _canonical_backend_with_candidate(contract, candidate, materialization)
    inputs = store.read_current_semantic_review_inputs(TaskId("task"))
    assert inputs is not None and inputs.candidate.materialization_id == materialization.materialization_id
    applicability = _current_applicability_context(contract)
    resolver_before_occurrence = store.occurrence
    resolver_before_state = store._state
    initial = resolve_current_semantic_review(
        inputs, applicability_context=applicability,
        byte_reader=_trusted_reader(contract, config_bytes), semantic_context_source=None,
    )
    assert store.occurrence == inputs.canonical_state_occurrence_binding
    assert store.read_candidate(candidate.candidate_id) == candidate
    assert store.read_candidate_materialization(materialization.materialization_id) == materialization
    assert store.read_contract(contract.contract_id) == contract
    assert store.read_authorization(inputs.authorization.authorization_id) == inputs.authorization
    assert store.read_task_working_set(inputs.task.task_id).task == inputs.task
    assert store.occurrence == resolver_before_occurrence
    assert store._state is resolver_before_state
    outcome = initial.obligation_outcomes[0]
    m1 = CandidateMaterializationId(RawSha256("1" * 64))
    historical_effective = _clone(
        outcome.effective_subject,
        subject_id=type(outcome.effective_subject.subject_id)("historical-m1-subject"),
        candidate_materialization_id=m1,
    )
    slot = outcome.trusted_evaluator_resolution.review_slots[0]
    invocation = ReviewInvocationId("historical-invocation")
    historical_subject = current_semantic_review.build_current_semantic_evidence_subject(
        outcome.resolved_obligation, slot, invocation,
    )
    historical_subject = replace(
        historical_subject,
        semantic_review_binding=SemanticReviewEvidenceBinding(outcome.obligation.obligation_id, m1),
    )
    admitted = admit_semantic_review(g5_fixture())
    assert admitted.proposed_evidence_record is not None
    operation = g6_operation("historical-review-operation", candidate_id=candidate.candidate_id)
    intent = _clone(
        operation.intent, contract_id=contract.contract_id,
        contract_raw_sha256=contract.contract_raw_sha256,
        authorization_id=inputs.authorization.authorization_id,
        admission_event_id=inputs.task.admission_event_id,
        target_registration_id=inputs.task.target_registration_id,
        policy_epoch_identity=inputs.task.last_evaluated_policy_epoch_identity,
    )
    operation = _clone(operation, intent=intent)
    request_id = type(admitted.proposed_evidence_record.payload.canonical_request_id)("historical-request")
    attempt_binding = backend_module.ReviewAttemptBindingRecord(
        historical_effective, invocation, slot.slot_id, operation.intent.operation_id, request_id,
    )
    working = store.read_task_working_set(inputs.task.task_id)
    assert working is not None
    created = g6_apply(
        store,
        CreateEvidenceHistory(historical_effective),
        CreateSemanticReviewOperationAndBinding(
            operation, attempt_binding, inputs.task.revision,
            working.task_operation_membership.membership_binding_id,
        ),
    )
    assert created.status.name == "APPLIED"
    proposed = admitted.proposed_evidence_record
    historical_record = replace(
        proposed, evidence_id=EvidenceId("historical-m1-evidence"), subject=historical_subject,
        payload=replace(
            proposed.payload, effective_subject_id=historical_effective.subject_id,
            slot_id=slot.slot_id, invocation_id=invocation, operation_id=operation.intent.operation_id,
            canonical_request_id=request_id,
        ),
    )
    history = store.read_review_eligibility_snapshot(historical_effective.subject_id)
    assert history is not None
    inserted = g6_apply(
        store,
        CreateEvidenceAndAdvanceHistory(
            historical_effective, history.evidence_history_membership.membership_binding_id,
            historical_record,
        ),
    )
    assert inserted.status.name == "APPLIED"
    assert store.read_evidence(historical_record.evidence_id) == historical_record
    current_inputs = store.read_current_semantic_review_inputs(TaskId("task"))
    assert current_inputs is not None
    assert current_inputs.candidate.materialization_id == materialization.materialization_id
    # Reconstruction is a read-only projection: preserve the complete frozen
    # G6 root/state object and representative canonical facts across the call.
    before_occurrence = store.occurrence
    before_state = store._state
    before_target = store.read_resolved_target_registration(TARGET)
    before_working_set = store.read_task_working_set(TaskId("task"))
    before_authorization = store.read_authorization(inputs.authorization.authorization_id)
    before_contract = store.read_contract(contract.contract_id)
    before_candidate = store.read_candidate(candidate.candidate_id)
    before_materialization = store.read_candidate_materialization(materialization.materialization_id)
    before_evidence = store.read_evidence(historical_record.evidence_id)
    before_operations = tuple(store._state.operations.values())
    import autodev_control.trusted.evidence as evidence_module
    import autodev_control.trusted.gates as gates_module
    import autodev_control.trusted.state as state_module

    def forbidden(*_args, **_kwargs):
        pytest.fail("Issue #32 reconstruction must remain a read-only structural projection")

    monkeypatch.setattr(InMemoryCanonicalStateBackend, "apply", forbidden)
    for function_name in (
        "evaluate_evidence_applicability", "compose_semantic_evidence",
        "build_evidence_supersession_record", "admit_semantic_review",
    ):
        monkeypatch.setattr(evidence_module, function_name, forbidden)
    for function_name in ("evaluate_task", "reserve_repair_attempt", "release_repair_attempt", "start_operation"):
        monkeypatch.setattr(state_module, function_name, forbidden)
    monkeypatch.setattr(gates_module.TrustedControlCommandBoundary, "evaluate_task", forbidden)
    monkeypatch.setattr(gates_module.FixtureProtectedGateRuntime, "commit_protected_start", forbidden)
    monkeypatch.setattr(gates_module.FixtureProtectedGateRuntime, "perform_effect", forbidden)
    monkeypatch.setattr(gates_module.TargetPublicationGate, "perform", forbidden)
    monkeypatch.setattr(gates_module.MergeGate, "perform", forbidden)
    reconstructed = current_semantic_review.reconstruct_current_semantic_evidence_subject(
        historical_record.evidence_id, backend=store, applicability_context=applicability,
        byte_reader=_trusted_reader(contract, config_bytes), semantic_context_source=None,
    )
    assert reconstructed.status is current_semantic_review.SemanticEvidenceSubjectReconstructionStatus.RECONSTRUCTED
    assert reconstructed.subject.semantic_review_binding.candidate_materialization_id == materialization.materialization_id
    assert historical_record.subject.semantic_review_binding.candidate_materialization_id == m1
    assert store.occurrence == before_occurrence
    assert store._state is before_state
    assert store.read_resolved_target_registration(TARGET) == before_target
    assert store.read_task_working_set(TaskId("task")) == before_working_set
    assert store.read_authorization(inputs.authorization.authorization_id) == before_authorization
    assert store.read_contract(contract.contract_id) == before_contract
    assert store.read_candidate(candidate.candidate_id) == before_candidate
    assert store.read_candidate_materialization(materialization.materialization_id) == before_materialization
    assert store.read_evidence(historical_record.evidence_id) == before_evidence
    assert tuple(store._state.operations.values()) == before_operations


@pytest.mark.parametrize(("dimension", "product"), (
    ("target", "success"), ("target", "unavailable"), ("target", "conflict"),
    ("pr", "success"), ("pr", "unavailable"), ("pr", "conflict"),
))
def test_reconstruction_uses_current_target_and_pr_context_not_historical_ids(monkeypatch, dimension, product):
    config = _semantic_config_bytes(
        target="REQUIRED" if dimension == "target" else "NOT_APPLICABLE",
        pr="REQUIRED" if dimension == "pr" else "NOT_APPLICABLE",
    )
    contract, _, _ = _semantic_contract(config_bytes=config)
    materialization = _materialization(CandidateId("current"), contract_raw=contract.contract_raw_sha256)
    inputs = _canonical_inputs(contract, candidate=_candidate(materialization, contract=contract), materialization=materialization)
    if dimension == "target":
        monkeypatch.setattr(current_semantic_review, "resolve_current_semantic_target_context", lambda *_: _target_success())
        monkeypatch.setattr(current_semantic_review, "resolve_current_semantic_pull_request_context", lambda *_: pytest.fail("PR is not demanded"))
    else:
        monkeypatch.setattr(current_semantic_review, "resolve_current_semantic_target_context", lambda *_: pytest.fail("target is not demanded"))
        monkeypatch.setattr(current_semantic_review, "resolve_current_semantic_pull_request_context", lambda *_: _pr_success())
    historical_current = resolve_current_semantic_review(
        inputs, applicability_context=_current_applicability_context(contract), byte_reader=_trusted_reader(contract, config),
        semantic_context_source=None,
    )
    record = _historical_evidence(historical_current.obligation_outcomes[0])
    if dimension == "target":
        monkeypatch.setattr(current_semantic_review, "resolve_current_semantic_target_context", lambda *_: CurrentSemanticTargetContextResolution(
            SemanticContextResolutionStatus.RESOLVED if product == "success" else SemanticContextResolutionStatus.INDETERMINATE if product == "unavailable" else SemanticContextResolutionStatus.DENIED,
            CurrentSemanticTargetContextReason.RESOLVED if product == "success" else CurrentSemanticTargetContextReason.TARGET_OBSERVATION_UNAVAILABLE if product == "unavailable" else CurrentSemanticTargetContextReason.SOURCE_INVALID,
            TargetContextId("target-current") if product == "success" else None,
            (_dependency(),) if product == "success" else (),
        ))
        monkeypatch.setattr(current_semantic_review, "resolve_current_semantic_pull_request_context", lambda *_: pytest.fail("PR is not demanded"))
    else:
        monkeypatch.setattr(current_semantic_review, "resolve_current_semantic_target_context", lambda *_: pytest.fail("target is not demanded"))
        monkeypatch.setattr(current_semantic_review, "resolve_current_semantic_pull_request_context", lambda *_: CurrentSemanticPullRequestContextResolution(
            SemanticContextResolutionStatus.RESOLVED if product == "success" else SemanticContextResolutionStatus.INDETERMINATE if product == "unavailable" else SemanticContextResolutionStatus.DENIED,
            CurrentSemanticPullRequestContextReason.RESOLVED if product == "success" else CurrentSemanticPullRequestContextReason.PR_OBSERVATION_MOVED if product == "unavailable" else CurrentSemanticPullRequestContextReason.PR_CONTEXT_CONFLICT,
            PullRequestIdentity("pr-current") if product == "success" else None,
            (_dependency("p"),) if product == "success" else (),
        ))
    store = _reconstruction_backend(monkeypatch, record, inputs)
    reconstructed = current_semantic_review.reconstruct_current_semantic_evidence_subject(
        record.evidence_id, backend=store, applicability_context=_current_applicability_context(contract),
        byte_reader=_trusted_reader(contract, config), semantic_context_source=None,
    )
    if product != "success":
        assert reconstructed.subject is None
        expected = (current_semantic_review.SemanticEvidenceSubjectReconstructionStatus.INDETERMINATE
                    if product == "unavailable" else current_semantic_review.SemanticEvidenceSubjectReconstructionStatus.DENIED)
        assert reconstructed.status is expected
    else:
        assert reconstructed.status is current_semantic_review.SemanticEvidenceSubjectReconstructionStatus.RECONSTRUCTED
        if dimension == "target":
            assert reconstructed.subject.target_context_id == TargetContextId("target-current")
        else:
            assert reconstructed.subject.pr_id == PullRequestIdentity("pr-current")
    assert record.subject.target_context_id == TargetContextId("historical-target")
    assert record.subject.pr_id == PullRequestIdentity("historical-pr")
    if product == "success":
        current_subject = historical_current.obligation_outcomes[0].effective_subject
        assert reconstructed.subject.requirement_ids == current_subject.requirement_ids
        assert reconstructed.subject.required_material_ids == current_subject.required_material_ids
        assert reconstructed.subject.required_context_ids == current_subject.required_context_ids
        assert reconstructed.subject.candidate_id == materialization.candidate_id
        assert reconstructed.subject.contract_raw_sha256 == contract.contract_raw_sha256


def test_nonsemantic_evidence_classes_remain_valid_without_semantic_provenance():
    result, _, _ = _resolved_product()
    for evidence_class in (
        EvidenceClass.DETERMINISTIC, EvidenceClass.CONTROLLED_RUNTIME,
        EvidenceClass.EXTERNAL_OBSERVATION, EvidenceClass.HUMAN_APPROVAL,
    ):
        record = _historical_evidence(result.obligation_outcomes[0], nonsemantic=True)
        record = replace(record, evidence_class=evidence_class)
        assert record.subject.semantic_review_binding is None


def test_canonical_backend_has_no_persisted_current_semantic_registry_or_mutation_namespace():
    derived_types = (
        current_semantic_review.CurrentSemanticReviewResolutionResult,
        current_semantic_review.SemanticEvaluatorObligationResolution,
        current_semantic_review.SemanticEvaluatorObligation,
        current_semantic_review.ResolvedSemanticEvaluatorObligation,
        current_semantic_review.CurrentReviewMaterial,
        current_semantic_review.SemanticEvidenceSubjectReconstructionResult,
        SemanticReviewAssignment, SemanticReviewEffectiveSubject,
    )
    registered_records = {record_type for _, record_type in backend_module._NAMESPACE_TYPES.values()}
    assert registered_records.isdisjoint(derived_types)
    assert all(all(value is not candidate for value in backend_module._MUTATION_TYPES) for candidate in derived_types)
    assert not any("semantic" in namespace.name.lower() or "semantic" in namespace.value.lower() for namespace in backend_module.CanonicalNamespace)
    assert not any("semantic" in item.name.lower() for item in fields(backend_module._State))
    assert not any(callable(value) and hasattr(value, "cache_info") for value in vars(current_semantic_review).values())
    # Downstream authority operations remain absent from the resolver's callable surface.
    assert not {
        "evaluate_evidence_applicability", "compose_semantic_evidence",
        "build_evidence_supersession_record", "evaluate_task", "reserve_repair_attempt",
        "release_repair_attempt", "DeterministicTrustedController",
    }.intersection(vars(current_semantic_review))


def test_canonical_serializer_round_trips_semantic_and_nonsemantic_subjects_and_record():
    result, _, _ = _resolved_product()
    outcome = result.obligation_outcomes[0]
    semantic_subject = current_semantic_review.build_current_semantic_evidence_subject(
        outcome.resolved_obligation, outcome.trusted_evaluator_resolution.review_slots[0], ReviewInvocationId("roundtrip"),
    )
    nonsemantic_subject = replace(semantic_subject, semantic_review_binding=None)
    for subject in (semantic_subject, nonsemantic_subject):
        encoded = backend_module.canonical_json_bytes(subject)
        envelope = json.loads(encoded)
        decoded = backend_module._decode_canonical_value(envelope["value"], EvidenceSubject)
        assert decoded == subject
        assert backend_module.canonical_json_bytes(decoded) == encoded
    historical = _historical_evidence(outcome)
    raw = backend_module.canonical_record_bytes(backend_module.CanonicalRecordKind.EVIDENCE, historical)
    decoded = backend_module._decode_canonical_record(raw)
    assert decoded == (backend_module.CanonicalRecordKind.EVIDENCE, "1", historical)
    assert backend_module.canonical_record_bytes(decoded[0], decoded[2], decoded[1]) == raw
    reference = backend_module.canonical_object_ref(backend_module.CanonicalRecordKind.EVIDENCE, historical)
    entry = backend_module.CanonicalIndexEntry(
        backend_module.canonical_logical_identity(backend_module.CanonicalRecordKind.EVIDENCE, historical), reference,
    )
    manifest = backend_module.CanonicalStateRootManifest(
        "2", None, (), (), (), (), (), (), (), (entry,), (), (),
    )
    stored = backend_module.CanonicalStoredObject(reference, raw)
    assert backend_module.validate_canonical_root_object_integrity(manifest, (stored,))
    assert reference == backend_module.canonical_object_ref(backend_module.CanonicalRecordKind.EVIDENCE, historical)
    assert not backend_module.validate_canonical_root_object_integrity(
        manifest, (backend_module.CanonicalStoredObject(reference, raw + b" "),),
    )


def test_current_resolution_is_read_only_structural_and_not_evidence_or_effect_authority(monkeypatch):
    import autodev_control.trusted.evidence as evidence_module
    import autodev_control.trusted.gates as gates_module
    import autodev_control.trusted.state as state_module

    result, contract, materialization = _resolved_product()
    inputs = _canonical_inputs(contract, candidate=_candidate(materialization, contract=contract), materialization=materialization)
    occurrence = inputs.canonical_state_occurrence_binding
    before = (inputs.task, inputs.candidate, inputs.materialization)
    monkeypatch.setattr(evidence_module, "evaluate_evidence_applicability", lambda *_: pytest.fail("applicability is outside #32"))
    monkeypatch.setattr(evidence_module, "compose_semantic_evidence", lambda *_: pytest.fail("composition is outside #32"))
    monkeypatch.setattr(InMemoryCanonicalStateBackend, "apply", lambda *_: pytest.fail("#32 cannot mutate canonical state"))
    for function_name in ("build_evidence_supersession_record", "admit_semantic_review"):
        monkeypatch.setattr(evidence_module, function_name, lambda *_: pytest.fail(f"{function_name} is outside #32"))
    for function_name in ("evaluate_task", "reserve_repair_attempt", "release_repair_attempt", "start_operation"):
        monkeypatch.setattr(state_module, function_name, lambda *_: pytest.fail(f"{function_name} is outside #32"))
    for owner, method in (
        (gates_module.TrustedControlCommandBoundary, "evaluate_task"),
        (gates_module.FixtureProtectedGateRuntime, "commit_protected_start"),
        (gates_module.FixtureProtectedGateRuntime, "perform_effect"),
        (gates_module.TargetPublicationGate, "perform"),
        (gates_module.MergeGate, "perform"),
    ):
        monkeypatch.setattr(owner, method, lambda *_: pytest.fail(f"{owner.__name__}.{method} is outside #32"))
    after = resolve_current_semantic_review(
        inputs, applicability_context=_current_applicability_context(contract),
        byte_reader=_trusted_reader(contract, _semantic_config_bytes()), semantic_context_source=None,
    )
    assert after.status is CurrentSemanticReviewResolutionStatus.RESOLVED
    assert after.occurrence == occurrence
    assert (inputs.task, inputs.candidate, inputs.materialization) == before
    assert type(after) is current_semantic_review.CurrentSemanticReviewResolutionResult
    assert not isinstance(after, (EvidenceRecord, SemanticEvidencePayload))
    assert "backend" not in inspect.signature(resolve_current_semantic_review).parameters
    assert "gates" not in current_semantic_review.__dict__
    forbidden_authority_names = {
        "evaluate_evidence_applicability", "compose_semantic_evidence", "build_evidence_supersession_record",
        "evaluate_task", "reserve_repair_attempt", "release_repair_attempt", "start_operation",
        "TrustedControlCommandBoundary", "FixtureProtectedGateRuntime", "TargetPublicationGate", "MergeGate",
    }
    assert forbidden_authority_names.isdisjoint(current_semantic_review.__dict__)
    assert current_semantic_review.TaskRecord is TaskRecord
    assert not hasattr(current_semantic_review, "evaluate_task")
