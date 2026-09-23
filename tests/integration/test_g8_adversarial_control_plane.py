"""G8 v0.2 adversarial integrations over the assembled G1--G7 fixtures.

Each test owns fresh fixture state.  Helpers are deliberately imported from the
lower-layer test fixtures: they construct the same G1--G7 candidate runtime,
not a parallel test authority path.
"""

from dataclasses import replace
import hashlib
import json

import pytest

import autodev_control.trusted.gates as gates_module
from autodev_control.trusted.authorization import (
    OrdinaryRootProtectionState,
    admit_direct_authorization,
    load_candidate_authorization_proposal,
)
from autodev_control.trusted.contract import (
    IssueContractApplicabilityCode,
    derive_contract_authority_ceiling,
    load_candidate_issue_contract,
)
from autodev_control.trusted.backend import (
    canonical_json_bytes,
)
from autodev_control.trusted.decision import Decision
from autodev_control.trusted.errors import (
    AuthorizationAdmissionReasonCode,
    AuthorizationProposalFailureCode,
)
from autodev_control.trusted.errors import G4FailureCode
from autodev_control.trusted.evidence import (
    EvidenceApplicabilityDecision,
    EvidenceApplicabilityReason,
    evaluate_evidence_applicability,
)
from autodev_control.trusted.gates import (
    ActionTargetFence,
    ControlStateGate,
    GateResultCode,
    MergeGate,
    ProtectedEffectSubject,
    SemanticEvidenceCommand,
    TargetPublicationGate,
    TaskEvaluationCommand,
)
from autodev_control.trusted.fixture_platform import (
    ProtectedEffectMarkerPreimage,
    PublishedCandidateRefEffectSubject,
    build_protected_effect_marker,
)
from autodev_control.trusted.identity import (
    GitRef,
    GitSha,
    RawSha256,
)
from autodev_control.trusted.materialization import MutationKind
from autodev_control.trusted.operation import (
    OperationActionId,
    OperationId,
    OperationIdempotencyKey,
    OperationState,
    OperationSubjectId,
    CandidateId,
)
from autodev_control.trusted.scope import (
    ChangeType,
    ContractId,
    MutationScope,
    MutationScopeRule,
    RepositorySelector,
    TaskCapability,
    TaskId,
)
from autodev_control.trusted.state import (
    CancellationRequestId, CancellationStatus, ConditionStatus, RepairBudget,
    TaskState,
)

from tests.trusted import test_authorization as authorization_fixture
from tests.trusted import test_evidence as evidence_fixture
from tests.trusted import test_gates as gates_fixture
from tests.trusted.contract_fixtures import (
    canonical_contract_fixture,
    trusted_admission_context_for_fixture,
)


def _operation(runtime, operation_id):
    return next(
        item for item in runtime.backend.read_task_working_set(gates_fixture.TASK).operations
        if item.intent.operation_id == operation_id
    )


def _publication_setup(name="g8-publication", *, target=None):
    runtime = gates_fixture.runtime(target)
    gates_fixture.initialize_task(runtime)
    materialization = gates_fixture.materialize(runtime)
    materialization = gates_fixture.adopt_recorded_candidate(runtime, materialization)
    operation = gates_fixture.reserve_protected(runtime, name, materialization.candidate_id)
    fence = ActionTargetFence(
        gates_fixture.REPO, materialization.candidate_branch, None,
        runtime.platform.snapshot().generation,
    )
    return runtime, materialization, operation, fence


def _evaluate(runtime, context, *, blockers=()):
    """Use the public G6/G4 evaluation path for one exact trusted context."""
    runtime.register_completion_evaluation_context(context)
    # G8 completion cases use the frozen no-semantic-evaluator contract fixture.
    # Refresh the real #29 neutral resolution after all setup mutations so its
    # G1 dependency and canonical occurrence are exact for this evaluation.
    dependencies = gates_fixture.register_zero_semantic_environment(runtime)
    return ControlStateGate(runtime).commit(
        runtime.boundary.evaluate_task(TaskEvaluationCommand(
            gates_fixture.TASK, context.context_id, blockers, (), None,
        )), runtime.acquire_control_lease(runtime.control_capability, dependencies),
    )


def _exact_publication_marker(runtime, started, materialization, fence):
    continuation = started.continuation
    effect_subject = PublishedCandidateRefEffectSubject(
        gates_fixture.REPO, materialization.candidate_branch,
        GitRef(materialization.candidate_branch.value), materialization.commit,
    )
    pre_identity = RawSha256(hashlib.sha256(
        canonical_json_bytes(("pre", fence))
    ).hexdigest())
    post_identity = RawSha256(hashlib.sha256(
        canonical_json_bytes(("post", effect_subject))
    ).hexdigest())
    action_digest = RawSha256(hashlib.sha256(canonical_json_bytes((
        continuation.subject, continuation.action_id,
        materialization.materialization_id, materialization.inventory.inventory_id,
        effect_subject,
    ))).hexdigest())
    return build_protected_effect_marker(ProtectedEffectMarkerPreimage(
        "autodev.protected-effect-marker/v1", continuation.subject.value,
        continuation.operation_id, continuation.idempotency_key,
        continuation.action_id, action_digest, materialization.materialization_id,
        materialization.inventory.inventory_id, continuation.prepared_start_id,
        runtime.binding.root_context_id, runtime.binding.runtime_generation.value,
        runtime.publication_capability.service_identity, effect_subject,
        pre_identity, post_identity,
    ))


def _current_semantic_runtime():
    """Use the existing #32/#29 G7 fixture with canonical favorable evidence."""
    runtime, materialization, target, base_dependency, evidence = (
        gates_fixture._issue29_semantic_publication_runtime(stale_schema=False)
    )
    semantic = runtime._resolve_semantic_consumption(
        evidence.subject.task_id, (evidence.evidence_id,), runtime.backend.occurrence,
    )
    assert semantic is not None
    assert semantic.contract_status is ConditionStatus.SATISFIED
    assert len(semantic.obligation_results) == 1
    assert semantic.obligation_results[0].status is ConditionStatus.SATISFIED
    assert semantic.obligation_results[0].progression_support_evidence_ids == (
        evidence.evidence_id,
    )
    assert not hasattr(semantic, "control_capability")
    assert not hasattr(semantic, "publication_capability")
    assert not hasattr(semantic, "merge_capability")
    assert semantic.evidence_currentness[0].status.name == "CURRENT"
    return runtime, materialization, target, base_dependency, evidence


def _raw_contract(*, contract_id, task_id, operations, objective="fixture objective"):
    raw, _, _ = canonical_contract_fixture(
        contract_id=contract_id, task_id=task_id,
        target_registration_id=gates_fixture.TARGET,
        repository_id=gates_fixture.REPO,
        policy_epoch_identity=gates_fixture.EPOCH,
        base_sha=gates_fixture.SHA,
        allowed_repository_scope=True,
        requested_operations=operations,
    )
    value = json.loads(raw)
    value["objective"] = objective
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _admit_raw_contract(runtime, raw, label):
    dependencies = gates_fixture.install_fixture_dependencies(
        runtime, label + "-base", label + "-issue",
    )
    resolved = runtime.backend.read_resolved_target_registration(gates_fixture.TARGET)
    assert resolved is not None
    context = trusted_admission_context_for_fixture(
        raw, resolved.registration, gates_fixture.EPOCH,
        dependencies.dependencies[0].expected_binding_id,
        dependencies.dependencies[1].expected_binding_id,
    )
    runtime.register_contract_context(raw, context)
    request = runtime.boundary.admit_contract(raw)
    assert ControlStateGate(runtime).commit(
        request, runtime.acquire_control_lease(runtime.control_capability, dependencies),
    ).code is GateResultCode.COMMITTED
    parsed = load_candidate_issue_contract(raw)
    contract = runtime.backend.read_contract(parsed.contract_id)
    assert contract is not None
    return contract


def test_g8_01_admitted_evidence_with_stale_base_is_not_current_proof():
    admitted = evidence_fixture.admit_semantic_review(
        evidence_fixture.fixture()
    ).proposed_evidence_record
    current = replace(admitted.subject, base=GitSha("b" * 40))
    result = evaluate_evidence_applicability(admitted, current)
    assert (result.decision, result.reason) == (
        EvidenceApplicabilityDecision.STALE,
        EvidenceApplicabilityReason.BASE_CHANGED,
    )
    assert result.decision is not EvidenceApplicabilityDecision.APPLICABLE

    # Keep the low-level applicability assertion, then move the assembled
    # current #32/#29 context to S2 and consume the exact canonical S1 record.
    runtime, materialization, target, base_dependency, evidence = (
        _current_semantic_runtime()
    )
    applicability, reader, context_source, dependency = runtime._semantic_contexts[
        evidence.subject.task_id
    ]
    assert dependency == base_dependency
    old_base = applicability.base_observation
    moved_base = gates_fixture.mint(
        type(old_base),
        **{
            **{name: getattr(old_base, name) for name in old_base.__dataclass_fields__},
            "sha": GitSha("d" * 40),
        },
    )
    moved_context = gates_fixture.mint(
        type(applicability),
        **{
            **{name: getattr(applicability, name)
               for name in applicability.__dataclass_fields__},
            "base_observation": moved_base,
        },
    )
    runtime.register_semantic_consumption_context(
        evidence.subject.task_id, moved_context, reader, context_source,
        base_dependency,
    )
    current = runtime._resolve_semantic_consumption(
        evidence.subject.task_id, (evidence.evidence_id,), runtime.backend.occurrence,
    )
    assert current is not None
    exact = current.evidence_currentness[0]
    assert exact.evidence_id == evidence.evidence_id
    assert exact.status.name == "STALE"
    assert exact.applicability_code is IssueContractApplicabilityCode.BASE_CHANGED
    assert current.obligation_results == ()
    assert not any(
        evidence.evidence_id in item.progression_support_evidence_ids
        for item in current.obligation_results
    )

    # The real G4 readiness boundary cannot consume the stale evidence.
    forward = gates_fixture.reserve_protected(
        runtime, "g8-stale-base-readiness", materialization.candidate_id,
        integration_binding=gates_fixture.IntegrationBound(
            GitRef(target.merge.allowed_integration_refs[0].value)
        ), required_evidence_ids=(evidence.evidence_id,),
    )
    ready_context = gates_fixture.completion_context(
        runtime, "g8-stale-base-readiness-context",
        contract=ConditionStatus.SATISFIED,
        additional=ConditionStatus.SATISFIED,
        applicability=ConditionStatus.SATISFIED,
        required=(forward.intent.operation_id,),
    )
    runtime.register_completion_evaluation_context(ready_context)
    with pytest.raises(gates_fixture._TaskSemanticDenied) as ready_denied:
        runtime.boundary.evaluate_task(TaskEvaluationCommand(
            evidence.subject.task_id, ready_context.context_id, (), (),
            forward.intent.operation_id,
        ))
    assert ready_denied.value.code is gates_fixture.TaskSemanticDenialCode.SEMANTIC_CONTEXT_INDETERMINATE
    assert runtime.backend.read_task_working_set(evidence.subject.task_id).task.state is not TaskState.INTEGRATION_READY

    # The real G7 start path independently rejects the same stale EvidenceId.
    fence = ActionTargetFence(
        evidence.subject.repository_id, materialization.candidate_branch, None,
        runtime.platform.snapshot().generation,
    )
    start_operation = gates_fixture.reserve_protected(
        runtime, "g8-stale-base-start", materialization.candidate_id,
        required_evidence_ids=(evidence.evidence_id,),
    )
    start = gates_fixture.start_protected(
        runtime, start_operation, ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
        fence, materialization, target=target,
        dependencies=gates_fixture.ControlStateAuthoritativeDependencySet(
            (base_dependency,)
        ),
    )
    assert start.code is GateResultCode.REJECTED
    assert start.semantic_denial_code.name == "REQUIRED_EVIDENCE_NOT_CURRENT"
    assert _operation(runtime, start_operation.intent.operation_id).start_binding_id is None
    assert runtime.platform.marker(
        start_operation.intent.operation_id, ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION.value,
    ) is None

    # G4 completion also cannot be granted by the stale historical proof.
    complete_context = gates_fixture.completion_context(
        runtime, "g8-stale-base-completion-context",
        contract=ConditionStatus.SATISFIED,
        additional=ConditionStatus.SATISFIED,
        applicability=ConditionStatus.SATISFIED,
    )
    runtime.register_completion_evaluation_context(complete_context)
    with pytest.raises(gates_fixture._TaskSemanticDenied) as completion_denied:
        runtime.boundary.evaluate_task(TaskEvaluationCommand(
            evidence.subject.task_id, complete_context.context_id, (), (), None,
        ))
    assert completion_denied.value.code is gates_fixture.TaskSemanticDenialCode.SEMANTIC_CONTEXT_INDETERMINATE
    assert runtime.backend.read_task_working_set(evidence.subject.task_id).task.state is not TaskState.COMPLETED


def test_g8_01_stale_base_denies_persisted_forward_merge_start():
    """An already-ready IntegrationBound operation rechecks exact evidence at start."""
    runtime, materialization, target, base_dependency, evidence = (
        _current_semantic_runtime()
    )
    dependencies = gates_fixture.ControlStateAuthoritativeDependencySet(
        (base_dependency,)
    )
    repository_id = evidence.subject.repository_id
    base_ref = target.merge.allowed_integration_refs[0]
    runtime.platform.seed_ref(repository_id, base_ref, materialization.base)

    publish = gates_fixture.reserve_protected(
        runtime, "g8-stale-forward-publish", materialization.candidate_id,
        required_evidence_ids=(evidence.evidence_id,),
    )
    publish_start = gates_fixture.start_protected(
        runtime, publish, ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
        ActionTargetFence(
            repository_id, materialization.candidate_branch, None,
            runtime.platform.snapshot().generation,
        ), materialization, target=target, dependencies=dependencies,
    )
    assert publish_start.code is GateResultCode.START_COMMITTED
    assert TargetPublicationGate(runtime).perform(
        publish_start.continuation,
    ).code is GateResultCode.EFFECT_SUCCEEDED
    create_pr = gates_fixture.reserve_protected(
        runtime, "g8-stale-forward-pr", materialization.candidate_id,
        required_evidence_ids=(evidence.evidence_id,),
    )
    pr_start = gates_fixture.start_protected(
        runtime, create_pr, ProtectedEffectSubject.PULL_REQUEST_CREATION,
        ActionTargetFence(
            repository_id, materialization.candidate_branch, materialization.commit,
            runtime.platform.snapshot().generation, base_ref, materialization.base,
        ), materialization, target=target, base_ref=base_ref,
        provenance_operation_id=publish.intent.operation_id,
        dependencies=dependencies,
    )
    assert pr_start.code is GateResultCode.START_COMMITTED
    assert TargetPublicationGate(runtime).perform(
        pr_start.continuation,
    ).code is GateResultCode.EFFECT_SUCCEEDED

    forward = gates_fixture.reserve_protected(
        runtime, "g8-stale-forward-merge", materialization.candidate_id,
        integration_binding=gates_fixture.IntegrationBound(GitRef(base_ref.value)),
        required_evidence_ids=(evidence.evidence_id,),
    )
    ready_context = gates_fixture.completion_context(
        runtime, "g8-stale-forward-ready-context",
        contract=ConditionStatus.SATISFIED,
        additional=ConditionStatus.SATISFIED,
        applicability=ConditionStatus.SATISFIED,
        required=(forward.intent.operation_id,),
    )
    runtime.register_completion_evaluation_context(ready_context)
    ready_request = runtime.boundary.evaluate_task(TaskEvaluationCommand(
        evidence.subject.task_id, ready_context.context_id, (), (),
        forward.intent.operation_id,
    ))
    assert ready_request.transaction.mutations[0].task.state is TaskState.INTEGRATION_READY
    assert ControlStateGate(runtime).commit(
        ready_request, runtime.acquire_control_lease(runtime.control_capability, dependencies),
    ).code is GateResultCode.COMMITTED

    applicability, reader, context_source, _ = runtime._semantic_contexts[
        evidence.subject.task_id
    ]
    old_base = applicability.base_observation
    moved_base = gates_fixture.mint(
        type(old_base),
        **{
            **{name: getattr(old_base, name) for name in old_base.__dataclass_fields__},
            "sha": GitSha("d" * 40),
        },
    )
    moved_context = gates_fixture.mint(
        type(applicability),
        **{
            **{name: getattr(applicability, name)
               for name in applicability.__dataclass_fields__},
            "base_observation": moved_base,
        },
    )
    runtime.register_semantic_consumption_context(
        evidence.subject.task_id, moved_context, reader, context_source,
        base_dependency,
    )
    before_ref = runtime.platform.read_ref(repository_id, base_ref)
    result = gates_fixture.start_protected(
        runtime, forward, ProtectedEffectSubject.FAST_FORWARD_MERGE,
        ActionTargetFence(
            repository_id, base_ref, materialization.base,
            runtime.platform.snapshot().generation,
        ), materialization, target=target, base_ref=base_ref,
        provenance_operation_id=create_pr.intent.operation_id,
        dependencies=dependencies,
    )
    assert result.code is GateResultCode.REJECTED
    assert result.semantic_denial_code.name == "REQUIRED_EVIDENCE_NOT_CURRENT"
    stored = _operation(runtime, forward.intent.operation_id)
    assert stored.state is OperationState.RESERVED
    assert stored.start_binding_id is None
    assert runtime.platform.marker(
        forward.intent.operation_id, ProtectedEffectSubject.FAST_FORWARD_MERGE.value,
    ) is None
    assert runtime.platform.read_ref(repository_id, base_ref) == before_ref


def test_g8_02_public_control_boundary_rejects_transferred_authorization():
    runtime = gates_fixture.runtime()
    gates_fixture.initialize_task(runtime)
    with pytest.raises(ValueError, match="exact canonical contract and authorization"):
        runtime.boundary.create_task(
            task_id=TaskId("g8-other-task"),
            contract_id=ContractId("g8-other-contract"),
            contract_raw_sha256=RawSha256("9" * 64),
            authorization_id=gates_fixture.AUTH,
            admission_event_id=gates_fixture.ADMISSION,
            target_registration_id=gates_fixture.TARGET,
            policy_epoch_identity=gates_fixture.EPOCH,
            repair_budget=RepairBudget(1),
        )
    assert runtime.backend.read_task_working_set(TaskId("g8-other-task")) is None


def test_g8_03_tree_derived_out_of_scope_addition_cannot_start_publication():
    modify_only = MutationScope((MutationScopeRule(
        RepositorySelector(), (ChangeType.MODIFY,),
    ),))
    target_fields = {
        field: getattr(gates_fixture.registration(), field)
        for field in gates_fixture.AdmittedTargetRegistration.__dataclass_fields__
    }
    target_fields["ordinary_allowed_scope"] = modify_only
    target = gates_fixture.mint(gates_fixture.AdmittedTargetRegistration, **target_fields)
    runtime, materialization, operation, fence = _publication_setup(
        "g8-scope-escape", target=target,
    )
    assert materialization.inventory.mutations[0].kind is MutationKind.ADDED
    with pytest.raises(ValueError):
        gates_fixture.start_protected(
            runtime, operation,
            ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
            fence, materialization, target=target,
        )
    assert runtime.platform.marker(
        operation.intent.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION.value,
    ) is None
    assert _operation(runtime, operation.intent.operation_id).state is OperationState.CONFLICT


def _g8_root_admissions():
    target = authorization_fixture.admitted_target()
    proposal = authorization_fixture.load_proposal(target.target_registration_id)
    contract, policy, approval, issuer, root = authorization_fixture.direct_contexts(
        proposal, target,
    )
    protected = authorization_fixture._ordinary_root_context_for_test(
        policy_epoch_identity=policy.policy_epoch_identity,
        repository_id=target.repository_id,
        state=OrdinaryRootProtectionState.ROOT_PROTECTED_MUTATION_SCOPE,
        root_protected_mutation_scope=authorization_fixture.proposal_scope(),
    )
    overlap = admit_direct_authorization(
        proposal, target, contract, policy, approval, issuer, protected,
    )
    unavailable = admit_direct_authorization(
        proposal, target, contract, policy, approval, issuer, None,
    )
    return overlap, unavailable


def test_g8_04a_root_scope_overlap_is_denied():
    overlap, _ = _g8_root_admissions()
    assert overlap.reason_code is AuthorizationAdmissionReasonCode.ROOT_SCOPE_OVERLAP
    assert overlap.decision is Decision.DENY
    assert overlap.admitted_authorization is None


def test_g8_04b_unavailable_root_context_escalates():
    _, unavailable = _g8_root_admissions()
    assert unavailable.decision is Decision.ESCALATE
    assert unavailable.reason_code is AuthorizationAdmissionReasonCode.ROOT_CONTEXT_UNAVAILABLE
    assert unavailable.admitted_authorization is None


def test_g8_05_target_movement_before_start_conflicts_without_effect():
    runtime, materialization, operation, fence = _publication_setup("g8-stale-target")
    runtime.platform.seed_ref(
        gates_fixture.REPO, materialization.candidate_branch, GitSha("d" * 40),
    )
    result = gates_fixture.start_protected(
        runtime, operation,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
        fence, materialization,
    )
    assert result.code is GateResultCode.ACTION_PRECONDITION_CONFLICT
    assert result.failure_code is G4FailureCode.ACTION_PRECONDITION_CONFLICT
    stored = _operation(runtime, operation.intent.operation_id)
    assert stored.state is OperationState.CONFLICT
    assert stored.start_binding_id is None
    assert runtime.platform.prepared_effect_state(
        operation.intent.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION.value,
    ) == "RELEASED"
    assert runtime.platform.marker(
        operation.intent.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION.value,
    ) is None
    assert runtime.platform.read_ref(gates_fixture.REPO, materialization.candidate_branch) == GitSha("d" * 40)
    assert not runtime.platform._markers


def test_g8_06_admitted_approved_evidence_cannot_override_a_deterministic_conflict():
    """Current canonical semantic approval cannot override a same-runtime G7 conflict."""
    runtime, materialization, target, base_dependency, evidence = _current_semantic_runtime()
    operation = gates_fixture.reserve_protected(
        runtime, "g8-evidence-conflict", materialization.candidate_id,
        required_evidence_ids=(evidence.evidence_id,),
    )
    dependencies = gates_fixture.ControlStateAuthoritativeDependencySet((base_dependency,))
    fence = ActionTargetFence(
        evidence.subject.repository_id, materialization.candidate_branch, None,
        runtime.platform.snapshot().generation,
    )
    runtime.platform.seed_ref(
        evidence.subject.repository_id, materialization.candidate_branch, GitSha("d" * 40),
    )
    result = gates_fixture.start_protected(
        runtime, operation,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
        fence, materialization, target=target, dependencies=dependencies,
    )
    assert result.code is GateResultCode.ACTION_PRECONDITION_CONFLICT
    assert result.failure_code is G4FailureCode.ACTION_PRECONDITION_CONFLICT
    stored = _operation(runtime, operation.intent.operation_id)
    assert stored.state is OperationState.CONFLICT
    assert stored.start_binding_id is None
    assert runtime.platform.marker(
        operation.intent.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION.value,
    ) is None


def test_g8_07_admitted_approval_is_not_merge_or_completion_authority():
    """Current semantic evidence is not protected-start, merge, or G4 completion authority."""
    runtime, materialization, target, base_dependency, evidence = _current_semantic_runtime()
    before = runtime.backend.read_task_working_set(evidence.subject.task_id)
    assert before is not None
    admitted_authorization = runtime.backend.read_authorization(before.task.authorization_id)
    resolved_target = runtime.backend.read_resolved_target_registration(
        before.task.target_registration_id,
    )
    root_context_id = runtime.binding.root_context_id
    platform_before = runtime.platform.snapshot()
    control_capability = runtime.control_capability
    publication_capability = runtime.publication_capability
    merge_capability = runtime.merge_capability
    assert admitted_authorization is not None and resolved_target is not None
    operation = gates_fixture.reserve_protected(
        runtime, "g8-evidence-required-merge", materialization.candidate_id,
        integration_binding=gates_fixture.IntegrationBound(
            gates_fixture.GitRef(target.merge.allowed_integration_refs[0].value)
        ),
        required_evidence_ids=(evidence.evidence_id,),
    )
    dependencies = gates_fixture.ControlStateAuthoritativeDependencySet((base_dependency,))
    fence = ActionTargetFence(
        evidence.subject.repository_id, target.merge.allowed_integration_refs[0], materialization.base,
        runtime.platform.snapshot().generation,
    )
    with pytest.raises(ValueError, match="protected action preconditions"):
        gates_fixture.start_protected(
            runtime, operation, ProtectedEffectSubject.FAST_FORWARD_MERGE,
            fence, materialization, target=target,
            base_ref=target.merge.allowed_integration_refs[0],
            dependencies=dependencies,
        )
    stored = _operation(runtime, operation.intent.operation_id)
    assert stored.state is OperationState.CONFLICT
    assert stored.start_binding_id is None
    assert runtime.platform.marker(
        operation.intent.operation_id,
        ProtectedEffectSubject.FAST_FORWARD_MERGE.value,
    ) is None
    assert runtime.platform.read_ref(
        evidence.subject.repository_id, target.merge.allowed_integration_refs[0],
    ) is None
    operations_before_currentness = runtime.backend.read_task_working_set(
        evidence.subject.task_id
    ).operations
    semantic = runtime._resolve_semantic_consumption(
        evidence.subject.task_id, (evidence.evidence_id,), runtime.backend.occurrence,
    )
    assert runtime.backend.read_task_working_set(evidence.subject.task_id).operations == operations_before_currentness
    assert semantic is not None and semantic.contract_status is ConditionStatus.SATISFIED
    assert semantic.evidence_currentness[0].status.name == "CURRENT"
    assert semantic.obligation_results[0].status is ConditionStatus.SATISFIED
    assert semantic.obligation_results[0].progression_support_evidence_ids == (
        evidence.evidence_id,
    )
    context = gates_fixture.completion_context(
        runtime, "g8-evidence-required-merge",
        contract=ConditionStatus.SATISFIED,
        additional=ConditionStatus.SATISFIED,
        applicability=ConditionStatus.SATISFIED,
        required=(operation.intent.operation_id,),
    )
    runtime.register_completion_evaluation_context(context)
    request = runtime.boundary.evaluate_task(TaskEvaluationCommand(
        evidence.subject.task_id, context.context_id, (), (), None,
    ))
    assert request.transaction.mutations[0].task.state is not TaskState.COMPLETED
    lease = runtime.acquire_control_lease(runtime.control_capability, dependencies)
    assert ControlStateGate(runtime).commit(request, lease).code is GateResultCode.COMMITTED
    assert runtime.backend.read_task_working_set(evidence.subject.task_id).task.state is not TaskState.COMPLETED
    assert runtime.backend.read_authorization(before.task.authorization_id) == admitted_authorization
    assert runtime.backend.read_resolved_target_registration(before.task.target_registration_id) == resolved_target
    assert runtime.binding.root_context_id == root_context_id
    assert runtime.control_capability is control_capability
    assert runtime.publication_capability is publication_capability
    assert runtime.merge_capability is merge_capability
    platform_after = runtime.platform.snapshot()
    assert platform_after.refs == platform_before.refs
    assert platform_after.pull_requests == platform_before.pull_requests
    assert platform_after.markers == platform_before.markers


def test_g8_08_exact_replay_never_duplicates_effect_or_lends_marker_to_other_operation():
    runtime, materialization, operation, fence = _publication_setup("g8-replay")
    started = gates_fixture.start_protected(
        runtime, operation,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
        fence, materialization,
    )
    exact = _exact_publication_marker(runtime, started, materialization, fence)
    assert runtime.platform.publish_and_mark(
        gates_fixture.REPO, materialization.candidate_branch, materialization.commit,
        exact, _fence_token=started.continuation.target_fence_token,
    )
    assert TargetPublicationGate(runtime).perform(
        started.continuation,
    ).code is GateResultCode.ALREADY_APPLIED
    marker = runtime.platform.marker(
        operation.intent.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION.value,
    )
    assert marker is not None
    other = gates_fixture.reserve_protected(runtime, "g8-replay-other", materialization.candidate_id)
    other_start = gates_fixture.start_protected(
        runtime, other, ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
        ActionTargetFence(
            gates_fixture.REPO, materialization.candidate_branch, None,
            runtime.platform.snapshot().generation,
        ), materialization,
    )
    assert other_start.code is GateResultCode.ACTION_PRECONDITION_CONFLICT
    assert _operation(runtime, other.intent.operation_id).state is OperationState.CONFLICT
    assert _operation(runtime, other.intent.operation_id).start_binding_id is None
    assert runtime.platform.marker(
        other.intent.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION.value,
    ) is None
    assert len(runtime.platform._markers) == 1


def test_g8_09a_prepared_without_marker_releases_and_fails_without_replay():
    runtime, materialization, operation, fence = _publication_setup("g8-recovery")
    started = gates_fixture.start_protected(
        runtime, operation,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
        fence, materialization,
    )
    restarted = runtime.restart()
    assert restarted.reconcile_recovered_effect(
        gates_fixture.TASK, operation.intent.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
    ).code is GateResultCode.EFFECT_FAILED
    assert restarted.platform.prepared_effect_state(
        operation.intent.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION.value,
    ) == "RELEASED"
    assert _operation(restarted, operation.intent.operation_id).state is OperationState.FAILED
    assert restarted.platform.marker(
        operation.intent.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION.value,
    ) is None
    assert started.continuation.target_fence_token.active is False


def test_g8_09b_consumed_exact_marker_reconciles_succeeded_without_replay():
    runtime, materialization, operation, fence = _publication_setup("g8-recovery-marker")
    started = gates_fixture.start_protected(
        runtime, operation,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
        fence, materialization,
    )
    assert TargetPublicationGate(runtime).perform(
        started.continuation,
    ).code is GateResultCode.EFFECT_SUCCEEDED
    marker = runtime.platform.marker(
        operation.intent.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION.value,
    )
    assert marker is not None
    restarted = runtime.restart()
    assert restarted.reconcile_recovered_effect(
        gates_fixture.TASK, operation.intent.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
    ).code is GateResultCode.EFFECT_SUCCEEDED
    assert _operation(restarted, operation.intent.operation_id).state is OperationState.SUCCEEDED
    assert restarted.platform.marker(
        operation.intent.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION.value,
    ) == marker


def test_g8_09c_contradictory_marker_postcondition_is_indeterminate():
    runtime, materialization, operation, fence = _publication_setup("g8-recovery-contradiction")
    started = gates_fixture.start_protected(
        runtime, operation,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
        fence, materialization,
    )
    assert TargetPublicationGate(runtime).perform(
        started.continuation,
    ).code is GateResultCode.EFFECT_SUCCEEDED
    runtime.platform.seed_ref(
        gates_fixture.REPO, materialization.candidate_branch, GitSha("d" * 40),
    )
    restarted = runtime.restart()
    assert restarted.reconcile_recovered_effect(
        gates_fixture.TASK, operation.intent.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
    ).code is GateResultCode.INDETERMINATE
    assert _operation(restarted, operation.intent.operation_id).state is OperationState.INDETERMINATE


def test_g8_10a_authoritative_cancellation_first_blocks_protected_start():
    runtime, materialization, operation, fence = _publication_setup("g8-cancel-first")
    cancellation = runtime.boundary.set_cancellation(
        gates_fixture.TASK, CancellationStatus.AUTHORITATIVE,
        CancellationRequestId("g8-cancel"),
    )
    assert ControlStateGate(runtime).commit(
        cancellation, gates_fixture.independent_lease(runtime),
    ).code is GateResultCode.COMMITTED
    task = runtime.backend.read_task_working_set(gates_fixture.TASK).task
    assert task.cancellation_status is CancellationStatus.AUTHORITATIVE
    assert task.state is TaskState.CANCELLED
    result = gates_fixture.start_protected(
        runtime, operation,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
        fence, materialization,
    )
    assert result.code is GateResultCode.REJECTED
    assert result.failure_code is G4FailureCode.CANCELLATION_BLOCKS_OPERATION_START
    stored = _operation(runtime, operation.intent.operation_id)
    assert stored.state is OperationState.RESERVED
    assert stored.start_binding_id is None
    assert runtime.platform.prepared_effect_state(
        operation.intent.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION.value,
    ) == "RELEASED"
    assert runtime.platform.marker(
        operation.intent.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION.value,
    ) is None


def test_g8_10b_started_operation_survives_authoritative_cancellation_until_recovery():
    runtime, materialization, operation, fence = _publication_setup("g8-start-first")
    started = gates_fixture.start_protected(
        runtime, operation,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
        fence, materialization,
    )
    performing = _operation(runtime, operation.intent.operation_id)
    assert performing.state is OperationState.PERFORMING
    cancellation = runtime.boundary.set_cancellation(
        gates_fixture.TASK, CancellationStatus.AUTHORITATIVE,
        CancellationRequestId("g8-cancel-after-start"),
    )
    assert ControlStateGate(runtime).commit(
        cancellation, gates_fixture.independent_lease(runtime),
    ).code is GateResultCode.COMMITTED
    task = runtime.backend.read_task_working_set(gates_fixture.TASK).task
    assert task.cancellation_status is CancellationStatus.AUTHORITATIVE
    assert task.next_integration_operation_id is None
    stored = _operation(runtime, operation.intent.operation_id)
    assert stored.state is OperationState.PERFORMING
    assert stored.start_binding_id == performing.start_binding_id
    assert started.continuation is not None


def test_g8_11_public_evaluation_boundary_can_represent_all_frozen_completion_inputs():
    """The root-managed context supplies all frozen completion facts exactly."""
    runtime, materialization, operation, fence = _publication_setup("g8-completion")
    started = gates_fixture.start_protected(
        runtime, operation,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
        fence, materialization,
    )
    assert TargetPublicationGate(runtime).perform(
        started.continuation,
    ).code is GateResultCode.EFFECT_SUCCEEDED
    assert runtime.reconcile_recovered_effect(
        gates_fixture.TASK, operation.intent.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
    ).code is GateResultCode.EFFECT_SUCCEEDED
    context = gates_fixture.completion_context(
        runtime, "g8-completion-positive",
        contract=ConditionStatus.SATISFIED,
        additional=ConditionStatus.SATISFIED,
        applicability=ConditionStatus.SATISFIED,
        required=(operation.intent.operation_id,),
    )
    assert context.contract_acceptance_status is ConditionStatus.SATISFIED
    assert context.additional_trusted_completion_conditions_status is ConditionStatus.SATISFIED
    assert context.current_applicability_and_authority_status is ConditionStatus.SATISFIED
    assert context.required_protected_operation_ids == (operation.intent.operation_id,)
    assert _evaluate(runtime, context).code is GateResultCode.COMMITTED
    assert _operation(runtime, operation.intent.operation_id).state is OperationState.SUCCEEDED
    assert runtime.backend.read_task_working_set(gates_fixture.TASK).task.state is TaskState.COMPLETED
    completed = runtime.backend.read_task_working_set(gates_fixture.TASK).task
    assert completed.cancellation_status is CancellationStatus.NONE
    completion_command = TaskEvaluationCommand(
        gates_fixture.TASK, context.context_id, (), (), None,
    )
    assert completion_command.blocking_condition_ids == ()
    assert completion_command.awaiting_input_requirement_ids == ()
    assert completion_command.next_integration_operation_id is None
    assert context.required_protected_operation_ids == (operation.intent.operation_id,)
    assert completed.next_integration_operation_id is None

    for name, contract, additional, applicability in (
        ("contract", ConditionStatus.UNSATISFIED, ConditionStatus.SATISFIED, ConditionStatus.SATISFIED),
        ("additional", ConditionStatus.SATISFIED, ConditionStatus.UNSATISFIED, ConditionStatus.SATISFIED),
        ("applicability", ConditionStatus.SATISFIED, ConditionStatus.SATISFIED, ConditionStatus.UNSATISFIED),
    ):
        negative = gates_fixture.runtime()
        gates_fixture.initialize_task(negative)
        negative_context = gates_fixture.completion_context(
            negative, "g8-completion-" + name,
            contract=contract, additional=additional, applicability=applicability,
        )
        blockers = (
            (gates_fixture.BlockingConditionId("g8-not-applicable"),)
            if applicability is ConditionStatus.UNSATISFIED else ()
        )
        assert _evaluate(negative, negative_context, blockers=blockers).code is GateResultCode.COMMITTED
        assert negative.backend.read_task_working_set(gates_fixture.TASK).task.state is not TaskState.COMPLETED


def test_g8_11_required_operation_not_succeeded_cannot_complete():
    runtime, materialization, operation, _ = _publication_setup("g8-required-not-succeeded")
    context = gates_fixture.completion_context(
        runtime, "g8-required-not-succeeded-context",
        contract=ConditionStatus.SATISFIED,
        additional=ConditionStatus.SATISFIED,
        applicability=ConditionStatus.SATISFIED,
        required=(operation.intent.operation_id,),
    )
    assert _evaluate(runtime, context).code is GateResultCode.COMMITTED
    assert _operation(runtime, operation.intent.operation_id).state is OperationState.RESERVED
    assert runtime.backend.read_task_working_set(gates_fixture.TASK).task.state is not TaskState.COMPLETED


def test_g8_11_unresolved_performing_operation_cannot_complete():
    runtime, materialization, operation, fence = _publication_setup("g8-performing")
    started = gates_fixture.start_protected(
        runtime, operation, ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
        fence, materialization,
    )
    context = gates_fixture.completion_context(
        runtime, "g8-performing-context",
        contract=ConditionStatus.SATISFIED,
        additional=ConditionStatus.SATISFIED,
        applicability=ConditionStatus.SATISFIED,
        required=(operation.intent.operation_id,),
    )
    assert _evaluate(runtime, context).code is GateResultCode.COMMITTED
    assert _operation(runtime, operation.intent.operation_id).state is OperationState.PERFORMING
    assert started.continuation is not None
    assert runtime.backend.read_task_working_set(gates_fixture.TASK).task.state is not TaskState.COMPLETED


def test_g8_11_unresolved_indeterminate_operation_cannot_complete():
    runtime, materialization, operation, fence = _publication_setup("g8-indeterminate")
    started = gates_fixture.start_protected(
        runtime, operation, ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
        fence, materialization,
    )
    assert TargetPublicationGate(runtime).perform(started.continuation).code is GateResultCode.EFFECT_SUCCEEDED
    runtime.platform.seed_ref(
        gates_fixture.REPO, materialization.candidate_branch, GitSha("d" * 40),
    )
    restarted = runtime.restart()
    assert restarted.reconcile_recovered_effect(
        gates_fixture.TASK, operation.intent.operation_id,
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
    ).code is GateResultCode.INDETERMINATE
    context = gates_fixture.completion_context(
        restarted, "g8-indeterminate-context",
        contract=ConditionStatus.SATISFIED,
        additional=ConditionStatus.SATISFIED,
        applicability=ConditionStatus.SATISFIED,
        required=(operation.intent.operation_id,),
    )
    assert _evaluate(restarted, context).code is GateResultCode.COMMITTED
    assert _operation(restarted, operation.intent.operation_id).state is OperationState.INDETERMINATE
    assert restarted.backend.read_task_working_set(gates_fixture.TASK).task.state is not TaskState.COMPLETED


def test_g8_11_authoritative_cancellation_cannot_complete():
    runtime = gates_fixture.runtime()
    gates_fixture.initialize_task(runtime)
    cancellation = runtime.boundary.set_cancellation(
        gates_fixture.TASK, CancellationStatus.AUTHORITATIVE,
        CancellationRequestId("g8-completion-cancel"),
    )
    assert ControlStateGate(runtime).commit(
        cancellation, gates_fixture.independent_lease(runtime),
    ).code is GateResultCode.COMMITTED
    context = gates_fixture.completion_context(
        runtime, "g8-cancelled-context",
        contract=ConditionStatus.SATISFIED,
        additional=ConditionStatus.SATISFIED,
        applicability=ConditionStatus.SATISFIED,
    )
    with pytest.raises(ValueError, match="TERMINAL_TASK"):
        _evaluate(runtime, context)
    task = runtime.backend.read_task_working_set(gates_fixture.TASK).task
    assert task.cancellation_status is CancellationStatus.AUTHORITATIVE
    assert task.state is not TaskState.COMPLETED


def test_g8_11_semantic_veto_preserves_g4_additional_completion_fact(monkeypatch):
    runtime = gates_fixture.runtime()
    gates_fixture.initialize_task(runtime)
    context = gates_fixture.completion_context(
        runtime, "g8-additional-fact-preservation",
        contract=ConditionStatus.SATISFIED,
        additional=ConditionStatus.UNSATISFIED,
        applicability=ConditionStatus.SATISFIED,
    )
    runtime.register_completion_evaluation_context(context)
    observed = []
    original = gates_module._compose_completion_aggregate

    def record_g4_additional_fact(**kwargs):
        observed.append(kwargs["additional_conditions_status"])
        return original(**kwargs)

    monkeypatch.setattr(
        gates_module, "_compose_completion_aggregate", record_g4_additional_fact,
    )
    command = TaskEvaluationCommand(
        gates_fixture.TASK, context.context_id, (), (), None,
    )
    request = runtime.boundary.evaluate_task(command)
    assert observed == [ConditionStatus.UNSATISFIED]
    assert request.transaction.mutations[0].task.state is not TaskState.COMPLETED
    assert _evaluate(runtime, context).code is GateResultCode.COMMITTED
    assert runtime.backend.read_task_working_set(gates_fixture.TASK).task.state is not TaskState.COMPLETED


def test_g8_13_external_merge_like_state_without_marker_never_recovers_succeeded():
    """An untrusted fast-forward cannot substitute for this merge's marker."""
    runtime, materialization, _, _ = _publication_setup("g8-merge-publication")
    publish = next(iter(runtime.backend.read_task_working_set(gates_fixture.TASK).operations))
    publish_started = gates_fixture.start_protected(
        runtime, publish, ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
        ActionTargetFence(
            gates_fixture.REPO, materialization.candidate_branch, None,
            runtime.platform.snapshot().generation,
        ), materialization,
    )
    assert TargetPublicationGate(runtime).perform(publish_started.continuation).code is GateResultCode.EFFECT_SUCCEEDED
    create_pr = gates_fixture.reserve_protected(
        runtime, "g8-merge-pr", materialization.candidate_id,
    )
    pr_started = gates_fixture.start_protected(
        runtime, create_pr, ProtectedEffectSubject.PULL_REQUEST_CREATION,
        ActionTargetFence(
            gates_fixture.REPO, materialization.candidate_branch,
            materialization.commit, runtime.platform.snapshot().generation,
            gates_fixture.REF, materialization.base,
        ), materialization, base_ref=gates_fixture.REF,
        provenance_operation_id=publish.intent.operation_id,
    )
    assert TargetPublicationGate(runtime).perform(pr_started.continuation).code is GateResultCode.EFFECT_SUCCEEDED
    merge = gates_fixture.reserve_protected(runtime, "g8-external-merge", materialization.candidate_id)
    started = gates_fixture.start_protected(
        runtime, merge, ProtectedEffectSubject.FAST_FORWARD_MERGE,
        ActionTargetFence(
            gates_fixture.REPO, gates_fixture.REF, materialization.base,
            runtime.platform.snapshot().generation,
        ), materialization, provenance_operation_id=create_pr.intent.operation_id,
    )
    assert _operation(runtime, merge.intent.operation_id).state is OperationState.PERFORMING
    assert runtime.platform.marker(
        merge.intent.operation_id, ProtectedEffectSubject.FAST_FORWARD_MERGE.value,
    ) is None
    # Fixture external mutation path: the target now resembles the intended merge,
    # but it carries neither this operation's marker nor a consumed prepared record.
    restarted = runtime.restart()
    assert restarted.platform.fast_forward(
        gates_fixture.REPO, gates_fixture.REF, materialization.base,
        materialization.commit, materialization.base,
    )
    result = restarted.reconcile_recovered_effect(
        gates_fixture.TASK, merge.intent.operation_id,
        ProtectedEffectSubject.FAST_FORWARD_MERGE,
    )
    assert result.code is GateResultCode.EFFECT_FAILED
    assert _operation(restarted, merge.intent.operation_id).state is OperationState.FAILED
    assert restarted.platform.prepared_effect_state(
        merge.intent.operation_id, ProtectedEffectSubject.FAST_FORWARD_MERGE.value,
    ) == "RELEASED"
    assert restarted.platform.marker(
        merge.intent.operation_id, ProtectedEffectSubject.FAST_FORWARD_MERGE.value,
    ) is None
    assert started.continuation.target_fence_token.active is False
    assert not any(
        item.intent.operation_id == merge.intent.operation_id
        and item.state is OperationState.SUCCEEDED
        for item in restarted.backend.read_task_working_set(gates_fixture.TASK).operations
    )
    completion = gates_fixture.completion_context(
        restarted, "g8-external-merge-completion",
        contract=ConditionStatus.SATISFIED,
        additional=ConditionStatus.SATISFIED,
        applicability=ConditionStatus.SATISFIED,
        required=(merge.intent.operation_id,),
    )
    assert _evaluate(restarted, completion).code is GateResultCode.COMMITTED
    assert restarted.backend.read_task_working_set(gates_fixture.TASK).task.state is not TaskState.COMPLETED


def test_g8_13_contradictory_marked_merge_state_recovers_indeterminate():
    """A real marker contradicted by current target truth remains INDETERMINATE."""
    runtime, materialization, _, _ = _publication_setup("g8-merge-contradiction")
    publish = next(iter(runtime.backend.read_task_working_set(gates_fixture.TASK).operations))
    publish_started = gates_fixture.start_protected(
        runtime, publish, ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION,
        ActionTargetFence(
            gates_fixture.REPO, materialization.candidate_branch, None,
            runtime.platform.snapshot().generation,
        ), materialization,
    )
    assert TargetPublicationGate(runtime).perform(
        publish_started.continuation,
    ).code is GateResultCode.EFFECT_SUCCEEDED
    create_pr = gates_fixture.reserve_protected(
        runtime, "g8-merge-contradiction-pr", materialization.candidate_id,
    )
    pr_started = gates_fixture.start_protected(
        runtime, create_pr, ProtectedEffectSubject.PULL_REQUEST_CREATION,
        ActionTargetFence(
            gates_fixture.REPO, materialization.candidate_branch,
            materialization.commit, runtime.platform.snapshot().generation,
            gates_fixture.REF, materialization.base,
        ), materialization, base_ref=gates_fixture.REF,
        provenance_operation_id=publish.intent.operation_id,
    )
    assert TargetPublicationGate(runtime).perform(
        pr_started.continuation,
    ).code is GateResultCode.EFFECT_SUCCEEDED
    existing = runtime.backend.read_task_working_set(gates_fixture.TASK).operations
    assert all(
        item.intent.operation_id != OperationId("g8-contradiction-merge-final")
        for item in existing
    )
    assert all(
        item.intent.idempotency_key.value != "key-g8-contradiction-merge-final"
        for item in existing
    )
    merge = gates_fixture.reserve_protected(
        runtime, "g8-contradiction-merge-final", materialization.candidate_id,
    )
    merge_started = gates_fixture.start_protected(
        runtime, merge, ProtectedEffectSubject.FAST_FORWARD_MERGE,
        ActionTargetFence(
            gates_fixture.REPO, gates_fixture.REF, materialization.base,
            runtime.platform.snapshot().generation,
        ), materialization, provenance_operation_id=create_pr.intent.operation_id,
    )
    assert MergeGate(runtime).perform(
        merge_started.continuation,
    ).code is GateResultCode.EFFECT_SUCCEEDED
    exact_marker = runtime.platform.marker(
        merge.intent.operation_id, ProtectedEffectSubject.FAST_FORWARD_MERGE.value,
    )
    assert exact_marker is not None

    # Contradict the marked postcondition with an external target mutation.
    runtime.platform.seed_ref(gates_fixture.REPO, gates_fixture.REF, materialization.base)
    restarted = runtime.restart()
    recovered = restarted.reconcile_recovered_effect(
        gates_fixture.TASK, merge.intent.operation_id,
        ProtectedEffectSubject.FAST_FORWARD_MERGE,
    )
    assert recovered.code is GateResultCode.INDETERMINATE
    assert _operation(restarted, merge.intent.operation_id).state is OperationState.INDETERMINATE
    assert restarted.platform.marker(
        merge.intent.operation_id, ProtectedEffectSubject.FAST_FORWARD_MERGE.value,
    ) == exact_marker
    completion = gates_fixture.completion_context(
        restarted, "g8-merge-contradiction-completion",
        contract=ConditionStatus.SATISFIED,
        additional=ConditionStatus.SATISFIED,
        applicability=ConditionStatus.SATISFIED,
        required=(merge.intent.operation_id,),
    )
    assert _evaluate(restarted, completion).code is GateResultCode.COMMITTED
    assert restarted.backend.read_task_working_set(gates_fixture.TASK).task.state is not TaskState.COMPLETED


def test_g8_12a_objective_prose_is_outside_the_trusted_contract_boundary():
    """Distinct raw Issue Contracts admit normally; prose creates no G3/G4 authority."""
    runtime = gates_fixture.runtime()
    operations = (TaskCapability.IMPLEMENTATION, TaskCapability.SEMANTIC_REVIEW)
    raw_a = _raw_contract(
        contract_id=ContractId("g8-prose-a"), task_id=TaskId("g8-prose-task-a"),
        operations=operations, objective="Ship only documentation.",
    )
    raw_b = _raw_contract(
        contract_id=ContractId("g8-prose-b"), task_id=TaskId("g8-prose-task-b"),
        operations=operations, objective="Rewrite production and merge immediately.",
    )
    first = _admit_raw_contract(runtime, raw_a, "g8-prose-a")
    second = _admit_raw_contract(runtime, raw_b, "g8-prose-b")
    assert first.raw_bytes == raw_a and second.raw_bytes == raw_b
    assert first.contract_raw_sha256 != second.contract_raw_sha256
    assert first.contract_id != second.contract_id
    assert (
        first.requested_operations, first.allowed_mutation_scope,
        first.prohibited_mutation_scope, first.base_ref, first.base_sha,
        first.risk_floor, first.acceptance_plan.requirements,
    ) == (
        second.requested_operations, second.allowed_mutation_scope,
        second.prohibited_mutation_scope, second.base_ref, second.base_sha,
        second.risk_floor, second.acceptance_plan.requirements,
    )
    assert "objective" not in first.__dataclass_fields__
    assert "objective" not in second.__dataclass_fields__
    assert all(
        evaluator.mechanism.value == "deterministic"
        for contract in (first, second)
        for requirement in contract.acceptance_plan.requirements
        for evaluator in requirement.evaluators
    )
    assert runtime.backend.read_task_working_set(first.task_id) is None
    assert runtime.backend.read_task_working_set(second.task_id) is None
    assert "objective" not in TaskEvaluationCommand.__dataclass_fields__


def test_g8_12b_requested_capability_ceiling_does_not_create_completion_work():
    """The real admitted contract ceiling is not authorization or a completion to-do list."""
    runtime = gates_fixture.runtime()
    narrow_ops = (TaskCapability.IMPLEMENTATION, TaskCapability.SEMANTIC_REVIEW)
    broad_ops = (*narrow_ops, TaskCapability.TARGET_PUBLISH)
    narrow = _admit_raw_contract(runtime, _raw_contract(
        contract_id=ContractId("g8-ops-narrow"), task_id=TaskId("g8-ops-task-narrow"),
        operations=narrow_ops,
    ), "g8-ops-narrow")
    broad = _admit_raw_contract(runtime, _raw_contract(
        contract_id=ContractId("g8-ops-broad"), task_id=TaskId("g8-ops-task-broad"),
        operations=broad_ops,
    ), "g8-ops-broad")
    narrow_ceiling = derive_contract_authority_ceiling(narrow)
    broad_ceiling = derive_contract_authority_ceiling(broad)
    assert TaskCapability.TARGET_PUBLISH not in narrow_ceiling.requested_capabilities
    assert TaskCapability.TARGET_PUBLISH in broad_ceiling.requested_capabilities
    target = runtime.backend.read_resolved_target_registration(gates_fixture.TARGET).registration
    assert TaskCapability.TARGET_PUBLISH not in target.allowed_task_capabilities

    proposal_value = authorization_fixture.proposal_json(gates_fixture.TARGET)
    proposal_value.update(
        task_id=broad.task_id.value,
        contract_id=broad.contract_id.value,
        contract_sha256=broad.contract_raw_sha256.value,
        capabilities=["implementation", "target_publish"],
    )
    proposal = load_candidate_authorization_proposal(
        json.dumps(proposal_value, separators=(",", ":")).encode(),
    )
    proposal_contract, policy, approval, issuer, root = authorization_fixture.direct_contexts(
        proposal, target,
    )
    assert proposal_contract.contract_id == broad.contract_id
    decision = admit_direct_authorization(
        proposal, target, broad_ceiling, policy, approval, issuer, root,
    )
    assert decision.decision is Decision.DENY
    assert decision.reason_code is AuthorizationAdmissionReasonCode.CAPABILITY_NOT_PERMITTED
    assert decision.admitted_authorization is None
    assert runtime.backend.read_task_working_set(broad.task_id) is None
    assert all(
        item.intent.task_id != broad.task_id
        for item in runtime.backend._state.operations.values()
    )
    assert "required_protected_operation_ids" not in broad.__dataclass_fields__


def test_g8_12_requested_operations_reorder_does_not_create_sequencing_semantics():
    runtime = gates_fixture.runtime()
    first_order = (TaskCapability.IMPLEMENTATION, TaskCapability.SEMANTIC_REVIEW)
    second_order = tuple(reversed(first_order))
    first = _admit_raw_contract(runtime, _raw_contract(
        contract_id=ContractId("g8-reorder-a"), task_id=TaskId("g8-reorder-task-a"),
        operations=first_order,
    ), "g8-reorder-a")
    second = _admit_raw_contract(runtime, _raw_contract(
        contract_id=ContractId("g8-reorder-b"), task_id=TaskId("g8-reorder-task-b"),
        operations=second_order,
    ), "g8-reorder-b")
    assert first.requested_operations == first_order
    assert second.requested_operations == second_order
    assert first.requested_operations != second.requested_operations
    assert frozenset(first.requested_operations) == frozenset(second.requested_operations)
    assert frozenset(derive_contract_authority_ceiling(first).requested_capabilities) == frozenset(
        derive_contract_authority_ceiling(second).requested_capabilities
    )
    assert "operation_order" not in first.__dataclass_fields__
    assert "operation_order" not in second.__dataclass_fields__
    assert runtime.backend.read_task_working_set(first.task_id) is None
    assert runtime.backend.read_task_working_set(second.task_id) is None


def test_g8_14_admitted_evidence_for_old_candidate_is_stale_for_replacement():
    runtime, original, target, base_dependency, evidence = _current_semantic_runtime()
    candidate_id = CandidateId("g8-replacement-candidate")
    replacement_commit = GitSha("4" * 40)
    replacement_tree_id = GitSha("5" * 40)
    replacement_blob_id = GitSha("6" * 40)
    runtime._object_store = gates_fixture.FixtureGitObjectStore(
        evidence.subject.repository_id,
        (
            gates_fixture.FixtureGitCommit(original.base, (), original.base_tree),
            gates_fixture.FixtureGitCommit(
                replacement_commit, (original.base,), replacement_tree_id,
            ),
        ),
        (
            gates_fixture.FixtureGitTree(original.base_tree, ()),
            gates_fixture.FixtureGitTree(replacement_tree_id, (
                gates_fixture.FixtureGitTreeEntry(
                    "replacement.py", gates_fixture.GitObjectKind.BLOB,
                    "100644", replacement_blob_id,
                ),
            )),
        ),
    )
    runtime = runtime.restart()
    create = runtime.boundary.record_candidate_truth(
        task_id=evidence.subject.task_id, candidate_id=candidate_id,
        candidate_commit_id=replacement_commit,
        parent_candidate_ids=(original.candidate_id,),
    )
    assert ControlStateGate(runtime).commit(
        create, gates_fixture.independent_lease(runtime),
    ).code is GateResultCode.COMMITTED
    candidate = runtime.backend.read_candidate(candidate_id)
    assert candidate is not None
    replacement = runtime.backend.read_candidate_materialization(
        candidate.materialization_id,
    )
    assert replacement is not None
    assert replacement.materialization_id != original.materialization_id
    assert candidate.candidate_id != original.candidate_id
    adopt = runtime.boundary.adopt_recorded_candidate(
        task_id=evidence.subject.task_id, candidate_id=candidate_id,
        decision_event_id=gates_fixture.DecisionEventId("g8-candidate-replacement"),
    )
    assert ControlStateGate(runtime).commit(
        adopt, gates_fixture.independent_lease(runtime),
    ).code is GateResultCode.COMMITTED
    assert runtime.backend.read_task_working_set(evidence.subject.task_id).task.current_candidate_id == candidate_id

    current = runtime._resolve_semantic_consumption(
        evidence.subject.task_id, (evidence.evidence_id,), runtime.backend.occurrence,
    )
    assert current is not None
    assert current.evidence_currentness[0].status.name == "STALE"
    assert current.evidence_currentness[0].applicability_reason is EvidenceApplicabilityReason.CANDIDATE_CHANGED
    assert current.obligation_results[0].progression_support_evidence_ids == ()

    # Existing G6 write validation refuses to attach a C1 EvidenceId to a C2
    # operation. If a caller asks the public start boundary for that absent
    # operation anyway, it cannot produce a prepared start or effect.
    assert runtime.backend.read_task_working_set(evidence.subject.task_id) is not None
    before_occurrence = runtime.backend.occurrence
    bad_request = runtime.boundary.reserve_operation(
        evidence.subject.task_id,
        gates_fixture.OperationReservationCommand(
            operation_id=OperationId("g8-stale-candidate-forward"),
            idempotency_key=OperationIdempotencyKey("g8-stale-candidate-forward-key"),
            action_id=OperationActionId("g8-stale-candidate-forward"),
            subject_id=OperationSubjectId("g8-stale-candidate-forward"),
            required_evidence_ids=(evidence.evidence_id,),
            integration_binding=gates_fixture.IntegrationBound(
                gates_fixture.GitRef(target.merge.allowed_integration_refs[0].value)
            ),
            is_repair_attempt=False,
        ),
    )
    rejected = ControlStateGate(runtime).commit(
        bad_request, gates_fixture.independent_lease(runtime),
    )
    assert rejected.code is GateResultCode.REJECTED
    assert runtime.backend.occurrence == before_occurrence
    assert all(
        item.intent.operation_id != OperationId("g8-stale-candidate-forward")
        for item in runtime.backend.read_task_working_set(evidence.subject.task_id).operations
    )
    assert all(
        item.intent.operation_id != OperationId("g8-stale-candidate-forward")
        for item in runtime.backend.read_task_working_set(evidence.subject.task_id).operations
    )
    assert runtime.platform.marker(
        OperationId("g8-stale-candidate-forward"),
        ProtectedEffectSubject.CANDIDATE_BRANCH_PUBLICATION.value,
    ) is None

    context = gates_fixture.completion_context(
        runtime, "g8-stale-candidate-completion",
        contract=ConditionStatus.SATISFIED,
        additional=ConditionStatus.SATISFIED,
        applicability=ConditionStatus.SATISFIED,
    )
    runtime.register_completion_evaluation_context(context)
    with pytest.raises(gates_fixture._TaskSemanticDenied) as denied:
        runtime.boundary.evaluate_task(TaskEvaluationCommand(
            evidence.subject.task_id, context.context_id, (), (), None,
        ))
    assert denied.value.code is gates_fixture.TaskSemanticDenialCode.SEMANTIC_CONTRACT_UNSATISFIED
    assert runtime.backend.read_task_working_set(evidence.subject.task_id).task.state is not TaskState.COMPLETED
