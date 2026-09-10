# Autonomous Development v2 — State Machine

**Status:** Phase 0 frozen  
**Version:** 1.4  
**Repository:** `RayZhang2024/autonomous-dev-control-plane`  
**Governing policy:** `docs/CORE_POLICY.md` v1.0  
**Governing architecture:** `docs/ARCHITECTURE.md` v1.2

## 1. Purpose

This document defines the canonical lifecycle model for autonomously controlled development tasks.

It specifies durable task states, canonical task revisions, candidate and evidence handling, repair and cancellation semantics, protected-operation lifecycle, concurrency and idempotency, reconciliation, and the relationship between canonical state and GitHub objects.

This specification is subordinate to `CORE_POLICY.md` and `ARCHITECTURE.md` and MUST NOT weaken either.

---

## 2. Model and design principle

The state machine records durable control significance, not every activity being performed.

The system distinguishes:

```text
TASK STATE                 durable lifecycle posture
TASK REVISION              version of safety-relevant canonical task data
CANDIDATE RECORD           immutable exact candidate identity
EVIDENCE RECORD            immutable admitted evidence
OPERATION RECORD           canonical record of a security-relevant invocation/effect
OPERATION REVISION         version of safety-relevant operation data
AUTHORITATIVE STATE        current GitHub/platform/control facts
```

These dimensions MUST NOT be collapsed into one status field.

Implementation, review, validation, repair, publication, runtime, and merge are activities or operations, not parallel task-state machines. States such as `implementing`, `reviewing`, `repairing`, or `merging` are therefore not part of the canonical task lifecycle.

---

## 3. Canonical task revisions

A **canonical task revision** identifies one version of the task's safety-relevant control record.

Any safety-relevant canonical task change MUST create a new revision even if the lifecycle state does not change. Examples include admitting evidence references, reserving repair allowance, changing the current candidate, recording cancellation, or changing the exact next integration action.

A **lifecycle transition** is a task revision in which the lifecycle-state enum changes. Not every task revision is a lifecycle transition.

Existing-task writes MUST bind to the exact expected prior task revision. Initial task creation MUST use atomic create-if-absent semantics. Last-write-wins behaviour is forbidden.

A stale expected revision produces a **revision conflict**: a Control-State Gate write result requiring fresh read and recomputation. It is not itself a task state or operation outcome.

---

## 4. Canonical task states

The v2 task lifecycle contains exactly seven canonical states:

| State | Meaning |
|---|---|
| `admitted` | The task has admitted contract and authorization and is eligible for controlled work, but no current candidate is selected. |
| `evaluating` | An exact current candidate exists and one or more required acceptance, publication, runtime, or integration conditions remain unresolved. |
| `awaiting_input` | Progress depends on specifically identified admissible non-autonomous input, with no independent blocking condition. |
| `integration_ready` | The current candidate/context satisfied the requirements for one exact next protected integration action at the last trusted evaluation. |
| `blocked` | Autonomous progress cannot safely continue under current policy, authorization, contract, state, evidence, target conditions, or bounded authority. |
| `completed` | The authorized completion postcondition has been established and verified. |
| `cancelled` | Valid authority deliberately terminated the task after relevant unresolved protected effects were reconciled. |

`completed` and `cancelled` are terminal for that canonical task identity.

Adding another canonical task state requires deliberate architectural review.

---

## 5. Task state is not authority

Canonical state records the trusted controller's last durable lifecycle conclusion. It is not bearer authority.

In particular, `integration_ready` does not itself authorize merge, publication, deployment, or any other protected operation.

Immediately before every consequential action, the responsible trusted boundary MUST establish the applicable active policy, authenticated authorization, current authoritative state, required provenance-bound evidence, exact candidate/context, and exact requested operation.

If those conditions no longer hold, the consequential action MUST NOT occur even if the persisted lifecycle state has not yet been reconciled.

---

## 6. Admission and initial creation

Planning proposals, issue drafts, GPT decompositions, proposed contracts, and proposed authorization have no canonical task state.

A canonical task is created only after required contract and authorization admission succeeds under the active policy.

Creation MUST be atomic:

```text
create task T
ONLY IF
canonical task T is absent
```

A competing creation attempt against an existing task identity fails with revision conflict and MUST NOT overwrite or replace the existing record.

A rejected admission attempt does not create a `blocked` task merely because admission failed; it MAY be audited separately.

---

## 7. Core lifecycle semantics

### 7.1 `admitted`

`admitted` means the task remains validly admitted while no current candidate is selected. Candidate-producing work may be requested, but implementation activity itself does not change lifecycle state.

The task moves to `evaluating` only when an exact candidate has been materialized, validated for applicable scope requirements, and atomically established as the current candidate.

### 7.2 `evaluating`

`evaluating` means an exact current candidate exists. Applicable authorized work may include deterministic validation, semantic review, evidence-producing publication, controlled runtime, external observation, bounded repair, or candidate replacement/retirement.

Evidence or budget changes may create same-state task revisions.

### 7.3 `blocked`

`blocked` is a safe suspended state used when an independent condition prevents safe autonomous progression. Examples include missing or revoked authorization, unauthorized scope, exhausted repair authority, invalid/unregistered target, unresolved state conflict, unknown publication side effects, active-policy incompatibility, unexpected protected mutation, uncertain trusted-core impact, or absence of an authorized recovery path.

Recovery from `blocked` requires fresh deterministic evaluation. Historical state MUST NOT simply be restored.

### 7.4 `completed`

`completed` means the task's authorized completion postcondition has been verified. Merge success alone is not automatically task completion.

### 7.5 `cancelled`

`cancelled` represents deliberate authorized termination after relevant unresolved protected effects have been reconciled. A cancelled task cannot autonomously resume; later work requires a new valid task identity and authority.

---

## 8. `awaiting_input` versus `blocked`

`awaiting_input` applies only when:

1. applicable policy, authorization, contract, target registration, and current candidate context where applicable remain viable;
2. no independent blocking condition exists;
3. the missing prerequisite is explicitly identified;
4. it has a known authorized or admissible non-autonomous source;
5. autonomous components are not authorized to manufacture it; and
6. satisfying it does not require unauthorized expansion of authority, scope, capability, target registration, or exhausted repair/retry limits.

Examples include exact human approval or registered external observation.

State selection is deterministic:

```text
if an independent blocking condition exists:
    blocked
else if an admissible non-autonomous prerequisite remains:
    awaiting_input
else:
    compute the otherwise applicable state
```

Thus `blocked` takes precedence over `awaiting_input`.

When missing input arrives, the controller recomputes the state from current facts; it MUST NOT blindly restore a previous lifecycle state.

---

## 9. Exact integration readiness

`integration_ready` MUST be bound to one exact next protected integration action.

The canonical record binds, where applicable:

```text
candidate identity
action type
action subject
target identity
expected authoritative target state
contract identity
authorization identity
active-policy identity
required evidence identities
```

A task may require several protected integration steps. It may remain `integration_ready` across same-state revisions when the exact next action changes, or return to `evaluating` if further evidence is required.

For example:

```text
integration_ready@R31: next_action = publish
    ↓ publication succeeds
integration_ready@R32: next_action = merge
```

The responsible gate still revalidates all action-time requirements before either operation begins.

`integration_ready` is **not** a mandatory waypoint to `completed`.

If the task's trusted structured completion conditions can be established without any further protected integration action, the controller MUST NOT invent a fictitious publication, merge, deployment, or other integration step merely to enter `integration_ready`.

Such a task may transition directly to `completed` from another permitted non-terminal state when the completion-integrity requirements in §32 are freshly established.

---

## 10. Candidate replacement and retirement

Candidate records are immutable and historical candidates are preserved.

A normal task has at most one canonical `current_candidate` at a time. A candidate record binds, where applicable, candidate identity, task, materialization, base, target, contract, authorization, active-policy identity, lineage, and creation-operation identity.

Replacing `C1` with `C2` or retiring `C1` requires a concurrency-protected task revision. Candidate-bound evidence for `C1` MUST NOT transfer to `C2` unless active policy explicitly permits deterministic proof of continued applicability.

A current candidate MAY be retired and the task returned directly to `admitted` when task authority remains valid, no replacement is simultaneously selected, and no independent blocker exists. `awaiting_input → admitted` additionally requires that no candidate-independent waiting condition remains.

Candidate detachment MUST NOT occur while an unresolved candidate-bound consequential operation could still change protected or authoritative state involving that candidate. Such an operation MUST first be reconciled, unless an explicitly trusted reconciliation mechanism safely resolves the relationship.

Ordinary non-consequential work still running against the old candidate does not prevent detachment; any late output remains bound to that old candidate.

---

## 11. Cancellation

Cancellation is a protected control action. A valid request MAY set a safety-relevant canonical condition such as `cancellation_requested = true` without immediately entering terminal `cancelled`.

Once cancellation is authoritative:

1. no new protected task operation may successfully enter `performing`, except an operation required for safe reconciliation/cancellation handling;
2. no new repair-attempt consumption, candidate adoption, protected materialization, target publication, controlled runtime, merge, or other consequential progression may begin;
3. already `performing` or `indeterminate` relevant consequential operations MUST be reconciled; and
4. only after relevant authoritative effects are established may the task become `cancelled`.

Ordinary untrusted work-plane computation SHOULD be stopped where practical. Late work-plane output remains untrusted and cannot alter canonical state or cross a protected boundary without a fresh valid control decision.

Terminal cancellation requires valid cancellation authority, an applicable cancellation request, and no unresolved relevant `performing` or `indeterminate` consequential operation.

---

## 12. Normal lifecycle

The lifecycle supports both candidate/integration work and tasks whose trusted structured completion conditions require no protected integration action.

```text
proposal
   │ admission
   ▼
admitted
   │
   ├──── completion established with
   │     no further protected
   │     integration required ───────────────► completed
   │
   │ exact candidate established
   ▼
evaluating
   ├──── completion established with
   │     no further protected
   │     integration required ───────────────► completed
   │
   ├──── admissible external input missing ──► awaiting_input
   │                                               │
   │                                               │ input admitted
   │                                               ▼
   │                                           re-evaluate
   │                                               │
   │                                               ├──► evaluating
   │                                               ├──► integration_ready
   │                                               └──► completed
   │
   ├──── safe candidate retirement ──────────► admitted
   │
   │ exact protected integration action ready
   ▼
integration_ready
   ├──── safe candidate retirement ──────────► admitted
   │
   │ protected action succeeds
   ▼
integration_ready / evaluating / completed
```

At any non-terminal point, an independent safety failure may produce `blocked`.

When the condition that caused `blocked` is later resolved, fresh deterministic evaluation computes the correct current state. That recomputation may produce `completed` directly if the completion-integrity requirements are now satisfied.

Valid cancellation may initiate cancellation handling and eventually produce `cancelled`.

Once cancellation has become authoritative under §11, the task no longer follows any completion path and MUST proceed only through permitted cancellation/reconciliation handling toward `cancelled`.

No transition to `completed` is inferred merely because no further autonomous work is planned.

---

## 13. Allowed lifecycle transitions

| From | To | Required significance |
|---|---|---|
| no task | `admitted` | Contract/authorization admission and atomic create-if-absent succeed. |
| `admitted` | `evaluating` | Exact candidate is validly established as current. |
| `admitted` | `awaiting_input` | Admissible non-autonomous input is required and no blocker exists. |
| `admitted` | `blocked` | Current trusted conditions prevent progression. |
| `admitted` | `completed` | No further protected integration action is required and the trusted structured completion predicate in §32 is freshly satisfied. |
| `admitted` | `cancelled` | Cancellation conditions are satisfied. |
| `evaluating` | `admitted` | Current candidate is safely retired. |
| `evaluating` | `awaiting_input` | Missing admissible non-autonomous input is the only remaining path. |
| `evaluating` | `integration_ready` | All prerequisites for one exact next protected integration action are satisfied. |
| `evaluating` | `blocked` | No safe authorized progression exists. |
| `evaluating` | `completed` | No further protected integration action is required and the trusted structured completion predicate is freshly satisfied for the applicable exact candidate/context. |
| `evaluating` | `cancelled` | Cancellation completes after required reconciliation. |
| `awaiting_input` | `admitted` | Candidate is safely retired and no candidate-independent wait remains. |
| `awaiting_input` | `evaluating` | Required input is admitted and further candidate evaluation remains. |
| `awaiting_input` | `integration_ready` | Required input is admitted and exact integration readiness is established. |
| `awaiting_input` | `blocked` | Re-evaluation exposes an independent blocker. |
| `awaiting_input` | `completed` | Required input is admitted, no further protected integration action is required, and the trusted structured completion predicate is freshly satisfied. |
| `awaiting_input` | `cancelled` | Cancellation completes after required reconciliation. |
| `integration_ready` | `admitted` | Current candidate is safely retired. |
| `integration_ready` | `evaluating` | Candidate/context/evidence changes, becomes stale, or further evaluation is required. |
| `integration_ready` | `awaiting_input` | An admissible non-autonomous prerequisite is now the only missing condition. |
| `integration_ready` | `blocked` | Safe integration/progression is no longer possible. |
| `integration_ready` | `completed` | Required protected integration effects and the trusted structured completion predicate are freshly verified. |
| `integration_ready` | `cancelled` | Cancellation completes before task completion. |
| `blocked` | `admitted` | Blocker is resolved and no current candidate remains. |
| `blocked` | `evaluating` | Blocker is resolved and a valid current candidate remains. |
| `blocked` | `awaiting_input` | Blocker is resolved but admissible input remains required. |
| `blocked` | `integration_ready` | Blocker is resolved and exact readiness is freshly established. |
| `blocked` | `completed` | The former blocker is freshly established as resolved, no further protected integration action is required, and the trusted structured completion predicate is freshly satisfied. |
| `blocked` | `cancelled` | Valid cancellation completes after required reconciliation. |

`completed` and `cancelled` have no autonomous outgoing transitions.

No actor may directly set a lifecycle state merely by requesting that value. Every transition is a deterministic trusted decision against the exact current context.

Direct transition to `completed` MUST NOT be used to bypass a required protected integration action.

If an admitted contract acceptance requirement, active trusted policy, Target Registration, or another structured completion-rule source explicitly designated by active trusted policy makes such an action necessary for completion, that action MUST first pass through its normal protected operation path.

Authorization must independently permit the action; authorization alone does not make that action a completion requirement.

**No transition to `completed` is permitted once cancellation has become authoritative under §11.**

If completion and cancellation race, the outcome is determined by the first valid concurrency-protected canonical mutation to linearize:

```text
completion revision linearizes first
→ completed
→ terminal

authoritative cancellation revision linearizes first
→ completion is no longer eligible
→ reconcile relevant protected effects
→ cancelled
```

A stale competing write fails by revision conflict and MUST be recomputed against the resulting current state.

---

## 14. Decision and persistence ownership

Roles are separated:

| Component | May trigger reevaluation? | May decide canonical revision validity? | May persist canonical records? |
|---|---:|---:|---:|
| GPT / orchestrator / workers / semantic reviewer | Yes, directly or indirectly | No | No |
| Authenticated human | Through authorized input | No direct lifecycle authority | No |
| State Reader | Through newly observed facts | No | No |
| Deterministic trusted controller | Yes | **Yes** | No |
| Control-State Gate | No policy discretion | No | **Yes** |

Every canonical task creation/revision and canonical operation creation/revision is persisted only through the Control-State Gate.

Workers, reviewers, publication/merge gates, runtime executors, and orchestrators MUST NOT directly rewrite canonical task or operation outcomes.

---

## 15. Canonical control-state mutation boundary

Canonical control-state writes are consequential protected actions and MUST satisfy active policy, authenticated authorization, exact identity, current authoritative-state preconditions, atomicity, and Control-State Gate enforcement.

They include creation or revision of task records, operation records, candidate/evidence references, repair/retry state, cancellation state, and other security-relevant canonical data.

The Control-State Gate transaction that records such a mutation does **not** recursively require another canonical operation record solely to represent that recording transaction. The atomic canonical revision and its audit record represent the mutation itself.

This is a representational boundary only; it does not make control-state writes non-consequential or exempt them from trusted enforcement.

---

## 16. Task revision records and atomicity

A safety-relevant task revision binds conceptually:

```text
revision identity
task identity
prior/new revision
prior/new lifecycle state
current candidate
next integration action where applicable
cancellation status where applicable
contract / authorization / active-policy / target-registration identities
supporting evidence identities
repair/retry state
reason code
requesting actor/service
decision identity
timestamp
```

For an existing task:

```text
write R18 ONLY IF current task revision == R17
```

For initial creation:

```text
create T ONLY IF T is absent
```

If the required atomic precondition cannot be established, no canonical mutation occurs.

---

## 17. Repair and retry

Autonomous repair is controlled by bounded canonical allowance governed by active trusted policy. Any task-selected repair/retry limit MUST remain within active-policy bounds.

Before repair begins, the controller MUST establish that repair is permitted for the exact current candidate, the failure basis remains applicable, scope remains authorized, and allowance remains.

Repair-attempt reservation/consumption is concurrency-safe and idempotent. The same repair-attempt identity MUST NOT consume allowance twice.

A repair creates a new candidate. Candidate-bound evidence does not carry forward by default.

Once an authorized semantic repair attempt begins, it SHOULD count as consumed unless trusted policy can establish that it did not occur. Repair exhaustion causes `blocked` unless another explicitly authorized path exists.

---

## 18. Evidence and freshness

Admitted evidence records are immutable. The system SHOULD NOT rely on a mutable authoritative `stale` flag as the source of truth.

Applicability is recomputed against the current exact context, including candidate, base, contract, authorization, active policy, and relevant target state.

Thus previously sufficient evidence may cease to apply and cause lifecycle regression, for example:

```text
integration_ready -- base changed --> evaluating
integration_ready -- candidate-bound approval stale --> awaiting_input
```

where fresh approval is the only missing condition in the second case.

Human approval is evidence, not a direct lifecycle command. It MUST be authenticated, authorized, subject-bound, candidate/context-bound where applicable, policy-applicable, provenance-valid, and admitted through the evidence boundary.

---

## 19. Policy, authorization, and contract changes

Task control binds the active-policy identity under which its current trusted evaluation occurred.

If active policy changes, previous lifecycle state, authorization, risk evaluation, candidate evidence, and other policy-sensitive conclusions MUST be re-evaluated before consequential progression.

Authorization is revalidated before every consequential action requiring it. Revocation, expiry, scope reduction, or policy invalidation removes permission immediately even if canonical lifecycle reconciliation has not yet occurred; the task normally becomes `blocked` unless valid cancellation applies.

Security-relevant contract modification creates a new contract identity. Editing GitHub issue prose does not modify the canonical contract. Previous lifecycle posture and evidence MUST NOT silently transfer to a replacement contract identity.

---

## 20. Risk, human approval, and semantic review

`supervised` is a risk property, not a lifecycle state. Routine and supervised tasks use the same seven-state machine.

A supervised task may move from `evaluating` to `awaiting_input` when exact human approval is the remaining prerequisite.

After applicable approval is admitted, fresh trusted evaluation computes the resulting state from all remaining structured requirements. Depending on the task, that state may be:

```text
evaluating
integration_ready
completed
```

If valid approval already exists, the intermediate waiting state need not occur.

Human approval does not itself command one of those states.

Semantic-review outcomes likewise do not map one-to-one to lifecycle states:

| Verdict | Typical consequence |
|---|---|
| `approved` | Remain `evaluating` while other requirements remain; advance to `integration_ready` when one exact protected integration action is next; or advance to `completed` when the §32 completion predicate is fully satisfied and no further protected integration action is required. |
| `changes_required` | Remain `evaluating` if bounded repair/reimplementation remains authorized; otherwise `blocked`. |
| `unable_to_determine` | Remain `evaluating`, enter `awaiting_input`, or enter `blocked`, depending on the missing basis. |

An admitted semantic verdict is only one evidence input to trusted control.

The semantic reviewer never chooses canonical lifecycle state, cannot declare the task complete, and cannot override a deterministic failure or another unsatisfied mandatory evaluator.

---

## 21. GitHub and external authoritative state

GitHub issues, labels, comments, and pull-request prose are not the canonical lifecycle unless active trusted policy explicitly designates a particular structured mechanism as authoritative.

Therefore issue open/closed state, convenience labels, or comments such as “approved” MUST NOT silently create task state or authority. Labels MAY mirror canonical state for human convenience.

A GitHub PR reporting `merged` is authoritative repository state, but is not proof that the control plane authorized the merge. An unexpected external merge requires reconciliation and normally causes `blocked` unless active policy defines an authorized reconciliation path. Unauthorized historical action is not retroactively legitimized merely because the resulting content is acceptable.

External changes such as base advancement, candidate-ref mutation, PR closure, ruleset/workflow/platform changes, or target deletion trigger applicability reevaluation rather than authorization.

---

## 22. Canonical operation records

Not every work-plane activity belongs in trusted canonical state.

A canonical operation record is required for an externally or operationally distinct security-relevant invocation/effect where identity is needed for protected-effect tracking, provenance, idempotency, bounded repair/retry consumption, or reconciliation.

Typical examples include target publication, controlled runtime, merge, repair attempt, security-relevant validation invocation, or semantic-review invocation where exact provenance is required.

Ordinary planning, local coding, prompt construction, context preparation, or convenience orchestration need not become canonical trusted operations unless another trusted requirement makes them security-relevant.

Canonical operation records are not recursively required merely because the Control-State Gate records canonical state; §15 governs those writes directly.

---

## 23. Operation identity and revisions

Every canonical operation represents one intended exact invocation or protected effect and binds, where applicable:

```text
operation identity
task identity
action type and exact subject
candidate/context identity
contract identity
authorization identity
active-policy identity
target identity
expected authoritative state
idempotency identity
```

Changing an identity-bearing component creates a new operation identity. An existing operation record MUST NOT be repurposed for a materially different attempt.

Each canonical operation has its own monotonic revision. Every safety-relevant operation update binds to the exact expected prior operation revision. A stale write yields revision conflict and requires reread; it MUST NOT automatically change the operation lifecycle to `conflict`.

---

## 24. Operation conflict versus revision conflict

The two concepts are distinct:

- **revision conflict**: the attempted canonical record write used a stale expected revision; no operation-outcome conclusion follows;
- operation state **`conflict`**: an action-specific authoritative precondition failed before the protected invocation/effect crossed its side-effect boundary.

For example, an expected PR head mismatch before merge may produce operation `conflict`; concurrent reconciliation having already updated the operation record produces revision conflict instead.

---

## 25. Operation granularity and lifecycle

A canonical consequential operation MUST represent one atomic or independently reconcilable protected invocation/effect. Composite workflows SHOULD use separate operations unless the underlying platform supplies one truly atomic, safely reconcilable primitive.

For one operation identity, the lifecycle is:

| State | Meaning |
|---|---|
| `reserved` | Stable operation identity and exact intended invocation/effect are recorded; no reusable authority is created. |
| `performing` | The operation-start linearization point succeeded; the protected invocation/effect may now begin. |
| `succeeded` | The exact invocation/effect was carried out and the required operation-level postcondition was reconciled. |
| `failed` | Trusted reconciliation establishes that the intended invocation/effect did not complete as required and no unresolved protected effect remains. |
| `conflict` | An action-specific authoritative precondition failed before protected execution began. |
| `indeterminate` | It cannot be established whether the protected effect occurred or whether unresolved partial effects remain. |

For one operation identity, `succeeded`, `failed`, and `conflict` are terminal. A new attempt after `failed` or `conflict` requires a new operation identity and fresh validation.

`indeterminate` may remain `indeterminate` or reconcile to `succeeded`/`failed`; unresolved partial effects remain `indeterminate`.

---

## 26. Operation outcome is not evidence verdict

Operation lifecycle describes whether the exact invocation/effect was carried out and reconciled, not whether evidence produced by it was favourable.

For example:

```text
validation operation = succeeded
validation evidence = tests failed

semantic-review operation = succeeded
review verdict = changes_required
```

are valid combinations.

`operation.succeeded` MUST NOT imply tests passed, semantic approval, acceptance satisfaction, or candidate approval. Evidence produced by an operation enters through Evidence Admission and is evaluated separately.

---

## 27. Operation-start linearization point

`reserved → performing` is the linearization point at which a protected operation becomes permitted to cross its external side-effect boundary.

Immediately before this transition, all required policy, authorization, evidence, identity, candidate/context, and current authoritative-state requirements MUST be freshly valid.

The operation start MUST be bound to every **authoritative state element whose continued value is required for the operation to remain permitted**, using an atomic, conditional, or equivalent trusted precondition. If the required binding cannot be established, the operation MUST NOT enter `performing`.

Only after `performing` is durably established may the protected external effect begin. The system MUST NOT perform the external effect first and record `performing` afterward.

---

## 28. Cross-record atomicity and races

Task and operation records may have independent revision identities, but safety invariants spanning them MUST be enforced by one atomic Control-State Gate transaction or an equivalent common authoritative-state conditional update.

For example, starting a candidate-bound merge may require simultaneously establishing:

```text
task_revision == R20
operation_revision == O3
current_candidate == C17
cancellation_requested == false
required policy/authorization/current target state still applies
```

before `M42` becomes `performing`.

This creates deterministic ordering for races:

- if cancellation becomes authoritative first, a later operation start requiring the previous state fails;
- if the operation start linearizes first, cancellation treats it as in flight and waits for reconciliation;
- if candidate retirement/replacement wins first, an operation bound to the old candidate cannot start;
- if the old-candidate operation starts first, detachment waits for reconciliation.

Independent stale reads followed by unrelated writes MUST NOT allow both competing protected actions to succeed.

---

## 29. Idempotency

Consequential operations MUST use stable operation identities sufficient to distinguish replay from a new attempt.

Duplicate delivery of one operation identity MUST NOT silently consume another repair attempt, create duplicate publication/PR effects, repeat merge, or repeat controlled execution unless active trusted policy explicitly defines the effect as safely repeatable.

Existing external state counts as idempotent success only when exact identity proves that state is the intended result of the exact operation.

---

## 30. Crash recovery and reconciliation

A persisted `performing` operation MUST be reconciled after process loss, controller restart, lost response, timeout after a possible effect, or other loss of execution certainty. `performing + restart` MUST NOT be interpreted as permission to retry.

If the exact intended postcondition is proven, the operation becomes `succeeded`. If authoritative evidence proves the protected effect did not occur or has been safely resolved as absent, it may become `failed`. Otherwise it becomes or remains `indeterminate`.

Dependent protected progression MUST fail closed while a required consequential operation remains unresolved.

Reconciliation is also required after unexpected external mutations or divergence relevant to a protected decision. It may change canonical task/operation records only through the deterministic controller and Control-State Gate and does not retroactively authorize an unauthorized historical action.

After restart, the trusted working view is reconstructed from canonical task/operation records, active policy, current authoritative GitHub/platform state, immutable candidates, and admitted evidence. Worker assertions alone are insufficient.

---

## 31. Operation and task interaction

Operation outcomes and task lifecycle are separate.

For example:

```text
merge M42: performing@O4 → succeeded@O5
```

may support a later trusted task revision:

```text
integration_ready@R30 → completed@R31
```

but the operation result MUST NOT directly mutate task state outside the ordinary deterministic controller + Control-State Gate revision path.

Likewise, later task blocking or cancellation does not rewrite historical operation outcomes.

---

## 32. Completion integrity

`completed` means that the task's **trusted structured completion predicate** has been freshly established.

For an ordinary task, completion requires all of the following:

1. **Contract acceptance is satisfied.**  
   Every applicable `acceptance_requirement` in the admitted contract is satisfied under its complete required evaluator set and the contract's structured acceptance-composition rules.

2. **Additional trusted completion conditions are satisfied.**  
   Every additional completion condition imposed by applicable active trusted policy, Target Registration, or another structured completion-rule source explicitly designated by active trusted policy is satisfied.

3. **Required protected effects are established.**  
   Every protected operation whose successful outcome is explicitly required by an applicable trusted structured completion condition has been performed through its normal protected-operation path and reconciled to the required outcome.

4. **No unresolved relevant protected effect remains.**  
   There is no relevant `performing` or `indeterminate` protected operation whose unresolved outcome could invalidate completion or leave an unaccounted protected effect.

5. **Current applicability and authority remain valid.**  
   Applicable contract, authorization, active-policy, target-registration, candidate/context, evidence, and authoritative-state conditions required for completion remain current and valid. Authorization continues to determine whether required operations and completion-related consequential actions are permitted; it does not independently invent completion obligations unless active trusted policy explicitly designates a particular structured authorization rule as a completion-rule source.

6. **Cancellation permits completion.**  
   No authoritative cancellation condition under §11 is in effect. A pending or proposed cancellation condition that is relevant under active policy MUST be resolved before completion. Once cancellation has become authoritative under §11, the task MUST follow the cancellation/reconciliation path and MUST NOT transition to `completed`.

The set of sources permitted to impose completion requirements is closed by trusted policy.

A structured record does not become completion-authoritative merely because it is machine-readable or trusted for some other purpose.

In particular:

```text
objective prose
≠ completion predicate
```

```text
operation listed in requested_operations
≠ operation required for completion
```

and:

```text
valid authorization
≠ independent completion specification
```

`requested_operations` is a contract allowlist/ceiling. Presence of `merge`, `target_publish`, `controlled_runtime`, or another operation permits consideration of that operation within the contract; it does not by itself require the operation to occur before completion.

If publication, merge, controlled runtime, external observation, human approval, or another condition is mandatory for completion, that requirement MUST arise from one of the following recognized structured sources:

```text
an applicable contract acceptance requirement
and evaluator binding

active trusted policy

Target Registration

another structured completion-rule source
explicitly designated by active trusted policy
```

Authorization must separately permit any consequential operation needed to satisfy those requirements.

Trusted code MUST NOT recover a missing completion requirement by parsing:

```text
contract objective
issue prose
PR text
comments
labels
reviewer rationale
authorization prose
or other free-form text
```

Nor may an implementation treat an arbitrary structured field as completion-authoritative merely because it appears in a trusted record.

### 32.1 Completion after protected integration

Where one or more recognized trusted structured completion conditions require protected integration actions, those actions follow their normal operation lifecycle and the task normally reaches `integration_ready` for each exact next protected integration action.

Successful operation execution alone is insufficient.

After the required effect succeeds, trusted control MUST freshly establish the complete §32 completion predicate before writing `completed`.

### 32.2 Direct completion without protected integration

Where the complete trusted structured completion predicate is satisfied, no further protected integration action is required, and no authoritative cancellation condition under §11 is in effect, a task MAY transition directly to `completed` from:

```text
admitted
evaluating
awaiting_input
blocked
```

according to §13.

The prior state does not itself establish completion.

In particular:

- `admitted → completed` is appropriate only where the completion predicate does not require a current candidate or further protected integration;
- `evaluating → completed` may apply where the exact current candidate has satisfied all mandatory requirements but publication, merge, deployment, or equivalent integration is not required;
- `awaiting_input → completed` requires the identified external/human input to have been validly admitted and every completion condition to be freshly satisfied;
- `blocked → completed` requires fresh proof that the former blocking condition no longer applies as well as independent proof that the complete completion predicate is satisfied.

The controller MUST NOT route a task through `integration_ready` merely to manufacture a predecessor state for completion.

Completion MUST NOT be inferred merely from:

```text
worker success
semantic approval
tests passing
PR creation
PR merge flag
issue closure
agent assertion
operation.succeeded
absence of remaining planned work
objective wording
presence of an operation in requested_operations
authorization existence
```

without the complete trusted structured completion predicate being established.

---

## 33. Root-path exclusion

This state machine defines the lifecycle of **ordinary autonomously controlled tasks**.

It does not define the lifecycle, admission, readiness, activation, release, rollback, recovery, or external migration of a root change.

A separately authorized ordinary task MAY coexist with a root-change effort only where the ordinary task's exact target and scope are independently proven disjoint from root-protected material under the previously active trusted boundary.

An ordinary task MUST NOT become a mechanism for tracking or authorizing the root-impacting modification itself when ordinary admission should have rejected that scope.

The following ordinary records do not substitute for root records:

```text
task state
task revision
operation record
candidate record
ordinary contract
ordinary authorization
semantic verdict
integration result
```

In particular, they do not substitute for applicable root-path constructs such as:

```text
Root Change Package
External Root Authority approval
externally protected transition state
Root Activation Readiness Record
Release Verification Record
Root Activation
```

No ordinary task state, task revision, operation outcome, candidate record, semantic verdict, source-control milestone, or ordinary integration result grants `root_activation`.

Root modification and policy-epoch transition are governed exclusively by `SELF_MODIFICATION.md` and the active predecessor/root authority defined there.

---

## 34. Non-authoritative projections and extensions

Implementation MAY maintain convenience labels, dashboards, internal orchestration statuses, or other projections.

Such mechanisms MUST NOT grant authority, replace canonical task/operation records, substitute for current authoritative state or admitted evidence, bypass atomic revision rules, weaken the seven-state lifecycle, bypass operation-start linearization/reconciliation, or circumvent cancellation/candidate-detachment rules.

Natural-language interpretation MUST NOT be used to infer security-relevant lifecycle or evaluator classification where structured control data is required.

---

## 35. Conformance invariants

An implementation conforms to this state machine only while all of the following remain true:

1. The canonical task lifecycle contains exactly `admitted`, `evaluating`, `awaiting_input`, `integration_ready`, `blocked`, `completed`, and `cancelled` unless deliberately revised.
2. Task state is machine-readable and never substitutes for action-time policy, authorization, current authoritative state, evidence, or exact identity validation.
3. Only the deterministic trusted controller decides canonical task/operation revisions; only the Control-State Gate persists them.
4. Initial task creation is create-if-absent; existing task and operation mutations bind exact expected prior revisions.
5. Same-state safety-relevant task changes receive the same concurrency protection as lifecycle transitions.
6. Canonical control-state writes remain consequential but do not recursively require operation records merely to record themselves.
7. Candidate records are immutable; historical candidates are preserved; replacement/repair does not inherit candidate-bound evidence by default.
8. Candidate retirement/replacement cannot detach a candidate while an unresolved candidate-bound consequential effect makes detachment unsafe.
9. Evidence records are immutable and applicability is recomputed against current context.
10. `supervised` remains a risk property rather than a lifecycle state; human approval remains evidence rather than a direct state command.
11. `awaiting_input` applies only to identified admissible non-autonomous prerequisites; an independent blocker takes precedence.
12. Deterministic failure cannot be overridden by semantic approval.
13. Repair/retry consumption is bounded by active trusted policy, concurrency-safe, idempotent, and creates a new candidate on repair.
14. `integration_ready` binds one exact next protected integration action and is never bearer authority or a mandatory waypoint for a task whose complete trusted structured completion predicate requires no further protected integration action.
15. Cancellation prevents later protected progression from starting and terminal cancellation requires relevant in-flight effects to be reconciled.
16. Canonical operations are used only where security, provenance, bounded-attempt identity, idempotency, or reconciliation requires them.
17. Every canonical operation has immutable exact-action identity and its own revision discipline.
18. Revision conflict and operation-state `conflict` remain distinct.
19. Each protected operation represents one atomic or independently reconcilable effect/invocation.
20. `reserved → performing` is the operation-start linearization point, and `performing` is durably established before the protected external effect begins.
21. Operation start is atomically/conditionally bound to every authoritative state element whose continued value is required for permission.
22. Cross-record invariants prevent cancellation, candidate detachment, and protected-operation start from independently succeeding from stale observations.
23. Operation execution outcome remains distinct from evidence/acceptance verdict.
24. `succeeded`, `failed`, and operation `conflict` are terminal for one operation identity; uncertain or partial protected effects remain `indeterminate` until reconciled.
25. Duplicate/replayed operation identities do not silently duplicate protected effects or consume additional bounded allowance.
26. Recovered `performing` operations are reconciled before retry or dependent protected progression.
27. Operation outcomes do not bypass normal task revision rules.
28. External GitHub/platform changes cause reevaluation, not authorization; unexpected external merge is not retroactively blessed.
29. `completed` requires the complete trusted structured completion predicate in §32. Completion requirements may originate only from the admitted contract's structured acceptance requirements, active trusted policy, Target Registration, or another structured completion-rule source explicitly designated by active trusted policy. Contract objective prose, mere presence of an operation in `requested_operations`, and authorization existence do not independently establish completion requirements. Where protected integration is structurally required, applicable protected-operation outcomes must first be established; where no further protected integration action is required, a task may complete directly from `admitted`, `evaluating`, `awaiting_input`, or freshly resolved `blocked` according to §13 and §32. Once cancellation becomes authoritative under §11, `completed` is no longer reachable. `completed` and `cancelled` are terminal.
30. Recovery from `blocked` recomputes current posture instead of restoring historical state.
31. Active-policy, authorization, or contract identity changes trigger applicability reevaluation before consequential progression.
32. The ordinary task lifecycle does not grant, represent, or substitute for root-change authority or the separately controlled root-transition records defined by `SELF_MODIFICATION.md`.
33. Failure to establish any required identity, authority, evidence, current-state binding, atomic precondition, or reconciliation result fails closed.

---

## 36. Phase 0 implementation boundary

This document defines lifecycle semantics and invariants only.

It does not implement a worker, reviewer, repair loop, GitHub Actions workflow, GitHub App, controlled-runtime executor, storage transaction mechanism, or target-repository adapter.

Phase 1 implementation MUST realize these semantics without inferring authoritative machine state or completion requirements from natural-language issue prose and without importing v1 workflow mechanics by default.
