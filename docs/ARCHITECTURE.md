# Autonomous Development v2 — Architecture

**Status:** Phase 0 frozen  
**Version:** 1.2  
**Repository:** `RayZhang2024/autonomous-dev-control-plane`  
**Governing policy:** `docs/CORE_POLICY.md` v1.0

## 1. Purpose

This document defines the architecture of Autonomous Development v2.

Its purpose is to make the invariants in `CORE_POLICY.md` enforceable using the smallest practical trusted system.

The architecture separates:

- semantic reasoning from authority enforcement;
- planning from authorization;
- implementation from candidate materialization;
- candidate materialization from target publication;
- review from merge;
- ordinary execution from controlled execution;
- mutable control state from natural-language collaboration;
- active trusted policy from candidate policy;
- repository-specific behaviour from generic control-plane policy;
- operational risk from technical capability.

This document MUST be interpreted under the active `CORE_POLICY.md`.

---

## 2. Architectural objective

The central design objective is:

> **Fallible or untrusted components may propose work, candidate content, reviews, evidence, or consequential actions, but only a small deterministic trusted boundary may establish whether those actions are permitted, and only protected capability gates may perform them.**

GPT, Codex, semantic-review LLMs, target repositories, candidate code, candidate tests, target adapters, and general orchestration remain outside the minimal trusted core.

They may influence protected decisions only through structured inputs, authenticated authority, authoritative state, and provenance-bound evidence.

---

## 3. System planes

Autonomous Development v2 consists of three logical planes.

### 3.1 Work plane

The work plane performs reasoning and software-development work.

It includes:

- GPT planning;
- task decomposition;
- authorization proposals;
- Codex implementation;
- repair reasoning;
- semantic-review LLMs;
- review-context preparation;
- target-repository adapters;
- ordinary development environments;
- repository-specific tooling.

Work-plane components are treated as fallible and potentially compromised.

They MUST NOT independently possess sufficient authority to cross protected trust boundaries.

### 3.2 Control plane

The control plane determines whether protected operations are permitted.

It contains:

- active-policy resolution;
- authoritative-state acquisition;
- deterministic policy evaluation;
- authorization admission;
- delegation validation;
- target-registration validation;
- contract validation;
- exact identity validation;
- evidence admission and validation;
- lifecycle enforcement;
- protected publication control;
- merge control;
- controlled-runtime control;
- canonical control-state management;
- audit generation.

### 3.3 Root plane

The root plane governs activation or replacement of:

- trusted-core code;
- active Core Policy;
- trusted schemas where designated;
- trusted enforcement configuration;
- trusted-core membership;
- root activation rules.

The root plane is outside ordinary autonomous-development authority.

---

## 4. High-level architecture

```text
                  HUMAN / AUTHORIZED ROOT
                           │
                  explicit / delegated
                       authority
                           │
                           ▼
                     GPT PLANNER
                      untrusted
                           │
                     proposals only
                           ▼
                    ORCHESTRATOR
                      untrusted
                           │
                  structured requests
                           ▼
              ┌──────────────────────────┐
              │ DETERMINISTIC TRUSTED    │
              │ CONTROLLER               │
              │                          │
              │ active policy            │
              │ authorization            │
              │ delegation               │
              │ target registration      │
              │ authoritative state      │
              │ identity                 │
              │ evidence                 │
              │ lifecycle                │
              │ risk                     │
              │ scope                    │
              └────────────┬─────────────┘
                           │
                  ALLOW / DENY /
                     ESCALATE
                           │
          ┌────────────────┼─────────────────┐
          ▼                ▼                 ▼
   CONTROL-STATE       TARGET-           MERGE
       GATE          PUBLICATION          GATE
                         GATE
          │                │                 │
          └──────────── GitHub ──────────────┘

            candidate materialization:
               non-publishing path

             separately when needed:
               CONTROLLED RUNTIME

             separately protected:
                ROOT ACTIVATION
```

No ordinary agent owns an independent path around these boundaries.

---

## 5. Trusted Computing Base

The architecture distinguishes the **minimal trusted core** from the broader **Trusted Computing Base (TCB)**.

The TCB comprises components and external trust dependencies whose correct behaviour is relied upon to preserve the control plane's authority and safety guarantees.

### 5.1 Minimal custom trusted core

The custom trusted core SHOULD primarily contain deterministic decision logic.

Its responsibilities include:

- identifying the active trusted policy;
- validating structured contracts;
- validating authenticated authorization;
- validating delegation and non-amplification;
- validating registered target configuration;
- verifying repository/task/PR/ref/SHA identities;
- verifying candidate scope;
- validating evidence identity, provenance, and applicability;
- validating lifecycle transitions;
- validating repair/retry limits;
- enforcing risk and escalation rules;
- evaluating consequential-action preconditions;
- producing structured decisions.

Its preferred form is:

```text
trusted structured inputs
          ↓
deterministic evaluation
          ↓
ALLOW | DENY | ESCALATE
          +
structured reason codes
          +
exact action context
```

The trusted core MUST NOT:

- implement application code;
- repair candidate code;
- perform semantic review;
- infer security classification from prose;
- contain general planning logic;
- contain target-specific business logic;
- execute arbitrary candidate-controlled commands;
- autonomously activate its replacement.

---

## 6. Logical security boundaries and deployment boundaries

A **logical security boundary** separates authorities that MUST not collapse into one another.

A **deployment boundary** determines which code runs in a particular process, service, container, account, or machine.

These are different concepts.

Logical capabilities MAY share:

- a codebase;
- reusable deterministic libraries;
- a deployment package;
- a physical host;

provided the required security boundaries remain technically enforceable.

Capabilities whose credentials or protected authority must remain mutually inaccessible MUST execute in separate security contexts or use an equivalent technically enforced credential boundary.

Ordinary modules in one unrestricted process MUST NOT be treated as mutually isolated merely because they are assigned different logical roles.

Physical microservice separation is not required unless needed to enforce the security boundary.

---

## 7. Trusted gates and generic mutation rule

Consequential state-changing operations are performed through narrowly scoped trusted gates.

A gate:

1. receives a structured requested operation;
2. establishes authenticated authority;
3. resolves the applicable active-policy identity;
4. acquires or revalidates current authoritative state;
5. obtains a deterministic trusted-core decision for the exact operation;
6. performs only its assigned capability;
7. verifies the intended postcondition where applicable;
8. emits structured audit evidence.

A gate MUST NOT reinterpret `DENY` or `ESCALATE` as permission.

### 7.1 Atomic state binding

If authorization of a consequential mutation depends on authoritative state observed before the mutation, the gate MUST bind the mutation to that required state through an atomic, conditional, compare-and-swap, or equivalent platform-enforced precondition.

A prior read followed by an unconditional mutation is insufficient when intervening change could invalidate the decision.

If the required binding cannot be established, the mutation MUST NOT occur.

This rule applies generically to protected mutations, including where relevant:

- canonical control-state updates;
- target publication;
- merge;
- authorization changes;
- target-registration changes;
- root activation.

---

## 8. Capability identity separation

Security-critical authority boundaries MUST be reflected in technically enforceable identities and credentials.

Separate tokens belonging to one broadly privileged platform identity are insufficient where compromise of that identity could bypass the intended separation.

For GitHub, materially different protected capabilities SHOULD use distinct narrowly permissioned GitHub App or service identities where GitHub itself must enforce their separation.

The minimum expected Phase 1 GitHub capability identities are:

```text
1. control-state identity
2. target-publication identity
3. merge identity
```

Candidate materialization SHOULD NOT require the target-publication credential.

Controlled-runtime identity is introduced when controlled execution is implemented.

Target-registration changes SHOULD initially be explicit human administrative actions.

Root activation SHOULD initially remain manual or otherwise out-of-band.

A universal GitHub App with broad bypass authority SHOULD NOT be used merely for convenience.

---

## 9. Authorization admission

A structured task contract is not automatically an authorization.

Before a task becomes autonomously executable, authority for that task MUST be admitted through the trusted control plane.

Initial authorization origins are:

- direct authenticated human authorization;
- bounded delegation from an already authorized parent task, programme, or authority.

The trusted core evaluates conceptually:

```text
issuer identity
+
issuer authority
+
parent authorization where applicable
+
delegable capability
+
delegable scope
+
risk ceiling
+
target
+
proposed child authorization
+
active-policy identity
```

and returns:

```text
ADMIT
DENY
ESCALATE
```

GPT MAY formulate an authorization proposal.

Producing a proposal does not create authority.

---

## 10. Admitted authorization record

A successfully admitted authorization MUST produce canonical structured control state.

The authorization record binds conceptually:

```text
authorization identity
issuer identity
parent authorization identity where applicable
authorization ancestry
task / contract identity
target registration identity
authorized scope
authorized protected capabilities
risk constraints
delegation constraints
validity conditions
active-policy identity under which it was admitted
admission event identity
```

Authorization evaluated or admitted under one active-policy identity MUST NOT silently remain applicable under another policy identity.

After policy activation changes, continued applicability must be re-established according to the active Core Policy.

---

## 11. Authority delegation

Delegated authority MUST remain within the authority that its source is permitted to delegate.

Conceptually:

```text
ChildAuthority
      ⊆
DelegableAuthority(Parent)
```

Delegation validation may constrain:

- target repository;
- file/resource scope;
- permitted protected operations;
- operational capability;
- risk ceiling;
- runtime permission;
- further delegation;
- validity period or conditions.

A parent authorization MAY prohibit further delegation.

No autonomous delegation chain may manufacture authority absent from its authorized ancestry.

---

## 12. Target registration

The control plane MUST NOT operate autonomously on an arbitrary repository merely because an agent names it.

Every autonomous target repository MUST have an approved **Target Registration Manifest**.

The manifest establishes trusted repository-specific control configuration without moving target-specific reasoning into the generic trusted core.

It identifies conceptually:

```text
repository immutable identity
repository display name

protected target refs
permitted publication mechanisms

target-publication identity
merge identity

ordinary validation profiles
controlled-runtime profiles

event-sensitive target-state definitions
runner classifications
secret/resource constraints

target-specific protected resources

risk constraints

adapter identity/configuration
```

The exact schema is deferred.

An unregistered repository is not an authorized autonomous target.

---

## 13. Stable target configuration and event-sensitive target state

Target registration MUST distinguish trusted configuration from current mutable facts whose value may alter the consequences of an operation.

### 13.1 Stable trusted target configuration

Examples include:

```text
repository immutable identity
approved service identities
protected refs
permitted publication mechanisms
permitted runner classes
registered runtime profiles
risk constraints
```

Changing these requires an authorized target-registration update.

### 13.2 Event-sensitive target state

Event-sensitive target state includes any mutable target fact whose current value can change the effect or safety of:

- candidate publication;
- validation;
- execution;
- merge;
- deployment or other protected action.

It may include two broad categories.

**Versioned repository state**, for example:

```text
workflow definitions
action configuration
deployment files
validation configuration
runner-selection configuration
repository automation definitions
```

**Mutable platform state**, for example:

```text
relevant rulesets or protections
Actions settings
runner configuration
environment protection
installed integration configuration
other platform settings on which safety depends
```

Target Registration defines **which facts are security-relevant**.

The State Reader determines **their current authoritative values**.

Previously observed event-sensitive state MUST NOT override fresher authoritative state.

---

## 14. Target-registration authority

Creating or materially broadening a Target Registration Manifest is a consequential administrative action.

Ordinary implementation authority MUST NOT permit an actor to:

- register a new target;
- broaden publication authority;
- designate a new merge actor;
- weaken runtime protection;
- alter event-sensitive-state requirements;
- increase its own capability.

Target registration requires authenticated authority permitted by active policy.

Changes affecting the trusted-core or root-of-trust boundary follow the root path.

---

## 15. GitHub authoritative state

GitHub is authoritative for mutable repository and control-plane state explicitly designated by the architecture.

Examples include:

- repository identity;
- Git refs;
- commit identity;
- pull-request identity;
- PR head;
- target ref;
- merge state;
- issue identity;
- relevant platform configuration;
- canonical control-state Git objects where GitHub is the state platform.

GitHub-hosted text is not authoritative merely because GitHub stores it.

Issue prose, PR descriptions, comments, arbitrary labels, code comments, logs, and generated claims are non-authoritative unless explicitly admitted through a trusted structured mechanism.

---

## 16. Canonical control-state store

Security-relevant lifecycle state MUST NOT be reconstructed from natural-language comments or accumulated label conventions.

The architecture uses a canonical machine-readable **Control-State Store** containing conceptually:

```text
task contract identity
authorization identity
authorization ancestry
authorization active-policy identity
target registration identity
risk classification
lifecycle state
candidate identities
evidence identities
repair/retry state
operation/idempotency state
audit/event references
```

### 16.1 Preferred storage boundary

The preferred architecture uses a separate protected private GitHub repository for canonical operational state.

Conceptually:

```text
autonomous-dev-control-plane
    source
    policy
    schemas

control-state repository
    registrations
    contracts
    authorizations
    lifecycle state
    evidence indexes
    operation state
    event records
```

The exact repository name is not fixed here.

Phase 0 defines this boundary but does not require creation of the state repository.

A same-repository protected ref MAY be used only if equivalent authority isolation can be demonstrated.

---

## 17. Control-State Gate

Only the designated Control-State Gate performs ordinary canonical state mutations.

It may record:

- admitted contracts;
- admitted authorization;
- authorization ancestry;
- lifecycle transitions;
- candidate identities;
- evidence references;
- repair state;
- idempotency/operation state;
- terminal outcomes.

It MUST NOT:

- implement candidate code;
- publish target refs;
- merge target branches;
- invoke controlled runtime;
- activate trusted-core replacements.

All safety-relevant control-state writes are subject to the generic atomic-state-binding rule.

---

## 18. Issue contract

A GitHub issue provides human context and discussion.

It is not itself the autonomous execution contract.

An autonomously executable ordinary task has a canonical structured issue contract describing conceptually:

```text
identity
objective
target registration identity
contract-bounded requested scope
prohibited scope
requested operations
base constraints
risk
acceptance requirements
evaluation requirements
runtime requirements
repair policy
human-approval requirements
delegation limits
```

The exact format belongs in `schemas/issue-contract.schema.json`.

Contract scope is a requested-work ceiling only. It does not establish authorization, authoritative risk, lifecycle state, evaluator authority, publication permission, controlled-runtime permission, merge authority, or root authority.

Contract validity does not establish authority.

Authorization admission is a separate operation.

---

## 19. Acceptance evaluation

Acceptance requirements explicitly identify their required evaluator mechanisms.

Initial evaluator classes are:

```text
deterministic
semantic
controlled_runtime
external_observation
human_approval
```

A requirement MAY require more than one evaluator.

The control plane MUST NOT infer evaluator class from the natural-language statement.

---

## 20. Evidence Admission

Security-relevant evidence is accepted only through a deterministic **Evidence Admission** boundary.

Evidence Admission validates evidence and produces an admitted evidence record. Persistence of that record, or of a canonical reference to it, occurs only through the Control-State Gate.

Evidence Admission evaluates conceptually:

```text
evidence type
evidence issuer
issuer authorization where required
task identity
contract identity
candidate context where applicable
active-policy identity
target identity
execution/review identity
schema validity
provenance
freshness
applicability
```

and returns:

```text
ADMIT
DENY
ESCALATE
```

Evidence Admission supports evidence sources including:

- deterministic validation;
- semantic review;
- controlled runtime;
- external observation;
- human approval.

Raw comments, logs, agent assertions, or uploaded artifacts do not become canonical security-relevant evidence merely by existing.

Evidence is evidence only; admission does not itself create authorization.

---

## 21. Risk model

Risk and operational capability are separate dimensions.

The initial ordinary risk tiers are:

```text
routine
supervised
```

### 21.1 Routine

A routine task may progress autonomously when all applicable policy, authorization, state, identity, evidence, and lifecycle requirements are satisfied.

### 21.2 Supervised

A supervised task may use autonomous:

- planning;
- implementation;
- candidate materialization;
- ordinary validation;
- semantic review;
- bounded repair.

The active trusted risk policy, represented through trusted policy or enforcement configuration identified by the Active Trusted Manifest, defines the **minimum protected integration boundary** requiring human approval for supervised work.

A Target Registration Manifest or admitted task contract MAY require earlier or additional approval.

They MUST NOT weaken the minimum human-approval requirement established by trusted risk policy.

### 21.3 Risk authority

GPT or another planner MAY propose risk.

The proposal is not authoritative unless the actor possesses explicit authority to establish risk.

Authoritative risk is recorded through admitted trusted control state.

Missing or unauthorized risk classification fails closed.

### 21.4 Trusted-core impact

Trusted-core impact is not another ordinary risk tier.

Such changes follow the root-change path.

---

## 22. Work-plane requests versus protected capabilities

The architecture distinguishes **work-plane requests** from **protected capabilities**.

### 22.1 Work-plane requests

Examples include:

```text
planning request
authorization proposal
implementation request
review request
repair request
ordinary analysis request
```

Submitting such a request does not itself grant authority.

### 22.2 Protected capabilities

Initial protected capabilities include:

```text
control_state_write
target_publish
merge
controlled_runtime
target_registration
root_activation
```

Candidate materialization becomes a protected capability only if the chosen implementation mutates shared or protected state.

A purely local or otherwise isolated non-publishing materialization step need not carry target-publication authority.

Possession of one protected capability does not imply another.

---

## 23. Active Trusted Manifest

Repository `main` is not automatically equivalent to the active trusted policy/core.

The architecture uses an **Active Trusted Manifest** identifying immutable versions of:

```text
CORE_POLICY
trusted-core implementation
trusted schemas
trusted enforcement configuration
trusted-core membership
manifest version
```

A separately protected active pointer identifies the currently authoritative manifest.

A repository commit may contain a candidate manifest without activating it.

Changing the active pointer is a root consequential action.

The physical trust anchor and activation procedure are defined further in `SELF_MODIFICATION.md`.

---

## 24. Trusted-core membership

Trusted-core membership is established by the previously active trusted boundary.

A candidate cannot escape root review by:

- renaming trusted functionality;
- deleting it from a proposed manifest;
- changing membership rules;
- claiming a security-critical component is no longer trusted.

The previously active trusted system determines whether a candidate affects the trusted boundary.

---

## 25. State Reader

A narrow State Reader obtains current authoritative target and GitHub facts.

It may retrieve:

```text
repository immutable identity
issue identity
PR identity
base ref
target ref
head ref
base SHA
head SHA
commit ancestry
changed-file inventory
merge state
control-state identity
event-sensitive repository identities
relevant mutable platform state
```

It performs deterministic normalization.

It MUST NOT infer:

- intent;
- semantic acceptance;
- risk from prose;
- authority from comments.

The platform connections and guarantees relied upon by the State Reader form part of the TCB or documented external trust dependencies.

---

## 26. Candidate generation

Candidate generation occurs outside the trusted core.

The preferred flow is:

```text
admitted task
      ↓
exact authorized base
      ↓
isolated workspace
      ↓
Codex implementation
      ↓
candidate proposal
      ↓
candidate materialization
```

Codex SHOULD NOT possess general target-repository write authority.

---

## 27. Candidate proposal

The implementation worker returns a deterministic candidate proposal rather than directly publishing target-repository mutations.

The proposal may contain:

```text
exact base identity
file additions
file replacements
file deletions
file modes where relevant
declared changed paths
```

The precise representation is deferred.

The proposal is not authoritative repository state.

---

## 28. Candidate materialization

Candidate materialization creates an exact candidate representation and identity without granting target-publication authority.

The materialization path may:

1. validate proposal structure;
2. confirm the authorized base;
3. validate paths and object types;
4. derive or construct the resulting tree/commit;
5. verify resulting changed scope;
6. produce an immutable candidate identity.

It MUST NOT:

- interpret implementation intent;
- repair code semantically;
- broaden scope;
- decide unauthorized changes are necessary;
- publish target refs unless separately authorized as target publication.

### 28.1 Preferred non-eventing substrate

Candidate materialization SHOULD use a substrate that does not generate target-repository execution or publication events.

Possible implementations include:

```text
Git objects constructed without moving a target ref

or

an isolated staging repository/environment
with target Actions, secrets, privileged runners,
deployment hooks, and equivalent effects disabled
```

If a proposed materialization mechanism necessarily updates an event-bearing target ref, it MUST be treated as target publication rather than as isolated materialization.

---

## 29. Target publication

Target publication is a consequential mutation that makes candidate content visible through an event-bearing or authoritative target object such as a branch, tag, pull request, or equivalent platform construct.

Candidate materialization does not imply target-publication authority.

Before publication, the trusted core evaluates:

```text
candidate identity
authorization
authorized candidate scope valid
target registration
publication mechanism
current authoritative target state
current event-sensitive target state
risk requirements
required evidence
expected side effects
```

The Target-Publication Gate then performs the exact authorized publication subject to the generic atomic-state-binding rule.

---

## 30. Publication side effects

Target publication MUST NOT be presumed harmless.

It may trigger:

```text
GitHub Actions
external CI
webhooks
deployment automation
GitHub Apps
self-hosted runners
secret-bearing jobs
hardware-connected systems
other external integrations
```

The permitted effect model is established jointly by:

```text
Target Registration
+
current authoritative event-sensitive target state
```

If publication can trigger a capability requiring stronger authority than the publication request possesses, that publication path MUST NOT be used.

Unknown material side effects fail closed.

A special candidate namespace MUST NOT be treated as inherently inert unless the lack of protected side effects is established for the exact relevant state.

---

## 31. Deterministic validation

Deterministic validation has two broad categories.

### 31.1 Core validation

The trusted control plane validates security-relevant facts such as:

- contract structure;
- authorization;
- delegation;
- target registration;
- exact identity;
- ancestry;
- changed scope;
- transition eligibility;
- evidence provenance;
- repair bounds.

### 31.2 Repository validation

Target-specific validation may include:

- tests;
- builds;
- linters;
- static checks;
- integration checks.

Repository validation executes through registered validation profiles.

Candidate-provided commands or candidate-modified configuration MUST NOT automatically become trusted validation definitions.

Validation output becomes canonical security-relevant evidence only through Evidence Admission.

---

## 32. Review architecture

Semantic review is split between untrusted context preparation and trusted review binding.

### 32.1 Untrusted Context Assembler

The Context Assembler may:

- summarize repository context;
- provide explanatory documents;
- prepare design history;
- generate background;
- propose excerpts.

Its output remains untrusted supplemental context.

It MUST NOT decide that omitted changed material is security-irrelevant.

### 32.2 Trusted Review Envelope Builder

A deterministic component creates the canonical review envelope binding:

```text
repository identity
task/issue identity
contract identity
target registration identity
active-policy identity
base SHA
candidate SHA
complete changed-file inventory
canonical changed-content identities
exact semantic requirements
review invocation identity
review schema version
```

The trusted component binds material.

It does not make semantic judgments or intelligently curate away candidate content.

### 32.3 Coverage

The review package MUST make material coverage explicit.

If required material is unavailable or omitted such that a semantic judgment cannot be supported, the reviewer returns:

```text
unable_to_determine
```

rather than optimistic approval.

---

## 33. Semantic reviewer

The semantic LLM receives:

- the trusted review envelope;
- candidate material;
- optional untrusted supplemental context.

Initial verdict outcomes are:

```text
approved
changes_required
unable_to_determine
```

The verdict is not immediately authoritative evidence.

It must pass Evidence Admission, including provenance, identity, schema, candidate-context, and policy checks.

Semantic review cannot:

- grant task authority;
- override deterministic failure;
- expand scope;
- grant controlled-runtime permission;
- merge;
- activate trusted policy.

The exact verdict schema is defined in `schemas/review-verdict.schema.json`.

---

## 34. External observation and human approval

External observations and human approvals are explicit evidence classes.

They MUST enter the control plane through Evidence Admission.

An approval must be bound to the subject for which it is intended, including the exact candidate/context when candidate identity matters.

A natural-language comment such as:

```text
Looks good, approved.
```

does not become security-relevant human approval merely because it exists on GitHub.

The trusted architecture must establish authenticated issuer, authorized approval role, exact subject, and applicability.

---

## 35. Controlled runtime

Controlled execution is separate from ordinary validation, target publication, and merge.

A controlled-runtime request binds:

```text
task
authorization
target registration
candidate
runtime profile
authorized operation
resource/environment
required evidence
```

Only registered runtime profiles may be invoked.

The Controlled Runtime Gate MUST prevent candidate code from silently broadening:

- command authority;
- secret access;
- hardware access;
- external-system access;
- runtime resource limits.

Controlled-runtime results become security-relevant evidence only through Evidence Admission.

Successful execution does not grant merge authority.

---

## 36. Repair

Repair creates a new candidate.

```text
candidate N
     ↓
failure evidence
     ↓
repair eligibility
     ↓
repair worker
     ↓
candidate proposal
     ↓
materialization
     ↓
candidate N+1
     ↓
fresh required evidence
```

Candidate `N+1` does not inherit candidate-bound evidence from candidate `N`.

Repair authority and retry limits come from admitted trusted control state.

The repair worker cannot increase them.

---

## 37. Candidate context identity

A candidate SHA alone is not sufficient for every security-relevant decision.

Where evidence depends on the state against which a candidate is evaluated, the architecture uses an exact candidate context.

Conceptually:

```text
repository identity
+
task identity
+
candidate SHA
+
target ref identity
+
expected target/base SHA
+
PR identity where applicable
+
contract identity
+
authorization identity
+
active-policy identity
```

Required evidence binds to the portions of this context on which its validity depends.

---

## 38. Base movement

If evidence was established for:

```text
base = X
candidate = C
```

and the authoritative integration target changes to:

```text
base = Y
```

the earlier evidence MUST NOT silently authorize the new context.

The candidate must be:

- re-evaluated;
- reconstructed/rebased and re-evaluated;
- or shown through an explicitly permitted deterministic rule to remain valid.

The default is stale evidence.

---

## 39. Merge transaction

Merge is a protected consequential operation.

Before merge, the trusted controller establishes:

```text
active policy valid
authorization valid
target registration valid
contract valid
risk requirements satisfied
candidate context exact
current target state exact
required deterministic evidence valid
required semantic evidence valid
required runtime evidence valid
required human approval valid
scope valid
transition valid
root impact absent
```

The Merge Gate MUST bind the mutation atomically to every current authoritative state element on which safety depends.

A head-only condition is insufficient when evidence also depends on an expected base.

If the platform cannot provide a safe integration primitive for the required state binding, merge MUST be denied or use another approved integration mechanism.

---

## 40. State transitions

Lifecycle changes occur through structured transition requests.

A request identifies conceptually:

```text
task
current canonical state
requested state
candidate context where applicable
authorization
supporting evidence
active-policy identity
```

The trusted controller decides whether the transition is permitted.

Only the Control-State Gate publishes canonical lifecycle state.

Human-facing labels MAY mirror lifecycle state but are not authoritative unless explicitly designated through trusted policy.

Exact states and transition ownership belong in `STATE_MACHINE.md`.

---

## 41. Orchestrator

The orchestrator coordinates work but does not acquire protected authority through coordination.

It may:

- observe state;
- request GPT planning;
- submit authorization proposals;
- request implementation;
- request materialization;
- request publication;
- request validation;
- request semantic review;
- request repair;
- propose transitions;
- propose merge;
- retry safe/idempotent requests.

It MUST NOT independently possess credentials capable of:

- writing canonical state;
- publishing unauthorized target refs;
- merging;
- invoking controlled runtime;
- broadening target registration;
- activating trusted policy.

If compromised, its expected failure mode is invalid requests, wasted work, or denied actions—not unauthorized protected mutation.

---

## 42. Event and idempotency model

The architecture assumes events may be:

- duplicated;
- delayed;
- retried;
- reordered;
- observed after restart.

Consequential operations use stable operation identities where required for provenance, idempotency, bounded-attempt accounting, protected-effect tracking, or reconciliation.

The canonical protected-operation lifecycle is defined by `STATE_MACHINE.md` and contains:

```text
reserved
performing
succeeded
failed
conflict
indeterminate
```

This section does not define a second operation-state vocabulary.

Duplicate delivery of one operation identity MUST NOT silently create a second protected effect, consume an additional bounded attempt, or become a newly authorized operation.

A retry that represents a genuinely new authorized attempt requires a new operation identity where `STATE_MACHINE.md` requires one.

An existing external postcondition may be accepted as idempotently complete only when exact identity establishes that it is the intended result of the exact intended operation.

Superficially similar state is insufficient.

Uncertain protected effects require reconciliation according to `STATE_MACHINE.md`; uncertainty MUST NOT be interpreted as permission to repeat the operation.

---

## 43. Audit model

Consequential decisions and mutations produce structured audit events.

An event SHOULD bind where relevant:

```text
event identity
operation identity
actor/service identity
task
target registration
candidate context
active-policy identity
contract identity
authorization identity
supporting evidence identities
prior state
requested action
decision
result
timestamp
```

Audit records provide traceability.

They do not create authorization and do not replace current authoritative state.

---

## 44. Target-adapter boundary

Repository-specific adapters remain outside the trusted core.

Adapters may:

- inspect repository layout;
- prepare validation input;
- prepare semantic context;
- explain repository conventions;
- propose validation profiles;
- normalize non-authoritative metadata.

Adapters MUST NOT independently determine:

- authorization;
- authoritative risk;
- scope expansion;
- protected capability;
- merge permission;
- active policy;
- trusted-core membership;
- whether deterministic failure may be ignored.

Security-relevant target configuration becomes trusted only through authenticated approved structured configuration.

---

## 45. Root and self-modification path

Trusted-core, active-policy, trusted-enforcement, trusted-membership, and other root-protected changes follow the separate root-change path.

At architecture level, the transition is:

```text
active trusted system N
        ↓
candidate trusted system N+1
        ↓
validation governed by N
        ↓
independent semantic review
        ↓
authenticated external root approval
        ↓
External Root Authority closes transition barrier
        ↓
quiescence / reconciliation
        ↓
N-governed readiness H
        ↓
External Root Authority seals H
        ↓
active-manifest pointer N → N+1
while transition remains CLOSED
        ↓
establish or preserve independent
pre-release capability fencing
        ↓
stage / deploy exact N+1 trusted contexts
under that independent fence
        ↓
N-governed verification of:
    actual deployed/executing N+1 identities
    exact intended capability bindings
    effective pre-release capability fencing
        ↓
N-governed release verification V
        ↓
External Root Authority seals V
        ↓
fresh release-state verification
        ↓
External Root Authority releases barrier
        ↓
N+1 governs newly starting protected operations
```

The active-manifest pointer changing to `N+1` does **not** by itself complete the policy-epoch handover.

While the root transition remains closed:

```text
transition.from = N
```

continues to identify the trusted predecessor governing transition-completion rules.

Candidate `N+1` MUST NOT become the authoritative evaluator of whether its own transition is complete.

Candidate `N+1` MUST NOT be capable of producing a protected consequential effect while the transition is closed.

Any `N+1` trusted security context staged or executed before release MUST already be subject to an enforcement mechanism outside candidate `N+1` that independently prevents such protected effects.

Candidate compliance with the closed barrier is not itself sufficient enforcement.

Ordinary merge authority MUST NOT provide an alternate route around the root-change path.

Trusted-core source may exist, be committed, or be merged without thereby becoming the governing trusted system.

`SELF_MODIFICATION.md` defines the detailed root-transition protocol, including:

- External Root Authority;
- Root Trust Anchor;
- root-impact determination;
- predecessor-governed evaluation;
- readiness and readiness sealing;
- active-manifest pointer mutation;
- pre-release capability fencing;
- deployed-runtime verification;
- release verification and sealing;
- barrier release;
- pre-release rollback;
- recovery and external-root migration.

The architectural invariant is:

> **Candidate `N+1` becomes the normal governing policy for newly starting protected autonomous work only after the predecessor-governed root transition has successfully crossed the externally controlled release boundary.**

---

## 46. Phase 1 minimum deployment topology

Phase 1 SHOULD implement the smallest topology that preserves the required technical authority boundaries.

A suitable initial layout is:

```text
            UNTRUSTED WORK PROCESS
      GPT / Codex / reviewer / orchestration
                        │
                        ▼
               TRUSTED CONTROLLER
            ┌──────────────────────┐
            │ deterministic core   │
            │ active-policy loader │
            │ state reader         │
            │ auth admission       │
            │ evidence admission   │
            │ review envelope      │
            │ audit logic          │
            └──────────────────────┘
                  │      │      │
                  ▼      ▼      ▼
                IPC / protected interfaces
                  │      │      │
          ┌───────┘      │      └────────┐
          ▼              ▼               ▼
   CONTROL-STATE     TARGET-           MERGE
      SECURITY      PUBLICATION       SECURITY
      CONTEXT        SECURITY         CONTEXT
                       CONTEXT
          │              │               │
   credential A     credential B    credential C
          │              │               │
          └─────────── GitHub ───────────┘
```

These security contexts MAY share:

- a machine;
- a codebase;
- common deterministic libraries;
- deployment tooling.

They MUST NOT share protected credentials in a way that allows compromise of one protected capability to exercise another.

Candidate materialization SHOULD occur without the target-publication credential.

Controlled runtime is added separately when required.

Target-registration changes SHOULD initially remain explicit human administrative operations.

Root activation SHOULD initially remain manual or out-of-band.

---

## 47. Evolution beyond Phase 1

The architecture MAY later physically separate components into distinct services, accounts, hosts, or administrative domains where justified by:

```text
higher assurance
credential separation
controlled hardware
production deployment
organizational separation
failure containment
increased threat surface
```

Physical separation is not itself the goal.

Enforceable authority separation is.

Logical security boundaries MUST not weaken merely because deployment topology changes.

---

## 48. Dedicated fixture strategy

Development MUST use dedicated fixture and integration scenarios rather than repeatedly exercising control-plane policy against production scientific repositories.

The fixture suite SHOULD cover at minimum:

```text
routine success
supervised success
missing authorization
authorization admitted under stale policy
delegation amplification attempt
unregistered target
unauthorized target-registration change
unauthorized scope
candidate materialization without target publication
materialization mechanism that unexpectedly publishes
target publication with unknown side effects
event-sensitive repository-state change
event-sensitive platform-state change
deterministic failure
semantic rejection
semantic unable-to-determine
forged semantic verdict
forged human approval
invalid external observation
stale candidate SHA
stale base SHA
contract mutation
risk downgrade attempt
duplicate event
concurrent state update
concurrent target update
bounded repair success
repair exhaustion
controlled-runtime success
controlled-runtime unauthorized
malicious repository prompt injection
candidate self-authorization
trusted-core change through ordinary path
candidate self-activation
credential-boundary violation
```

Scientific/Abaqus/GUI/ML repositories are later target systems, not the primary control-plane test laboratory.

---

## 49. Failure model

Expected safe outcomes include:

```text
DENY
BLOCK
ESCALATE
STALE
CONFLICT
INVALID
UNAUTHORIZED
UNREGISTERED_TARGET
INSUFFICIENT_EVIDENCE
UNVERIFIABLE
```

Agents may diagnose these outcomes and propose remediation.

They MUST NOT reinterpret them as permission.

---

## 50. Components deliberately outside the minimal trusted core

The following remain outside the minimal trusted core:

```text
GPT
Codex
semantic LLM
prompts
planning logic
task decomposition
authorization proposal generation
repair reasoning
repository prose
candidate source code
candidate tests
context summarization
target adapters
ordinary orchestration
dashboards
human-readable labels/comments
```

Compromise of these components may produce incorrect proposals, poor implementation, or bad semantic judgment.

It SHOULD NOT independently permit an unauthorized consequential action.

---

## 51. Document relationships

The Phase 0 authority structure is:

```text
CORE_POLICY.md
        │
        ▼
ARCHITECTURE.md
        │
        ├── STATE_MACHINE.md
        ├── REVIEW_MODEL.md
        ├── SELF_MODIFICATION.md
        ├── issue-contract.schema.json
        └── review-verdict.schema.json

LESSONS_FROM_V1.md
        │
        └── evidence and rationale only
```

Subordinate designs MUST conform to both Core Policy and this architecture.

---

## 52. Core architectural invariants

The architecture remains valid only while all of the following hold:

1. Planning does not create authorization.
2. Every autonomously executable task enters through authorization admission.
3. Every admitted authorization is bound to the active-policy identity under which it was admitted.
4. Delegation cannot amplify authority.
5. Autonomous targets must be explicitly registered.
6. Target registration cannot be broadened through ordinary implementation authority.
7. Stable target configuration is distinguished from current event-sensitive target state.
8. Current event-sensitive state includes relevant repository and platform state.
9. Agents may propose protected operations but cannot independently perform them.
10. Protected mutations pass through deterministic trusted enforcement.
11. Security-critical capability boundaries use technically enforceable identities or security contexts.
12. Shared code or infrastructure MUST NOT be mistaken for shared authority.
13. Candidate generation is separated from candidate materialization.
14. Candidate materialization is separated from target publication.
15. Candidate materialization SHOULD NOT possess target-publication credentials.
16. A materialization mechanism that moves an event-bearing target ref is treated as publication.
17. Target-publication effects are part of the authorization decision.
18. Unknown material target-publication effects fail closed.
19. Security-relevant evidence enters through deterministic Evidence Admission.
20. Evidence admission does not create authorization.
21. Review-envelope binding is trusted; semantic context curation is not.
22. Review is separated from implementation and merge.
23. Work-plane requests are distinguished from protected operational capabilities.
24. Risk is separate from operational capability.
25. Trusted risk policy establishes the minimum supervised human gate.
26. Target or task policy may strengthen but not weaken that minimum.
27. Risk proposals do not become authoritative without authorization.
28. Evidence is bound to the exact identity/context on which it depends.
29. Base movement may invalidate evidence even when candidate SHA is unchanged.
30. Every race-sensitive consequential mutation is atomically bound to required current state.
31. Candidate-controlled output cannot self-attest trust.
32. Controlled runtime is separated from ordinary execution and merge.
33. Autonomous repair is bounded.
34. Target adapters cannot weaken generic trusted policy.
35. Active trusted policy is distinct from repository `main`.
36. Trusted-core membership is evaluated under the previously active trust boundary.
37. A candidate trusted core cannot activate itself.
38. Human-facing projections do not replace canonical structured control state.
39. Audit records do not create authority.
40. Failure to establish required policy, authorization, authoritative state, or evidence results in no consequential action.
