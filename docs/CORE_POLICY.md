# Autonomous Development v2 — Core Policy

**Status:** Phase 0 frozen  
**Version:** 1.0  
**Repository:** `RayZhang2024/autonomous-dev-control-plane`

## 1. Purpose

This document defines the constitutional policy of Autonomous Development v2.

It establishes the invariants governing:

- authority;
- trust;
- identity;
- evidence;
- separation of capabilities;
- consequential autonomous actions;
- failure behaviour;
- trusted-core modification.

Detailed lifecycle states, schemas, review formats, retry limits, repository adapters, execution profiles, and implementation mechanisms belong in subordinate specifications.

No subordinate specification, configuration, workflow, agent, repository adapter, or task contract may weaken this policy.

---

## 2. Normative language

The terms **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are normative.

Where a MUST-level precondition for a consequential action cannot be established, the action MUST NOT occur.

Uncertainty is not authorization.

---

## 3. Consequential actions

A **consequential action** is an autonomous operation capable of changing protected or authoritative state, creating externally observable effects, granting or revoking authority, invoking protected capabilities, or causing a candidate to advance through a protected trust boundary.

Consequential actions include, where applicable:

- modifying repository content;
- creating or updating protected control-plane state;
- granting, delegating, changing, or revoking authorization;
- changing lifecycle state where that state affects authority or execution;
- merging, publishing, deploying, or activating a candidate;
- invoking controlled, privileged, production-like, secret-bearing, hardware-connected, or otherwise protected execution;
- activating trusted policy, trusted configuration, or trusted-core components.

This list is illustrative and not exhaustive.

The architecture MUST explicitly identify the protected operations treated as consequential.

An operation whose consequential status is unknown or ambiguous MUST be treated as consequential.

A component outside the trusted enforcement boundary MUST NOT determine that an operation is non-consequential in order to bypass policy enforcement.

---

## 4. Central invariant

A consequential autonomous action MUST occur only when:

1. the **active trusted policy** permits it;
2. valid **authenticated authorization** permits it;
3. **current authoritative state** satisfies its preconditions; and
4. required **provenance-bound evidence** supports it.

These elements MUST jointly establish that an authorized actor may perform the exact operation on the exact subject in its exact current state.

If any required element is missing, stale, ambiguous, contradictory, unverifiable, or unauthorized, the action MUST NOT occur.

---

## 5. Distinct authority domains

Autonomous Development v2 MUST distinguish four different domains.

They are complementary and MUST NOT be collapsed into a single precedence hierarchy.

### 5.1 Active trusted policy

Policy determines what operations are permitted in principle and what conditions must be satisfied before they may occur.

Autonomous operation MUST use the currently activated trusted policy set.

A candidate policy or trusted-core modification is not authoritative merely because it exists in a branch, pull request, repository file, generated artifact, or proposed configuration.

### 5.2 Authenticated authorization

Authorization determines what a particular task, actor, or capability is permitted to do within the constraints of active policy.

Authorization MUST have sufficient authenticated provenance to establish its issuer, subject, scope, and applicability.

Structured validity alone does not create authority.

### 5.3 Current authoritative state

Authoritative state determines what currently exists.

GitHub is authoritative for mutable repository and control-plane state explicitly designated by the architecture as GitHub-authoritative.

Repository state MUST be read and verified when a consequential decision depends on it.

Cached observations, previous prompts, model memory, audit records, comments, or earlier workflow state MUST NOT override conflicting current authoritative state.

### 5.4 Provenance-bound evidence

Evidence establishes what has been demonstrated about a particular subject or state.

Evidence does not create authority.

Tests, reviews, runtime results, comments, reports, agent assertions, or audit events MUST NOT authorize operations that are not already permitted by active policy and authenticated authorization.

---

## 6. GitHub authority boundary

The fact that information is stored on GitHub does not by itself make that information authoritative.

Repository objects and explicitly designated control-plane state MAY be authoritative.

Natural-language issue text, pull-request descriptions, comments, code, logs, generated files, labels, statuses, or other GitHub-hosted data have only the authority explicitly assigned to them by active policy and architecture.

A GitHub-hosted claim such as:

> tests passed

or:

> this change is approved

is not trusted merely because GitHub stores it.

The control plane MUST distinguish authoritative state from untrusted or evidentiary content hosted by the same platform.

---

## 7. Exact identity binding

Consequential decisions MUST be bound to the exact subjects to which they apply.

Where relevant, identity MUST include immutable or sufficiently strong identifiers for:

- repository;
- task or issue;
- pull request;
- branch;
- base revision;
- candidate revision;
- contract;
- authorization;
- review or validation evidence.

Mutable names or numbers MUST NOT substitute for stronger immutable identity when the stronger identity is required to prevent ambiguity or stale reuse.

Evidence or authorization created for one candidate MUST NOT be silently reused for another.

A change to an identity on which a decision depends invalidates that decision unless active policy explicitly permits deterministic proof that the change is irrelevant.

---

## 8. Structured control

Security-relevant authority MUST be represented through explicit structured control data.

Natural-language prose MAY express:

- intent;
- context;
- goals;
- explanations;
- semantic requirements.

Natural-language prose MUST NOT silently create or expand:

- authorization;
- permitted scope;
- privileged capability;
- lifecycle authority;
- acceptance-evaluation requirements;
- merge authority;
- trusted-core authority.

The control plane MUST NOT infer security-relevant classification from arbitrary prose using:

- regular expressions;
- keyword matching;
- heuristic parsing;
- LLM interpretation.

Where security-relevant structured information is required but absent, the system MUST treat it as absent.

---

## 9. Acceptance evaluation

The mechanism required to establish satisfaction of an acceptance requirement MUST be explicit in structured control data.

Evaluation MAY require one or more mechanisms, including:

- deterministic verification;
- semantic review;
- controlled or privileged execution;
- external observation;
- explicit human approval.

The applicable evaluation mechanism MUST NOT be inferred from the wording of the requirement.

Deterministic mechanisms SHOULD establish facts that can be reliably machine-verified.

Semantic reasoning SHOULD be used only where genuine interpretation or judgment is necessary.

An LLM judgment MUST NOT replace a deterministic fact that can and must be independently verified.

---

## 10. Provenance and self-attestation

Security-relevant contracts, authorizations, evidence, review results, approvals, and state transitions MUST have sufficient provenance to determine whether they came from an authorized source.

Conformance to a schema is necessary where required, but schema conformance alone is not evidence of authority or authenticity.

A candidate or implementation actor MUST NOT be able to satisfy a required trust condition merely by producing content that claims the condition is satisfied.

Candidate-controlled output MUST therefore be treated as untrusted until independently verified where that output affects a consequential decision.

No component may establish its own authority merely by asserting that authority.

---

## 11. Authority delegation and non-amplification

Authority MUST NOT increase merely through delegation, transformation, orchestration, or repetition.

An authorization issuer MUST NOT grant or delegate authority exceeding the authority that active policy permits that issuer to delegate.

Any delegated authority MUST remain within the applicable limits of its authorized source unless an independently authorized actor explicitly grants additional authority.

An actor MUST NOT use an intermediary, agent, workflow, or subordinate actor to perform an operation that the actor itself is not authorized to cause.

No chain of authorization may create authority that does not originate from a valid authorized root.

Where the validity of delegated authority cannot be established, the delegated authority MUST be treated as absent.

---

## 12. Separation of roles and capabilities

Autonomous Development v2 MUST separate at least the following functions:

- planning;
- implementation;
- deterministic verification;
- semantic review;
- repair;
- merge or final repository mutation;
- controlled-runtime execution;
- trusted-core activation.

A component performing one function MUST NOT automatically acquire the authority of another.

Implementation MUST NOT imply approval.

Review MUST NOT imply merge authority.

Repair MUST NOT imply review authority.

Ordinary repository modification MUST NOT imply privileged-runtime authority.

None of these authorities imply authority to modify or activate the trusted core.

Where compromise of a component could otherwise bypass these boundaries, separation MUST be enforced through actual capability restrictions, credentials, permissions, protected interfaces, or equivalent technical controls.

Prompt instructions alone MUST NOT be treated as a security boundary.

---

## 13. Non-bypassability

Every consequential autonomous operation MUST pass through an enforcement boundary governed by the active trusted policy.

Components outside that enforcement boundary MUST NOT possess sufficient authority to bypass it.

The architecture MUST be designed so that compromise or malfunction of an ordinary planner, implementation agent, semantic reviewer, repair agent, target repository, or candidate code cannot independently cause an unauthorized consequential action.

The trusted control plane exists to enforce authority, not merely to coordinate cooperating agents.

---

## 14. Scope containment

Autonomous modification or execution MUST remain within explicitly authorized scope.

Scope MUST NOT expand implicitly because an implementation agent believes additional work is useful or necessary.

If satisfying a task requires authority or scope that has not been granted, autonomous execution MUST stop until valid authorization is deliberately changed through an approved mechanism.

Unexpected scope is a control-plane condition, not an invitation to reinterpret the task.

---

## 15. Freshness and candidate identity

Evidence whose validity depends on repository content MUST be bound to the candidate to which it applies.

When a candidate changes, evidence for an earlier candidate MUST be considered stale unless active policy explicitly permits deterministic proof of continued applicability.

A repaired implementation is a new candidate.

Semantic approval, deterministic validation, runtime evidence, or other candidate-bound evidence MUST NOT silently transfer to the repaired candidate.

A final consequential decision MUST operate on the exact candidate for which all required evidence remains valid.

---

## 16. Risk and authority

The system MUST distinguish:

**risk**, which determines the degree of review, assurance, or escalation required;

from:

**operational authority**, which determines what capabilities or resources an operation requires.

These concepts MUST NOT be treated as interchangeable.

A change may be high risk without requiring privileged execution.

An operation may require privileged capability without being a high-risk code change.

Trusted-core modification is a separately protected class governed by the self-modification policy.

The detailed risk taxonomy and authority classes are subordinate design decisions.

---

## 17. Repair and retry boundedness

Autonomous repair and retry behaviour MUST be bounded by governing trusted policy.

A task contract MAY select repair or retry limits only within the ranges and conditions permitted by that policy.

A failed candidate MUST NOT enter an unbounded autonomous implementation, validation, review, or repair cycle.

Repair authority MUST NOT implicitly expand scope, capability, authorization, or retry limits.

A repair creates a new candidate and is subject to the identity and freshness requirements of this policy.

When the permitted repair or retry bound is exhausted, autonomous continuation MUST stop or escalate through an explicitly authorized path.

The numerical limits and detailed repair eligibility rules belong in subordinate specifications.

---

## 18. Fail-closed operation

Fail-closed behaviour is a normal control-plane outcome.

The system MUST refuse a consequential action when required conditions include:

- unknown or ambiguous identity;
- missing or invalid authorization;
- stale evidence;
- contradictory evidence;
- conflicting authoritative state;
- invalid structured control data;
- unauthorized scope;
- unsupported state transition;
- unknown policy applicability;
- unverifiable provenance;
- candidate mismatch;
- unmet escalation requirements;
- uncertain trusted-core impact;
- exhausted autonomous repair or retry authority.

The control plane MUST NOT convert uncertainty into permission through optimistic interpretation.

Recovery requires establishment of valid state, evidence, policy, or authorization through an approved path.

---

## 19. Concurrency and atomicity

Consequential state-changing operations MUST defend against stale observations and concurrent change.

Where the safety of a consequential mutation depends on authoritative state remaining unchanged, the mutation MUST be bound to that state through an atomic, conditional, or platform-enforced precondition.

If the required state-binding guarantee cannot be established, the consequential mutation MUST NOT occur.

A prior read followed by an unconditional mutation is insufficient when intervening state change could invalidate authorization or evidence.

After a consequential mutation, the control plane SHOULD verify that the intended postcondition was actually established.

Retries MUST NOT silently duplicate consequential effects.

---

## 20. Untrusted content

Repository contents and task-controlled natural language MUST be treated as untrusted input to the control plane.

This includes, where applicable:

- source code;
- documentation;
- issue prose;
- pull-request descriptions;
- comments;
- code comments;
- test output;
- logs;
- generated artifacts;
- external content supplied through the task.

Such content MUST NOT modify control-plane authority, policy, credentials, permissions, or trusted instructions merely by containing language that requests or instructs such a change.

Instructions affecting authority MUST enter through authenticated control channels explicitly recognized by active policy.

Semantic reviewers MAY interpret untrusted content for meaning but MUST NOT treat embedded instructions as control-plane authority.

---

## 21. Trusted Computing Base

Autonomous Development v2 MUST explicitly identify its **Trusted Computing Base (TCB)**.

The TCB comprises components and external trust dependencies whose correct behaviour is relied upon to preserve the control plane's stated authority and safety guarantees.

The architecture SHOULD distinguish at least:

- the minimal custom **trusted core**;
- trusted policy and enforcement configuration;
- required external trust dependencies.

The trusted core SHOULD contain only the minimum custom logic necessary to enforce critical invariants.

External services or platform guarantees MAY be part of the TCB without being part of the custom trusted-core code.

Trusted-core membership MUST be explicit rather than heuristically inferred.

The architecture MUST seek to minimize both the trusted core and the overall TCB.

---

## 22. Target-repository isolation

Repository-specific behaviour SHOULD remain outside the trusted core wherever deterministic validation at the trust boundary can make this safe.

Target-specific code, configuration, commands, fixtures, tests, semantic requirements, and adapters MUST NOT be able to weaken active Core Policy.

Repository-controlled output MUST NOT become trusted merely because the control plane consumes it.

The control plane SHOULD support dedicated fixture and integration environments so its safety properties can be tested without repeatedly mutating a production repository.

---

## 23. Trusted-core self-modification

The trusted core MUST NOT autonomously certify or activate reconstruction, replacement, or weakening of itself.

Trusted-core changes MUST be evaluated under the previously active trusted policy and trusted enforcement environment.

A candidate trusted core MUST NOT become authoritative merely by:

- existing on an approved branch;
- passing its own tests;
- producing a favourable self-review;
- modifying the policy that defines its own acceptance;
- declaring itself trusted.

Activation of a new trusted core or active trusted policy MUST follow a separate root-change procedure.

That procedure MUST require independent review and explicit external approval bound to the exact candidate being activated.

The candidate MUST NOT be the sole authority determining whether its own activation requirements are satisfied.

The detailed bootstrap and activation process is defined in `SELF_MODIFICATION.md`.

---

## 24. Active policy continuity

At any consequential decision point, the system MUST be able to identify which trusted policy set is active.

A proposed modification to:

- Core Policy;
- trusted-core code;
- trusted-core membership;
- authority rules;
- evidence-validation rules;
- enforcement configuration;
- root activation rules;

MUST remain a candidate until successfully activated through the root-change procedure.

Evidence or authorization evaluated under one active-policy identity MUST NOT be reused under a different active-policy identity unless governing policy explicitly permits deterministic proof of continued applicability.

Policy activation itself is a consequential operation.

---

## 25. Auditability

Consequential autonomous actions and decisions MUST produce sufficient machine-readable audit evidence to allow later reconstruction of what happened and under what authority.

Audit records provide traceability.

They MUST NOT replace authoritative state, active policy, authorization, or required validation evidence.

An audit record stating that an action was valid does not itself make the action valid.

---

## 26. Relationship to v1

The autonomous-development system previously developed in `RayZhang2024/ML-AMstress` is reference evidence only.

Its successes, failures, operational history, and design lessons MAY inform v2.

Its terminology, workflow structure, issue format, implementation mechanisms, risk labels, reviewer design, repair design, controlled-runtime mechanisms, and other policies have no inherited authority in v2.

Any v1 concept used in v2 MUST be deliberately reconsidered and adopted through the v2 design process.

---

## 27. Constitutional interpretation

Subordinate specifications MUST make this policy operational without weakening its invariants.

Where two subordinate mechanisms conflict, they MUST be reconciled under the active Core Policy.

Where policy, authorization, authoritative state, and required evidence do not jointly establish permission for an action, there is no valid autonomous authority to act.

The system MUST stop rather than invent an interpretation that grants additional authority.

---

## 28. Minimality principle

The trusted core SHOULD contain only functionality whose correctness is necessary to prevent unauthorized consequential actions.

Planning, orchestration, implementation, semantic reasoning, reporting, convenience logic, target-specific behaviour, and other functionality SHOULD remain outside the trusted core wherever enforceable trust boundaries permit.

The objective is not to trust every component.

The objective is to make safe autonomous development depend on as little trusted machinery as practical.