# Autonomous Development v2 — Self-Modification and Root Activation

**Status:** Phase 0 frozen  
**Version:** 1.2  
**Repository:** `RayZhang2024/autonomous-dev-control-plane`

## 1. Purpose

This document defines how Autonomous Development v2 may modify its trusted core, trusted policy, trusted enforcement boundary, or other root-protected material without allowing a candidate trusted system to certify or activate itself.

It defines:

- the External Root Authority;
- the externally protected Root Trust Anchor;
- root-impact determination;
- trusted dependency and runtime-artifact identity;
- root candidate preparation;
- deterministic root validation;
- independent semantic review;
- authenticated external approval;
- race-free policy-epoch transition;
- readiness creation and sealing;
- final activation freshness;
- Root Activation;
- predecessor-governed post-activation verification;
- pre-release capability fencing;
- state-bound release verification;
- pre-release rollback;
- External Root Recovery;
- external recovery fencing;
- External Root Migration;
- concurrency, failure handling, and genesis bootstrap.

This document governs the **root-change path**.

It does not grant ordinary autonomous tasks root authority.

---

## 2. Relationship to Core Policy

`CORE_POLICY.md` is constitutionally superior to this document.

This specification operationalizes its requirements that:

- trusted-core modification is separately protected;
- trusted-core candidates remain candidates until valid Root Activation;
- a candidate cannot establish the rules governing its own activation;
- candidate evaluation occurs under the previously active trusted boundary;
- independent review is required;
- explicit external approval is required;
- activation is exact-candidate-bound;
- active-policy continuity is preserved;
- uncertain trusted-core impact fails closed.

No rule in this document may weaken Core Policy.

---

## 3. Root-change principle

For a normal autonomous-root transition:

```text
active trusted system N
        ↓
candidate trusted system N+1
        ↓
evaluation governed by N
        ↓
independent evidence
        ↓
authenticated external root approval
        ↓
externally protected transition barrier
        ↓
quiescence
        ↓
N-governed final readiness
        ↓
readiness sealed by External Root Authority
        ↓
fresh applicability check under N
        ↓
Root Activation N → N+1
        ↓
establish or preserve independent
pre-release capability fencing
        ↓
stage / deploy exact N+1 trusted contexts
under that independent fence
        ↓
N-governed/external deployed-state verification
        ↓
N-governed release verification
        ↓
release verification sealed externally
        ↓
fresh release-state verification
        ↓
External Root Authority releases barrier
        ↓
N+1 governs newly starting protected work
```

Candidate `N+1` does not become authoritative because it:

- exists;
- is committed;
- is merged;
- appears on `main`;
- passes candidate-provided tests;
- approves itself;
- changes its own acceptance rules;
- changes trusted-core membership;
- changes reviewer rules;
- changes activation rules;
- declares itself safe;
- declares changed material no longer trusted.

Only successful completion of the externally controlled root transition establishes `N+1` as the policy governing newly starting protected autonomous operations.

---

## 4. External Root Authority

The autonomous chain of trust terminates at an **External Root Authority**.

Conceptually:

```text
External Root Authority
        │
        │ controls
        ▼
externally protected root state
        │
        │ identifies
        ▼
Active Trusted Manifest N
        │
        ▼
autonomous trusted system
```

The External Root Authority is outside the autonomous trusted system represented by Active Trusted Manifests.

For the initial design it consists conceptually of:

- authenticated human root-administrative identity;
- externally protected root credential or equivalent capability;
- protected authoritative root-state mutation mechanism;
- External Root Recovery authority;
- external recovery-fencing authority;
- administrative controls protecting those mechanisms.

Candidate `N+1` does not create, grant, or redefine the External Root Authority used to activate it.

The autonomous system may determine that a candidate satisfies prerequisites established by `N`.

It cannot manufacture the external authority required to activate itself.

---

## 5. External root-administration boundary

The following belong to bootstrap/external-root administration rather than ordinary `N → N+1` candidate state:

```text
authoritative root-state location and identity

External Root Authority identity model

external root administrative credentials

protected root-state mutation mechanism

External Root Recovery authority

external recovery-fencing authority

canonical Root Trust Anchor designation mechanism
```

Changing these elements changes the external root boundary itself.

Such a change MUST NOT be treated as ordinary self-modification merely because active trusted system `N` approves it.

It requires a separate **External Root Migration / Re-bootstrap Ceremony** authorized by the existing External Root Authority.

The autonomous system MAY prepare analysis, validation, migration plans, and evidence.

It MUST NOT be the final authority that replaces the external authority controlling its own root anchor.

---

## 6. Root plane versus ordinary task plane

Ordinary autonomous work and root modification are separate authority domains.

The ordinary issue-contract path MUST NOT authorize:

```text
root_activation

External Root Authority mutation

external root-state mutation

trusted-core replacement

active-policy replacement

root-protection weakening

external root migration
```

An ordinary task does not become a root task because its issue, objective, branch, pull request, candidate, or implementation says that it is one.

Root work uses separately controlled root-change records and the authority model defined here.

`schemas/issue-contract.schema.json` is not a Root Activation authorization format.

---

## 7. Root-protected material

The previously active trusted system determines the autonomous root-protected boundary.

Root-protected material includes at least the active identities and mechanisms governing:

```text
Core Policy

trusted-core implementation

trusted schemas used for security-relevant control

trusted enforcement configuration

trusted-core membership

authorization admission

Evidence Admission

scope and identity enforcement

protected capability gating

active-policy loading

root-impact determination

root semantic-review requirements

root approval requirements

root readiness rules

protected-operation policy-epoch checks

Active Trusted Manifest interpretation

trusted dependency definitions

capability and credential assignments whose alteration
could cross a protected authority boundary
```

The active trusted boundary MAY designate additional root-protected resources.

External Root Authority infrastructure remains separately protected outside this autonomous root set.

---

## 8. Root impact is determined under the old system

For:

```text
N → N+1
```

root impact is determined using the rules and trusted membership of **N**.

Candidate `N+1` MUST NOT redefine the test used to determine whether its own changes are root-impacting.

It cannot escape root review by:

- removing a component from its proposed trusted manifest;
- renaming a trusted component;
- moving trusted logic elsewhere;
- moving authority decisions behind an adapter;
- changing imports or dependency wiring;
- replacing trusted behavior through build configuration;
- changing deployment composition;
- changing credential ownership;
- declaring previously trusted behavior untrusted;
- changing the definition of root impact.

Where deterministic evaluation cannot prove that proposed ordinary work is outside the old root boundary, the work MUST be treated as root-impacting.

---

## 9. Closed-world trusted execution model

Initial v2 uses a **closed-world trusted execution model**.

Trusted behavior MUST depend only on:

1. explicitly identified immutable root-managed inputs; and
2. explicitly declared external TCB dependencies.

Trusted dependency membership MUST NOT be inferred from:

- repository scanning plus heuristic interpretation;
- natural-language descriptions;
- filenames alone;
- regex classification of semantic importance;
- LLM judgment;
- candidate assertions.

Unexpected executable, module, configuration, dependency, plugin, or equivalent input entering a trusted security context fails closed.

---

## 10. Root-managed dependency closure

The Active Trusted Manifest or trusted configuration governed by it MUST deterministically bind every root-managed input capable of affecting trusted behavior.

Where applicable this includes immutable identities for:

```text
trusted runtime artifact

trusted executable or package

trusted source/code modules

resolved dependency set or dependency lock

trusted entry points

trusted schemas

trusted enforcement configuration

trusted policy resources

build definition

container/image

runtime configuration

capability/security-context wiring

credential-routing configuration

permitted module/plugin loading
```

The precise representation may vary by deployment topology.

The security requirement is:

> every root-managed input capable of affecting trusted behavior is represented through explicit trusted identity.

---

## 11. Actual trusted runtime artifact identity

The artifact that actually executes with trusted capability MUST itself have an immutable identity.

Examples include an exact:

```text
executable digest

wheel/package digest

container-image digest

deployment artifact identity

content-addressed runtime bundle
```

Approval of source code, dependency locks, or build definitions alone MUST NOT substitute for establishing the identity of the artifact that actually executes.

Where supply-chain or reproducible-build provenance is required, it is additional evidence linking:

```text
approved source
        ↓
approved build definition
        ↓
exact produced artifact
        ↓
exact artifact deployed/executed
```

The trusted runtime identity remains the exact artifact exercising trusted capability.

---

## 12. Dynamic loading

Initial trusted security contexts MUST NOT load executable or security-relevant configuration material outside the explicit trusted dependency model.

If plugins, modules, dynamic libraries, runtime configuration, or equivalent extension points are permitted, their admissible identities MUST be deterministically constrained through trusted configuration.

Unregistered dynamic loading into a trusted security context fails closed.

---

## 13. External TCB dependencies

Some security guarantees depend on systems outside root-managed artifacts.

These are **external TCB dependencies**.

Examples may include:

- GitHub identity/platform guarantees;
- operating-system isolation;
- protected credential storage;
- cryptographic implementations;
- externally protected root-state storage;
- authenticated platform APIs.

Such dependencies MUST be explicitly represented as trusted assumptions or dependencies.

They MUST NOT be silently discovered from candidate behavior.

A change to an ordinary external TCB assumption may require the autonomous root path.

A change to the External Root Authority itself requires External Root Migration.

---

## 14. Incomplete dependency model

If trusted execution can obtain security-relevant behavior from a resource not represented as either:

```text
explicit immutable root-managed input
```

or:

```text
explicit external TCB dependency
```

then the trusted dependency model is incomplete.

Protected autonomous operation MUST fail closed until the dependency is brought under explicit trusted control.

A candidate cannot cure an incomplete trust model merely by declaring the dependency harmless.

---

## 15. Active Trusted Manifest

The active autonomous trusted system is identified by an immutable **Active Trusted Manifest**.

Conceptually it identifies exact versions of:

```text
manifest version

Core Policy

trusted-core implementation

trusted schemas

trusted enforcement configuration

trusted-core membership

root-managed dependency closure

trusted runtime artifacts

root-sensitive configuration
```

Every security-relevant manifest reference MUST be immutable or content-addressed.

Mutable selectors such as:

```text
main
latest
current
default
production
```

MUST NOT serve as authoritative component identities.

---

## 16. Candidate manifest

A root candidate MUST produce a complete candidate manifest.

Candidate `N+1` MUST identify:

```text
predecessor_manifest_id = N
```

The candidate manifest MUST be immutable before candidate-bound final evaluation begins.

Any security-relevant candidate modification creates a new candidate identity.

Earlier validation, semantic review, approval, readiness, readiness sealing, or release verification MUST NOT silently transfer.

---

## 17. Externally protected root state

Initial Phase 1 SHOULD represent the Root Trust Anchor and Root Transition Barrier in one externally protected authoritative state object, or through a mechanism providing equivalent atomic guarantees.

Normal state is conceptually:

```text
{
    active_manifest: N,
    transition: open,
    revision: R
}
```

A closed transition may contain:

```text
{
    active_manifest: N,
    transition: {
        root_change_id: X,
        from: N,
        to: N+1,
        readiness_id: null,
        release_verification_id: null
    },
    revision: R
}
```

After readiness sealing:

```text
{
    active_manifest: N,
    transition: {
        root_change_id: X,
        from: N,
        to: N+1,
        readiness_id: H,
        release_verification_id: null
    },
    revision: R
}
```

After successful pre-release verification:

```text
{
    active_manifest: N+1,
    transition: {
        root_change_id: X,
        from: N,
        to: N+1,
        readiness_id: H,
        release_verification_id: V
    },
    revision: R
}
```

The externally protected state contains identities, transition state, and concurrency state only.

It does not perform semantic review or application-policy reasoning.

---

## 18. Why pointer and barrier share one boundary

Active-manifest identity and transition state jointly determine whether new protected work may begin.

Separating them into independently mutable authoritative stores would create a cross-store consistency problem during activation.

Therefore initial v2 SHOULD use one externally protected state object or a mechanism capable of atomically binding:

```text
active manifest identity

transition identity/state

sealed readiness identity

sealed release-verification identity where applicable

root-state revision
```

If equivalent guarantees cannot be established, Root Activation or barrier release MUST fail closed.

---

## 19. Authoritative root-state requirements

The externally protected root-state mechanism MUST provide:

- authenticated authoritative reads;
- write isolation from ordinary autonomous credentials;
- exact active-manifest identity;
- exact transition identity/state;
- exact predecessor and successor identities while transitioning;
- sealed readiness identity where applicable;
- sealed release-verification identity where applicable;
- authoritative revision identity;
- conditional/compare-and-set mutation;
- deterministic reconciliation after uncertain outcomes;
- auditable mutations.

The external root state MUST remain deliberately small.

Root evaluation and deployment-verification logic belongs to trusted predecessor `N` or explicitly trusted external mechanisms, not to the root-state storage mechanism.

---

## 20. Repository state is not activation state

Repository state and externally protected root state are distinct.

Therefore:

```text
candidate trusted source merged to main
```

does not imply:

```text
candidate trusted source active
```

A repository may contain multiple trusted versions while only one Active Trusted Manifest is authoritative.

Ordinary merge authority cannot change externally protected root state.

---

## 21. Root-change roles

The root path separates at least:

```text
proposal / planning

candidate implementation

candidate materialization

deterministic root validation

independent semantic root review

external root approval

root-transition coordination

readiness determination

external Root Activation

pre-release deployment verification

external barrier release
```

The same physical human or system MAY perform compatible roles where governing policy permits.

Possession of one role never automatically grants another capability.

In particular:

```text
candidate implementation ≠ semantic review authority

review authority ≠ external root approval

external root approval ≠ root-state write capability

ordinary merge authority ≠ Root Activation

candidate deployment ≠ protected operational authority

autonomous protected credentials ≠ External Root Authority
```

---

## 22. Candidate implementation

GPT, Codex, humans, or other work-plane components MAY assist in producing root candidates.

Candidate generation remains untrusted.

Candidate-producing components MUST NOT possess External Root Authority.

Candidate-provided:

- tests;
- explanations;
- risk claims;
- migration instructions;
- membership claims;
- safety claims

remain advisory until established through the governing trusted path.

---

## 23. Root Change Package

A proposed autonomous-root transition MUST be represented by structured identity-bound control data.

A Root Change Package conceptually binds:

```text
root_change_id

expected active manifest N

candidate manifest N+1

candidate manifest content identity

candidate repository / commit / artifact identities

exact trusted runtime-artifact identities

complete root-protected changed-resource inventory

root-managed dependency identities

relevant external TCB dependencies

required deterministic root-validation profile identity

required semantic root-review profile identity

required external root-approval configuration identity

activation subject

canonical external Root Trust Anchor identity

pre-release rollback target N
```

Explanatory prose MAY accompany the package.

Prose cannot create or broaden root authority.

---

## 24. Root Change Package identity

Security-relevant Root Change Package content MUST have an immutable identity.

The same root-change identity cannot be retained while altering:

- candidate content;
- predecessor;
- runtime artifact;
- changed-resource inventory;
- dependency closure;
- validation requirements;
- semantic-review requirements;
- external approval requirements;
- activation subject;
- canonical Root Trust Anchor identity;
- pre-release rollback target.

Any such modification creates a new root-change candidate.

---

## 25. Governing transition manifest

Every closed root transition explicitly identifies:

```text
transition.from = N
transition.to   = N+1
```

For the entire lifetime of that closed transition:

```text
transition_governing_manifest = transition.from
```

Therefore, for transition `X`:

```text
governing manifest = N
```

even after `active_manifest` has been changed to `N+1` while the barrier remains closed.

Transition-completion logic MUST load governing policy, validation rules, verifier configuration, and applicable trusted identities from exact immutable predecessor `N`.

It MUST NOT determine transition-completion policy by loading whichever manifest currently appears in `active_manifest`.

Candidate `N+1` does not become the authority deciding whether its own transition is complete.

---

## 26. Policy-epoch handover rule

Rules governing completion of:

```text
N → N+1
```

come from exact predecessor `N` or the External Root Authority.

This includes:

- root impact;
- trusted membership;
- dependency closure;
- runtime-artifact requirements;
- deterministic validation;
- semantic review;
- reviewer eligibility;
- root approval requirements;
- quiescence;
- readiness;
- readiness applicability;
- post-activation verification;
- pre-release capability fencing;
- release verification;
- pre-release rollback;
- barrier release.

`N+1` becomes the normal autonomous policy authority for newly starting protected work only after successful external barrier release.

---

## 27. Root evaluation sequence

Initial root evaluation follows:

```text
establish exact active N
        ↓
establish exact candidate N+1
        ↓
establish runtime/dependency/change inventory
        ↓
deterministic root validation under N
        ↓
semantic root review under N
        ↓
Evidence Admission
        ↓
authenticated external root approval
        ↓
External Root Authority closes barrier
        ↓
drain / reconcile protected operations
        ↓
N-governed final freshness validation
        ↓
N-governed Readiness Record H
        ↓
External Root Authority seals H
        ↓
fresh mutable-applicability verification under N
        ↓
External Root Authority activates N+1
        ↓
establish or preserve independent
pre-release capability fencing
        ↓
stage / deploy exact N+1 trusted contexts
under that independent fence
        ↓
N-governed/external deployed-state verification
        ↓
N-governed Release Verification Record V
        ↓
External Root Authority seals V
        ↓
fresh release-state verification
        ↓
External Root Authority releases barrier
```

No later step retroactively excuses failure of an earlier mandatory condition.

---

## 28. Deterministic root validation

Root validation is defined by exact governing system `N`.

It establishes where applicable:

```text
current active manifest is exactly N

external root-state integrity is valid

candidate predecessor is exactly N

candidate manifest is immutable

candidate runtime artifact is exact

candidate dependencies resolve exactly

complete changed-resource inventory exists

closed-world dependency closure exists

external TCB assumptions are identified

root-impact inventory is complete

required validation profiles originate from N

required fixture/integration validation completed

evidence provenance is valid

candidate has not changed rules used to evaluate itself

activation subject is exact

pre-release rollback target is exactly N
```

Candidate-provided tests MAY contribute evidence.

They cannot alone define or satisfy root acceptance rules unless `N` explicitly recognizes them through trusted configuration.

---

## 29. Isolated candidate evaluation

Candidate `N+1` SHOULD be evaluated without replacing active trusted system `N`.

Where execution of `N+1` is necessary before activation, it MUST occur in an isolated environment lacking production Root Activation authority.

The candidate environment MUST NOT possess:

- External Root Authority credentials;
- production protected credentials merely because the candidate requests them;
- broader runtime capability than `N` explicitly authorizes.

Dedicated control-plane fixtures are preferred over production repository experimentation.

---

## 30. Semantic root review reuses REVIEW_MODEL

Root semantic review uses the trust model defined by `REVIEW_MODEL.md`, with this document imposing additional root-specific constraints.

Root review therefore inherits, where applicable:

- exact subject binding;
- trusted review-envelope construction;
- trusted reviewer-profile identity;
- deterministic material coverage;
- invocation provenance;
- Evidence Admission;
- prompt-injection isolation;
- structured verdict semantics;
- `unable_to_determine`;
- evidence freshness;
- reviewer non-authority;
- retry/adjudication constraints.

This document does not create a second semantic-review security model.

---

## 31. Root semantic-review subject

Root semantic review additionally binds:

```text
root_change_id

active manifest N

candidate manifest N+1

exact runtime artifact

exact changed-resource inventory

dependency identities

relevant unchanged trusted context

root semantic requirement identities

review profile identity

review invocation identity
```

The reviewer cannot control:

- Root Activation;
- External Root Authority;
- root approver eligibility;
- trusted review instructions;
- required review material;
- recording of unfavorable outcomes.

---

## 32. Semantic root-review coverage

Root semantic review MUST consider where applicable:

- authorization weakening;
- capability widening;
- Evidence Admission weakening;
- scope weakening;
- freshness or exact-identity weakening;
- fail-closed weakening;
- credential separation weakening;
- trusted-core membership changes;
- root-impact rule changes;
- readiness or barrier-rule changes;
- protected-operation policy-epoch checks;
- root approval changes;
- future self-certification paths;
- trusted dependency changes;
- runtime-artifact/build trust changes;
- external TCB assumption changes.

Insufficient material or context produces `unable_to_determine`.

A favorable semantic verdict remains evidence only.

---

## 33. Root review verdict representation

Where compatible, raw root semantic-review output MAY use:

`schemas/review-verdict.schema.json`

Using that schema does not convert root review into ordinary-task authority.

Root-specific subject identities, active-manifest binding, provenance, candidate binding, and applicability remain trusted root records.

Semantic approval never grants Root Activation.

---

## 34. External human root approval

Forward activation requires explicit authenticated approval from an eligible root approver recognized under predecessor `N` and exercised through the External Root Authority process.

The candidate, reviewer, implementation agent, or ordinary autonomous workflow cannot be the sole source of Root Activation authority.

A root approver MAY also have participated in planning or review where `N` permits.

Root approval nevertheless remains a distinct authenticated external-root action.

---

## 35. Stable root-approval subject

Root approval MUST bind the **stable transition subject**, not a volatile external root-state revision that the activation ceremony itself is expected to change.

A root approval record conceptually binds:

```text
approval identity

authenticated approver identity

root_change_id

active predecessor N

candidate N+1

candidate runtime artifact identity

required deterministic evidence identities

required semantic evidence identities

canonical Root Trust Anchor identity

exact requested activation N → N+1

approval validity / expiry where applicable
```

It MUST NOT require a pre-barrier root-state revision to remain unchanged after the externally authorized barrier-close operation.

Volatile transition-state revisions are bound through readiness evaluation and external CAS operations instead.

---

## 36. Root approval composition

If predecessor `N` requires multiple approvals, composition is defined through explicit structured rules belonging to `N`.

The system MUST NOT infer:

- majority;
- quorum;
- seniority;
- equivalence;
- latest-wins

from prose or duplicated records.

A natural-language GitHub comment such as:

```text
approved
```

does not constitute root approval solely because a human wrote it.

---

## 37. Approval cannot waive failed evidence

External root approval is an additional requirement, not an override.

Unless `N` explicitly defines a permitted structured alternative, approval cannot convert:

```text
deterministic validation failure

semantic changes_required

semantic unable_to_determine

missing evidence

stale evidence

candidate mismatch

runtime-artifact mismatch

dependency-closure failure
```

into Root Activation permission.

---

## 38. Candidate freshness

Root evidence and approval are exact-candidate-bound.

Any security-relevant modification to `N+1` creates a new candidate by default.

This includes changes to:

- trusted code;
- policy;
- schemas;
- enforcement configuration;
- membership;
- dependencies;
- build configuration;
- actual runtime artifact;
- deployment composition;
- candidate manifest.

Earlier evidence does not silently transfer.

---

## 39. Active-policy freshness before barrier acquisition

Evidence for:

```text
N → N+1
```

becomes stale if the active manifest ceases to be `N` before this transition acquires the external barrier.

If another transition:

```text
N → M
```

completes first, the outstanding `N → N+1` proposal is stale by default.

It requires reevaluation under the now-active trusted system.

---

## 40. No autonomous root repair loop

Initial v2 provides no autonomous trusted-core repair loop.

If root validation or review identifies required changes:

```text
candidate A
    ↓
rejected
    ↓
candidate B
```

candidate `B` is a new root candidate.

It requires fresh applicable validation, semantic review, external approval, barrier acquisition, and readiness.

Ordinary task `repair_policy` does not govern root candidates.

---

## 41. Root Transition Barrier ownership

The Root Transition Barrier is part of the **externally protected root state**, not ordinary canonical control state.

Ordinary:

```text
control_state_write
target_publish
merge
controlled_runtime
```

capabilities cannot open, close, replace, or bypass it.

Candidate `N+1` therefore cannot control the barrier governing completion of its own activation.

---

## 42. Protected-operation start rule

Normal externally protected root state is:

```text
{
    active_manifest: N,
    transition: open,
    revision: R
}
```

An ordinary protected operation may cross its security-relevant start boundary only when fresh authoritative root state establishes:

```text
transition == open
AND
active_manifest == operation.expected_policy_identity
```

in addition to all other ordinary protected-operation start conditions.

For the ordinary state machine this applies before:

```text
reserved → performing
```

is durably established.

---

## 43. Barrier acquisition

After deterministic validation, semantic review, and external approval, the External Root Authority conditionally changes:

```text
{
    active_manifest: N,
    transition: open,
    revision: R
}
```

to:

```text
{
    active_manifest: N,
    transition: {
        root_change_id: X,
        from: N,
        to: N+1,
        readiness_id: null,
        release_verification_id: null
    },
    revision: R+1
}
```

The mutation MUST be conditional on exact prior authoritative state.

Once acquired, no new ordinary protected operation may cross `reserved → performing`.

---

## 44. Barrier governance across the epoch switch

The root transition beginning under `N` remains governed by:

```text
transition.from = N
```

and by the External Root Authority until either:

- the transition is successfully verified and externally released; or
- the transition is externally aborted or recovered.

Changing:

```text
active_manifest: N → N+1
```

while the transition remains closed does not allow `N+1` to change:

- completion requirements;
- post-activation verification requirements;
- pre-release capability-fence requirements;
- release-verification requirements;
- pre-release rollback conditions;
- transition state;
- barrier-release authority.

---

## 45. Root quiescence

After barrier closure, protected operations already in:

```text
performing
indeterminate
```

are identified.

Initial v2 permits forward activation only after there are **zero unresolved protected operations** in either state.

A safely completable `performing` operation MAY finish under `N`.

Uncertain effects MUST be reconciled.

The initial system does not migrate a performing protected operation across policy epochs.

If quiescence cannot be established, forward activation does not proceed.

---

## 46. Reserved operations during transition

Operations remaining `reserved` have not crossed the protected-effect start boundary.

While the barrier is closed, they MUST NOT enter `performing`.

After successful barrier release under `N+1`, they require fresh start evaluation under `N+1`.

Reservation under `N` does not authorize start under `N+1`.

---

## 47. Final freshness evaluation before readiness

Once quiescence is established, trusted evaluation explicitly loaded from:

```text
transition.from = N
```

rechecks:

```text
active manifest is still exactly N

barrier belongs to exact root_change_id X

transition.from is exactly N

transition.to is exactly candidate N+1

candidate is exactly N+1

runtime artifact is unchanged

deterministic evidence remains applicable

semantic evidence remains applicable

external approval remains applicable

Root Change Package remains exact

quiescence still holds

canonical Root Trust Anchor is exact
```

Failure of any required check prevents readiness.

---

## 48. Root Activation Readiness Record

Only after:

```text
barrier closure
+
quiescence
+
final freshness evaluation
```

may trusted logic governed by exact predecessor `N` produce a **Root Activation Readiness Record**.

It conceptually binds:

```text
readiness_id

root_change_id

governing manifest N

candidate N+1

candidate runtime artifact identity

Root Change Package identity

deterministic evidence identities

semantic evidence identities

external root-approval identity

exact held transition identity X

evaluated_root_revision R

canonical Root Trust Anchor identity

pre-release rollback target N

activation subject

readiness = ready
```

`evaluated_root_revision` is the exact externally protected root-state revision against which readiness was calculated.

The readiness record is a machine-readable result of `N`-governed root evaluation.

It is not Root Activation authority.

---

## 49. Readiness sealing consumes the evaluated revision

The External Root Authority MUST seal the exact readiness identity into externally protected root state before changing `active_manifest`.

Suppose readiness `H` was established against:

```text
{
    active_manifest: N,
    transition: X(readiness_id = null),
    revision: R
}
```

and records:

```text
evaluated_root_revision = R
```

The sealing operation conditionally consumes that exact evaluated state:

```text
CAS

{
    active_manifest: N,
    transition: X(readiness_id = null),
    revision: R
}

→

{
    active_manifest: N,
    transition: X(readiness_id = H),
    revision: R+1
}
```

The sealing mutation MUST verify:

```text
H.evaluated_root_revision == R
```

and that all other bound identities correspond to transition `X`.

The expected revision for later activation is now `R+1`.

The intentional sealing revision change does not itself invalidate readiness `H`; it is the trusted conditional handoff consuming readiness for revision `R`.

---

## 50. Sealed-readiness identity rule

After readiness `H` is sealed:

- candidate identity MUST NOT change;
- runtime-artifact identity MUST NOT change;
- Root Change Package identity MUST NOT change;
- required evidence identities MUST NOT be substituted;
- external approval identity MUST NOT be substituted;
- transition subject MUST NOT change;
- governing predecessor `transition.from` MUST NOT change.

Any such identity change invalidates the transition and requires abort/re-evaluation.

A readiness identity stored only in ordinary mutable state is insufficient for Root Activation.

---

## 51. Mutable applicability after readiness sealing

Immutable identity equality does not by itself prove continuing applicability.

A bound record may retain the same identity while becoming inapplicable because of:

- expiry;
- revocation;
- supersession;
- changed external authorization state;
- changed policy-recognized issuer eligibility;
- changed security-relevant authoritative state not frozen by the root barrier.

Therefore immediately before Root Activation, every security-relevant condition whose applicability can change without changing its immutable identity MUST be freshly established under predecessor `N`.

Where safe activation depends on mutable authoritative state remaining unchanged, that state MUST be:

- made invariant for the closed transition;
- represented in an atomic/platform-enforced activation precondition;
- or freshly checked through a mechanism whose result remains safely bound to the mutation.

If none can establish continuing applicability, Root Activation fails closed.

---

## 52. Initial Phase 1 freshness strategy

Initial Phase 1 SHOULD keep root evidence and approval semantics sufficiently simple that continuing applicability can be deterministically re-established immediately before activation.

It SHOULD NOT introduce a complex distributed lease or generalized transactional system merely to preserve root evidence.

The External Root Authority's atomic state protects:

```text
active_manifest
transition
sealed readiness identity
root revision
```

Other mutable security-relevant conditions still satisfy the fresh-applicability rule.

---

## 53. Final Root Activation preconditions

Immediately before the external pointer mutation, transition-completion logic governed by:

```text
transition.from = N
```

MUST establish:

```text
current active manifest == N

current transition == exact X

transition.from == exact N

transition.to == exact N+1

sealed readiness == exact H

current root revision == sealing result revision

candidate identity still matches H

runtime artifact identity still matches H

Root Change Package still matches H

required deterministic evidence is still applicable

required semantic evidence is still applicable

external root approval is still applicable

canonical Root Trust Anchor is unchanged

all other mutable activation conditions
remain applicable under N
```

A stale immutable record identity does not satisfy an applicability check merely by still existing.

---

## 54. Final Root Activation transaction

The External Root Authority performs forward Root Activation only from exact sealed state.

Conceptually:

```text
{
    active_manifest: N,
    transition: {
        root_change_id: X,
        from: N,
        to: N+1,
        readiness_id: H,
        release_verification_id: null
    },
    revision: R
}
```

becomes:

```text
{
    active_manifest: N+1,
    transition: {
        root_change_id: X,
        from: N,
        to: N+1,
        readiness_id: H,
        release_verification_id: null
    },
    revision: R+1
}
```

The barrier remains closed.

The mutation MUST be conditional on the exact externally protected prior state.

Any additional mutable state on which safety depends MUST satisfy Section 51 before mutation and must be atomically/platform-bound where intervening change could invalidate the decision.

A prior read followed by unconditional mutation is insufficient.

---

## 55. Single-pointer activation

Root Activation changes one authoritative active-manifest identity to a complete immutable candidate manifest.

Trusted state SHOULD NOT be activated by independently rewriting multiple live policy/configuration resources.

Preferred model:

```text
immutable N
immutable N+1

externally protected root state:

active_manifest: N
        ↓
active_manifest: N+1

transition remains closed
```

If equivalent atomicity cannot be established, Root Activation fails closed.

---

## 56. Pre-release activation interval

After the pointer changes to `N+1` but before the barrier reopens, the system is in a **pre-release activation interval**:

```text
active_manifest = N+1

transition.from = N

transition.to = N+1

transition = closed
```

No ordinary protected operation may start under `N+1`.

The transition remains governed by exact immutable predecessor:

```text
transition_governing_manifest = transition.from = N
```

until release or external recovery.

---

## 57. Predecessor-governed transition verifier

Any trusted verifier deciding whether transition `X` may complete MUST load its governing rules and verifier configuration from exact:

```text
transition.from
```

not from:

```text
active_manifest
```

while the transition is closed.

Therefore, after pointer switch:

```text
active_manifest = N+1
transition.from = N
```

the verifier still uses `N`.

Candidate `N+1` output may be examined as evidence.

`N+1` MUST NOT be the authoritative interpreter of rules deciding whether its own barrier may be released.

---

## 58. Actual deployed/executing trusted identity

Before barrier release, verification MUST establish more than the existence or resolvability of candidate artifacts.

For every trusted security context that will be capable of exercising protected authority after release, the verifier MUST establish:

```text
expected trusted security-context identity
+
expected N+1 runtime artifact/configuration identity
=
actual deployed/executing trusted identity
```

Where applicable this includes:

```text
Control-State Gate

Target-Publication Gate

Merge Gate

Controlled Runtime Gate

other trusted enforcement or admission contexts
enabled after release
```

The exact mechanism may later use:

- deployment metadata;
- executable digest;
- container image digest;
- package identity;
- signed attestation;
- process/runtime identity;
- another trusted deterministic deployment mechanism.

Phase 0 does not select the implementation mechanism.

An artifact merely existing or resolving is insufficient.

---

## 59. Pre-release capability fencing

Verification of candidate `N+1` trusted security contexts MUST NOT require trusting those candidate contexts to refrain from protected action.

While transition `X` remains closed:

> candidate `N+1` security contexts MUST NOT be capable of producing protected consequential effects unless an enforcement mechanism outside candidate `N+1` independently prevents such effects.

The required invariant is:

```text
while transition != open:

N+1 cannot produce a protected consequential effect
```

Candidate compliance with the barrier is not sufficient evidence of this invariant.

---

## 60. Initial pre-release fencing patterns

Initial Phase 1 MAY satisfy pre-release capability fencing through a small number of explicit mechanisms.

For example:

```text
candidate N+1 context
        ↓
starts without usable protected credential/capability
        ↓
identity and behavior are verified
        ↓
protected capability enabled only after release
```

or:

```text
candidate N+1 context
        ↓
may possess a service identity
        ↓
independent external/platform enforcement
checks transition == open
before allowing protected effect
```

The second enforcement mechanism MUST be outside candidate `N+1`'s control.

A candidate implementation merely containing:

```text
if transition != open:
    deny()
```

does not independently establish pre-release capability fencing.

---

## 61. Pre-release capability inventory

The transition verifier MUST establish which trusted security contexts and capability bindings will become effective after release.

Conceptually the verified inventory includes, where applicable:

```text
security-context identity

exact N+1 runtime artifact/configuration identity

protected capability type

credential/service identity

external enforcement/fencing mechanism

intended post-release capability binding
```

The inventory MUST come from trusted structured configuration.

It MUST NOT be reconstructed through candidate prose, process-name guessing, or semantic interpretation.

Unknown protected capability binding fails closed.

---

## 62. Post-activation verification

While the barrier remains closed, deterministic verification governed by exact predecessor `N`, or External Root Authority mechanisms applying rules established by `N`, MUST establish where required:

```text
external root state identifies exact N+1

transition remains exact X

transition.from remains exact N

sealed readiness remains exact H

manifest N+1 resolves exactly

manifest integrity is valid

expected N+1 trusted runtime artifacts resolve

actual deployed/executing trusted security contexts
match exact N+1 artifact identities

root-managed dependency closure resolves

required external TCB assumptions are available

trusted-core membership resolves

trusted enforcement configuration resolves

pre-release capability fencing is effective

intended protected-capability bindings are exact

protected gates are configured to recognize N+1
after release

stale N instances cannot pass new-policy protected gates

candidate N+1 has not become authority over
transition-completion checks
```

Verification SHOULD be non-mutating with respect to ordinary canonical security-relevant operational state except for explicitly transition-scoped verification records.

Candidate-controlled success claims remain evidence only.

---

## 63. Release Verification Record

After successful post-activation verification and while pre-release capability fencing remains effective, predecessor-governed trusted logic MAY produce a **Release Verification Record**.

It conceptually binds:

```text
release_verification_id

root_change_id

governing manifest N

active candidate N+1

sealed readiness H

exact transition X

evaluated_root_revision R

actual deployed/executing trusted identities

intended protected-capability bindings

pre-release capability-fence identities/state

post-activation verification evidence identities

canonical Root Trust Anchor identity

release = verified
```

The Release Verification Record is evidence that the exact candidate deployment is suitable for release under rules established by predecessor `N`.

It does not itself grant authority to open the barrier.

---

## 64. Release-verification sealing

Before barrier release, the External Root Authority MUST seal the exact Release Verification Record identity into externally protected transition state.

Suppose release verification `V` was established against:

```text
{
    active_manifest: N+1,
    transition: X(
        readiness_id = H,
        release_verification_id = null
    ),
    revision: R
}
```

with:

```text
V.evaluated_root_revision = R
```

The External Root Authority conditionally changes:

```text
CAS

{
    active_manifest: N+1,
    transition: X(
        readiness_id = H,
        release_verification_id = null
    ),
    revision: R
}

→

{
    active_manifest: N+1,
    transition: X(
        readiness_id = H,
        release_verification_id = V
    ),
    revision: R+1
}
```

The sealing operation MUST verify that `V` applies to the exact transition, candidate, readiness record, deployed identities, and root revision being consumed.

The resulting `R+1` becomes the external root-state revision expected by barrier release.

---

## 65. Release-state freshness

Sealing release-verification identity `V` does not make mutable deployment or capability state permanently valid.

Immediately before barrier release, predecessor-governed or external deterministic verification MUST establish that every mutable condition on which safe release depends is still applicable.

At minimum this includes:

```text
active_manifest == exact N+1

transition == exact X

transition.from == exact N

transition.to == exact N+1

readiness_id == exact H

release_verification_id == exact V

post-activation verification remains applicable

actual deployed/executing trusted identities
still equal verified N+1 identities

pre-release capability fencing remains effective

intended protected-capability bindings remain exact

no stale N or unverified context can exercise
protected authority after release
```

If a security-relevant release condition can change between observation and barrier opening, it MUST be:

- frozen for the transition;
- atomically/platform-bound to release;
- independently fenced so the change cannot create an unauthorized effect;
- or established through an equivalent conditional mechanism.

Otherwise the barrier remains closed.

---

## 66. Candidate deployment cannot self-unfence

Candidate `N+1` MUST NOT possess authority to:

- enable its own protected credential;
- remove its own pre-release fence;
- alter the external capability binding used for release;
- replace its verified runtime artifact after verification;
- cause an unverified security context to inherit its intended protected capability.

Such mutations require an independent trusted or externally controlled mechanism.

If candidate-controlled deployment state can invalidate the verified release subject without an independent fence or conditional binding, release MUST NOT occur.

---

## 67. Barrier-release transaction

Only after exact release verification and fresh release-state checks may External Root Authority open the transition.

Conceptually:

```text
{
    active_manifest: N+1,
    transition: {
        root_change_id: X,
        from: N,
        to: N+1,
        readiness_id: H,
        release_verification_id: V
    },
    revision: R
}
```

becomes:

```text
{
    active_manifest: N+1,
    transition: open,
    revision: R+1
}
```

Release MUST be conditional on:

```text
exact transition X

exact transition.from = N

exact transition.to = N+1

exact readiness H

exact release verification V

exact external root-state revision

continuing applicability of release conditions
```

A prior verification followed by an unconditional barrier-opening mutation is insufficient where intervening deployment or capability change could invalidate the release decision.

---

## 68. Capability enablement at release

Where the chosen pre-release fencing model withholds usable protected capability from `N+1`, capability enablement MUST be coordinated with barrier release so there is no interval in which:

```text
N+1 has protected capability
AND
release conditions are no longer guaranteed
```

A permitted implementation MAY use:

- one platform-enforced atomic transition;
- a protected external capability gate whose decision depends on authoritative `transition == open`;
- another mechanism proving equivalent non-bypassable ordering.

Phase 0 does not select the platform mechanism.

The candidate itself MUST NOT be the enforcement boundary establishing this ordering.

---

## 69. Point of policy-epoch release

The security-relevant autonomous policy handover completes only at:

```text
transition: X → open
```

after successful predecessor-governed release verification.

Before that point:

```text
transition_governing_manifest = N
```

for transition completion.

After that point:

```text
normal_governing_manifest = active_manifest = N+1
```

for newly starting ordinary protected operations.

This provides one explicit handover boundary and avoids an interval in which `N` and `N+1` can independently authorize protected starts.

---

## 70. Failure before active-manifest change

If the transition is abandoned before `active_manifest` changes from `N`, External Root Authority MAY reopen the barrier only after reconciliation establishes:

```text
active manifest remains exactly N

transition belongs to expected root_change_id

no root-state mutation is indeterminate

ordinary protected effects are reconciled
```

The abort/reopen operation remains externally controlled.

---

## 71. Pre-release rollback

If the pointer has changed:

```text
N → N+1
```

but the transition barrier has **not** been released, External Root Recovery MAY restore the active pointer to exact predecessor `N`.

This is the initial system's only generic pointer-rollback case.

It is bounded by the invariants that:

```text
no ordinary protected operation has entered performing
under N+1

and

pre-release capability fencing prevented N+1
from producing protected consequential effects
```

Post-activation verification is not permitted to make ordinary canonical protected mutations under `N+1`.

---

## 72. Pre-release rollback transaction

Conceptually:

```text
{
    active_manifest: N+1,
    transition: X(N → N+1, readiness H),
    revision: R
}
```

may be conditionally restored to:

```text
{
    active_manifest: N,
    transition: X(N → N+1, readiness H),
    revision: R+1
}
```

The barrier remains closed.

Rollback MUST require:

```text
current transition == exact X

transition.from == exact N

transition.to == exact N+1

current active manifest == exact N+1

rollback target == exact predecessor N

transition has never been released under N+1

pre-release capability fencing/reconciliation
establishes no protected N+1 effect occurred
```

No arbitrary replacement manifest is permitted.

---

## 73. Verification after pre-release rollback

After restoring pointer `N`, External Root Recovery MUST verify:

```text
exact N resolves

trusted runtime artifacts required by N resolve

actual trusted execution contexts intended
for resumed operation match N

root-managed dependency closure for N resolves

no ordinary protected work began under N+1

no protected N+1 effect escaped the pre-release fence

external root state is internally consistent

no unresolved external root mutation remains
```

Only then may External Root Authority reopen the transition barrier under `N`.

---

## 74. No generic pointer rollback after release

Once:

```text
active_manifest = N+1
transition = open
```

generic pointer rollback is no longer assumed safe.

At that point `N+1` may have performed protected operations or changed canonical security-relevant state.

Therefore:

```text
after release
    ↓
generic pointer rollback unavailable by default
    ↓
External Root Recovery required
```

Initial v2 deliberately does **not** implement a general backwards-compatible state-migration theorem.

A future active root policy MAY introduce a structured safe rollback mechanism through the root-change procedure.

---

## 75. Why initial rollback is narrow

Restricting simple rollback to the pre-release interval avoids requiring Phase 1 trusted code to determine whether an arbitrary previous trusted version can interpret every possible later authoritative state.

It also avoids unsafe generic restoration of old snapshots that could erase knowledge of real:

- merges;
- publications;
- controlled-runtime effects;
- control-state mutations;
- external effects.

After protected operation resumes under `N+1`, recovery is an exceptional external-root procedure.

---

## 76. Indeterminate Root Activation or release

If an external root-state mutation may have occurred but its result is uncertain:

- the barrier is treated as closed unless exact authoritative state proves otherwise;
- no new protected operation starts until state is reconciled;
- the mutation is not blindly retried;
- External Root Authority reconciles authoritative root state.

Possible states include:

```text
N remains active with transition closed

N+1 is active with transition closed

N+1 is active with transition open

unexpected manifest or transition state is present

root state cannot be verified
```

Only known exact states admit deterministic normal reconciliation.

Unexpected or unverifiable state requires External Root Recovery.

---

## 77. Stale control-plane instances

An instance still using cached `N` after successful release of `N+1` MUST NOT perform a new protected action.

Every protected start reads fresh externally protected root state.

Thus:

```text
instance expects N

external root state says:
    active_manifest = N+1
    transition = open

        ↓

protected start denied
```

Cached policy does not override authoritative root state.

---

## 78. External Root Recovery

External Root Recovery is part of the External Root Authority.

It exists so recovery does not depend solely on the currently active autonomous trusted system.

After policy-epoch release, recovery MAY:

- halt protected autonomy;
- externally fence protected capability holders;
- inspect exact authoritative state;
- restore a previously reviewed trusted system only through a specifically established recovery procedure;
- conduct a new external re-bootstrap where necessary.

It MUST NOT become a shortcut for activating arbitrary unreviewed new trusted code.

---

## 79. Recovery fencing

If normal quiescence cannot be established during external recovery, changing only the active-manifest pointer is insufficient.

A process from the old epoch may still possess external capability capable of protected effects.

Before protected autonomy may resume, External Root Recovery MUST independently establish:

```text
old/untrusted epoch can no longer produce
protected consequential effects
```

This is **recovery fencing**.

Pre-release capability fencing and recovery fencing serve different purposes:

- pre-release fencing prevents an untrusted candidate from exercising authority before release;
- recovery fencing prevents a failed or stale epoch from continuing to exercise authority during exceptional recovery.

---

## 80. External recovery-fence inventory

External Root Authority MUST maintain enough explicit administrative knowledge to determine which external identities/security contexts may require fencing.

Where applicable these include:

```text
control-state service identity

target-publication identity

merge identity

controlled-runtime identity

privileged runner/security context

deployment identity

hardware-connected execution identity

other protected external capability holders
```

The inventory MUST be structured or otherwise authoritative under External Root Authority.

It MUST NOT be reconstructed from candidate prose or guessed solely from observed running processes.

If the protected capability inventory is incomplete, external recovery cannot safely resume autonomy.

---

## 81. Recovery-fencing mechanisms

Depending on deployment, external fencing MAY include:

- revoking or rotating credentials;
- disabling service identities;
- disabling protected application installations;
- stopping or isolating trusted hosts/security contexts;
- disabling protected runtime access;
- revoking deployment or hardware access;
- another platform-enforced denial mechanism.

This document does not mandate one mechanism.

It mandates the postcondition:

```text
the fenced epoch cannot exercise protected effects
```

---

## 82. Failure to fence

If normal quiescence is unavailable and effective recovery fencing cannot be established:

```text
protected autonomy remains halted
```

The system MUST NOT treat pointer manipulation alone as successful operational recovery.

External administrative investigation is then required.

---

## 83. Break-glass recovery

Break-glass recovery exists for cases such as:

- trusted core cannot start;
- policy loader is broken;
- trusted configuration cannot load;
- normal transition coordination is unavailable;
- active system cannot reconcile its own state.

Break-glass recovery MUST:

- remain inaccessible to ordinary automation;
- authenticate the External Root Recovery operator;
- close or externally enforce the equivalent of the transition barrier;
- fence protected capabilities when quiescence cannot be established;
- operate only on exact known root identities or a separately approved re-bootstrap target;
- fail closed on ambiguous identity;
- avoid arbitrary unreviewed new trusted code;
- verify the recovered trusted system before re-enabling autonomy.

---

## 84. External Root Migration

Changing the External Root Authority or canonical Root Trust Anchor requires a separate **External Root Migration / Re-bootstrap Ceremony**.

Examples include changing:

- root-state storage technology;
- root administrative identity system;
- root write credentials/security mechanism;
- break-glass authority;
- canonical root-anchor designation mechanism.

This is not ordinary autonomous `N → N+1` activation.

---

## 85. External-root migration continuity

External Root Migration MUST preserve a single canonical external trust anchor whenever protected autonomy is permitted.

A suitable initial ceremony is:

```text
existing External Root Authority
        ↓
close/fence protected autonomy
        ↓
record exact active manifest N
        ↓
establish replacement external root infrastructure
        ↓
initialize replacement root state
to EXACT same active manifest N
        ↓
verify replacement root infrastructure
        ↓
externally switch canonical Root Trust Anchor designation
        ↓
prove old authority can no longer compete
        ↓
verify exact active-manifest continuity
        ↓
re-enable protected autonomy
```

The migration does not implicitly activate a new autonomous trusted manifest.

---

## 86. Exactly one canonical Root Trust Anchor

Whenever protected autonomous operation is enabled:

> exactly one External Root Authority designation identifies exactly one canonical Root Trust Anchor.

Two competing anchors with different authoritative values MUST NOT simultaneously be accepted.

During migration, if uniqueness cannot be established, protected autonomy remains fenced.

The autonomous manifest MUST NOT select its preferred canonical external anchor through candidate-controlled configuration.

Canonical external-root selection is an external administrative fact.

---

## 87. Retirement of old root infrastructure

External Root Migration is incomplete until old root infrastructure can no longer create a competing authoritative root-state mutation, unless External Root Authority explicitly retains it as a non-authoritative recovery mechanism with deterministic precedence rules.

Initial v2 SHOULD prefer retirement or revocation of the old authoritative write path.

Ambiguous dual authority fails closed.

---

## 88. Changes to autonomous root rules

Changes to:

- root-impact determination;
- Root Change Package rules;
- semantic root-review requirements;
- readiness rules;
- trusted-core membership;
- protected-operation epoch checks;
- barrier/readiness logic;
- pre-release verification rules;
- transition-governing-manifest rules;
- pre-release capability-fencing rules;
- release-verification rules

are autonomous root changes:

```text
N → N+1
```

and are evaluated using corresponding rules from predecessor `N`.

Weaker candidate rules do not apply to the candidate's own activation.

---

## 89. Trusted-core membership changes

If `N` considers component `X` trusted and `N+1` proposes:

```text
X no longer trusted
```

then `X` remains root-protected while evaluating and activating `N+1`.

Moving trusted behavior from `X` elsewhere also remains a root-boundary change.

Membership changes become authoritative only after successful policy-epoch release.

---

## 90. Capability and credential changes

A proposed autonomous-system change is root-impacting if it changes which component may exercise a protected capability governed by the autonomous trusted boundary.

Examples include:

```text
control-state capability

target-publication capability

merge capability

controlled-runtime capability

service identity mapping

credential routing

protected IPC boundary
```

External Root Authority credentials and canonical external-root mechanisms remain outside candidate control and require External Root Migration to change.

---

## 91. External trust-dependency changes

Changing an external TCB dependency can be security-relevant even when trusted source code is unchanged.

The active trusted system determines which ordinary external TCB assumptions are root-protected.

If a proposed change alters the External Root Authority itself, External Root Migration applies instead.

Unknown changes to required trust dependencies fail closed.

---

## 92. Root operation identities and idempotency

Barrier closure, readiness sealing, activation, release-verification sealing, barrier release, abort, pre-release rollback, fencing, recovery, and external migration MUST use stable operation identities where applicable.

A repeated operation identity MUST NOT silently duplicate effects.

An existing postcondition may count as idempotently complete only when exact identity proves it is the intended result of that exact operation.

Superficially similar root state is insufficient.

---

## 93. Concurrent root transitions

Conflicting root transitions from the same initial state cannot both proceed.

For example:

```text
N → A
N → B
```

compete for:

```text
{
    active_manifest: N,
    transition: open,
    revision: R
}
```

Only one can acquire the externally protected transition state.

The other becomes stale and requires reevaluation against later root state.

---

## 94. Audit requirements

Each root transition MUST produce enough structured records to reconstruct:

```text
active predecessor

candidate successor

root_change_id

candidate/runtime artifact identity

changed-resource inventory

dependency closure

deterministic validation evidence

semantic-review evidence

external approval

barrier acquisition

quiescence/reconciliation

readiness record

evaluated root revision

readiness sealing

sealed activation revision

final mutable-applicability checks

external root operator

active-manifest mutation

actual deployed/executing trusted identities

pre-release capability-fence state

intended protected-capability bindings

predecessor-governed release verification

release-verification identity

release-verification sealing

final release-state checks

barrier release

pre-release rollback or external recovery where applicable
```

Audit records provide traceability.

They do not create root authority.

---

## 95. Root change and ordinary lifecycle state

Root authority cannot be inferred from ordinary task states such as:

```text
admitted
evaluating
integration_ready
completed
```

Nor can Root Activation authority come from:

- ordinary operation success;
- semantic approval alone;
- PR approval;
- repository merge;
- issue closure;
- candidate existence.

Root records MAY reuse compatible operation/idempotency concepts.

They do not inherit ordinary lifecycle authority.

---

## 96. Genesis bootstrap

The first active trusted system has no predecessor autonomous system capable of authorizing it.

Genesis is therefore an external trust decision.

Initial bootstrap uses an External Root Authority ceremony:

```text
Phase 0 frozen design
        ↓
initial trusted-core implementation
        ↓
deterministic validation
        ↓
human/GPT architectural review
        ↓
external human root acceptance
        ↓
immutable genesis manifest G
        ↓
exact genesis runtime artifact
        ↓
initialize external root state:
active_manifest = G
transition = open
```

The autonomous system MUST NOT claim genesis was self-authorized.

---

## 97. Genesis record

Genesis MUST record at least:

```text
genesis manifest identity

Core Policy identity

trusted-core runtime-artifact identity

trusted schemas

trusted enforcement configuration

trusted-core membership

root-managed dependency closure

declared external TCB dependencies

canonical Root Trust Anchor identity

External Root Authority model

root administrative identities

External Root Recovery authority

recovery-fence inventory

bootstrap approver identity

bootstrap timestamp
```

After genesis, ordinary autonomous root evolution follows:

```text
G → G+1
```

under active `G`.

External Root Authority replacement follows External Root Migration instead.

---

## 98. Initial Phase 1 operating model

The smallest acceptable initial model is:

```text
GPT / Codex / human
        │
        ▼
candidate N+1
        │
        ▼
exact trusted runtime artifact
        │
        ▼
deterministic validation under N
        │
        ▼
semantic review under REVIEW_MODEL + N
        │
        ▼
Evidence Admission
        │
        ▼
authenticated external root approval
        │
        ▼
External Root Authority closes barrier
        │
        ▼
drain performing / reconcile indeterminate
        │
        ▼
final freshness validation using transition.from = N
        │
        ▼
Readiness H
with evaluated_root_revision = R
        │
        ▼
External Root Authority CAS-seals H
        │
        ▼
fresh mutable-applicability checks under N
        │
        ▼
CAS active_manifest N → N+1
barrier remains closed
        │
        ▼
deploy/start exact N+1 trusted contexts
under independent pre-release capability fence
        │
        ▼
verify actual N+1 deployed identities
        │
        ▼
verify exact intended capability bindings
        │
        ▼
Release Verification V under N
        │
        ▼
External Root Authority seals V
        │
        ▼
fresh release-state verification
        │
        ├── FAIL
        │      ↓
        │ exact pre-release rollback → N
        │
        └── PASS
               ↓
External Root Authority releases barrier /
independently enables protected capability
               ↓
N+1 becomes governing policy for
new protected-operation starts
```

No ordinary autonomous component possesses External Root Authority.

---

## 99. Required fixture scenarios

Root-path testing SHOULD include at least:

```text
valid N → N+1 activation

candidate modifies own acceptance rules

candidate removes itself from trusted membership

candidate moves trusted logic outside prior location

candidate introduces unregistered runtime dependency

candidate introduces dynamic plugin loading

approved source but wrong runtime artifact

candidate attempts ordinary issue-contract root modification

candidate self-approval

reviewer attempts Root Activation

human GitHub comment incorrectly treated as root approval

approval bound to wrong candidate

approval expires after readiness seal

approval revoked after readiness seal

candidate changes after approval

barrier acquisition conflict

protected operation attempts reserved → performing
after barrier closure

existing performing operation drains

indeterminate ordinary operation blocks activation

readiness generated before quiescence is rejected

readiness H evaluated against revision R

readiness seal against wrong evaluated revision rejected

successful readiness seal R → R+1

candidate changes after readiness seal

activation without exact sealed readiness rejected

mutable applicability changes after readiness seal

transition verifier incorrectly loads active_manifest N+1
instead of transition.from N

candidate N+1 attempts to verify/release own barrier

manifest N+1 resolves but old N trusted process still runs

expected and actual deployed trusted artifact mismatch

candidate N+1 receives usable merge credential
before release without independent fence

candidate N+1 ignores closed barrier

independent pre-release fence prevents protected effect

pre-release capability inventory incomplete

intended capability binding targets wrong process identity

release verification V bound to wrong deployment

deployment changes after release verification

capability binding changes after release verification

release verification sealed against wrong root revision

barrier release attempted without sealed V

fresh release-state verification detects changed deployment

candidate attempts to remove its own capability fence

successful exact deployed-artifact and capability verification

N-governed post-activation verification failure

exact pre-release rollback N+1 → N

pre-release rollback confirms no protected N+1 effect occurred

attempted generic pointer rollback after barrier release

activation or release mutation outcome indeterminate

stale N instance attempts protected operation

normal recovery cannot quiesce old epoch

external recovery fences old protected capabilities

fencing inventory incomplete

root pointer changed but old protected capability remains active

break-glass restoration procedure

break-glass attempt to activate arbitrary unreviewed manifest

candidate attempts External Root Authority mutation

external migration initializes new anchor to same active N

external migration temporarily exposes competing anchors

old root write authority not retired

genesis bootstrap
```

---

## 100. Conformance invariants

The self-modification design remains conformant only while all of the following hold:

1. The autonomous trust chain terminates at an explicit External Root Authority.
2. Ordinary autonomous components cannot manufacture or amplify External Root Authority.
3. External-root infrastructure changes require External Root Migration rather than ordinary `N → N+1`.
4. Root-impacting changes cannot use the ordinary issue-contract authority path.
5. Root impact is determined under the previously active trusted boundary.
6. Candidate changes cannot remove themselves from root review.
7. Trusted execution uses a closed-world dependency model.
8. The actual trusted runtime artifact has immutable identity.
9. Source/build approval does not substitute for runtime-artifact identity.
10. External TCB dependencies are explicitly represented.
11. Unexpected trusted dynamic loading fails closed.
12. Repository merge/main state does not imply activation.
13. One exact Active Trusted Manifest identifies the active autonomous trusted system.
14. Active-manifest identity, transition state, readiness identity, release-verification identity, and revision share one externally protected authoritative boundary or equivalent atomic mechanism.
15. Ordinary protected capabilities cannot mutate or bypass that boundary.
16. Candidate `N+1` identifies expected predecessor `N`.
17. A closed transition binds exact `transition.from` and `transition.to`.
18. `transition.from` is the governing manifest for transition completion.
19. Transition-completion logic never selects its governing rules from candidate `N+1` while the transition is closed.
20. The transition remains governed by `N` and External Root Authority until external barrier release.
21. Candidate-provided tests cannot become sole self-certifying authority.
22. Root semantic review reuses `REVIEW_MODEL.md`.
23. Semantic review never grants Root Activation.
24. Explicit authenticated external human root approval is required.
25. Root approval binds the stable transition subject rather than a volatile barrier-era revision.
26. Human comments do not create root approval.
27. Human approval cannot override mandatory failed evidence.
28. Candidate modification invalidates candidate-bound evidence by default.
29. Initial root repair is not an autonomous loop.
30. Barrier acquisition is conditional on exact external root state.
31. No new protected operation crosses `reserved → performing` after barrier closure.
32. Forward activation requires zero unresolved `performing` or `indeterminate` protected operations.
33. Reserved operations are freshly reevaluated after policy-epoch release.
34. Candidate `N+1` cannot release or weaken the barrier governing its own activation.
35. Readiness is created only after barrier closure, quiescence, and final freshness validation.
36. Readiness binds the exact root revision against which it was evaluated.
37. Readiness does not grant Root Activation.
38. Readiness sealing conditionally consumes the exact evaluated root revision.
39. The intentional readiness-sealing revision increment does not itself invalidate readiness.
40. The post-seal root revision becomes the exact root-state precondition for activation.
41. Immutable identity equality does not substitute for fresh applicability.
42. Expired, revoked, superseded, or otherwise inapplicable evidence/approval cannot authorize Root Activation merely because its identity remains unchanged.
43. Mutable authoritative state on which safe activation depends is frozen, atomically/platform-bound, or freshly established before mutation.
44. Root Activation is conditional on exact sealed external root state.
45. Transition state remains closed across active-manifest pointer change.
46. Post-activation transition verification is governed by exact predecessor `N` or External Root Authority applying `N`'s rules.
47. Candidate `N+1` cannot authoritatively certify completion of its own activation.
48. Barrier release requires verification of actual deployed/executing trusted security-context identities.
49. Merely resolving or locating candidate artifacts is insufficient.
50. Every trusted context enabled after release must match the runtime/configuration identity prescribed by `N+1`.
51. While the transition is closed, candidate `N+1` cannot produce a protected consequential effect.
52. Enforcement of pre-release capability fencing does not depend solely on candidate `N+1` honoring the barrier.
53. Candidate `N+1` cannot enable or remove its own protected capability fence.
54. Intended protected-capability bindings are explicitly and deterministically identified.
55. Unknown or unverified capability bindings fail closed.
56. Release verification is performed under predecessor `N` or External Root Authority applying `N`'s rules.
57. Release verification binds exact deployed identities, capability bindings, fence state, transition, and readiness.
58. Release-verification identity is sealed into externally protected transition state before barrier release in the initial design.
59. A sealed release-verification identity does not substitute for continuing applicability of mutable deployment or capability state.
60. Mutable release conditions are frozen, atomically/platform-bound, independently fenced, or freshly established before release.
61. Deployment substitution between verification and barrier release cannot silently acquire protected authority.
62. Capability-binding substitution between verification and barrier release cannot silently acquire protected authority.
63. Barrier release is conditional on exact transition, readiness, release-verification, and root-state identities.
64. Capability enablement at release is independently ordered so candidate code cannot obtain protected authority before the release boundary.
65. No ordinary protected work starts under `N+1` before barrier release.
66. Policy-epoch handover completes at barrier release.
67. Generic pointer rollback exists only before policy-epoch release.
68. Pre-release rollback target is exactly predecessor `N`.
69. Pre-release rollback requires assurance that no protected `N+1` effect escaped the fence.
70. No generic pointer rollback is assumed safe after protected work is released under `N+1`.
71. Indeterminate root mutation leaves protected operation stopped until exact state is reconciled.
72. Stale instances cannot perform protected actions under an obsolete manifest.
73. External Root Recovery cannot become an arbitrary-new-code activation path.
74. Break-glass recovery fences old-epoch capabilities when normal quiescence cannot be established.
75. Recovery-fence inventory is explicit rather than heuristically reconstructed.
76. Failure to establish required recovery fencing leaves protected autonomy halted.
77. External Root Migration preserves one canonical root anchor whenever protected autonomy is enabled.
78. Replacement external-root infrastructure is initialized to the same active autonomous manifest during ordinary root migration.
79. Old competing root authority is retired or deterministically rendered non-authoritative before protected autonomy resumes.
80. Autonomous root-rule changes remain evaluated under old root rules.
81. Trusted-core membership changes remain evaluated under old membership.
82. External root credentials remain outside candidate control.
83. Concurrent conflicting root transitions cannot both succeed from one root state.
84. Ordinary task lifecycle state never grants root authority.
85. Genesis is externally bootstrapped rather than self-authorized.
86. Missing, stale, ambiguous, conflicting, unauthorized, expired, revoked, dependency-incomplete, artifact-mismatched, capability-unfenced, deployment-mismatched, unsealed, unfenced, or unverifiable root conditions fail closed.

---

## 101. Phase 0 boundary

This document specifies architecture and policy only.

Phase 0 does not create:

```text
external Root Trust Anchor store

Active Trusted Manifest schema

Root Change Package schema

Root Activation Readiness Record schema

Release Verification Record schema

external transition-state schema

External Root Authority credential

pre-release capability-fencing implementation

recovery-fencing implementation

root approval service

root activation tooling

root validation implementation

trusted deployment-attestation mechanism

protected capability-enablement mechanism

genesis manifest

GitHub Actions workflows

GitHub App configuration

automated Root Activation
```

Those belong to later phases.

Initial implementation MUST choose the smallest mechanism preserving the invariants in this document.

The autonomous trusted system must never need to trust a candidate's claim that the candidate is safe enough to replace it, must never allow that candidate to exercise protected authority before its release boundary, must never allow that candidate to control completion of its own activation, and must never become the ultimate authority that creates or replaces the external root authority on which its activation depends.
