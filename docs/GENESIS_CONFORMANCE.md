# Genesis Conformance Specification

## 1. Status and identity

**Status:** subordinate, non-executable conformance specification

**Version:** R3 v0.3

**Genesis scope:** fixture-only G1–G8 candidate conformance; not activation

**Reviewed executable base:** `ff8cbebb7637792108b9381d5bfb6f1e3b4af596`

```text
reviewed_executable_base:
ff8cbebb7637792108b9381d5bfb6f1e3b4af596
```

This is the pre-R3 executable-source baseline. This document does not contain, derive, or require a self-referential final commit identity. Its own resource identity is separate:

```text
GENESIS_CONFORMANCE.md identity
!= reviewed executable base identity
```

The exact identity of this root-managed resource is to be bound externally by a future reviewed genesis resource graph. No such binding or activation is created here. Any executable trusted-source change after the reviewed executable base invalidates this conformance mapping until it is re-reviewed. Adding this non-executable document does not alter the R2 executable membership recorded in §18.

## 2. Normative precedence

This specification is subordinate to the frozen Phase 0 documents:

- [`CORE_POLICY.md`](CORE_POLICY.md)
- [`ARCHITECTURE.md`](ARCHITECTURE.md)
- [`STATE_MACHINE.md`](STATE_MACHINE.md)
- [`REVIEW_MODEL.md`](REVIEW_MODEL.md)
- [`SELF_MODIFICATION.md`](SELF_MODIFICATION.md)

Those documents are the normative governing sources. This document records a durable conformance mapping and may not amend Phase 0, override Phase 0, weaken Phase 0, expand Phase 0 authority, or legalize a rule that Phase 0 does not support. If a rule cannot be derived from frozen Phase 0, the required result is **STOP** and explicit reviewed policy/specification amendment—not reinterpretation of this document.

No issue, pull-request, review, implementation, or test pointer in this document is normative authority. Phase 0 citations provide normative derivation; this R3 text is subordinate conformance specification; executable loci and tests are non-authoritative implementation/proof pointers. Passing tests cannot create, waive, or amplify authority.

## 3. Scope and non-authority

G1–G8 below are a **conformance decomposition**, not separate authorities. They describe how the reviewed fixture-only genesis candidate conforms to Phase 0. This document creates no authorization source, autonomous authority, credential, capability, lifecycle transition, evidence class, evaluator class or mechanism, root authority, activation path, or operational permission.

This is a non-executable root-managed policy/schema resource classified as `GENESIS_ROOT_MANAGED_POLICY_OR_SCHEMA`. Recording a rule here does not activate it, change executable membership, or authorize a protected action. R3 is not R4, G9, or Root Activation.

## 4. G1–G8 conformance model

### 4.1 G1 — deterministic primitives, parsing, and exact identity

G1 conformance requires strict bounded structured parsing; exact nominal identities and digests; closed deterministic decision and failure domains; explicit evaluator mechanism/configuration identity; and no security classification inferred from prose. Malformed, ambiguous, unsupported, or unverifiable input fails closed at the boundary that requires it.

Normative derivation: [CORE_POLICY.md](CORE_POLICY.md), §§7–10, 18; [ARCHITECTURE.md](ARCHITECTURE.md), §§18–19, 31; [REVIEW_MODEL.md](REVIEW_MODEL.md), §§4, 13, 21; resource and policy continuity also follow [CORE_POLICY.md](CORE_POLICY.md), §§21, 23–24, and [SELF_MODIFICATION.md](SELF_MODIFICATION.md), §§9–16.

### 4.2 G2 — trusted resources, manifest, and membership grammar

Trusted root-managed resource kinds and identities are explicit and content-bound. Trusted-core membership and dependency declarations are explicit and closed-world. Policy epoch identity is security relevant. Declaring an external TCB dependency does not make that dependency candidate authority. Unexpected or dynamic trusted loading is not admitted.

Normative derivation: [CORE_POLICY.md](CORE_POLICY.md), §§21, 23–24, 28; [ARCHITECTURE.md](ARCHITECTURE.md), §§5, 23–24; [SELF_MODIFICATION.md](SELF_MODIFICATION.md), §§9–16, 89–91, 96–100.

### 4.3 G3 — target registration, authorization, delegation, and root containment

Target Registration and Authorization are independent ceilings. Structured validity is not authority; authenticated provenance is required. Delegation cannot amplify authority, and effective authority remains the intersection of applicable ceilings. Root overlap and unavailable required root context fail closed. Risk classification does not create operational authority.

Normative derivation: [CORE_POLICY.md](CORE_POLICY.md), §§4–5, 8, 10–11, 14, 16, 18; [ARCHITECTURE.md](ARCHITECTURE.md), §§9–14, 21; [STATE_MACHINE.md](STATE_MACHINE.md), §§19–20, 33.

### 4.4 G4 — canonical task and operation lifecycle

Canonical task and operation state use exact identities and revisions. Task state is not authority; operation outcome is not an evidence verdict. Protected start has a defined linearization point and requires atomic/fenced state mutation. Cancellation/start races are revision-safe. Recovery reconciles uncertain effects before retry, and idempotency prevents duplicate effects. Completion requires the complete structured completion predicate. `requested_operations` is not a source of operation records or completion obligations.

Normative derivation: [CORE_POLICY.md](CORE_POLICY.md), §§12, 18–19, 25; [STATE_MACHINE.md](STATE_MACHINE.md), §§3–20, 22–32; [ARCHITECTURE.md](ARCHITECTURE.md), §§17, 39–42.

### 4.5 G5 — Evidence Admission and semantic composition

Reviewer output and semantic verdicts are untrusted until admitted. Evidence is provenance-bound and cannot create authority. Exact EvidenceId, subject, applicability, and supersession matter; composition is deterministic. Favorable admitted evidence cannot override deterministic failure or mint merge, completion, or root authority.

Normative derivation: [CORE_POLICY.md](CORE_POLICY.md), §§5.4, 7, 9–10, 15, 18; [ARCHITECTURE.md](ARCHITECTURE.md), §20; [REVIEW_MODEL.md](REVIEW_MODEL.md), §§3–4, 21–31; [STATE_MACHINE.md](STATE_MACHINE.md), §§18, 20, 26, 32.

### 4.6 G6 — canonical state and authoritative observation

Canonical control state and authoritative external observations are distinct. GitHub-hosted prose, comments, and logs are not authoritative state. Authoritative observations bind exact normalized identities and content. Cached or historical observations do not substitute for current facts. A consequential decision consumes one coherent canonical occurrence and its exact authoritative dependency set.

Normative derivation: [CORE_POLICY.md](CORE_POLICY.md), §§5.3, 6–7, 18–19; [ARCHITECTURE.md](ARCHITECTURE.md), §§13, 15–17, 25; [STATE_MACHINE.md](STATE_MACHINE.md), §§16, 21, 28; [REVIEW_MODEL.md](REVIEW_MODEL.md), §§7–11, 27.

### 4.7 G7 — protected gates and consequential effects

C is the canonical writer boundary. P/M protected effects require their exact role-scoped gate and authority. Authorization, evidence, and current state are revalidated at action time. PREPARED, START_HELD, and exact start-binding rules fail closed. Retry cannot duplicate a protected effect. Recovery requires exact same-operation provenance and postcondition; look-alike external state is insufficient. Audit is diagnostic/provenance, not bearer authority.

Normative derivation: [CORE_POLICY.md](CORE_POLICY.md), §§4, 12–13, 18–19, 25; [ARCHITECTURE.md](ARCHITECTURE.md), §§7–8, 17, 22, 29–30, 39–43; [STATE_MACHINE.md](STATE_MACHINE.md), §§27–30. The deployment realization remains subordinate to Phase 0.

### 4.8 G8 — adversarial conformance evidence

G8 tests and proofs are evidence that G1–G7 enforce frozen policy; they create no authority. Required adversarial themes include stale SHA, non-transferable authority, scope escape, root fail-close, action-time movement, semantic non-authority, idempotency and recovery, race safety, completion integrity, prose non-authority, requested-operation ceiling semantics, external look-alike state, and candidate-change semantic staleness.

```text
tests passing != genesis activation
```

Normative derivation: [CORE_POLICY.md](CORE_POLICY.md), §§10, 18–20, 23, 25; [ARCHITECTURE.md](ARCHITECTURE.md), §§31, 48–49; [SELF_MODIFICATION.md](SELF_MODIFICATION.md), §§22, 28–30, 96–100.

## 5. Ordinary Issue Contract conformance

Accepted raw contract bytes have exact content identity. Canonical contract admission is deterministic but is not authorization. Objective and human-readable requirement statements have no hidden security semantics. Evaluator mechanism comes only from explicit structured control data; regex, keyword, NLP, or LLM classification does not establish security-relevant meaning.

`requested_operations` is an unordered structured operation/capability ceiling only. It does not automatically create an `OperationRecord`, reserve or start an operation, define execution order, populate `required_protected_operation_ids`, create integration readiness, or create completion obligations. In particular, completion requirements are not inferred from the requested-operation list.

Contract, Target Registration, policy, issuer/parent authority, admitted Authorization, and root boundary remain independent ceilings; no ceiling silently replaces another. Where later consequential use depends on mutable state, current applicability must be freshly established.

Normative derivation: [CORE_POLICY.md](CORE_POLICY.md), §§4–11, 14, 18; [ARCHITECTURE.md](ARCHITECTURE.md), §§18–19; [STATE_MACHINE.md](STATE_MACHINE.md), §32; evaluator-mechanism constraints also derive from [REVIEW_MODEL.md](REVIEW_MODEL.md), §§4, 13, 21.

## 6. Candidate truth, materialization, and adoption

A candidate proposal is not trusted candidate truth merely because supplied values are internally hash-consistent. Trusted materialization derives exact candidate commit, tree, and mutation inventory from the reviewed deterministic object substrate. Actual mutation inventory—not caller prose or a declared file list—controls scope checks.

Recording and adoption are distinct:

```text
record candidate truth
→ canonical CandidateRecord + materialization
→ TaskRecord unchanged

adopt candidate
→ resolve exact canonical candidate/materialization
→ apply existing lifecycle/applicability rules
```

Recording success does not imply progression. A recorded candidate is not thereby current; mutable refs are not continuing candidate truth; caller-supplied `MutationInventory` is not authoritative. Only the exact canonically adopted current candidate/materialization may drive current semantic review, evidence, or protected progression. Candidate replacement changes candidate identity and stales candidate-bound evidence by default.

Normative derivation: [CORE_POLICY.md](CORE_POLICY.md), §§7, 10, 14–15, 19; [ARCHITECTURE.md](ARCHITECTURE.md), §§26–28, 37–38; [STATE_MACHINE.md](STATE_MACHINE.md), §§10, 18.

## 7. Semantic evaluator configuration

Current trusted G1 resolution selects the exact evaluator/configuration identity and policy epoch. Raw configuration bytes do not select their own trusted identity or policy epoch. Exact content digest verification precedes semantic interpretation, and only the closed reviewed configuration grammar is accepted.

Trusted semantic evaluator resolution derives from current trusted resolution plus exact verified configuration bytes—not caller claims, registry guesses, template assertions, or reviewer output. Security-relevant configuration movement changes exact resolution identity. Configuration resolution is deterministic configuration truth; it is not Evidence Admission or semantic authority.

Normative derivation: [CORE_POLICY.md](CORE_POLICY.md), §§7, 9–10, 18, 24; [ARCHITECTURE.md](ARCHITECTURE.md), §§19, 32–33; [REVIEW_MODEL.md](REVIEW_MODEL.md), §§13, 15, 17, 21.

## 8. Current semantic target and PR context

Current semantic target/PR context is derived from trusted current Target Registration plus authenticated authoritative observation paths. Caller-selected profiles or normalized JSON alone are not authenticated current state. An `AuthoritativeStateDependency` binds the exact repository/locator, observation profile, transport identity, and expected authoritative binding. Dependency identity is not bearer authority; consequential consumers freshly revalidate and fence dependencies.

Consumers determine all and only required observation profiles. A manually created look-alike PR without trusted candidate-PR provenance is not current semantic PR truth. Unavailable, incomplete, or conflicting current observations produce an indeterminate/fail-closed result.

Normative derivation: [CORE_POLICY.md](CORE_POLICY.md), §§5.3, 6–7, 18–19; [ARCHITECTURE.md](ARCHITECTURE.md), §§13, 15, 25, 32; [REVIEW_MODEL.md](REVIEW_MODEL.md), §§7–11, 27.

## 9. Semantic-review reconstruction and Evidence Admission

The current semantic-review subject is reconstructed from current trusted state, never taken from historical review assertions. Reconstruction binds the current candidate and contract, semantic obligation, evaluator/configuration resolution, assignment/profile, current target/PR context, required material, and authoritative dependencies as applicable. Trusted reconstruction failure fails closed; there is no historical fallback.

Semantic reviewer output remains judgment only. Favorable raw output is unusable until Evidence Admission. Current review material and dependencies are deterministically reconstructed and bound.

Normative derivation: [CORE_POLICY.md](CORE_POLICY.md), §§5.4, 7, 9–10, 18; [ARCHITECTURE.md](ARCHITECTURE.md), §§32–33; [REVIEW_MODEL.md](REVIEW_MODEL.md), §§3–11, 17, 21–27.

## 10. Current semantic evidence versus progression support

The distinction is strict and security-relevant:

```text
historically admitted semantic evidence
!= currently applicable semantic evidence

currently applicable semantic evidence
!= favorable reviewer outcome

currently applicable semantic evidence
!= satisfied obligation

currently applicable semantic evidence
!= progression support

currently applicable semantic evidence
!= operational authority
```

Historical `EvidenceSubject` is immutable provenance and cannot self-certify currentness. Current `EvidenceSubject` is freshly reconstructed from current trusted state. Exact semantic EvidenceId freshness requires coherent canonical record/history and supersession, successful current-subject reconstruction, and `APPLICABLE` applicability. It establishes freshness/applicability only:

```text
EvidenceId CURRENT/APPLICABLE
does not imply reviewer outcome APPROVED
does not imply obligation SATISFIED
does not imply progression support
does not imply authorization
does not imply capability
does not imply repair authority, scope, or operational authority
```

Candidate, base, configuration, or context movement may stale prior EvidenceIds. Valid supersession excludes the older exact EvidenceId from current use and progression support. An exact E1 requirement is not silently satisfied by E2 merely because E2 is current for the same obligation.

Only exact EvidenceIds that are current, unsuperseded, included in a successful current composition, and actually contributing to a `SATISFIED` semantic obligation may enter `progression_support_evidence_ids`. `UNSATISFIED`, `INDETERMINATE`, incomplete, conflicted, stale, superseded, or non-contributing evidence yields no progression support.

Normative derivation: [CORE_POLICY.md](CORE_POLICY.md), §§5.4, 7, 9–10, 15, 18; [ARCHITECTURE.md](ARCHITECTURE.md), §20; [REVIEW_MODEL.md](REVIEW_MODEL.md), §§3–4, 21–31; [STATE_MACHINE.md](STATE_MACHINE.md), §§18, 20, 26, 32.

## 11. Same-occurrence and authoritative dependency rules

G6 supplies canonical/current facts. G5 decides semantic applicability, supersession, composition, and progression support. Every semantic evidence item used in one consequential semantic decision is assembled from one coherent canonical occurrence `N`. Where applicability depends on mutable external authoritative facts, that same decision carries exact authoritative dependency set `F`; consequential commit/start is fenced and revalidated against `N + F`.

The current semantic dependency set is the deterministic union of required G1/basic evaluator dependencies and current semantic-context dependencies. A caller cannot omit a required dependency. Earlier `INTEGRATION_READY` state or `ALLOW` is not bearer authority; forward protected start rechecks current semantic state.

```text
current semantic dependencies
= required G1/basic evaluator dependencies
  UNION current semantic-context dependencies
```

Normative derivation: [CORE_POLICY.md](CORE_POLICY.md), §§5.3–5.4, 15, 18–19; [STATE_MACHINE.md](STATE_MACHINE.md), §§16, 18, 28, 32; [REVIEW_MODEL.md](REVIEW_MODEL.md), §§7–11, 26–27; [ARCHITECTURE.md](ARCHITECTURE.md), §§17, 20, 25.

## 12. Protected-operation semantic consumption

For every explicitly required semantic EvidenceId on a protected/authoritative operation, exact currentness is freshly checked. Generic semantic currentness does not itself grant permission for a non-integration protected action. For forward IntegrationBound progression, contract-wide semantic currentness must freshly equal `SATISFIED`, and each exact required forward semantic EvidenceId must also be a progression-support EvidenceId.

An empty `required_evidence_ids` set cannot bypass mandatory semantic acceptance. A subset of evidence IDs cannot bypass another mandatory evaluator obligation. Preserve the exact typed distinctions:

```text
known stale/superseded required semantic evidence
→ REQUIRED_EVIDENCE_NOT_CURRENT

known current semantic state that fails the stronger progression requirement
→ REQUIRED_EVIDENCE_NOT_VALID_FOR_OPERATION

current semantic validity/context cannot be established
→ REQUIRED_EVIDENCE_CONTEXT_INDETERMINATE
```

```text
G4 operation/start failure domain
!=
semantic denial/currentness domain
```

These domains are not collapsed into one generic error or prose judgment. The semantic reason domains remain subordinate to Phase 0 fail-closed/currentness rules.

Normative derivation: [CORE_POLICY.md](CORE_POLICY.md), §§4, 5.4, 7, 9–10, 12–13, 18–19; [ARCHITECTURE.md](ARCHITECTURE.md), §§17, 20, 29–30, 39–43; [STATE_MACHINE.md](STATE_MACHINE.md), §§18, 20, 26–30, 32; [REVIEW_MODEL.md](REVIEW_MODEL.md), §§24–27.

## 13. Completion semantics

Completion is allowed only when the complete structured completion predicate is satisfied. No evaluation order is normative unless Phase 0 makes that ordering security-relevant. Mandatory semantic evaluator obligations are freshly current and `SATISFIED` where completion depends on them. Semantic currentness/satisfaction is veto-only where applicable: favorable semantic evidence cannot upgrade a failed deterministic completion condition. G4 operation failure and semantic denial remain distinct reason domains.

Normative derivation: [STATE_MACHINE.md](STATE_MACHINE.md), §§26, 32; [CORE_POLICY.md](CORE_POLICY.md), §§5.4, 18; [REVIEW_MODEL.md](REVIEW_MODEL.md), §§24–27.

## 14. Deterministic and semantic denial composition

Deterministic policy, authorization, scope, identity, state, root, freshness, and gate-precondition failures remain controlling and cannot be overridden by semantic evidence. Missing or indeterminate facts fail closed at the boundary requiring them. Semantic evidence governs only the semantic obligations to which it applies; it never manufactures deterministic authority. Current semantic evidence may still be negative or non-supporting. Typed completion/start reasons preserve deterministic versus semantic domains rather than collapsing them into prose or generic model judgment.

Normative derivation: [CORE_POLICY.md](CORE_POLICY.md), §§4–5, 8–11, 13–14, 18; [ARCHITECTURE.md](ARCHITECTURE.md), §§7–8, 17, 20–21; [STATE_MACHINE.md](STATE_MACHINE.md), §§18–20, 26–32; [REVIEW_MODEL.md](REVIEW_MODEL.md), §§3–4, 21–27.

## 15. Non-authorities

None of the following independently creates authority, current truth, or Root Activation authority:

- objective prose or requirement-statement prose;
- issue comments, PR comments, labels, or repository-hosted prose;
- reviewer output before Evidence Admission;
- favorable semantic evidence, including admitted evidence;
- audit records;
- task lifecycle state alone;
- `INTEGRATION_READY` alone;
- `requested_operations` alone;
- candidate existence or candidate recording alone;
- historical `EvidenceSubject` or historical currentness assertions;
- authoritative dependency identifiers by themselves;
- tests or G8 success;
- repository merge or `main` state;
- this R3 specification itself.

None of these creates Root Activation authority.

Normative derivation: [CORE_POLICY.md](CORE_POLICY.md), §§4–10, 13, 18, 20, 23, 25; [ARCHITECTURE.md](ARCHITECTURE.md), §§18–21, 31, 48–50; [STATE_MACHINE.md](STATE_MACHINE.md), §§5, 18, 20, 34; [REVIEW_MODEL.md](REVIEW_MODEL.md), §§3–4, 20–21, 26; [SELF_MODIFICATION.md](SELF_MODIFICATION.md), §§20, 89–100.

## 16. Fail-closed requirements

Malformed, ambiguous, unsupported, stale, conflicting, incomplete, or unverifiable inputs do not produce a permissive result. Required identity, authority, current state, root context, observation, evidence provenance, dependency, or fence that cannot be established fails closed at the boundary that requires it. No fallback to prose, a caller-selected profile, a historical subject, a cached observation, a look-alike external effect, or a test result supplies missing authority or current truth.

Normative derivation: [CORE_POLICY.md](CORE_POLICY.md), §§8, 10–11, 13–14, 18–19; [ARCHITECTURE.md](ARCHITECTURE.md), §§17, 31, 49; [STATE_MACHINE.md](STATE_MACHINE.md), §§16, 21, 28, 30; [SELF_MODIFICATION.md](SELF_MODIFICATION.md), §§10–14, 28–30, 96–100.

## 17. R1 deployment overlay

The reviewed pre-G9 realization is recorded only as a subordinate conformance constraint; R3 does not redefine R1:

- genesis scope: `FIXTURE-ONLY`;
- candidate roles: `T / C / P / M`;
- T: no protected mutation;
- C: canonical writer only;
- P: publication authority only;
- M: merge authority only;
- broad target/effect substrate: external / not candidate G;
- external `START_HELD` recovery: outside candidate roles.

These deployment facts do not activate genesis, grant any additional authority, or change Phase 0. Normative derivation: [CORE_POLICY.md](CORE_POLICY.md), §§12–13, 21–23; [ARCHITECTURE.md](ARCHITECTURE.md), §§3–8, 44–50; [SELF_MODIFICATION.md](SELF_MODIFICATION.md), §§6, 21–22, 96–100.

## 18. R2 executable membership

The frozen candidate executable membership is embedded here in full. This list, not an issue/PR comment, is the durable R3 membership record.

### 18.1 `GENESIS_MINIMAL_CORE` — 18 modules

```text
src/autodev_control/trusted/errors.py
src/autodev_control/trusted/identity.py
src/autodev_control/trusted/parsing.py
src/autodev_control/trusted/scope.py
src/autodev_control/trusted/resources.py
src/autodev_control/trusted/manifest.py
src/autodev_control/trusted/genesis_resource_graph.py
src/autodev_control/trusted/decision.py
src/autodev_control/trusted/contract.py
src/autodev_control/trusted/target_registration.py
src/autodev_control/trusted/authorization.py
src/autodev_control/trusted/operation.py
src/autodev_control/trusted/state.py
src/autodev_control/trusted/evidence.py
src/autodev_control/trusted/review.py
src/autodev_control/trusted/semantic_config.py
src/autodev_control/trusted/semantic_context.py
src/autodev_control/trusted/current_semantic_review.py
```

### 18.2 `GENESIS_PROTECTED_RUNTIME_TCB` — 8 modules

```text
src/autodev_control/trusted/__init__.py
src/autodev_control/trusted/audit.py
src/autodev_control/trusted/backend.py
src/autodev_control/trusted/state_reader.py
src/autodev_control/trusted/materialization.py
src/autodev_control/trusted/protected_effect.py
src/autodev_control/trusted/runtime_authority.py
src/autodev_control/trusted/runtime_roles.py
```

Total: **26 candidate executable Python modules**.

### 18.3 Explicit exclusions

The following are not candidate executable membership:

```text
src/autodev_control/trusted/gates.py
src/autodev_control/trusted/fixture_audit.py
src/autodev_control/trusted/fixture_capabilities.py
src/autodev_control/trusted/fixture_transport.py
src/autodev_control/trusted/fixture_platform.py
tests/**
```

Classification:

| Resource | Classification |
| --- | --- |
| `gates.py` | `FIXTURE_ONLY_NOT_IN_GENESIS` |
| `fixture_audit.py` | `FIXTURE_ONLY_NOT_IN_GENESIS` |
| `fixture_capabilities.py` | `FIXTURE_ONLY_NOT_IN_GENESIS` |
| `fixture_transport.py` | `FIXTURE_ONLY_NOT_IN_GENESIS` |
| `fixture_platform.py` | `EXTERNAL_TCB_DEPENDENCY SOURCE / NOT CANDIDATE G` |
| `tests/**` | Not candidate executable membership; proof artifacts only |

External dependency declaration does not transfer the declared dependency into candidate executable authority. R3 neither changes these classifications nor activates the listed membership. Normative derivation: [CORE_POLICY.md](CORE_POLICY.md), §§21, 23–24, 28; [ARCHITECTURE.md](ARCHITECTURE.md), §§5, 23–24, 50; [SELF_MODIFICATION.md](SELF_MODIFICATION.md), §§9–16, 89–91, 96–100.

## 19. Traceability matrix

The stable `GC-*` identifiers below are local specification traceability IDs only; they are not runtime identities, authorization classes, or evidence classes. Phase 0 sections are the normative derivation. The rule summary is subordinate R3 text. Executable loci and proof/test families are non-authoritative pointers. Any `trusted/<module>.py` shorthand in the locus column refers to `src/autodev_control/trusted/<module>.py`. A passing test never creates or waives authority. A material change to executable semantics or these mappings requires R3 re-review.

| Rule ID | Rule summary | Phase 0 governing sections | Executable locus (non-authoritative) | Proof/test family (non-authoritative) | Failure behavior |
| --- | --- | --- | --- | --- | --- |
| `GC-G1-001` | Bounded parsing, exact identities/digests, closed deterministic decisions; prose is not security classification. | [CORE_POLICY.md](CORE_POLICY.md) §§7–10, 18; [ARCHITECTURE.md](ARCHITECTURE.md) §§18–19, 31; [REVIEW_MODEL.md](REVIEW_MODEL.md) §§4, 13, 21 | `trusted/parsing.py`, `identity.py`, `decision.py`, `contract.py` | G1 parser, identity, decision, contract regressions | Reject or fail closed on malformed, ambiguous, unsupported, or unverifiable input. |
| `GC-G2-001` | Explicit content-bound resources, policy epoch, closed membership/dependencies; no unexpected dynamic loading. | [CORE_POLICY.md](CORE_POLICY.md) §§21, 23–24, 28; [ARCHITECTURE.md](ARCHITECTURE.md) §§5, 23–24; [SELF_MODIFICATION.md](SELF_MODIFICATION.md) §§9–16, 89–91, 96–100 | `trusted/resources.py`, `manifest.py`, `genesis_resource_graph.py`, `runtime_roles.py` | G2 resources/manifest/import-closure regressions | Fail closed on identity, membership, epoch, or closure mismatch. |
| `GC-G3-001` | Target and authorization are independent authenticated ceilings; delegation cannot amplify; root containment is fail-closed. | [CORE_POLICY.md](CORE_POLICY.md) §§4–5, 8, 10–11, 14, 16, 18; [ARCHITECTURE.md](ARCHITECTURE.md) §§9–14, 21; [STATE_MACHINE.md](STATE_MACHINE.md) §§19–20, 33 | `trusted/target_registration.py`, `authorization.py`, `scope.py` | G3 target, authorization, delegation, root-scope regressions | Deny/escalate at the required boundary when authority, provenance, or root context is invalid or unavailable. |
| `GC-G4-001` | Canonical task/operation revisions, start linearization, race-safe cancellation, idempotency, recovery, full completion predicate. | [CORE_POLICY.md](CORE_POLICY.md) §§12, 18–19, 25; [STATE_MACHINE.md](STATE_MACHINE.md) §§3–20, 22–32; [ARCHITECTURE.md](ARCHITECTURE.md) §§17, 39–42 | `trusted/state.py`, `operation.py`, `backend.py`, `state_reader.py` | G4 lifecycle/start/recovery/completion regressions | Reject stale revisions and unsafe transitions; reconcile uncertain effects before retry. |
| `GC-G5-001` | Evidence Admission binds provenance and subject; deterministic semantic composition cannot mint authority or override deterministic failure. | [CORE_POLICY.md](CORE_POLICY.md) §§5.4, 7, 9–10, 15, 18; [ARCHITECTURE.md](ARCHITECTURE.md) §20; [REVIEW_MODEL.md](REVIEW_MODEL.md) §§3–4, 21–31; [STATE_MACHINE.md](STATE_MACHINE.md) §§18, 20, 26, 32 | `trusted/evidence.py`, `review.py` | G5 admission, supersession, composition regressions | Unadmitted, stale, conflicting, or inapplicable evidence cannot support a permissive result. |
| `GC-G6-001` | Canonical state differs from external observations; one decision binds occurrence N and exact current dependency set F. | [CORE_POLICY.md](CORE_POLICY.md) §§5.3, 6–7, 18–19; [ARCHITECTURE.md](ARCHITECTURE.md) §§13, 15–17, 25; [STATE_MACHINE.md](STATE_MACHINE.md) §§16, 21, 28; [REVIEW_MODEL.md](REVIEW_MODEL.md) §§7–11, 27 | `trusted/state_reader.py`, `semantic_context.py`, `backend.py` | G6 snapshot/dependency/same-occurrence regressions | Missing, conflicting, stale, or unbound observations fail closed. |
| `GC-G7-001` | Exact role-scoped protected effects revalidate at action time; recovery uses same-operation provenance; audit is not authority. | [CORE_POLICY.md](CORE_POLICY.md) §§4, 12–13, 18–19, 25; [ARCHITECTURE.md](ARCHITECTURE.md) §§7–8, 17, 22, 29–30, 39–43; [STATE_MACHINE.md](STATE_MACHINE.md) §§27–30 | `trusted/protected_effect.py`, `runtime_authority.py`, `runtime_roles.py` | G7 protected start/effect/recovery/audit regressions | Fail closed on binding, authorization, freshness, idempotency, or recovery-provenance failure. |
| `GC-G8-001` | Adversarial proofs test G1–G7 conformance; tests do not activate genesis. | [CORE_POLICY.md](CORE_POLICY.md) §§10, 18–20, 23, 25; [ARCHITECTURE.md](ARCHITECTURE.md) §§31, 48–49; [SELF_MODIFICATION.md](SELF_MODIFICATION.md) §§22, 28–30, 96–100 | No production authority locus; tests only | G8 adversarial/integration suite | A failed proof blocks conformance claims; a passing proof grants no authority. |
| `GC-CONTRACT-001` | Exact raw contract identity/admission; prose has no hidden evaluator/security meaning. | [CORE_POLICY.md](CORE_POLICY.md) §§4–11, 14, 18; [ARCHITECTURE.md](ARCHITECTURE.md) §§18–19; [REVIEW_MODEL.md](REVIEW_MODEL.md) §§4, 13, 21 | `trusted/contract.py`, `parsing.py` | Issue Contract parsing/admission regressions | Reject invalid structure; admission alone grants no authorization. |
| `GC-CONTRACT-002` | `requested_operations` is an unordered ceiling, not operation creation/order/readiness/completion obligation. | [CORE_POLICY.md](CORE_POLICY.md) §§4–5, 8, 11–14, 18; [ARCHITECTURE.md](ARCHITECTURE.md) §§18–19, 22; [STATE_MACHINE.md](STATE_MACHINE.md) §§5, 22, 32 | `trusted/contract.py`, `operation.py`, `state.py` | Contract-to-operation and completion-integrity regressions | Do not infer operation or completion obligations from the request ceiling. |
| `GC-CANDIDATE-001` | Materialization derives exact commit/tree/inventory; record and adopt are distinct; only exact adopted current truth progresses. | [CORE_POLICY.md](CORE_POLICY.md) §§7, 10, 14–15, 19; [ARCHITECTURE.md](ARCHITECTURE.md) §§26–28, 37–38; [STATE_MACHINE.md](STATE_MACHINE.md) §§10, 18 | `trusted/materialization.py`, `backend.py`, `state.py` | Candidate materialization/adoption/scope regressions | Reject inconsistent materialization; recording alone leaves task state unchanged and does not establish currentness. |
| `GC-SEM-CONFIG-001` | Current G1 resolution and exact verified bytes determine closed-grammar evaluator config identity. | [CORE_POLICY.md](CORE_POLICY.md) §§7, 9–10, 18, 24; [ARCHITECTURE.md](ARCHITECTURE.md) §§19, 32–33; [REVIEW_MODEL.md](REVIEW_MODEL.md) §§13, 15, 17, 21 | `trusted/semantic_config.py`, `current_semantic_review.py` | Semantic config resolution regressions | Reject digest/epoch/grammar/binding mismatch; no caller-selected identity fallback. |
| `GC-SEM-CONTEXT-001` | Current target/PR context comes from trusted registration and authenticated observations with exact dependencies. | [CORE_POLICY.md](CORE_POLICY.md) §§5.3, 6–7, 18–19; [ARCHITECTURE.md](ARCHITECTURE.md) §§13, 15, 25, 32; [REVIEW_MODEL.md](REVIEW_MODEL.md) §§7–11, 27 | `trusted/semantic_context.py`, `target_registration.py`, `state_reader.py` | Current target/PR observation and dependency regressions | Unavailable, incomplete, conflicting, or look-alike observations are indeterminate/fail closed. |
| `GC-SEM-REVIEW-001` | Current review subject/material/dependencies are reconstructed from current trusted state, not historical assertions. | [CORE_POLICY.md](CORE_POLICY.md) §§5.4, 7, 9–10, 18; [ARCHITECTURE.md](ARCHITECTURE.md) §§32–33; [REVIEW_MODEL.md](REVIEW_MODEL.md) §§3–11, 17, 21–27 | `trusted/current_semantic_review.py`, `review.py` | Semantic reconstruction and exact-subject regressions | Reconstruction failure fails closed; no historical fallback; raw reviewer output is not admitted evidence. |
| `GC-SEM-CURRENT-001` | Historical subject cannot self-certify; exact EvidenceId currentness requires coherent history/supersession, reconstructed subject, and APPLICABLE. | [CORE_POLICY.md](CORE_POLICY.md) §§5.4, 7, 9–10, 15, 18; [ARCHITECTURE.md](ARCHITECTURE.md) §20; [REVIEW_MODEL.md](REVIEW_MODEL.md) §§21–31; [STATE_MACHINE.md](STATE_MACHINE.md) §§18, 20, 26, 32 | `trusted/evidence.py`, `review.py`, `current_semantic_review.py` | Evidence currentness/supersession regressions | Stale, superseded, incoherent, or unestablishable current evidence is unusable. |
| `GC-PROGRESSION-001` | Only exact current, unsuperseded, contributing EvidenceIds in successful SATISFIED composition support progression. | [CORE_POLICY.md](CORE_POLICY.md) §§5.4, 7, 9–10, 15, 18; [ARCHITECTURE.md](ARCHITECTURE.md) §20; [REVIEW_MODEL.md](REVIEW_MODEL.md) §§21–27; [STATE_MACHINE.md](STATE_MACHINE.md) §§18, 20, 26, 32 | `trusted/evidence.py`, `review.py`, `current_semantic_review.py` | G5 composition and semantic progression-support regressions | UNSATISFIED, INDETERMINATE, incomplete, conflicted, stale, superseded, or non-contributing evidence yields no support. |
| `GC-SAME-OCCURRENCE-001` | Semantic decision binds one canonical occurrence N and deterministic dependency union F; consequential use fences N + F. | [CORE_POLICY.md](CORE_POLICY.md) §§5.3–5.4, 15, 18–19; [STATE_MACHINE.md](STATE_MACHINE.md) §§16, 18, 28, 32; [REVIEW_MODEL.md](REVIEW_MODEL.md) §§7–11, 26–27; [ARCHITECTURE.md](ARCHITECTURE.md) §§17, 20, 25 | `trusted/backend.py`, `state_reader.py`, `current_semantic_review.py`, `protected_effect.py` | Same-occurrence/dependency-fencing regressions | Stale or mismatched occurrence/dependencies deny or fail closed. |
| `GC-START-001` | Protected start rechecks current authorization/evidence and IntegrationBound semantic requirements; typed failure domains remain distinct. | [CORE_POLICY.md](CORE_POLICY.md) §§4, 5.4, 12–13, 18–19, 25; [ARCHITECTURE.md](ARCHITECTURE.md) §§7–8, 17, 20, 29–30, 39–43; [STATE_MACHINE.md](STATE_MACHINE.md) §§27–30 | `trusted/protected_effect.py`, `runtime_roles.py`, `operation.py` | G7 protected-start and semantic-consumption regressions | `REQUIRED_EVIDENCE_NOT_CURRENT`, `REQUIRED_EVIDENCE_NOT_VALID_FOR_OPERATION`, and `REQUIRED_EVIDENCE_CONTEXT_INDETERMINATE` remain distinct; G4 failures remain distinct. |
| `GC-COMPLETION-001` | Full structured completion predicate is conjunctive/order-neutral; semantic currentness is veto-only. | [CORE_POLICY.md](CORE_POLICY.md) §§5.4, 18; [STATE_MACHINE.md](STATE_MACHINE.md) §§26, 32; [REVIEW_MODEL.md](REVIEW_MODEL.md) §§24–27 | `trusted/state.py`, `operation.py`, `evidence.py` | Completion integrity and semantic-veto regressions | Completion is withheld unless every required structured predicate is satisfied. |
| `GC-NON-AUTHORITY-001` | Prose, evidence, lifecycle projections, audit, dependencies, tests, merge/main, and R3 itself do not create authority or activation. | [CORE_POLICY.md](CORE_POLICY.md) §§4–10, 13, 18, 20, 23, 25; [ARCHITECTURE.md](ARCHITECTURE.md) §§18–21, 31, 48–50; [STATE_MACHINE.md](STATE_MACHINE.md) §§5, 18, 20, 34; [REVIEW_MODEL.md](REVIEW_MODEL.md) §§3–4, 20–21, 26; [SELF_MODIFICATION.md](SELF_MODIFICATION.md) §§20, 89–100 | No authority locus | G1–G8 non-authority and activation-boundary regressions | Treat the item only as information/evidence, never as authorization or activation. |
| `GC-FAIL-CLOSED-001` | Missing, malformed, stale, conflicting, unsupported, or unverifiable required facts fail closed at their consuming boundary. | [CORE_POLICY.md](CORE_POLICY.md) §§8, 10–11, 13–14, 18–19; [ARCHITECTURE.md](ARCHITECTURE.md) §§17, 31, 49; [STATE_MACHINE.md](STATE_MACHINE.md) §§16, 21, 28, 30; [SELF_MODIFICATION.md](SELF_MODIFICATION.md) §§10–14, 28–30, 96–100 | Trusted validators, readers, gates, and backend boundaries | G1–G8 negative/adversarial regression families | Deny, reject, or escalate as defined by the boundary; never fall back to untrusted/historical assertions. |
| `GC-R1-001` | The reviewed fixture-only T/C/P/M deployment overlay is subordinate and does not activate or redefine authority. | [CORE_POLICY.md](CORE_POLICY.md) §§12–13, 21–23; [ARCHITECTURE.md](ARCHITECTURE.md) §§3–8, 44–50; [SELF_MODIFICATION.md](SELF_MODIFICATION.md) §§6, 21–22, 96–100 | `trusted/runtime_roles.py`; fixture substrate outside candidate G | R1 role-separation and fixture-boundary regressions | Reject role/authority expansion; external substrate remains outside candidate G. |
| `GC-R2-001` | Candidate executable membership is exactly the two listed sets (18 + 8); explicit exclusions remain outside membership. | [CORE_POLICY.md](CORE_POLICY.md) §§21, 23–24, 28; [ARCHITECTURE.md](ARCHITECTURE.md) §§5, 23–24, 50; [SELF_MODIFICATION.md](SELF_MODIFICATION.md) §§9–16, 89–91, 96–100 | `trusted/manifest.py`, `resources.py`, `genesis_resource_graph.py`, `runtime_roles.py` | G2 manifest/import-closure regressions | Any membership or classification mismatch blocks conformance; external dependency declaration grants no membership. |
| `GC-STOP-001` | An unsupported or contradictory rule requires STOP and explicit reviewed Phase 0/specification amendment; R3 cannot legalize it. | [CORE_POLICY.md](CORE_POLICY.md) §§27–28; [ARCHITECTURE.md](ARCHITECTURE.md) §§51–52; [REVIEW_MODEL.md](REVIEW_MODEL.md) §§2, 36–37; [SELF_MODIFICATION.md](SELF_MODIFICATION.md) §§88–91, 100–101 | No runtime locus | Policy/specification review | Stop implementation or use until explicit reviewed amendment and re-review. |

## 20. Historical implementation provenance — non-normative

**NON-NORMATIVE — HISTORICAL / REVIEW PROVENANCE ONLY.** The following references explain the history of refinements represented by this conformance map. They are not governing authority and must not be used to establish, amend, or interpret a normative rule:

- Issue #27: Issue Contract refinement.
- Issue #30: candidate truth and materialization.
- Issue #33: semantic evaluator configuration.
- Issue #35: current semantic context.
- Issue #32: semantic-review reconstruction.
- Issue #29: semantic evidence currentness and progression.
- Issue #40: R1 runtime separation.
- Issue #42: R2 membership cleanup.
- Issue #39: R2 resource/membership provenance.
- Issue #47: R4 genesis resource-graph repair.

Only the frozen Phase 0 documents cited in the traceability matrix supply normative derivation. Issue/PR comments and implementation history are provenance only.

## 21. STOP and amendment rule

If a future executable rule cannot be derived from frozen Phase 0, contradicts Phase 0, changes authority allocation or lifecycle semantics, introduces evaluator/evidence/authorization types, turns issue history into authority, creates Root Activation semantics, or requires executable trusted-semantic changes merely to make this document true:

```text
STOP
```

The required next step is an explicit reviewed policy/specification amendment. Do not reinterpret this conformance document to legalize new semantics. Changes to trusted executable source, R1 topology, R2 membership, Phase 0 authority, or semantic rule mapping may invalidate this R3 mapping and require re-review. The R3 resource itself remains non-executable and grants no R4, G9, or Root Activation authority.
