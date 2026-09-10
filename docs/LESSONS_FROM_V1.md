# Autonomous Development v2 — Lessons from v1

**Status:** Phase 0 frozen  
**Version:** 1.0  
**v2 repository:** `RayZhang2024/autonomous-dev-control-plane`  
**v1 reference repository:** `RayZhang2024/ML-AMstress`  
**primary v1 repository snapshot:** `b299d8daab1696c7880986ea04bfac76327595b3`

## 1. Purpose

This document records engineering lessons learned from Autonomous Development v1 in `RayZhang2024/ML-AMstress`.

Its purpose is to preserve evidence that informed the Phase 0 design of Autonomous Development v2 without turning v1 mechanisms into v2 requirements.

v1 is therefore treated as:

```text
historical implementation evidence
+
failure evidence
+
operational experience
```

not as:

```text
v2 policy
v2 architecture
v2 authority
v2 compatibility contract
```

The central question throughout this document is:

> What did v1 teach us, and where is the resulting v2 decision actually governed?

---

## 2. This document has no control-plane authority

`LESSONS_FROM_V1.md` is a historical/reference artifact.

It does not independently define:

- trusted-core membership;
- active policy;
- authorization;
- lifecycle state;
- evaluator type;
- risk;
- scope;
- evidence admission;
- repair permission;
- controlled-runtime permission;
- publication or merge permission;
- Root Activation.

Freezing or committing this document does not make its contents active policy input or root-protected material merely because they are frozen.

Where this document describes a Phase 0 design choice, the cited governing v2 artifact remains authoritative.

If a governing v2 artifact later changes through its valid modification path, stale wording in this historical document does not preserve the older rule.

---

## 3. Evidence provenance

Repository-file evidence in this document is anchored primarily to exact v1 snapshot:

```text
RayZhang2024/ML-AMstress
b299d8daab1696c7880986ea04bfac76327595b3
```

Representative repository evidence includes:

```text
docs/AUTONOMOUS_DEVELOPMENT.md
docs/AUTONOMOUS_ORCHESTRATION.md

docs/A4_18_COMPLETION_OBSERVER.md

docs/A5_1_REVIEWER.md
docs/A5_2_REVIEW_STATE.md
docs/A5_3_REPAIR_WORKER.md
docs/A5_4A_REVIEW_LOOP.md

docs/A6_1_ABAQUS_RUNNER_PREFLIGHT.md
docs/A6_2_EXACT_PR_VALIDATION.md

docs/A7_1_ISOLATED_TARGET_VALIDATION.md
docs/A7_2_IMPORT_PARTITION_REGRESSION.md

scripts/codex_issue_worker.py
scripts/a5_reviewer.py
scripts/a5_review_orchestrator.py
```

Issue, PR, workflow, review, and repair history provides additional event evidence.

Where a historical candidate matters, exact candidate or run identity is preferred over a mutable branch name.

Representative later evidence includes:

```text
D1 Issue #253 / PR #254
head a21b398b174c1e42ab59332507d849c8c9cc3479

D1 Issue #258 / PR #259
head 7140b01f14e71a3bdd0850262d566b1dc1e22e08

D1 Issue #263 / PR #264
head 52fb27e2d3cf8e1886d59e3d08742087ad8ae2eb

D1 Issue #266 / PR #267
head c1e0bff72686b56c0d2f8c4b6d730bf444a8f9cb

D1 Issue #270 / PR #271
head 171b729671c563c0cbc7573b9026b294b61637a3

D1 Issue #272 / PR #273
head 6426025a3dc7ac775dd084ff391cdb2aecd82a58

D1 Issue #274 / PR #275
head b3cd883d4803a3d44e395b2a61660cbfd1a45172

D0 Issue #276 / PR #277
head 8cb1ded79ac6e7185ca583ab1bd63b79dfa077ae

D0 Issue #280 / PR #281
head 555c1851d3c51a00ae1e6bdb374744e6416e6306
```

Later modification of v1 does not retroactively redefine the historical evidence summarized here.

---

## 4. How experimental v1 evidence is interpreted

Not all v1 evidence has the same meaning.

This document distinguishes three cases.

### Demonstrated useful property

A mechanism or principle repeatedly behaved usefully across exercised workflows.

Example:

```text
semantic reviewer lacks mutation credentials
```

may support a lesson about capability separation.

### Demonstrated failure mode

A failed, blocked, or rejected candidate may provide strong evidence that a particular design assumption was unsafe or brittle.

Example:

```text
free-text semantic regex accepted or rejected
the wrong governance meaning
```

may demonstrate that deterministic prose interpretation is unsuitable for a security boundary.

### Experimental remedy

A failed, blocked, unmerged, or incomplete v1 proposal may suggest a possible solution without proving that solution correct.

In particular:

> Evidence that D0 or D1 exposed a problem does not imply that the corresponding D0 or D1 remedy was validated architecture.

Phase 0 may retain the lesson while choosing a completely different mechanism.

---

# Part I — Principles v1 demonstrated usefully

## 5. Exact identity binding

### v1 evidence

v1 progressively bound significant decisions to exact combinations of:

```text
repository
issue
PR
branch
base SHA
candidate/head SHA
workflow run
authorization record
changed paths
review evidence
runtime evidence
```

Exact-head review and validation prevented a result for one PR head from silently applying to a later changed head.

### Lesson

Mutable names are insufficient for consequential decisions when the underlying object may change independently.

### Phase 0 disposition

**Retained and generalized.**

v2 represents exact subject identity as a foundational control-plane concept rather than as an A5/A6 convention.

### Governing v2 artifacts

- `docs/CORE_POLICY.md`
- `docs/ARCHITECTURE.md`
- `schemas/issue-contract.schema.json`
- `schemas/review-verdict.schema.json`

---

## 6. Freshness near the action boundary

### v1 evidence

v1 repeatedly rechecked state before:

```text
claim
review
repair
runtime execution
merge consideration
```

because earlier observations could become stale.

### Lesson

A valid observation and a valid later mutation are separate events.

Time between them creates race and freshness risk.

### Phase 0 disposition

**Retained and strengthened.**

Phase 0 adopted exact current-state requirements and state-bound consequential mutation rather than relying on read-then-unconditional-write.

### Governing v2 artifacts

- `docs/CORE_POLICY.md`
- `docs/ARCHITECTURE.md`
- `docs/STATE_MACHINE.md`
- `docs/SELF_MODIFICATION.md`

---

## 7. Fail-closed handling

### v1 evidence

v1 blocked execution on conditions including:

```text
stale head
ambiguous linkage
duplicate claim
unknown or conflicting state
authorization mismatch
malformed evidence
unsafe path identity
missing runtime isolation
uncertain scientific evidence
```

This sometimes reduced liveness, but it prevented uncertainty from becoming permission.

### Lesson

Failure to establish a required security fact must not be interpreted as evidence that the fact is safe.

### Phase 0 disposition

**Retained.**

### Governing v2 artifacts

- `docs/CORE_POLICY.md`
- `docs/STATE_MACHINE.md`
- `docs/SELF_MODIFICATION.md`

---

## 8. Implementation and semantic review separation

### v1 evidence

The A5 reviewer was designed as a read-only semantic reviewer.

It did not own ordinary GitHub mutation or repair authority.

This made it possible to ask semantic questions without giving the reviewer direct authority to make the reviewed result true.

### Lesson

Semantic review is stronger when it cannot directly alter the candidate or the authoritative state it evaluates.

### Phase 0 disposition

**Retained and strengthened.**

Semantic verdicts in v2 are evidence rather than authority.

### Governing v2 artifacts

- `docs/CORE_POLICY.md`
- `docs/ARCHITECTURE.md`
- `docs/REVIEW_MODEL.md`
- `schemas/review-verdict.schema.json`

---

## 9. Deterministic verification and semantic reasoning are different evaluator classes

### v1 evidence

v1 was strongest when deterministic mechanisms established facts such as:

```text
exact SHA
exact path set
schema validity
CI result
runner identity
authorization record
bounded count
```

while LLM review handled questions such as:

```text
does the implementation satisfy intent?
does the prose contradict the contract?
does this change have a semantic consequence
not obvious from file identity?
```

### Lesson

Deterministic truth and semantic judgment should not be conflated.

### Phase 0 disposition

**Retained structurally.**

Phase 0 defines explicit evaluator mechanisms rather than inferring them from prose.

### Governing v2 artifacts

- `docs/CORE_POLICY.md`
- `docs/ARCHITECTURE.md`
- `docs/REVIEW_MODEL.md`
- `schemas/issue-contract.schema.json`

---

## 10. Candidate output is not self-authenticating evidence

### v1 evidence

v1 progressively rejected assumptions such as:

```text
Codex says tests passed
therefore tests passed

process exits zero
therefore controlled validation succeeded

candidate emits success marker
therefore candidate is accepted
```

More trusted paths used independent CI, exact state checks, controller-owned sentinels, or external review.

### Lesson

The subject being evaluated must not be the sole authority establishing the evidence required to accept itself.

### Phase 0 disposition

**Retained and generalized.**

### Governing v2 artifacts

- `docs/CORE_POLICY.md`
- `docs/ARCHITECTURE.md`
- `docs/REVIEW_MODEL.md`
- `docs/SELF_MODIFICATION.md`

---

## 11. Trusted evaluation must come from outside the candidate being evaluated

### v1 evidence

Later v1 workflows deliberately distinguished:

```text
trusted-current control-plane implementation
```

from:

```text
candidate repository state being evaluated
```

Exact candidate heads were evaluated using trusted-current review/orchestration logic rather than automatically allowing candidate modifications to replace the evaluator deciding whether those same modifications were acceptable.

This appeared repeatedly in requirements for:

```text
trusted-current-main A5
exact candidate head
current trusted review machinery
fresh candidate implementation from trusted main
```

### Lesson

Exact candidate identity alone is not sufficient if the candidate is also allowed to redefine the mechanism that interprets whether that identity is valid or acceptable.

The evaluator's own identity and provenance matter.

### Phase 0 disposition

**Retained and generalized.**

Phase 0 represents active trusted policy/evaluator identity separately from candidate identity.

For trusted-core transitions, the distinction becomes explicit:

```text
trusted predecessor N
        ↓
evaluates
        ↓
candidate N+1
```

Candidate `N+1` does not provide the authoritative rules governing its own activation.

### Governing v2 artifacts

- `docs/CORE_POLICY.md`
- `docs/ARCHITECTURE.md`
- `docs/REVIEW_MODEL.md`
- `docs/SELF_MODIFICATION.md`

---

## 12. Structured evidence is safer than prose claims

### v1 evidence

v1 increasingly used machine-readable records for:

```text
worker claims
completion observations
authorization
review state
repair attempts
runtime evidence
bootstrap evidence
```

This improved exact correlation and replay handling.

### Lesson

Security-relevant machine state should be structurally represented.

However:

```text
structured
≠
authoritative
```

A JSON record is not authoritative merely because it parses.

### Phase 0 disposition

**Retained, with stronger provenance rules.**

### Governing v2 artifacts

- `docs/CORE_POLICY.md`
- `docs/ARCHITECTURE.md`
- v2 schemas

---

## 13. Technical capability separation matters

### v1 evidence

v1 exercised separation among several execution contexts and credentials, including implementation, semantic review, repair, and ordinary GitHub mutation.

Reviewer and sandboxed implementation contexts were deliberately denied broader credentials.

Later A6/A7 work additionally identified stronger separation requirements around privileged target execution.

Not every A7 host/account/isolation property was independently demonstrated by repository-controlled execution; some depended on externally provisioned operating-system and security configuration.

### Lesson

Prompt instructions are not a sufficient security boundary.

Where authority separation matters, the boundary must be technically enforced.

### Phase 0 disposition

**Retained as an architectural requirement.**

### Governing v2 artifacts

- `docs/CORE_POLICY.md`
- `docs/ARCHITECTURE.md`
- `docs/SELF_MODIFICATION.md`

---

## 14. Controlled runtime is a separate authority domain

### v1 evidence

A6 concretely exercised the distinction:

```text
authorized to modify repository
≠
authorized to execute privileged target runtime
```

Controlled execution required additional runtime-specific identity, profile, and evidence checks.

A7 subsequently designed stronger isolation around target execution, including separate execution identity and environmental isolation.

Some A7 host, Windows-account, ACL, or equivalent isolation properties depended on external provisioning and were not independently provable from repository logic alone.

### Lesson

Privileged execution requires authority and isolation distinct from implementation authority.

A repository workflow should not claim proof of external host/isolation properties it cannot establish.

### Phase 0 disposition

**Retained and generalized.**

### Governing v2 artifacts

- `docs/CORE_POLICY.md`
- `docs/ARCHITECTURE.md`
- `docs/SELF_MODIFICATION.md`
- `schemas/issue-contract.schema.json`

---

## 15. Some trust properties exist outside repository code

### v1 evidence

A7 explicitly encountered security properties that repository code could not establish on its own, including execution-account and host-isolation assumptions.

External provisioning was required.

### Lesson

Repository code cannot prove every platform, identity, credential, host, or hardware property on which trusted execution depends.

### Phase 0 disposition

**Retained through explicit external TCB and observation concepts.**

### Governing v2 artifacts

- `docs/CORE_POLICY.md`
- `docs/ARCHITECTURE.md`
- `docs/SELF_MODIFICATION.md`

---

## 16. Replay, idempotency, and bounded repair require explicit state

### v1 evidence

v1 introduced:

```text
idempotency keys
repair-attempt records
persistent attempt ceilings
exact-head repair binding
operation-specific audit evidence
```

The system also exposed difficulties when failed repair re-entry had to reconstruct prior accepted blocker evidence.

Issue #278 is representative of this problem.

### Lesson

Retry and replay semantics must be explicit control state.

A second execution is not automatically:

```text
the same operation
```

and is not automatically:

```text
a newly authorized attempt
```

### Phase 0 disposition

**Retained and generalized.**

### Governing v2 artifacts

- `docs/CORE_POLICY.md`
- `docs/STATE_MACHINE.md`
- `docs/ARCHITECTURE.md`

---

# Part II — Failure modes v1 exposed

## 17. Natural-language issue structure does not make a robust machine contract

### v1 evidence

v1 used an eight-section issue structure:

```text
Goal
Necessity Gate
Required behavior
Do not change
Acceptance criteria
Tests/validation
Risk classification
Dependencies
```

This was useful for human discipline.

Over time, however, these issue bodies mixed:

```text
intent
scope
authorization-like statements
risk
state history
acceptance
evidence requirements
implementation history
```

Some later issue bodies became extremely large because they also carried detailed history from previous failed attempts.

### Lesson

Human-readable issue prose is useful context but is a poor canonical execution protocol.

### Phase 0 disposition

**Rejected as the v2 machine-contract architecture.**

The eight-section structure has no special v2 authority.

### Governing v2 artifacts

- `docs/CORE_POLICY.md`
- `docs/ARCHITECTURE.md`
- `schemas/issue-contract.schema.json`

---

## 18. Security-relevant semantic classification should not be implemented by parsing English

### v1 evidence

A5 increasingly needed to decide whether natural-language acceptance criteria represented:

```text
repository-editable requirements
external observations
historical facts
controlled-runtime evidence
```

D1 later attempted deterministic validation of governance prose.

The failure sequence repeatedly exposed problems including:

```text
literal wording dependence
line-wrap sensitivity
synonym dependence
phase inversion
bag-of-words false acceptance
```

Issue #266 explicitly changed direction after repeated prose-semantic validation failures and moved toward structured metadata plus human/semantic review.

### Lesson

The more important the classification, the less acceptable it is to derive it from ad hoc interpretation of unrestricted prose.

### Phase 0 disposition

**Rejected for security-relevant machine classification.**

Phase 0 requires structured evaluator selection.

### Governing v2 artifacts

- `docs/CORE_POLICY.md`
- `docs/ARCHITECTURE.md`
- `schemas/issue-contract.schema.json`

---

## 19. GitHub labels should not be canonical control state

### v1 evidence

v1 used labels such as:

```text
status:ready
status:in-progress
status:review
status:blocked

risk:green
risk:yellow
risk:red

agent:codex
agent:gpt-review
```

These were understandable to humans but required extensive logic for:

```text
mutual exclusion
freshness
routing
authorization interpretation
risk escalation
state transitions
```

### Lesson

UI labels are useful projections but weak as the only structured security state.

### Phase 0 disposition

**Not retained as canonical v2 control state.**

### Governing v2 artifacts

- `docs/ARCHITECTURE.md`
- `docs/STATE_MACHINE.md`

---

## 20. GitHub comment streams became an accidental state database

### v1 evidence

Important v1 control evidence was increasingly encoded as specially formatted comments:

```text
authorization
claims
repair markers
review state
completion observations
bootstrap markers
```

The system consequently needed increasingly complex logic for:

```text
trusted author
canonical body
duplicate comments
conflicting comments
staleness
replay
historical lookup
re-entry
```

### Lesson

Audit-friendly transport and canonical control-state storage are different concerns.

### Phase 0 disposition

**GitHub auditability retained; comment-stream reconstruction rejected as the canonical v2 state model.**

### Governing v2 artifacts

- `docs/CORE_POLICY.md`
- `docs/ARCHITECTURE.md`

---

## 21. Repository-specific risk taxonomies should remain repository-specific

### v1 evidence

ML-AMstress used:

```text
GREEN
YELLOW
RED
```

to distinguish ordinary changes, workflow/data changes, and scientific/physical changes.

This was valuable domain knowledge.

It also led to repository-specific protected-YELLOW rules and exceptions.

### Lesson

Risk models can be useful without being universal.

Scientific risk and generic software-control-plane authority are different dimensions.

### Phase 0 disposition

**Concept retained; v1 taxonomy not adopted as the universal v2 model.**

### Governing v2 artifacts

- `docs/CORE_POLICY.md`
- `docs/ARCHITECTURE.md`
- future target registration/policy

---

## 22. Special-case lanes create architectural accretion

### v1 evidence

v1 evolved through layers including:

```text
A4
A5.1
A5.2
A5.3
A5.4a
A6
A7
D0
D1
```

Each addressed a real problem.

But later features had to preserve increasingly complex interaction with earlier ones.

For example, protected review/repair involved combinations of:

```text
implementation authorization
claim evidence
review findings
acceptance bindings
changed-file fingerprints
repair history
CI
issue state
PR state
risk state
```

D0 then required an exceptional route around part of the existing review machinery while preserving other controls.

### Lesson

Locally reasonable exceptions can create global control-plane complexity.

### Phase 0 disposition

**v1 subsystem/lane naming is not adopted as the v2 organizing architecture.**

Phase 0 instead defines reusable control concepts.

### Governing v2 artifacts

- `docs/ARCHITECTURE.md`
- `docs/STATE_MACHINE.md`

---

## 23. Reimplementing the same security concept in many subsystems creates drift risk

### v1 evidence

Related checks appeared repeatedly across v1 mechanisms:

```text
issue/PR linkage
candidate head
changed paths
risk
authorization
repository identity
credential policy
runtime identity
```

Fresh revalidation was valuable, but multiple independent semantic definitions increased the chance of disagreement.

### Lesson

Fresh checking and duplicated security semantics are not the same thing.

### Phase 0 disposition

**Fresh checks retained; authoritative definitions centralized conceptually in the trusted control boundary.**

### Governing v2 artifacts

- `docs/CORE_POLICY.md`
- `docs/ARCHITECTURE.md`

---

## 24. Incidental workspace state should not define candidate semantics

### v1 evidence

The later D1 sequence repeatedly encountered a mismatch between:

```text
trusted-worker validation before commit
```

and:

```text
hosted validation after commit
```

The same three candidate files were legitimately:

```text
untracked candidates
```

in one phase and:

```text
tracked committed files
```

in another.

This produced repeated attempts to make pre-/post-commit semantics exact.

### Lesson

The intended candidate identity/state should be represented directly rather than inferred from incidental workspace representation wherever possible.

### Phase 0 disposition

**Generalized into explicit candidate identity and lifecycle semantics rather than preserving D1's particular phase mechanism.**

### Governing v2 artifacts

- `docs/ARCHITECTURE.md`
- `docs/STATE_MACHINE.md`

---

## 25. Repository identity and filesystem identity are different

### v1 evidence

D1 exposed edge cases involving:

```text
case differences
Unicode normalization
path aliases
raw Git inventory parsing
tracked/untracked state
filesystem enumeration
```

Later D1 contracts explicitly preferred exact Git-reported repository identities over filesystem equivalence.

### Lesson

When authorization is path-scoped, repository identity must be established using the repository/platform identity model, not host-filesystem coincidence.

### Phase 0 disposition

**Underlying identity principle retained.**

The specific D1 parser architecture is not inherited.

### Governing v2 artifacts

- `docs/CORE_POLICY.md`
- `docs/ARCHITECTURE.md`

---

## 26. Deterministic tests and semantic review catch different defect classes

### v1 evidence

Several D1 candidates passed large deterministic suites and hosted CI but were still rejected by GPT review for issues including:

```text
incorrect authority taxonomy
missing negative invariants
semantic inversion
filesystem-derived identity
incomplete contract coverage
```

Conversely, semantic review could not independently prove exact SHAs, exact path sets, schema validity, or workflow state.

### Lesson

Neither deterministic validation nor semantic review subsumes the other.

### Phase 0 disposition

**Retained as separate evidence mechanisms.**

### Governing v2 artifacts

- `docs/CORE_POLICY.md`
- `docs/REVIEW_MODEL.md`
- `schemas/issue-contract.schema.json`

---

# Part III — Later v1 experiments and what they actually prove

## 27. D1 provides strong failure evidence, not a validated v2 governance model

### v1 evidence

The D1 sequence went through many fresh attempts.

Failures exposed issues including:

```text
wrong authority classification
non-deterministic ordering
unterminated Git protocol data
case/Unicode alias handling
pre/post-commit phase mismatch
prose-semantic brittleness
filesystem versus Git identity
incomplete regression coverage
empty-inventory semantics
```

The later experimental direction moved toward:

```text
structured metadata
+
exact Git identity
+
human/semantic review of ordinary prose
```

### Lesson

D1 strongly supports two conclusions:

```text
important control facts should be explicit and structured

machine interpretation of ordinary governance prose
is a poor security boundary
```

### What D1 does not prove

D1 does **not** establish that its final manifest taxonomy, exact path grammar, phase truth table, Git parser, or governance-index design should become v2 architecture.

Several D1 candidates were failed, blocked, or unmerged experimental work.

### Phase 0 disposition

The **failure modes** informed v2.

The D1 implementation architecture was not imported.

### Governing v2 artifacts

- `docs/CORE_POLICY.md`
- `docs/ARCHITECTURE.md`
- v2 schemas

---

## 28. D0 exposed a bootstrap problem, not a validated bootstrap solution

### v1 evidence

The later D0 work was motivated by self-reference:

```text
governance knowledge needs reconstruction
        ↓
normal semantic review depends on
that governance/review knowledge
        ↓
candidate reconstruction risks being
certified through machinery it affects
```

D0 experimented with a tightly bounded knowledge-bootstrap exception.

Subsequent attempts exposed additional ordering and compatibility problems, including bootstrap probing affecting ordinary A5 behavior.

### Lesson

Trusted governance reconstruction and related bootstrap/self-reference problems cannot safely be handled by assuming that the ordinary review machinery may certify changes affecting the basis on which that machinery operates.

### What D0 does not prove

The D0 skip mechanism, owner-comment transport, path taxonomy, or A5 exception architecture is not treated as validated v2 design.

### Phase 0 disposition

Phase 0 addresses the underlying self-reference problem independently through an explicit root/self-modification architecture.

### Governing v2 artifacts

- `docs/CORE_POLICY.md`
- `docs/ARCHITECTURE.md`
- `docs/SELF_MODIFICATION.md`

---

# Part IV — Phase 0 dispositions

## 29. Retained principles

Phase 0 retained the following high-level lessons from v1:

```text
exact identity binding

fresh authoritative-state verification

fail-closed behavior

least privilege

technical capability separation

implementation/review separation

trusted evaluator / candidate separation

deterministic/semantic separation

candidate evidence treated as untrusted

structured provenance-bound evidence

bounded repair authority

replay/idempotency control

controlled-runtime separation

external trust dependencies made explicit

historical evidence preserved distinctly from current state
```

The governing meaning of those concepts comes from the frozen v2 artifacts, not this summary.

---

## 30. Generalized concepts

Phase 0 deliberately generalized several useful v1 mechanisms:

```text
v1 exact PR head
→ generic candidate identity

v1 worker claims / event markers
→ explicit operation, admission, or evidence records
  according to their actual security meaning

v1 trusted-current-main evaluation
→ explicit trusted evaluator / active-policy identity

v1 A5 snapshot
→ trusted review envelope

v1 A5 verdict
→ semantic evidence

v1 A6/A7 runtime profile
→ controlled-runtime evaluator/profile

v1 protected path rules
→ structured scope/policy/registration

v1 repair markers
→ canonical repair/operation records

v1 completion observer
→ external observation evidence

v1 governance reconstruction
→ explicit trusted manifests and membership

v1 D0 bootstrap concern
→ separate root/self-modification architecture
```

These mappings explain design history.

They do not create aliases between v1 and v2 concepts.

---

## 31. Mechanisms deliberately not inherited as v2 defaults

Phase 0 did not adopt the following v1 mechanisms as generic v2 architecture:

```text
eight-section natural-language issue body as machine contract

GitHub status labels as canonical lifecycle state

risk labels as authorization

agent labels as authorization

GREEN/YELLOW/RED as universal risk policy

GitHub comments as canonical control-state storage

A4/A5/A6/A7 subsystem architecture

A5-specific repair terminology

D0/D1 lane architecture

regex/keyword/synonym interpretation
of security-relevant prose

protected-YELLOW special-case routing

bootstrap/self-reference handled through
special exceptions inside ordinary review machinery

production scientific repository as
the primary control-plane integration fixture
```

Some may still be useful historical terminology, UI convention, or target-specific policy.

They carry no automatic v2 authority.

---

# Part V — Implications for later v2 validation

## 32. v1 failures should become v2 fixture scenarios

When implementation begins, representative v1 failure classes should be converted into dedicated v2 fixture/integration scenarios rather than recreated through v1 architecture.

Useful scenario families include:

```text
stale candidate identity

duplicate/conflicting admission

authorization/contract mismatch

scope drift

ambiguous repository identity

review bound to wrong candidate

candidate changes evaluator used to review itself

malformed semantic verdict

candidate-controlled evidence

operation replay

failed repair with remaining budget

repair authority amplification

runtime identity mismatch

runtime credential leakage

controlled runtime without authorization

merge request using stale review

policy epoch changes during protected operation

trusted-core candidate attempting self-activation

candidate trusted runtime obtaining capability
before root release
```

The fixture should test the v2 invariant directly.

It should not require reproducing the v1 A4/A5/A6/A7 workflow that originally revealed the problem.

---

## 33. Keep the trusted core small

One broad lesson from v1 is that every additional trusted:

```text
parser
classifier
exception
state convention
repair lane
compatibility rule
```

increases the surface whose correctness becomes security-relevant.

Phase 0 therefore chose a small trusted-core direction and placed planning, implementation, semantic reasoning, and repair generation outside the deterministic authority boundary.

### Governing v2 artifacts

- `docs/CORE_POLICY.md`
- `docs/ARCHITECTURE.md`

This historical explanation does not independently define trusted-core membership.

---

## 34. Final lesson

The most important lesson from v1 is not that safe autonomous development requires an ever-growing number of gates.

It is that reliability improved whenever an implicit control assumption was replaced by something explicit:

```text
implicit subject
→ exact identity

implicit permission
→ explicit authorization

implicit evaluator
→ exact trusted evaluator identity

implicit state
→ structured state

candidate claim
→ independently admitted evidence

prompt-only separation
→ technical capability separation

prose interpretation
→ structured contract

ordinary bootstrap exception
→ separate root architecture
```

v1 became harder to reason about when those same objectives were implemented through accumulated labels, prose conventions, special-case lanes, and mutually dependent exception paths.

Phase 0 therefore used v1 as evidence for a simpler direction:

```text
explicit authority
exact identity
structured state
provenance-bound evidence
narrow capabilities
trusted evaluator provenance
non-authoritative semantic reasoning
fail-closed ambiguity
small trusted core
separate root authority
```

The governing definition of that direction lives in the frozen v2 architecture and policy artifacts.

v1 explains **why** those choices were made.

It does not determine **what v2 is allowed to do**.
