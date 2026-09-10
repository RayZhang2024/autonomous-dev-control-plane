# Autonomous Development v2 — Review Model

**Status:** Phase 0 baseline  
**Version:** 1.0  
**Repository:** `RayZhang2024/autonomous-dev-control-plane`  
**Governing policy:** `docs/CORE_POLICY.md` v1.0  
**Governing architecture:** `docs/ARCHITECTURE.md` v1.0  
**Lifecycle model:** `docs/STATE_MACHINE.md` v1.0

## 1. Purpose

This document defines how Autonomous Development v2 establishes semantic-review evidence without granting semantic reviewers control-plane authority.

It specifies the evaluator boundary, exact review subject and inputs, reviewer profiles and independence, data-egress controls, verdict semantics, Evidence Admission, freshness, retry and re-review rules, partitioned review, and the relationship between semantic review and the canonical state machine.

The exact JSON representation of semantic verdicts belongs in `schemas/review-verdict.schema.json`.

---

## 2. Normative relationship

`CORE_POLICY.md` is constitutional authority. `ARCHITECTURE.md` defines the system trust boundaries. `STATE_MACHINE.md` defines canonical task and operation lifecycles.

This document is subordinate to those baselines and MUST NOT weaken them.

Where this document is silent, the governing documents continue to apply.

---

## 3. Semantic review is judgment, not authority

Semantic review evaluates explicitly assigned semantic requirements. It does not grant authority.

A semantic reviewer MUST NOT determine whether the system is authorized to:

```text
admit a task
expand scope
change risk
publish a candidate
invoke controlled runtime
increase repair authority
merge
complete a task
activate trusted policy
```

Those decisions remain with trusted deterministic control.

A valid semantic verdict is evidence for a consequential decision, never the consequential decision itself.

Acceptance requirements explicitly identify their evaluator mechanisms. Initial evaluator classes are:

```text
deterministic
semantic
controlled_runtime
external_observation
human_approval
```

One requirement MAY require more than one evaluator.

Evaluator class MUST NOT be inferred from natural-language wording.

Active trusted policy establishes mandatory evaluator minimums and permitted alternatives. A task contract MAY select among policy-permitted alternatives or strengthen requirements, but MUST NOT remove, substitute, or weaken policy-required evaluators.

---

## 4. Deterministic and semantic responsibility

Deterministic validation establishes facts that can be reliably machine-verified, including where applicable:

```text
repository identity
candidate SHA
base SHA
commit ancestry
changed-file inventory
authorized path scope
contract structure
authorization validity
target registration
test exit status
required file existence
machine-readable equality
schema validity
repair/retry bounds
```

Semantic review addresses requirements that genuinely require interpretation or judgment, such as intended behaviour, architectural meaning, semantic consistency, or documentation accuracy.

An LLM MUST NOT establish a fact that policy or contract requires to be established deterministically.

Reviewer statements such as `tests pass`, `all files are in scope`, or `the expected base was used` do not establish those facts.

Semantic review MAY reason from admitted deterministic facts but does not replace them.

---

## 5. Semantic requirement identity

Every semantic requirement MUST have a stable machine-readable identity.

Conceptually:

```text
requirement_id
requirement statement
required evaluator = semantic
applicable subject/context
required reviewer profile/class where applicable
```

The reviewer evaluates only explicitly supplied semantic requirements.

It MUST NOT create new acceptance requirements merely because additional work appears desirable.

---

## 6. Canonical review flow

The ordinary semantic-review flow is:

```text
exact current candidate
        ↓
deterministic review preconditions
        ↓
Trusted Review Envelope Builder
        ↓
exact review envelope + input manifest
        ↓
reserve semantic-review operation
        ↓
fresh operation-start checks
        ↓
reserved → performing
        ↓
trusted invocation boundary submits exact canonical request
        ↓
provider response + operation reconciliation
        ↓
raw structured verdict
        ↓
Evidence Admission
        ↓
admitted semantic-review evidence
        ↓
trusted controller computes control consequence
```

The semantic reviewer does not write canonical task state or operation state.

---

## 7. Exact review subject

Semantic review MUST be bound to an exact subject.

The subject includes, where applicable:

```text
repository immutable identity
task identity
contract identity
target-registration identity
active-policy identity
base SHA
candidate SHA
target/base context
PR identity
semantic-requirement identities
review-invocation identity
reviewer-profile identity
verdict-schema version
```

Candidate SHA alone is insufficient where review validity depends on additional context.

---

## 8. Trusted Review Envelope Builder

A deterministic trusted component constructs the review envelope.

It MUST bind:

```text
exact review subject
complete changed-file inventory
canonical changed-content identities
exact semantic requirements
required trusted-context identities
reviewer-profile identity
review-invocation identity
verdict-schema version
```

The builder establishes what must be reviewed. It does not make semantic judgments.

It MUST NOT intelligently omit changed material because an LLM, regex, keyword rule, or heuristic believes the material is irrelevant.

---

## 9. Review input manifest

Every semantic-review invocation MUST have an exact machine-readable input manifest binding the canonical request.

It includes, where applicable:

```text
review-invocation identity
review-envelope identity
candidate identity
semantic-requirement identities
changed-material identities
required trusted-context identities
supplemental-context identities or references
reviewer-profile identity
verdict-schema version
partition identity
```

A reviewer assertion that it reviewed the correct material is insufficient.

---

## 10. Trusted invocation boundary and request provenance

The reviewer invocation boundary is a narrow deterministic transport and provenance function.

It may:

```text
validate/build the canonical request
bind the exact request identity
submit it to the configured reviewer service
bind observable provider response metadata
bind the raw response identity
```

It MUST NOT make semantic judgments, decide material relevance, alter requirements, decide Evidence Admission, choose lifecycle outcomes, expand authority, publish or merge repository state, invoke controlled runtime, or activate trusted policy.

Its security-relevant behaviour is part of the TCB, but it need not be a separate large service or independent protected capability.

The boundary MUST bind, where available:

```text
review-invocation identity
reviewer-profile identity
canonical request identity
request payload or content-addressed representation
submission event identity
provider-returned invocation/model metadata
raw response identity
```

Evidence Admission MUST establish that the response corresponds to the canonical request emitted by this boundary.

The system MUST NOT claim to prove unobservable provider-internal processing. Provider-side behaviour beyond the observable configured request/response interface is an explicit external trust dependency governed by active policy and reviewer-profile requirements.

---

## 11. Material and required-context coverage

The review package MUST make semantic coverage explicit.

For every changed path, the envelope identifies the applicable candidate-side content identity or deletion identity and relevant metadata where required.

The canonical review request MUST supply the changed material required for every assigned semantic requirement, either as exact content or as an explicitly permitted, identity-bound deterministic representation suitable for that review.

A filename, path, digest, or content identity alone does not establish semantic-review coverage.

Where an unchanged artifact is required to support a semantic judgment, the envelope MUST bind its exact canonical identity and the canonical request MUST supply the corresponding content or an explicitly permitted identity-bound deterministic representation.

Examples include governing policy, architecture, referenced schemas, relevant unchanged interfaces, or required baseline implementation.

Missing, silently omitted, unsupported, unverifiably truncated, substituted, stale, or unbound required material cannot yield admissible approval evidence.

A reviewer that genuinely lacks sufficient supplied material SHOULD return `unable_to_determine`. Failure to establish request provenance is instead an Evidence Admission failure.

---

## 12. Supplemental context

An untrusted Context Assembler MAY provide summaries, design history, background, excerpts, candidate explanations, issue discussion, or implementation notes.

Supplemental context remains untrusted and advisory.

It MUST NOT replace required changed material, required trusted-bound unchanged context, or authoritative facts.

---

## 13. Reviewer-profile authority

Reviewer profiles are security-relevant trusted configuration.

Active trusted policy or trusted enforcement configuration identifies permitted profiles and minimum requirements.

A reviewer profile conceptually defines:

```text
profile identity
trusted reviewer instructions
permitted model/service class
minimum capability/version constraints where enforceable
tool permissions
coverage requirements
context limits
data-egress constraints
verdict schema
retry/re-review rules
applicable policy constraints
```

A task contract MAY select among profiles or classes explicitly permitted by active policy.

A contract MAY require a stronger profile only according to a trusted-policy-defined ordering, constraint set, or capability rule. No actor may infer profile strength from names, descriptions, natural-language instructions, vendor reputation, or model reputation.

A task contract, candidate, worker, reviewer, or orchestrator MUST NOT invent an authoritative profile or weaken its trusted instructions, coverage, capability floor, tool restrictions, data-egress restrictions, or retry rules.

Changing security-relevant reviewer-profile configuration creates a new trusted configuration identity.

---

## 14. Reviewer capability and independence

A semantic reviewer SHOULD have only the capability required for semantic judgment.

It MUST NOT independently possess:

```text
canonical control-state write authority
target-publication authority
merge authority
controlled-runtime authority
target-registration authority
root-activation authority
```

Where compromise of the reviewer could cross one of those boundaries, technical capability separation is required. Prompt instructions alone are not a security boundary.

Semantic review MUST be invoked through a control path independent of candidate-production authority.

The candidate, implementation worker, repair worker, or another candidate-producing actor MUST NOT control trusted reviewer instructions, reviewer-profile authority, required material delivery, required semantic requirements, recording of unfavorable completed verdicts, or verdict provenance.

This does not require a different model vendor or model family. It requires independently controlled invocation, instructions, input binding, capabilities, provenance, and Evidence Admission.

A candidate-producing actor cannot satisfy semantic-review requirements merely by manufacturing review-shaped output about its own work.

---

## 15. Model/service identity and provider trust

Where reproducible exact model/service identity is available, it SHOULD be bound to the reviewer profile or invocation record.

Where only a mutable alias or weaker identity is available, that limitation MUST be explicit. Active trusted policy determines whether that identity strength is acceptable for the applicable reviewer profile or risk class.

Reviewer output MUST NOT claim stronger model identity than the invocation infrastructure can establish.

Provider-internal routing, preprocessing, tokenization, or model execution that is not observable at the configured interface remains an external trust dependency, not a fact proved by the control plane.

---

## 16. Review data egress and disclosure classification

Submitting repository, candidate, trusted-context, or supplemental material to an external reviewer service is a security-relevant disclosure action.

Before submission, deterministic trusted control MUST establish that the exact disclosure is permitted.

The decision binds, where applicable:

```text
target-registration identity
repository identity
reviewer service/profile identity
authorization identity
active-policy identity
material/resource classifications
permitted disclosure scope
secret/resource constraints
exact canonical request
```

Target Registration and active trusted policy determine the permitted reviewer services, disclosure classes, and resource constraints.

Disclosure classification MUST come from trusted structured configuration, registered resource metadata, or another active-policy-authorized deterministic mechanism.

A reviewer, candidate producer, Context Assembler, or other untrusted component MUST NOT establish disclosure authority by semantically classifying repository content or prose.

Where required disclosure classification is absent, conflicting, or unknown, external disclosure fails closed.

Reviewer profiles cannot expand disclosure authority beyond active policy and Target Registration.

---

## 17. Semantic-review operation boundary

A semantic-review invocation is a canonical security-relevant operation whenever it crosses an external disclosure boundary or is relied upon to produce provenance-bound semantic evidence.

The operation binds, where applicable:

```text
operation identity
task identity
review-invocation identity
reviewer service/profile identity
exact canonical request identity
candidate/context identity
contract identity
authorization identity
active-policy identity
target-registration identity
expected authoritative state
applicable disclosure authorization
```

It follows the operation lifecycle and operation-start rules in `STATE_MACHINE.md`.

Before any external review material is transmitted:

```text
operation reserved
        ↓
fresh deterministic checks
        ↓
reserved → performing durably succeeds
        ↓
external transmission may begin
```

The earlier disclosure evaluation is not reusable bearer authority.

Immediately before operation start, every authoritative state element whose continued value is required for the disclosure and review invocation to remain permitted MUST still be valid and bound through the State Machine's atomic/conditional rules.

If an action-specific precondition fails before transmission, the disclosure MUST NOT occur.

Once transmission may have begun, absence of a response does not prove absence of disclosure. The operation must be reconciled to `succeeded`, `failed`, or `indeterminate` as the State Machine permits.

No separate data-egress lifecycle is created.

---

## 18. Secrets, protected resources, and transformed representations

The review path MUST NOT transmit material whose disclosure to the configured reviewer service is prohibited.

This includes applicable secrets, credentials, protected artifacts, regulated/confidential material, target-specific protected resources, and other policy-restricted content.

Prohibited disclosure MUST NOT be handled by silently omitting required material while treating review coverage as complete.

If required material cannot be disclosed, sufficient approval evidence does not exist unless active trusted policy permits an explicitly defined alternative review mechanism.

A deterministic transformation or redaction MAY be used only where policy permits it, the transformed representation is identity-bound, and an explicit trusted coverage rule establishes that the representation is acceptable for the assigned semantic requirement.

The reviewer or another LLM MUST NOT decide for itself that arbitrary redaction is sufficient.

---

## 19. Reviewer tools

Initial Phase 1 reviewer profiles MUST use a bounded canonical review request and MUST NOT permit general or unmanifested autonomous tools.

They MUST NOT independently browse the web, search arbitrary repository state, fetch unmanifested files, query external systems, or obtain dynamic context outside the canonical request.

Reviewer tools MAY be introduced later only through an active-policy-authorized profile whose provenance and disclosure model preserves the review trust boundary.

Every security-relevant tool interaction affecting semantic judgment MUST then bind, as applicable:

```text
review-invocation identity
tool-event identity
tool-profile identity
exact tool request
authorized target/source
source classification
returned-content identity
interaction ordering
data-egress implications
```

Tool results do not automatically become authoritative facts. Dynamic external information remains semantic context unless separately admitted through the applicable evidence class.

If required tool provenance or disclosure authorization cannot be established, the resulting verdict MUST NOT become admitted evidence.

---

## 20. Prompt-injection boundary

Candidate code, documentation, comments, issue prose, diffs, logs, test output, supplemental context, and permitted tool results are untrusted reviewer inputs.

Instructions embedded in them MUST NOT modify review authority, trusted instructions, evaluator requirements, candidate identity, scope, risk, verdict schema, input manifest, disclosure authority, or control-plane policy.

The reviewer MAY interpret embedded instructions as candidate content where semantically relevant, but MUST NOT treat them as control instructions.

---

## 21. Structured verdict

A semantic-review invocation returns structured output.

The exact schema is defined separately, but conceptually includes:

```text
schema_version
review_invocation_id
subject correlation fields
requirement_results[]
findings[]
overall_verdict
reviewer_summary
```

Reviewer-returned identity fields are correlation echoes only. Canonical identity comes from trusted invocation and Evidence Admission records.

Schema validity alone does not establish provenance, authenticity, request binding, or applicability.

---

## 22. Per-requirement verdict semantics

Every semantic requirement assigned to one review invocation MUST have exactly one valid explicit result in that invocation.

Each result conceptually contains:

```text
requirement_id
verdict
rationale
unable_reason_code where applicable
finding references where applicable
```

Initial verdict values are exactly:

```text
approved
changes_required
unable_to_determine
```

`approved` means the reviewer found sufficient reviewable material to conclude that the semantic requirement is satisfied for the exact reviewed subject.

`changes_required` means the reviewer found a substantive semantic basis that the requirement is not satisfied.

`unable_to_determine` means the reviewer cannot support either approval or a sufficiently grounded failure judgment.

None of these verdicts establish authorization, deterministic validation success, runtime success, human approval, merge authority, or task completion.

Missing, duplicate, unknown, or mismatched requirement results make the raw verdict invalid or insufficient under deterministic admission rules.

---

## 23. `unable_to_determine` reason codes

Every `unable_to_determine` result MUST include a structured reason code defined by the verdict schema.

Initial conceptual classes include:

```text
missing_required_material
unsupported_material
insufficient_context
ambiguous_requirement
conflicting_context
context_limit
reviewer_capability_limit
permitted_tool_failure
other
```

Free-form rationale MAY explain the reason, but trusted control MUST NOT parse that prose to classify retry, waiting, blocking, escalation, or authority.

Reviewer-supplied reason codes are structured semantic claims, not authoritative operational facts.

A reviewer statement such as `permitted_tool_failure` does not prove a tool failed, and `missing_required_material` does not override trusted invocation records establishing what was supplied.

Machine-verifiable operational conditions MUST be established from trusted invocation or operation evidence.

Where reviewer reason code conflicts with trusted deterministic facts, the deterministic fact prevails.

---

## 24. Overall summary and control use

Trusted deterministic code computes an overall semantic summary from the complete per-requirement result vector for an invocation:

```text
if any required result == unable_to_determine:
    overall_verdict = unable_to_determine
else if any required result == changes_required:
    overall_verdict = changes_required
else:
    overall_verdict = approved
```

The reviewer MAY emit `overall_verdict` for convenience, but trusted deterministic code MUST recompute it. A mismatch prevents valid admission.

The aggregate is a summary only.

No consequential lifecycle, repair, integration, adjudication, or escalation decision may rely on the aggregate alone when per-requirement results exist.

Trusted control evaluates the complete applicable result vector so that an unresolved requirement cannot hide a known failure and a known failure cannot disappear behind an aggregate uncertainty.

---

## 25. Findings and advisory observations

A semantic finding SHOULD identify its affected requirements and, where applicable, affected material or locations, reasoning, and suggested remediation.

Suggested remediation is advisory and cannot expand authorized scope.

A reviewer MAY provide observations outside explicit failures, but those observations MUST NOT silently become new acceptance requirements, veto conditions, scope, risk classification, or authority.

If an observation appears relevant to an existing trusted requirement, the controller MAY trigger a separate authorized evaluation.

---

## 26. Operation outcome and Evidence Admission

Review operation lifecycle and semantic verdict are distinct.

For example:

```text
semantic-review operation = succeeded
semantic verdict = changes_required
```

is valid.

Operation `succeeded` means the exact invocation completed and its operation-level postcondition was established. It does not mean the candidate was approved.

Raw reviewer output is not canonical evidence.

Evidence Admission MUST validate, where applicable:

```text
review-invocation identity
reviewer/profile identity
semantic-review operation identity
input-manifest identity
canonical request provenance
data-egress authorization
provider response binding
schema validity/version
task/contract/candidate/context identities
active-policy identity
target identity
semantic-requirement coverage
per-invocation result completeness
unable-reason validity
deterministic aggregate consistency
raw-verdict provenance
freshness
applicability
```

and returns `ADMIT`, `DENY`, or `ESCALATE`.

Evidence Admission does not create authorization.

A valid `unable_to_determine` may be admitted as semantic evidence.

Malformed, schema-invalid, incomplete, aggregate-inconsistent, reason-invalid, or provenance-unverifiable output is not rewritten as `unable_to_determine`; its admission attempt is denied or escalated.

---

## 27. Freshness and context movement

Semantic-review evidence is immutable and bound to its exact applicable context.

Candidate replacement or repair makes prior candidate-bound review stale by default.

If base, target, contract, authorization, active policy, required context, or another identity-bearing dependency changes, applicability MUST be re-evaluated.

Earlier evidence may continue only where active policy explicitly permits deterministic proof of continued applicability.

Otherwise the candidate must be freshly reviewed, reconstructed/rebased and reviewed, or blocked from consequential progression.

Approval of one candidate does not approve another.

---

## 28. Relationship to other evaluator classes

Semantic approval cannot override deterministic failure.

Semantic review cannot manufacture or substitute for required deterministic validation, controlled runtime, external observation, or human approval unless active trusted policy explicitly defines that evaluator alternative.

Human approval and external observation remain separate evidence classes and enter through their own applicable Evidence Admission paths.

A task contract may select only among alternatives permitted by active trusted policy.

---

## 29. Multiple semantic reviewers and adjudication

Active trusted policy establishes any minimum reviewer-profile, reviewer-count, quorum, independence, or adjudication requirements.

A task contract MAY strengthen those requirements or select among policy-permitted alternatives, but MUST NOT weaken them.

Where multiple semantic-review evidence items are required, aggregation or adjudication MUST be explicit and deterministic.

The control plane MUST NOT invent majority voting, latest-verdict-wins, highest-confidence-wins, reviewer precedence, or other conflict resolution from prose.

Conflicting required semantic evidence fails closed unless active trusted policy defines an authorized deterministic resolution path.

---

## 30. Review retry and anti-review-shopping

Operational retry and substantive semantic re-review are distinct.

Operational retry MAY occur only when trusted invocation or operation evidence establishes a policy-defined retryable operational condition, such as transport or provider failure. It remains bounded and MUST NOT weaken material coverage, reviewer profile, evaluator requirements, required context, or disclosure controls.

A valid `unable_to_determine` is not automatically an operational failure.

Once an invocation produces substantive admitted semantic evidence, an untrusted actor MUST NOT repeat review of the same effective candidate/context until a preferred verdict appears.

Substantive re-review of unchanged effective context requires an explicitly authorized reason, such as:

```text
policy-required independent second review
authorized adjudication
trusted-policy-defined re-review
new candidate
materially changed relevant context
```

Applicable prior evidence MUST NOT be silently discarded merely because later evidence is more favorable.

---

## 31. Verdict supersession

Semantic evidence is immutable.

A later verdict does not physically replace earlier admitted evidence.

Where trusted policy permits supersession for control purposes, the relationship MUST be explicit and deterministic, binding at least the earlier and later evidence identities, authorized reason, applicable policy, subject/context, and decision identity.

An orchestrator, reviewer, or candidate producer cannot privately decide that unfavorable evidence is superseded.

---

## 32. Partitioned and large-candidate review

Large candidates MUST NOT be made reviewable by silently dropping material.

The preferred initial design is a single review package where feasible.

If partitioned review is supported, the trusted review system MUST produce a deterministic coverage manifest binding:

```text
complete changed-material inventory
required trusted-context inventory
partition identities
material assigned to each partition
semantic requirements assigned to each partition
review-invocation identities
aggregation/composition rule
```

Material-to-partition and requirement-to-partition assignment MUST come from explicit structured scope or a deterministic coverage rule authorized by active policy.

It MUST NOT be inferred using LLM relevance judgment, regex, keyword matching, or heuristic prose interpretation.

A single semantic requirement MUST NOT be split across independent partitions unless structured control data or an active-policy-authorized rule explicitly defines semantic sub-requirements, their material/context scope, required coverage, and a deterministic composition rule.

Without such a rule, approval of individual partitions MUST NOT be assumed to imply approval of the combined semantic requirement.

If a semantic requirement depends on interactions across multiple pieces of material, those materials must be reviewed together in an invocation capable of judging the combined property.

---

## 33. Review retry versus implementation repair

Semantic-review retry does not authorize candidate changes, broaden scope, or grant repair authority.

Implementation repair changes the candidate, creates a new candidate identity, consumes any applicable repair allowance, and normally requires fresh candidate-bound evidence.

The mechanisms MUST NOT be conflated.

---

## 34. Trusted-core changes

Ordinary semantic review MAY contribute evidence about a trusted-core candidate but cannot authorize trusted-core or active-policy activation.

Those changes follow `SELF_MODIFICATION.md` and are evaluated under the previously active trusted boundary.

No reviewer, reviewer profile, candidate, verdict, reviewer service, or replacement trusted core may approve itself into trusted authority.

---

## 35. Initial verdict-schema direction

`schemas/review-verdict.schema.json` SHOULD initially model at least:

```text
schema_version
review_invocation_id

subject_echo
    repository identity
    task identity
    contract identity
    candidate identity
    base/context identity where applicable

requirement_results[]
    requirement_id
    verdict
    unable_reason_code where applicable
    rationale
    finding references

findings[]
overall_verdict
reviewer_summary
```

Reviewer-supplied subject fields are correlation echoes only.

Security-relevant identity, evaluator, requirement, verdict, and reason-code fields MUST remain structured.

Free-form text is appropriate for rationale and findings, but trusted control MUST NOT infer security-relevant state from it.

Invocation manifests, profile identities, operation identities, disclosure authorization, and canonical subject identities may remain in their own trusted records rather than being duplicated as reviewer claims.

---

## 36. Conformance invariants

The review model remains conformant only while all of the following hold:

1. Evaluator mechanisms are explicit structured control data and are never inferred from acceptance prose.
2. Active trusted policy establishes evaluator/reviewer minimums; task contracts may strengthen or select only policy-permitted alternatives.
3. Deterministic facts remain deterministically established and cannot be overridden by semantic claims.
4. Semantic review supplies judgment/evidence only and never grants operational authority.
5. Every semantic requirement has stable identity and every assigned requirement receives exactly one valid result per review invocation.
6. Review subject, candidate/context, changed material, and required unchanged context are exact-identity-bound.
7. Required semantic content is actually supplied in the canonical request; identifiers alone do not establish semantic coverage.
8. Untrusted context preparation cannot omit or substitute required material.
9. Reviewer profiles originate in trusted policy/configuration; profile strength and permissions are never inferred from prose or reputation.
10. Candidate-producing actors cannot control trusted review instructions, required review inputs, recording of unfavorable verdicts, or verdict provenance.
11. Reviewer capability cannot independently cross protected control-state, publication, merge, runtime, registration, or root boundaries.
12. External review disclosure is explicitly authorized from trusted structured classifications; untrusted semantic classification cannot create disclosure authority.
13. Prohibited secrets/protected resources are not disclosed merely to satisfy semantic coverage, and prohibited material is not silently omitted and counted as reviewed.
14. Permitted redaction/transformation is policy-authorized, deterministic, identity-bound, and governed by explicit coverage rules.
15. The review invocation boundary remains narrow, deterministic, provenance-oriented, and non-semantic.
16. Provider internals beyond the observable request/response interface remain an explicit external trust dependency.
17. A semantic-review invocation subject to external disclosure reaches durable `performing` before transmission and is reconciled if the disclosure outcome becomes uncertain.
18. General/unmanifested reviewer tools are prohibited in initial Phase 1; any later tool path has explicit policy, provenance, and disclosure controls.
19. Candidate, supplemental, and tool-provided content remain untrusted instructions.
20. Initial verdict values are exactly `approved`, `changes_required`, and `unable_to_determine`.
21. `unable_to_determine` carries a structured reason code; reviewer reason codes remain semantic claims rather than operational facts.
22. Trusted control never parses free-form rationale to classify security-relevant control state.
23. Trusted deterministic code recomputes overall semantic summary, while consequential decisions use the complete applicable per-requirement result vector.
24. Review-operation success remains distinct from semantic approval.
25. Raw semantic output becomes security-relevant evidence only through Evidence Admission; invalid output is not rewritten as `unable_to_determine`.
26. Candidate, base, contract, authorization, policy, or required-context changes trigger applicability reevaluation; candidate-bound evidence does not silently transfer.
27. Semantic review cannot substitute for another required evaluator or override deterministic failure except through an explicit policy-permitted evaluator alternative.
28. Multiple-reviewer aggregation, conflict handling, and adjudication are explicit and deterministic.
29. Substantive semantic evidence cannot be silently discarded or repeatedly regenerated until approval.
30. Operational retries are bounded and based on trusted operational facts; semantic re-review requires an explicitly authorized reason.
31. Verdict supersession is explicit, immutable-evidence-preserving, policy-bound, and identity-bound.
32. Partitioned review provides deterministic complete material/context/requirement coverage and does not infer relevance from prose.
33. A semantic requirement is not decomposed across partitions without explicit structured decomposition and deterministic composition.
34. Review retry and implementation repair remain distinct.
35. Semantic review of trusted-core candidates never grants root activation.
36. Missing, stale, conflicting, incomplete, unauthorized, disclosure-prohibited, or unverifiable required semantic evidence fails closed.

---

## 37. Phase 0 boundary

This document defines review semantics only.

It does not implement:

```text
semantic reviewer
review-envelope builder
review-input-manifest storage
reviewer-profile registry
trusted reviewer invocation boundary
data-classification or secret-scanning implementation
reviewer-tool framework
Evidence Admission code
LLM-provider integration
review orchestration
review retry/adjudication
GitHub workflow
review-verdict schema file
```

Initial Phase 1 semantic review MUST favor a complete, content-addressed, explicitly authorized review package with no general or unmanifested reviewer tools.

Phase 1 MUST implement this model without importing v1 reviewer mechanics by default and without using regex, keyword matching, heuristic parsing, or LLM interpretation to infer security-relevant evaluator classes or review-control decisions from natural-language prose.
