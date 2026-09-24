# Arena synthesis record

Required by `arena/SKILL.md` Phase E. Names the base, the grafts with source candidate, the
rejections, the dropouts, and the verification result.

## Frame

**Artifact:** a design package (module map, record types, signatures with `not implemented`
bodies, subagent prompt contracts, JSON schemas) for a system of LLM skills wrapping
Semgrep/CodeQL with parallel FP triage, threshold-gated auto-fix, and post-fix verification.

**Rubric** (written before any candidate was read; six criteria, 1–5, C1 and C2 weighted
highest): record-type quality · anti-pattern-defeat (Constraint 4) · threshold and
normalization rigor · interface depth · prior-art judgment · buildability as skills.
Tie-break per the Laziness Protocol: cleaner boundary, smaller API, then extensibility
without touching the core record.

**Runners:** four, on three model families. The configured pstack defaults name
`gpt-5.6-sol-max` and `grok-4.6-fast-xhigh`, which this session could not reach; substituted
within the available set. Runner 4 received additional pressure to break out of the
linear-pipeline default before committing to it.

## Candidates

| # | Shape | Distinctive contribution |
|---|---|---|
| 1 | `sast-assist`, one skill; triage emits a `SecurityContract`, not a verdict | fixer structurally blind to the rule; red-green witness with vacuity detection; `stageOf()` derived; severity absent from non-exploitable branches |
| 2 | `sast-triage` + `sast-fix` over a deterministic CLI; `Finding` = fold over an append-only event log | `input_hash` idempotency; per-fingerprint JSONL (race-free by layout); termination proof; honest blind-spot disclosure |
| 3 | `sast-triage` + `sast-assist`, split on the mutation boundary | conflict-graph partitioning of parallel fixes; deterministic suppression gate before the verifier spawns |
| 4 | `vulnfix`, fixpoint loop over a `Case` ledger; merged resolver + hostile auditor | `Case` = root cause (clustering as the cost lever); `structural` witness tier; rescan read by no state transition |

Convergence worth noting: candidates 2 and 3 independently reached the same shape on several
load-bearing decisions (skills split at the mutation boundary, two-tier threshold, one
fingerprint per root cause with false-split preferred, bounded attempts in per-finding
worktrees, differential exploit check). Candidates 1 and 4 diverged structurally from them and
from each other, which is what made the pick informative rather than a vote.

## Cross-judge

One judge, different model family from the parent, read the rubric, the grounding, the red
flags, the prior art, and all eight candidate files under **shuffled labels** so it could not
preferentially recognize any family's work. It scored criterion by criterion with citations
and returned a full verdict before hitting a session limit.

**It recommended candidate 1, "plainly ahead, not close."** That matches the parent's
independent pick, which confirms the base per arena Phase D.

Its adjudication of the central disagreement (same agent for triage and fix, or separate) is
adopted in full: separation, *because the base pays for it with a typed contract rather than a
lossy boolean*, and because the concrete thing separation buys is the fixer's `cannot_fix`
refusal path. A second independent mind that can decline before any patch exists.

## Base

**Candidate 1.** Strongest on both heavily-weighted criteria. Cleanest record type (derived
stage eliminates a whole class of desync bugs the others carry as an explicit state field;
invariants pushed into the type system rather than asserted). Strongest Constraint 4 mechanism
(witness authored before the fixer exists, mechanically red-on-base/green-on-patch with
vacuity detection, plus the fixer never being shown the rule). Best-defended threshold
position. Only candidate to demonstrate guidance mode rather than assert it.

## Grafts

| From | Graft | What had to change |
|---|---|---|
| 4 | **Root-cause clustering**, `ClusterKey{invariant_class, sink_symbol, source_class}`, `Finding.sites[]` | Added a second fold at ingest above the base's cross-scanner merge; identity now hashes cluster material rather than a single locus; added the `split` escape hatch for a triage agent that finds distinct enforcement points |
| 4 | **`structural` witness tier**, a narrow self-authored Semgrep rule that must fire at an anchor pre-patch | Replaced the base's `static` arm, whose `predicate_holds` was an LLM boolean; `runWitness` now executes the inlined rule against both trees the same way the rescan step already invokes a scanner |
| 4 | **`Lease{agent_id, role, started_at, ttl_s}`** | The base inferred "in flight" from an absent branch record and could not distinguish a crashed agent from a slow one; the parent now sets a lease on dispatch and reclaims on expiry, discarding unaudited branches |
| 4 | **Rescan demoted to a recorded signal** | Removed the base's `rescan_original_present` failure obligation entirely. See "Override" below |
| 3 | **Conflict-graph fix waves**, maximal independent sets over a file-and-line-proximity graph | Parent computes and enforces the partition before spawning; wave N+1 branches off the integration tip after wave N lands |
| 2 | **`input_hash` idempotency at the store boundary** | Added to `appendStage`; closes the crash-between-agent-return-and-parent-record window that the base's slot-emptiness check alone leaves open |
| 2 | **`regression_detected`**, a previously `fixed` finding that reappears | Added to `prefilter` as case (c); routes straight to the gate on the still-valid prior triage rather than re-triaging a known, characterized root cause |
| 2 | **Token-type-sequence cosmetic-diff check** | Folded into `guardDiff` as `cosmetic_change_only`, carrying candidate 2's own statement of its blind spot (a real-shaped no-op call changes the type sequence and is not caught here; the witness catches it) |

## Rejections

- **R1, severity ceilings (candidates 2 and 3).** Both clamped agent instance severity to a
  scanner-derived ceiling before the gate read it, arguing a ceiling is the most generous
  reading and can only save spend. It cannot: the clamp lets rule-category severity cap what
  the fix decision can ever see, the exact Constraint 3 conflation, one layer down and harder
  to see. The cross-judge independently found this in candidate 2's `gate.ts` calling
  `instanceSeverity(f.triage, f.severity_ceiling)`, contradicting candidate 2's own prose
  ("it gates spend, never the fix decision"). Candidate 2's own hand-back corroborates
  ("clamped to never exceed the ceiling"). `gate()` in the synthesis takes `Triage` and
  `Policy` and has no ceiling parameter.
- **R2, merged triage-and-fix agent (candidate 4).** Adjudicated above.
- **R3, event-log-plus-fold record (candidate 2).** Elegant, but the parent is the sole
  writer, so the race its storage layout prevents cannot occur; and a fold-derived record is
  harder to read, schema-validate whole, and hand to a human debugging one finding. Its
  idempotency mechanism was grafted without the log.
- **R4, fixpoint loop as the top-level structure (candidate 4).** The cycle is real but thin
  in practice, since a patch introducing a new ≥threshold finding already fails and reverts.
  An 11-state machine plus round protocol is a lot of exposed machinery for a cycle that
  mostly does not run. The cheap form of the property was kept: re-running is the resume path,
  and `regression_detected` handles a fixed bug that returns.
- **R5, the reference skill's coverage ledger, critic waves, `fstat` promotion ritual, reconnaissance and hunting
  prompts, and two separate LLM verification passes.** Reasons in `DESIGN.md` §9.

## Override (parent, not from any single candidate's ranking)

Candidates 1, 2, and 3 all made **"the scanner no longer reports this finding" a required
verification gate**, candidate 1 as `rescan_original_present`, candidate 2 as
`composeVerdict` step 3, candidate 3 as `targeted_rescan`. Each was careful to call it
necessary-but-not-sufficient, which is better than treating it as the whole test but still wrong.

SAST rules match shapes, and genuinely fixed code often keeps the shape, a correctly
parameterized query or a properly validated path can still trip the rule. A correct fix then
fails the gate, the agent retries, and the cheapest edit that satisfies it on attempt two is
exactly the pattern-defeating change the design exists to prevent. **A gate that creates
pressure toward the behavior it forbids is worse than no gate.**

Candidate 4 alone got this right and stated it flatly. The synthesis follows candidate 4:
`rescan.original_absent` is computed, stored, and reported, and **no state transition reads
it**. The rescan contributes exactly one obligation, `rescan_new`, about findings the patch
*introduced*. This overrides the base.

The cross-judge did not flag this; it surfaced from reading the four `evaluateVerification`
equivalents side by side.

## Defects found in candidates (not adopted, recorded so they are not reintroduced)

1. *Candidate 2*, severity ceiling clamped into the gate; code contradicts its own prose.
   **Verified** via the author's own hand-back wording.
2. *Candidate 2*, `proof_obligation` never mechanically run against the pre-patch baseline;
   the red-green property reduced to an LLM's opinion about whether a test "would pass against
   the original vulnerable code." Judge's finding; not independently re-verified (see
   Dropouts). The synthesis runs the differential mechanically in `witness-run.cjs` regardless.
3. *Candidate 4*, `Adjudication` documented as frozen for life while the transition table
   sends `rejected`/`below_gate` back to `open`, defined as "no adjudication." Judge's finding;
   not independently re-verified. **Resolved structurally in the synthesis rather than
   patched:** identity includes `sink_digest`, so changed source yields a *new* Finding with a
   `prior` link. Reopening is a new record, never a mutated one, so `triage` can be frozen for
   life without contradiction.
4. *Candidate 3*, no first-class `enforcement_point`; the fixer's only sense of "where" came
   from the scanner's sink location, which is frequently the wrong place to patch. The
   synthesis carries the base's typed `enforcement_point` with a `rationale` field.
5. *Candidate 3*, taint path threaded into triage but absent from the fixer's receive-list.
   The synthesis threads `flow` into `buildFixPrompt` explicitly.

## Dropouts and limitations of this record

- The cross-judge **completed its verdict** and then terminated on a session rate limit. The
  verdict is complete and internally consistent; no re-run was attempted, since the session
  limit was the binding constraint.
- The session scratchpad was **wiped between sessions**, destroying all four candidate
  packages, the rubric file, and the reference clone. `GROUNDING.md` survived on disk.
  Phase E was therefore performed from: the four hand-backs, the full cross-judge verdict, and
  substantial verbatim reads taken before the wipe, including the base candidate's complete
  record type, gate, guard, and verification sections, which are the parts the synthesis leans
  on hardest.
- **Consequence for trust:** graft sources and rejections traceable to text read directly or
  corroborated by an author's own hand-back are marked verified above. Judge findings #2 and
  #3 could not be re-checked against the files and are recorded as the judge's claims. Neither
  blocks: #2 is moot because the synthesis runs the differential mechanically, and #3 is
  resolved structurally by the identity scheme rather than by adopting the mechanism.

## Verification (arena Phase F)

The synthesized design was screened against `design-red-flags.md`, shallow module,
information leakage, temporal decomposition, pass-through methods, two writers, in
`DESIGN.md` §10.

Checks performed on the synthesized artifact:

- **Every graft is reachable from the caller's usage.** Clustering appears in the worked run
  output; leases in the resume call site; conflict waves in the fix line; `regression_detected`
  in `prefilter`.
- **No stage re-derives what an earlier one established.** `flow.steps[].code` materialized at
  ingest; contract carried verbatim into fixer and auditor; `gate` pure; `stageOf` derived.
- **The gate cannot read scanner severity.** `Triage` carries no scanner claim and `gate()`
  takes no ceiling parameter. The rejection is structural, not a convention.
- **No obligation in `evaluateVerification` reads `original_absent`.** Confirmed against §4.5.
- **The threshold question and the Constraint 4 question each have exactly one answer in one
  place** (`gate.cjs`; `evaluateVerification`).

Not verified, and flagged rather than papered over: none of this has been run. The design is a
sketch with `not implemented` bodies. `RATIONALE.md` "Open questions and risks" lists six
items a human should weigh before implementation, the sharpest being witness extraction for
languages whose tests live inside the file being patched (Rust `#[cfg(test)]`, Go
same-package), which degrades the strongest defense exactly where it degrades.

---

## Post-synthesis revisions

Changes made after the arena closed, on direct user feedback. Recorded separately so the
arena record stays honest about what came from the candidates and what did not.

### PS1: The `dynamic` witness tier (user-raised gap)

**None of the four candidates proposed running the application.** All four verified fixes
through source analysis, the project's test harness, or a structural rule. For a web
application that leaves the real attack surface untested: a unit test on a handler can pass
while the route stays exploitable through middleware ordering, framework routing, content
negotiation, serialization, or proxy normalization. The vulnerability frequently lives in the
gap between the handler and the wire, and every candidate verified only on the handler side of
that gap.

Added as tier 1 of four (`dynamic` > `executable` > `structural` > `argued`), selected per
finding as the strongest *available and meaningful* tier. Brings with it:

- `AppHarness`, discovered from the repo and never invented (`discoverAppHarness`).
- `HttpExchange` and a closed `Observable` union, so "the attack worked" is checked
  deterministically rather than graded by an agent, and the blast radius of a successful
  witness is a design-time decision rather than an in-the-moment judgment.
- `app_harness_modified` as a guard violation. Editing how the app boots is the same class of
  defeat as editing scanner config.
- Harness boot amortized across a conflict-partitioned wave (one instance per tree per wave),
  which gives waves a second justification beyond collision safety.

### PS2: The functional control (fell out of PS1, but fixes a general hole)

Designing the dynamic tier surfaced a gap that **all four candidates shared and none named**:
every obligation in every candidate could be satisfied by a patch that *disables the
functionality*. Return 500 to everything and the attack stops working, the scanner goes quiet,
the diff contains no suppression, and a hostile auditor reading the diff sees a real change.
The project's regression suite is the intended backstop, but a newly-touched route is exactly
what a suite tends not to cover.

`FunctionalControl` is now required on every tier that can express one, must pass on **both**
trees, and has its own failure (`witness_control_failed`). Obligations 3 and 4 are a pair:
"did the attack stop working" and "does the legitimate path still work." Neither is sufficient
alone. This raised the obligation count from six to seven.

### PS3: Revised the argument for dropping the reference skill's promotion ritual

§9 originally justified dropping the 11-step `fstat` procedure on the grounds that "no artifact
crosses a trust boundary." Booting a live application weakens that claim, and the original
wording would have been quietly wrong once PS1 landed.

Resolved structurally rather than by adopting the ritual: **the parent drives every exchange
itself** and records the transcript, so evidence never originates inside target-controlled
code and there is nothing to promote out of scratch. What *is* now adopted in full is the
execution sandbox around a booted app (§6.5), isolated loopback, ephemeral port, empty
allowlisted environment, dummy fixtures and principals, no dependency fetch, bounded
observable, guaranteed teardown, and never a deployed environment. That was previously
described as a principle carried over in spirit; with the dynamic tier it is load-bearing.

### PS4: Durability

The lost artifacts were recreated where recreation is meaningful:

- The prior art was re-cloned into the project for reading during design, and later removed.
  Nothing in the skill is copied from it; the schemas and validators were written from scratch.
- `design/arena/RUBRIC.md`, restored verbatim from context; text unchanged from the original.
- `design/arena/CANDIDATES.md`, reconstructed summaries, explicitly labeled as such.

**The four candidate packages themselves are not recoverable.** They were independent model
runs; re-running produces four *different* designs, not those four. Since the base was picked,
the grafts folded, and the synthesis verified, re-running would restart the arena rather than
restore it. The positions, mechanisms, and defects that mattered are preserved in
`CANDIDATES.md` and in the graft and rejection tables above.
