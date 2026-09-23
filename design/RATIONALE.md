# Rationale: `sast-remediate`

Shaped per `architect/references/rationale-template.md`. The design sketch is `DESIGN.md`;
the Phase A grounding is `GROUNDING.md`; the arena record is `SYNTHESIS-NOTE.md`.

## Problem

The team already runs Semgrep and CodeQL. Scanning is not the problem. False positives and
patching are. The ask is a system of LLM skills that runs the scanners, filters false
positives with parallel subagents, auto-fixes everything at or above a severity threshold,
and verifies the fix still works.

Three things make the shape non-obvious, all established in Phase A.

**The prior art is inverted.** A published security-audit skill is the usual reference for
agentic security work, but its six phases exist to answer *"did we look everywhere?"*, LLM
hunters generate findings, and the coverage ledger and critic waves prove coverage. The
scanners already answer that deterministically. Our expensive question is *"which of these
are real, and can we fix them without breaking the build?"* The reference skill's Phase 3 (a fresh
verifier tries to refute a candidate) is false-positive triage almost verbatim; its Phases
1–2 are replaced by ingestion; and its stated boundary, *"the audit describes fixes; it does
not modify target source"*, means fix-and-verify inherits no shape from the prior art at
all.

**"Medium and above" is not a field either scanner emits.** Four vocabularies are in play:
Semgrep's `ERROR/WARNING/INFO`, Semgrep's `impact × likelihood × confidence` cube, CodeQL's
continuous `security-severity` float, and CodeQL's `problem.severity`. No meaning-preserving
mapping exists among them. Worse, all of them are *rule-category* severity, a property of
the rule, not of the instance the rule fired on.

**"Verify that it still works" is two obligations wearing one sentence.** Does the code still
build and pass tests, and is the vulnerability actually gone? The second has a failure mode
that naive designs reward directly: the cheapest way to silence a SAST rule is to defeat its
pattern matcher. Rename a variable, add an indirection, drop a `nosemgrep`.

## Usage (caller's view)

```
  /sast-remediate .                  # full run, default fix threshold = medium
  /sast-remediate . --fix-at high
  /sast-remediate . --triage-only    # CI-safe; touches nothing
  /sast-remediate .                  # run it again: resumes. There is no --resume flag.
```

One command, one threshold flag. The operator makes exactly one decision at the end: review
and merge `sast-fix/integration-<run-id>`, a branch of individually-witnessed commits, each
carrying its invariant, its counterexample, its witness test, and its audit verdict in the
commit message. Findings the system could not fix arrive in `HANDOFF.md` with a retained
branch and a *failing test that encodes the bug*, most of the work already done.

Guidance mode is the same skill: asking "what does this CodeQL path-injection finding mean?"
loads the refutation rubric, answers, and writes nothing.

`DESIGN.md` §1 has the full call sites for an ordinary run, a crash resume, CI, and
guidance mode.

## Shape

**The record first.** `Observation` is an immutable scanner fact; `Finding` is one *root
cause*, carrying every site that shares an enforcement point and every scanner observation
that landed on those sites. Forty Semgrep hits on one unsafe helper are one Finding, one
contract, one patch, one witness, one commit. Two folds run at ingest: cross-scanner within a
locus, then cross-site on `ClusterKey{invariant_class, sink_symbol, source_class}`. Both
prefer false-split to false-merge. We would rather triage twice than merge two bugs into one
contract.

**Triage returns a contract, not a verdict.** `SecurityContract = {invariant, violating_input,
enforcement_point, witness, writable_scope, forbidden_resolutions}`. The verdict falls out of
it. One artifact answers what the bug is, where the fix goes, and how we will know it worked,
so no later stage re-derives security semantics from a rule message. `enforcement_point` is
first-class because the right place to enforce an invariant is frequently upstream of the
sink the scanner flagged.

**Invariants encoded in types, per encode-lessons-in-structure.** `severity` exists only on
the `exploitable` branch of the `Triage` union. The reference skill's "only confirmed records receive
severity" made unrepresentable rather than stated. `Witness.expected_pre_fix: "fail"` is a
literal type, so a witness that does not claim to be red before the fix cannot be constructed.
`PatchAttempt.attempt: 1 | 2` puts the retry cap in the type. `stageOf(f)` derives pipeline
position from the record's own shape, so there is no `status` field that can desync.

**Validation at the boundary, trust inside, per boundary-discipline.** SARIF and Semgrep JSON
exist in exactly one module. Path traversal, file existence, flow well-formedness, and id
uniqueness are established at ingest and trusted everywhere after. `gate()` is pure and total.
`evaluateVerification` is the sole definition of "verified."

**Scanner severity is retained but quarantined.** Each scanner's claim is preserved in its own
vocabulary rather than collapsed into a shared enum, because no honest collapse exists. Two
consumers read it: `priority()`, which only *orders*, and the report. The gate structurally
cannot. `Triage` carries no scanner claim and `gate()` takes no ceiling parameter.

**Verification is tiered, and dynamic where it can be.** The witness, the artifact that must
fire before the patch and fall silent after, is authored at the strongest tier the repo
supports: `dynamic` (drive the running app over its real network interface) > `executable`
(the project's test harness) > `structural` (a narrow self-authored rule) > `argued` (no
mechanical check; can never reach verified). For a web application the dynamic tier is the
only one that tests what an attacker actually touches: a unit test on a handler can pass while
the route stays exploitable through middleware ordering, routing, content negotiation, or
proxy normalization. Every tier that can express a **functional control** must carry one, a
legitimate request that passes on both trees, because otherwise "the attack stopped working"
is satisfiable by disabling the endpoint.

**What the system deliberately does not do:** it never merges, never pushes, never installs
dependencies into the target, never modifies a dependency manifest (a fix needing a new
dependency is a human decision), and never patches at all when no test command is discoverable
unless explicitly overridden.

**Interface depth.** The public interface is one command and a threshold. Behind it: two scanner
wire formats, two folds, a refutation rubric, a pure gate, a conflict-graph partitioner,
per-finding git worktrees, a six-obligation verifier, and an integration bisect that names the
culprit when combined fixes break. The complexity that remains exposed is the threshold itself
and the review of the final branch, both irreducibly the operator's call. Tracing one finding
end to end reads three files, per minimize-reader-load.

## Synthesis decision

Four candidates were produced in parallel on three model families, screened against
`design-red-flags.md`, and scored against a six-criterion rubric written before any candidate
was read. An independent cross-judge on a different family scored them under shuffled labels.
The judge and I picked the same base independently.

**Base: candidate 1.** It had the most rigorous record type of the four, derived stage
eliminating an entire class of desync bugs the others carry as an explicit `state` field, and
invariants pushed into the type system rather than asserted in prose. It had the strongest
Constraint 4 mechanism: triage authors the witness *before the fixer exists*, run mechanically
red-on-base/green-on-patch with vacuity detection, plus the structural move that the fixer is
never shown the rule id, scanner name, or message and has no scanner tool access. You cannot
game a matcher you were never shown. It had the best-defended threshold position, and it was
the only candidate to demonstrate guidance mode rather than assert it.

**Grafted in:**

- *From candidate 4:* root-cause clustering, which became `Finding.sites` plus `ClusterKey`. This is
  the cost lever that makes post-triage gating affordable without a pre-filter, and the base
  lacked it. Also its `structural` witness tier, a narrow self-authored Semgrep rule that
  must fire at a specific anchor pre-patch, replacing the base's LLM-judged `predicate_holds`
  boolean, which the base's own rationale admitted weakened its strongest defense exactly
  where a test harness is unavailable. Also `Lease` with TTL, since the base inferred
  "in flight" from an absent branch record and could not distinguish a crashed agent from a
  slow one.
- *From candidate 3:* conflict-graph partitioning of parallel fixes into maximal independent
  sets, computed and enforced by the parent. Nothing else addressed concurrent patch
  collision, per separate-before-serializing-shared-state.
- *From candidate 2:* `input_hash` idempotency at the store boundary, closing the
  crash-between-agent-return-and-parent-record window; and the `regression_detected` path for
  a finding that was fixed and came back, which routes to the gate on the still-valid prior
  triage instead of re-triaging from scratch. Also its token-type-sequence cosmetic-diff
  check, folded into `guardDiff`, *including* its honest statement of the blind spot.

**Rejected:**

- *Severity ceilings* (candidates 2 and 3). Both clamped the agent's instance severity to a
  scanner-derived ceiling before the gate read it, arguing a ceiling can only save spend. It
  cannot: the clamp lets rule-category severity cap what the fix decision can ever see, which
  is the exact Constraint 3 conflation reintroduced one layer down and harder to see. The
  cross-judge independently found this in candidate 2's code contradicting candidate 2's own
  prose.
- *Merging triage and fix into one agent* (candidate 4). Its argument is serious, a split
  makes the invariant round-trip through a field and the fixer re-derive the flow, but its
  stated defense against anchoring was that confirming costs more effort than refuting, which
  assumes effort-minimization dominates task-completion pressure in an agentic loop. The
  concrete thing separation buys is the fixer's `cannot_fix` refusal path: a second
  independent mind cold-reading the frozen contract can decline before any patch exists. An
  agent that just wrote "verdict: exploitable" will not conclude two steps later that it is
  unsure. The base's typed contract already removes the lossy-handoff objection.
- *The reference skill's coverage ledger, critic waves, `fstat` promotion ritual, recon and hunting
  prompts, and two separate LLM verification passes.* Reasons in `DESIGN.md` §9.

**One override of three of the four candidates, and of the base.** Candidates 1, 2, and 3 all
made "the scanner no longer reports this finding" a *required* verification gate. Candidate 4
alone recorded it and read it in no state transition. Candidate 4 is right, and the synthesis
follows it, see the first tradeoff below. The cross-judge did not flag this; it emerged from
reading the four verification functions side by side.

**Cross-judge disagreements worth recording:** none on the base. It scored candidate 4's
static witness tier as "the best single idea in any of the four designs," which the graft
reflects. It scored candidate 1 slightly down for an untyped-vs-typed scanner extension
point; the synthesis keeps the typed discriminated union, accepting a bounded single-arm edit
when a third scanner is added, because the alternative is an opaque bag that re-opens the
severity-conflation hole.

## Tradeoffs accepted

- **We accept that a correct fix may leave the scanner still reporting, in exchange for never
  pressuring the fixer toward pattern-defeat.** SAST rules match shapes, and genuinely fixed
  code often keeps the shape. Making scanner silence mandatory means correct fixes get
  rejected, the agent retries, and the cheapest edit satisfying the gate on attempt two is
  exactly the cheating change the design exists to prevent. A gate that creates pressure
  toward the behavior it forbids is worse than no gate. `original_absent` is recorded and
  reported; no transition reads it. `rescan_new`, findings the patch *introduced*, remains a
  hard failure.
- **We accept a false-split bias in both dedup folds in exchange for never merging two bugs
  into one contract.** Triaging the same root cause twice costs an agent call. Merging two
  different bugs produces one contract that under-describes both and a patch that fixes at
  most one.
- **We accept the cost of booting the application in exchange for testing the boundary an
  attacker actually reaches.** App boot is the most expensive operation in the run, so it
  amortizes across a conflict-partitioned wave (one instance per tree per wave, not per
  finding), and findings whose flow source is not a network entry surface never select the
  tier. A repo with no runnable service pays nothing.
- **We accept that adding dynamic testing re-opens a sandbox obligation we had argued away.**
  The original case for dropping the reference skill's artifact-promotion procedure was that nothing
  crosses a trust boundary. Booting a live app weakens that. The resolution is structural, the
  parent drives every exchange and records the transcript, so evidence never originates inside
  target-controlled code, but the execution sandbox itself (isolated loopback, empty
  allowlisted environment, dummy fixtures, no dependency fetch, bounded observable, guaranteed
  teardown) is now load-bearing rather than a principle we gestured at.
- **We accept a hard cap of two fix attempts in exchange for a bounded loop and an honest
  handoff.** Attempt 2 receives typed failures, not "try again." Giving up still ships a
  retained branch with a red witness test that encodes the bug.
- **We accept one triage agent per root cause rather than batching, in exchange for verdict
  independence.** Two candidates batched up to 8–10 findings per call; clustering already
  captured most of that saving, and batching lets one agent's bias taint several verdicts.
- **We accept refusing to patch when no test command is discoverable** (overridable by an
  explicit flag) in exchange for never shipping unverified security patches by default.
- **We accept keeping scanner-shaped fields inside `Observation`** rather than normalizing at
  ingest. This looks like transport leaking into the domain; it is retained evidence. The test
  for leakage is whether changing the representation forces coordinated edits elsewhere, and
  it does not, only `priority()` and the report read it, both switching exhaustively on
  `kind`.
- **We accept that `argued` witnesses exist** for invariants with no mechanical check (a
  hardcoded credential, a weak KDF parameter). They can never reach `verified`; they reach
  `fixed_unwitnessed` and always require human review, so the fallback is visible in the
  report rather than absorbed into the aggregate.

## Alternatives considered

- **A linear pipeline with a per-finding record and no clustering** (the base as submitted).
  Lost on cost: it pays a triage agent per scanner hit, so forty hits on one helper cost forty
  adjudications. It hides the same complexity behind the same surface, but the operator pays
  for it in spend rather than in interface size.
- **A fixpoint convergence loop over a case ledger** (candidate 4). Its argument is real:
  patching changes the tree, which changes scanner output, which creates work, and a straight
  pipeline can only express that with a back-edge that is secretly a loop. It lost narrowly.
  The back-edge in practice is thin, a patch that introduces a new ≥threshold finding is
  already a hard failure that reverts, so the second round has little left to do, and an
  11-state machine plus a lease-and-round protocol is a large amount of exposed machinery to
  buy a cycle that mostly does not run. The convergence property was kept in the cheap form:
  re-running the command is the resume path, and `regression_detected` handles a fixed bug
  that returns.
- **An append-only event log with the record derived by `fold()`** (candidate 2). Genuinely
  elegant, and the strongest idempotency story of the four: per-fingerprint JSONL makes
  parallel writes race-free by storage layout rather than by discipline. It lost because the
  parent is the sole writer anyway, so the race it prevents cannot occur, and a fold-derived
  record is meaningfully harder to read, schema-validate as a whole, and hand to a human
  debugging one finding. Its `input_hash` idempotency was grafted without the log.
- **Four composable stage-skills** (`sast-scan`, `sast-triage`, `sast-fix`, `sast-verify`).
  Rejected as textbook temporal decomposition: four modules cut on execution order, each
  re-handling the same representation, with the schema, path rules, and id derivation
  duplicated across all four, and an operator orchestrating five calls instead of one.
- **Triage emitting a verdict plus a suggested patch.** Rejected: it merges the decision and
  the action while keeping them in one lossy artifact, getting the anchoring risk of a merged
  agent without the efficiency gain.

## Open questions and risks

1. **Extracting only the witness test onto the base commit is not a clean file copy in every
   language.** Rust `#[cfg(test)]` modules and Go same-package tests live inside the file
   being patched, so the red run cannot simply apply one new test file. Those degrade to the
   `structural` tier. Which is now mechanically checked rather than LLM-judged, so the
   degradation is less severe than in the base candidate, but it is still the weakest point of
   the strongest defense. Is a per-language witness-extraction strategy worth building for the
   languages you actually ship, or is the structural tier acceptable there?
2. **Is `sink_symbol` the right clustering key for your codebases?** It folds hits by callee,
   which is right for "forty calls to one unsafe helper" and wrong if your pattern is "one
   call site reached from forty routes." Should `source_class` be weighted more heavily?
3. **Does your app boot cleanly from a cold repo with no external dependencies?** The dynamic
   tier is worth more than every other obligation combined for web-reachable findings, and it
   is entirely gated on `discoverAppHarness` finding something that starts without network
   access, real credentials, or a live database. If your services need a VPN, a secrets
   manager, or a seeded production-shaped dataset to come up, the tier silently falls back to
   `executable` everywhere and the headline defense is weaker than it looks. Worth checking
   before building it.
4. **Who authors the fixture data and the dummy principals?** A dynamic witness for a
   cross-tenant read needs at least two dummy tenants with distinguishable data. That is repo
   knowledge the harness has to carry, and if it does not exist yet, somebody has to write it
   once per service.
5. **What is the real severity distribution of your current findings?** The threshold is only
   as useful as the shape of the distribution under it. If most findings land at medium, "fix
   medium and above" is "fix everything" and the budget maths change.
6. **Should CodeQL database build be in scope?** The design assumes a prebuilt database or a
   buildable one. For compiled languages the build can dominate runtime, and that changes
   whether the rescan-per-fix step is affordable or has to be batched to the integration
   branch only.
7. **Who reviews `fixed_unwitnessed` and `undecidable`?** Both land in `HANDOFF.md`. If
   nobody owns that queue, the design quietly converts a false-positive problem into a
   backlog problem.
8. **Is two fix attempts right?** It is a policy constant, not a structural one. The retained
   branch plus red witness means giving up is cheap, but if your findings are mostly
   mechanical the ceiling may be leaving value on the table.

## Next implementation step

Build `normalize.cjs` + `cluster.cjs` against `finding.schema.json`, run it over real Semgrep
and CodeQL output from one repo, and hand-check both folds, because every later stage
depends on the record being right, and fold correctness is the cheapest thing to get wrong and
the most expensive to discover late. The `dynamic` witness tier lands last (§11 step 6),
against a pipeline that already works end to end on the cheaper tiers.
