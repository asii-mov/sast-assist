# Candidate record — reconstructed

**Status: these are reconstructed summaries, not the original packages.** The four
`DESIGN.md`/`RATIONALE.md` pairs (≈5,000 lines total) were lost when the session scratchpad
was wiped. What follows is rebuilt from each runner's own hand-back report plus the parent's
verbatim reads taken before the wipe. It is a faithful record of *positions and mechanisms*,
not a substitute for the originals.

**The originals cannot be regenerated.** Re-running four independent model runs would produce
four *different* designs, not these. Since the base was already picked, the grafts already
folded in, and the synthesis verified, re-running would restart the arena rather than restore
it. The one thing genuinely worth recovering, the prior art, was re-read during design and
has since been removed from the project.

---

## Candidate 1 — `sast-remediate` (the base)

One skill, 10 files, 3 agent contracts. **Triage returns a `SecurityContract`, not a verdict;
the verdict falls out of it.**

- `Finding` per finding, per-file on disk, monotonic slots. `stage` is **derived**
  (`stageOf(f)`), stored nowhere, so nothing can desync and resume is a `switch`.
- Severity exists only on the `exploitable` branch of the union — unrepresentable elsewhere.
- `gate()` structurally cannot read scanner severity: `Triage` has no such field.
- Pre-triage step is a **budget allocator, not a filter** — orders and bounds, never discards;
  unspent becomes persisted `deferred`.
- `TaintFlow = traced | sink_only`, two constructors, prompt builder switches on the
  constructor. `FlowStep.code` materialized at ingest.
- **The fixer is never shown the rule id, scanner name, or message, and has no scanner tool
  access.** Schema forbids `invariant` from naming a rule.
- Red-green witness authored at triage time; `witness_vacuous` covers both pass-on-base and
  error-on-base.
- Per-finding git worktrees; max 2 attempts in the type; `fix_failed` ships a retained branch
  with a red witness plus the contract.
- Hard stance: if no test command is discoverable, **refuses to patch** absent
  `--allow-unverified-fixes`.
- Self-flagged risk: extracting only the witness test onto base is not a clean copy for Rust
  `#[cfg(test)]` / Go same-package tests.

## Candidate 2 — `sast-triage` + `sast-fix` over `sastctl`

**`Finding` is a fold over an append-only per-fingerprint event log**, not a mutable record.

- Every derived field computed by `fold()`, never stored. `appendEvent` hashes decisive stage
  inputs into `input_hash`; a repeat hash is a no-op, making idempotency structural.
- Per-fingerprint `.jsonl` files make parallel writes race-free by storage layout.
- `nextAction` is the sole lifecycle dispatcher, with an inline termination proof.
- `proof_obligation` (concrete input + expected unsafe/safe behavior) required by schema on
  every `confirmed`.
- `regression_detected` state for a finding that was fixed and came back.
- Token-type-sequence cosmetic-diff check, **with its blind spot stated plainly** (a
  real-shaped no-op call is not caught).
- **Defect (verified):** `instanceSeverity(v, ceiling) = min(...)` clamped into the gate, so
  rule-category severity caps what the fix decision can see — contradicting its own prose.
- **Defect (judge, unverified):** `proof_obligation` never mechanically run against the
  pre-patch baseline; red-green reduced to an LLM's opinion.

## Candidate 3 — `sast-triage` + `sast-remediate`, split on the mutation boundary

- Fingerprint from the sink's **enclosing-function identity**, not line number.
- Two skills split on trust/mutation, not pipeline stage: triage is read-only; remediate is
  the only thing with git write access.
- **Conflict graph** over findings (same file, line ranges within a window) partitioned into
  maximal independent sets; the parent computes and enforces it before spawning anyone.
- `checkSuppressionGate` — deterministic, zero-LLM, runs **before the verifier is spawned**,
  unbypassable by a well-argued fixer rationale.
- `PatternDefeatSignature` checklist that forces failure regardless of other checks passing.
- Differential exploit check with explicit `inconclusive_no_harness` degradation rather than
  pass-by-default.
- **Defect (judge):** no first-class `enforcement_point`; fixer's only sense of "where" came
  from the scanner's sink location.
- **Defect (judge):** taint path threaded into triage but absent from the fixer's receive-list.

## Candidate 4 — `vulnfix`, a fixpoint loop over a Case ledger

The structural dissenter, and the source of four grafts.

- **`Case` = one root cause, not one finding.** 487 observations fold to ~63 cases via
  `ClusterKey{cwe_family, sink_symbol, source_class}`. This is the cost lever.
- `Observation` (immutable fact) and `Case` (mutable judgment) are separate types.
- **A convergence loop, not a pipeline:** patching changes the tree, which changes scanner
  output, which creates work. `advance()` returns false at the fixpoint. `--resume` is the
  same call as a fresh run.
- **Witness with a mandatory pre-patch signal**, three tiers: `executable`, `static` (a narrow
  Semgrep rule the agent authors restating its own invariant, required to fire at an anchor
  pre-patch), `argued` (can never reach verified).
- **`rescan.finding_gone` is recorded and read by NO state transition.** The only candidate to
  get this right.
- Under-informed hostile auditor: four verdicts, one named `suppression`; denied the fixer's
  rationale, the rescan, and the witness result.
- `Lease` with TTL and a demonstrated expiry-and-reclaim path.
- Budget reserves auditors **before** resolvers.
- Contrarian position: triage and fix are **one agent** (the resolver). Adjudicated against —
  see `SYNTHESIS-NOTE.md` R2.
- **Defect (judge, unverified):** `Adjudication` documented as frozen for life while the
  transition table sends `rejected`/`below_gate` back to `open` ("no adjudication").
  Resolved structurally in the synthesis via the identity scheme rather than adopted.
