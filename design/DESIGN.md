# `sast-assist`: design sketch

Synthesized from four independent candidates. See `SYNTHESIS-NOTE.md` for the arena record
and `RATIONALE.md` for the reasoning. Grounded in `GROUNDING.md`.

The organizing idea, stated once so the rest reads as consequence:

> **Triage does not return a verdict. It returns a security contract, and the verdict falls
> out of it. The contract is frozen before any patch exists, and every patch must carry a
> witness that fires on the pre-patch tree and falls silent on the post-patch tree.**

A contract is `{invariant, violating_input, enforcement_point, witness, writable_scope,
forbidden_resolutions}`. One artifact answers all three downstream questions:

- **What is the bug?** `invariant` and `violating_input` answer it.
- **Where does the fix go?** `enforcement_point` answers it.
- **How do we know the fix worked?** `witness` answers it.

A pipeline whose triage emits a boolean forces the fixer to re-derive the security semantics
from the rule message and the verifier to re-derive them a third time from the diff. Three
independent derivations of one fact is where Constraint 4's failure mode is born: nobody
downstream holds an independent statement of what was supposed to become true, so the only
remaining test is whether the scanner stopped complaining.

---

## 1. Usage (caller's view): written first

```
  /sast-assist .                    # full run, default fix threshold = medium
  /sast-assist . --fix-at high      # only high + critical
  /sast-assist . --triage-only      # triage + report, touch nothing (CI-safe)
  /sast-assist . --scanners codeql
  /sast-assist . --scope src/api
  /sast-assist .                    # run again: resumes. There is no --resume flag.

Output, outside the target repo, at ~/sast-assist/<repo>/run-<N>/:
  REMEDIATION.md      what was fixed, what was not, and why. Read this first.
  HANDOFF.md          findings a human must resolve, each with its contract and a
                      failing witness test already committed on a retained branch.
  findings/<id>.json  one record per root cause, full history, schema-validated.

In the target repo:
  sast-fix/<id>/<n>                one branch per fix attempt
  sast-fix/integration-<run-id>    verified fixes, cherry-picked and re-tested.
                                   The only branch you need to look at. Never merged for you.
```

### Call site 1: the ordinary case

```
> /sast-assist .

Scanning (semgrep, codeql) ................ 341 raw results
Normalized ................................ 268 observations
Clustered ................................. 96 findings   (73 cross-scanner merges at one
                                              locus, 99 sites folded onto 21 shared root causes)
Deterministic pre-pass .................... 41 resolved without an agent
                                              (28 test/vendor/generated, 13 carried from run-3)
Triage (55 parallel refuters) ............. 19 exploitable · 27 not exploitable · 9 undecidable
Gate (fix-at: medium) ..................... 12 to fix, 7 report-only
Fix + verify (3 waves, conflict-partitioned)  9 verified
  witness tiers ........................... 6 dynamic · 2 executable · 1 structural
                                              2 fix_failed (witness stayed red)
                                              1 fix_failed (guard: added `# nosemgrep`)
Integration ............................... 9 cherry-picked, suite green, no new findings

  → sast-fix/integration-run-4 (9 commits, 9 new regression tests)
  → HANDOFF.md: 3 unfixable + 9 undecidable + 7 below threshold
```

The operator makes **one** decision: review and merge the integration branch. Not nine.

### Call site 2: resume after a crash

```
> /sast-assist .

Resuming run-4 (96 findings on disk).
  ingested 0 · triaged 96 · gated 96 · fixing 3 · verifying 0 · done 93
  2 leases expired (triage t_11; fixer f_04) — reclaimed.
  1 unaudited branch sast-fix/f_2b90ff/1 discarded.
Re-entering: 3 findings in `fixing`.
```

Re-running **is** the resume path. Stage is derived from the record's own shape, never
stored, so nothing can desync. Leases distinguish a crashed agent from a slow one.

### Call site 3: CI

```yaml
- run: claude -p "/sast-assist . --fix-at high --budget 60 --json" > result.json
- run: test "$(jq '.unverified_fixes' result.json)" = "0"
```

Exit non-zero only when the run could not reach a terminal state, never merely because
findings exist.

### Call site 4: guidance mode

```
> What does this CodeQL js/path-injection finding actually mean?
```

Loads, answers from `references/TRIAGE.md`, writes nothing, creates no directory, spawns no
fan-out. Per GROUNDING Constraint 5.

---

## 2. Module map

```
skills/sast-assist/
  SKILL.md                    operator commands, modes, stage machine, policy defaults
  references/
    INGEST.md                 scanner invocation + normalization  [scanner-format knowledge]
    TRIAGE.md                 refutation rubric + triage prompt   [security-semantics knowledge]
    FIX-AND-VERIFY.md         fixer + auditor prompts, witness discipline, branch protocol,
                              the seven verification obligations  [repo-build + patch knowledge]
    DYNAMIC-WITNESS.md        app-harness discovery, exchange authoring, observables,
                              controls, the execution sandbox     [app-runtime knowledge]
    REPORT.md                 artifact shapes and the coverage statement
  schema/
    finding.schema.json       THE record. Every stage writes into this one shape.
    agent-results.schema.json the three agent return envelopes
  bin/                        zero-dependency Node. Nothing is installed into the target.
    normalize.cjs             SARIF + semgrep-JSON -> Finding[]   (pure)
    cluster.cjs               Observation[] -> Finding[]           (pure)
    gate.cjs                  Triage + Policy -> GateDecision      (pure)
    patch-guard.cjs           diff -> GuardResult                  (pure)
    witness-run.cjs           differential witness runner          (deterministic, no LLM)
    app-harness.cjs           discover / boot / probe / reset / tear down the app
    partition.cjs             conflict graph -> FixWave[]          (pure)
    validate.cjs              schema gate for records and agent returns
    ledger.cjs                parent-only read/write/resume/lease over findings/
```

Eleven source files. The reference skill is twenty-two; §9 says what was dropped.

**Modules are cut by knowledge, not by execution order.** Ingest, triage, gate, fix and
verify are an execution order, and cutting modules along it is textbook temporal
decomposition.

- `INGEST.md` + `normalize.cjs` own **everything the system knows about scanner wire
  formats**. SARIF, `extra.metavars`, `partialFingerprints`, `security-severity` floats,
  `codeFlows`, all of it stops here. Nothing downstream imports a scanner type.
- `TRIAGE.md` owns **what makes a vulnerability real**: the refutation rubric, the closed
  rejection set, the severity anchors, the `undecidable` discipline.
- `FIX-AND-VERIFY.md` deliberately holds fixing **and** verifying together. They share the
  contract, the witness, and the branch protocol. Splitting them into `FIX.md` and
  `VERIFY.md` would be exactly the temporal cut.
- `DYNAMIC-WITNESS.md` is a **separate file because it is separate knowledge**, not a separate
  stage: how to boot this project's app, mint a dummy principal, drive it over an isolated
  loopback, and tear it down safely. A repo with no runnable service never loads it.
- The gate is not a file. It is thirty lines of pure function. Threshold semantics must
  never be a prompt.

**Call chain depth.** Tracing one finding end to end reads `SKILL.md`, then
`finding.schema.json`, then one reference file. Three files, never more.

---

## 3. The record

### 3.1 Two levels: Observation and Finding

```ts
/** One normalized scanner result. Immutable once written. A fact, not a judgment. */
type Observation = {
  scanner: "semgrep" | "codeql";
  rule_id: string;
  rule_name: string | null;
  native_fingerprint: string | null;  // semgrep extra.fingerprint | SARIF partialFingerprints
  message: string;
  claimed: ClaimedSeverity;           // in the scanner's OWN vocabulary. Never normalized.
  cwe: string[];
  owasp: string[];
  engine: string | null;              // "OSS" | "PRO" | "codeql/python-queries@1.2.3"
  suppressed_at_source: boolean;      // semgrep extra.is_ignored | SARIF suppressions[]
  raw_pointer: string;                // "scans/semgrep.json#/results/41" — provenance ONLY,
                                      // never re-parsed by the pipeline
  seen_in_rounds: number[];           // SINGLE SOURCE for "did this stop firing".
};

/** One locus, with every scanner observation that landed on it. */
type Site = { locus: LocusAnchor; observations: Observation[] };  // observations >= 1

/**
 * ONE ROOT CAUSE. The unit of triage, of patching, of witnessing, of commit, of review.
 * Forty Semgrep hits on one unsafe helper are one Finding, one contract, one patch.
 * The parent is the sole writer. Agents return values; they never touch shared state.
 */
type Finding = {
  schema_version: 1;
  id: FindingId;
  run_id: string;

  // ---- established at ingest, never rewritten ----
  invariant_class: InvariantClass;
  cluster: ClusterKey;            // why these sites are one root cause
  sites: Site[];                  // >= 1, append-only across rounds
  flow: TaintFlow;                // best evidence across all sites (§3.4)
  context: SourceContext;         // materialized source at scan_commit

  // ---- monotonic stage slots ----
  lease: Lease | null;            // set on dispatch, TTL'd, reclaimed on expiry
  triage: Triage | null;          // written ONCE, then frozen (§3.5)
  gate: GateDecision | null;      // pure function of (triage, policy)
  patches: PatchAttempt[];        // append-only, max length 2
  disposition: Disposition | null;// terminal

  prior: PriorLink | null;        // same id, or superseded id, in an earlier run
};
```

Four properties this shape is built to have:

1. **No re-derivation.** `flow.steps[].code` is materialized at ingest, so the triage agent
   never re-reads the repo to reconstruct a path CodeQL already computed. `triage.contract`
   is carried verbatim into the fixer and the auditor. `gate` is pure.
2. **Idempotent transitions.** Every transition is "write a `null` slot" or "append." Nothing
   is mutated in place. Re-running a stage whose slot is populated is a no-op by
   construction, not by a guard. Reinforced by `input_hash` at the store boundary (§5.1).
3. **Stage is derived, never stored** (§3.9). There is no `status` field to fall out of sync.
4. **No transport types on the public interface.** `Observation.claimed` keeps each scanner's
   native vocabulary, deliberately (§3.3), but nothing else has a scanner shape, and no
   consumer outside `normalize.cjs` and the report knows SARIF exists.

### 3.2 Identity, clustering, and the answer to Q7

```ts
type FindingId = string;   // "f_" + first 16 hex of sha256(cluster_material)

type LocusAnchor = {
  file: string;            // repo-relative, POSIX, non-traversing. Validated at ingest.
  symbol: string | null;   // enclosing function chain, "UserRepo.findByEmail"
  sink_digest: string;     // sha256 of sink line, inner whitespace collapsed
  line_at_scan: number;    // provenance ONLY. Never identity — lines move.
};

type ClusterKey = {
  invariant_class: InvariantClass;
  sink_symbol: string | null;   // the CALLEE. "db.query", "subprocess.run".
                                // This is what folds 40 call sites onto one root cause.
  source_class: string | null;  // the entry surface family, when the flow gives one
};
```

**Position on Q7: one Finding per root cause. Both scanners' observations live inside it,
and so do every call site that shares an enforcement point. Triaged once, fixed once.**

Two folds happen at ingest, in order:

```
FOLD 1 (cross-scanner, within a locus) — two raw results become one Site iff
  same file AND same invariant_class AND
    (same sink_digest) OR (|line_a - line_b| <= 2 AND same non-null enclosing symbol)

FOLD 2 (cross-site, root cause) — two Sites become one Finding iff
  same ClusterKey AND the sink_symbol is non-null
```

The ±2-line window covers Semgrep pointing at the call while CodeQL points at the argument
expression a line below. Without a resolved symbol on both sides the window is not applied:
**we would rather triage twice than merge two different bugs into one contract.** Fold 2
requires a non-null `sink_symbol` for the same reason, an unresolved callee never clusters.

Fold 2 is the cost lever that makes post-triage gating affordable. It is also reversible:
a triage agent that discovers two sites need *different* enforcement points returns
`{"split": [...]}`, and the parent re-emits them as separate Findings with `prior` links.
One split per finding per run; a second split escalates to the human queue.

Why not a `duplicate_of` pointer: a pointer means every downstream stage must decide whether
to follow it. That is information leakage. The dedup decision becomes a fact several modules
depend on. Folding at ingest means no other module knows dedup happened.

What plurality buys beyond cost: **evidence union** (CodeQL contributes the `codeFlow`,
Semgrep contributes `metavars` and the `likelihood × impact × confidence` triple. Neither
alone gives the best prompt); **corroboration as a priority signal**; and **per-scanner
reporting**, so the Semgrep owner learns which of *their* rule's results we rejected, by
native fingerprint, and rule tuning stays possible.

**Identity is computed by us, never from `extra.fingerprint` or `partialFingerprints`**,
which differ per scanner, per engine tier, and across version bumps. Native fingerprints are
retained inside `Observation` for incremental mapping.

**The reopen rule falls out of identity.** Identifiers are preserved in `sink_digest`, so
renaming `exec(cmd)` to `exec(sanitizedCmd)` yields a *different* id. Changed source therefore
produces a fresh Finding with a `prior` link rather than unfreezing a frozen triage.
A rename can never inherit a prior `not_exploitable`. This is why `triage` can be frozen
for life without a contradiction: reopening is a new record, not a mutated one.

### 3.3 Three severity vocabularies, kept apart

```ts
type Tri = "LOW" | "MEDIUM" | "HIGH";

type ClaimedSeverity =
  | { kind: "semgrep"; severity: "ERROR" | "WARNING" | "INFO";
      impact: Tri | null; likelihood: Tri | null; confidence: Tri | null }
  | { kind: "codeql"; problem_severity: "error" | "warning" | "recommendation";
      security_severity: number | null };   // 0.0 – 10.0
```

**Claimed severity is never normalized into a single enum, and this is deliberate.**
GROUNDING Constraint 3 establishes that no meaning-preserving mapping exists between
`ERROR/WARNING/INFO`, a 3×3×3 metadata cube, a continuous 0–10 float, and
`error/warning/recommendation`. Any collapsed enum is a lie every downstream consumer would
then trust.

Exactly two things read `claimed`, both narrow:

- `priority(f) → number`, used **only to order** triage and bound spend (§4.2). Ordering is
  lossy-tolerant in a way filtering is not.
- The report, which prints both scanners' claims beside our instance severity.

**Nothing else reads it. In particular the gate cannot**. `Triage` has no such field (§4.4).

### 3.4 The taint path: the answer to Q4

```ts
type FlowStep = {
  file: string; line: number; symbol: string | null;
  role: "source" | "propagation" | "sink";
  code: string;         // MATERIALIZED at ingest by reading the repo at scan_commit
  note: string | null;  // the scanner's own message for this step
};

type TaintFlow =
  | { kind: "traced"; provenance: "codeql_codeflows" | "semgrep_dataflow_trace";
      steps: FlowStep[] }                    // >=2, [0] source, [last] sink
  | { kind: "sink_only"; sink: FlowStep; reason: "scanner_emitted_no_flow" };
```

**The path survives because it is a first-class type with two constructors, and the prompt
builder switches on the constructor.** There is no "path" field that is sometimes empty.
`sink_only` is not a degenerate `traced`. It is a different situation producing a materially
different prompt. A flow is **never fabricated at ingest.**

- `traced` prompt: *"the path below is the scanner's claim. Attack it. Find the step where
  it is wrong."*
- `sink_only` prompt: *"no dataflow path was provided. Establish reachability from an
  attacker-controlled entry point yourself before asserting anything. If you cannot, the
  verdict is `not_exploitable / input_is_not_attacker_controlled`, or `undecidable` if the
  entry point is outside this repo."*

`FlowStep.code` is read once by the parent. For a nine-step CodeQL `threadFlow` this is the
difference between a prompt the agent reasons over and a scavenger hunt it abandons.

```
selectFlow: most steps wins; tie-break codeql > semgrep-PRO > semgrep-OSS; else sink_only.
```

### 3.5 Triage output: the contract

```ts
type Severity = "critical" | "high" | "medium" | "low" | "informational";

type Triage =
  | { verdict: "exploitable";
      established_by: Provenance;
      contract: SecurityContract;
      severity: Severity;      // INSTANCE severity, from demonstrated impact
      impact: string; likelihood: string; blast_radius: string }

  | { verdict: "not_exploitable";
      established_by: Provenance;
      refutation: { reason: RefutationReason; control: CodeRef | null; explanation: string } }

  | { verdict: "undecidable";
      established_by: Provenance;
      hypothesis: SecurityContract;
      blocker: { missing_fact: string;
                 resolve_by: "owner_observation" | "local_check"; plan: string } };

type Provenance = "agent" | "carried_from_prior_run" | "deterministic_prepass";
```

**`severity` exists only on the `exploitable` branch.** Not optional, not nullable, absent
from the type. The reference skill's "only confirmed records receive severity" made unrepresentable
rather than stated. The gate cannot accidentally read a severity nobody established.

```ts
type RefutationReason =
  | "input_is_not_attacker_controlled"
  | "control_on_path_already_enforces_invariant"
  | "sink_is_not_the_dangerous_overload"
  | "defense_in_depth_gap_only"        // a large share of SAST noise. Named, so it is countable.
  | "unreachable_code"
  | "test_or_fixture_or_generated_code"
  | "rule_semantics_mismatch";
```

Closed, not prose, because a rejection must be auditable and countable. "37 rejected as
`defense_in_depth_gap_only`" is a rule-tuning signal the security team can act on.

### 3.6 `SecurityContract`: the load-bearing type

```ts
type SecurityContract = {
  invariant: string;
    // The property that must hold, stated about VALUES and BOUNDARIES, never about rules.
    // Good: "every string reaching subprocess argv[0] is an element of the fixed
    //        ALLOWED_TOOLS list; user input may only select an index into it."
    // REJECTED BY THE SCHEMA GATE: any mention of a rule id, a scanner name, or the
    // words warning, finding or alert. This closes the way around §6.0.

  violating_input: string;      // a concrete VALUE, never a category

  enforcement_point: {
    file: string; symbol: string | null;
    rationale: string;          // why THIS is the last trusted decision point, not merely
                                // the nearest place a patch would compile
  };

  witness: Witness;

  writable_scope: string[];     // repo-relative globs the fixer may modify. Anything else
                                // it touches is a deterministic guard violation.

  forbidden_resolutions: string[];  // seeded fixed, extended per finding:
    //   "adding a nosemgrep / codeql[...] / lgtm[...] / noqa suppression"
    //   "renaming or aliasing the sink so the rule's pattern stops matching"
    //   "wrapping the sink in an indirection that changes nothing about the value"
    //   "logging or alerting on the violating input instead of rejecting it"
    //   "validating at the caller when an untrusted caller can bypass it"
    //   "deleting the code path instead of enforcing the invariant on it"
};
```

`enforcement_point` is a first-class field precisely because the right place to enforce an
invariant is frequently **upstream of the sink the scanner flagged**. A design that hands the
fixer only the sink location structurally invites a patch at the wrong boundary.

### 3.7 `Witness`: the answer to Q5, and the core of Constraint 4

Four tiers. The triage agent authors the **strongest enabled tier the repo can support**, and
`witness-run.cjs` executes it deterministically. No agent grades a witness.

```
executable  >  structural  >  argued          selected automatically
dynamic                                        opt-in, --witness=dynamic
```

**The `dynamic` tier is deferred.** It is built and proven end to end, but it is not selected
automatically, because it needs an application that boots cold with no network and no real
credentials plus fixture data a repository may not have. It is tracked in
`FUTURE-IMPROVEMENTS.md`. The rest of this section describes it as designed; read the tier
ordering above as the active default.

The **functional control is not deferred**. It was found while designing the dynamic tier but
applies to every tier, and without it a patch satisfies every other obligation by disabling the
functionality.

```ts
type Witness =
  /**
   * TIER 1 — drive the running application over its real network interface.
   * The only tier that proves the invariant holds at the boundary an attacker actually
   * reaches. A unit test on a handler can pass while the route stays exploitable through
   * middleware ordering, routing, content negotiation, serialization, or proxy
   * normalization. Applicable when the flow's source is a network entry point AND an
   * AppHarness was discovered.
   */
  | { tier: "dynamic";
      harness_id: string;           // which discovered AppHarness boots the target
      attack: HttpExchange;         // the violating_input, as a real request
      observable: Observable;       // what "the attack worked" means, checkable, bounded
      control: FunctionalControl;   // REQUIRED. See "the control is not optional" below.
      expected_pre_fix: "observable_fires";
      expected_post_fix: "observable_absent" }

  /** TIER 2 — the project's own test harness, driving the public entrypoint. */
  | { tier: "executable";
      framework: string;            // "pytest" | "jest" | "go test" | "cargo test"
      entrypoint: string;           // the PUBLIC surface named in the contract — the flow's
                                    // source, never an internal helper
      attack_input: string;
      asserts: string;
      command_template: string;
      control: FunctionalControl | null;   // required when a covering test exists; see below
      expected_pre_fix: "fail";     // literal type: the red-green obligation, in the type
      expected_post_fix: "pass" }

  /** TIER 3 — a narrow structural rule restating the invariant. */
  | { tier: "structural";
      rule_yaml: string;            // a NARROW Semgrep rule the triage agent authors,
                                    // restating its own invariant. Inlined, so the runner
                                    // never trusts a path.
      anchor: LocusAnchor;          // it must fire HERE pre-patch, not merely somewhere
      expected_pre_fix: "match";
      expected_post_fix: "no_match" }

  /** TIER 4 — no mechanical witness exists. Can never reach `verified`. */
  | { tier: "argued";
      obstacle: "no_test_harness" | "no_runnable_entrypoint" | "no_app_harness"
              | "invariant_is_configuration" | "invariant_is_cryptographic_parameter"
              | "requires_external_service";
      why: string };
```

```ts
/** A request the PARENT sends. Never a shell string — argv/structured fields only. */
type HttpExchange = {
  method: string; path: string;
  headers: Record<string, string>;      // dummy credentials only, minted by the harness
  query: Record<string, string>;
  body: { kind: "json"; value: unknown } | { kind: "form"; value: Record<string, string> }
      | { kind: "raw"; value: string; content_type: string } | { kind: "none" };
  as_principal: string;                 // which dummy identity, e.g. "tenant_b_user"
};

/**
 * What counts as "the attack worked" — deterministic, checkable by the runner, and BOUNDED
 * to the minimum effect that establishes the boundary failure, per the reference skill's
 * bounded-local-evidence rule. Stop at the smallest observable. Never escalate.
 */
type Observable =
  | { kind: "status_code";      equals: number }                  // e.g. 200 where 403 is due
  | { kind: "body_contains";    canary: string }                  // a planted dummy secret
  | { kind: "body_json_path";   path: string; equals: unknown }   // leaked field
  | { kind: "header_present";   name: string; matches: string }
  | { kind: "row_appears";      query: string; in_fixture_db: true }  // unauthorized write
  | { kind: "reflected_unescaped"; marker: string }               // XSS: marker survives raw
  | { kind: "latency_exceeds";  ms: number; baseline_ms: number }; // blind injection only

/**
 * THE CONTROL. A legitimate request that MUST succeed both pre- and post-patch.
 * Without it, "make the attack stop working" is satisfiable by breaking the endpoint.
 */
type FunctionalControl =
  | { kind: "http";          exchange: HttpExchange; expect: Observable }
  | { kind: "existing_test"; command_template: string }   // a suite test covering the
                                                          // legitimate path through this code
  | { kind: "unavailable";   why: string };               // allowed ONLY on tier 3/4

/** How to boot and drive this project's app. DISCOVERED from the repo, never invented. */
type AppHarness = {
  id: string;
  kind: "docker_compose" | "procfile" | "npm_script" | "django" | "rails" | "go_run"
      | "spring_boot" | "custom";
  up: string[];                  // argv
  ready: { probe_path: string; expect_status: number; timeout_s: number };
  base_url: string;              // isolated loopback only, ephemeral port
  down: string[];
  reset: string[] | null;        // restore fixture state between exchanges
  fixtures: { seed: string[] | null; dummy_principals: string[] };
  boot_s_observed: number | null;
};
```

```ts
type WitnessResult = {
  tier: Witness["tier"];
  pre:   { ran: boolean; signal: boolean; detail: string };  // signal = test failed /
                                                             // rule fired / observable fired
  post:  { ran: boolean; signal: boolean; detail: string };
  control: { ran: boolean; passed_pre: boolean; passed_post: boolean; detail: string }
         | { ran: false; why: string };
  differential_ok: boolean;   // pre.signal && !post.signal
  control_ok: boolean;        // control.ran ? (passed_pre && passed_post)
                              //             : tier === "structural" || tier === "argued"
                              // i.e. a missing control is only forgiven on tiers that
                              // cannot express one. Never on dynamic. Never on executable
                              // when a covering test exists.
  transcript_path: string | null;  // parent-recorded exchange log, redacted
};
```

Four properties make this non-gameable:

1. **The witness is authored at triage time, before any fix exists**, against the public
   entrypoint named in the contract. That is what makes the pre-fix run expressible, by
   construction it only touches API that already exists on the base commit.
2. **The pre-patch signal is mandatory.** You cannot write a witness for a suppression. A
   test cannot demonstrate that `nosemgrep` fixed something; a structural rule required to
   *fire* before the patch cannot be a rule that trivially never matches; and an HTTP attack
   that does not work before the patch proves nothing about after it.
3. **Vacuity is detected, not excused.** A witness that passes on base does not exercise the
   bug. A witness that *errors* on base depends on the fix's own new code. Both are
   `witness_vacuous`.
4. **The control is not optional.** Every tier that can express one must, and it must pass on
   *both* trees. This closes a hole the other obligations leave open: a patch can satisfy
   guard, witness, audit, and rescan by **disabling the functionality**. Return 500 to
   everything and the attack stops working. The project's regression suite is supposed to
   catch that, but a newly-touched route is exactly the kind of thing a suite tends not to
   cover. `witness_control_failed` is a first-class failure.

### Why the `dynamic` tier is worth its cost

For a web application it is the only tier that tests the thing an attacker touches. Source
analysis and unit tests both reason about the handler; the vulnerability frequently lives in
the gap between the handler and the wire. Middleware that runs in the wrong order, a
framework that re-parses a parameter the validator already checked, a serializer that
re-introduces the payload, a router that normalizes a traversal differently than the check
did. A fix verified only at the function boundary can leave every one of those intact.

It is also the tier most able to embarrass a plausible-looking patch, which is the point.

**Cost, and how it is contained.** Booting an app per finding, twice, is prohibitive. So:
`partitionForParallelFix` already groups non-conflicting findings into waves; the harness
boots **once per wave per tree** (base and head), every dynamic witness in that wave runs
against that instance, and `harness.reset` restores fixture state between exchanges. Findings
whose flow source is not a network entry point never select this tier, so a crypto-misuse in
a batch job costs nothing.

### Applicability

`selectWitnessTier` picks the strongest tier that is *available and meaningful*, and the
choice is recorded on the contract so the report can show the evidence strength distribution:

```
dynamic     iff an AppHarness was discovered AND flow.kind === "traced"
                AND the flow's source is a network entry surface
executable  iff a test command was discovered
structural  always available (Semgrep is already a dependency)
argued      only when the invariant is genuinely non-mechanical
```

A run where most contracts fall back to `structural` is telling you something real about the
repo, and `REMEDIATION.md` says so rather than reporting uniform confidence.

### The other tiers

The `structural` tier generalizes the defense to languages and sinks with no harness at all.
The agent writes a rule expressing *its own honest restatement* of the invariant, narrower
and more structural than the original, and the runner requires it to fire at `anchor` on the
pre-patch tree. To game it you would have to write a rule that fires on the buggy code and not
on the patched code *without the patch changing anything relevant*, which is the definition of
having changed something relevant. The auditor additionally reads the rule against the frozen
`invariant` and rejects one narrower than the invariant.

`argued` exists because some invariants have no mechanical witness (a hardcoded credential, a
weak KDF parameter). **It can never reach `verified`.** It reaches
`disposition.state = "fixed_unwitnessed"` and always requires human review, so "we fell back"
is visible in the report rather than invisible in the aggregate.
### 3.8 Patch, guard, and verification

```ts
type PatchAttempt = {
  attempt: 1 | 2;                  // hard cap, in the type. There is no attempt 3.
  branch: string;                  // "sast-fix/<id>/<attempt>"
  base_commit: string;             // identical across all findings in a run
  head_commit: string | null;      // null when the fixer produced no diff
  fixer_agent_id: string;
  declared_files: string[];        // what the fixer said it would touch, before touching it
  enforcement_note: string;        // its claim about HOW the invariant is now enforced
  witness_test_path: string | null;
  verification: Verification | null;
};

type Verification = {
  guard:      GuardResult;       // deterministic, no LLM
  witness:    WitnessResult;     // differential, run by witness-run.cjs
  regression: RegressionResult;  // the project's own suite
  rescan:     RescanResult;      // RECORDED, NOT A VERDICT INPUT. See §6.
  audit:      AuditResult;       // independent agent, tries to refute the fix
  outcome:    "verified" | "rejected";      // DERIVED by evaluateVerification()
  failures:   VerificationFailure[];        // empty iff outcome === "verified"
};

type RescanResult = {
  original_absent: boolean;   // RECORDED FOR THE REPORT ONLY. Never read by a transition.
  new_findings: FindingId[];  // ids on head, absent on base -> this IS a failure obligation
  scanners: ("semgrep" | "codeql")[];
};

type AuditResult = {
  auditor_agent_id: string;
  verdict: "enforces_invariant" | "silences_rule" | "moves_trust" | "incomplete_enforcement";
  trace: { step: string; loc: CodeRef }[];  // the frozen violating_input walked through the
                                            // PATCHED source, step by step
  stopped_at: CodeRef | null;               // where it dies. null with "enforces_invariant"
                                            // is a schema error.
  uncovered_siblings: CodeRef[];            // non-empty => must be "incomplete_enforcement"
  explanation: string;
};

type GuardViolation =
  | { kind: "suppression_comment_added";        file: string; line: number; text: string }
  | { kind: "scanner_config_modified";          files: string[] }
  | { kind: "ignore_file_modified";             files: string[] }
  | { kind: "rule_pack_pin_changed";            files: string[] }
  | { kind: "existing_test_weakened";           files: string[]; detail: string }
  | { kind: "test_skipped";                     files: string[]; detail: string }
  | { kind: "sink_deleted_without_enforcement"; detail: string }
  | { kind: "outside_writable_scope";           files: string[] }
  | { kind: "dependency_manifest_modified";     files: string[] }
  | { kind: "cosmetic_change_only";             detail: string }
  | { kind: "witness_missing";                  expected_tier: Witness["tier"] }
  | { kind: "app_harness_modified";             files: string[] };  // booting the app is not
                                                //   a place to hide a fix

type VerificationFailure =
  | { obligation: "guard";            violations: GuardViolation[] }
  | { obligation: "witness_vacuous";
      detail: "passed on the unpatched base — it does not exercise the bug"
            | "errored on the unpatched base — it depends on the fix's own code"
            | "structural rule did not fire at anchor on the unpatched base" }
  | { obligation: "witness_red";      output_excerpt: string }
  | { obligation: "witness_control_failed";
      detail: "the legitimate control request failed on the patched tree — the patch
               removed functionality rather than enforcing the invariant"
            | "the control failed on the BASE tree — the control is not a valid baseline" }
  | { obligation: "regression";       failing: string[]; output_excerpt: string }
  | { obligation: "rescan_new";       introduced: FindingId[] }
  | { obligation: "audit";            verdict: AuditResult["verdict"]; explanation: string }
  | { obligation: "integration";      conflicts_with: FindingId[] }
  | { obligation: "no_diff";          detail: string };
```

Note what is **absent**: there is no `rescan_original_present` obligation. §6.3 explains why
that omission is load-bearing rather than an oversight.

### 3.9 Terminal state, leases, and stage as a derived value

```ts
type Disposition =
  | { state: "fixed";              branch: string; commit: string; landed_in: string | null }
  | { state: "fixed_unwitnessed";  branch: string; commit: string; obstacle: string }
  | { state: "fix_failed";         attempts: 1 | 2; last_failures: VerificationFailure[];
      handoff: { contract: SecurityContract; witness_test_path: string | null;
                 branch: string; what_to_try: string } }
  | { state: "report_only";        gate: GateDecision }
  | { state: "deferred";           reason: "triage_budget_exhausted" | "scan_incomplete"
                                         | "unverifiable_fixes_not_permitted" };

type Lease = { agent_id: string; role: "triage" | "fix" | "audit";
               started_at: string; ttl_s: number };

type Stage = "ingested" | "triaged" | "gated" | "fixing" | "verifying" | "done";

/** The single source of truth for where a finding is. Stored nowhere. */
function stageOf(f: Finding): Stage {
  if (f.disposition)                       return "done";
  const last = f.patches.at(-1);
  if (last && last.verification === null)  return "verifying";
  if (f.gate?.action === "fix")            return "fixing";
  if (f.triage)                            return "gated";
  return "ingested";
}
```

There is no `status` field. Nothing can disagree with anything. Crash recovery is a `switch`
over `stageOf` plus lease expiry: an empty slot with a live lease is in flight; an empty slot
with an expired lease is reclaimable; an unaudited branch from an expired fix lease is
discarded. Without leases, "no patch record" cannot distinguish a crashed agent from a slow
one.

`fix_failed` carries a **handoff**, not just a failure. The branch is retained, the red
witness is on it, and the contract explains what must hold. A human inherits a failing test
that encodes the bug, most of the work. This is why the loop may give up cheaply: giving up
still ships something.

---

## 4. Signatures

### 4.1 Ingest and cluster

```ts
/**
 * Parse both scanners' native output. The ONLY place SARIF or semgrep-JSON exists.
 * Invariants established here and trusted everywhere downstream, per boundary-discipline:
 *  - every `file` is repo-relative, POSIX, non-traversing, and exists at scan_commit
 *  - every `id` is unique; `flow` is well-formed; `sites` non-empty
 */
function normalize(raw: { semgrep?: SemgrepJson; codeql?: Sarif },
                   repo: RepoSnapshot, runId: string): Finding[] {
  throw new Error("not implemented");
}
// TODO(normalize):
//  1. flatten each scanner to RawResult{file,line,rule_id,cwe[],message,flow?,claimed}
//     - semgrep: results[].{check_id,path,start.line,extra.*}
//     - codeql:  runs[].results[] JOINED to runs[].tool.driver.rules[] for the property bag
//                (security-severity and problem.severity live on the RULE, not the result)
//  2. drop any result whose path escapes the repo root or does not exist; count the drops
//  3. invariant_class := cweTable(cwe) ?? ruleIdKeywordTable(rule_id) ?? "other"
//  4. locus := {file, symbol: logicalLocation ?? scanForEnclosingSymbol(repo,file,line),
//               sink_digest: sha256(collapseInnerWs(repo.line(file,line))), line_at_scan}
//  5. FOLD 1 -> Site[]   (§3.2)
//  6. FOLD 2 -> Finding[] via cluster.cjs, keyed on ClusterKey   (§3.2)
//  7. flow := selectFlow(sites); hydrate every FlowStep.code from `repo`, never from an agent
//  8. context.source_hash := sha256(enclosing function text)  -- drives prior-run carry
```

### 4.2 Prioritize and pre-resolve: the cheap half of triage

```ts
/** Ordering ONLY. Never filters. Deterministic; ties break by id. */
function priority(f: Finding): number { throw new Error("not implemented"); }
// TODO: 3*classRisk(invariant_class) + 2*claimedRank(sites) + 2*(flow.kind==="traced")
//     + 1*(distinct scanners > 1) + 1*entrypointProximity(file) + 1*log2(sites.length)
//     - 3*(every observation suppressed_at_source)
//   claimedRank switches exhaustively on ClaimedSeverity.kind and is the ONLY consumer
//   of `claimed` besides the report.

/** Resolve what can be resolved without spending an agent. Each resolved finding gets a
 *  REAL Triage with `established_by` set — not a special "skipped" state. */
function prefilter(findings: Finding[], policy: Policy, prior: PriorRun | null):
  { toAgent: Finding[]; resolved: Finding[] } { throw new Error("not implemented"); }
// TODO, first match wins:
//  a) every site matches policy.exclude_globs (test/vendor/generated/minified/migrations)
//       -> not_exploitable / test_or_fixture_or_generated_code, "deterministic_prepass"
//       NOTE: a POLICY rejection, not a security claim. REPORT.md says so under its own
//       heading. --include-tests disables it.
//  b) prior run has this id, verdict not_exploitable, AND unchanged context.source_hash
//       -> carry the refutation verbatim, "carried_from_prior_run"
//     Prior `exploitable` and `undecidable` are NEVER carried — they are current work.
//  c) prior run has this id with disposition `fixed` and the finding is BACK
//       -> regression_detected: route straight to `gate` on the PRIOR triage (same root
//          cause, already characterized). The one place a prior confirmation is reused,
//          because re-triaging a known-fixed-then-reverted bug is pure waste.
//  d) otherwise -> toAgent, sorted by priority() desc, id asc
```

### 4.3 Triage fan-out

```ts
function planTriage(toAgent: Finding[], budget: number):
  { dispatch: Finding[]; deferred: Finding[] } { throw new Error("not implemented"); }
// TODO: ONE agent per Finding. Clustering already did the cost amortization that batching
//   would otherwise buy, and batching lets one agent's bias taint several verdicts at once.
//   Emit in descending priority() until `budget` is spent; the remainder is `deferred`,
//   PERSISTED with no triage so the next run picks it up first. Never dropped.

function buildTriagePrompt(f: Finding, rubric: string): string {
  throw new Error("not implemented");
}
// TODO: switch on f.flow.kind for the traced vs sink_only instruction body (§3.4).
//   Embed agent-results.schema.json#/triage verbatim. NEVER embed another agent's
//   conclusion, and never a prior-run verdict for this same finding.
```

### 4.4 The gate: Q3's answer in thirty lines

```ts
type Policy = {
  fix_at: Severity;                 // default "medium"
  scanners: ("semgrep" | "codeql")[];
  scope: string[]; exclude_globs: string[]; include_tests: boolean;
  triage_budget: number | null; fix_budget: number | null;
  allow_unverified_fixes: boolean;  // default FALSE
  land: boolean;                    // default true
};

/** Pure. Total. No LLM. The ONLY place the threshold is interpreted. */
function gate(t: Triage, p: Policy): GateDecision { throw new Error("not implemented"); }
// TODO:
//   switch (t.verdict) {
//     case "not_exploitable": return { action: "report_only", reason: "not_exploitable" };
//     case "undecidable":     return { action: "report_only", reason: "undecidable" };
//     case "exploitable":
//       return rank(t.severity) >= rank(p.fix_at)
//         ? { action: "fix", threshold: p.fix_at, reason: "at_or_above_threshold" }
//         : { action: "report_only", reason: "below_threshold" };
//   }
// It never reads a scanner's claim. It CANNOT: `t` does not contain one, and there is no
// ceiling parameter to clamp against. See §5 and SYNTHESIS-NOTE rejection R1.
```

### 4.5 Fix, guard, verify

```ts
function buildFixPrompt(f: Finding, repo: RepoFacts): string {
  throw new Error("not implemented");
}
// TODO: assemble from f.triage.contract, f.flow (threaded in FULL — the fixer needs the
//   path to patch the right boundary), f.context, and repo.{build,test,lint}.
//   MUST NOT include: any Observation, any rule_id, any scanner name, any scanner message,
//   f.triage.impact/likelihood prose, or the run's report. See §6.0.

function buildAuditPrompt(f: Finding, a: PatchAttempt, diff: string): string {
  throw new Error("not implemented");
}
// TODO: frozen contract + diff + witness source + a.enforcement_note framed as
//   "the author claims this; disprove it".
//   MUST NOT include: the fixer's reasoning transcript, the mechanical results, the
//   witness OUTCOME, or the rescan. An auditor told "everything mechanical passed" grades
//   a conclusion instead of reading the code.

/** Deterministic. Runs before any test, any scan, any agent. Cheapest gate first. */
function guardDiff(diff: UnifiedDiff, c: SecurityContract, repo: RepoFacts): GuardResult {
  throw new Error("not implemented");
}
// TODO, each independently sufficient to fail:
//  - added line matching /\b(nosemgrep|nosem|codeql\s*\[|lgtm\s*\[|noqa|NOSONAR|#\s*nosec|
//    eslint-disable|@SuppressWarnings|#\s*type:\s*ignore)\b/  -> suppression_comment_added
//  - touched {.semgrep.yml,.semgrepignore,semgrep rules dirs,.github/codeql/**,
//    codeql-config.yml,qlpack.yml,.codeqlignore}              -> scanner_config_modified
//  - a pinned pack/suite version or selection changed          -> rule_pack_pin_changed
//  - removed assert token in a pre-existing test, or a deleted test fn -> existing_test_weakened
//  - added .skip/xit/@Ignore/t.Skip on an existing test         -> test_skipped
//  - touched path not matching c.writable_scope                 -> outside_writable_scope
//  - touched dependency manifest (package.json, requirements.txt, go.mod, Cargo.toml,
//    pom.xml, *.lock) -> dependency_manifest_modified
//    (a fix needing a new dependency is a human decision, not an agent's)
//  - COSMETIC CHECK: tokenize the sink region before and after with a language-aware lexer
//    (generic identifier/string/number/operator/keyword lexer as fallback); strip comments
//    and whitespace; compare TOKEN-TYPE sequences. Identical sequences => provably a
//    rename/relabel/reformat -> cosmetic_change_only.
//    KNOWN BLIND SPOT, stated rather than hidden: a real-shaped but behaviorally no-op call
//    changes the type sequence and is NOT caught here. It is caught by the differential
//    witness, which exercises behavior instead of shape.
//  - touched {docker-compose.y*ml, Procfile, the harness `up`/`ready` target, the
//    [harness] block of .sast-assist.toml} -> app_harness_modified
//    (a patch that edits how the app boots can make a dynamic witness pass without
//     fixing anything — the same defeat as editing scanner config)
//  - c.witness.tier !== "argued" and the diff adds no witness file -> witness_missing
//  - sink line deleted with no added validation/allowlist/escape construct in the
//    enforcement_point file -> sink_deleted_without_enforcement (loose heuristic; the
//    auditor is the real check for this one)

/** Pick the strongest witness tier that is available AND meaningful for this finding.
 *  Pure. Called by the parent before the triage prompt is built, so the agent is told which
 *  tier to author rather than choosing one it might not be able to run. */
function selectWitnessTier(f: Finding, repo: RepoFacts,
                           harnesses: AppHarness[]): Witness["tier"] {
  throw new Error("not implemented");
}
// TODO, first match wins:
//   "dynamic"    harnesses.length > 0 AND f.flow.kind === "traced"
//                AND isNetworkEntrySurface(f.flow.steps[0])
//   "executable" repo.test_command !== null
//   "structural" always (Semgrep is already a dependency)
//   "argued"     never selected here — only a triage agent may downgrade TO it, and only
//                by naming an obstacle. The parent never pre-authorizes giving up.

/** Discover how to boot this project's app. Pure over a repo snapshot. Never invents. */
function discoverAppHarness(repo: RepoSnapshot): AppHarness[] {
  throw new Error("not implemented");
}
// TODO, in precedence order; return every match so the agent can pick:
//  docker-compose.y*ml with a service exposing a port  -> kind "docker_compose"
//  Procfile `web:`                                      -> "procfile"
//  package.json scripts.{start,dev,serve}               -> "npm_script"
//  manage.py + settings module                          -> "django"
//  config.ru / bin/rails                                -> "rails"
//  main.go with net/http ListenAndServe                 -> "go_run"
//  src/main/resources/application.y*ml                  -> "spring_boot"
//  .sast-assist.toml [harness] block                 -> "custom" (always wins)
//  For each: derive `ready` from a health/readiness route if one exists, else
//  GET / expecting any < 500. ALWAYS bind an ephemeral port on loopback; never a fixed
//  port, never 0.0.0.0. If no candidate -> [] and the dynamic tier is unavailable.

/** Deterministic. No agent grades a witness. The PARENT drives every exchange. */
function runWitness(w: Witness, base: Worktree, head: Worktree,
                    boot: BootedHarness | null): WitnessResult {
  throw new Error("not implemented");
}
// TODO:
//  dynamic: requires `boot` (one instance per tree per wave; see §4.6).
//    1. harness.reset; send w.control.exchange -> must satisfy control.expect on BASE.
//       If it fails here the control is not a valid baseline -> witness_control_failed.
//    2. harness.reset; send w.attack to BASE -> w.observable MUST fire. If not,
//       pre.signal=false -> witness_vacuous (the attack does not work; nothing was proven).
//    3. on HEAD: harness.reset; send w.attack -> observable MUST NOT fire.
//    4. harness.reset; send w.control -> MUST still satisfy control.expect.
//       This is the step that catches "fixed it by breaking the endpoint".
//    The parent performs every request itself and records the transcript, redacting
//    header values by name against an allowlist. Evidence therefore never originates
//    inside target-controlled code. See §6.5.
//  executable: check out base in a scratch worktree, apply ONLY the witness test file from
//    the patch branch, run command_template.
//      pass  -> pre.signal=false -> witness_vacuous (does not exercise the bug)
//      error -> pre.signal=false -> witness_vacuous (depends on the fix's own code)
//      fail  -> pre.signal=true. Then run on head; must pass.
//    If w.control is an existing_test, run it on BOTH trees; both must pass.
//  structural: run the inlined rule_yaml against base; require a match AT anchor (not merely
//    somewhere in the file). Then against head; require no match at anchor.
//  argued: no run. differential_ok=false by definition; outcome can only be fixed_unwitnessed.

/** Pure. The ONLY definition of "verified". */
function evaluateVerification(g: GuardResult, w: WitnessResult, r: RegressionResult,
                              s: RescanResult, a: AuditResult, p: Policy): Verification {
  throw new Error("not implemented");
}
// TODO: collect failures; outcome := failures.length === 0 ? "verified" : "rejected".
//   guard      : !g.passed                                  -> { guard }
//   witness    : !w.pre.signal                              -> { witness_vacuous }
//                w.post.signal                              -> { witness_red }
//                !w.control_ok                              -> { witness_control_failed }
//   regression : "fail"                                     -> { regression }
//                "unavailable" && !p.allow_unverified_fixes -> { regression }
//   rescan     : s.new_findings.length > 0                  -> { rescan_new }
//                // s.original_absent is RECORDED AND NEVER READ HERE. §6.3.
//   audit      : a.verdict !== "enforces_invariant"         -> { audit }
```

### 4.6 Conflict-partitioned fix waves

```ts
type FixWave = { wave: number; findings: FindingId[] };  // mutually non-conflicting

function partitionForParallelFix(fs: Finding[], conflictWindow = 20): FixWave[] {
  throw new Error("not implemented");
}
// TODO:
//  1. build an undirected conflict graph: edge between two findings iff any of their sites
//     share a file AND their line ranges are within conflictWindow. Different files never
//     conflict. A multi-site finding contributes every one of its sites.
//  2. repeatedly take a maximal independent set (sorted by id for determinism) as the next
//     wave. Connected findings land in different waves.
//  3. wave N worktrees branch off base_commit; wave N+1 branches off the integration tip
//     AFTER wave N's verified fixes are picked.
//  4. If any finding in the wave carries a `dynamic` witness, boot the harness ONCE per
//     tree for the whole wave (base instance + head instance) and hand both to verifyOne.
//     This is why waves exist for cost as well as for collision safety: app boot is the
//     most expensive thing in the run and it amortizes across the wave.
//  The PARENT computes and enforces this before spawning anyone. It is never an agent's job
//  to notice it is about to collide, per separate-before-serializing-shared-state.
```

### 4.7 One finding's verification, cheapest first

```ts
async function verifyOne(f: Finding, a: PatchAttempt, io: Io): Promise<Verification> {
  throw new Error("not implemented");
}
// TODO — short-circuit on first failure EXCEPT the audit, which always runs so attempt 2
//        gets a real explanation:
//  1. diff; if empty -> failures [{no_diff}]. Stop. Zero agent spend.
//  2. guard := guardDiff(...)                     // milliseconds, no LLM
//     if !passed -> record, still run the auditor for its explanation, stop.
//  3. witness := runWitness(w, base, head, boot)  // the red half, then the green half,
//     then the control on both trees. `boot` is the wave's harness pair, or null.
//  4. regression: the project's discovered suite on the patch branch. A suite already red
//     on base yields "unavailable"/"suite_red_on_base" rather than blaming the patch.
//  5. rescan: same scanner set on the patch branch. Compute new_findings (ids on head minus
//     ids on base). RECORD original_absent for the report. Do not branch on it.
//  6. audit: fresh agent that did not triage and did not fix this finding.
//  7. evaluateVerification(...)
```

### 4.8 Landing

```ts
async function integrate(verified: Finding[], io: Io): Promise<Integration> {
  throw new Error("not implemented");
}
// TODO: branch sast-fix/integration-<run_id> off base_commit; cherry-pick each verified
//   finding's commit in id order. A conflict marks THAT finding
//   fix_failed/{obligation:"integration"} and skips the pick, so the branch always builds
//   from a consistent subset. Then, once, on the integration branch:
//     - the full project suite (catches "each fix fine alone, together broken")
//     - every landed witness, re-run
//     - a full rescan; any NEW finding vs base fails integration and bisects the picks to
//       name the culprit (log2 n rescans, capped at 6)
//   NEVER merges. NEVER pushes. Writes the branch name and a PR body.
```

### 4.9 The shell: one entry point

```ts
/** Everything the operator can run. Idempotent: re-invoking resumes. */
async function remediate(policy: Policy, target: string, io: Io): Promise<RunSummary> {
  throw new Error("not implemented");
}
// TODO:
//   run := openOrCreateRun(target, policy, io)          // run-metadata.json, base_commit
//   if no scan artifacts: runScanners(...); ledger.writeAll(normalize(...))
//   reclaimExpiredLeases(ledger); discardUnauditedBranches(ledger, io)
//   { toAgent, resolved } := prefilter(...); ledger.write(resolved)
//   { dispatch, deferred } := planTriage(...); ledger.write(deferred.map(markDeferred))
//   for each wave of dispatch:
//       results := io.tasks(dispatch.map(f => ({ prompt: buildTriagePrompt(f, rubric) })))
//       validate each against agent-results.schema#/triage
//         - malformed -> DISCARD, never repair; re-run once with a fresh agent, then defer
//         - well-formed -> ledger.write(f with .triage set)     // parent is sole writer
//   for f in stage "gated": ledger.write({...f, gate: gate(f.triage, policy)})
//   if no test command discoverable && !policy.allow_unverified_fixes:
//       mark fixable `deferred`/"unverifiable_fixes_not_permitted"; skip to report   // §6.5
//   for wave of partitionForParallelFix(fixable):
//       worktree + branch per finding; io.tasks(fix prompts); verifyOne each
//       on rejected && attempt === 1: build attempt 2 with the TYPED failures
//   if policy.land: integrate(...)
//   report(...)
```

---

## 5. Position on Q3: the threshold gate

**The gate is strictly post-triage, on the triage agent's instance severity. The pre-triage
step exists, but it is a budget allocator, not a severity filter, and it never discards a
finding. No ceiling derived from scanner severity ever clamps the gated value.**

The question as posed ("pre- or post-triage?") is a false binary running two jobs together.

**Why the fix gate must be post-triage.** Scanner severity is *rule-category* severity, a
property of the rule, not the instance. `ERROR` on `dangerous-subprocess-use` says "command
injection is bad," not "this call is exploitable." And `security-severity: 3.8` on a rule
whose instance sits on an unauthenticated route is a critical a pre-gate would discard.

**Why a "ceiling" is not a safe compromise.** Two candidates proposed clamping the agent's
instance severity to a scanner-derived ceiling, arguing the ceiling is the most generous
plausible reading and so can only save spend. It cannot. The moment the clamp is applied to
the value the gate reads, the scanner's rule-category severity caps what the fix decision can
ever see. Which is precisely the conflation Constraint 3 warns about, reintroduced one layer
down and harder to see. `gate()` therefore takes `Triage` and `Policy` and nothing else.

**Why the pre-pass does not filter either.** A discarded finding is re-derived next run at
full cost and, worse, is invisible. Nobody can audit a decision that left no record. So
everything the scanners produce is ingested, clustered, and persisted. The pre-pass *orders*
and *bounds*; unspent budget produces `deferred`, a persisted state the next run picks up
first.

**Why this does not cost a triage pass on every INFO.** Two tiers absorb it:

- **Clustering** (§3.2) is the main lever: 268 observations became 96 findings in the worked
  example, and 21 root causes absorbed 99 sites. You pay per root cause, not per hit.
- **The deterministic pre-pass** resolves path-policy and prior-run-carry cases for zero
  agent spend, each with a genuine `Triage` record.

**Where scanner severity is allowed to matter:** ordering, inside `priority()`. If budget runs
out, what got triaged is what both scanners flagged, on a traced path, in an injection class,
near an entry point. That is the right use of a weak prior.

---

## 6. Position on Q5: what stops the fixer from defeating the pattern matcher

Six obligations. A fix is `verified` only if all pass. `evaluateVerification` is the sole
definition and it is a pure function, not a prompt.

### 6.0 The structural move: the fixer is never shown the rule

`buildFixPrompt` receives the contract, the flow, and the source context. It does **not**
receive the rule id, the scanner name, the scanner's message, or any `Observation`. The fixer
also has no tool access to run a scanner.

You cannot game a matcher you were never shown. An agent told *"Semgrep's
`dangerous-subprocess-use` fires at line 41"* has an obvious cheapest path: make line 41 stop
matching. An agent told *"every string reaching subprocess argv[0] must be an element of
ALLOWED_TOOLS"* has no such shortcut available. The only way to satisfy it is to enforce it.

The schema gate closes the way around it. `contract.invariant` may not mention a rule id, a
scanner name, or the words warning/finding/alert. Otherwise a triage agent could leak the rule
into the contract and hand the fixer the target anyway.

### 6.1 The seven obligations

| # | Obligation | Mechanism | Defeats |
|---|---|---|---|
| 1 | **Frozen target** | the contract is written before the patch exists and is immutable across retries | the fixer redefining success |
| 2 | **Deterministic guard** | `guardDiff`: suppression tokens, scanner config, ignore files, rule-pack pins, weakened/skipped tests, out-of-scope writes, dependency manifests, cosmetic token-sequence identity | the laziest 80%, for free, before any agent spend |
| 3 | **Differential witness** | must signal pre-patch, must not post-patch, run by `witness-run.cjs`; strongest available tier, `dynamic` drives the real running app over HTTP | everything, because a suppression cannot produce a pre-patch signal |
| 4 | **Functional control** | a legitimate request or covering test that must pass on **both** trees | "fixing" the bug by disabling the functionality |
| 5 | **Regression suite** | the project's own tests | "does the code still work", the other half of the user's sentence |
| 6 | **No new findings** | rescan delta vs base; any introduced finding fails | fixing A by creating B |
| 7 | **Under-informed hostile auditor** | given the frozen contract and the diff; denied the fixer's rationale transcript, the mechanical results, the witness outcome, and the rescan; four verdicts, one named `silences_rule` | semantic suppressions the guard cannot see, moved indirection, renamed variable, refactor that looks unreachable |

Obligations 3 and 4 are a pair and neither is sufficient alone. Obligation 3 asks "did the
attack stop working?", satisfiable by breaking the endpoint. Obligation 4 asks "does the
legitimate path still work?", satisfiable by changing nothing. Only together do they say
"this code does what it did, minus the vulnerability." The regression suite (5) is a weaker
version of 4 that happens to cover the whole repo; 4 is aimed at the specific route the patch
touched, which is exactly what a suite tends not to cover.

Obligation 2's cosmetic check and obligation 3 are deliberately complementary. The token-type
comparison catches pure renames and reformats at near-zero cost but **cannot** catch a
real-shaped, behaviorally-no-op call. That case is caught by the witness, which exercises
behavior rather than shape. Stating the blind spot is the point: an undocumented gap is one
someone later assumes is covered.

### 6.2 Why the auditor is kept under-informed

An auditor told "the witness went green and the scanner is quiet" grades a conclusion. An
auditor given only the frozen contract and the diff must walk the `violating_input` through
the patched source and say where it dies. `stopped_at: null` with verdict
`enforces_invariant` is a schema error, it forces the auditor to point at a line.

### 6.3 Why "the scanner stopped reporting it" is recorded but never read

This is the one place the synthesis overrides three of its four inputs.

Making scanner silence a *required* obligation looks conservative and is not. SAST rules match
shapes, and plenty of genuinely fixed code keeps the shape, a properly parameterized query
or a correctly validated path can still trip the rule. When a correct fix is rejected for
failing this gate, the agent retries, and the cheapest edit that satisfies it on attempt two
is exactly the pattern-defeating change the entire design exists to prevent. **A gate that
creates pressure toward the behavior it forbids is worse than no gate.**

So `rescan.original_absent` is computed, stored, and printed in the report, it is useful
signal for rule tuning and for a human reviewer, and **no state transition reads it**. The
rescan contributes exactly one failure obligation, `rescan_new`, which is about findings the
patch *introduced*. Obligations 3 and 6 carry the "is the vulnerability gone" question.

### 6.4 When there is no way to verify

If no test command is discoverable, the run **refuses to patch** and degrades to triage-only
unless `--allow-unverified-fixes` is passed explicitly. Shipping unverified security patches
by default is worse than shipping a report. `RegressionResult.status: "unavailable"` is never
coerced to a pass.

### 6.5 Execution safety: what changes once we boot the app

Every other obligation reads source or runs the project's own tests. The `dynamic` tier runs
**target-controlled code as a service**, which is a different risk class, so the reference skill's
execution boundary applies in full and is not optional:

- **Never a deployed environment.** No staging, no shared instance, no provider API, no real
  credential, no live control plane. The harness boots a fresh local instance and tears it
  down. If a decisive fact lives only in a deployment, that is `undecidable` with an
  owner-observed plan, not a request we send somewhere.
- **Isolated loopback, ephemeral port.** Bound to localhost in its own network namespace where
  the platform provides one. External networking disabled; a harness that cannot start without
  reaching the internet makes the tier unavailable rather than earning an exception.
- **Empty, allowlisted environment.** Populated from an explicit allowlist with safe values;
  scratch-local `HOME`, temp dirs and caches. Never the ambient environment.
- **Dummy everything.** Fixture database, dummy principals minted by the harness, planted
  canaries. Never real data, never a real tenant, never another user's records.
- **Bounded to the minimum observable.** Stop at the first status code, canary, or unauthorized
  fixture row that establishes the boundary failure. Do not escalate, pivot, persist, or
  continue past it. `Observable` is a closed union precisely so "how far did we go" is a
  design-time decision rather than an agent's judgment in the moment.
- **Resource and wall-clock limits** on the harness process, with teardown guaranteed on
  timeout.
- **No dependency installation.** A harness that requires fetching packages makes the tier
  unavailable.

**This revises a claim made in §9.** The original argument for dropping the reference skill's 11-step
artifact-promotion procedure was that "we run the project's own test suite and our agents
return JSON, so no artifact crosses a trust boundary." With a live application that argument no
longer holds on its own. An HTTP transcript is evidence produced in the presence of
target-controlled code.

The resolution is structural rather than procedural: **the parent drives every exchange
itself.** It sends the request, reads the response, and writes the transcript. Evidence
therefore never originates inside the target-controlled process and never has to be promoted
out of it. Header values are redacted by name against an allowlist before the transcript is
retained. The sandboxed process writes only to its own scratch, and nothing in scratch is ever
read as evidence.

If any control above cannot be enforced, the dynamic tier is **unavailable**, not
best-effort. `selectWitnessTier` falls back and records `obstacle: "no_app_harness"`.

---

## 7. Agent contracts

Three roles. Each returns exactly one JSON object and no surrounding prose. A malformed or
prose-wrapped result is **discarded, never repaired**, and re-run once with a fresh agent
(The reference skill's rule). Each agent gets its own `agents/<id>/scratch/`; the parent is the sole
writer of everything shared.

| Role | Receives | Never receives | Returns |
|---|---|---|---|
| **triager** | the Finding, flow, materialized source, refutation rubric, severity anchors, the discovered `AppHarness[]` and test command (so it can author the strongest witness tier), the schema branch | another agent's conclusion; a prior verdict for this finding | `{verdict, ...}` per §3.5, or `{"split": [...]}` |
| **fixer** | frozen contract, full flow, source context, repo build/test commands, prior typed failures on attempt 2 | rule id, scanner name, scanner message, any Observation, triage prose; no scanner tool access | `{outcome: "patched"\|"cannot_fix", ...}` |
| **auditor** | frozen contract, the diff, the witness source | the fixer's rationale transcript, mechanical results, witness outcome, rescan, the triager's identity | `AuditResult` per §3.8 |

The **fixer's refusal path** (`cannot_fix`) is why triage and fix are separate agents, and is
the direct answer to the arena's central disagreement. A second, independent mind cold-reading
the frozen contract can decline *before* any patch or witness is written. An agent that just
concluded "verdict: exploitable" is very unlikely to conclude two steps later "actually I am
not sure this is enforceable". Self-consistency pressure runs the wrong way. That checkpoint
cannot exist by construction in a merged triage-and-fix agent.

---

## 8. Idempotency and the store boundary

```ts
function appendStage(store: FindingStore, id: FindingId, stage: Stage,
                     payload: unknown, inputHash: string): Finding {
  throw new Error("not implemented");
}
// TODO:
//  1. validate payload against schema/<stage>.schema.json. Reject and throw on failure.
//     Never coerce or repair; the caller re-runs the producing agent fresh.
//  2. if the record's existing entry for `stage` carries the same inputHash -> return it
//     UNCHANGED. This is the crash-between-return-and-record path: on resume the parent
//     re-derives the same inputHash (a hash of the stage's decisive inputs — for `fix`,
//     hash(contract + base_commit) — never a random id), calls again, and gets the prior
//     result instead of double-fixing.
//  3. otherwise write findings/<id>.json atomically (tmp + rename) and fsync.
```

One file per finding. The parent is the only writer, so parallel agents never contend.

---

## 9. What we took from the reference skill, and what we dropped

**Taken:** adversarial validation (the checker is never the actor); three verdicts with
`undecidable` carrying an exact unresolved fact and no severity; stable identity across state
changes; parent-as-sole-writer with per-agent scratch; schema-plus-zero-dep-validator as a
hard gate with malformed results discarded rather than repaired; severity requires
demonstrated impact, and overall never exceeds it; `defense_in_depth_gap_only` as a named
rejection; prior runs as inputs where a prior rejection suppresses only the unchanged claim;
guidance-vs-full-run mode split; budget reserves. Verification capacity is reserved before
fixers are dispatched.

**Dropped, with reasons:**

- **The coverage ledger and coverage-critic waves.** Their six phases exist to answer "did we
  look everywhere," which LLM hunters cannot answer deterministically. Semgrep and CodeQL
  already answer it: coverage is the rule packs that ran against a commit. Importing the
  ledger would be ceremony over a settled question.
- **The 11-step `fstat` artifact-promotion ritual, but not the sandbox it protects.** Their
  procedure exists because hunters execute target-controlled fuzzers and parsers and must lift
  evidence *out of* a scratch directory the target could have tampered with. We avoid the
  promotion problem by never creating it: for tests, agents return JSON; for the dynamic tier,
  **the parent drives the exchanges and records the transcript itself**, so evidence never
  originates inside target-controlled code. The execution sandbox around a booted application
  is adopted in full (§6.5). It is load-bearing, not a principle we gestured at. What we drop
  is the file-promotion ceremony, because the design has no file to promote.
- **Reconnaissance, hunting prompts, and the domain attack-class companions.** Those find
  vulnerabilities. The scanners find ours.
- **Two separate LLM verification passes (Phases 3 and 5).** One hostile under-informed
  auditor plus five mechanical obligations beats two LLM passes over prose.
- **The six-phase structure itself.** Our shape is ingest, triage, gate, fix and verify, with
  a bounded retry, and the module cut is by knowledge, not by those stages.

---

## 10. Red-flag self-screen

- **Shallow module?** The operator runs one command with a threshold flag. Behind it:
  two scanner formats, two folds, a refutation rubric, a pure gate, a conflict partitioner, a
  six-obligation verifier, worktree isolation, and an integration bisect. Capability is
  concentrated behind a small interface, not scattered across stages the caller sequences.
- **Information leakage?** Scanner wire formats exist in exactly one module. `invariant_class`
  is ours. The dedup decision is invisible downstream because folding happens at ingest and
  produces one record rather than a pointer.
- **Temporal decomposition?** The reference files are cut by knowledge (scanner formats /
  security semantics / repo-build-and-patch), not by execution order. `FIX-AND-VERIFY.md` is
  deliberately one file because fixing and verifying share the contract, the witness, and the
  branch protocol.
- **Pass-through methods?** `gate()` is thirty lines of policy, not forwarding.
  `evaluateVerification` is the only definition of "verified" and computes rather than relays.
- **Two writers?** The parent is the sole writer of every shared file. Agents return values.
  One file per finding. Leases make in-flight work visible without a lock.

---

## 11. Implementation order

1. `normalize.cjs` + `cluster.cjs` + `finding.schema.json` + `validate.cjs`, with real
   Semgrep and CodeQL output from one repo. Everything downstream depends on the record being
   right, and fold correctness is the cheapest thing to get wrong.
2. `gate.cjs` and `priority()`, pure, trivially testable.
3. `TRIAGE.md` and the triager contract; run triage-only end to end and read the verdicts by
   hand. Tune the refutation rubric before automating anything that writes.
4. `patch-guard.cjs` + `witness-run.cjs`, the deterministic half of verification, testable
   against hand-written good and cheating diffs.
5. Fixer, auditor, worktrees, `partition.cjs`, integration, with the `executable` and
   `structural` witness tiers only.
6. `app-harness.cjs` and the `dynamic` tier last. It is the highest-value obligation and the
   most environment-specific, so it should land against a pipeline that already works. Build
   `discoverAppHarness` for the one stack you actually ship before generalizing it.
