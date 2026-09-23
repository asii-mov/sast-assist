# Fix and verify

Fixing and verifying live in one file because they share one contract, one witness and one branch
protocol. Splitting them would repeat the same invariants across two documents.

## Branch protocol

One git worktree and one branch per finding, `sast-fix/<run-id>/<id>/<attempt>`, all off the same base
commit. The operator's working tree is never touched. Rollback is declining to cherry-pick.

At most two attempts. There is no attempt three, and the cap is in the type. Attempt two receives
the typed failures from attempt one, never a bare "try again."

Findings are partitioned into conflict-free waves before anyone is spawned. Two findings conflict
when they share a file and their line ranges fall within twenty lines. Connected findings land in
different waves. It is never an agent's job to notice it is about to collide.

`bin/partition.cjs` computes this. `partition(findings)` returns waves by deterministic greedy
colouring over `order()`, so the assignment is stable run to run.

Wave N branches off base. Wave N+1 branches off the integration tip after wave N's verified fixes
are picked.

## The fixer

**Receives.** The frozen contract. The full flow, every step, with materialized source. The
enclosing excerpt. The repository's build, test and lint commands. On attempt two, the typed
verification failures.

**Never receives.** A rule id. A scanner name. A scanner message. Any observation. The triage
agent's impact or likelihood prose. Any scanner tool access.

You cannot game a matcher you were never shown. An agent told that a particular rule fires at a
particular line has an obvious cheapest path, which is to make that line stop matching. An agent
told that every value reaching a sink must be an element of a fixed list has no such shortcut
available. The only way to satisfy it is to enforce it.

**Returns.** Exactly one JSON object.

```json
{"outcome": "patched", "declared_files": ["..."], "enforcement_note": "how the invariant is now enforced"}
{"outcome": "cannot_fix", "reason": "..."}
```

`cannot_fix` is a real and expected outcome. A second independent mind cold-reading the contract
can decline before any patch exists. That checkpoint is the reason triage and fix are separate
agents, and a merged agent cannot produce it. An agent that just wrote "verdict: exploitable" will
not conclude two steps later that it is unsure.

The fixer commits to its own branch, including the witness file.

## The witness

Four tiers. Author the strongest one the repository supports, from those enabled.

```
executable  >  structural  >  argued          default
dynamic                                        opt-in, --witness=dynamic
```

**Only `dynamic` and `argued` are implemented.** `runWitnessInner` in `bin/witness-run.cjs`
throws on any other tier. `executable` and `structural` are the designed default path and are
not written yet, so today the only mechanical proof available is the opt-in `dynamic` tier.
Until they land, a run either opts into `dynamic` or degrades to `argued`.

`executable` will use the project's own test harness against the public entrypoint named in the
contract, and becomes the tier selected automatically once it exists.

`dynamic` drives the running application over its real network interface. It is built and proven
but not enabled by default, because it needs an app that boots cold with no network and no real
credentials, and fixture data the repository may not have yet. See `DYNAMIC-WITNESS.md` for the
mechanics and `design/FUTURE-IMPROVEMENTS.md` for what to settle before turning it on. `structural` is a narrow rule the triage agent authors that
restates its own invariant. `argued` means no mechanical witness exists.

Three properties make a witness non-gameable.

**It is authored before the fix exists**, against API already present on the base commit. That is
what makes the pre-patch run expressible at all.

**The pre-patch signal is mandatory.** You cannot write a witness for a suppression. A test
cannot demonstrate that a suppression comment fixed something. A rule required to fire before the
patch cannot be a rule that never matches. An attack that does not work before the patch proves
nothing about after it.

**Vacuity is detected, not excused.** A witness that passes on base does not exercise the bug. A
witness that errors on base depends on the fix's own new code. Both are `witness_vacuous`.

The `structural` tier generalizes the defense to languages and sinks with no harness. The agent
writes a rule narrower and more structural than the original, and the runner requires it to fire
at a specific anchor on the pre-patch tree. To game it you would have to write a rule that fires
on the buggy code and not on the patched code without the patch changing anything relevant, which
is the definition of having changed something relevant. The auditor also reads the rule against
the frozen invariant and rejects one narrower than the invariant.

`argued` can never reach `verified`. It reaches `fixed_unwitnessed` and always needs human review,
so a fallback is visible in the report rather than absorbed into the aggregate.

## The functional control

Required on every tier that can express one. It must pass on **both** trees.

Without it, every other obligation is satisfiable by a patch that disables the functionality.
Return an error to everything and the attack stops working, the scanner goes quiet, the diff
carries no suppression, and an auditor reading that diff sees a real change. The regression suite
is the intended backstop, but a newly touched route is exactly what a suite tends not to cover.

For `executable`, the control is an existing test that covers the legitimate path. For `dynamic`,
it is a legitimate request with an expected observable.

## The auditor

**Receives.** The frozen contract. The diff. The witness source. The fixer's `enforcement_note`,
framed as a claim to disprove.

**Never receives.** The fixer's reasoning transcript. The mechanical results. The witness outcome.
The rescan. The triage agent's identity.

An auditor told that everything mechanical passed grades a conclusion. An auditor given only the
contract and the diff has to walk the `violating_input` through the patched source and say where
it dies.

**Returns.** One JSON object with a verdict of `enforces_invariant`, `silences_rule`,
`moves_trust` or `incomplete_enforcement`, a step-by-step trace through the patched source, the
location where the counterexample dies, and any uncovered sibling sites.

`stopped_at: null` with `enforces_invariant` is a schema error. The auditor must point at a line.

`silences_rule` is a first-class, expected outcome, not an anomaly. It means the scanner is quiet
and the counterexample still reaches its effect.

## Verification order

Cheapest first. Short-circuit on the first failure, except the audit, which always runs so
attempt two gets a real explanation.

1. **Empty diff.** Fail as `no_diff`. Zero agent spend.
2. **Guard.** `bin/patch-guard.cjs`. Milliseconds, no LLM, and no rationale can argue past it.
3. **Witness, red half.** Check out base, apply only the witness file from the patch branch, run
   it. It must signal.
4. **Witness, green half.** Run on the patch branch. It must fall silent.
5. **Control.** Must pass on both trees.
6. **Regression.** The project's suite on the patch branch. A suite already red on base yields
   `unavailable` with reason `suite_red_on_base` rather than blaming the patch.
7. **Rescan.** Compute `new_findings` against base. Record `original_absent` for the report.
8. **Audit.** A fresh agent that neither triaged nor fixed this finding.

## What "verified" means

All seven obligations pass. `evaluateVerification` in `bin/stage.cjs` is the sole definition
and it is a pure function, not a prompt.

`rescan.original_absent` is recorded and **read by no transition**. SAST rules match shapes and
genuinely fixed code often keeps the shape, so a correct fix can still trip the rule. Gate on it
and a correct fix gets rejected, the agent retries, and the cheapest edit that passes on attempt
two is the pattern-defeat this whole design exists to prevent. A gate that creates pressure
toward the behavior it forbids is worse than no gate.

Only `rescan_new`, findings the patch introduced, is a failure.

## Integration

**Not implemented.** `bin/run.cjs` stops after verification and leaves each verified fix on its
own branch; nothing cherry-picks, re-runs or bisects yet. The rest of this section is the
specification.

Branch `sast-fix/integration-<run-id>` off base. Cherry-pick each verified finding in id order. A
conflict marks that finding `fix_failed` with obligation `integration` and skips the pick, so the
branch always builds from a consistent subset.

Then once, on the integration branch: the full suite, every landed witness re-run, and a full
rescan. Any new finding against base fails integration and bisects the picks to name the culprit.

Never merge. Never push. Write the branch name and a PR body.

## Failure ships something

`fix_failed` carries a handoff, not just a failure. The branch is retained, the red witness is on
it, and the contract says what must hold. A human inherits a failing test that encodes the bug,
which is most of the work. That is why the loop is allowed to give up after two attempts.
