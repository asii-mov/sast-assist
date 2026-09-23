# Fix and verify

Fixing and verifying live in one file because they share one contract, one witness and one branch
protocol. Splitting them would repeat the same invariants across two documents.

## Branch protocol

One git worktree and one branch per finding, `sast-fix/<run-id>/<id>/<attempt>`, all off the same base
commit. The operator's working tree is never touched. Rollback is declining to cherry-pick.

Worktrees live under `$XDG_CACHE_HOME/sast-remediate/worktrees/<hash>/`, `~/.cache` when the
variable is unset, where the hash is taken from the output directory. Never inside the output
directory: its `findings/` and `scans/` name the rule the fixer is never shown.

Before an attempt creates its branch, `clearAttempt` removes any branch or worktree of the same
name. Only a run that died before saving that attempt leaves one behind, and no record holds its
work, so the attempt starts again from base. A fixer call that returns no usable answer records
no attempt at all. Its branch is removed, the finding stays open, and the next run tries again.

At most two attempts. There is no attempt three, and the cap is in the type. Attempt two receives
the typed failures from attempt one, never a bare "try again."

Findings are fixed one at a time in `order()` from `bin/gate.ts`. Every branch starts at base, so
two fixes never see each other's edits.

## The fixer

**Receives.** The frozen contract. The full flow, every step, with materialized source. The
enclosing excerpt. The repository's build, test and lint commands. On attempt two, the typed
verification failures.

**Never receives.** A rule id. A scanner name. A scanner message. Any observation. The triage
agent's impact or likelihood prose. A shell. Its tools are Read, Grep, Glob, Edit and Write. The
harness builds, tests and rescans after the fixer returns, and a shell narrowed to the test
command is no boundary when the fixer can edit the script that command runs. It does see
repository source, which may name a scanner (a workflow, a docs folder); only this finding's own
rule id, fingerprint and message are refused there.

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

The fixer does not commit. It lists every file it changed or created, the witness file included,
in `declared_files`. The harness resets the worktree index to base, stages only those files, runs
the deterministic guard on that diff, and makes the commit itself when the guard passes. A file
the fixer left undeclared never reaches the branch, and neither does a file a hook or tool wrote
during the call. A fixer that commits anyway is harmless, because the reset undoes its commit and
keeps its edits. A commit the harness cannot make ends the finding `fix_failed`.

## Agent isolation

Every agent call runs `claude -p` with `--setting-sources user --settings '{"disableAllHooks":true}'`.
The triage and audit calls run inside the target and the fixer inside a worktree of it, so without
these flags the target's `CLAUDE.md`, its `.claude/settings.json` hooks and permissions, and the
operator's plugin hooks all apply. A probe on claude 2.1.280 measured the difference. With the
flags, a canary word in a project `CLAUDE.md` did not reach the answer and no project hook fired.
Without them, the canary came back and three hooks fired. `--bare` would also isolate, but it
never reads the keychain login.

Every call also passes `--restricted --strict-mcp-config --permission-mode dontAsk` and `--tools`
with the role's list. `--allowed-tools` alone only pre-approves, and under the operator's `auto`
mode it did not keep Bash out: the probe's control call ran the flags above without `--restricted`
and `--tools`, and its `init.tools` came back with `"Bash"` present alongside 68 MCP tools. With
the full flag set, the probe's confined call saw `init.mcp_servers: 0`, no shell in `init.tools`
(`["Edit","Glob","Grep","Read","Write"]`), and a file outside the cwd went unread. `--restricted`
ignores user settings files, so the operator's default model does not apply to agents; pass
`--model` to set one. Measured on claude 2.1.280 in `.work/probe/sandbox.txt`.

Role tools: triage and the auditor get Read, Grep and Glob; the fixer adds Edit and Write.

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

`dynamic` drives the running application over its real network interface. It runs when the
operator passes `--witness=dynamic` and `discoverAppHarness` finds a harness in the target;
otherwise triage is offered `argued` only. See `DYNAMIC-WITNESS.md` for the mechanics and
`design/FUTURE-IMPROVEMENTS.md` for what to settle before turning it on by default. `structural`
is a narrow rule the triage agent authors that restates its own invariant. `argued` means no
mechanical witness exists.

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

`argued` can never reach `verified`. At every level it lands `fixed_unwitnessed`; at `full` that
means obligations 3 and 4 are recorded unavailable with the obstacle, while the regression suite,
the rescan and the auditor still have to pass. A fallback is visible in the report rather than
absorbed into the aggregate.

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
7. **Rescan.** Rerun the scanners whose output made the baseline, and no others, with the run's
   recorded scanner configuration. A result is in `new_findings` only when base had no hit of
   the same rule in the same file. Record
   `original_absent` for the report. A rescan that produces no output is `unavailable`.
8. **Audit.** A fresh agent that neither triaged nor fixed this finding.

For `dynamic`, steps 3 to 5 are the four-step run described in `DYNAMIC-WITNESS.md`, answered by
`witnessObligations` in `bin/witness-run.cjs` in one call: control on base, attack on base, attack
on head, control on head.

## What "verified" means

All seven obligations pass. `evaluateVerification` in `bin/stage.ts` is the sole definition
and it is a pure function, not a prompt.

`rescan.original_absent` is recorded and **read by no transition**. SAST rules match shapes and
genuinely fixed code often keeps the shape, so a correct fix can still trip the rule. Gate on it
and a correct fix gets rejected, the agent retries, and the cheapest edit that passes on attempt
two is the pattern-defeat this whole design exists to prevent. A gate that creates pressure
toward the behavior it forbids is worse than no gate.

Only `rescan_new`, findings the patch introduced, is a failure. "Introduced" means a rule firing
in a file where base never saw it fire. Finding ids hash the sink line, so an id comparison
counted a correct containment check that rewrote the flagged line as a new finding, and the
retry it forced shipped a weaker fix that dodged the rule's shape. The known blind spot: a patch
that adds a second hit of a rule already present in the same file passes the rescan unseen.

## Why `executable` is not built

Three reasons, not one. First, the witness file would be written by the fixer during the fix, which
breaks the first non-gameable property above (authored before the fix exists): a fixer can write a
test that imports something only the patch adds, so it fails on base and passes on the patch,
looking exactly like a valid differential. Second, telling "assertion failed" apart from "crashed
because it needs new code" (the vacuity check above) requires parsing each framework's own result
format, TAP, pytest, go test; exit codes alone cannot do it. Third, done with exit codes anyway,
the tier would label a gamed fix `fixed` instead of `fixed_unwitnessed`, which is worse than not
having the tier at all.

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
