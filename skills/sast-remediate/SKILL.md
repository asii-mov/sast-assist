---
name: sast-remediate
description: Triage, fix and verify Semgrep and CodeQL findings. Use when a repository has SAST results to work through, when asked to cut false positives from a scan, to auto-fix findings above a severity threshold, or to verify that a security patch actually closed the hole. Also answers focused questions about a single finding.
---

# sast-remediate

Scanners find. This skill decides what is real, fixes what crosses a threshold, and proves the fix.

**Triage does not return a verdict. It returns a security contract, and the verdict falls out of it.**
A contract is `{invariant, violating_input, enforcement_point, witness, writable_scope,
forbidden_resolutions}`. It answers all three downstream questions at once. What is the bug
(`invariant` + `violating_input`). Where does the fix go (`enforcement_point`). How do we know it
worked (`witness`).

A pipeline whose triage emits a boolean makes the fixer re-derive the security semantics from
the rule message, then makes the verifier re-derive them again from the diff. Three derivations
of one fact is where the failure mode is born. Nobody downstream holds an independent statement
of what must become true, so the only remaining test is whether the scanner went quiet.

## Operating modes

Loading this skill does not authorize a run.

**Guidance mode** is the default. Answer questions about a finding, a rule, or a triage call from
`references/TRIAGE.md`. Write nothing. Create no directory. Spawn no fan-out.

**Full run** happens when the user asks to triage a scan, to fix findings, or to remediate a
repository. Then follow the stages below and write the artifacts.

If the request could mean either, ask one question before creating anything.

## Setup

Resolve before anything else.

- **Skill directory.** The absolute directory holding this file.
- **Target.** The repository root under review.
- **Output directory.** Outside the target. Default: the latest `~/sast-remediate/<repo>/run-<N>`
  when that run is unfinished and was started on the same commit, otherwise a new `run-<N+1>`.
  `--out` always wins. Inside the target only when the user picks it and version control ignores it.
- **Base commit.** The reviewed commit, and whether the worktree is dirty.
- **Policy.** `fix_at` defaults to `medium`.
- **Scanner configuration.** `--semgrep-config` (default `p/default`) and `--codeql-suite` (default
  `security-extended`). The baseline scan and every rescan use it, and `run-metadata.json` records
  it, so a resumed run rescans with the same rules. With `--scans`, pass the rules those scans were
  made with, or every rescan hit counts as new.

## Write isolation

The parent is the only writer of `run-metadata.json`, `findings/<id>.json`, `REMEDIATION.md` and
`HANDOFF.md`. Agents return JSON and never touch shared state. Each agent gets
`agents/<id>/scratch/`. One file per finding, so parallel agents never contend.

## What runs today

The deterministic core is built and tested. `bin/normalize.ts`, `bin/validate.ts`,
`bin/gate.ts`, `bin/stage.ts`, `bin/patch-guard.ts`, and the `dynamic` tier of
`bin/witness-run.ts` all work and are covered by `test/run-all.sh`.

`bin/run.ts` drives them. One command runs every stage: `run.ts --target=DIR`. It spawns the
triage and fix agents through `bin/agent.ts`, orders fix work with `order()` from `bin/gate.ts`,
and writes the artifacts with `bin/report.ts`. Re-running it is the resume path.
Agents run with the target's Claude settings, `CLAUDE.md` and hooks shut out. Each gets only the
tools its role needs, and none gets a shell. The harness, not the fixer, commits each fix, and
only the files the fixer declared. See `references/FIX-AND-VERIFY.md`.

The `dynamic` witness tier is wired into `run.ts` behind `--witness=dynamic`: it boots the target
application twice and sends the attack and a control exchange to both. At `full`, an `argued`
witness records obligations 3 and 4 unavailable with the obstacle, still runs the regression
suite, the rescan and the hostile auditor, and lands as `fixed_unwitnessed` after one attempt.

Still unwritten: the integration branch (cherry-pick, combined re-run, bisection), the
`executable` and `structural` witness tiers, tier selection, the `row_appears` observable, and
split-count bookkeeping. Verified fixes are left on their own branches. `--verify` selects how much proof a fix
must carry; `cheap` is the default and skips the witness pair and the auditor, so a fix verified
at `cheap` is not a fix verified at `full`, and the report says which ran.
`design/FUTURE-IMPROVEMENTS.md` is the authoritative gap list.

## Stages

Stage is derived from the record's shape and the run's verify level by `stageOf` in
`bin/stage.ts`, never stored. `run-metadata.json` records the level, so a resumed run judges
with the level it started at. A finding's saved `disposition` is its final outcome, and the
report reads only that.
Re-running the command is the resume path. There is no `--resume` flag and no `status` field to fall out of sync.

**1. Scan and normalize.** Run the scanners, then `bin/normalize.ts`. Read
`references/INGEST.md` first, including its note on silent zeros. Validate with
`bin/validate.ts` against `schema/finding.schema.json`. Fix every error before continuing.

**2. Pre-resolve without agents.** Path policy (test, vendor, generated, minified, migrations)
and prior-run carry. Each resolved finding gets a real `Triage` with `established_by`, not a
skipped state. A path-policy rejection is a policy call, not a security claim, and the report
says so under its own heading.

**3. Triage.** One agent per finding, ordered by `priority()` from `bin/gate.ts`. Build the
prompt per `references/TRIAGE.md`, switching on `flow.kind`. Budget bounds the run. Findings past
the budget stay untriaged on disk and the next run picks them up. A triage call that returns no
usable answer is not a verdict: the finding stays at triage, the run ends `incomplete` and names
it, and the next run asks again.

**4. Gate.** `gate(triage, policy)` from `bin/gate.ts`. Pure, total, no LLM. It takes a Triage
and a Policy and nothing else, so a scanner's severity cannot reach the fix decision.

**5. Fix and verify.** `references/FIX-AND-VERIFY.md` owns this. One finding at a time in
`order()`, one worktree and branch per finding off base, at most two attempts, seven
obligations.

**6. Report.** `references/REPORT.md`. `REMEDIATION.md` and `HANDOFF.md`, derived from the
records.

End in exactly one of two states. Every finding has a terminal disposition, or `run_status` is
`incomplete` with its exact reason stated in the report.

## The seven obligations

A fix is verified only when every obligation its verify level requires passes: all seven at
`full`, four at `cheap`, none at `none`. The report names the level beside every verified fix.
`evaluateVerification` in `bin/stage.ts` is the sole definition. It indexes the seven obligation keys and nothing else, so `original_absent`
is structurally unreachable from the verdict rather than merely forbidden in prose.

1. **Frozen target.** The contract is written before the patch exists and never changes.
2. **Deterministic guard.** `bin/patch-guard.ts` over the diff.
3. **Differential witness.** Signals before the patch, silent after. Strongest available tier.
   `executable` is the designed default and is not implemented; today that means the opt-in
   `dynamic` tier or a degraded `argued`. At `argued`, 3 and 4 are recorded unavailable and
   excused, and the fix is `fixed_unwitnessed`. See `references/FIX-AND-VERIFY.md`.
4. **Functional control.** A legitimate request or covering test that passes on both trees.
5. **Regression suite.** The project's own tests.
6. **No new findings.** Rescan delta against base.
7. **Under-informed hostile auditor.** Given the contract and the diff, nothing else.

Obligations 3 and 4 are a pair. "Did the attack stop working" is satisfiable by breaking the
endpoint. "Does the legitimate path still work" is satisfiable by changing nothing. Together
they mean the code does what it did, minus the vulnerability.

## Rules that are not negotiable

**The fixer is never shown the rule.** No rule id, no scanner name, no scanner message, no
observation, and no scanner tool access. You cannot game a matcher you were never shown.
`assertNoLeak` in `bin/leak-guard.ts` enforces it on every fixer and auditor prompt. The whole
prompt must not contain this finding's own rule id, fingerprint or message. The contract prose the
triage agent wrote must also not name a scanner or a rule, or carry the syntactic form of a CodeQL
rule id. Repository source is exempt from those last two checks, because a workflow that runs
`github/codeql-action` or a line like `uses: actions/setup-node@v4` names nothing about the rule
that fired. The schema closes the way around it too. A contract `invariant` fails validation when
it names a scanner, borrows scanner-artifact vocabulary, or carries the form of a Semgrep or
CodeQL rule id. Form rather than a name list, because no list closes on ids this skill has never
seen.

**The scanner going quiet is recorded and never read.** `rescan.original_absent` appears in the
report and in no state transition. SAST rules match shapes and genuinely fixed code often keeps
the shape, so a correct fix can still trip the rule. Gate on it and a correct fix gets rejected,
the agent retries, and the cheapest passing edit on attempt two is the pattern-defeat the whole
design exists to prevent. Only `rescan_new` is a failure, meaning a rule firing in a file where
base never saw it fire.

**Severity requires demonstrated impact.** Only `exploitable` carries a severity. The other
verdicts have no severity field at all. Overall severity never exceeds demonstrated impact.

**A defense-in-depth gap is not a vulnerability.** If a control on the path already prevents the
attack, the absence of a second one is a hardening note. It is a named refutation reason so it
stays countable.

**Malformed agent output is discarded, never repaired.** Re-run once with a fresh agent, then leave the finding open for the next run.

**A missing test suite does not stop patching.** With no test command, `regression_suite` is
recorded `unavailable` and the report says it was excused, not passed.

## Reference files

Load only what the stage needs.

`references/INGEST.md` runs the scanners and normalizes their output. Scanner wire formats stop
here. `references/TRIAGE.md` holds the refutation rubric, the severity anchors and the triage
prompt. `references/FIX-AND-VERIFY.md` holds the fixer and auditor contracts, the witness
discipline and the branch protocol. `references/REPORT.md` shapes the artifacts.

`references/DYNAMIC-WITNESS.md` covers driving a running application. That tier is built and
proven but is **not enabled by default**. It is opt-in, tracked in
`design/FUTURE-IMPROVEMENTS.md`. Load it only when the operator passes `--witness=dynamic`.

## Tools

All TypeScript that Node 22.18 or newer runs directly, with no build step and no dependencies.
Nothing is installed into the target. Types for the finding records are generated from
`schema/finding.schema.json` by `tools/gen-schema-types.ts`. The type check is a developer tool:
run `npm install` once at the repository root, and `test/run-all.sh` runs it with the tests.

`bin/scan.ts` runs the scanners, CodeQL once per detected language, and decides which rescan
results a patch introduced. `bin/leak-guard.ts` holds `assertNoLeak`, the check that keeps
scanner material out of fixer and auditor prompts.
`bin/normalize.ts` turns scanner output into findings. `bin/validate.ts` gates every write
against a schema. `bin/gate.ts` holds the threshold and the ordering. `bin/patch-guard.ts`
screens a diff. `bin/stage.ts` holds `stageOf` and `evaluateVerification`, the only definitions of where a
record is and whether a fix is verified. `bin/resume.ts` picks the run directory, merges the
records already on disk, and clears the leftovers of an attempt that a crashed run never
recorded. `bin/witness-run.ts` runs the differential witness
and the control.
`bin/app-harness.ts` discovers, boots and tears down the target application, and is used only
by the opt-in dynamic tier.

`test/selftest.ts` runs the unit suite against real scanner fixtures. `test/e2e-witness.ts`
boots the fixture app and proves the witness and the control end to end.
`tools/validate-skill.ts` checks this tree.

## Anti-patterns

1. Gating fixes on a scanner's severity, or on a ceiling derived from it.
2. Treating a quiet rescan as evidence the vulnerability is gone.
3. Flattening a finding to file, line and message, which discards the taint path.
4. Forcing a binary call on a finding whose decisive fact is not in the source. That is what
   `undecidable` is for.
5. Showing the fixer the rule it needs to satisfy.
6. Verifying a fix with the agent that wrote it.
7. Reporting a patch as fixed when only the scanner, and not the behavior, changed.
