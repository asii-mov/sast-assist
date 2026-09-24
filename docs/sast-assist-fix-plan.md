# sast-assist fix plan

This plan fixes the five Act On findings from the 2026-09-22 interrogate review of `skills/sast-assist/`.
It is for the operator who runs `node bin/run.cjs --target=DIR` and reads `REMEDIATION.md` afterwards.
After it lands, a default run patches repos with no tests, makes one fixer call per good fix, keeps a correct fix whose line still matches the rule, reports only branches that exist, and ignores the target's own Claude settings.
The rule the program enforces is one source of truth for a finding's outcome, the saved `disposition`, which `stageOf`, the fix loop and the report all read.
Units in order are U0, U1, U2, U3, U4. Each is one change with its own evidence.

## How to read this

One box is one unit of work. Every box names the evidence that checks it. A nested box is a sub-step of the box above it. Check a box only when its evidence exists, a file, a log line, a test run, or a snapshot path. The body is a how-to. The appendices explain and record.

The program runs `pstack/skills/poteto-mode/playbooks/autopilot-stack.md` in spirit, adapted. This directory is not a git repository and has no remote, so there are no PRs, no branches and no forge. Each unit is a serial edit to the working tree by one `poteto-agent` owner on model `opus` (Opus 5.5). The root reviews each diff against a snapshot before the next unit starts. The operator lands nothing. The operator reads the final report and the live-run evidence.

Tests alone are not sufficient verification. A PR is verified only when its unit, live, and perf boxes are all checked.

## Program checklist

### Arm the program

- [ ] State the protocol and this plan to the operator. The operator's request on 2026-09-22 ("give requests to fix these to opus 5.5") is the go.
- [ ] Snapshot `skills/sast-assist/` to `.work/snapshots/sast-assist-pre-fix/` before U0. Every diff below is taken against this snapshot or the previous unit's snapshot.
- [ ] Read these at program start.
  - [ ] `pstack/skills/poteto-mode/SKILL.md`
  - [ ] `pstack/skills/principle-test-behavior-not-implementation/SKILL.md`
  - [ ] `pstack/skills/principle-model-the-domain/SKILL.md`
  - [ ] `AGENTS.md` at the repo root
- [ ] Skip the 30-minute audit tick. The chain is serial and the root is re-invoked when each owner finishes.

### Spawn owners

- [ ] Spawn one owner per unit, `subagent_type` `pstack:poteto-agent`, `model` `opus`. Never `fable`.
- [ ] Follow this dependency graph. Every unit runs strictly after the one before it, because U1 to U4 all edit `bin/run.cjs`.
  - [ ] U0 first.
  - [ ] U1 after U0.
  - [ ] U2 after U1.
  - [ ] U3 after U2.
  - [ ] U4 after U3.
- [ ] Hold the file boundaries. Every owner touches only `skills/sast-assist/**`, `design/FUTURE-IMPROVEMENTS.md` and `.work/`. No owner edits `reference/`, `fixtures/vuln-app/src/**` or `AGENTS.md`.
- [ ] Hold the review gate. No unit changes an operator-facing interaction beyond the report text, so none is review-gated.

### Unit mechanics, for every unit

- [ ] Take a fresh snapshot at `.work/snapshots/after-<unit>/` when the unit is green.
- [ ] Run `sh test/run-all.sh` from `skills/sast-assist/` and keep it green.
- [ ] Apply `/deslop` and `/no-comments` rules to the diff. Keep a comment only for a non-obvious why.
- [ ] Return a report with the file list, the new test case names, the `run-all.sh` tail, and anything left undone.

### Verdict, for every unit

- [ ] The root diffs the unit against the previous snapshot with `diff -ru` and reads every hunk.
- [ ] The root reruns `sh test/run-all.sh` itself. A green claim without a rerun does not count.
- [ ] Findings go back to a fresh owner with consolidated scope. A new diff gets a fresh verdict.

### Boot recipe, for the live check

The live check runs once at the end, after U4, on this machine.

- [ ] Copy `.work/targets/vuln-app-git` to `.work/targets/vuln-app-live` with `cp -a`.
- [ ] Run `node bin/run.cjs --target=<copy> --scans=test/fixtures --out=.work/targets/run-postfix` from `skills/sast-assist/`.
- [ ] Read `run-postfix/REMEDIATION.md`, `run-postfix/findings/*.json` and `git -C <copy> branch -a`.

## Add a real-git pipeline test (U0)

**Depends on.** None.

**Files.**

- [ ] Create `skills/sast-assist/test/pipeline.real.test.cjs`.
- [ ] Create `skills/sast-assist/test/fake-claude.cjs`.
- [ ] Edit `skills/sast-assist/test/run-all.sh`.

**Build.**

- [ ] `fake-claude.cjs` is an executable stand-in for the `claude` CLI. It reads the prompt, answers triage with a schema-valid contract, and on a fix prompt edits the named file in its cwd and runs `git commit`. It prints the real envelope shape that `bin/agent.cjs` `resultText` parses.
- [ ] `pipeline.real.test.cjs` copies `fixtures/vuln-app` to a temp dir, runs `git init` and one commit, puts the fake on `PATH` as `claude`, and calls `run()` from `bin/run.cjs` with real git and the real `renderRemediation`.
- [ ] It asserts on literal observed values only, the fixer call count, `git branch --list`, each record's `disposition.state`, and lines in the rendered `REMEDIATION.md`.
- [ ] Cases that expose U1 to U4 bugs are written now and marked `expectFail` with the unit id, so the suite stays green and each later unit flips its case.

**You see.**

- [ ] `run-all.sh` prints a `== pipeline (real git) ==` section with at least one passing baseline case and one `expected-fail (U2)` line per pending case.

**Verify, unit.** Tests alone are not sufficient verification. A PR is verified only when its unit, live, and perf boxes are all checked.

- [ ] Baseline case "a real run on a real git copy reaches report" passes. Run `sh test/run-all.sh`.
- [ ] Mutation check. Make `renderRemediation` return an empty string and confirm the baseline case fails, then revert.

**Verify, live.** Tests alone are not sufficient verification. A PR is verified only when its unit, live, and perf boxes are all checked.

- [ ] The live check waits for U4. This unit adds no product behavior. It records that fact.

**Verify, perf.** Tests alone are not sufficient verification. A PR is verified only when its unit, live, and perf boxes are all checked.

- [ ] Metric. Wall time of `sh test/run-all.sh`.
- [ ] Probe. Three runs before and three after.
- [ ] Baseline. About 4.3 s measured on 2026-09-22.
- [ ] Rule. Fail above 15 s.

**Review gate.** None. U0 is not review-gated.

**Merge.**

- [ ] Root verdict clean at snapshot `after-U0`.

## Remove the no-tests patch gate and dead weight (U1)

**Depends on.** U0.

**Files.**

- [ ] Edit `skills/sast-assist/bin/run.cjs`.
- [ ] Edit `skills/sast-assist/SKILL.md`.
- [ ] Edit `skills/sast-assist/test/run.test.cjs`.
- [ ] Edit `skills/sast-assist/bin/report.cjs`.
- [ ] Edit `design/FUTURE-IMPROVEMENTS.md`.
- [ ] Delete `skills/sast-assist/bin/partition.cjs`.
- [ ] Delete `skills/sast-assist/test/partition.test.cjs`.
- [ ] Delete `skills/sast-assist/err.log`.

**Build.**

- [ ] Delete the `no_test_command_discoverable` branch in `run()` near `bin/run.cjs:928`. A missing test command leaves `regression_suite` as `unavailable`, which `MAY_BE_UNAVAILABLE` already excuses.
- [ ] Delete `--allow-unverified-fixes` from `parseArgs` and `USAGE`, and the SKILL.md rule "No patching without verification".
- [ ] Invert the test "no test command and no override degrades to triage-only" into "no test command still patches and the report says no suite ran". Delete the `--allow-unverified-fixes` test.
- [ ] Replace `partition()` in `fixAll` with `order(fixable)` from `bin/gate.cjs`. Drop `meta.counts.waves` and its test line.
- [ ] Delete the `sast-fix/integration-<run>` paragraph in `bin/report.cjs` near line 278. List each verified finding's own branch instead.
- [ ] Remove FUTURE-IMPROVEMENTS items that claim the driver and partition are unbuilt, and the `selectWitnessTier` and `--witness=dynamic` references that match no code.

**You see.**

- [ ] A U0 case "a repo with no test script gets patched" flips from expected-fail to pass.

**Verify, unit.** Tests alone are not sufficient verification. A PR is verified only when its unit, live, and perf boxes are all checked.

- [ ] `test/run.test.cjs` gains the inverted case. `test/pipeline.real.test.cjs` case flips. Run `sh test/run-all.sh`.
- [ ] `grep -rn "allow-unverified\|partition\|integration-" skills/sast-assist` prints only intended hits.

**Verify, live.** Tests alone are not sufficient verification. A PR is verified only when its unit, live, and perf boxes are all checked.

- [ ] Covered by the final live check. Pass when a run on a copy with the `test` script removed from `package.json` still produces fix branches.

**Verify, perf.** Tests alone are not sufficient verification. A PR is verified only when its unit, live, and perf boxes are all checked.

- [ ] Metric. Wall time of `sh test/run-all.sh`.
- [ ] Probe. Three runs before and three after.
- [ ] Baseline. About 4.3 s measured on 2026-09-22.
- [ ] Rule. Fail above 15 s.

**Review gate.** None. U1 is not review-gated.

**Merge.**

- [ ] Root verdict clean at snapshot `after-U1`.

## Make the saved disposition the only outcome (U2)

**Depends on.** U1.

**Files.**

- [ ] Edit `skills/sast-assist/bin/stage.cjs`.
- [ ] Edit `skills/sast-assist/bin/run.cjs`.
- [ ] Edit `skills/sast-assist/bin/report.cjs`.
- [ ] Edit `skills/sast-assist/test/selftest.cjs`.
- [ ] Edit `skills/sast-assist/test/run.test.cjs`.

**Build.**

- [ ] `stageOf(finding, level)` judges the last patch with `evaluateVerification(v, VERIFY_LEVELS[level])`. Every caller passes the run's level. The level is written into `run-metadata.json` so a resumed run judges with the same level.
- [ ] `dispositionFor` sends every outcome other than `patched` and `cannot_fix` to `fix_failed` at every level, including `none`.
- [ ] `refused` ends the fix loop in `fixAll` like `cannot_fix`.
- [ ] `report.cjs` buckets findings by `f.disposition.state` only. Delete `classify`, `classifyPatch` and every read of `patch.fix.*`. `fixed_unwitnessed` renders in its own section, never under "Fixed".
- [ ] Delete the `split_escalated` branch and its HANDOFF section, since no code writes it.

**You see.**

- [ ] U0 cases flip. "A fix that passes every cheap check makes exactly one fixer call." "verify=none with a crashing fixer ends fix_failed." "cannot_fix appears under its own heading, and the run says complete." "An argued fix is not listed under Fixed."

**Verify, unit.** Tests alone are not sufficient verification. A PR is verified only when its unit, live, and perf boxes are all checked.

- [ ] `test/selftest.cjs` gains `stageOf` cases at `none`, `cheap` and `full` with literal expected stages. Run `sh test/run-all.sh`.

**Verify, live.** Tests alone are not sufficient verification. A PR is verified only when its unit, live, and perf boxes are all checked.

- [ ] Covered by the final live check. Pass when every `patches` array in `run-postfix/findings/*.json` for a passing fix has length 1.

**Verify, perf.** Tests alone are not sufficient verification. A PR is verified only when its unit, live, and perf boxes are all checked.

- [ ] Metric. Fixer calls per run, read from `run-metadata.json` `fix_attempts`.
- [ ] Probe. The final live run against the same reused scans as `run-full4`, which were `test/fixtures`.
- [ ] Baseline. `run-full4` recorded 4 fixer calls for 2 fixed findings.
- [ ] Rule. Fail when `fix_attempts` exceeds the number of findings gated to fix, unless a record shows a failed first attempt.

**Review gate.** None. U2 is not review-gated.

**Merge.**

- [ ] Root verdict clean at snapshot `after-U2`.

## Stop counting a rewritten line as a new finding (U3)

**Depends on.** U2.

**Files.**

- [ ] Edit `skills/sast-assist/bin/run.cjs`.
- [ ] Edit `skills/sast-assist/test/run.test.cjs`.

**Build.**

- [ ] In the rescan near `bin/run.cjs:724-738`, a rescan result is new only when no base finding has the same rule id and the same file. The line text and line number stop taking part in this comparison. Finding ids in `normalize.cjs` stay as they are.
- [ ] The rescan runs only the scanners that produced the baseline. When the baseline came from `--scans` and a scanner's file was absent, that scanner is not rerun.
- [ ] A rescan that cannot run records `no_new_findings` as `unavailable`, and `no_new_findings` joins `MAY_BE_UNAVAILABLE`.

**You see.**

- [ ] A U0 case flips. "A fix that edits the flagged line while the rule still matches passes no_new_findings and keeps original_absent false."

**Verify, unit.** Tests alone are not sufficient verification. A PR is verified only when its unit, live, and perf boxes are all checked.

- [ ] `test/run.test.cjs` gains a case whose fake rescan returns the same rule at a new line, asserting `no_new_findings.status === 'pass'`. Run `sh test/run-all.sh`.

**Verify, live.** Tests alone are not sufficient verification. A PR is verified only when its unit, live, and perf boxes are all checked.

- [ ] Covered by the final live check. Pass when the path-traversal finding's accepted patch still contains a symlink or `realpath` containment check, or the record shows attempt 1 was not failed for `rescan_new`.

**Verify, perf.** Tests alone are not sufficient verification. A PR is verified only when its unit, live, and perf boxes are all checked.

- [ ] Metric. Fixer calls per run, read from `run-metadata.json` `fix_attempts`.
- [ ] Probe. The final live run against the same reused scans as `run-full4`, which were `test/fixtures`.
- [ ] Baseline. `run-full4` recorded 4 fixer calls for 2 fixed findings.
- [ ] Rule. Fail when `fix_attempts` exceeds the number of findings gated to fix, unless a record shows a failed first attempt.

**Review gate.** None. U3 is not review-gated.

**Merge.**

- [ ] Root verdict clean at snapshot `after-U3`.

## Isolate the agents from the target's Claude settings (U4)

**Depends on.** U3.

**Files.**

- [ ] Edit `skills/sast-assist/bin/agent.cjs`.
- [ ] Edit `skills/sast-assist/bin/run.cjs`.
- [ ] Edit `skills/sast-assist/test/agent.test.cjs`.
- [ ] Edit `skills/sast-assist/test/run.test.cjs`.

**Build.**

- [ ] Prototype first. In a temp dir holding a `CLAUDE.md` with a canary word and a `.claude/settings.json` with a hook that touches a file, run `claude -p` once with `--setting-sources user --settings '{"disableAllHooks":true}'`. Record whether the canary reaches the answer and whether the hook file appears. `--bare` is ruled out because it skips keychain reads, which this login depends on.
- [ ] `argvFor` in `bin/agent.cjs` adds the flags the prototype proved. If project `CLAUDE.md` still loads, run agents with cwd set to a scratch dir outside the target and pass the target path in the prompt, or document the residual risk in Appendix C.
- [ ] `collectDiff` in `bin/run.cjs` stages only the files the fixer declared plus the witness file, not `git add -A`. The harness makes the commit itself after the guard passes, so a fixer that forgot to commit still yields a real branch.

**You see.**

- [ ] `test/agent.test.cjs` asserts the literal argv contains `--setting-sources user`. A U0 case flips. "A stray `.claude/` file written during the fix is not in the patch diff."

**Verify, unit.** Tests alone are not sufficient verification. A PR is verified only when its unit, live, and perf boxes are all checked.

- [ ] The two cases above. Run `sh test/run-all.sh`.

**Verify, live.** Tests alone are not sufficient verification. A PR is verified only when its unit, live, and perf boxes are all checked.

- [ ] The prototype run above is the live check for isolation. Save its transcript to `.work/probe/isolation.txt`. Pass when the hook file is absent.

**Verify, perf.** Tests alone are not sufficient verification. A PR is verified only when its unit, live, and perf boxes are all checked.

- [ ] Metric. Wall time of `sh test/run-all.sh`.
- [ ] Probe. Three runs before and three after.
- [ ] Baseline. About 4.3 s measured on 2026-09-22.
- [ ] Rule. Fail above 15 s.

**Review gate.** None. U4 is not review-gated.

**Merge.**

- [ ] Root verdict clean at snapshot `after-U4`.

## Close the program

- [ ] Run the live check from the boot recipe once, with the real `claude`.
- [ ] Every box above is checked with its evidence.
- [ ] Reply to the operator with what changed per unit, the live run's `REMEDIATION.md` excerpt, `fix_attempts` against the baseline of 4, and what stays open.

## Appendix A. Prototype evidence

- `claude --help` on 2026-09-22 lists `--setting-sources`, `--settings`, `--bare`, `--disallowed-tools` and `--strict-mcp-config`. The help text says `--bare` skips keychain reads. Whether `--setting-sources user` stops project `CLAUDE.md` from loading is unproven. U4 settles it.
- The double fix call is measured. `run-full4/findings/f_d72e46f6d1ec2eb0.json` holds 2 patches, and its disposition is `fixed_unwitnessed` at `cheap`.
- The weaker shipped fix is measured. `sast-fix/run-full4/f_6ed43412e0d9b09d/1` has a `realpath` symlink check. Attempt `/2`, the accepted one, has none.
- The phantom branch is measured. `git branch -a` in `vuln-app-git` lists no `integration` branch while `run-full4/REMEDIATION.md` names one.

## Appendix B. Alternatives rejected

- Parallel owners per unit. Rejected because U1 to U4 all edit `bin/run.cjs`, another session edited that file at 20:40 on 2026-09-22, and subagent fan-out on this machine keeps hitting HTTP 429.
- Keeping `partition.cjs` for future parallel fixing. Rejected because fixes run one at a time and every branch starts at base, so the waves change nothing.
- Making the rescan delta line-aware through the diff. Rejected for now. Rule and file matching is smaller and stops the known failure. It can miss a genuinely new second hit of the same rule in the same file, which Appendix C records.
- Wiring the dynamic witness into `--verify=full`. Deferred. It is a Consider item, not an Act On item.

## Appendix C. Risks

- U3 rule-and-file matching hides a patch that adds a second hit of an existing rule in the same file. The U3 owner notes this in `references/FIX-AND-VERIFY.md`.
- U4 may show that project `CLAUDE.md` still loads under `--setting-sources user`. The fallback is running agents from a scratch cwd, which changes how the fixer finds files.
- The live check spends real model calls and may hit HTTP 429. A 429 during the live run is a retry, not a failure of the unit.
- Another session may edit `skills/sast-assist/` during the program. Each owner compares file mtimes against the snapshot before writing and stops on a mismatch.
- Out of scope and still open. Resume without `--out` starts over. A failed triage call parks a finding for good. A crash mid-fix leaves a branch that blocks the retry, as `run-full3` shows. The fixer has unrestricted Bash. The leak guard rejects ordinary source. CodeQL analyses one language.

## Appendix D. Links and reading list

- The interrogate verdict from this session, with findings from reviewers on fable, opus and sonnet.
- `skills/sast-assist/SKILL.md` and `references/FIX-AND-VERIFY.md` before U1 and U3.
- `pstack/skills/interrogate/SKILL.md` for a re-review after U4 if the operator wants one.
