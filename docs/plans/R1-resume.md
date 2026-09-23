# R1: re-running the command is a real resume

## 1. Plain-language summary

Today, running the command a second time usually starts over instead of picking up where the last run stopped. Worse, when an AI call fails for a boring reason (a timeout, a rate limit, the CLI missing), the finding is marked as settled and the run claims it finished, so nobody ever retries it. And if the program crashes at one exact moment during a fix, it leaves a git branch behind that makes every later attempt at that finding fail for good.
After this change, a plain re-run continues the last unfinished run for the same commit, a failed AI call leaves the finding open and the run says "incomplete, retry", and leftovers from a crashed fix attempt are cleaned up before that attempt is tried again.

## 2. Problem, with evidence

Line numbers are for the current `skills/sast-remediate/bin/run.cjs` (936 lines), which matches `.work/snapshots/after-U4-final/`.

**(a) A plain re-run starts over.** `defaultOutDir` (`bin/run.cjs:123-133`) returns `run-<max+1>` whenever any `run-N` exists. It never looks inside the latest run. `run` computes `outDir` at line 808, before it knows the base commit (line 810-811). The only way to resume is to repeat `--out` by hand, although `SKILL.md:58` and `SKILL.md:75` both say "re-running the command is the resume path".

**(b) A failed agent call is a terminal outcome.**
- Triage: `triageAll` (`bin/run.cjs:312-314`) sets `f.disposition = { state: 'deferred', reason: 'triage_agent_failed', ... }`. `stageOf` (`bin/stage.cjs:22`) returns `done` for any non-null disposition, so the next run never asks again. `run` (lines 880-885) counts only findings with no disposition as unresolved, so the run says `complete`.
- On-disk proof: `.work/targets/run-full2/run-metadata.json` has `run_status: "complete"` while `.work/targets/run-full2/findings/f_e2981bd8a7b838b9.json` carries `{"state":"deferred","reason":"triage_agent_failed","detail":"discarded twice: cli exited 1 | cli exited 1"}`. `.work/targets/run-vulnapp/findings/f_6ed43412e0d9b09d.json` has the same disposition from a schema failure.
- Fix: `fixOne` (`bin/run.cjs:491-495`) records `outcome: 'agent_failed'` on a pushed patch, which uses one of the two attempt slots, and `finalize` (lines 746-752) turns it into `fix_failed` through `dispositionFor` (lines 724-736). The test `at verify=none a fixer that crashes ends fix_failed, not fixed` (`test/run.test.cjs:636`) and the real-git case `verify=none with a crashing fixer ends fix_failed` (`test/pipeline.real.test.cjs`) pin that behaviour today.
- The budget path is already non-terminal: `triageAll` lines 301-303 leave findings past `--max-findings` with no disposition and `run` names them in `incomplete_reason`. That path stays; the agent-failure path must be told apart from it.

**(c) A crash between `git worktree add -b` and the save leaves a trap.** `fixOne` creates the branch and worktree at line 462 and `fixAll` saves the record only after `fixOne` returns (line 520). A crash in between leaves the branch and the worktree directory with no record. On the next run the same attempt number is computed (`f.patches.length + 1`, line 456), `worktree add -b` fails because the branch exists, and the finding ends `fix_failed` with `outcome: 'error'`, permanently.
On-disk proof: `.work/targets/run-full3/findings/f_d72e46f6d1ec2eb0.json` has `gate.action: "fix"`, `patches: []`, no disposition, and no `run-metadata.json` exists in that run. `git -C .work/targets/vuln-app-git worktree list` shows `.work/targets/run-full3/worktrees/f_d72e46f6d1ec2eb0-1` on branch `sast-fix/run-full3/f_d72e46f6d1ec2eb0/1` at the base commit `08d3364`.
Probe (git 2.x, this machine): `git worktree add -b B W HEAD` on an existing branch exits 255 ("a branch named ... already exists"); into an existing unregistered non-empty directory exits 128 ("already exists"). `git worktree remove --force --force W` removes a dirty registered worktree (exit 0) and exits 128 on a path that is not a worktree. `git branch -D` on a missing branch exits 1. So the reconcile must remove the registered worktree, remove the directory, prune, and delete the branch, ignoring each exit status.

## 3. Design

### Data shape

- `run-metadata.json`, first write (today `{ run_id, verify_level }` at `bin/run.cjs:827`) gains `base_commit`. A run that crashes before its final write still says which commit it was started on.
- `run-metadata.json`, final write gains `agent_failures: [{ id, stage, reason }]` where `stage` is `'triage'` or `'fix'` and `reason` is the `reason` string `runAgent` returned, plus `counts.agent_failures` (a number).
- The finding record gains nothing. An agent failure is the absence of a result: triage stays `null`, and a failed fixer call leaves no patch entry. `stageOf` already sends such a record back to `triage` or `fix`, so resume needs no new state.
- `disposition.state === 'deferred'` now means only `split_requested`, which stays terminal because it needs a human.
- Legacy records are reopened on load: a disposition `{ state: 'deferred', reason: 'triage_agent_failed' }` becomes `null`, and a disposition `{ state: 'fix_failed', outcome: 'agent_failed' }` becomes `null` with its last patch dropped.

### Behaviour

**Run directory choice** (`defaultOutDir(target, base, root)`). Look at the highest `run-N` under `root/<basename(target)>`. Reuse it when its `run-metadata.json` does not say `run_status: 'complete'` AND its `base_commit` is absent or equals the current base. Otherwise return `run-(N+1)`. No `run-N` yields `run-1`. `--out` always wins and is never inspected.
Why "complete means fresh": a complete run has nothing left to resume, so a re-run of it is a request to run again, and a fresh directory is the only way new flags (`--verify`, `--fix-at`) take effect. Why the base check: records and branches of an unfinished run describe a different tree once HEAD moves.
When the chosen directory already has `run-metadata.json`, `run` logs `resuming <dir>`.

**Agent failure is non-terminal.**
- `triageAll` pushes `{ id, stage: 'triage', reason }` onto a `failed` list and leaves the record untouched. It returns `{ triaged, deferred, failed }`, where `triaged` now counts successful calls only.
- `fixOne`, when `runAgent` returns `ok: false`, pops the patch it pushed, calls `clearAttempt` for that branch and worktree, and returns `{ failed: reason }`. `fixAll` collects `{ id, stage: 'fix', reason }`, does not save, and moves to the next finding. It returns `{ attempted, failed }`.
- `finalize` takes a fourth argument, a `Set` of finding ids whose agent call failed this run, and skips them. This matters on attempt two: after attempt one was patched but failed its checks and attempt two's call failed, `dispositionFor` would otherwise read attempt one and write `fix_failed`.
- `run` builds `incomplete_reason` with `incompleteReason`, which lists every cause, joined by `'; '`, in this order: the degraded mode, the budget deferral, the agent failures, and, only if none of those applies, the generic "left without a terminal disposition". Budget deferral keeps its current text (`max_findings=N reached, K finding(s) deferred to the next run`), and agent failure gets its own prefix `agent_failed:`, so the two are never confused.

**Stale attempt reconcile** (`clearAttempt(git, branch, wt)`). Called by `fixOne` immediately before `git worktree add -b`, every time. It runs `git worktree remove --force --force <wt>`, `fs.rmSync(wt, { recursive: true, force: true })`, `git worktree prune`, `git branch -D <branch>`, ignoring every exit status. The branch name carries run id, finding id and attempt number, and `attempt = f.patches.length + 1`, so no saved record refers to that branch. Whatever it holds is the unrecorded work of a run that died, and starting the attempt again from base is the convergent answer.

**Module.** The resume logic moves to a new `bin/resume.cjs`: `defaultOutDir`, `recordedLevel`, `mergeExisting` (with `reopenAgentFailure`), `clearAttempt`, `incompleteReason`. `bin/run.cjs` shrinks by about 20 lines and keeps re-exporting `mergeExisting`.

### Alternatives rejected

- Reuse the latest run regardless of status: a finished run would swallow new `--verify` and `--fix-at` flags on every later run.
- A `--fresh` flag: not needed, a moved HEAD already starts fresh and `--out=<new dir>` covers the rare same-commit restart.
- Reuse a stale branch instead of deleting it: its fixer answer (`declared_files`, `enforcement_note`) was never saved, so there is nothing to verify it against.
- A stored `retry` or `status` field on the finding: `stageOf` already derives "still needs triage" and "still needs a fix" from the record's shape; a flag would be a second source of truth.
- Retry the failed call again inside the same run: `bin/agent.cjs` already re-asks once, and a rate limit usually lasts longer than one run.
- Split transport failures from malformed output: both mean "no usable answer", and the operator's re-run is the retry budget for either.

## 4. Steps

All paths below are under `skills/sast-remediate/` unless they start with `docs/` or `.work/`.

1. **Create `bin/resume.cjs`** with exactly this content (comments may be trimmed per `/no-comments`, keep the "why" ones):

   ```js
   #!/usr/bin/env node
   'use strict';
   // What one run leaves for the next, and how the next one picks it up. Re-running the command is
   // the resume path, so every function here answers "what if the last run stopped here?"

   const fs = require('fs');
   const path = require('path');
   const os = require('os');
   const { VERIFY_LEVELS } = require('./stage.cjs');
   const { trim } = require('./scan.cjs');

   const readJson = (f) => JSON.parse(fs.readFileSync(f, 'utf8'));

   // The latest run of this target is continued while it is unfinished and was started on the
   // same commit. A finished run has nothing left to resume, and an unfinished run of other code
   // holds triage and branches that describe a different tree.
   function defaultOutDir(target, base, root = path.join(os.homedir(), 'sast-remediate')) {
     const dir = path.join(root, path.basename(target));
     const nums = fs.existsSync(dir)
       ? fs.readdirSync(dir).map((d) => /^run-(\d+)$/.exec(d)).filter(Boolean).map((m) => Number(m[1]))
       : [];
     if (!nums.length) return path.join(dir, 'run-1');
     const latest = Math.max(...nums);
     const latestDir = path.join(dir, `run-${latest}`);
     let meta = {};
     try { meta = readJson(path.join(latestDir, 'run-metadata.json')) || {}; } catch { /* died before writing it */ }
     const sameBase = meta.base_commit === undefined || meta.base_commit === base;
     return meta.run_status !== 'complete' && sameBase ? latestDir : path.join(dir, `run-${latest + 1}`);
   }

   function recordedLevel(metaFile) {
     try {
       const level = readJson(metaFile).verify_level;
       return Object.hasOwn(VERIFY_LEVELS, level) ? level : null;
     } catch { return null; }
   }

   // Records written before a failed agent call became retryable carry it as an outcome. Reopen
   // them, so a call that died on a rate limit is asked again instead of standing as a verdict.
   function reopenAgentFailure(r) {
     const d = r.disposition;
     if (d && d.state === 'deferred' && d.reason === 'triage_agent_failed') return { ...r, disposition: null };
     if (d && d.state === 'fix_failed' && d.outcome === 'agent_failed') {
       return { ...r, disposition: null, patches: (r.patches || []).slice(0, -1) };
     }
     return r;
   }

   // Records already on disk win, so triage, gate and patches survive a re-run and stageOf decides
   // what each record still needs. This is the whole of resume.
   function mergeExisting(findings, outDir) {
     const dir = path.join(outDir, 'findings');
     if (!fs.existsSync(dir)) return 0;
     const prior = new Map();
     for (const file of fs.readdirSync(dir)) {
       if (!file.endsWith('.json')) continue;
       try { const r = readJson(path.join(dir, file)); prior.set(r.id, r); } catch { /* a truncated record is re-derived */ }
     }
     let n = 0;
     findings.forEach((f, i) => {
       if (!prior.has(f.id)) return;
       const p = reopenAgentFailure(prior.get(f.id));
       findings[i] = { ...f, triage: p.triage, gate: p.gate, patches: p.patches || [], disposition: p.disposition, prior: p.prior };
       n++;
     });
     return n;
   }

   // A run that died between creating an attempt's branch and saving its record left both behind,
   // and `worktree add -b` refuses an existing branch or directory. No record names that attempt,
   // so its leftovers go and the attempt starts again from base. Each step makes something absent,
   // so a failing step means it already was.
   function clearAttempt(git, branch, wt) {
     git(['worktree', 'remove', '--force', '--force', wt]);
     fs.rmSync(wt, { recursive: true, force: true });
     git(['worktree', 'prune']);
     git(['branch', '-D', branch]);
   }

   // Every reason the run is not finished, so a budget stop and a failed agent call never read alike.
   function incompleteReason({ degraded, unresolved, budget, deferred, failures }) {
     const parts = [];
     if (degraded) parts.push(`${degraded}: ${unresolved} finding(s) left without a terminal disposition`);
     if (deferred) parts.push(`max_findings=${budget} reached, ${deferred} finding(s) deferred to the next run`);
     if (failures.length) {
       parts.push(`agent_failed: ${failures.length} agent call(s) failed and will be retried on the next run (`
         + `${failures.map((x) => `${x.id} ${x.stage}: ${trim(x.reason)}`).join(', ')})`);
     }
     if (!parts.length && unresolved) parts.push(`${unresolved} finding(s) left without a terminal disposition`);
     return parts.length ? parts.join('; ') : null;
   }

   module.exports = { defaultOutDir, recordedLevel, reopenAgentFailure, mergeExisting, clearAttempt, incompleteReason };
   ```

2. **`bin/run.cjs`, imports.** Add after the `guardDiff` require (line 28):
   `const { defaultOutDir, recordedLevel, mergeExisting, clearAttempt, incompleteReason } = require('./resume.cjs');`
   Delete the local `defaultOutDir` (lines 123-133), `recordedLevel` (lines 756-761) and `mergeExisting` with its two-line comment (lines 769-787). Remove `os` from the requires only if nothing else uses it (grep `os\.`; today only `defaultOutDir` does).

3. **`bin/run.cjs`, `USAGE`.** Replace the `--out` line with two lines:
   ```
     --out=DIR           output dir (default: continue the latest unfinished run of this
                         commit under ~/sast-remediate/<repo>/, else start run-<N+1>)
   ```

4. **`bin/run.cjs`, `triageAll`.** Declare `const failed = [];` before the loop. Replace the `if (!res.ok)` branch body with:
   ```js
   failed.push({ id: f.id, stage: 'triage', reason: res.reason });
   continue;
   ```
   with a one-line comment: `// No answer is not a verdict. The record stays at triage, so the next run asks again.` (The record was already saved after pre-resolve, so nothing is written.) Change the return to `return { triaged: doing.length - failed.length, deferred, failed };`.

5. **`bin/run.cjs`, `fixOne`.** Insert `clearAttempt(ctx.git, branch, wt);` on the line before `const add = ctx.git(['worktree', 'add', '-b', branch, wt, ctx.base]);`. Replace the `if (!res.ok) { patch.outcome = 'agent_failed'; ... return; }` block with:
   ```js
   if (!res.ok) {
     // No answer is not an attempt: it takes no attempt slot, and the next run tries again.
     f.patches.pop();
     clearAttempt(ctx.git, branch, wt);
     return { failed: res.reason };
   }
   ```
   Every other `return` in `fixOne` stays a bare `return;`.

6. **`bin/run.cjs`, `fixAll`.** Declare `const failed = [];`. Inside the `while`, replace `await fixOne(f, ctx);` with:
   ```js
   const r = await fixOne(f, ctx);
   attempted++;
   if (r && r.failed) { failed.push({ id: f.id, stage: 'fix', reason: r.failed }); break; }
   ```
   and delete the old `attempted++;` line so it is counted once. Return `{ attempted, failed }`.

7. **`bin/run.cjs`, `finalize`.** New signature `function finalize(findings, level, ctx, open = new Set())`. First line in the loop becomes `if (f.disposition || open.has(f.id)) continue;`.

8. **`bin/run.cjs`, `run`.**
   - Move the three lines `const git = ...`, `const head = ...`, `const base = ...` above the `outDir` line, and change that line to `const outDir = path.resolve(opts.out || defaultOutDir(target, base));`.
   - After `const metaFile = ...`, add:
     ```js
     if (fs.existsSync(metaFile)) deps.log(`resuming ${outDir}`);
     ```
   - First metadata write becomes `writeJson(metaFile, { run_id: runId, verify_level: opts.verify, base_commit: base });`.
   - `let fixSummary = { attempted: 0, failed: [] };`.
   - Before `finalize`, add `const failures = [...tr.failed, ...fixSummary.failed];` and call `finalize(findings, opts.verify, ctx, new Set(failures.map((x) => x.id)));`.
   - Replace the nested-ternary `incompleteReason` constant with
     ```js
     const why = incompleteReason({ degraded, unresolved: unresolved.length, budget: opts.maxFindings,
       deferred: tr.deferred.length, failures });
     ```
     and use `why` for `run_status` and `incomplete_reason`.
   - In `meta`, add `agent_failures: failures,` after `incomplete_reason`, and `agent_failures: failures.length,` inside `counts` after `deferred`.
   - `module.exports` keeps `mergeExisting` (now the imported one) and adds `defaultOutDir`.

9. **`bin/report.cjs`, `renderRemediation`.** Line 206: `(${findings.length - triagedCount} deferred)` becomes `(${findings.length - triagedCount} not triaged yet)`. "Deferred" no longer describes both a budget stop and a failed call.

10. **`SKILL.md`.**
    - Setup, **Output directory** bullet: replace `Default \`~/sast-remediate/<repo>/run-<N>\`.` with `Default: the latest \`~/sast-remediate/<repo>/run-<N>\` when that run is unfinished and was started on the same commit, otherwise a new \`run-<N+1>\`. \`--out\` always wins.`
    - Stage 3: replace `Budget bounds the run; unspent work becomes \`deferred\` and is persisted, never dropped.` with `Budget bounds the run. Findings past the budget stay untriaged on disk and the next run picks them up. A triage call that returns no usable answer is not a verdict: the finding stays at triage, the run ends \`incomplete\` and names it, and the next run asks again.`
    - Rule **Malformed agent output is discarded, never repaired.** Replace `Re-run once with a fresh agent, then\ndefer.` with `Re-run once with a fresh agent, then leave the finding open for the next run.`
    - Tools section: after the `bin/stage.cjs` sentence add `\`bin/resume.cjs\` picks the run directory, merges the records already on disk, and clears the leftovers of an attempt that a crashed run never recorded.`
11. **`references/TRIAGE.md` line 13.** `Re-run once with a fresh agent, then defer.` becomes `Re-run once with a fresh agent, then leave the finding open. The run ends \`incomplete\` and the next run asks again.`
12. **`references/FIX-AND-VERIFY.md`, Branch protocol.** Append a paragraph after "Rollback is declining to cherry-pick.":
    `Before an attempt creates its branch, \`clearAttempt\` removes any branch or worktree of the same name. Only a run that died before saving that attempt leaves one behind, and no record holds its work, so the attempt starts again from base. A fixer call that returns no usable answer records no attempt at all. Its branch is removed, the finding stays open, and the next run tries again.`
13. Run `node ../../tools/check-prose.cjs` and `node tools/validate-skill.cjs`. `clearAttempt` in backticks is checked against `bin/` definitions, and it is defined as `function clearAttempt(`.

## 5. Tests

Write each test, run it against the unchanged code to see it fail (or, for rewritten cases, see the old assertion now contradicted), then land the code. All `run.test.cjs` cases use the existing `makeDeps`, `baseOpts`, `triageOnlyRun`, `fixRun` helpers. Add a new section `section('resume');` before `section('end state');` for the new cases unless stated otherwise.

**Helper changes.**
- `test/run.test.cjs` `fixRun`: `const out = over.out || path.join(tmp(), 'run-1');` so a second run can reuse the directory.
- `test/pipeline.real.test.cjs` `runScenario`: add options `runs = 1` and `prepare = null`. After writing the scenario file call `if (prepare) prepare(target, out);`. Move the post-run snapshot (everything from `const calls = ...` to the returned object) into a local `snapshot(res)`. Loop `runs` times calling `R.run(opts, deps)` and `snapshot`. Return `{ ...last, first }` where `first` is the first snapshot.

**`test/run.test.cjs`, rewritten cases.**

1. Rename `malformed agent output defers the finding instead of being repaired` to `a failed triage call leaves the finding open for the next run`. Setup: `triageOnlyRun({ triage: () => ({ ok: false, reason: 'unparseable', raw: '{' }) })`, plus `opts.triageOnly` stays. For every finding: `f.triage === null`, `f.disposition === null`, `stageOf(f, 'cheap') === 'triage'`. Meta: `run_status === 'incomplete'`, `counts.agent_failures === 3`, `counts.triaged === 0`, `agent_failures.every((x) => x.stage === 'triage' && x.reason === 'unparseable')`, `incomplete_reason` matches `/agent_failed: 3 agent call\(s\) failed and will be retried on the next run/`.
2. Rename `at verify=none a fixer that crashes ends fix_failed, not fixed` to `a fixer call that fails takes no attempt slot and leaves the finding open`. Setup unchanged: `fixRun({ verify: 'none', fix: () => ({ ok: false, reason: 'exit 1' }) })`. Let `fixable = res.findings.filter((f) => f.gate && f.gate.action === 'fix')`; assert `fixable.length > 0`. For each: `f.patches.length === 0`, `f.disposition === null`, and `deps.state.execCalls` contains `git -C ${REPO} branch -D sast-fix/${R.refSafe(res.runId)}/${f.id}/1`. Meta: `run_status === 'incomplete'`, `agent_failures` deep-equals `fixable.map((f) => ({ id: f.id, stage: 'fix', reason: 'exit 1' }))` in fix order (compare sorted by id), fixer call count equals `fixable.length`.
3. `a worktree that was never created names no branch in the handoff`: change its `fixRun` argument to `{ fix: () => ({ ok: true, data: { outcome: 'cannot_fix', reason: 'x' } }) }` so a patch record exists; the rest of the case is unchanged.

**`test/run.test.cjs`, new cases.**

4. `defaultOutDir continues an unfinished run of the same commit and starts fresh otherwise`. Pure, no `run`. `const root = tmp(); const B = 'b'.repeat(40);` Helper `mk(n, meta)` creates `root/vuln-app/run-n` and, when `meta` is given, writes it as `run-metadata.json`. Assert in order, calling `R.defaultOutDir('/x/vuln-app', B, root)`:
   - nothing created: `path.join(root, 'vuln-app', 'run-1')`.
   - `mk(1, { run_status: 'complete', base_commit: B })`: `run-2`.
   - `mk(2, { run_id: 'run-2', verify_level: 'cheap', base_commit: B })` (a run that died mid-way): `run-2`.
   - rewrite run-2 meta to `{ run_status: 'incomplete', base_commit: B }`: `run-2`.
   - rewrite run-2 meta to `{ run_status: 'incomplete', base_commit: 'c'.repeat(40) }`: `run-3`.
   - rewrite run-2 meta to `{ run_status: 'incomplete' }` (legacy, no base recorded): `run-2`.
   - `mk(3)` with no metadata file: `run-3`.
   - `mk(10, { run_status: 'complete', base_commit: B })`: `run-11` (numeric, not lexical, order).
5. `a plain re-run continues the unfinished run instead of starting run-2`. Save `process.env.HOME`, set it to `tmp()`, restore in `finally`. Run 1: `baseOpts()` with `maxFindings = 1`, no `out`, triage `notExploitable`. Assert `res1.outDir === path.join(HOME, 'sast-remediate', 'vuln-app', 'run-1')` and `res1.meta.run_status === 'incomplete'`. Run 2: `baseOpts()`, no `out`, fresh deps. Assert `res2.outDir === res1.outDir`, `deps2.state.agentCalls.length === 2`, `res2.meta.run_status === 'complete'`, and `readJson(path.join(res1.outDir, 'run-metadata.json')).base_commit === 'a'.repeat(40)`. Run 3: same again. Assert `res3.outDir` ends with `run-2`.
6. `a failed triage call is asked again by the next run`. `out = path.join(tmp(), 'run-1')`, triage-only opts with that `out`. Run 1 triage `{ ok: false, reason: 'rate limited' }`; run 2 triage `notExploitable`. Assert run 2 `agentCalls.length === 3`, `meta.run_status === 'complete'`, `meta.agent_failures` deep-equals `[]`, every finding's `disposition.state === 'rejected'`.
7. `a budget stop and a failed agent call are told apart`. Triage-only, `maxFindings = 1`, triage `{ ok: false, reason: 'timed out after 300000ms' }`. Assert `meta.counts.deferred === 2`, `meta.counts.agent_failures === 1`, and `incomplete_reason` includes both `max_findings=1 reached, 2 finding(s) deferred to the next run` and `agent_failed: 1 agent call(s) failed and will be retried on the next run (` and `triage: timed out after 300000ms)`.
8. `a failed second fix attempt keeps the first attempt and the finding open`. `fixRun({ npm: (cwd) => (cwd.includes('worktrees/base') ? 0 : 1), fix: (o) => (o.cwd.endsWith('-1') ? PATCHED : { ok: false, reason: 'rate limited' }) })` where `PATCHED` is the default `fixRun` patched answer (lift it into a const). For each finding with `gate.action === 'fix'`: `patches.length === 1`, `patches[0].outcome === 'patched'`, `disposition === null`, `stageOf(f, 'cheap') === 'fix'`. Meta `run_status === 'incomplete'`. Then re-run with `fixRun({ out, npm: () => 0 })` (default fixer). For the same ids: `patches.length === 2`, `patches[1].attempt === 2`, `disposition.state === 'fixed_unwitnessed'` (the default contract is `argued`), and meta `run_status === 'complete'`.
9. `a record deferred by a failed triage call under the old rules is reopened`. Run 1: triage-only with `out`, triage `notExploitable`. Pick `id = res1.findings[0].id`, edit `out/findings/<id>.json`: `triage = null`, `gate = null`, `disposition = { state: 'deferred', reason: 'triage_agent_failed', detail: 'discarded twice: cli exited 1 | cli exited 1' }`. Run 2 with same `out` and triage `notExploitable`. Assert run 2 `agentCalls.length === 1` and the edited record's `disposition.state === 'rejected'`.
10. `a fix that failed on a dead agent call under the old rules is tried again`. Run 1: `fixRun()` default. Pick the first finding with `patches.length === 1`, remember `state1 = f.disposition.state`. Edit its file: `patches = [{ ...patches[0], outcome: 'agent_failed', detail: 'exit 1', verification: {} }]`, `disposition = { state: 'fix_failed', outcome: 'agent_failed', detail: 'exit 1', branch: patches[0].branch, attempts: 1, failed: [], missing: [], worktree: patches[0].worktree }`. Run 2: `fixRun({ out })`. Assert run 2 made exactly 1 call with `schemaPointer === '#/$defs/fix'`, the record has `patches.length === 1`, `patches[0].outcome === 'patched'`, and `disposition.state === state1`.

**`test/pipeline.real.test.cjs`.**

11. Replace scenario `crashAtNone` with `crashThenFix: memo(() => runScenario('crash', { verify: 'none', runs: 2, fix: [{ act: 'crash' }, { act: 'crash' }, PATCH] }))` (two crashes because `bin/agent.cjs` re-asks once). Replace case `verify=none with a crashing fixer ends fix_failed` with `a crashing fixer leaves the finding open, and the next run fixes it`: `s.first.states[PATH_ID] === null`, `s.first.meta.run_status === 'incomplete'`, `s.first.meta.incomplete_reason` includes `${PATH_ID} fix: discarded twice: cli exited 1`, `s.first.branches` deep-equals `[]`, `s.first.fixerCalls === 2`; `s.states[PATH_ID] === 'fixed'`, `s.meta.run_status === 'complete'`, `s.fixerCalls === 3`, `s.branches` deep-equals `[`sast-fix/run-crash/${PATH_ID}/1`]`.
12. New scenario `stale: memo(() => runScenario('stale', { prepare: (target, out) => { const wt = path.join(out, 'worktrees', `${PATH_ID}-1`); git(target, 'worktree', 'add', '-q', '-b', `sast-fix/run-stale/${PATH_ID}/1`, wt, 'HEAD'); fs.writeFileSync(path.join(wt, 'half-written.txt'), 'left by a run that died\n'); } }))`. Case `a branch left by a run that died mid-fix is cleared and the attempt runs again`: `s.states[PATH_ID] === 'fixed'`, `s.fixerCalls === 1`, `s.filesOn(`sast-fix/run-stale/${PATH_ID}/1`)` deep-equals `['src/routes/files.js', 'test/files.test.js']`, `s.meta.run_status === 'complete'`. This mirrors `.work/targets/run-full3`.

Net: 8 new cases (4, 5, 6, 7, 8, 9, 10, 12) and 4 rewritten (1, 2, 3, 11).

## 6. Verification

1. `cd skills/sast-remediate && sh test/run-all.sh` ends with `all green`. The `pipeline` block reports 7 more passes than today (cases 4 to 10); the real-git block reports one more (case 12).
2. `wc -l bin/run.cjs` is below 936 (expect about 915). `wc -l bin/resume.cjs` is about 95.
3. `node tools/check-prose.cjs` from the repo root prints `prose clean`.
4. Mutation checks. Apply each, run the named file, see the named case fail, revert.
   - `defaultOutDir`: change the return to always `path.join(dir, \`run-${latest + 1}\`)`. Cases 4 and 5 fail.
   - `triageAll`: restore `f.disposition = { state: 'deferred', reason: 'triage_agent_failed', detail: res.reason };` in place of `continue`. Cases 1 and 6 fail.
   - `fixOne`: delete `f.patches.pop();`. Case 2 fails (`patches.length` is 1).
   - `finalize`: drop `|| open.has(f.id)`. Case 8 fails (`disposition` is `fix_failed`).
   - `mergeExisting`: replace `reopenAgentFailure(prior.get(f.id))` with `prior.get(f.id)`. Cases 9 and 10 fail.
   - `incompleteReason`: drop the `failures` part. Cases 1 and 7 fail.
   - `fixOne`: delete the `clearAttempt(ctx.git, branch, wt);` line before `worktree add`. Case 12 fails with state `fix_failed`.
5. No real `claude` call and no `fable` model anywhere; the fake CLI and the `deps.runAgent` seam cover every case.

## 7. Risks and scope

**Top risk: an auto-resumed run keeps the flags it started with.** `run` already makes the recorded `verify_level` win (log line only), and saved gates keep the `--fix-at` they were computed with. Before this change that needed `--out`; now a plain re-run of an unfinished run does it. Example: a `--triage-only` run, then `--verify=full`, resumes at `cheap`. The `resuming <dir>` log line and the existing "was started at --verify" line say so, and `--out=<new dir>` starts fresh. Changing that rule is a separate unit.

Other risks:
- A finding whose agent call always fails (a prompt the model never answers in schema) keeps every run `incomplete`. That is honest, and the reason names the finding. There is no cross-run retry cap.
- `clearAttempt` runs `git branch -D` on `sast-fix/<run-id>/<id>/<attempt>` in the target. Only this tool creates that name, and no saved record refers to it at that moment, so no recorded fix is deleted.
- Reopening legacy records means `--out=.work/targets/run-full2` would re-ask the finding that died on `cli exited 1`. That is the intended convergence.

Out of scope:
- A failed hostile-auditor call (`runAudit`, `--verify=full` only) still becomes a failed `hostile_auditor` obligation and uses up an attempt. Same pattern as (b), but the patch is already committed, so retrying only the audit needs a partial-verification state. Recommend a follow-up unit.
- `worktree_failed` for any other cause (disk full) is still terminal.
- An explicit `--out` pointing at a run of a different commit is not checked.

**Symbols touched, for sequencing.** `bin/run.cjs`: requires block, `USAGE`, `defaultOutDir` (removed), `recordedLevel` (removed), `mergeExisting` (removed, re-exported), `triageAll`, `fixOne`, `fixAll`, `finalize`, `run`, `module.exports`. `bin/report.cjs`: `renderRemediation` (one line). New `bin/resume.cjs`. `SKILL.md`, `references/TRIAGE.md`, `references/FIX-AND-VERIFY.md`. `test/run.test.cjs`, `test/pipeline.real.test.cjs`.
