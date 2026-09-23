# R5: make `--verify=full` able to pass a fix, and connect the live-app witness

## 1. Plain-language summary

Today, asking for the strictest check (`--verify=full`) guarantees failure. Every fix is marked failed after two tries, because the tool demands proof from an "attack test" that, in the default setup, can never run. This plan changes two things. First, when the triage agent says no attack test is possible (the `argued` tier), the tool records that honestly as "not available", still runs every other check (the project's tests, the rescan, the independent reviewer), and lands the fix as "patched but needs a human look" after one try. Second, a new `--witness=dynamic` option lets the tool start the real app twice (before and after the fix), send the attack and a normal request to both, and pass the fix only if the attack stops working while the normal request still works. The third piece, running a fixer-written test file (`executable` tier), is deferred, because done cheaply it would be easy to game and would label gamed fixes as fully proven.

## 2. Problem, with evidence

All line numbers are in `skills/sast-remediate/` and were read on the current tree (run.cjs is 936 lines).

1. **Triage is only ever offered `argued`.** `bin/run.cjs:851` sets `witnessTiers: ['argued']` unconditionally, and `buildTriagePrompt` prints it at `bin/run.cjs:289`.
2. **An argued witness at full is always a failure.** `runDifferentialWitness` (`bin/run.cjs:631-648`) returns `{ status: 'unavailable', reason: 'tier_not_implemented:argued' }` for every non-dynamic tier. `differential_witness` is not in `MAY_BE_UNAVAILABLE` (`bin/stage.cjs:372`), so `evaluateVerification` counts it as failed. `verifyPatch` then stops at `bin/run.cjs:576` (`stopped = ... !== 'pass'`), so `functional_control`, `regression_suite` and `no_new_findings` are never written and show as `missing`. `stageOf` sends the finding back to `fix`, and the second attempt fails the same way.
3. **Reproduced.** A probe through the `run()` deps seam (same `makeDeps` as `test/run.test.cjs`, `verify=full`, argued contract, auditor answering `enforces_invariant`) produced, for `f_6ed43412e0d9b09d`:
   `{"state":"fix_failed","attempts":2,"failed":["differential_witness"],"missing":["functional_control","regression_suite","no_new_findings"]}`
   with `differential_witness: {"status":"unavailable","reason":"tier_not_implemented:argued"}` on both patches. The docs say the opposite: `references/FIX-AND-VERIFY.md:108` "argued ... reaches `fixed_unwitnessed`".
4. **The dynamic tier is wired wrongly.** `bin/run.cjs:642` calls `runWitness(contract.witness, { base, patched: patch.worktree }, {})`:
   - no `allowDynamic`, so `runWitness` throws "opt-in" (`bin/witness-run.cjs:137-139`), caught at `run.cjs:645` as `unavailable`;
   - it passes directory paths, while `runDynamic` reads `trees[tree].baseUrl` for `tree` in `base` and `head` (`bin/witness-run.cjs:81`), so it needs booted apps under `base` and `head`, not dirs under `patched`;
   - it reads `r.classification` (`run.cjs:643-644`), but the field `runWitnessInner` returns is `failure` (`bin/witness-run.cjs:160`);
   - nothing boots or tears down an app. `boot` exists at `bin/app-harness.cjs:262` and `test/e2e-witness.cjs:106-113` shows the correct call (`boot` both trees on free ports, `runWitness(w, { base: b, head: h }, { allowDynamic: true })`, `kill()` in `finally`).
5. **No `--witness` flag.** `parseArgs` (`bin/run.cjs:54-86`) has no `witness` case, yet `SKILL.md:164`, `references/DYNAMIC-WITNESS.md:4`, `references/FIX-AND-VERIFY.md:71` and the thrown message at `witness-run.cjs:138` all tell the operator to pass `--witness=dynamic`.
6. **The guard would reject every dynamic fix.** `bin/patch-guard.cjs:146` raises `witness_missing` for any tier other than `argued` when no test or yaml file is in the diff. A dynamic witness is an HTTP exchange stored in the contract. The fixer writes no file for it.
7. **The http control is never exercised.** `runFunctionalControl` returns `unavailable: http_control_needs_the_dynamic_tier` (`bin/run.cjs:664`), and `runDynamic` already computes `control_ok` from both trees, which nobody reads.
8. **Report contradiction (found while reading).** `verificationSummary` (`bin/report.cjs:88-100`) prints "verified at `full`: all seven obligations passed" whenever nothing was skipped, then appends "X unavailable and excused, not passed". Once argued fixes reach full, that sentence would appear on every one of them.
9. **Test fake cannot answer an auditor.** `test/fake-claude.cjs:79-88` answers only `triage` and `fix`; an `audit` prompt exits 3. No pipeline.real case runs at `full` today.

On-disk runs: every `.work/targets/run-full*/run-metadata.json` records `"verify_level": "cheap"`. No real run at `full` exists, which is consistent with full never succeeding.

## 3. Design

### Data shapes

**CLI option.** `opts.witness`: `null` (default) or `'dynamic'`. Any other value is a `UsageError`.

**Offered tiers.** `ctx.witnessTiers`: `['dynamic', 'argued']` when `opts.witness === 'dynamic'` and `discoverAppHarness(target)` returned at least one harness, else `['argued']`. `ctx.appHarness` is always an array (empty when discovery threw or found nothing).

**Witness result**, returned by one new function `witnessObligations` in `bin/witness-run.cjs`, and written into `patch.verification` by the caller without reinterpretation:

```js
{
  differential_witness: { status: 'pass'|'fail'|'unavailable', reason?: string, detail?: string, transcript?: Array },
  functional_control?:  { status: 'pass'|'fail'|'unavailable', reason?: string, detail?: string },
}
```

`functional_control` is present only when the tier answers it: `argued` (always unavailable, it has no control) and `dynamic` (the four-step run sends the control to both trees). Reasons are fixed strings:

| case | differential_witness | functional_control |
|---|---|---|
| tier `argued` | `unavailable`, `argued_tier:<obstacle>` | `unavailable`, `argued_tier_has_no_control` |
| tier `executable` or `structural` | `unavailable`, `tier_not_implemented:<tier>` | absent |
| tier `dynamic`, `allowDynamic` false | `unavailable`, `dynamic_tier_not_enabled` | absent |
| tier `dynamic`, `baseDir` null | `unavailable`, `no_base_tree` | absent |
| tier `dynamic`, no harness with `id === w.harness_id` | `unavailable`, `no_app_harness:<harness_id>` | absent |
| base tree does not boot | `unavailable`, `base_did_not_boot:<why>` | absent |
| patched tree does not boot | `fail`, `patched_tree_did_not_boot:<why>` | same object |
| ran, `differential_ok` | `pass`, `detail` = `r.post.detail`, `transcript` | see next rows |
| ran, not `differential_ok` | `fail`, `reason` = `r.failure` or `witness_not_differential` | see next rows |
| ran, `control_ok` | | `pass`, `detail` = `r.control.detail` |
| ran, control failed on base (`r.control.passed_pre === false`) | | `fail`, `control_failed_on_base` |
| ran, control failed on patched tree | | `fail`, `control_failed_on_patched_tree` |

**Excusal rule**, one table in `bin/stage.cjs`, next to `MAY_BE_UNAVAILABLE`:

```js
const EXCUSED_AT_ARGUED = new Set(['differential_witness', 'functional_control']);
const excused = (name, tier) => MAY_BE_UNAVAILABLE.has(name) || (tier === 'argued' && EXCUSED_AT_ARGUED.has(name));
```

`evaluateVerification(verification, required = OBLIGATIONS, tier = null)` uses `excused(name, tier)` where it used `MAY_BE_UNAVAILABLE.has(name)`. The tier comes from the frozen contract, never from the verification record, so a patch cannot excuse itself.

### Behaviour

- **Argued at full.** Obligations 3 and 4 are recorded `unavailable` with the obstacle as the reason and are excused. Verification does not stop there, so the guard, regression suite, rescan and hostile auditor all run and must hold. If they do, `dispositionFor` already yields `fixed_unwitnessed` (`bin/run.cjs:740`) and the report lists it under "Patched but unwitnessed", naming the excused obligations. One fixer call. This is strictly more checking than `cheap`, which already lands argued fixes as `fixed_unwitnessed`.
- **Dynamic.** `witnessObligations` finds the harness by `w.harness_id` in `ctx.appHarness`, boots base (the shared `baseTree(ctx)` worktree) and the patched worktree on fresh loopback ports via `boot` from `bin/app-harness.cjs`, runs `runWitness(w, { base: b, head: h }, { allowDynamic: true })`, maps the result per the table, and kills both processes in a `finally`. A dynamic fix that passes everything reaches `fixed`.
- **Short-circuit** in `verifyPatch` becomes "stop unless the obligation holds", where holds means `pass`, or `unavailable` and `excused(name, tier)`. For `regression_suite` and `no_new_findings` this is exactly the current `=== 'fail'` behaviour.
- **Guard.** `witness_missing` applies only to tiers whose witness is a file the fixer commits: `executable` and `structural`.

### Executable tier: deferred

Not implemented in R5. Reason, stated for `design/FUTURE-IMPROVEMENTS.md`:

1. The executable witness file is written by the fixer during the fix (`witnessBrief` says "Commit this test", `bin/run.cjs:359`). That breaks the first non-gameable property in `FIX-AND-VERIFY.md` ("authored before the fix exists"). A fixer can write a test that imports something only the patch adds. It fails on base and passes on the patch, which looks exactly like a valid differential.
2. `FIX-AND-VERIFY.md` requires "a witness that errors on base" to be `witness_vacuous`. Telling "assertion failed" apart from "crashed because it needs new code" requires parsing each framework's result format (TAP, pytest, go test). Exit codes alone cannot do it.
3. Done with exit codes, the tier would label gamed fixes `fixed` instead of `fixed_unwitnessed`, which is worse than not having it. The fake fixer's witness (`test/fake-claude.cjs:44-49`) is not even runnable (`statusFor` is undefined), so it would "pass" the red half by crashing.

### Alternatives rejected

- Drop obligations 3 and 4 from the required set for argued: they would show as "skipped at this verify level", which misstates why. Recording them unavailable with the obstacle is honest.
- Add `differential_witness` to `MAY_BE_UNAVAILABLE` globally: a dynamic run whose base will not boot would then pass as `fixed`.
- A new status value such as `not_applicable`: every reader of `status` would need a new branch; `unavailable` plus a tier-scoped excusal changes one function.
- Put boot and teardown in `bin/run.cjs`: pushes run.cjs toward 1000 lines and splits the sandbox rules across two files. `witness-run.cjs` already owns the witness.
- Validate at triage that the witness tier is one of the offered tiers: useful, but a separate change to triage handling (see Risks).

## 4. Steps

Do them in this order. Run `sh test/run-all.sh` from `skills/sast-remediate` after step 7 and at the end.

1. **`bin/stage.cjs`.**
   - Below `MAY_BE_UNAVAILABLE`, add `EXCUSED_AT_ARGUED` and `excused(name, tier)` exactly as in section 3, with a two-line comment: an argued witness sends no attack and has no control, so the pair is recorded unavailable with the obstacle and excused, and the disposition is `fixed_unwitnessed` so a human still reviews it.
   - `evaluateVerification(verification, required = OBLIGATIONS, tier = null)`: replace `MAY_BE_UNAVAILABLE.has(name)` with `excused(name, tier)`. Update the comment above `MAY_BE_UNAVAILABLE` to mention the argued pair.
   - `stageOf`: in the `fix` case, pass the tier: `evaluateVerification(last.verification, VERIFY_LEVELS[level], finding.triage.contract?.witness?.tier ?? null)`. Optional chaining is required because `test/selftest.cjs` builds triages with no contract (`const triaged = { verdict: 'exploitable' }`, line 344).
   - Add `excused` to `module.exports`.

2. **`bin/patch-guard.cjs`.** Add `const WITNESS_FILE_TIERS = new Set(['executable', 'structural']);` near the other constants. Change line 146 to `if (WITNESS_FILE_TIERS.has(tier) && opts.requireWitnessFile !== false) {`.

3. **`bin/witness-run.cjs`.** Add, above `module.exports`:
   - `freePort()`: the same five-line helper as `test/e2e-witness.cjs:72-75` (`net.createServer().listen(0, '127.0.0.1')`, read the port, close). Require `net` at the top.
   - `const unavailable = (reason) => ({ status: 'unavailable', reason });`
   - `async function witnessObligations(w, { baseDir, headDir, harnesses }, { allowDynamic = false } = {})` implementing the table in section 3, in the table's row order. For the dynamic run: `const b = await boot(harness, baseDir, { port: await freePort() }); let h = null; try { ...; h = await boot(harness, headDir, { port: await freePort() }); ... } finally { b.kill(); if (h) h.kill(); }`. `boot` returns a no-op `kill` when it failed, so calling it unconditionally is safe. Call `runWitness(w, { base: b, head: h }, { allowDynamic: true })`.
   - Export `witnessObligations` and `freePort`. Leave `runWitness` and its opt-in throw unchanged.
   - Update the error text at line 138 only if it names a flag that differs (it already says `--witness=dynamic`, keep it).

4. **`bin/run.cjs`, CLI.**
   - `USAGE`: add the line `  --witness=dynamic   also offer the live-app witness (boots the app on loopback)` after `--verify`.
   - `parseArgs`: default `witness: null`; `case 'witness': opts.witness = String(val); break;`; after the loop, `if (opts.witness !== null && opts.witness !== 'dynamic') throw new UsageError('--witness must be dynamic');`.

5. **`bin/run.cjs`, `run()`.** Replace lines 845-846 and 851:
   ```js
   let appHarness = [];
   try { appHarness = require('./app-harness.cjs').discoverAppHarness(target); } catch { /* optional */ }
   const dynamicOffered = opts.witness === 'dynamic' && appHarness.length > 0;
   if (opts.witness === 'dynamic' && !dynamicOffered) deps.log('--witness=dynamic: no app harness discovered, so triage is offered argued only');
   ```
   and `witnessTiers: dynamicOffered ? ['dynamic', 'argued'] : ['argued'],`.
   In `buildTriagePrompt` (line 288) change the harness line to `app harness: ${ctx.appHarness && ctx.appHarness.length ? JSON.stringify(ctx.appHarness) : 'none discovered'}` (an empty array must not print `[]`; `test/run.test.cjs:281` passes `appHarness: null`).

6. **`bin/run.cjs`, verification.**
   - Replace `runDifferentialWitness` (lines 631-648) with a thin adapter:
     ```js
     async function runDifferentialWitness(contract, patch, ctx) {
       const { witnessObligations } = require('./witness-run.cjs');
       const w = contract.witness;
       try {
         return await witnessObligations(w,
           { baseDir: w.tier === 'dynamic' ? baseTree(ctx) : null, headDir: patch.worktree, harnesses: ctx.appHarness },
           { allowDynamic: ctx.opts.witness === 'dynamic' });
       } catch (e) {
         return { differential_witness: { status: 'unavailable', reason: `witness_error:${trim(e.message)}` } };
       }
     }
     ```
   - `verifyPatch`: import `excused` from `./stage.cjs` (line 23). At the top add `const tier = contract.witness.tier;` and `const holds = (name) => v[name].status === 'pass' || (v[name].status === 'unavailable' && excused(name, tier));`. Then:
     - differential block: `const w = await runDifferentialWitness(contract, patch, ctx); v.differential_witness = w.differential_witness; if (w.functional_control) v.functional_control = w.functional_control; stopped = !holds('differential_witness');` with a one-line comment that the dynamic run sends the control to both trees and the argued tier has none, so either answers obligation 4 as well.
     - control block: `if (!v.functional_control) v.functional_control = runFunctionalControl(contract, patch, ctx); stopped = !holds('functional_control');`
     - regression block: `stopped = !holds('regression_suite');`
     - rescan block: `stopped = !holds('no_new_findings');`
     - guard call: delete the `requireWitnessFile: contract.witness.tier !== 'argued',` line (the guard now decides by tier).
   - `fixOne` line 506: `evaluateVerification(patch.verification, VERIFY_LEVELS[ctx.opts.verify], f.triage.contract.witness.tier)`.
   - `dispositionFor`: move `const tier = f.triage.contract.witness.tier;` above the `ev` computation and pass it as the third argument to `evaluateVerification`.
   - Check `wc -l bin/run.cjs` stays under 1000 (expected about 945).

7. **`bin/report.cjs`, `verificationSummary`.** When `d.skipped_obligations.length === 0`, push `` `verified at ${code('full')}: all seven obligations ${d.unavailable.length ? 'checked' : 'passed'}` ``. The rest is unchanged, so the unavailable clause follows.

8. **`test/fake-claude.cjs`.**
   - Header comment: add `audit` to the scenario shape and `"disable"` to the acts.
   - Add `role === 'audit'`: `answer(scenario.audit || AUDIT_PASS)` where
     ```js
     const AUDIT_PASS = {
       verdict: 'enforces_invariant',
       trace: [{ step: 'the name is checked against the files already in the public directory', loc: { file: 'src/routes/files.js', line: 9, note: 'allowlist' } }],
       stopped_at: { file: 'src/routes/files.js', line: 9, note: 'unknown names are answered with 400' },
       uncovered_siblings: [], explanation: 'the traversal name is not in the allowlist, so the read never runs',
     };
     ```
   - Add act `disable` in the `fix` branch: replace `'function read(req, res) {'` in `src/routes/files.js` with `"function read(req, res) {\n  res.statusCode = 404; return res.end('not found');"`, keep the sink line, commit like `patch()`, and answer `{ outcome: 'patched', declared_files: ['src/routes/files.js'], enforcement_note: 'every request is refused' }`. Simplest shape: give `patch(step)` a branch on `step.act === 'disable'` for the text transform.

9. **Prose.** No long dashes, no arrows, no two words joined by a slash such as `base/patched` (check-prose `slash-or` rule). Any camelCase name in backticks must exist in `bin/` (validate-skill).
   - `SKILL.md`, "What runs today": say the `dynamic` tier is wired into `run.cjs` behind `--witness=dynamic`; at `full` an `argued` witness records obligations 3 and 4 unavailable with the obstacle, still runs the suite, rescan and auditor, and lands as `fixed_unwitnessed`. Keep "`executable` and `structural` ... unwritten". In "Reference files", replace "It is a planned improvement" with the opt-in wording. Obligation 3 text: add "At `argued`, 3 and 4 are recorded unavailable and excused, and the fix is `fixed_unwitnessed`."
   - `references/FIX-AND-VERIFY.md`: lines 74-77 say `dynamic` runs when the operator passes `--witness=dynamic` and a harness was discovered; line 108 paragraph: at every level argued lands as `fixed_unwitnessed`; at `full` obligations 3 and 4 are recorded unavailable with the obstacle, and the regression suite, rescan and auditor must still pass. Add a line under "Verification order" that for `dynamic`, steps 3 to 5 are the four-step run in `DYNAMIC-WITNESS.md`, answered by `witnessObligations` in `bin/witness-run.cjs`. Add a short "Why `executable` is not built" paragraph with the three reasons from section 3.
   - `references/DYNAMIC-WITNESS.md`: status line says the tier is wired and opt-in via `--witness=dynamic`; `run.cjs` offers it to triage only when a harness was discovered. "Cost containment": today base and patched trees are booted once per attempt and torn down after it; sharing the base instance across a run is not done.
   - `references/TRIAGE.md` line 135: "The strongest tier the repo supports, chosen from the enabled witness tiers listed under Repository facts."
   - `design/FUTURE-IMPROVEMENTS.md` section 1: replace "no flag turns `dynamic` on yet" with the flag and what it does; keep the three open questions. Section 3: add the executable deferral reasons.

## 5. Tests

For each new test, write it, see it fail on the unfixed code (or by the mutation named in section 6), then land the fix.

**`test/selftest.cjs`** (stage and guard sections).

- T1 `'at the argued tier the witness pair may be unavailable, and at no other tier'`:
  ```js
  const pair = { ...allPass, differential_witness: { status: 'unavailable' }, functional_control: { status: 'unavailable' } };
  assert.deepStrictEqual(evaluateVerification(pair, OBLIGATIONS, 'argued'),
    { verified: true, failed: [], unavailable: ['differential_witness', 'functional_control'], missing: [], skipped: [] });
  assert.deepStrictEqual(evaluateVerification(pair, OBLIGATIONS, 'dynamic').failed, ['differential_witness', 'functional_control']);
  assert.deepStrictEqual(evaluateVerification(pair).failed, ['differential_witness', 'functional_control']);
  assert.strictEqual(evaluateVerification({ ...pair, hostile_auditor: { status: 'unavailable' } }, OBLIGATIONS, 'argued').verified, false);
  ```
- T2 `'at full, an argued patch with its pair excused reaches report, and a dynamic one goes back to fix'`:
  ```js
  const withTier = (tier) => ({ ...base, triage: { verdict: 'exploitable', contract: { witness: { tier } } }, gate: { action: 'fix' },
    patches: [{ verification: { ...allPass, differential_witness: { status: 'unavailable' }, functional_control: { status: 'unavailable' } } }] });
  assert.strictEqual(stageOf(withTier('argued'), 'full'), 'report');
  assert.strictEqual(stageOf(withTier('dynamic'), 'full'), 'fix');
  ```
- T3 `'a dynamic witness needs no witness file, because the attack lives in the contract'`: `guardDiff(diff('src/routes/admin.js', [], ['  const x = 1;']), { ...contract, witness: { tier: 'dynamic' } }, { sinkFiles: ['src/routes/admin.js'] })` has no violation with `kind === 'witness_missing'`. The existing executable case at line 265 must still pass.

**`test/run.test.cjs`** (deps seam, no boot).

- T4 `'--witness accepts dynamic and nothing else'`: `R.parseArgs(['--target=/x']).witness === null`; `R.parseArgs(['--target=/x', '--witness=dynamic']).witness === 'dynamic'`; `assert.throws(() => R.parseArgs(['--target=/x', '--witness=executable']), /--witness must be dynamic/)`.
- T5 `'the dynamic tier is offered to triage only when asked for and a harness exists'`: three `triageOnlyRun` calls.
  (a) default opts: every triage prompt (`deps.state.agentCalls`) includes `'enabled witness tiers: argued\n'`;
  (b) `opts: { witness: 'dynamic' }`: every prompt includes `'enabled witness tiers: dynamic, argued'` (the fixture's `package.json` has a `start` script);
  (c) `opts: { witness: 'dynamic', target: copy }` where `copy` is `fs.cpSync(REPO, tmp()/vuln-app)` with `package.json` deleted: prompts include `'enabled witness tiers: argued\n'` and `'app harness: none discovered'`.
- T6 `'at full, an argued fix ends fixed_unwitnessed after one fixer call'`: `const { res, deps } = await fixRun({ verify: 'full' });` (default contract is argued `no_test_harness`, default audit passes, `npm` returns 0). For `f = res.findings.find((x) => x.id === PATH_ID)`:
  - `f.patches.length === 1`;
  - `f.patches[0].verification.differential_witness` deep-equals `{ status: 'unavailable', reason: 'argued_tier:no_test_harness' }`;
  - `f.patches[0].verification.functional_control` deep-equals `{ status: 'unavailable', reason: 'argued_tier_has_no_control' }`;
  - `regression_suite`, `no_new_findings` and `hostile_auditor` each have `status === 'pass'`;
  - `f.disposition` deep-equals `{ state: 'fixed_unwitnessed', branch: \`sast-fix/${R.refSafe(res.runId)}/${PATH_ID}/1\`, verify_level: 'full', skipped_obligations: [], unavailable: ['differential_witness', 'functional_control'], witness_tier: 'argued' }`;
  - fixer calls (`schemaPointer === '#/$defs/fix'`) equal the number of findings with patches (one each).
  Note that `PATH_ID` is declared at `run.test.cjs:717`, after the fix section; place T6 after that declaration or reference the literal `'f_6ed43412e0d9b09d'`.
- T7 `'a dynamic witness without --witness=dynamic is recorded unavailable, not thrown'`: `fixRun({ verify: 'full', witness: { witness: DYNAMIC_WITNESS } })` where `DYNAMIC_WITNESS` is the object from `test/e2e-witness.cjs:56-70` (copy it into run.test.cjs as a constant). `f.patches[0].verification.differential_witness` deep-equals `{ status: 'unavailable', reason: 'dynamic_tier_not_enabled' }`, `f.patches[0].verification.deterministic_guard.status === 'pass'` (no `witness_missing`), `f.disposition.state === 'fix_failed'`.

**`test/pipeline.real.test.cjs`** (real git, real worktrees, fake claude, real app boot).

- Harness changes: add `WITNESS.dynamic` (the e2e witness object, `harness_id: 'npm_start'`). `runScenario` gains `witness = null`; when set, push `` `--witness=${witness}` `` into the `parseArgs` argv. Return also `auditCalls: calls.filter((c) => c.role === 'audit').length`. Add scenarios:
  `fullArgued: memo(() => runScenario('full-argued', { tier: 'argued', verify: 'full', fix: [{ act: 'patch' }] }))`,
  `dynamic: memo(() => runScenario('dynamic', { tier: 'dynamic', verify: 'full', witness: 'dynamic', fix: [{ act: 'patch' }] }))`,
  `dynamicCheat: memo(() => runScenario('dynamic-cheat', { tier: 'dynamic', verify: 'full', witness: 'dynamic', fix: [{ act: 'disable' }] }))`.
- T8 `'at full, an argued fix ends fixed_unwitnessed after one fixer call'`:
  - `s.fixerCalls === 1`, `s.auditCalls === 1`;
  - `s.record.disposition` deep-equals `{ state: 'fixed_unwitnessed', branch: \`sast-fix/run-full-argued/${PATH_ID}/1\`, verify_level: 'full', skipped_obligations: [], unavailable: ['differential_witness', 'functional_control', 'regression_suite'], witness_tier: 'argued' }` (the fixture has no `test/smoke.test.js`, so the suite is red on base; measured on the current `argued` cheap scenario: `regression_suite: {"status":"unavailable","reason":"suite_red_on_base"}`);
  - `s.report` includes ``'verified at `full`: all seven obligations checked'`` and ``'`differential_witness`, `functional_control`, `regression_suite` unavailable and excused, not passed'``, and does not include `'all seven obligations passed'`.
- T9 `'with --witness=dynamic, a fix that stops the attack and keeps the control green ends fixed'`:
  - `s.fixerCalls === 1`, `s.auditCalls === 1`, `s.states[PATH_ID] === 'fixed'`;
  - `s.record.disposition.witness_tier === 'dynamic'`, `s.record.disposition.unavailable` deep-equals `['regression_suite']`;
  - `v = s.record.patches[0].verification`: `v.differential_witness.status === 'pass'`, `v.functional_control.status === 'pass'`, `v.deterministic_guard.status === 'pass'`;
  - `v.differential_witness.transcript.map((x) => \`${x.label}:${x.tree}\`)` deep-equals `['control:base', 'attack:base', 'attack:head', 'control:head']`.
- T10 `'with --witness=dynamic, a fix that disables the endpoint passes the differential and fails the control'`:
  - `s.fixerCalls === 2`, `s.states[PATH_ID] === 'fix_failed'`;
  - `s.record.patches[0].verification.differential_witness.status === 'pass'`;
  - `s.record.patches[0].verification.functional_control` has `status: 'fail'` and `reason: 'control_failed_on_patched_tree'`;
  - `s.record.disposition.failed` deep-equals `['functional_control']`.

Ten new cases: 3 selftest, 4 run.test, 3 pipeline.real. `test/e2e-witness.cjs` stays as is and must keep passing.

## 6. Verification

From `/home/asiimov/Projects/code-scanning/skills/sast-remediate`:

1. `sh test/run-all.sh` ends with `all green`. Each suite prints `N passed, 0 failed`.
2. `wc -l bin/run.cjs` prints a number below 1000.
3. `timeout 180 node test/pipeline.real.test.cjs; echo "exit=$?"` prints `exit=0`. An exit of 124 means a booted app was not torn down (the detached child keeps the event loop alive).
4. After step 3, `ss -ltnp 2>/dev/null | grep -c 'node'` shows no listener left over from the fixture app (compare against a count taken before the run).

Mutation checks. Apply each alone, run the named suite, confirm the named test fails, then revert.

| mutation | suite | must fail |
|---|---|---|
| `excused`: drop the `tier === 'argued'` clause | selftest, run.test, pipeline.real | T1, T2, T6, T8 |
| `stageOf`: stop passing the tier | selftest, pipeline.real | T2, T8 (`fixerCalls` 2) |
| `verifyPatch`: restore `stopped = v.differential_witness.status !== 'pass'` | run.test | T6 (missing obligations, `fix_failed`) |
| `run()`: hard-code `witnessTiers: ['argued']` | run.test | T5 (b) |
| `parseArgs`: drop the `--witness` validation | run.test | T4 |
| `runDifferentialWitness`: pass `allowDynamic: false` | pipeline.real | T9 (`dynamic_tier_not_enabled`) |
| `witnessObligations`: return `functional_control: { status: 'pass' }` unconditionally | pipeline.real | T10 |
| `witnessObligations`: delete the `finally` teardown | pipeline.real | step 3 times out (`exit=124`) |
| `patch-guard.cjs`: restore `tier !== 'argued'` | selftest, pipeline.real | T3, T9 (`witness_missing`) |
| `verificationSummary`: restore the unconditional "passed" | pipeline.real | T8 |

## 7. Risks and out of scope

**Top risk: the dynamic cases add real app boots to the suite.** T9 and T10 boot the fixture app four and six times (base and patched per attempt). Each boot waits on `/healthz`, measured under a second in `e2e-witness.cjs`, but a slow machine or a port race between `freePort()` and `boot()` could flake. `boot` has a 30 s readiness timeout and a 120 s kill guard, so a failure shows as `base_did_not_boot` or `patched_tree_did_not_boot` rather than a hang, as long as the `finally` teardown is in place.

Other risks:

- `boot` writes `.scratch-home` and `.scratch-tmp` into the tree it starts in. For the patched worktree that happens after the harness commit, so the branch is unaffected, but a real rescan of that worktree will walk two extra, mostly empty directories. The base worktree is shared with the regression suite.
- A triage agent can still return a tier that was not offered (for example `executable`). At full that records `tier_not_implemented:executable` and fails after two fixer calls. The TRIAGE.md wording change lowers the odds; a hard check at triage (defer with `witness_tier_not_offered`) is a follow-up.
- An `unavailable` witness that is not excused (a dynamic base that will not boot) still spends a second fixer call that cannot help. Making environment failures final is a follow-up.
- `opts.witness` is not written to `run-metadata.json`. A resumed run started with `--witness=dynamic` and resumed without it records `dynamic_tier_not_enabled`. Recording it next to `verify_level` is a follow-up.

Out of scope: the `executable` and `structural` tiers (see section 3), automatic tier selection, sharing one base app instance across a run, fixture-state reset between the four exchanges, `row_appears`, the integration branch.

**Symbols touched, for sequencing with other units.** `bin/run.cjs`: `USAGE`, `parseArgs`, `buildTriagePrompt` (harness line only), `fixOne` (one `evaluateVerification` call), `verifyPatch`, `runDifferentialWitness`, `dispositionFor`, `run` (the `appHarness` and `witnessTiers` lines), the `stage.cjs` import line. `bin/stage.cjs`: `evaluateVerification`, `stageOf`, new `excused` and `EXCUSED_AT_ARGUED`, exports. `bin/witness-run.cjs`: new `witnessObligations`, `freePort`, exports. `bin/patch-guard.cjs`: the `witness_missing` condition. `bin/report.cjs`: `verificationSummary`. `test/fake-claude.cjs`, `test/selftest.cjs`, `test/run.test.cjs`, `test/pipeline.real.test.cjs`. Prose: `SKILL.md`, `references/FIX-AND-VERIFY.md`, `references/DYNAMIC-WITNESS.md`, `references/TRIAGE.md`, `design/FUTURE-IMPROVEMENTS.md`.
