# R3: the rescan uses the same scanner rules as the baseline

## 1. Plain-language summary

After the tool patches a finding, it scans the patched copy again and fails the fix if a rule fires in a file where the original scan never saw that rule fire.
Today that second scan always uses Semgrep's `p/default` rules and CodeQL's `security-extended` queries, whatever rules produced the original scan.
When the operator hands in a scan made with other rules (the mkcert scan was made with `p/trailofbits`), every hit in the second scan comes from a rule the first scan never ran, so it looks new, and every fix fails.
This unit adds two flags, `--semgrep-config` and `--codeql-suite`, used for both scans, saved in `run-metadata.json` so a resumed run scans the same way, and printed in the report.
It also confirms, with a test, that the second scan's absolute file paths are matched to the first scan's relative ones.

## 2. Problem, with evidence

All line numbers are in `skills/sast-assist/` and were checked against the current tree.

- `bin/scan.cjs:51` hard-codes Semgrep's rules: `deps.exec('semgrep', ['scan', '--config', 'p/default', ...])`.
- `bin/scan.cjs:63` hard-codes CodeQL's suite: `` `codeql/${lang}-queries:codeql-suites/${lang}-security-extended.qls` ``.
- `bin/scan.cjs:83` makes the rescan call the same `runScanners` with only `{ scans: null, scanners: baseline.scanners }`, so it always gets the hard-coded rules above.
- `bin/scan.cjs:74` and `:78` build the baseline as the set of `rule_id + file` pairs. `bin/scan.cjs:90` counts a rescan result as new when any of its pairs is missing from that set. A rule id the baseline scan never ran can never be in the set.
- `bin/run.cjs:43` and `:70` accept `--scans=DIR`, which reuses a scan made outside the tool. Nothing records which rules that scan ran.
- `bin/run.cjs:756` and `:827` persist only `verify_level` in `run-metadata.json` at start. A resumed run has no record of how the baseline was scanned.
- On disk, `.work/targets/scans-mkcert/semgrep.json` holds one result, rule `trailofbits.go.unsafe-dll-loading.unsafe-dll-loading` on `truststore_windows.go` (measured). `p/default` rule ids are named like `go.lang...` and `javascript.lang...` (measured on `.work/targets/run-postfix/scans/*/semgrep.json`), so none of them can match that baseline.
- The mkcert failure is predicted from the code, not observed. In `.work/targets/run-mkcert` and `run-mkcert2` the one finding was `rejected` at triage, so no rescan ran (measured from `findings/*.json`).

Path handling, checked because the scope asked.

- A reused Semgrep scan run from inside the target has relative paths (`truststore_windows.go`, measured). The rescan passes the absolute worktree path, so its results carry absolute paths, for example `.../run-postfix/worktrees/f_6ed43412e0d9b09d-1/src/app.js` (measured).
- `bin/normalize.cjs:249` `toRepoRelative` resolves both forms against the scanned root and returns a repo-relative path. `normalize(raw, makeRepo(worktree), ...)` at `bin/scan.cjs:89` roots the rescan at the worktree, so both forms become `src/app.js`.
- Live evidence it works: in `.work/targets/run-postfix`, the baseline had `using-http-server` on relative `src/app.js`, and all three rescans reported it on the absolute path, yet none counted it new. The only `rescan_new` there was `js/file-system-race` in `src/routes/files.js`, a CodeQL rule the baseline fixture never reported, which the patch introduced (measured).
- Unit coverage exists at `test/selftest.cjs:488` and `:500`. No pipeline test drives an absolute rescan path through `rescan()`. This unit adds one.

## 3. Design

### Data shape

One object, named `ScanConfig`, passed and stored verbatim.

```js
// opts.scanConfig, ctx.baseline.scanConfig, meta.scan_config in run-metadata.json
{ semgrep: ['p/default'],            // non-empty array of strings, each passed as one `--config`
  codeql_suite: 'security-extended' } // matches /^[a-z0-9][a-z0-9-]*$/, expanded to <lang>-<suite>.qls
```

A Semgrep config entry that names an existing local file or directory is stored as its absolute path, so a resume from a different working directory scans with the same rules. Anything else (`p/...`, `r/...`, a URL) is stored as typed.

### Behaviour

1. `parseArgs` builds `opts.scanConfig` from `--semgrep-config` (repeatable, each value also split on commas) and `--codeql-suite`. Defaults are `['p/default']` and `security-extended`, today's hard-coded values, so a run with no new flags behaves exactly as before.
2. `runScanners` reads Semgrep configs and the CodeQL suite from `opts.scanConfig`. Each scanner entry it actually runs carries `config`, which `describeScanners` in `bin/report.cjs:170` already prints. Reused entries carry no `config`, because the tool does not know it.
3. `baselineOf` stores the config on the baseline. `rescan` passes `baseline.scanConfig` to `runScanners`. The baseline is the one channel the rescan already reads, so no new field is threaded through `ctx`.
4. `run` reads `scan_config` from an existing `run-metadata.json`. A valid recorded config wins over the flags, with a log line, exactly as `verify_level` does today. When the file lacks either `verify_level` or a valid `scan_config` (a fresh run, or a run started before this change), `run` writes both before scanning.
5. The final `meta` carries `scan_config`. `renderRemediation` prints a `Rescan configuration` line under `Scanners`, and, when any scanner was `reused`, one sentence saying the rescan config must match the rules the reused scan ran.
6. `planLines` (dry run) prints a `scan config` line.

### Rejected alternatives

- Prefix sanity check of reused rule ids against the pack name. Rejected because it gives false warnings on the default path: `p/trailofbits` ids start with `trailofbits.`, but `p/default` ids start with `javascript.`, `go.`, `problem-based-packs.` and so on.
- Rescanning base with the configured rules to build the delta baseline. Rejected for this unit because `--scans` exists to skip scanning, and a CodeQL database build costs minutes. It is the root-cause fix if config drift keeps biting, so it goes in `design/FUTURE-IMPROVEMENTS.md`.
- Reading the rules out of the reused scan file. Rejected because Semgrep's JSON does not record which config produced it.
- A free-form `--codeql-suite` query spec. Rejected because the spec is language-specific and the tool picks the language. A suite name covers `security-extended`, `security-and-quality` and `code-scanning`.

## 4. Steps

Touched symbols, for sequencing: `bin/scan.cjs` `runScanners`, `baselineOf`, `rescan`, new `DEFAULT_SCAN_CONFIG`, `SUITE_NAME`, `semgrepConfigArg`, `parseScanConfig`. `bin/run.cjs` `USAGE`, `parseArgs`, `recordedLevel` (renamed `readRecorded`), `planLines`, `run`, the `require('./scan.cjs')` line. `bin/report.cjs` `renderRemediation`. Test helpers `makeDeps` and `fixRun` in `test/run.test.cjs`. `bin/run.cjs` grows by about 20 lines, from 936 to about 956.

1. `bin/scan.cjs`, top of file after `trim`. Add these and export all four.

   ```js
   const DEFAULT_SCAN_CONFIG = Object.freeze({ semgrep: ['p/default'], codeql_suite: 'security-extended' });
   const SUITE_NAME = /^[a-z0-9][a-z0-9-]*$/;
   // A local rules file is stored absolute so a resume from another directory scans identically.
   const semgrepConfigArg = (c) => (fs.existsSync(c) ? path.resolve(c) : c);

   // run-metadata.json is read back on resume, so its scan_config is parsed, not trusted.
   function parseScanConfig(x) {
     if (!x || !Array.isArray(x.semgrep) || !x.semgrep.length) return null;
     if (!x.semgrep.every((c) => typeof c === 'string' && c)) return null;
     if (typeof x.codeql_suite !== 'string' || !SUITE_NAME.test(x.codeql_suite)) return null;
     return { semgrep: [...x.semgrep], codeql_suite: x.codeql_suite };
   }
   ```

2. `bin/scan.cjs` `runScanners`. Add `const cfg = opts.scanConfig;` after `const scanners = [];`.
   - Line 51 becomes `deps.exec('semgrep', ['scan', ...cfg.semgrep.flatMap((c) => ['--config', c]), `--json-output=${out}`, target])`. The target must stay the last argument, because `test/pipeline.real.test.cjs:118` reads it from there.
   - Line 63 becomes `` `codeql/${lang}-queries:codeql-suites/${lang}-${cfg.codeql_suite}.qls` ``.
   - Every `scanners.push` inside the Semgrep branch that runs after the `present(name)` check gets `config: cfg.semgrep.join(' ')`. Every `scanners.push` in the CodeQL branch after that check gets `config: cfg.codeql_suite`. The `absent` push and the `--scans` branch pushes stay unchanged.

3. `bin/scan.cjs` `baselineOf(raw, findings, scanConfig)` returns `{ scanners: Object.keys(raw), ruleFiles: ..., scanConfig }`.

4. `bin/scan.cjs` `rescan`, line 83: `runScanners({ scans: null, scanners: baseline.scanners, scanConfig: baseline.scanConfig }, deps, worktree, scanDir)`.

5. `bin/run.cjs` line 26: also import `DEFAULT_SCAN_CONFIG, SUITE_NAME, semgrepConfigArg, parseScanConfig`.

6. `bin/run.cjs` `USAGE`, after the `--scans=DIR` line, add

   ```
     --semgrep-config=C  Semgrep --config for the scan and every rescan, repeatable or
                         comma separated (default p/default)
     --codeql-suite=S    CodeQL suite name for the scan and every rescan (default security-extended)
   ```

   and change the `--scans=DIR` line to `reuse existing scanner output; pass the rules it was made with`.

7. `bin/run.cjs` `parseArgs`.
   - Initial opts gains `scanConfig: { semgrep: [], codeql_suite: DEFAULT_SCAN_CONFIG.codeql_suite }`.
   - New case:
     ```js
     case 'semgrep-config': {
       const items = val === true ? [] : String(val).split(',').map((s) => s.trim()).filter(Boolean);
       if (!items.length) throw new UsageError('--semgrep-config needs a value');
       opts.scanConfig.semgrep.push(...items.map(semgrepConfigArg));
       break;
     }
     case 'codeql-suite': opts.scanConfig.codeql_suite = String(val); break;
     ```
   - After the loop, before the existing checks:
     ```js
     if (!opts.scanConfig.semgrep.length) opts.scanConfig.semgrep = [...DEFAULT_SCAN_CONFIG.semgrep];
     if (!SUITE_NAME.test(opts.scanConfig.codeql_suite)) {
       throw new UsageError('--codeql-suite must be a suite name such as security-extended');
     }
     ```

8. `bin/run.cjs` replace `recordedLevel` (line 756) with

   ```js
   function readRecorded(metaFile) {
     let m = null;
     try { m = readJson(metaFile); } catch { /* a fresh run */ }
     m = m || {};
     return {
       level: Object.hasOwn(VERIFY_LEVELS, m.verify_level) ? m.verify_level : null,
       scanConfig: parseScanConfig(m.scan_config),
     };
   }
   ```

9. `bin/run.cjs` `run`, lines 821 to 827, become

   ```js
   const recorded = readRecorded(metaFile);
   if (recorded.level && recorded.level !== opts.verify) {
     deps.log(`${outDir} was started at --verify=${recorded.level}; resuming at that level`);
     opts = { ...opts, verify: recorded.level };
   }
   // The rescan is only comparable to the baseline when both ran the same rules.
   if (recorded.scanConfig && JSON.stringify(recorded.scanConfig) !== JSON.stringify(opts.scanConfig)) {
     deps.log(`${outDir} was started with scanner config ${JSON.stringify(recorded.scanConfig)}; resuming with it`);
     opts = { ...opts, scanConfig: recorded.scanConfig };
   }
   if (!recorded.level || !recorded.scanConfig) {
     writeJson(metaFile, { run_id: runId, verify_level: opts.verify, scan_config: opts.scanConfig });
   }
   ```

   Keep the existing comment above `metaFile`.

10. `bin/run.cjs` `run`, line 852: `baseline: baselineOf(raw, findings, opts.scanConfig),`.

11. `bin/run.cjs` `run`, the `meta` object: add `scan_config: opts.scanConfig,` directly after `skipped_obligations`.

12. `bin/run.cjs` `planLines`: after the `scanners` line add
    `` `scan config   semgrep ${opts.scanConfig.semgrep.join(' ')}; codeql ${opts.scanConfig.codeql_suite}`, ``.

13. `bin/report.cjs` `renderRemediation`, after the `- Scanners:` line (204):

    ```js
    if (meta.scan_config) {
      L.push(`- Rescan configuration: semgrep ${code(meta.scan_config.semgrep.join(' '))}, `
        + `CodeQL suite ${code(meta.scan_config.codeql_suite)}`);
      if ((meta.scanners || []).some((s) => s.status === 'reused')) {
        L.push('- Reused scans were made outside this run. Rescans ran the configuration above, so '
          + 'a rule it runs that the reused scan did not is counted as introduced by the patch.');
      }
    }
    ```

14. Prose, so it matches the code.
    - `SKILL.md`, section `## Setup`, add a bullet after `Policy`: `- **Scanner configuration.** `--semgrep-config` (default `p/default`) and `--codeql-suite` (default `security-extended`). The baseline scan and every rescan use it, and `run-metadata.json` records it, so a resumed run rescans with the same rules. With `--scans`, pass the rules those scans were made with, or every rescan hit counts as new.`
    - `references/INGEST.md`, the Semgrep block: replace `--config p/default` with `--config <each --semgrep-config value, default p/default>`. The CodeQL block: replace `<lang>-security-extended.qls` with `<lang>-<--codeql-suite, default security-extended>.qls`. Add one sentence below the blocks: `The rescan in bin/scan.cjs runs these same commands with the run's recorded configuration.`
    - `references/FIX-AND-VERIFY.md` step 7 (line 157): after `and no others` add `, with the run's recorded scanner configuration`.
    - `references/REPORT.md` line 10: after `scanners and rule packs` add `(the rescan configuration, and a warning when a reused scan's rules may differ from it)`.
    - `design/FUTURE-IMPROVEMENTS.md`: add an entry `Rescan delta against a same-rules scan of base`. Two sentences: with `--scans`, the delta baseline comes from a scan whose rules the tool cannot see. Scanning base once with the configured rules and diffing against that would remove the operator's burden, at the cost of the scan `--scans` skips.
    - Run `node tools/check-prose.cjs` from the repo root after editing. It bans long dashes, arrows, `(s)` plurals and `word/word` pairs.

15. Tests, per section 5. `test/run.test.cjs` helpers.
    - `makeDeps`: in the `semgrep` branch of `exec`, write `typeof state.rescan === 'function' ? state.rescan(args[args.length - 1]) : state.rescan`.
    - `fixRun`: `const opts = baseOpts({ argv: over.argv });`. After the existing `recordedLevel` block add `if (over.recordedMeta) { fs.mkdirSync(out, { recursive: true }); fs.writeFileSync(path.join(out, 'run-metadata.json'), JSON.stringify(over.recordedMeta)); }`.

## 5. Tests

All in `skills/sast-assist/test/run.test.cjs`. Helpers `tmp`, `baseOpts`, `makeDeps`, `fixRun`, `pathHit`, `movingFix`, `PATH_ID`, `REPO`, `notExploitable`, `renderRemediation` already exist. `semgrepCalls` below means `deps.state.execCalls.filter((c) => c.startsWith('semgrep '))`.

Section `cli`.

1. Extend `defaults match the documented ones` with
   `assert.deepStrictEqual(o.scanConfig, { semgrep: ['p/default'], codeql_suite: 'security-extended' });`.
2. New `--semgrep-config is repeatable and comma separated, and a local rules file is stored absolute`.
   Setup: `const dir = tmp(); const rules = path.join(dir, 'rules.yml'); fs.writeFileSync(rules, 'rules: []\n');`.
   Call `R.parseArgs(['--target=/x', '--semgrep-config=p/trailofbits', `--semgrep-config=p/golang,${path.relative(process.cwd(), rules)}`, '--codeql-suite=security-and-quality'])`.
   Expect `o.scanConfig` deep-equals `{ semgrep: ['p/trailofbits', 'p/golang', rules], codeql_suite: 'security-and-quality' }`.
3. New `an empty --semgrep-config or a --codeql-suite that is not a suite name is refused`.
   `assert.throws(() => R.parseArgs(['--target=/x', '--semgrep-config=']), /--semgrep-config needs a value/)`,
   `assert.throws(() => R.parseArgs(['--target=/x', '--semgrep-config']), /--semgrep-config needs a value/)`,
   `assert.throws(() => R.parseArgs(['--target=/x', '--codeql-suite=../x.qls']), /--codeql-suite must be/)`.
4. Extend `--dry-run prints the plan...` with `assert.ok(text.includes('scan config   semgrep p/default; codeql security-extended'), text);`.

Section `fix and verify`.

5. New `the baseline scan runs the configured semgrep rules and CodeQL suite`.
   Setup: `const opts = R.parseArgs([`--target=${REPO}`, `--out=${path.join(tmp(), 'run-1')}`, '--semgrep-config=p/trailofbits', '--codeql-suite=security-and-quality', '--triage-only']);`
   `const deps = makeDeps({ rescan: { results: [pathHit(null, 9)], errors: [] }, agents: { '#/$defs/triage': () => ({ ok: true, data: notExploitable() }) } });`
   `const res = await R.run(opts, deps);`
   Expect `semgrepCalls.length === 1` and `semgrepCalls[0].startsWith('semgrep scan --config p/trailofbits --json-output=')`.
   Expect one exec call that includes `'codeql/javascript-queries:codeql-suites/javascript-security-and-quality.qls'`.
   Expect `res.meta.scanners.find((s) => s.name === 'semgrep')` to have `status: 'ok'` and `config: 'p/trailofbits'`.
   Note: the fake `codeql analyze` writes no SARIF, so CodeQL records `failed`. That is fine. `fixtures/vuln-app` has `package.json`, so the language is `javascript`.
6. New `the rescan runs the run's semgrep rules, not p/default`.
   `const { res, deps } = await fixRun({ argv: ['--semgrep-config=p/trailofbits'] });`
   Expect every `semgrepCalls` entry to include `--config p/trailofbits` and none to include `p/default`, and `semgrepCalls.length >= 1`.
   Expect `res.findings.find((x) => x.id === PATH_ID).patches[0].verification.rescan.scanners[0].config === 'p/trailofbits'`.
7. New `a fresh run records its scanner config before any fixer runs`.
   Copy the shape of `a fresh run records its verify level before any fixer runs`, with `argv: ['--semgrep-config=p/trailofbits']`, reading `scan_config` in the fix handler.
   Expect `{ semgrep: ['p/trailofbits'], codeql_suite: 'security-extended' }`.
8. New `a resumed run rescans with the scanner config it was started with`.
   `fixRun({ recordedMeta: { verify_level: 'cheap', scan_config: { semgrep: ['p/trailofbits'], codeql_suite: 'security-extended' } } })`, no `argv`.
   Expect `res.meta.scan_config` deep-equals the recorded object, and every `semgrepCalls` entry includes `--config p/trailofbits`.
9. New `a run started before scan_config existed adopts the flags and records them`.
   `fixRun({ recordedLevel: 'cheap', argv: ['--semgrep-config=p/golang'] })`.
   Expect `readJson(path.join(out, 'run-metadata.json')).scan_config` deep-equals `{ semgrep: ['p/golang'], codeql_suite: 'security-extended' }` and every `semgrepCalls` entry includes `--config p/golang`.
10. New `a malformed recorded scan_config is ignored, not trusted`.
    `fixRun({ recordedMeta: { verify_level: 'cheap', scan_config: { semgrep: 'p/x', codeql_suite: 'security-extended' } } })`.
    Expect `res.meta.scan_config` deep-equals `{ semgrep: ['p/default'], codeql_suite: 'security-extended' }`.
11. New `a rescan that reports absolute worktree paths matches the baseline's relative ones`.
    `fixRun({ fix: movingFix, rescan: (target) => ({ results: [{ ...pathHit(null, 11), path: path.join(target, 'src/routes/files.js') }], errors: [] }) })`.
    Expect `v.no_new_findings` deep-equals `{ status: 'pass' }`, `v.rescan.new_findings` deep-equals `[]` and `v.rescan.original_absent === false`, where `v` is the first patch's `verification` of `PATH_ID`.
12. New `the report names the rescan configuration and warns that a reused scan must match it`.
    `const { res } = await fixRun({ argv: ['--semgrep-config=p/trailofbits'] });` (fixRun reuses `test/fixtures` via `--scans`).
    `const report = renderRemediation(res.findings, res.meta);`
    Expect `report.includes('- Rescan configuration: semgrep `p/trailofbits`, CodeQL suite `security-extended`')` and `report.includes('- Reused scans were made outside this run.')`.

That is 9 new cases and 2 extended ones.

## 6. Verification

1. `cd skills/sast-assist && sh test/run-all.sh`. Pass means it ends with `all green`.
2. `wc -l skills/sast-assist/bin/run.cjs` prints under 1000.
3. Mutation checks. Apply each, run `node test/run.test.cjs`, confirm the named case fails, then revert.
   - `bin/scan.cjs` rescan: drop `scanConfig: baseline.scanConfig` and set `scanConfig: DEFAULT_SCAN_CONFIG`. Cases 6, 8 and 9 fail.
   - `bin/scan.cjs` runScanners: put back the literal `'--config', 'p/default'`. Cases 5 and 6 fail.
   - `bin/scan.cjs` runScanners: put back the literal `security-extended.qls`. Case 5 fails.
   - `bin/run.cjs` run: delete the `if (recorded.scanConfig && ...)` block. Case 8 fails.
   - `bin/run.cjs` run: change the write condition back to `if (!recorded.level)`. Case 9 fails.
   - `bin/scan.cjs` parseScanConfig: return `x` unparsed. Case 10 fails.
   - `bin/normalize.cjs` toRepoRelative: return `String(file)` first thing. Case 11 fails (the selftest cases at `:488` and `:500` fail too).
   - `bin/report.cjs`: delete the pushed lines. Case 12 fails.
   - `bin/run.cjs` parseArgs: drop `.map(semgrepConfigArg)`. Case 2 fails.
4. Dry run on the real mkcert target, no agent call.
   `cd skills/sast-assist && node bin/run.cjs --target=../../.work/targets/mkcert --scans=../../.work/targets/scans-mkcert --scanners=semgrep --semgrep-config=p/trailofbits --dry-run`.
   Pass means the output has `scan config   semgrep p/trailofbits; codeql security-extended`.
5. Real scanner probe, no agent call. It needs the Semgrep registry. If the fetch fails, record the error and skip this step.
   ```sh
   cd skills/sast-assist && node -e '
   const { runScanners } = require("./bin/scan.cjs");
   const { spawnSync } = require("child_process");
   const exec = (c, a) => { const r = spawnSync(c, a, { encoding: "utf8", maxBuffer: 1 << 26 }); return { status: r.status, stdout: r.stdout, stderr: r.stderr }; };
   const t = require("path").resolve("../../.work/targets/mkcert");
   const r = runScanners({ scans: null, scanners: ["semgrep"], scanConfig: { semgrep: ["p/trailofbits"], codeql_suite: "security-extended" } }, { exec }, t, "/tmp/r3-probe");
   console.log(r.scanners, [...new Set(r.raw.semgrep.results.map((x) => x.check_id))]);'
   ```
   Pass means `status: 'ok'`, `config: 'p/trailofbits'`, and the rule list includes `trailofbits.go.unsafe-dll-loading.unsafe-dll-loading`, the rule in the reused baseline.
6. Never call the real `claude` CLI and never use the fable model.

## 7. Risks and out of scope

- Top risk: the operator still has to know which rules a reused scan ran. The flag makes a match possible and the report states the rescan rules, but nothing detects a mismatch. The base-rescan alternative in section 3 is the real fix and is recorded in `design/FUTURE-IMPROVEMENTS.md`, not built.
- A recorded `scan_config` beats the flags on resume. An operator who resumes with a new `--semgrep-config` gets the old one and a log line. This mirrors `verify_level` and is deliberate.
- `semgrepConfigArg` treats any existing path as a file. A registry id such as `p/default` would only be misread if a directory named `p/default` exists under the working directory.
- A registry pack changes over time. Two scans a week apart with `p/default` can differ. Out of scope.
- `--scans` itself is not persisted, so a resume without `--scans` rescans base with the tool. Out of scope; it predates this unit.
- `AGENTS.md` line 17 cites `bin/run.cjs:194` as the place `p/default` is hard-coded. That is stale after this unit. The orchestrator owns `AGENTS.md`, so the executor leaves it.
- Other units edit `bin/run.cjs`. This unit touches `USAGE`, `parseArgs`, `recordedLevel` (renamed), `planLines`, `run` (the metadata block, `ctx.baseline`, `meta`) and the `scan.cjs` import.
