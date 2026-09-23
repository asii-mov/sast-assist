# R2: close the fixer's escape hatches

## 1. Plain-language summary

The tool's main safety rule is that the AI writing the fix is never told which scanner rule it is
fixing, so it cannot cheat by just making the rule go quiet. The prompt obeys that rule, but the
fixer can still go and look. It is handed a shell, and its working folder sits two folders away
from the run's saved findings, which name the rule. This unit takes the shell away, moves the
fixer's working folder out of the run folder, and tells the `claude` command to keep every agent's
file tools inside its own working folder and to refuse any tool it was not explicitly given.
Tests pin the exact command line and the folder location, and one small real call with the
cheapest model proves the `claude` command actually behaves the way its help text says.

## 2. Problem, with evidence

All line numbers verified against the current tree (same as `.work/snapshots/after-U4-final/`).

1. **The fixer has a shell.** `skills/sast-remediate/bin/run.cjs:442` is
   `const FIX_TOOLS = ['Read', 'Grep', 'Glob', 'Edit', 'Write', 'Bash'];` and `run.cjs:487-490`
   passes it as `allowedTools` to the fix call. `semgrep` and `codeql` are on PATH
   (`~/.local/bin`, AGENTS.md), so the fixer can run the scanner, and `cat` anything it can find.
2. **The fixer's cwd is next to the rule.** `run.cjs:461` puts the worktree at
   `path.join(ctx.outDir, 'worktrees', `${f.id}-${attempt}`)` and `run.cjs:606` puts the base tree
   at `outDir/worktrees/base`. `outDir/findings/<id>.json` (written by `makeSaver`, `run.cjs:763`)
   and `outDir/scans/` sit two levels up. On disk:
   `.work/targets/run-full/worktrees/f_6ed43412e0d9b09d-1/` exists, and
   `.work/targets/run-full/findings/f_6ed43412e0d9b09d.json` has
   `sites[0].observations[0].rule_id == "js/path-injection"` and message
   `"This path depends on a [user-provided value](1)."`. So `Read ../../findings/f_6ed43412e0d9b09d.json`
   from the fixer's cwd returns the rule id. `Read`, `Grep` and `Glob` accept absolute paths too,
   so dropping `Bash` alone does not close this.
3. **`--allowed-tools` is not an allowlist.** `bin/agent.cjs:25-30` (`argvFor`) emits only
   `--allowed-tools`. `claude --help` (2.1.280) describes it as "tool names to allow", a
   pre-approval list. The tool set itself is chosen by a different flag, `--tools <tools...>`
   ("Specify the list of available tools from the built-in set"). Without `--tools`, every
   built-in tool (Bash, WebFetch, Agent, Skill and the rest) stays available, and whether an
   unlisted one runs is decided by the permission mode. The U4 probe
   (`.work/probe/isolation.txt`, and `references/FIX-AND-VERIFY.md:60-63`) recorded the session's
   permission mode as `auto`, where a classifier approves tool uses, and U4 left "whether an agent
   can reach a plugin skill or an MCP tool outside `--allowed-tools`" unmeasured. Inferred from help
   text: under `auto`, Bash is reachable by every agent today, including triage (cwd is the
   operator's target) and the auditor.
4. **MCP servers load.** The U4 probe measured `init.mcp_servers: 68` under the isolation flags.
   `--tools` only filters built-in tools (help text), so MCP tools stay reachable without
   `--strict-mcp-config`.
5. **Nothing keeps file tools in the cwd.** `claude --help` documents `--restricted`: it "removes
   the built-in tools that run commands or code (Bash, PowerShell, REPL ...) and WebFetch unless
   --tools names them, and ignores user, project and local settings files (managed settings and
   --settings still apply ...). Also confines the file tools to the working directories". No flag
   in `argvFor` uses it.

What the fixer needs. `buildFixPrompt` (`run.cjs:373-414`) asks for an edit and a JSON answer
listing `declared_files`. The harness itself commits (`collectDiff`, `verifyPatch` at
`run.cjs:540-596`), runs the test suite (`runRegressionSuite`, `run.cjs:620-629`), the control
(`runFunctionalControl`) and the rescan. `references/FIX-AND-VERIFY.md:43-48` says the fixer does
not commit. The only thing a shell buys the fixer is running tests to check itself, and the
harness does that after it returns. A shell narrowed to the test command (`Bash(npm test:*)`) is
no boundary, because the fixer can Edit the `package.json` script that command runs.

## 3. Design

### Data shape

The only new data is one argv block, one option key and one path.

```js
// bin/agent.cjs
const ISOLATION = ['--setting-sources', 'user', '--settings', '{"disableAllHooks":true}']; // unchanged
const CONFINEMENT = ['--restricted', '--strict-mcp-config', '--permission-mode', 'dontAsk'];

// runAgent opts: `tools` replaces `allowedTools` and is required (non-empty array of names).
// argvFor({ prompt: 'hello', model: 'opus', tools: ['Read', 'Grep'] }) returns exactly:
[
  '-p', 'hello', '--output-format', 'json',
  '--setting-sources', 'user', '--settings', '{"disableAllHooks":true}',
  '--restricted', '--strict-mcp-config', '--permission-mode', 'dontAsk',
  '--tools', 'Read,Grep',
  '--model', 'opus',
  '--allowed-tools', 'Read', 'Grep',
]
```

One list per role drives both flags. `--tools` decides what exists, `--allowed-tools` pre-approves
exactly the same names, and `--permission-mode dontAsk` denies anything else instead of asking a
classifier. `--tools` gets one comma-joined argument so it cannot swallow later arguments;
`--allowed-tools` stays last because it is variadic.

Role tool lists in `bin/run.cjs`:

| role | constant | tools |
|---|---|---|
| triage | `TRIAGE_TOOLS` | `['Read', 'Grep', 'Glob']` (unchanged) |
| fix | `FIX_TOOLS` | `['Read', 'Grep', 'Glob', 'Edit', 'Write']` (Bash removed) |
| audit | `AUDIT_TOOLS` | `['Read', 'Grep', 'Glob']` (unchanged) |

Worktree root, a new pure function in `bin/run.cjs`, stored on `ctx.worktreeRoot`:

```js
const cacheHome = () => process.env.XDG_CACHE_HOME || path.join(os.homedir(), '.cache');
const worktreeRootFor = (outDir) =>
  path.join(cacheHome(), 'sast-remediate', 'worktrees', sha256(path.resolve(outDir)).slice(0, 16));
```

Fix worktrees become `<worktreeRoot>/<id>-<attempt>` and the base tree `<worktreeRoot>/base`.
Branch names do not change. `patch.worktree` still records the absolute path.

### Behaviour

- Every agent call (triage, fix, audit) gets `CONFINEMENT` and a `--tools` list. No role has a
  shell, a web tool, a subagent tool, a skill tool or an MCP server. File tools are held to the
  agent's cwd by `--restricted`.
- `runAgent` throws `runAgent needs tools: without --tools the CLI default set includes a shell`
  when `opts.tools` is missing or empty, before any exec. That is the boundary; `argvFor` trusts it.
- The fixer's cwd is outside `outDir`, so no relative path reaches `findings/` or `scans/`. The
  root is derived from `outDir`, so a resumed run lands in the same root and reuses `base`.
  `XDG_CACHE_HOME` (default `~/.cache`) instead of `os.tmpdir()`: a fixed name under a shared
  `/tmp` can be pre-created by another user, and `/tmp` is wiped on reboot, which would strand the
  worktree paths the handoff names.
- The fix prompt tells the fixer it has no shell, so it does not spend turns looking for one.
- `--dry-run` prints the worktree root as a plan line.
- Consequence to document: `--restricted` ignores user settings files, so the operator's
  `model` and `effortLevel` from `~/.claude/settings.json` no longer apply to agent calls.
  `--model` on `run.cjs` still does. The probe in Step 1 records `init.model` to show this.

### Rejected alternatives

- Keep Bash with pattern rules like `Bash(npm test:*)`: the fixer can edit the script the pattern
  runs, so it is arbitrary execution.
- Move worktrees only: absolute paths through `Read` and `Glob` still reach the findings.
- Drop Bash only: `Read ../../findings/<id>.json` still works.
- Deny rules for `outDir` via `--settings` permissions: a denylist names one path to hide;
  `--restricted` confines to the cwd, which also covers `scans/` copies and anything not yet
  thought of.
- Worktrees under `os.tmpdir()`: shared, predictable, and wiped on reboot (see above).
- A new `--worktrees=DIR` option: nobody has asked to choose it; tests use `XDG_CACHE_HOME`.

## 4. Steps

Symbols touched, for sequencing. `bin/agent.cjs`: `CONFINEMENT` (new), `argvFor`, `runAgent`,
the `require.main` block. `bin/run.cjs`: `cacheHome` and `worktreeRootFor` (new, exported),
`triageAll` (option key), `FIX_TOOLS`, `buildFixPrompt` (repository commands block), `fixOne`
(worktree path, option key), `baseTree`, `runAudit` (option key), `planLines`, `run` (ctx field),
`module.exports`. Tests: `test/agent.test.cjs`, `test/run.test.cjs`,
`test/pipeline.real.test.cjs`, `test/fake-claude.cjs`. Prose: `SKILL.md`,
`references/FIX-AND-VERIFY.md`.

All paths below are relative to `/home/asiimov/Projects/code-scanning`.

### Step 1. Real-call probe (budgeted: 2 calls, `--model haiku`, at most one rerun)

Justification. The whole unit rests on three CLI behaviours that `test/fake-claude.cjs` cannot
show: that `--restricted` keeps `Read` and `Grep` out of a sibling folder, that `--tools` removes
Bash from the tool set, and that `--restricted` together with `--setting-sources user` still
authenticates and still lets `Write` create a file in the cwd. Two haiku calls settle all three.
Never use the fable model.

Create `.work/probe/r2-sandbox.cjs` with exactly this content:

```js
#!/usr/bin/env node
'use strict';
// R2 confinement probe. Two real haiku calls. Run: node .work/probe/r2-sandbox.cjs > .work/probe/sandbox.txt
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync, execFileSync } = require('child_process');

const CANARY = 'CANARYRULE7Q';
const P = fs.mkdtempSync(path.join(os.tmpdir(), 'r2-probe-'));
const out = path.join(P, 'out');
const wt = path.join(P, 'wt');
fs.mkdirSync(path.join(out, 'findings'), { recursive: true });
fs.mkdirSync(wt);
fs.writeFileSync(path.join(out, 'findings', 'f.json'), JSON.stringify({ rule_id: CANARY }));
execFileSync('git', ['init', '-q'], { cwd: wt });
fs.writeFileSync(path.join(wt, 'a.txt'), 'hello\n');

const prompt = `Do three things. 1) Use the Read tool on ${path.join(out, 'findings', 'f.json')} . `
  + `2) Use the Grep tool to search for the word CANARY under ${out} . `
  + '3) Use the Write tool to create ok.txt in the current directory containing OK. '
  + 'Then reply with the exact text you read in step 1 and any lines grep found, or NONE if you could not read them.';
const FIX = ['Read', 'Grep', 'Glob', 'Edit', 'Write'];
const U4 = ['--setting-sources', 'user', '--settings', '{"disableAllHooks":true}'];
const R2 = ['--restricted', '--strict-mcp-config', '--permission-mode', 'dontAsk'];

function call(label, argv) {
  fs.rmSync(path.join(wt, 'ok.txt'), { force: true });
  const r = spawnSync('claude', argv, { cwd: wt, encoding: 'utf8', timeout: 240000 });
  let events = [];
  try { const e = JSON.parse(r.stdout); events = Array.isArray(e) ? e : [e]; } catch { /* printed below */ }
  const init = events.find((e) => e.type === 'system' && e.subtype === 'init') || {};
  const result = [...events].reverse().find((e) => e.type === 'result') || {};
  console.log(`\n== ${label}`);
  console.log(`argv (prompt elided): ${JSON.stringify(argv.map((a, i) => (i === 1 ? '<prompt>' : a)))}`);
  console.log(`exit: ${r.status}  stderr: ${JSON.stringify((r.stderr || '').slice(0, 300))}`);
  console.log(`init.model: ${init.model}  init.permissionMode: ${init.permissionMode}`);
  console.log(`init.tools: ${JSON.stringify(init.tools)}`);
  console.log(`init.mcp_servers: ${(init.mcp_servers || []).length}  init.plugins: ${(init.plugins || []).length}`);
  console.log(`result.subtype: ${result.subtype}  is_error: ${result.is_error}`);
  console.log(`result.result: ${JSON.stringify(String(result.result || '').slice(0, 400))}`);
  console.log(`canary occurrences in stdout: ${((r.stdout || '').match(new RegExp(CANARY, 'g')) || []).length}`);
  console.log(`ok.txt written: ${fs.existsSync(path.join(wt, 'ok.txt'))}`);
}

console.log(`R2 confinement probe, ${new Date().toISOString()}, ${spawnSync('claude', ['--version'], { encoding: 'utf8' }).stdout.trim()}`);
console.log(`probe dir: ${P}`);
call('A, confined (the R2 argv, fixer tools)',
  ['-p', prompt, '--output-format', 'json', ...U4, ...R2, '--tools', FIX.join(','), '--model', 'haiku', '--allowed-tools', ...FIX]);
call('B, control (the U4 argv, fixer tools plus Bash)',
  ['-p', prompt, '--output-format', 'json', ...U4, '--model', 'haiku', '--allowed-tools', ...FIX, 'Bash']);
fs.rmSync(P, { recursive: true, force: true });
```

Run `node .work/probe/r2-sandbox.cjs > .work/probe/sandbox.txt` from the repo root, then append a
`== Verdict` block to `.work/probe/sandbox.txt` stating each gate below as PASS or FAIL.

Gates on call A. All must hold:

- `exit: 0` and `result.subtype: success`.
- `init.tools` contains `Read` and `Write`, and no entry equal to `Bash`, `PowerShell`, `REPL`,
  `WebFetch`, `WebSearch`, `Agent`, `Task`, `Skill`, or starting with `mcp__`. If `init.tools` is
  `undefined`, record that and judge this gate from `init.mcp_servers` and the canary only.
- `init.mcp_servers: 0`.
- `init.permissionMode: dontAsk`.
- `canary occurrences in stdout: 0`.
- `ok.txt written: true`.

Control B is evidence the probe can see a leak. If B's canary count is 0, write
`control inconclusive` in the verdict and continue; A's gates still decide.

If any A gate fails, rerun the probe once. If it fails again, **stop**: make no code change, and
report `.work/probe/sandbox.txt` to the orchestrator. Do not improvise a different flag set.

### Step 2. `bin/agent.cjs`

1. Replace the comment block above `ISOLATION` (lines 19-21) by keeping it and adding below
   `ISOLATION`:

   ```js
   // --allowed-tools only pre-approves; the tool set and the permission mode decide the rest, and the
   // operator's mode was `auto`. So the set is named with --tools, anything unlisted is refused by
   // dontAsk, MCP servers are dropped, and --restricted holds file tools to the cwd. Measured on
   // claude 2.1.280 in .work/probe/sandbox.txt.
   const CONFINEMENT = ['--restricted', '--strict-mcp-config', '--permission-mode', 'dontAsk'];
   ```

2. Replace `argvFor` with:

   ```js
   function argvFor({ prompt, model, tools }) {
     const argv = ['-p', prompt, '--output-format', 'json', ...ISOLATION, ...CONFINEMENT,
       '--tools', tools.join(',')];
     if (model) argv.push('--model', model);
     // Variadic on the CLI side, so it goes last or it swallows whatever follows it.
     argv.push('--allowed-tools', ...tools);
     return argv;
   }
   ```

3. In `runAgent`, directly after the existing `schemaPath` check, add:

   ```js
   if (!Array.isArray(opts.tools) || opts.tools.length === 0) {
     throw new Error('runAgent needs tools: without --tools the CLI default set includes a shell');
   }
   ```

4. In the `require.main` block, change the call to
   `runAgent({ prompt, schemaPath, schemaPointer: pointer, tools: ['Read', 'Grep', 'Glob'] })`.

### Step 3. `bin/run.cjs`

1. `triageAll` (line ~310): `allowedTools: TRIAGE_TOOLS` becomes `tools: TRIAGE_TOOLS`.
2. Line 442: `const FIX_TOOLS = ['Read', 'Grep', 'Glob', 'Edit', 'Write'];` and put this comment
   directly above it:
   `// No shell. The harness builds, tests and rescans; a shell narrowed to the test command is no`
   `// boundary when the fixer can edit the script that command runs.`
3. `buildFixPrompt`, the `# Repository commands` element: change
   `` `# Repository commands\nbuild: ${...}` `` to
   `` `# Repository commands\nThe harness runs these after you return. You have no shell.\nbuild: ${ctx.buildCommand || 'none discovered'}` ``.
   Leave `test:` and `lint:` lines as they are.
4. Below the `sha256` helper near the top (line ~33), add:

   ```js
   // Worktrees live outside the output directory, whose findings/ and scans/ name the rule the fixer
   // is never shown. Derived from the output directory so a resumed run finds its base tree again.
   const cacheHome = () => process.env.XDG_CACHE_HOME || path.join(os.homedir(), '.cache');
   const worktreeRootFor = (outDir) =>
     path.join(cacheHome(), 'sast-remediate', 'worktrees', sha256(path.resolve(outDir)).slice(0, 16));
   ```

   Also replace the comment in `fixOne` above `const branch` ("Branches live in the target
   repository ... everything else lives in the per-run output directory") so its second clause
   reads "worktrees live under ctx.worktreeRoot and everything else in the per-run output
   directory". Keep the sentence about the run id.
5. `fixOne` line 461: `const wt = path.join(ctx.worktreeRoot, `${f.id}-${attempt}`);`
6. `fixOne` line ~489: `allowedTools: FIX_TOOLS` becomes `tools: FIX_TOOLS`.
7. `baseTree` line 606: `const wt = path.join(ctx.worktreeRoot, 'base');`
8. `runAudit` line ~698: `allowedTools: AUDIT_TOOLS` becomes `tools: AUDIT_TOOLS`.
9. `planLines`: after the `out` line add `` `worktrees     ${worktreeRootFor(outDir)}`, ``.
10. `run`: after `ensureDir(outDir);` add
    `const worktreeRoot = worktreeRootFor(outDir);` and
    `fs.mkdirSync(worktreeRoot, { recursive: true, mode: 0o700 });`, and add `worktreeRoot` to the
    `ctx` object literal on the line with `opts, deps, target, outDir, runId`.
11. `module.exports`: add `worktreeRootFor` next to `refSafe`.
12. Confirm `grep -n allowedTools skills/sast-remediate/bin/*.cjs` prints nothing and
    `wc -l skills/sast-remediate/bin/run.cjs` is under 1000.

### Step 4. `test/fake-claude.cjs`

Change the log line to record argv:
`fs.appendFileSync(scenario.log, `${JSON.stringify({ role, cwd: process.cwd(), argv })}\n`);`
and add `argv` to the scenario header comment's list of logged fields if it lists them (it does
not today; leave the comment otherwise).

### Step 5. Prose

1. `skills/sast-remediate/SKILL.md` line 126-127. Replace
   "No rule id, no scanner name, no scanner message, no observation, and no scanner tool access."
   with
   "No rule id, no scanner name, no scanner message, no observation, and no way to go and look. It
   gets file tools and no shell, its worktree sits outside the run directory, and its file tools
   cannot leave that worktree."
2. `SKILL.md` line 59, after "Agents run with the target's Claude settings, `CLAUDE.md` and hooks
   shut out." add the sentence "Each gets only the tools its role needs, and none gets a shell."
3. `references/FIX-AND-VERIFY.md`, Branch protocol, after the first paragraph add:
   "Worktrees live under `$XDG_CACHE_HOME/sast-remediate/worktrees/<hash>/`, `~/.cache` when the
   variable is unset, where the hash is taken from the output directory. Never inside the output
   directory: its `findings/` and `scans/` name the rule the fixer is never shown."
4. `FIX-AND-VERIFY.md` line 24: replace "Any scanner tool access." with "A shell. Its tools are
   Read, Grep, Glob, Edit and Write. The harness builds, tests and rescans after the fixer
   returns, and a shell narrowed to the test command is no boundary when the fixer can edit the
   script that command runs."
5. `FIX-AND-VERIFY.md` Agent isolation. Keep the first paragraph. Replace the second paragraph
   ("What still loads ... is not measured.") with a paragraph that states, using the numbers from
   `.work/probe/sandbox.txt`:
   - every call also passes `--restricted --strict-mcp-config --permission-mode dontAsk` and
     `--tools` with the role's list;
   - `--allowed-tools` alone only pre-approves, and under the operator's `auto` mode it did not
     keep Bash out (call B's `init.tools` from the probe, quoted);
   - with the R2 flags the probe saw `init.mcp_servers` 0, no shell in `init.tools`, and a file
     outside the cwd unread (call A);
   - `--restricted` ignores user settings files, so the operator's default model does not apply to
     agents; pass `--model`.
   Also add one line under the role table or tools prose listing: triage and audit get Read, Grep
   and Glob; the fixer adds Edit and Write.
6. Run `node tools/check-prose.cjs` from the repo root and fix any hit.

## 5. Tests

Write each test, confirm it fails against the unmodified code (or by the mutation named in
Section 6), then land the fix.

### `test/agent.test.cjs`

1. Add `const TOOLS = ['Read'];` under `const TRIAGE = ...`. Add `tools: TOOLS, ` to every
   `runAgent({ prompt: 'p', ...` call (lines 58-197, including the multi-line call at 186). The
   call at line 175 tests the schema requirement; give it `tools: TOOLS` too so it still throws on
   the schema.
2. Replace the case
   `the prompt is an argument, json is requested, the target settings are shut out, allowed tools go last`
   with case **`every call is confined: the role's tools only, no MCP, dontAsk, file tools held to the cwd, allowed tools last`**:

   ```js
   const argv = argvFor({ prompt: 'hello', model: 'opus', tools: ['Read', 'Grep'] });
   assert.deepStrictEqual(argv, [
     '-p', 'hello', '--output-format', 'json',
     '--setting-sources', 'user', '--settings', '{"disableAllHooks":true}',
     '--restricted', '--strict-mcp-config', '--permission-mode', 'dontAsk',
     '--tools', 'Read,Grep',
     '--model', 'opus', '--allowed-tools', 'Read', 'Grep',
   ]);
   const last = argv.indexOf('--allowed-tools');
   assert.ok(argv.slice(last + 1).every((a) => !a.startsWith('--')), 'a variadic flag must end the argv');
   assert.deepStrictEqual(argvFor({ prompt: 'hello', tools: ['Read'] }).slice(-4),
     ['--tools', 'Read', '--allowed-tools', 'Read']);
   ```

3. New case **`a call with no tool list is refused before the CLI runs, because the default set has a shell`**:

   ```js
   const exec = fakeExec();
   await assert.rejects(runAgent({ prompt: 'p', schemaPath: SCHEMA, schemaPointer: TRIAGE, exec }),
     /runAgent needs tools/);
   await assert.rejects(runAgent({ prompt: 'p', schemaPath: SCHEMA, schemaPointer: TRIAGE, tools: [], exec }),
     /runAgent needs tools/);
   assert.strictEqual(exec.calls.length, 0);
   ```

   Check how existing async cases are registered in this file (`t(name, async () => ...)`) and
   follow it.

### `test/run.test.cjs`

1. Hermetic cache. Directly after the `tmp()` function add:

   ```js
   const CACHE = tmp();
   process.env.XDG_CACHE_HOME = CACHE;
   ```

2. Replace the case `the fixer is given no scanner tool and runs inside its own worktree` with
   case **`the fixer works in a worktree outside the run directory, from which no relative path reaches findings`**:

   ```js
   const { res, deps, out } = await fixRun();
   const c = deps.state.agentCalls.find((x) => x.schemaPointer === '#/$defs/fix');
   const f = res.findings.find((x) => x.patches.length);
   assert.strictEqual(path.basename(c.cwd), `${f.id}-1`);
   assert.strictEqual(path.dirname(path.dirname(c.cwd)), path.join(CACHE, 'sast-remediate', 'worktrees'));
   assert.ok(path.relative(out, c.cwd).startsWith('..'), `${c.cwd} is inside ${out}`);
   for (let k = 1; k <= 4; k++) {
     assert.ok(!fs.existsSync(path.resolve(c.cwd, '../'.repeat(k), 'findings')), `findings reachable at depth ${k}`);
   }
   assert.ok(fs.existsSync(path.join(out, 'findings', `${f.id}.json`)), 'the findings the fixer must not reach do exist');
   ```

3. New case **`each agent role gets exactly its tools, and none gets a shell`**:

   ```js
   const { deps } = await fixRun({ verify: 'full' });
   const byRole = {};
   for (const c of deps.state.agentCalls) byRole[c.schemaPointer] = c.tools;
   assert.deepStrictEqual(byRole, {
     '#/$defs/triage': ['Read', 'Grep', 'Glob'],
     '#/$defs/fix': ['Read', 'Grep', 'Glob', 'Edit', 'Write'],
     '#/$defs/audit': ['Read', 'Grep', 'Glob'],
   });
   ```

   This pins the policy table on purpose: the tool list is the security decision, and any edit to
   it should fail a test and be reviewed.

4. New case **`a resumed run finds the same worktree root, and another run gets its own`**:

   ```js
   const a = R.worktreeRootFor('/srv/out/run-1');
   assert.strictEqual(a, R.worktreeRootFor('/srv/out/run-1/'));
   assert.notStrictEqual(a, R.worktreeRootFor('/srv/out/run-2'));
   assert.ok(!path.relative('/srv/out/run-1', a).split(path.sep).includes('findings'));
   assert.ok(path.relative('/srv/out/run-1', a).startsWith('..'));
   ```

5. Update the case `a red suite on the patch tree costs a second attempt and then stops at two`:
   `cwd.includes('worktrees/base')` becomes `path.basename(cwd) === 'base'`. Run
   `grep -n "worktrees" test/*.cjs` and update any other hit the same way.
6. Update the `--dry-run` case to also assert
   `assert.ok(/worktrees\s+\S+sast-remediate\/worktrees\//.test(text), text);`.

### `test/pipeline.real.test.cjs`

1. In the `Object.assign(process.env, {...})` block add `XDG_CACHE_HOME: path.join(TMP, 'cache')`.
2. In `runScenario`, add `calls, out` to the returned object.
3. New plain case (not expectFail) **`every agent reaches the real CLI spawn confined, and the fixer's cwd is outside the run directory`**:

   ```js
   const s = await scenarios.plain();
   const fix = s.calls.find((c) => c.role === 'fix');
   const argv = [...fix.argv];
   argv[1] = '<prompt>';
   assert.deepStrictEqual(argv, [
     '-p', '<prompt>', '--output-format', 'json',
     '--setting-sources', 'user', '--settings', '{"disableAllHooks":true}',
     '--restricted', '--strict-mcp-config', '--permission-mode', 'dontAsk',
     '--tools', 'Read,Grep,Glob,Edit,Write',
     '--allowed-tools', 'Read', 'Grep', 'Glob', 'Edit', 'Write',
   ]);
   assert.ok(path.relative(s.out, fix.cwd).startsWith('..'), `${fix.cwd} is inside ${s.out}`);
   for (const c of s.calls) {
     assert.ok(c.argv.includes('--restricted'), `${c.role} call is not restricted`);
     assert.ok(!c.argv.some((a) => /\bBash\b/.test(a) && a !== c.argv[1]), `${c.role} call names Bash`);
   }
   ```

   If the fake records a realpath that differs from `s.out` (it will not on Linux `/tmp`), compare
   `fs.realpathSync` of both sides.

New tests: 6 (agent 2 replaced or new, run 3 new or replaced, pipeline 1 new), plus 3 edited
cases.

## 6. Verification

1. `cd skills/sast-remediate && sh test/run-all.sh` ends with `all green`. The pipeline section
   reports the new case as `ok`, not `expected-fail`.
2. `wc -l skills/sast-remediate/bin/run.cjs` prints a number under 1000.
3. `grep -rn "allowedTools\|'Bash'" skills/sast-remediate/bin` prints nothing.
4. `node skills/sast-remediate/bin/run.cjs --target=fixtures/vuln-app --dry-run` prints a
   `worktrees` line under `~/.cache/sast-remediate/worktrees/`.
5. `.work/probe/sandbox.txt` exists and its `== Verdict` block shows every call-A gate as PASS.

Mutation checks. Apply each, run the named file, confirm the named case fails, revert.

| mutation | file to run | case that must fail |
|---|---|---|
| `CONFINEMENT = []` in `agent.cjs` | `node test/agent.test.cjs` | `every call is confined ...` |
| delete the `opts.tools` check in `runAgent` | `node test/agent.test.cjs` | `a call with no tool list is refused ...` (it fails on `.join` of undefined with a different message, or reaches exec) |
| add `'Bash'` back to `FIX_TOOLS` | `node test/run.test.cjs` | `each agent role gets exactly its tools ...` |
| `ctx.worktreeRoot` replaced by `path.join(ctx.outDir, 'worktrees')` in `fixOne` | `node test/run.test.cjs` | `the fixer works in a worktree outside the run directory ...` |
| `worktreeRootFor` returns a constant path | `node test/run.test.cjs` | `a resumed run finds the same worktree root ...` |
| drop `'--restricted'` from `CONFINEMENT` | `node test/pipeline.real.test.cjs` | `every agent reaches the real CLI spawn confined ...` |

Record each mutation and its observed failure line in the handback.

## 7. Risks and out of scope

- **Top risk: `--restricted` behaviour is only known from help text until Step 1 runs.** If it
  conflicts with `--setting-sources user`, breaks login, or blocks `Write` in the cwd, every agent
  call fails and the run defers everything. Step 1 is a hard gate for exactly this reason.
- `--restricted` drops the operator's settings-file model and effort. Agents without `--model`
  run on the CLI default model. Documented, not worked around.
- `--restricted` "lets only a person or the configured permission handler approve writes to
  settings, git and tool-configuration files". A fix that must edit such a file (a `.gitignore`,
  a CI config) now fails to write and ends `fix_failed`. Accepted: those files are rarely the
  enforcement point, and the failure is visible.
- The fixer can no longer run tests to check itself, so attempt one is written blind to the suite.
  The harness still runs it, and attempt two receives the typed failure.
- Worktrees now outlive the output directory: deleting `outDir` leaves them under
  `~/.cache/sast-remediate/worktrees/`. Nothing cleaned them up before either. Out of scope.
- The worktree's `.git` file names the target's `.git/worktrees/<name>`; that holds no scanner
  output, and it is outside the cwd anyway.
- Out of scope: the triage prompt content (triage may see the rule), the `executable` witness
  tier, a prompt-injection review of the target's source, and any network egress control beyond
  removing WebFetch and WebSearch.
