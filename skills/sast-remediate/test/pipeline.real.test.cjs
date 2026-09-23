#!/usr/bin/env node
'use strict';
// Run: node test/pipeline.real.test.cjs
// The whole pipeline against a real git copy of the fixture app. Real git, the real agent
// spawn path in bin/agent.cjs (a fake `claude` found on PATH), the real report renderer. Only
// the scanners are stood in for: the baseline comes from test/fixtures via --scans, and the
// rescan is answered by a fake semgrep. A case marked expectFail(unit) documents a known
// defect; it must fail today, and the unit that fixes it turns it into a plain case.

const fs = require('fs');
const os = require('os');
const path = require('path');
const assert = require('assert');
const { execFileSync } = require('child_process');

const ROOT = path.resolve(__dirname, '..');
const FIXTURE = path.resolve(ROOT, '../../fixtures/vuln-app');
const SCANS = path.join(ROOT, 'test/fixtures');
const R = require(path.join(ROOT, 'bin/run.cjs'));
const { runAgent } = require(path.join(ROOT, 'bin/agent.cjs'));
const { renderRemediation, renderHandoff } = require(path.join(ROOT, 'bin/report.cjs'));

const PATH_ID = 'f_6ed43412e0d9b09d';
const COMMAND_ID = 'f_d72e46f6d1ec2eb0';
const TRANSPORT_ID = 'f_e2981bd8a7b838b9';

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'sast-pipeline-'));
const BIN = path.join(TMP, 'bin');
fs.mkdirSync(BIN);
fs.chmodSync(path.join(__dirname, 'fake-claude.cjs'), 0o755);
fs.symlinkSync(path.join(__dirname, 'fake-claude.cjs'), path.join(BIN, 'claude'));
// XDG_CONFIG_HOME too: git reads ~/.config/git/ignore even with GIT_CONFIG_GLOBAL unset, and a
// personal ignore of .claude/ files would hide the stray-file defect.
Object.assign(process.env, {
  PATH: `${BIN}${path.delimiter}${process.env.PATH}`,
  GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_NOSYSTEM: '1', XDG_CONFIG_HOME: BIN,
  GIT_AUTHOR_NAME: 'fixture', GIT_AUTHOR_EMAIL: 'fixture@example.invalid',
  GIT_COMMITTER_NAME: 'fixture', GIT_COMMITTER_EMAIL: 'fixture@example.invalid',
  XDG_CACHE_HOME: path.join(TMP, 'cache'),
});

const git = (cwd, ...args) => execFileSync('git', ['-C', cwd, ...args], { encoding: 'utf8' });

// ------------------------------------------------------------------ scenario

const contract = (witness) => ({
  invariant: 'every string reaching the file read in `read` names a file already present in the '
    + 'public directory, so no request can select a path outside it',
  violating_input: '../../secret.txt',
  enforcement_point: {
    file: 'src/routes/files.js', symbol: 'read',
    rationale: 'the last point at which the requested name is still an untrusted plain string',
  },
  witness,
  writable_scope: ['src/**', 'test/**'],
  forbidden_resolutions: ['do not delete the route', 'do not return an error for every request'],
});

const WITNESS = {
  executable: {
    tier: 'executable', framework: 'node assert', entrypoint: 'read',
    attack_input: '../../secret.txt', asserts: 'the traversal is answered with 400',
    command_template: 'node test/files.test.js', control: null,
    expected_pre_fix: 'fail', expected_post_fix: 'pass',
  },
  argued: { tier: 'argued', obstacle: 'no_test_harness', why: 'the fixture ships no harness for this route' },
  // Same witness as test/e2e-witness.cjs:56-70: the real endpoint and the real public files this
  // fixture ships, so a live boot of the app can send the attack and the control for real.
  dynamic: {
    tier: 'dynamic',
    harness_id: 'npm_start',
    attack: { method: 'GET', path: '/files', headers: {}, query: { name: '../secret.txt' },
              body: { kind: 'none' }, as_principal: 'dummy_anonymous' },
    observable: { kind: 'body_contains', canary: 'CANARY_DUMMY_SECRET_d41d8cd9' },
    control: {
      kind: 'http',
      exchange: { method: 'GET', path: '/files', headers: {}, query: { name: 'hello.txt' },
                  body: { kind: 'none' }, as_principal: 'dummy_anonymous' },
      expect: { kind: 'body_contains', canary: 'public file' },
    },
    expected_pre_fix: 'observable_fires',
    expected_post_fix: 'observable_absent',
  },
};

const exploitable = (tier) => ({
  verdict: 'exploitable', established_by: 'agent', contract: contract(WITNESS[tier]),
  severity: 'high', impact: 'any file readable by the process is returned to the caller',
  likelihood: 'a single crafted request', blast_radius: 'every file the process user can read',
});

const PATCH = { act: 'patch', witness: true };

// The semgrep result for the path finding, moved to wherever `path.join(ROOT` sits in the
// patched file. Same rule, same file, new line: what a correct fix that keeps the call shape
// looks like to a rescan.
function sameRuleMoved(worktree) {
  const base = JSON.parse(fs.readFileSync(path.join(SCANS, 'semgrep.json'), 'utf8'));
  const hit = base.results.find((r) => r.path === 'src/routes/files.js');
  const lines = fs.readFileSync(path.join(worktree, hit.path), 'utf8').split('\n');
  const at = lines.findIndex((l) => l.includes('path.join(ROOT')) + 1;
  const moved = { ...hit, start: { ...hit.start, line: at }, end: { ...hit.end, line: at },
    extra: { ...hit.extra, lines: lines[at - 1] } };
  return { ...base, results: [moved] };
}

function makeTarget(name, { dropTestScript }) {
  const dir = path.join(TMP, name, 'repo');
  fs.cpSync(FIXTURE, dir, { recursive: true, filter: (src) => !src.includes(`${path.sep}.claude`) });
  if (dropTestScript) {
    const pkgPath = path.join(dir, 'package.json');
    const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
    delete pkg.scripts.test;
    fs.writeFileSync(pkgPath, JSON.stringify(pkg, null, 2));
  }
  git(dir, 'init', '-q', '-b', 'main');
  git(dir, 'add', '-A');
  git(dir, '-c', 'commit.gpgsign=false', 'commit', '-q', '-m', 'fixture');
  return dir;
}

async function runScenario(name, { tier = 'executable', fix = [PATCH], verify = 'cheap', witness = null,
  rescan = () => ({ results: [], errors: [] }), dropTestScript = false, runs = 1, prepare = null } = {}) {
  const target = makeTarget(name, { dropTestScript });
  const out = path.join(TMP, name, `run-${name}`);
  const log = path.join(TMP, name, 'claude-calls.jsonl');
  const scenarioFile = path.join(TMP, name, 'scenario.json');
  fs.writeFileSync(scenarioFile, JSON.stringify({ log, triage: { 'src/routes/files.js': exploitable(tier) }, fix }));
  process.env.SAST_FAKE_CLAUDE = scenarioFile;
  if (prepare) prepare(target, out);

  const deps = {
    runAgent, renderRemediation, renderHandoff,
    exec: (cmd, args, o) => {
      if (cmd !== 'semgrep') return R.realExec(cmd, args, o);
      const outArg = args.find((a) => a.startsWith('--json-output='));
      fs.writeFileSync(outArg.slice('--json-output='.length), JSON.stringify(rescan(args[args.length - 1])));
      return { status: 0, stdout: '', stderr: '' };
    },
    onPath: (bin) => bin === 'semgrep',
    log: () => {},
    now: () => '2026-09-22T00:00:00.000Z',
  };
  const opts = R.parseArgs([`--target=${target}`, `--scans=${SCANS}`, `--out=${out}`,
    `--verify=${verify}`, '--timeout-ms=30000', ...(witness ? [`--witness=${witness}`] : [])]);

  const snapshot = (res) => {
    const calls = fs.readFileSync(log, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
    const record = (id) => JSON.parse(fs.readFileSync(path.join(out, 'findings', `${id}.json`), 'utf8'));
    return {
      runId: res.runId,
      calls, out,
      fixerCalls: calls.filter((c) => c.role === 'fix').length,
      auditCalls: calls.filter((c) => c.role === 'audit').length,
      branches: git(target, 'for-each-ref', '--format=%(refname:short)', 'refs/heads/sast-fix/')
        .split('\n').filter(Boolean).sort(),
      filesOn: (branch) => git(target, 'diff', '--name-only', 'main', branch).split('\n').filter(Boolean),
      states: Object.fromEntries([PATH_ID, COMMAND_ID, TRANSPORT_ID]
        .map((id) => [id, (record(id).disposition || {}).state || null])),
      record: record(PATH_ID),
      report: fs.readFileSync(path.join(out, 'REMEDIATION.md'), 'utf8'),
      meta: JSON.parse(fs.readFileSync(path.join(out, 'run-metadata.json'), 'utf8')),
    };
  };

  let last, first;
  for (let i = 0; i < runs; i++) {
    const res = await R.run(opts, deps);
    last = snapshot(res);
    if (i === 0) first = last;
  }
  return { ...last, first };
}

const memo = (fn) => { let p; return () => (p = p || fn()); };
const scenarios = {
  plain: memo(() => runScenario('plain')),
  noTestScript: memo(() => runScenario('notest', { dropTestScript: true })),
  crashThenFix: memo(() => runScenario('crash', { verify: 'none', runs: 2, fix: [{ act: 'crash' }, { act: 'crash' }, PATCH] })),
  declined: memo(() => runScenario('declined', {
    fix: [{ act: 'cannot_fix', reason: 'the route has no caller that could supply a safe name' }],
  })),
  argued: memo(() => runScenario('argued', { tier: 'argued', fix: [{ act: 'patch' }] })),
  fullArgued: memo(() => runScenario('full-argued', { tier: 'argued', verify: 'full', fix: [{ act: 'patch' }] })),
  dynamic: memo(() => runScenario('dynamic', { tier: 'dynamic', verify: 'full', witness: 'dynamic', fix: [{ act: 'patch' }] })),
  dynamicCheat: memo(() => runScenario('dynamic-cheat', { tier: 'dynamic', verify: 'full', witness: 'dynamic', fix: [{ act: 'disable' }] })),
  lineMoved: memo(() => runScenario('moved', { rescan: sameRuleMoved })),
  stray: memo(() => runScenario('stray', { fix: [{ ...PATCH, stray: true }] })),
  uncommitted: memo(() => runScenario('uncommitted', { fix: [{ ...PATCH, commit: false }] })),
  stale: memo(() => runScenario('stale', {
    // The worktree a died run leaves behind now lives under R.worktreeRootFor(out) (R2), not
    // under out itself, so the stale fixture has to plant it at the same path fixOne computes.
    prepare: (target, out) => {
      const wt = path.join(R.worktreeRootFor(out), `${PATH_ID}-1`);
      git(target, 'worktree', 'add', '-q', '-b', `sast-fix/run-stale/${PATH_ID}/1`, wt, 'HEAD');
      fs.writeFileSync(path.join(wt, 'half-written.txt'), 'left by a run that died\n');
    },
  })),
};

function sections(report) {
  const out = [];
  for (const line of report.split('\n')) {
    if (/^(\*\*.+\*\*|#+ .+)$/.test(line.trim())) out.push({ heading: line.trim(), body: '' });
    else if (out.length) out[out.length - 1].body += `${line}\n`;
  }
  return out;
}

// ------------------------------------------------------------------- cases

const tests = [];
const t = (name, fn) => tests.push({ name, fn, unit: null });
t.expectFail = (unit, name, fn) => tests.push({ name, fn, unit });

t('a real run on a real git copy reaches report', async () => {
  const s = await scenarios.plain();
  assert.deepStrictEqual(s.states, { [PATH_ID]: 'fixed', [COMMAND_ID]: 'rejected', [TRANSPORT_ID]: 'rejected' });
  assert.ok(s.branches.includes(`sast-fix/run-plain/${PATH_ID}/1`), s.branches.join(', '));
  assert.deepStrictEqual(s.filesOn(`sast-fix/run-plain/${PATH_ID}/1`), ['src/routes/files.js', 'test/files.test.js']);
  assert.strictEqual(s.meta.run_status, 'complete');
  assert.ok(s.report.includes(`\`${PATH_ID}\``), 'the fixed finding is named in REMEDIATION.md');
  assert.ok(s.report.includes('This run completed.'), s.report);
});

t('every agent reaches the real CLI spawn confined, and the fixer\'s cwd is outside the run directory', async () => {
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
});

t('refuted findings get no branch, and a declined fix is recorded after one fixer call', async () => {
  const s = await scenarios.declined();
  assert.deepStrictEqual(s.branches, [`sast-fix/run-declined/${PATH_ID}/1`]);
  assert.strictEqual(s.fixerCalls, 1);
  assert.deepStrictEqual(s.states, { [PATH_ID]: 'fix_declined', [COMMAND_ID]: 'rejected', [TRANSPORT_ID]: 'rejected' });
});

t('a repo with no test script gets patched', async () => {
  const s = await scenarios.noTestScript();
  assert.strictEqual(s.states[PATH_ID], 'fixed');
  assert.deepStrictEqual(s.filesOn(s.record.patches[0].branch), ['src/routes/files.js', 'test/files.test.js']);
});

t('REMEDIATION.md names only branches that exist', async () => {
  const s = await scenarios.plain();
  const named = [...new Set(s.report.match(/sast-fix\/[A-Za-z0-9._/-]+/g) || [])];
  assert.deepStrictEqual(named.filter((b) => !s.branches.includes(b)), [], `phantom branches in ${s.branches.join(', ')}`);
  assert.ok(named.some((b) => b.startsWith(`sast-fix/run-plain/${PATH_ID}/`)), `named: ${named.join(', ')}`);
});

t('the scanner-quiet row reads the rescan the run recorded', async () => {
  const s = await scenarios.plain();
  assert.strictEqual(s.record.patches[0].verification.rescan.original_absent, true);
  assert.ok(s.report.includes(`| \`${PATH_ID}\` | scanner is quiet on the original rule`), s.report);
});

t('a fix that passes every cheap check makes exactly one fixer call', async () => {
  const s = await scenarios.plain();
  assert.strictEqual(s.fixerCalls, 1);
  assert.deepStrictEqual(s.branches, [`sast-fix/run-plain/${PATH_ID}/1`]);
});

t('a crashing fixer leaves the finding open, and the next run fixes it', async () => {
  const s = await scenarios.crashThenFix();
  assert.strictEqual(s.first.states[PATH_ID], null, `ended ${s.first.states[PATH_ID]}`);
  assert.strictEqual(s.first.meta.run_status, 'incomplete');
  assert.ok(s.first.meta.incomplete_reason.includes(`${PATH_ID} fix: discarded twice: cli exited 1`),
    s.first.meta.incomplete_reason);
  assert.deepStrictEqual(s.first.branches, []);
  assert.strictEqual(s.first.fixerCalls, 2);

  assert.strictEqual(s.states[PATH_ID], 'fixed');
  assert.strictEqual(s.meta.run_status, 'complete');
  assert.strictEqual(s.fixerCalls, 3);
  assert.deepStrictEqual(s.branches, [`sast-fix/run-crash/${PATH_ID}/1`]);
});

t('cannot_fix appears under its own heading, and the run says complete', async () => {
  const s = await scenarios.declined();
  const home = sections(s.report).find((x) => x.body.includes(`\`${PATH_ID}\``));
  assert.ok(home, 'the declined finding is named in REMEDIATION.md');
  assert.ok(s.report.includes('the route has no caller that could supply a safe name'), 'the fixer reason is shown');
  assert.ok(!s.report.includes('mid-fix'), 'a declined fix is terminal, not mid-fix');
  assert.ok(s.report.includes('This run completed.'), s.report);
});

t('an argued fix is not listed under Fixed', async () => {
  const s = await scenarios.argued();
  assert.strictEqual(s.states[PATH_ID], 'fixed_unwitnessed');
  const all = sections(s.report).filter((x) => x.body.includes(`\`${PATH_ID}\``)).map((x) => x.heading);
  assert.ok(all.length, 'the argued finding is named in REMEDIATION.md');
  assert.deepStrictEqual(all.filter((h) => /fixed/i.test(h) && !/unwitnessed|argued|not/i.test(h)), [], all.join(' | '));
});

t('an argued fix is still named as waiting on review under What changed', async () => {
  const s = await scenarios.argued();
  const changed = sections(s.report).find((x) => /What changed/.test(x.heading));
  assert.ok(changed.body.includes(`\`${PATH_ID}\`: \`sast-fix/`), changed.body);
  assert.ok(!s.report.includes('Nothing is waiting on review'), changed.body);
});

t('a fix that edits the flagged line while the rule still matches passes no_new_findings and keeps original_absent false', async () => {
  const s = await scenarios.lineMoved();
  const v = s.record.patches[0].verification;
  assert.strictEqual(v.no_new_findings.status, 'pass', JSON.stringify(v.no_new_findings));
  assert.strictEqual(v.rescan.original_absent, false);
  assert.strictEqual(s.states[PATH_ID], 'fixed');
});

t('a stray .claude/ file written during the fix is not in the patch diff', async () => {
  const s = await scenarios.stray();
  const first = s.record.patches[0];
  assert.strictEqual(first.verification.deterministic_guard.status, 'pass', JSON.stringify(first.verification.deterministic_guard));
  assert.deepStrictEqual(s.filesOn(first.branch), ['src/routes/files.js', 'test/files.test.js']);
  assert.strictEqual(s.states[PATH_ID], 'fixed');
});

t('a fixer that edits but does not commit still leaves a branch carrying the fix', async () => {
  const s = await scenarios.uncommitted();
  assert.strictEqual(s.states[PATH_ID], 'fixed');
  assert.deepStrictEqual(s.filesOn(`sast-fix/run-uncommitted/${PATH_ID}/1`), ['src/routes/files.js', 'test/files.test.js']);
});

t('a branch left by a run that died mid-fix is cleared and the attempt runs again', async () => {
  const s = await scenarios.stale();
  assert.strictEqual(s.states[PATH_ID], 'fixed');
  assert.strictEqual(s.fixerCalls, 1);
  assert.deepStrictEqual(s.filesOn(`sast-fix/run-stale/${PATH_ID}/1`), ['src/routes/files.js', 'test/files.test.js']);
  assert.strictEqual(s.meta.run_status, 'complete');
});

t('at full, an argued fix ends fixed_unwitnessed after one fixer call', async () => {
  const s = await scenarios.fullArgued();
  assert.strictEqual(s.fixerCalls, 1);
  assert.strictEqual(s.auditCalls, 1);
  assert.deepStrictEqual(s.record.disposition, {
    state: 'fixed_unwitnessed', branch: `sast-fix/run-full-argued/${PATH_ID}/1`,
    verify_level: 'full', skipped_obligations: [],
    unavailable: ['differential_witness', 'functional_control', 'regression_suite'],
    witness_tier: 'argued',
  });
  assert.ok(s.report.includes('verified at `full`: all seven obligations checked'), s.report);
  assert.ok(s.report.includes(
    '`differential_witness`, `functional_control`, `regression_suite` unavailable and excused, not passed'), s.report);
  assert.ok(!s.report.includes('all seven obligations passed'), s.report);
});

t('with --witness=dynamic, a fix that stops the attack and keeps the control green ends fixed', async () => {
  const s = await scenarios.dynamic();
  assert.strictEqual(s.fixerCalls, 1);
  assert.strictEqual(s.auditCalls, 1);
  assert.strictEqual(s.states[PATH_ID], 'fixed');
  assert.strictEqual(s.record.disposition.witness_tier, 'dynamic');
  assert.deepStrictEqual(s.record.disposition.unavailable, ['regression_suite']);
  const v = s.record.patches[0].verification;
  assert.strictEqual(v.differential_witness.status, 'pass');
  assert.strictEqual(v.functional_control.status, 'pass');
  assert.strictEqual(v.deterministic_guard.status, 'pass');
  assert.deepStrictEqual(v.differential_witness.transcript.map((x) => `${x.label}:${x.tree}`),
    ['control:base', 'attack:base', 'attack:head', 'control:head']);
});

t('with --witness=dynamic, a fix that disables the endpoint passes the differential and fails the control', async () => {
  const s = await scenarios.dynamicCheat();
  assert.strictEqual(s.fixerCalls, 2);
  assert.strictEqual(s.states[PATH_ID], 'fix_failed');
  assert.strictEqual(s.record.patches[0].verification.differential_witness.status, 'pass');
  assert.strictEqual(s.record.patches[0].verification.functional_control.status, 'fail');
  assert.strictEqual(s.record.patches[0].verification.functional_control.reason, 'control_failed_on_patched_tree');
  assert.deepStrictEqual(s.record.disposition.failed, ['functional_control']);
});

const brief = (e) => e.message.replace(/\x1b\[[0-9;]*m/g, '').split('\n').map((l) => l.trim()).filter(Boolean).join(' ').slice(0, 200);

(async () => {
  let pass = 0, fail = 0;
  for (const { name, fn, unit } of tests) {
    let err = null;
    try { await fn(); } catch (e) { err = e; }
    if (!unit && !err) { pass++; console.log(`  ok   ${name}`); }
    else if (unit && err) { pass++; console.log(`  expected-fail (${unit}) ${name}\n         ${brief(err)}`); }
    else if (unit) { fail++; console.log(`  FAIL ${name}\n         passes now; ${unit} landed, so make it a plain case`); }
    else { fail++; console.log(`  FAIL ${name}\n         ${err.stack}`); }
  }
  fs.rmSync(TMP, { recursive: true, force: true });
  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail === 0 ? 0 : 1);
})();
