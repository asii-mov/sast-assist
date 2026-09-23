#!/usr/bin/env node
'use strict';
// Run: node test/run.test.cjs
// The orchestrator, driven end to end with an injected agent runner and an injected process
// runner. No real model call, no real scanner, no network. The findings are normalized from the
// genuine semgrep and CodeQL fixtures, so the leak assertions below run against real rule ids.

const fs = require('fs');
const os = require('os');
const path = require('path');
const assert = require('assert');

const ROOT = path.resolve(__dirname, '..');
const REPO = path.resolve(ROOT, '../../fixtures/vuln-app');
const SCHEMA_DIR = path.join(ROOT, 'schema');

const R = require(path.join(ROOT, 'bin/run.cjs'));
const { normalize, makeRepo } = require(path.join(ROOT, 'bin/normalize.cjs'));
const { validate } = require(path.join(ROOT, 'bin/validate.cjs'));
const { VERIFY_LEVELS, stageOf } = require(path.join(ROOT, 'bin/stage.cjs'));

const readJson = (f) => JSON.parse(fs.readFileSync(f, 'utf8'));

let pass = 0, fail = 0;
const tests = [];
const t = (name, fn) => tests.push([name, fn]);
const section = (s) => tests.push([s, null]);

const tmpDirs = [];
function tmp() {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'sast-run-'));
  tmpDirs.push(d);
  return d;
}

// ------------------------------------------------------------------- fixtures

const raw = {
  semgrep: readJson(path.join(ROOT, 'test/fixtures/semgrep.json')),
  codeql: readJson(path.join(ROOT, 'test/fixtures/codeql.sarif')),
};
const fixtures = () => normalize(raw, makeRepo(REPO), 'run-test').findings;
const pathFinding = () => fixtures().find((f) => f.invariant_class === 'injection.path');

const RULE_ID = 'js/path-injection';

const contract = (over = {}) => ({
  invariant: 'every string reaching the first argument of the file read in `read` resolves inside '
    + 'the public directory, and a request may only select a name already present there',
  violating_input: '../../secret.txt',
  enforcement_point: {
    file: 'src/routes/files.js', symbol: 'read',
    rationale: 'the last point at which the requested name is still an untrusted plain string',
  },
  witness: { tier: 'argued', obstacle: 'no_test_harness', why: 'the fixture ships no unit harness for this route' },
  writable_scope: ['src/**'],
  forbidden_resolutions: ['do not delete the route', 'do not return an error for every request'],
  ...over,
});

const exploitable = (over = {}) => ({
  verdict: 'exploitable', established_by: 'agent', contract: contract(over.contract || {}),
  severity: over.severity || 'high',
  impact: 'any file readable by the process is returned to an unauthenticated caller',
  likelihood: 'a single crafted request',
  blast_radius: 'every file under the process user',
});
const notExploitable = () => ({
  verdict: 'not_exploitable', established_by: 'agent',
  refutation: { reason: 'input_is_not_attacker_controlled', control: null, explanation: 'the value is a literal' },
});

const EXEC_WITNESS = {
  tier: 'executable', framework: 'node:test', entrypoint: 'read',
  attack_input: '../../secret.txt', asserts: 'the response is rejected',
  command_template: 'npm test', control: { kind: 'existing_test', command_template: 'npm test' },
  expected_pre_fix: 'fail', expected_post_fix: 'pass',
};

const DIFF_SRC = `diff --git a/src/routes/files.js b/src/routes/files.js
--- a/src/routes/files.js
+++ b/src/routes/files.js
@@ -7,7 +7,9 @@
-  const target = path.join(ROOT, name);
+  const safe = path.basename(String(name));
+  if (!ALLOWED.has(safe)) { res.statusCode = 400; return res.end('unknown name'); }
+  const target = path.join(ROOT, safe);
`;
const DIFF_TEST = `diff --git a/test/files.test.js b/test/files.test.js
--- a/test/files.test.js
+++ b/test/files.test.js
@@ -0,0 +1,2 @@
+assert.strictEqual(statusFor('../../secret.txt'), 400);
+assert.strictEqual(statusFor('hello.txt'), 200);
`;

// ----------------------------------------------------------------- injections

function makeDeps(o = {}) {
  const state = {
    agentCalls: [], execCalls: [], diff: o.diff === undefined ? DIFF_SRC : o.diff,
    npm: o.npm || (() => 0), rescan: o.rescan || { results: [], errors: [] },
    reports: {},
  };
  const okr = (stdout = '') => ({ status: 0, stdout, stderr: '' });

  const exec = (cmd, args, opt = {}) => {
    state.execCalls.push([cmd, ...args].join(' '));
    if (cmd === 'git') {
      const rest = args[0] === '-C' ? args.slice(2) : args;
      if (rest[0] === 'rev-parse') {
        return o.base === null ? { status: 1, stdout: '', stderr: 'not a git repository' } : okr('a'.repeat(40) + '\n');
      }
      if (rest[0] === 'worktree' && rest[1] === 'add') {
        const dir = rest.find((a) => path.isAbsolute(a));
        fs.mkdirSync(dir, { recursive: true });
        return okr();
      }
      if (rest[0] === 'diff') return okr(state.diff);
      return okr();
    }
    if (cmd === 'npm') return { status: state.npm(opt.cwd || ''), stdout: '', stderr: 'suite output' };
    if (cmd === 'semgrep') {
      const out = (args.find((a) => a.startsWith('--json-output=')) || '=').split('=')[1];
      fs.mkdirSync(path.dirname(out), { recursive: true });
      fs.writeFileSync(out, JSON.stringify(state.rescan));
      return okr();
    }
    return okr();
  };

  const deps = {
    exec,
    onPath: o.onPath || (() => true),
    log: () => {},
    now: () => '2026-01-01T00:00:00.000Z',
    partition: o.partition || ((fs_) => [fs_.map((f) => f.id)]),
    renderRemediation: (f, m) => { state.reports.remediation = { f, m }; return '# remediation\n'; },
    renderHandoff: (f, m) => { state.reports.handoff = { f, m }; return '# handoff\n'; },
    runAgent: async (opts) => {
      state.agentCalls.push(opts);
      const h = (o.agents || {})[opts.schemaPointer];
      if (!h) return { ok: false, reason: 'no handler', raw: '' };
      const r = typeof h === 'function' ? h(opts, state) : h;
      return r;
    },
  };
  deps.state = state;
  return deps;
}

const baseOpts = (over = {}) => R.parseArgs([
  `--target=${REPO}`, `--scans=${path.join(ROOT, 'test/fixtures')}`,
  ...(over.argv || []),
]);

// ============================================================================

section('cli');

t('defaults match the documented ones', () => {
  const o = R.parseArgs(['--target=/x']);
  assert.strictEqual(o.fixAt, 'medium');
  assert.strictEqual(o.verify, 'cheap');
  assert.deepStrictEqual(o.scanners, ['semgrep', 'codeql']);
  assert.strictEqual(o.triageOnly, false);
  assert.strictEqual(o.maxFindings, Infinity);
});

t('--target is required', () => {
  assert.throws(() => R.parseArgs([]), /--target is required/);
});

t('an out-of-range --verify or --fix-at is refused, not silently defaulted', () => {
  assert.throws(() => R.parseArgs(['--target=/x', '--verify=some']), /--verify must be/);
  assert.throws(() => R.parseArgs(['--target=/x', '--fix-at=urgent']), /--fix-at must be/);
  assert.throws(() => R.parseArgs(['--target=/x', '--scanners=snyk']), /unknown scanner/);
  assert.throws(() => R.parseArgs(['--target=/x', '--max-findings=0']), /--max-findings/);
});

t('an unknown flag is an error rather than an ignored typo', () => {
  assert.throws(() => R.parseArgs(['--target=/x', '--verfy=cheap']), /unknown option/);
});

t('--dry-run prints the plan, names the skipped obligations, and writes nothing', async () => {
  const out = path.join(tmp(), 'never');
  const opts = baseOpts(); opts.dryRun = true; opts.out = out; opts.verify = 'cheap';
  const lines = R.planLines(opts, REPO, out, 'abc123');
  const text = lines.join('\n');
  assert.ok(/verify\s+cheap/.test(text), text);
  assert.ok(text.includes('differential_witness'), 'the plan must name what cheap does not check');
  assert.ok(text.includes('scan normalize pre-resolve triage gate fix verify report'));
  const deps = makeDeps();
  await R.run(opts, deps);
  assert.strictEqual(fs.existsSync(out), false, 'a dry run must create no output directory');
  assert.strictEqual(deps.state.agentCalls.length, 0);
});

// ============================================================================

section('the fixer prompt: the rule this skill exists to enforce');

t('a real rule id from the fixtures appears NOWHERE in the assembled fixer prompt', () => {
  const f = pathFinding();
  f.triage = exploitable();
  const ids = f.sites.flatMap((s) => s.observations.map((o) => o.rule_id));
  assert.ok(ids.includes(RULE_ID), `fixture must carry ${RULE_ID}, got ${ids.join(', ')}`);

  const prompt = R.buildFixPrompt(f, { testCommand: 'npm test' }, []);
  assert.ok(!prompt.includes(RULE_ID), `fixer prompt leaked ${RULE_ID}`);
  assert.ok(!prompt.toLowerCase().includes('semgrep'), 'fixer prompt leaked a scanner name');
  assert.ok(!prompt.toLowerCase().includes('codeql'), 'fixer prompt leaked a scanner name');
  for (const s of f.sites) {
    for (const o of s.observations) {
      assert.ok(!prompt.includes(o.rule_id), `leaked rule id ${o.rule_id}`);
      assert.ok(!prompt.includes(o.message.trim()), 'leaked a scanner message');
      if (o.rule_name) assert.ok(!prompt.includes(o.rule_name), 'leaked a rule name');
    }
  }
});

t('the prompt still carries the contract, so an empty prompt cannot pass the test above', () => {
  const f = pathFinding();
  f.triage = exploitable();
  const prompt = R.buildFixPrompt(f, { testCommand: 'npm test' }, []);
  const c = f.triage.contract;
  assert.ok(prompt.includes(c.invariant), 'the invariant must reach the fixer');
  assert.ok(prompt.includes(c.violating_input), 'the violating input must reach the fixer');
  assert.ok(prompt.includes(c.enforcement_point.rationale), 'the enforcement point must reach the fixer');
  assert.ok(prompt.includes(c.writable_scope[0]), 'the writable scope must reach the fixer');
  assert.ok(prompt.includes(c.forbidden_resolutions[0]), 'the forbidden resolutions must reach the fixer');
  assert.ok(prompt.includes(f.flow.steps[0].code), 'the materialized flow source must reach the fixer');
  assert.ok(prompt.includes(f.context.enclosing_excerpt.split('\n')[0]), 'the excerpt must reach the fixer');
});

t('the scanner-authored per-step note is dropped while the source line is kept', () => {
  const f = pathFinding();
  f.triage = exploitable();
  const notes = f.flow.steps.map((s) => s.note).filter((n) => n && n.includes(' ... '));
  assert.ok(notes.length, 'fixture must carry an elided scanner note');
  const prompt = R.buildFixPrompt(f, {}, []);
  for (const n of notes) assert.ok(!prompt.includes(n), `leaked a scanner-authored note: ${n}`);
});

t('the structural witness rule is withheld, because handing a fixer a matcher is the whole defect', () => {
  const w = {
    tier: 'structural', rule_yaml: 'rules:\n  - id: x\n    pattern: path.join($A, $B)\n',
    anchor: { file: 'src/routes/files.js', symbol: 'read', sink_digest: 'f'.repeat(64), line_at_scan: 9 },
    expected_pre_fix: 'match', expected_post_fix: 'no_match',
  };
  const brief = R.witnessBrief(w);
  assert.ok(!brief.includes('pattern:'), 'the structural rule must not reach the fixer');
  assert.ok(brief.includes('src/routes/files.js:9'), 'the anchor must reach the fixer');
});

t('assertNoLeak rejects a prompt that carries a rule id, a message or a scanner name', () => {
  const f = pathFinding();
  const good = R.buildFixPrompt(Object.assign(f, { triage: exploitable() }), {}, []);
  R.assertNoLeak(good, f);
  assert.throws(() => R.assertNoLeak(`${good}\nsee ${RULE_ID}`, f), /leaked scanner material|carries a rule id/);
  const msg = f.sites[0].observations[0].message.trim();
  assert.throws(() => R.assertNoLeak(`${good}\n${msg}`, f), /leaked scanner material/);
  assert.throws(() => R.assertNoLeak(`${good}\nreported by semgrep`, f), /leaked scanner material/);
});

t('assertNoLeak also rejects a rule id shape it has never seen on this finding', () => {
  const f = pathFinding();
  assert.throws(() => R.assertNoLeak('satisfy py/reflected-xss here', f), /carries a rule id/);
  // A source path that merely looks similar is not a rule id.
  R.assertNoLeak('edit js/some-file.js and ts/index.js', f);
});

t('passing a finding record wholesale is exactly what the guard catches', () => {
  const f = pathFinding();
  assert.throws(() => R.assertNoLeak(JSON.stringify(f), f), /leaked scanner material|carries a rule id/);
});

t('the triage prompt DOES carry the scanner claim, so the asymmetry is deliberate', () => {
  const f = pathFinding();
  const prompt = R.buildTriagePrompt(f, { testCommand: 'npm test', appHarness: null, witnessTiers: ['argued'] });
  assert.ok(prompt.includes(RULE_ID), 'the triage agent must see the claim it is asked to refute');
  assert.ok(prompt.includes('Refute this candidate'));
  assert.ok(prompt.includes('Attack it'), 'traced flows get the traced instruction');
});

t('the triage prompt switches on flow.kind', () => {
  const sinkOnly = fixtures().find((f) => f.flow.kind === 'sink_only');
  const p = R.buildTriagePrompt(sinkOnly, { witnessTiers: [] });
  assert.ok(p.includes('No dataflow path was provided'));
  assert.ok(!p.includes('claimed route from source to sink'), 'the traced instruction must not be sent');
});

t('the auditor is given the contract and the diff and no scanner material', () => {
  const f = pathFinding();
  f.triage = exploitable();
  const p = R.buildAuditPrompt(f, { enforcement_note: 'the name is now an index into a fixed list' }, DIFF_SRC);
  R.assertNoLeak(p, f);
  assert.ok(p.includes(f.triage.contract.invariant));
  assert.ok(p.includes('const safe = path.basename'));
  assert.ok(!p.includes(RULE_ID));
});

// ============================================================================

section('pre-resolve without an agent');

t('a finding whose every site is test or vendor code gets a real triage, not a skipped state', () => {
  const f = pathFinding();
  f.sites[0].locus.file = 'test/routes/files.test.js';
  const n = R.preResolve([f]);
  assert.strictEqual(n, 1);
  assert.strictEqual(f.triage.established_by, 'deterministic_prepass');
  assert.strictEqual(f.triage.verdict, 'not_exploitable');
  assert.strictEqual(f.triage.refutation.reason, 'test_or_fixture_or_generated_code');
  const errs = validate({ $ref: 'finding.schema.json#/$defs/triage' }, f.triage, SCHEMA_DIR);
  assert.deepStrictEqual(errs, [], errs.join('\n'));
});

t('real source is never pre-resolved', () => {
  const f = pathFinding();
  assert.strictEqual(R.pathPolicy(f), null);
  assert.strictEqual(R.preResolve([f]), 0);
  assert.strictEqual(f.triage, null);
});

t('one site outside the policy globs keeps the whole finding in scope', () => {
  const f = pathFinding();
  const real = JSON.parse(JSON.stringify(f.sites[0]));
  f.sites[0].locus.file = 'vendor/lib/read.js';
  f.sites.push(real);
  assert.strictEqual(R.pathPolicy(f), null);
});

t('each policy family matches', () => {
  const f = pathFinding();
  for (const p of ['test/a.js', 'node_modules/x/a.js', 'dist/a.js', 'a.min.js', 'db/migrate/001.js']) {
    f.sites = [{ ...f.sites[0], locus: { ...f.sites[0].locus, file: p } }];
    assert.ok(R.pathPolicy(f), `${p} should match path policy`);
  }
});

// ============================================================================

section('the pipeline, end to end with injected agents');

async function triageOnlyRun(over = {}) {
  const out = path.join(tmp(), 'run-1');
  const opts = baseOpts(); opts.out = out; opts.triageOnly = true;
  Object.assign(opts, over.opts || {});
  const deps = makeDeps({ agents: { '#/$defs/triage': over.triage || (() => ({ ok: true, data: notExploitable() })) } });
  const res = await R.run(opts, deps);
  return { res, deps, out };
}

t('a triage-only run writes one file per finding plus the shared artifacts', async () => {
  const { res, deps, out } = await triageOnlyRun();
  assert.strictEqual(res.findings.length, 3);
  for (const f of res.findings) {
    const p = path.join(out, 'findings', `${f.id}.json`);
    assert.ok(fs.existsSync(p), `missing ${p}`);
    assert.strictEqual(readJson(p).id, f.id);
  }
  assert.ok(fs.existsSync(path.join(out, 'run-metadata.json')));
  assert.ok(fs.existsSync(path.join(out, 'REMEDIATION.md')));
  assert.ok(fs.existsSync(path.join(out, 'HANDOFF.md')));
  assert.strictEqual(deps.state.agentCalls.length, 3, 'one triage call per finding');
  assert.strictEqual(deps.state.agentCalls[0].schemaPointer, '#/$defs/triage');
  assert.strictEqual(deps.state.agentCalls[0].schemaPath, path.join(ROOT, 'schema/agent-results.schema.json'));
});

t('the reporter is handed the meta the report spec requires', async () => {
  const { deps } = await triageOnlyRun();
  const m = deps.state.reports.remediation.m;
  for (const k of ['run_id', 'target', 'base_commit', 'policy', 'verify_level', 'run_status',
    'incomplete_reason', 'dropped', 'scanners']) {
    assert.ok(k in m, `meta is missing ${k}`);
  }
  assert.strictEqual(deps.state.reports.handoff.m.run_id, m.run_id);
});

t('the gate runs on every triaged finding and its decision is persisted', async () => {
  const { res } = await triageOnlyRun();
  for (const f of res.findings) {
    assert.ok(f.gate, `${f.id} was never gated`);
    assert.strictEqual(f.gate.action, 'report_only');
    assert.strictEqual(f.gate.reason, 'not_exploitable');
    assert.strictEqual(f.disposition.state, 'rejected');
  }
});

t('a below-threshold exploitable finding is reported, not fixed', async () => {
  const { res } = await triageOnlyRun({
    triage: () => ({ ok: true, data: exploitable({ severity: 'low' }) }),
    opts: { fixAt: 'high' },
  });
  for (const f of res.findings) {
    assert.strictEqual(f.gate.action, 'report_only');
    assert.strictEqual(f.gate.reason, 'below_threshold');
    assert.strictEqual(f.disposition.state, 'below_threshold');
    assert.strictEqual(f.disposition.severity, 'low');
  }
});

t('--triage-only leaves fixable findings unpatched and says so as incomplete', async () => {
  const { res } = await triageOnlyRun({ triage: () => ({ ok: true, data: exploitable() }) });
  assert.strictEqual(res.meta.run_status, 'incomplete');
  assert.ok(/triage_only/.test(res.meta.incomplete_reason), res.meta.incomplete_reason);
  assert.ok(res.findings.every((f) => f.patches.length === 0));
});

t('malformed agent output defers the finding instead of being repaired', async () => {
  const { res } = await triageOnlyRun({ triage: () => ({ ok: false, reason: 'unparseable', raw: '{' }) });
  for (const f of res.findings) {
    assert.strictEqual(f.triage, null, 'nothing may be invented from malformed output');
    assert.strictEqual(f.disposition.state, 'deferred');
    assert.strictEqual(f.disposition.reason, 'triage_agent_failed');
  }
});

t('a split is escalated rather than triaged under a contract that fits neither half', async () => {
  const { res } = await triageOnlyRun({
    triage: () => ({ ok: true, data: { split: [{ site_lines: [9], why: 'a' }, { site_lines: [10], why: 'b' }] } }),
  });
  assert.strictEqual(res.findings[0].disposition.state, 'deferred');
  assert.strictEqual(res.findings[0].disposition.reason, 'split_requested');
});

t('re-running the same command is the resume path and spends nothing twice', async () => {
  const out = path.join(tmp(), 'run-1');
  const opts = baseOpts(); opts.out = out; opts.triageOnly = true;
  const mk = () => makeDeps({ agents: { '#/$defs/triage': () => ({ ok: true, data: notExploitable() }) } });
  const first = mk();
  await R.run(opts, first);
  assert.strictEqual(first.state.agentCalls.length, 3);
  const second = mk();
  const res2 = await R.run(opts, second);
  assert.strictEqual(second.state.agentCalls.length, 0, 'a resumed run must re-triage nothing');
  assert.strictEqual(res2.meta.counts.resumed, 3);
  assert.ok(res2.findings.every((f) => stageOf(f) === 'done'));
});

t('--max-findings bounds the run and the rest are deferred on disk, never dropped', async () => {
  const out = path.join(tmp(), 'run-1');
  const opts = baseOpts(); opts.out = out; opts.maxFindings = 1;
  const deps = makeDeps({ agents: { '#/$defs/triage': () => ({ ok: true, data: notExploitable() }) } });
  const res = await R.run(opts, deps);
  assert.strictEqual(deps.state.agentCalls.length, 1, 'the budget must bound agent spend');
  assert.strictEqual(res.meta.counts.deferred, 2);
  assert.strictEqual(res.meta.run_status, 'incomplete');
  assert.ok(/max_findings=1/.test(res.meta.incomplete_reason), res.meta.incomplete_reason);
  const untriaged = res.findings.filter((f) => !f.triage);
  assert.strictEqual(untriaged.length, 2);
  for (const f of untriaged) {
    const p = path.join(out, 'findings', `${f.id}.json`);
    assert.ok(fs.existsSync(p), 'a deferred finding is still written');
    assert.strictEqual(readJson(p).triage, null);
  }
});

t('a deferred finding is picked up by the next run', async () => {
  const out = path.join(tmp(), 'run-1');
  const one = baseOpts(); one.out = out; one.maxFindings = 1;
  const agents = { '#/$defs/triage': () => ({ ok: true, data: notExploitable() }) };
  await R.run(one, makeDeps({ agents }));
  const two = baseOpts(); two.out = out;
  const d2 = makeDeps({ agents });
  const res = await R.run(two, d2);
  assert.strictEqual(d2.state.agentCalls.length, 2, 'the next run picks up exactly what was deferred');
  assert.strictEqual(res.meta.run_status, 'complete');
  assert.ok(res.findings.every((f) => f.disposition));
});

t('every scanner failing is fatal rather than a clean report', async () => {
  const opts = baseOpts(); opts.out = path.join(tmp(), 'run-1'); opts.scans = tmp();
  await assert.rejects(R.run(opts, makeDeps()), /every requested scanner failed/);
});

t('a scanner that is absent is recorded and the run continues on what is left', async () => {
  const dir = tmp();
  fs.copyFileSync(path.join(ROOT, 'test/fixtures/semgrep.json'), path.join(dir, 'semgrep.json'));
  const opts = baseOpts(); opts.out = path.join(tmp(), 'run-1'); opts.scans = dir; opts.triageOnly = true;
  const deps = makeDeps({ agents: { '#/$defs/triage': () => ({ ok: true, data: notExploitable() }) } });
  const res = await R.run(opts, deps);
  const ql = res.meta.scanners.find((s) => s.name === 'codeql');
  assert.strictEqual(ql.status, 'absent');
  assert.ok(res.findings.length > 0);
});

t('normalized findings are validated before anything else runs', () => {
  const res = R.normalizeAndValidate(raw, REPO, 'run-test');
  assert.strictEqual(res.findings.length, 3);
  // An empty run id makes every record fail the schema, which is the cheapest proof that the
  // validator is actually in the path rather than decorating it.
  assert.throws(() => R.normalizeAndValidate(raw, REPO, ''), /do not validate/);
});

// ============================================================================

section('fix and verify');

async function fixRun(over = {}) {
  const out = path.join(tmp(), 'run-1');
  const opts = baseOpts();
  opts.out = out; opts.scanners = ['semgrep']; opts.verify = over.verify || 'cheap';
  const witness = over.witness || {};
  const agents = {
    '#/$defs/triage': (o) => ({ ok: true, data: exploitable({ contract: witness }) }),
    '#/$defs/fix': over.fix || (() => ({
      ok: true,
      data: { outcome: 'patched', declared_files: ['src/routes/files.js'], enforcement_note: 'the name is now an index into a fixed list' },
    })),
    '#/$defs/audit': over.audit || (() => ({
      ok: true,
      data: {
        verdict: 'enforces_invariant',
        trace: [{ step: 'the name is normalized', loc: { file: 'src/routes/files.js', line: 8, note: 'basename' } }],
        stopped_at: { file: 'src/routes/files.js', line: 9, note: 'rejected' },
        uncovered_siblings: [], explanation: 'the traversal never reaches the read',
      },
    })),
  };
  const deps = makeDeps({ agents, diff: over.diff, npm: over.npm });
  const res = await R.run(opts, deps);
  return { res, deps, out };
}

t('the fixer prompt sent by the live pipeline carries no rule id', async () => {
  const { deps } = await fixRun();
  const fixPrompts = deps.state.agentCalls.filter((c) => c.schemaPointer === '#/$defs/fix');
  assert.ok(fixPrompts.length > 0, 'the fix stage must have run');
  for (const c of fixPrompts) {
    assert.ok(!c.prompt.includes(RULE_ID), 'the live fixer prompt leaked a rule id');
    assert.ok(!/semgrep|codeql/i.test(c.prompt), 'the live fixer prompt leaked a scanner name');
    assert.ok(c.prompt.includes('resolves inside'), 'the live fixer prompt lost the invariant');
  }
});

t('the fixer is given no scanner tool and runs inside its own worktree', async () => {
  const { deps, out } = await fixRun();
  const c = deps.state.agentCalls.find((x) => x.schemaPointer === '#/$defs/fix');
  assert.ok(c.cwd.startsWith(path.join(out, 'worktrees')), c.cwd);
  for (const tool of c.allowedTools) assert.ok(!/semgrep|codeql/i.test(tool), tool);
});

t('one worktree and one branch per finding, off the base commit', async () => {
  const { res, deps } = await fixRun();
  const fixed = res.findings.filter((f) => f.patches.length);
  assert.ok(fixed.length > 0);
  for (const f of fixed) {
    const want = `sast-fix/${R.refSafe(res.runId)}/${f.id}/1`;
    assert.strictEqual(f.patches[0].branch, want);
    assert.ok(deps.state.execCalls.some((c) => c.includes(`worktree add -b ${want}`)));
  }
  assert.ok(deps.state.execCalls.some((c) => c.endsWith('a'.repeat(40))), 'branches must be cut off base');
});

t('at cheap, the witness obligations are absent from the record, not faked', async () => {
  const { res } = await fixRun({ verify: 'cheap' });
  const f = res.findings.find((x) => x.patches.length);
  const v = f.patches[0].verification;
  for (const o of ['differential_witness', 'functional_control', 'hostile_auditor']) {
    assert.ok(!(o in v), `${o} must not be written at verify=cheap`);
  }
  for (const o of VERIFY_LEVELS.cheap) assert.ok(o in v, `${o} must be evaluated at verify=cheap`);
  assert.strictEqual(v.frozen_target.status, 'pass');
  assert.strictEqual(v.deterministic_guard.status, 'pass');
  assert.strictEqual(v.no_new_findings.status, 'pass');
});

t('a fix verified at cheap is never described as fully verified', async () => {
  const { res } = await fixRun({ verify: 'cheap' });
  const f = res.findings.find((x) => x.patches.length);
  assert.strictEqual(f.disposition.verify_level, 'cheap');
  assert.deepStrictEqual(f.disposition.skipped_obligations.sort(),
    ['differential_witness', 'functional_control', 'hostile_auditor'].sort());
  assert.strictEqual(f.disposition.state, 'fixed_unwitnessed', 'an argued witness can never reach fixed');
});

t('a non-argued witness tier reaches fixed', async () => {
  const { res } = await fixRun({
    witness: { witness: EXEC_WITNESS, writable_scope: ['src/**', 'test/**'] },
    diff: DIFF_SRC + DIFF_TEST,
  });
  const f = res.findings.find((x) => x.patches.length);
  assert.strictEqual(f.disposition.state, 'fixed', JSON.stringify(f.patches[0].verification));
  assert.strictEqual(f.disposition.witness_tier, 'executable');
});

t('verify=none records the patch and skips all seven, writing no obligation at all', async () => {
  const { res } = await fixRun({ verify: 'none' });
  const f = res.findings.find((x) => x.patches.length);
  assert.deepStrictEqual(Object.keys(f.patches[0].verification), []);
  assert.strictEqual(f.disposition.skipped_obligations.length, 7);
  assert.strictEqual(res.meta.verify_level, 'none');
  assert.deepStrictEqual(res.meta.verify_obligations, []);
});

t('an empty diff fails as no_diff and spends no further obligation', async () => {
  const { res } = await fixRun({ diff: '' });
  const f = res.findings.find((x) => x.patches.length);
  const v = f.patches[0].verification;
  assert.strictEqual(v.deterministic_guard.status, 'fail');
  assert.strictEqual(v.deterministic_guard.reason, 'no_diff');
  assert.ok(!('no_new_findings' in v), 'verification must short-circuit on the first failure');
  assert.strictEqual(f.disposition.state, 'fix_failed');
});

t('a suppression comment is caught by the guard before a test or a scan runs', async () => {
  const bad = `diff --git a/src/routes/files.js b/src/routes/files.js
--- a/src/routes/files.js
+++ b/src/routes/files.js
+  // nosemgrep
   const target = path.join(ROOT, name);
`;
  const { res, deps } = await fixRun({ diff: bad });
  const f = res.findings.find((x) => x.patches.length);
  assert.strictEqual(f.patches[0].verification.deterministic_guard.status, 'fail');
  assert.ok(/suppression_comment_added/.test(f.patches[0].verification.deterministic_guard.reason));
  assert.ok(!deps.state.execCalls.some((c) => c.startsWith('npm')), 'no suite runs after the guard fails');
});

t('a red suite on the patch tree costs a second attempt and then stops at two', async () => {
  const { res, deps } = await fixRun({ npm: (cwd) => (cwd.includes('worktrees/base') ? 0 : 1) });
  const f = res.findings.find((x) => x.patches.length);
  assert.strictEqual(f.patches.length, 2, 'there is no attempt three');
  assert.strictEqual(f.patches[0].verification.regression_suite.status, 'fail');
  assert.strictEqual(f.disposition.state, 'fix_failed');
  assert.strictEqual(f.disposition.attempts, 2);
  const prompts = deps.state.agentCalls.filter((c) => c.schemaPointer === '#/$defs/fix').map((c) => c.prompt);
  assert.ok(/previous attempt failed/i.test(prompts[1]), 'attempt two gets the typed failures');
  assert.ok(prompts[1].includes('regression_suite'));
  assert.ok(!prompts[1].includes(RULE_ID), 'attempt two is still not shown the rule');
});

t('a suite already red on base is unavailable rather than blamed on the patch', async () => {
  const { res } = await fixRun({ npm: () => 1 });
  const f = res.findings.find((x) => x.patches.length);
  assert.strictEqual(f.patches[0].verification.regression_suite.status, 'unavailable');
  assert.strictEqual(f.patches[0].verification.regression_suite.reason, 'suite_red_on_base');
  assert.strictEqual(f.disposition.state, 'fixed_unwitnessed', 'regression_suite alone may be unavailable');
});

t('the rescan records original_absent and gates only on findings the patch introduced', async () => {
  const { res } = await fixRun();
  const f = res.findings.find((x) => x.patches.length);
  const v = f.patches[0].verification;
  assert.strictEqual(typeof v.rescan.original_absent, 'boolean');
  assert.strictEqual(v.rescan.original_absent, true);
  assert.strictEqual(v.no_new_findings.status, 'pass', 'a quiet rescan is not what passes this');
  assert.ok(!('original_absent' in v.no_new_findings), 'the obligation must not read the quiet rescan');
});

t('cannot_fix is a real outcome and does not burn a second attempt', async () => {
  const { res, deps } = await fixRun({
    fix: () => ({ ok: true, data: { outcome: 'cannot_fix', reason: 'the enforcement point is generated code' } }),
  });
  const attempted = res.findings.filter((x) => x.patches.length);
  for (const f of attempted) {
    assert.strictEqual(f.patches.length, 1, 'cannot_fix must not trigger attempt two');
    assert.strictEqual(f.disposition.state, 'fix_declined');
  }
  assert.strictEqual(deps.state.agentCalls.filter((c) => c.schemaPointer === '#/$defs/fix').length,
    attempted.length, 'exactly one fixer call per declining finding');
});

t('at full, the auditor runs and a silences_rule verdict sinks the fix', async () => {
  const { res, deps } = await fixRun({
    verify: 'full',
    witness: { witness: EXEC_WITNESS, writable_scope: ['src/**', 'test/**'] },
    diff: DIFF_SRC + DIFF_TEST,
    audit: () => ({
      ok: true,
      data: {
        verdict: 'silences_rule', trace: [{ step: 'the value still reaches the read', loc: { file: 'src/routes/files.js', line: 10, note: 'sink' } }],
        stopped_at: null, uncovered_siblings: [], explanation: 'the traversal still resolves outside the root',
      },
    }),
  });
  const f = res.findings.find((x) => x.patches.length);
  assert.ok(deps.state.agentCalls.some((c) => c.schemaPointer === '#/$defs/audit'), 'the auditor must run at full');
  assert.strictEqual(f.patches[0].verification.hostile_auditor.status, 'fail');
  assert.strictEqual(f.disposition.state, 'fix_failed');
});

t('the auditor runs even when an earlier obligation already failed', async () => {
  const { deps } = await fixRun({ verify: 'full', diff: '' });
  assert.ok(deps.state.agentCalls.some((c) => c.schemaPointer === '#/$defs/audit'),
    'attempt two needs a real explanation, so the audit is not short-circuited');
});

t('no test command and no override degrades to triage-only instead of patching blind', async () => {
  // A copy of the fixture app with its test script removed, so the findings still normalize
  // against real source while the suite the verifier needs is genuinely missing.
  const copy = path.join(tmp(), 'vuln-app');
  fs.cpSync(REPO, copy, { recursive: true });
  const pkg = readJson(path.join(copy, 'package.json'));
  delete pkg.scripts.test;
  fs.writeFileSync(path.join(copy, 'package.json'), JSON.stringify(pkg, null, 2));
  assert.strictEqual(R.discoverTestCommand(copy), null);

  const opts = baseOpts(); opts.out = path.join(tmp(), 'run-1'); opts.target = copy;
  const deps = makeDeps({ agents: { '#/$defs/triage': () => ({ ok: true, data: exploitable() }) } });
  const res = await R.run(opts, deps);
  assert.ok(res.findings.length > 0, 'the copy must still normalize');
  assert.ok(res.findings.every((f) => f.patches.length === 0), 'nothing may be patched unverified');
  assert.ok(/no_test_command_discoverable/.test(res.meta.incomplete_reason), res.meta.incomplete_reason);
  assert.strictEqual(deps.state.agentCalls.filter((c) => c.schemaPointer === '#/$defs/fix').length, 0);
});

t('--allow-unverified-fixes is the only way past that degrade', async () => {
  const copy = path.join(tmp(), 'vuln-app');
  fs.cpSync(REPO, copy, { recursive: true });
  const pkg = readJson(path.join(copy, 'package.json'));
  delete pkg.scripts.test;
  fs.writeFileSync(path.join(copy, 'package.json'), JSON.stringify(pkg, null, 2));

  const opts = baseOpts();
  opts.out = path.join(tmp(), 'run-1'); opts.target = copy;
  opts.scanners = ['semgrep']; opts.allowUnverifiedFixes = true;
  const deps = makeDeps({
    agents: {
      '#/$defs/triage': () => ({ ok: true, data: exploitable() }),
      '#/$defs/fix': () => ({ ok: true, data: { outcome: 'cannot_fix', reason: 'declined' } }),
    },
  });
  await R.run(opts, deps);
  assert.ok(deps.state.agentCalls.some((c) => c.schemaPointer === '#/$defs/fix'), 'the override must reach the fix stage');
});

t('a target that is not a git repository never reaches the fix stage', async () => {
  const opts = baseOpts(); opts.out = path.join(tmp(), 'run-1');
  const deps = makeDeps({ base: null, agents: { '#/$defs/triage': () => ({ ok: true, data: exploitable() }) } });
  const res = await R.run(opts, deps);
  assert.strictEqual(res.meta.base_commit, null);
  assert.ok(res.findings.every((f) => f.patches.length === 0));
  assert.ok(/not_a_git_repository/.test(res.meta.incomplete_reason), res.meta.incomplete_reason);
});

t('the partitioner decides the waves and the orchestrator honours them', async () => {
  const seen = [];
  const out = path.join(tmp(), 'run-1');
  const opts = baseOpts();
  opts.out = out; opts.scanners = ['semgrep'];
  const deps = makeDeps({
    partition: (fs_) => { seen.push(fs_.map((f) => f.id)); return fs_.map((f) => [f.id]); },
    agents: {
      '#/$defs/triage': () => ({ ok: true, data: exploitable() }),
      '#/$defs/fix': () => ({ ok: true, data: { outcome: 'cannot_fix', reason: 'no' } }),
    },
  });
  const res = await R.run(opts, deps);
  assert.strictEqual(seen.length, 1, 'partition is called once, with the fixable set');
  assert.ok(seen[0].length > 0);
  assert.strictEqual(res.meta.counts.waves, seen[0].length);
});

// ============================================================================

section('end state');

t('every finding ends terminal, or the run says incomplete with its exact reason', async () => {
  for (const [name, over] of [
    ['rejected', { triage: () => ({ ok: true, data: notExploitable() }) }],
    ['deferred', { triage: () => ({ ok: false, reason: 'bad' }) }],
  ]) {
    const { res } = await triageOnlyRun(over);
    const open = res.findings.filter((f) => !f.disposition);
    if (open.length) {
      assert.strictEqual(res.meta.run_status, 'incomplete', name);
      assert.ok(res.meta.incomplete_reason, name);
    } else {
      assert.strictEqual(res.meta.run_status, 'complete', `${name}: ${res.meta.incomplete_reason}`);
    }
  }
});

t('the fake triage records used above are themselves schema-valid', () => {
  for (const obj of [exploitable(), notExploitable(), exploitable({ contract: { witness: EXEC_WITNESS } })]) {
    const errs = validate({ $ref: 'agent-results.schema.json#/$defs/triage' }, obj, SCHEMA_DIR);
    assert.deepStrictEqual(errs, [], errs.join('\n'));
  }
});

section('prompt schemas: what the prompt shows is what the validator enforces');

t('the triage return schema carries no unresolved cross-file pointer', () => {
  const b = R.bundleDef('triage');
  assert.strictEqual((b.match(/finding\.schema\.json#/g) || []).length, 0,
    'a $ref to a file the agent was never given is a pointer it has to guess past');
  JSON.parse(b);
});

t('every local $defs pointer in the triage schema resolves inside the bundle', () => {
  const o = JSON.parse(R.bundleDef('triage'));
  const pointers = new Set();
  const walk = (n) => {
    if (Array.isArray(n)) return n.forEach(walk);
    if (!n || typeof n !== 'object') return;
    for (const [k, v] of Object.entries(n)) {
      if (k === '$ref' && typeof v === 'string') pointers.add(v.replace('#/$defs/', ''));
      else walk(v);
    }
  };
  walk(o);
  const missing = [...pointers].filter((k) => !(k in o.$defs));
  assert.deepStrictEqual(missing, [], `dangling: ${missing.join(', ')}`);
});

t('the triage schema states the envelope and the per-tier witness fields', () => {
  const b = R.bundleDef('triage');
  // The two shapes a live run actually got wrong before the schema was bundled.
  for (const k of ['verdict', 'established_by', 'contract', 'not_exploitable', 'undecidable',
                   'argued', 'expected_pre_fix', 'enforcement_point', 'forbidden_resolutions']) {
    assert.ok(b.includes(k), `triage schema omits ${k}, so the agent must guess it`);
  }
});

t('the audit schema is bundled too, and code_ref is spelled out', () => {
  const b = R.bundleDef('audit');
  assert.strictEqual((b.match(/finding\.schema\.json#/g) || []).length, 0);
  const o = JSON.parse(b);
  assert.ok('code_ref' in o.$defs, 'stopped_at needs code_ref inlined or the agent guesses it');
  for (const k of ['file', 'line', 'note']) assert.ok(b.includes(k), `code_ref omits ${k}`);
});

t('a bundled schema carries no scanner vocabulary into a fixer prompt', () => {
  const b = R.bundleDef('fix').toLowerCase();
  for (const t2 of ['semgrep', 'codeql', 'nosemgrep', 'sarif', 'rule_id']) {
    assert.ok(!b.includes(t2), `fix schema would leak ${t2}`);
  }
});

section('branches: a second run against the same repository does not collide');

t('fix branches carry the run id, so two runs name different branches', () => {
  const a = `sast-fix/${R.refSafe('run-1')}/f_0000000000000001/1`;
  const b = `sast-fix/${R.refSafe('run-2')}/f_0000000000000001/1`;
  assert.notStrictEqual(a, b, 'identical names are what made the second live run die at worktree add');
});

t('an operator-supplied run id is made safe for a git ref', () => {
  for (const [input, want] of [['run 3', 'run-3'], ['..evil', 'evil'], ['a~b^c', 'a-b-c'],
                               ['x:y', 'x-y'], ['-lead', 'lead'], ['trail.', 'trail'], ['', 'run']]) {
    assert.strictEqual(R.refSafe(input), want, JSON.stringify(input));
  }
});

section('leaks: every fixer-visible field is guarded, and a refusal never crashes the run');

const FSCHEMA = JSON.parse(fs.readFileSync(path.join(ROOT, 'schema/finding.schema.json'), 'utf8'));
const contractErrs = (c) => validate({ $ref: '#/$defs/security_contract', $defs: FSCHEMA.$defs }, c, SCHEMA_DIR);

t('forbidden_resolutions naming the scanner is rejected at the triage boundary', () => {
  // Verbatim from a live triage that crashed a run.
  const c = contract({ forbidden_resolutions:
    ['inline or file-level comments that silence the tool (nosemgrep, lgtm, codeql suppression)'] });
  assert.ok(contractErrs(c).length > 0, 'this string reached a real fixer prompt');
});

t('the same rule written by effect is accepted', () => {
  assert.deepStrictEqual(contractErrs(contract({ forbidden_resolutions:
    ['a comment or annotation that turns off checking for a line, a block or a file'] })), []);
});

t('violating inputs that look like hosts and paths are not mistaken for rule ids', () => {
  for (const v of ['http://evil.attacker.example.com/', '../../static/js/app.js', '../../secret.txt']) {
    assert.deepStrictEqual(contractErrs(contract({ violating_input: v })), [], v);
  }
});

t('a leak that slips past the schema refuses that finding and the run still completes', async () => {
  let fixerCalls = 0;
  const { res, out } = await fixRun({
    witness: { violating_input: RULE_ID },
    fix: () => { fixerCalls++; return { ok: true, data: { outcome: 'patched', declared_files: ['src/routes/files.js'], enforcement_note: 'x' } }; },
  });
  assert.strictEqual(fixerCalls, 0, 'a leaking prompt must never reach the fixer');
  const refused = res.findings.flatMap((f) => f.patches).filter((p) => p.outcome === 'refused');
  assert.ok(refused.length > 0, 'the refusal is recorded on the patch');
  assert.ok(refused.every((p) => p.detail.startsWith('fixer_prompt_leak')), refused.map((p) => p.detail).join('; '));
  assert.ok(fs.existsSync(path.join(out, 'run-metadata.json')), 'the run wrote its metadata instead of crashing');
  assert.ok(fs.existsSync(path.join(out, 'REMEDIATION.md')), 'the run wrote its report instead of crashing');
});

// ============================================================================

(async () => {
  for (const [name, fn] of tests) {
    if (!fn) { console.log(`\n${name}`); continue; }
    try { await fn(); pass++; console.log(`  ok   ${name}`); }
    catch (e) { fail++; console.log(`  FAIL ${name}\n         ${e.message}`); }
  }
  for (const d of tmpDirs) { try { fs.rmSync(d, { recursive: true, force: true }); } catch { /* best effort */ } }
console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail === 0 ? 0 : 1);
})();
