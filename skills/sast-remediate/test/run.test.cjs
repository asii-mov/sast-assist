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
const S = require(path.join(ROOT, 'bin/scan.cjs'));
const { normalize, makeRepo } = require(path.join(ROOT, 'bin/normalize.cjs'));
const { validate } = require(path.join(ROOT, 'bin/validate.cjs'));
const { VERIFY_LEVELS, stageOf } = require(path.join(ROOT, 'bin/stage.cjs'));
const { renderRemediation, renderHandoff } = require(path.join(ROOT, 'bin/report.cjs'));

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

const CACHE = tmp();
process.env.XDG_CACHE_HOME = CACHE;

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
      if (rest[0] === 'commit' && o.commitFails) return { status: 1, stdout: '', stderr: 'Author identity unknown' };
      return okr();
    }
    if (cmd === 'npm') return { status: state.npm(opt.cwd || ''), stdout: '', stderr: 'suite output' };
    if (cmd === 'semgrep') {
      const out = (args.find((a) => a.startsWith('--json-output=')) || '=').split('=')[1];
      fs.mkdirSync(path.dirname(out), { recursive: true });
      const payload = typeof state.rescan === 'function' ? state.rescan(args[args.length - 1]) : state.rescan;
      fs.writeFileSync(out, JSON.stringify(payload));
      return okr();
    }
    return okr();
  };

  const deps = {
    exec,
    onPath: o.onPath || (() => true),
    log: () => {},
    now: () => '2026-01-01T00:00:00.000Z',
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
  assert.deepStrictEqual(o.scanConfig, { semgrep: ['p/default'], codeql_suite: 'security-extended' });
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

t('--witness accepts dynamic and nothing else', () => {
  assert.strictEqual(R.parseArgs(['--target=/x']).witness, null);
  assert.strictEqual(R.parseArgs(['--target=/x', '--witness=dynamic']).witness, 'dynamic');
  assert.throws(() => R.parseArgs(['--target=/x', '--witness=executable']), /--witness must be dynamic/);
});

t('--semgrep-config is repeatable and comma separated, and a local rules file is stored absolute', () => {
  const dir = tmp();
  const rules = path.join(dir, 'rules.yml');
  fs.writeFileSync(rules, 'rules: []\n');
  const o = R.parseArgs(['--target=/x', '--semgrep-config=p/trailofbits',
    `--semgrep-config=p/golang,${path.relative(process.cwd(), rules)}`, '--codeql-suite=security-and-quality']);
  assert.deepStrictEqual(o.scanConfig, { semgrep: ['p/trailofbits', 'p/golang', rules], codeql_suite: 'security-and-quality' });
});

t('an empty --semgrep-config or a --codeql-suite that is not a suite name is refused', () => {
  assert.throws(() => R.parseArgs(['--target=/x', '--semgrep-config=']), /--semgrep-config needs a value/);
  assert.throws(() => R.parseArgs(['--target=/x', '--semgrep-config']), /--semgrep-config needs a value/);
  assert.throws(() => R.parseArgs(['--target=/x', '--codeql-suite=../x.qls']), /--codeql-suite must be/);
});

t('--dry-run prints the plan, names the skipped obligations, and writes nothing', async () => {
  const out = path.join(tmp(), 'never');
  const opts = baseOpts(); opts.dryRun = true; opts.out = out; opts.verify = 'cheap';
  const lines = R.planLines(opts, REPO, out, 'abc123');
  const text = lines.join('\n');
  assert.ok(/verify\s+cheap/.test(text), text);
  assert.ok(text.includes('differential_witness'), 'the plan must name what cheap does not check');
  assert.ok(text.includes('scan normalize pre-resolve triage gate fix verify report'));
  assert.ok(/worktrees\s+\S+sast-remediate\/worktrees\//.test(text), text);
  assert.ok(text.includes('scan config   semgrep p/default; codeql security-extended'), text);
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
  // A scanner name in repository text (the whole prompt) is not refused; the same name in
  // triage-authored prose still is.
  const named = pathFinding();
  named.triage = exploitable({ contract: { invariant: 'the value reported by semgrep must be escaped' } });
  assert.throws(() => R.assertNoLeak(R.buildFixPrompt(named, {}, []), named), /leaked scanner material: "semgrep"/);
});

t('assertNoLeak also rejects a rule id shape it has never seen on this finding', () => {
  const f = pathFinding();
  f.triage = exploitable({ contract: { enforcement_point: {
    file: 'src/routes/files.js', symbol: 'read', rationale: 'satisfy py/reflected-xss here' } } });
  assert.throws(() => R.assertNoLeak(R.buildFixPrompt(f, {}, []), f), /carries a rule id: "py\/reflected-xss"/);
  // A source path that merely looks similar is not a rule id, checked against a finding whose
  // contract prose carries none.
  R.assertNoLeak('edit js/some-file.js and ts/index.js', pathFinding());
});

t('passing a finding record wholesale is exactly what the guard catches', () => {
  const f = pathFinding();
  assert.throws(() => R.assertNoLeak(JSON.stringify(f), f), /leaked scanner material|carries a rule id/);
});

t('repository source that looks like a rule id or names a scanner still reaches the fixer', () => {
  const f = pathFinding();
  f.triage = exploitable();
  f.context.enclosing_excerpt = [
    '      - uses: actions/setup-node@v4',
    "app.use(express.static('/static/js/admin-panel/main.js'));",
    "const util = require('./go/some-pkg/util');",
    '// notes live in docs/semgrep-notes',
    '      - uses: github/codeql-action/init@v3',
    '// this route requires login',
    // A rule-id-shaped path that IS a clean match for RULE_ID_FORM. It must still pass, because
    // the form check reads only triage-authored prose, never the repository excerpt.
    '// helper lives under rb/legacy-handler in this repo',
  ].join('\n');
  const prompt = R.buildFixPrompt(f, {}, []);
  assert.ok(prompt.includes('actions/setup-node@v4'), 'the excerpt must reach the prompt');
  assert.strictEqual(R.leakError(prompt, f), null);
});

t("this finding's own rule id and message are refused even inside the source excerpt", () => {
  const f = pathFinding();
  f.triage = exploitable();
  const msg = f.sites.flatMap((s) => s.observations).find((o) => o.rule_id === RULE_ID).message.trim();
  f.context.enclosing_excerpt = `// ${RULE_ID}`;
  assert.strictEqual(R.leakError(R.buildFixPrompt(f, {}, []), f), `fixer prompt leaked scanner material: "${RULE_ID}"`);
  f.context.enclosing_excerpt = `// ${msg}`;
  assert.match(R.leakError(R.buildFixPrompt(f, {}, []), f), /^fixer prompt leaked scanner material: /);
});

t('a path given as the violating value is not a rule id', () => {
  const f = pathFinding();
  f.triage = exploitable({ contract: { violating_input: '../../static/js/admin-panel/main.js' } });
  assert.strictEqual(R.leakError(R.buildFixPrompt(f, {}, []), f), null);
  f.triage = exploitable({ contract: { violating_input: 'py/reflected-xss' } });
  assert.strictEqual(R.leakError(R.buildFixPrompt(f, {}, []), f), 'fixer prompt carries a rule id: "py/reflected-xss"');
});

t("the auditor sees the fixer's own words about the vulnerability class", () => {
  const f = pathFinding();
  f.triage = exploitable();
  const name = f.sites.flatMap((s) => s.observations).find((o) => o.rule_name && !o.rule_name.startsWith('http')).rule_name;
  const p = R.buildAuditPrompt(f, { enforcement_note: `closes the ${name} by resolving against the public root` }, DIFF_SRC);
  assert.strictEqual(R.leakError(p, f), null);
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

t('the dynamic tier is offered to triage only when asked for and a harness exists', async () => {
  const a = await triageOnlyRun();
  for (const c of a.deps.state.agentCalls) assert.ok(c.prompt.includes('enabled witness tiers: argued\n'), c.prompt);

  const b = await triageOnlyRun({ opts: { witness: 'dynamic' } });
  for (const c of b.deps.state.agentCalls) {
    assert.ok(c.prompt.includes('enabled witness tiers: dynamic, argued'), c.prompt);
  }

  const copy = path.join(tmp(), 'vuln-app');
  fs.cpSync(REPO, copy, { recursive: true });
  fs.rmSync(path.join(copy, 'package.json'));
  const d = await triageOnlyRun({ opts: { witness: 'dynamic', target: copy } });
  for (const c of d.deps.state.agentCalls) {
    assert.ok(c.prompt.includes('enabled witness tiers: argued\n'), c.prompt);
    assert.ok(c.prompt.includes('app harness: none discovered'), c.prompt);
  }
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

t('a failed triage call leaves the finding open for the next run', async () => {
  const { res } = await triageOnlyRun({ triage: () => ({ ok: false, reason: 'unparseable', raw: '{' }) });
  for (const f of res.findings) {
    assert.strictEqual(f.triage, null, 'nothing may be invented from malformed output');
    assert.strictEqual(f.disposition, null);
    assert.strictEqual(stageOf(f, 'cheap'), 'triage');
  }
  assert.strictEqual(res.meta.run_status, 'incomplete');
  assert.strictEqual(res.meta.counts.agent_failures, 3);
  assert.strictEqual(res.meta.counts.triaged, 0);
  assert.ok(res.meta.agent_failures.every((x) => x.stage === 'triage' && x.reason === 'unparseable'));
  assert.ok(/agent_failed: 3 agent call\(s\) failed and will be retried on the next run/.test(res.meta.incomplete_reason),
    res.meta.incomplete_reason);
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
  assert.ok(res2.findings.every((f) => stageOf(f, res2.meta.verify_level) === 'done'));
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

const PATCHED = { ok: true, data: { outcome: 'patched', declared_files: ['src/routes/files.js'],
  enforcement_note: 'the name is now an index into a fixed list' } };

const semgrepCalls = (deps) => deps.state.execCalls.filter((c) => c.startsWith('semgrep '));

async function fixRun(over = {}) {
  const out = over.out || path.join(tmp(), 'run-1');
  const opts = baseOpts({ argv: over.argv });
  opts.out = out; opts.scanners = over.scanners || ['semgrep']; opts.verify = over.verify || 'cheap';
  if (over.scans) opts.scans = over.scans;
  const witness = over.witness || {};
  const agents = {
    '#/$defs/triage': (o) => ({ ok: true, data: exploitable({ contract: witness }) }),
    '#/$defs/fix': over.fix || (() => PATCHED),
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
  const deps = makeDeps({ agents, diff: over.diff, npm: over.npm, rescan: over.rescan, onPath: over.onPath,
    commitFails: over.commitFails });
  if (over.recordedLevel) {
    fs.mkdirSync(out, { recursive: true });
    fs.writeFileSync(path.join(out, 'run-metadata.json'), JSON.stringify({ verify_level: over.recordedLevel }));
  }
  if (over.recordedMeta) {
    fs.mkdirSync(out, { recursive: true });
    fs.writeFileSync(path.join(out, 'run-metadata.json'), JSON.stringify(over.recordedMeta));
  }
  const res = await R.run(opts, deps);
  return { res, deps, out };
}

t('the baseline scan runs the configured semgrep rules and CodeQL suite', async () => {
  const opts = R.parseArgs([`--target=${REPO}`, `--out=${path.join(tmp(), 'run-1')}`,
    '--semgrep-config=p/trailofbits', '--codeql-suite=security-and-quality', '--triage-only']);
  const deps = makeDeps({ rescan: { results: [pathHit(null, 9)], errors: [] },
    agents: { '#/$defs/triage': () => ({ ok: true, data: notExploitable() }) } });
  const res = await R.run(opts, deps);
  const calls = semgrepCalls(deps);
  assert.strictEqual(calls.length, 1);
  assert.ok(calls[0].startsWith('semgrep scan --config p/trailofbits --json-output='), calls[0]);
  assert.ok(deps.state.execCalls.some(
    (c) => c.includes('codeql/javascript-queries:codeql-suites/javascript-security-and-quality.qls')));
  const semgrepMeta = res.meta.scanners.find((s) => s.name === 'semgrep');
  assert.strictEqual(semgrepMeta.status, 'ok');
  assert.strictEqual(semgrepMeta.config, 'p/trailofbits');
});

t("the rescan runs the run's semgrep rules, not p/default", async () => {
  const { res, deps } = await fixRun({ argv: ['--semgrep-config=p/trailofbits'] });
  const calls = semgrepCalls(deps);
  assert.ok(calls.length >= 1);
  for (const c of calls) {
    assert.ok(c.includes('--config p/trailofbits'), c);
    assert.ok(!c.includes('p/default'), c);
  }
  const f = res.findings.find((x) => x.id === PATH_ID);
  assert.strictEqual(f.patches[0].verification.rescan.scanners[0].config, 'p/trailofbits');
});

t('a fresh run records its scanner config before any fixer runs', async () => {
  let onDisk = null;
  const out = path.join(tmp(), 'run-1');
  await fixRun({
    out,
    argv: ['--semgrep-config=p/trailofbits'],
    fix: () => {
      onDisk = readJson(path.join(out, 'run-metadata.json')).scan_config;
      return { ok: false, reason: 'stop here' };
    },
  });
  assert.deepStrictEqual(onDisk, { semgrep: ['p/trailofbits'], codeql_suite: 'security-extended' });
});

t('a resumed run rescans with the scanner config it was started with', async () => {
  const { res, deps } = await fixRun({
    recordedMeta: { verify_level: 'cheap', scan_config: { semgrep: ['p/trailofbits'], codeql_suite: 'security-extended' } },
  });
  assert.deepStrictEqual(res.meta.scan_config, { semgrep: ['p/trailofbits'], codeql_suite: 'security-extended' });
  const calls = semgrepCalls(deps);
  assert.ok(calls.length >= 1);
  for (const c of calls) assert.ok(c.includes('--config p/trailofbits'), c);
});

t('a run started before scan_config existed adopts the flags and records them', async () => {
  const { out, deps } = await fixRun({ recordedLevel: 'cheap', argv: ['--semgrep-config=p/golang'] });
  assert.deepStrictEqual(readJson(path.join(out, 'run-metadata.json')).scan_config,
    { semgrep: ['p/golang'], codeql_suite: 'security-extended' });
  for (const c of semgrepCalls(deps)) assert.ok(c.includes('--config p/golang'), c);
});

t('a malformed recorded scan_config is ignored, not trusted', async () => {
  const { res } = await fixRun({
    recordedMeta: { verify_level: 'cheap', scan_config: { semgrep: 'p/x', codeql_suite: 'security-extended' } },
  });
  assert.deepStrictEqual(res.meta.scan_config, { semgrep: ['p/default'], codeql_suite: 'security-extended' });
});

t("a rescan that reports absolute worktree paths matches the baseline's relative ones", async () => {
  const { res } = await fixRun({
    fix: movingFix,
    rescan: (target) => ({ results: [{ ...pathHit(null, 11), path: path.join(target, 'src/routes/files.js') }], errors: [] }),
  });
  const v = res.findings.find((x) => x.id === PATH_ID).patches[0].verification;
  assert.deepStrictEqual(v.no_new_findings, { status: 'pass' });
  assert.deepStrictEqual(v.rescan.new_findings, []);
  assert.strictEqual(v.rescan.original_absent, false);
});

t('the report names the rescan configuration and warns that a reused scan must match it', async () => {
  const { res } = await fixRun({ argv: ['--semgrep-config=p/trailofbits'] });
  const report = renderRemediation(res.findings, res.meta);
  assert.ok(report.includes('- Rescan configuration: semgrep `p/trailofbits`, CodeQL suite `security-extended`'), report);
  assert.ok(report.includes('- Reused scans were made outside this run.'), report);
});

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

t('the fixer works in a worktree outside the run directory, from which no relative path reaches findings', async () => {
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
});

t('each agent role gets exactly its tools, and none gets a shell', async () => {
  const { deps } = await fixRun({ verify: 'full' });
  const byRole = {};
  for (const c of deps.state.agentCalls) byRole[c.schemaPointer] = c.tools;
  assert.deepStrictEqual(byRole, {
    '#/$defs/triage': ['Read', 'Grep', 'Glob'],
    '#/$defs/fix': ['Read', 'Grep', 'Glob', 'Edit', 'Write'],
    '#/$defs/audit': ['Read', 'Grep', 'Glob'],
  });
});

t('a resumed run finds the same worktree root, and another run gets its own', () => {
  const a = R.worktreeRootFor('/srv/out/run-1');
  assert.strictEqual(a, R.worktreeRootFor('/srv/out/run-1/'));
  assert.notStrictEqual(a, R.worktreeRootFor('/srv/out/run-2'));
  assert.ok(!path.relative('/srv/out/run-1', a).split(path.sep).includes('findings'));
  assert.ok(path.relative('/srv/out/run-1', a).startsWith('..'));
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

t('a commit the harness cannot make ends fix_failed, with no retry', async () => {
  const { res, deps } = await fixRun({ commitFails: true });
  const f = res.findings.find((x) => x.id === 'f_6ed43412e0d9b09d');
  assert.deepStrictEqual(f.patches.map((p) => [p.outcome, p.detail]), [['error', 'commit_failed: Author identity unknown']]);
  assert.strictEqual(f.disposition.state, 'fix_failed');
  assert.strictEqual(f.disposition.branch, null);
  assert.strictEqual(deps.state.agentCalls.filter((c) => c.schemaPointer === '#/$defs/fix').length, 3);
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

t('a resumed run judges with the verify level it was started at', async () => {
  const { res } = await fixRun({ verify: 'cheap', recordedLevel: 'none' });
  const f = res.findings.find((x) => x.patches.length);
  assert.strictEqual(res.meta.verify_level, 'none');
  assert.deepStrictEqual(Object.keys(f.patches[0].verification), []);
  assert.strictEqual(f.disposition.state, 'fixed_unwitnessed');
});

t('a fresh run records its verify level before any fixer runs', async () => {
  // The fixer's cwd is now outside outDir on purpose (R2), so this reads outDir directly
  // instead of walking up from the fixer's cwd the way an earlier version of this test did.
  let onDisk = null;
  const out = path.join(tmp(), 'run-1');
  await fixRun({
    out,
    verify: 'full',
    fix: () => {
      onDisk = readJson(path.join(out, 'run-metadata.json')).verify_level;
      return { ok: false, reason: 'stop here' };
    },
  });
  assert.strictEqual(onDisk, 'full');
});

t('a fixer call that fails takes no attempt slot and leaves the finding open', async () => {
  const { res, deps } = await fixRun({ verify: 'none', fix: () => ({ ok: false, reason: 'exit 1' }) });
  const fixable = res.findings.filter((f) => f.gate && f.gate.action === 'fix');
  assert.ok(fixable.length > 0);
  for (const f of fixable) {
    assert.strictEqual(f.patches.length, 0);
    assert.strictEqual(f.disposition, null);
    assert.ok(deps.state.execCalls.includes(
      `git -C ${REPO} branch -D sast-fix/${R.refSafe(res.runId)}/${f.id}/1`), f.id);
  }
  assert.strictEqual(res.meta.run_status, 'incomplete');
  const byId = (a, b) => (a.id < b.id ? -1 : 1);
  assert.deepStrictEqual([...res.meta.agent_failures].sort(byId),
    fixable.map((f) => ({ id: f.id, stage: 'fix', reason: 'exit 1' })).sort(byId));
  assert.strictEqual(deps.state.agentCalls.filter((c) => c.schemaPointer === '#/$defs/fix').length, fixable.length);
});

t('a worktree that was never created names no branch in the handoff', async () => {
  const { res } = await fixRun({ fix: () => ({ ok: true, data: { outcome: 'cannot_fix', reason: 'x' } }) });
  const f = res.findings.find((x) => x.patches.length);
  f.patches[0].outcome = 'error';
  f.disposition = R.dispositionFor(f, 'cheap');
  assert.strictEqual(f.disposition.branch, null);
  const handoff = renderHandoff([f], res.meta);
  assert.ok(handoff.includes(`\`${f.id}\` (\`high\`): branch none, 1 attempt made.`), handoff);
  assert.ok(!handoff.includes('sast-fix/'), handoff);
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
  const { res, deps } = await fixRun({ npm: (cwd) => (path.basename(cwd) === 'base' ? 0 : 1) });
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

// The fixer inserts two lines above the flagged read, so the rule's hit moves from line 9 to 11
// and its sink line text changes, which is what a correct containment check looks like.
const PATH_ID = 'f_6ed43412e0d9b09d';
const pathHit = (rule, line) => {
  const hit = JSON.parse(fs.readFileSync(path.join(ROOT, 'test/fixtures/semgrep.json'), 'utf8')).results.find((r) => r.path === 'src/routes/files.js');
  return { ...hit, check_id: rule || hit.check_id, start: { ...hit.start, line }, end: { ...hit.end, line } };
};
const movingFix = (o) => {
  const src = fs.readFileSync(path.join(REPO, 'src/routes/files.js'), 'utf8').split('\n');
  src.splice(8, 1, '  const safe = String(name);', "  if (safe.includes('..')) return res.end('no');", '  const target = path.join(ROOT, safe);');
  fs.mkdirSync(path.join(o.cwd, 'src/routes'), { recursive: true });
  fs.writeFileSync(path.join(o.cwd, 'src/routes/files.js'), src.join('\n'));
  return { ok: true, data: { outcome: 'patched', declared_files: ['src/routes/files.js'], enforcement_note: 'dot segments are refused' } };
};

t('at full, an argued fix ends fixed_unwitnessed after one fixer call', async () => {
  const { res, deps } = await fixRun({ verify: 'full' });
  const f = res.findings.find((x) => x.id === PATH_ID);
  assert.strictEqual(f.patches.length, 1);
  assert.deepStrictEqual(f.patches[0].verification.differential_witness,
    { status: 'unavailable', reason: 'argued_tier:no_test_harness' });
  assert.deepStrictEqual(f.patches[0].verification.functional_control,
    { status: 'unavailable', reason: 'argued_tier_has_no_control' });
  for (const o of ['regression_suite', 'no_new_findings', 'hostile_auditor']) {
    assert.strictEqual(f.patches[0].verification[o].status, 'pass', o);
  }
  assert.deepStrictEqual(f.disposition, {
    state: 'fixed_unwitnessed', branch: `sast-fix/${R.refSafe(res.runId)}/${PATH_ID}/1`,
    verify_level: 'full', skipped_obligations: [],
    unavailable: ['differential_witness', 'functional_control'], witness_tier: 'argued',
  });
  const fixerCalls = deps.state.agentCalls.filter((c) => c.schemaPointer === '#/$defs/fix');
  assert.strictEqual(fixerCalls.length, res.findings.filter((x) => x.patches.length).length);
});

// Copied from test/e2e-witness.cjs:56-70 so this deps-seam test can exercise the dynamic tier
// without booting a real app: it never reaches witnessObligations' boot step because
// --witness=dynamic is not passed, so allowDynamic is false.
const DYNAMIC_WITNESS = {
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
};

t('a dynamic witness without --witness=dynamic is recorded unavailable, not thrown', async () => {
  const { res } = await fixRun({ verify: 'full', witness: { witness: DYNAMIC_WITNESS } });
  const f = res.findings.find((x) => x.id === PATH_ID);
  assert.deepStrictEqual(f.patches[0].verification.differential_witness,
    { status: 'unavailable', reason: 'dynamic_tier_not_enabled' });
  assert.strictEqual(f.patches[0].verification.deterministic_guard.status, 'pass');
  assert.strictEqual(f.disposition.state, 'fix_failed');
});

t('the same rule in the same file at a new line is not a finding the patch introduced', async () => {
  const { res } = await fixRun({ fix: movingFix, rescan: { results: [pathHit(null, 11)], errors: [] } });
  const f = res.findings.find((x) => x.id === PATH_ID);
  const v = f.patches[0].verification;
  assert.deepStrictEqual(v.no_new_findings, { status: 'pass' });
  assert.deepStrictEqual(v.rescan.new_findings, []);
  assert.strictEqual(v.rescan.original_absent, false);
  assert.strictEqual(f.patches.length, 1);
  assert.strictEqual(f.disposition.state, 'fixed_unwitnessed');
});

t('a rule base never fired in that file is a finding the patch introduced', async () => {
  const rule = 'javascript.lang.security.detect-child-process.detect-child-process';
  const { res } = await fixRun({ fix: movingFix, rescan: { results: [pathHit(rule, 11)], errors: [] } });
  const v = res.findings.find((x) => x.id === PATH_ID).patches[0].verification;
  assert.strictEqual(v.no_new_findings.status, 'fail');
  assert.strictEqual(v.no_new_findings.reason, 'rescan_new');
  assert.strictEqual(v.no_new_findings.new_findings.length, 1);
  assert.strictEqual(v.rescan.original_absent, true);
});

t('the rescan reruns only the scanners whose output made the baseline', async () => {
  const scans = tmp();
  fs.copyFileSync(path.join(ROOT, 'test/fixtures/semgrep.json'), path.join(scans, 'semgrep.json'));
  const { res } = await fixRun({ scans, scanners: ['semgrep', 'codeql'] });
  const v = res.findings.find((x) => x.id === PATH_ID).patches[0].verification;
  assert.deepStrictEqual(res.meta.scanners.map((s) => [s.name, s.status]), [['semgrep', 'reused'], ['codeql', 'absent']]);
  assert.deepStrictEqual(v.rescan.scanners.map((s) => [s.name, s.status]), [['semgrep', 'ok']]);
});

t('a rescan that cannot run is unavailable and excused, not a failed patch', async () => {
  const { res } = await fixRun({ onPath: () => false });
  const f = res.findings.find((x) => x.id === PATH_ID);
  const v = f.patches[0].verification;
  assert.deepStrictEqual(v.no_new_findings, { status: 'unavailable', reason: 'rescan_produced_no_output' });
  assert.strictEqual(f.patches.length, 1);
  assert.strictEqual(f.disposition.state, 'fixed_unwitnessed');
  assert.deepStrictEqual(f.disposition.unavailable, ['no_new_findings']);
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

t('no test command still patches, and the report says no suite ran', async () => {
  const copy = path.join(tmp(), 'vuln-app');
  fs.cpSync(REPO, copy, { recursive: true });
  const pkg = readJson(path.join(copy, 'package.json'));
  delete pkg.scripts.test;
  fs.writeFileSync(path.join(copy, 'package.json'), JSON.stringify(pkg, null, 2));
  assert.strictEqual(R.discoverTestCommand(copy), null);

  const opts = baseOpts(); opts.out = path.join(tmp(), 'run-1'); opts.target = copy; opts.scanners = ['semgrep'];
  const deps = makeDeps({
    agents: {
      '#/$defs/triage': () => ({ ok: true, data: exploitable() }),
      '#/$defs/fix': () => ({ ok: true, data: { outcome: 'patched', declared_files: ['src/routes/files.js'], enforcement_note: 'basename' } }),
    },
  });
  const res = await R.run(opts, deps);
  const patched = res.findings.filter((f) => f.patches.length);
  assert.ok(patched.length > 0, 'a repo with no test script must still be patched');
  assert.deepStrictEqual(patched[0].patches[0].verification.regression_suite,
    { status: 'unavailable', reason: 'no_test_command_discovered' });
  assert.strictEqual(res.meta.incomplete_reason, null);
  const report = renderRemediation(res.findings, res.meta);
  assert.ok(report.includes('`regression_suite` unavailable and excused, not passed'), report);
});

t('a target that is not a git repository never reaches the fix stage', async () => {
  const opts = baseOpts(); opts.out = path.join(tmp(), 'run-1');
  const deps = makeDeps({ base: null, agents: { '#/$defs/triage': () => ({ ok: true, data: exploitable() }) } });
  const res = await R.run(opts, deps);
  assert.strictEqual(res.meta.base_commit, null);
  assert.ok(res.findings.every((f) => f.patches.length === 0));
  assert.ok(/not_a_git_repository/.test(res.meta.incomplete_reason), res.meta.incomplete_reason);
});

// ============================================================================

section('resume');

t('defaultOutDir continues an unfinished run of the same commit and starts fresh otherwise', () => {
  const root = tmp(); const B = 'b'.repeat(40);
  const mk = (n, meta) => {
    const dir = path.join(root, 'vuln-app', `run-${n}`);
    fs.mkdirSync(dir, { recursive: true });
    if (meta) fs.writeFileSync(path.join(dir, 'run-metadata.json'), JSON.stringify(meta));
  };
  const at = () => R.defaultOutDir('/x/vuln-app', B, root);
  const run = (n) => path.join(root, 'vuln-app', `run-${n}`);

  assert.strictEqual(at(), run(1), 'nothing created');

  mk(1, { run_status: 'complete', base_commit: B });
  assert.strictEqual(at(), run(2), 'run-1 is complete');

  mk(2, { run_id: 'run-2', verify_level: 'cheap', base_commit: B });
  assert.strictEqual(at(), run(2), 'a run that died mid-way carries no run_status');

  fs.writeFileSync(path.join(run(2), 'run-metadata.json'), JSON.stringify({ run_status: 'incomplete', base_commit: B }));
  assert.strictEqual(at(), run(2), 'incomplete and same base');

  fs.writeFileSync(path.join(run(2), 'run-metadata.json'),
    JSON.stringify({ run_status: 'incomplete', base_commit: 'c'.repeat(40) }));
  assert.strictEqual(at(), run(3), 'incomplete but a different base');

  fs.writeFileSync(path.join(run(2), 'run-metadata.json'), JSON.stringify({ run_status: 'incomplete' }));
  assert.strictEqual(at(), run(2), 'legacy record with no base recorded');

  mk(3);
  assert.strictEqual(at(), run(3), 'a run with no metadata file at all');

  mk(10, { run_status: 'complete', base_commit: B });
  assert.strictEqual(at(), run(11), 'numeric order, not lexical');
});

t('a plain re-run continues the unfinished run instead of starting run-2', async () => {
  const savedHome = process.env.HOME;
  process.env.HOME = tmp();
  try {
    const agents = { '#/$defs/triage': () => ({ ok: true, data: notExploitable() }) };
    const opts1 = baseOpts(); opts1.maxFindings = 1;
    const res1 = await R.run(opts1, makeDeps({ agents }));
    assert.strictEqual(res1.outDir, path.join(process.env.HOME, 'sast-remediate', 'vuln-app', 'run-1'));
    assert.strictEqual(res1.meta.run_status, 'incomplete');

    const deps2 = makeDeps({ agents });
    const res2 = await R.run(baseOpts(), deps2);
    assert.strictEqual(res2.outDir, res1.outDir);
    assert.strictEqual(deps2.state.agentCalls.length, 2, 'only the deferred two are asked');
    assert.strictEqual(res2.meta.run_status, 'complete');
    assert.strictEqual(readJson(path.join(res1.outDir, 'run-metadata.json')).base_commit, 'a'.repeat(40));

    const res3 = await R.run(baseOpts(), makeDeps({ agents }));
    assert.ok(res3.outDir.endsWith('run-2'), res3.outDir);
  } finally {
    process.env.HOME = savedHome;
  }
});

t('a failed triage call is asked again by the next run', async () => {
  const out = path.join(tmp(), 'run-1');
  const opts1 = baseOpts(); opts1.out = out; opts1.triageOnly = true;
  await R.run(opts1, makeDeps({ agents: { '#/$defs/triage': () => ({ ok: false, reason: 'rate limited' }) } }));

  const opts2 = baseOpts(); opts2.out = out; opts2.triageOnly = true;
  const deps2 = makeDeps({ agents: { '#/$defs/triage': () => ({ ok: true, data: notExploitable() }) } });
  const res2 = await R.run(opts2, deps2);
  assert.strictEqual(deps2.state.agentCalls.length, 3, 'every finding is asked again, not just the failed one');
  assert.strictEqual(res2.meta.run_status, 'complete');
  assert.deepStrictEqual(res2.meta.agent_failures, []);
  assert.ok(res2.findings.every((f) => f.disposition.state === 'rejected'));
});

t('a budget stop and a failed agent call are told apart', async () => {
  const { res } = await triageOnlyRun({
    triage: () => ({ ok: false, reason: 'timed out after 300000ms' }),
    opts: { maxFindings: 1 },
  });
  assert.strictEqual(res.meta.counts.deferred, 2);
  assert.strictEqual(res.meta.counts.agent_failures, 1);
  assert.ok(res.meta.incomplete_reason.includes('max_findings=1 reached, 2 finding(s) deferred to the next run'),
    res.meta.incomplete_reason);
  assert.ok(res.meta.incomplete_reason.includes('agent_failed: 1 agent call(s) failed and will be retried on the next run ('),
    res.meta.incomplete_reason);
  assert.ok(res.meta.incomplete_reason.includes('triage: timed out after 300000ms)'), res.meta.incomplete_reason);
});

t('a failed second fix attempt keeps the first attempt and the finding open', async () => {
  const { res: res1, out } = await fixRun({
    npm: (cwd) => (path.basename(cwd) === 'base' ? 0 : 1),
    fix: (o) => (o.cwd.endsWith('-1') ? PATCHED : { ok: false, reason: 'rate limited' }),
  });
  const fixable1 = res1.findings.filter((f) => f.gate && f.gate.action === 'fix');
  assert.ok(fixable1.length > 0);
  for (const f of fixable1) {
    assert.strictEqual(f.patches.length, 1);
    assert.strictEqual(f.patches[0].outcome, 'patched');
    assert.strictEqual(f.disposition, null);
    assert.strictEqual(stageOf(f, 'cheap'), 'fix');
  }
  assert.strictEqual(res1.meta.run_status, 'incomplete');

  const { res: res2 } = await fixRun({ out, npm: () => 0 });
  const fixable2 = res2.findings.filter((f) => f.gate && f.gate.action === 'fix');
  for (const f of fixable2) {
    assert.strictEqual(f.patches.length, 2);
    assert.strictEqual(f.patches[1].attempt, 2);
    assert.strictEqual(f.disposition.state, 'fixed_unwitnessed', 'the default contract is argued');
  }
  assert.strictEqual(res2.meta.run_status, 'complete');
});

t('a record deferred by a failed triage call under the old rules is reopened', async () => {
  const out = path.join(tmp(), 'run-1');
  const opts1 = baseOpts(); opts1.out = out; opts1.triageOnly = true;
  const res1 = await R.run(opts1, makeDeps({ agents: { '#/$defs/triage': () => ({ ok: true, data: notExploitable() }) } }));
  const id = res1.findings[0].id;
  const file = path.join(out, 'findings', `${id}.json`);
  const record = readJson(file);
  record.triage = null;
  record.gate = null;
  record.disposition = { state: 'deferred', reason: 'triage_agent_failed', detail: 'discarded twice: cli exited 1 | cli exited 1' };
  fs.writeFileSync(file, JSON.stringify(record, null, 2));

  const opts2 = baseOpts(); opts2.out = out; opts2.triageOnly = true;
  const deps2 = makeDeps({ agents: { '#/$defs/triage': () => ({ ok: true, data: notExploitable() }) } });
  const res2 = await R.run(opts2, deps2);
  assert.strictEqual(deps2.state.agentCalls.length, 1, 'only the reopened record is asked again');
  const reopened = res2.findings.find((f) => f.id === id);
  assert.strictEqual(reopened.disposition.state, 'rejected');
});

t('a fix that failed on a dead agent call under the old rules is tried again', async () => {
  const { res: res1, out } = await fixRun();
  const f1 = res1.findings.find((x) => x.patches.length === 1);
  const state1 = f1.disposition.state;
  const file = path.join(out, 'findings', `${f1.id}.json`);
  const record = readJson(file);
  const p0 = record.patches[0];
  record.patches = [{ ...p0, outcome: 'agent_failed', detail: 'exit 1', verification: {} }];
  record.disposition = { state: 'fix_failed', outcome: 'agent_failed', detail: 'exit 1',
    branch: p0.branch, attempts: 1, failed: [], missing: [], worktree: p0.worktree };
  fs.writeFileSync(file, JSON.stringify(record, null, 2));

  const { res: res2, deps: deps2 } = await fixRun({ out });
  const fixCalls = deps2.state.agentCalls.filter((c) => c.schemaPointer === '#/$defs/fix');
  assert.strictEqual(fixCalls.length, 1);
  const reopened = res2.findings.find((x) => x.id === f1.id);
  assert.strictEqual(reopened.patches.length, 1);
  assert.strictEqual(reopened.patches[0].outcome, 'patched');
  assert.strictEqual(reopened.disposition.state, state1);
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

t('an invariant in plain words and property paths is accepted at the triage boundary', () => {
  for (const v of [
    'the warning banner text must not carry markup taken from the query string',
    'each finding id in the URL must belong to the authenticated caller',
    'a form field named alert is HTML-escaped before it is rendered',
    'req.params.user.id must equal the session user id before the row is read',
    'the comment body never reaches the shell in the step after uses: actions/setup-node@v4',
    'every name resolved under ./go/some-pkg/util stays inside the module root',
    'files under /static/js/admin-panel/ are served read-only',
    'the redirect target resolves to api.my-service.example.com and nothing else',
  ]) assert.deepStrictEqual(contractErrs(contract({ invariant: v })), [], v);
});

t('rule ids of every shape are still rejected in the invariant', () => {
  for (const id of ['actions/code-injection/critical', 'actions/missing-workflow-permissions', 'js/xss',
    'yaml.github-actions.security.run-shell-injection.run-shell-injection',
    'trailofbits.go.unsafe-dll-loading.unsafe-dll-loading']) {
    assert.ok(contractErrs(contract({ invariant: `the condition ${id} describes must not hold` })).length > 0, id);
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
  for (const f of res.findings.filter((x) => x.patches.length)) {
    assert.deepStrictEqual([f.patches.length, f.disposition.state, f.disposition.outcome], [1, 'fix_failed', 'refused'],
      'a refusal is final, like cannot_fix');
  }
  assert.ok(fs.existsSync(path.join(out, 'run-metadata.json')), 'the run wrote its metadata instead of crashing');
  assert.ok(fs.existsSync(path.join(out, 'REMEDIATION.md')), 'the run wrote its report instead of crashing');
});

// ============================================================================

section('languages: CodeQL sees every language in the repository');

const tree = (files) => {
  const d = tmp();
  for (const [rel, body] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(d, rel)), { recursive: true });
    fs.writeFileSync(path.join(d, rel), body);
  }
  return d;
};
// A fake codeql: each analyze writes a one-run SARIF whose driver name is its language.
const codeqlDeps = (failCreate = []) => ({
  onPath: () => true,
  exec: (cmd, args) => {
    const lang = (args.find((a) => a.startsWith('--language=')) || '').slice('--language='.length)
      || path.basename(args[2]).replace('codeql-db-', '');
    if (args[1] === 'create') return failCreate.includes(lang)
      ? { status: 32, stdout: '', stderr: `no ${lang} source seen` } : { status: 0, stdout: '', stderr: '' };
    const out = args.find((a) => a.startsWith('--output=')).slice('--output='.length);
    fs.writeFileSync(out, JSON.stringify({ version: '2.1.0', runs: [{ tool: { driver: { name: lang, rules: [] } }, results: [] }] }));
    return { status: 0, stdout: '', stderr: '' };
  },
});
const scanOpts = (over = {}) => ({ scans: null, scanners: ['codeql'],
  scanConfig: { semgrep: ['p/default'], codeql_suite: 'security-extended' }, ...over });

t('every language with source files is detected, and vendored code is not', () => {
  const d = tree({ 'package.json': '{}', 'src/a.js': '', 'svc/main.go': '', 'go.mod': '', 'tools/x.py': '',
    'node_modules/dep/index.rb': '', 'vendor/lib/X.java': '', '.hidden/y.rs': '',
    '.github/workflows/ci.yml': 'on: push\n' });
  assert.deepStrictEqual(S.detectLanguages(d), ['javascript', 'python', 'go', 'actions']);
});

t('a root marker with no source files is not a language', () => {
  assert.deepStrictEqual(S.detectLanguages(tree({ 'package.json': '{}', 'main.go': '' })), ['go']);
});

t('one database per language, merged into one SARIF with a run each', () => {
  const target = tree({ 'a.js': '', 'b.py': '' });
  const scanDir = path.join(tmp(), 'scans');
  const { raw: r, scanners } = S.runScanners(scanOpts(), codeqlDeps(), target, scanDir);
  assert.deepStrictEqual(r.codeql.runs.map((x) => x.tool.driver.name), ['javascript', 'python']);
  assert.deepStrictEqual(scanners, [{ name: 'codeql', status: 'ok', detail: path.join(scanDir, 'codeql.sarif'),
    config: 'javascript,python', languages: ['javascript', 'python'] }]);
  assert.deepStrictEqual(JSON.parse(fs.readFileSync(path.join(scanDir, 'codeql.sarif'), 'utf8')).runs.length, 2);
});

t('a language that fails is recorded and the others still count', () => {
  const target = tree({ 'a.js': '', 'b.py': '' });
  const { raw: r, scanners } = S.runScanners(scanOpts(), codeqlDeps(['python']), target, path.join(tmp(), 'scans'));
  assert.deepStrictEqual(r.codeql.runs.map((x) => x.tool.driver.name), ['javascript']);
  assert.deepStrictEqual([scanners[0].status, scanners[0].languages, scanners[0].detail],
    ['partial', ['javascript'], 'python: no python source seen']);
});

t("the rescan analyses the baseline's languages, not whatever the patch left behind", () => {
  const target = tree({ 'a.js': '', 'b.py': '' });
  const deps = codeqlDeps(['python']);
  const opts = scanOpts();
  const base = S.runScanners(opts, deps, target, path.join(tmp(), 'scans'));
  // baselineOf's third argument stays scanConfig (bin/scan.cjs, R3); languages ride alongside it
  // as a fourth argument, taken from the codeql scanner entry rather than replacing scanConfig.
  const baseline = S.baselineOf(base.raw, [], opts.scanConfig, base.scanners);
  assert.deepStrictEqual(baseline.languages, ['javascript']);
  const worktree = tree({ 'a.js': '', 'b.py': '', 'c.go': '' });
  const f = pathFinding();
  const res = S.rescan(f, worktree, path.join(tmp(), 'rescan'),
    { deps: codeqlDeps(), runId: 'run-test', baseline });
  assert.deepStrictEqual(res.rescan.scanners.map((s) => [s.name, s.languages]), [['codeql', ['javascript']]]);
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
