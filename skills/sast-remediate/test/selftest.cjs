#!/usr/bin/env node
'use strict';
// Run: node test/selftest.cjs
// Every assertion runs against the real artifact. The scanner fixtures are genuine output
// from semgrep 1.177.0 and CodeQL 2.26.4 over fixtures/vuln-app, not hand-written JSON.

const fs = require('fs');
const path = require('path');
const assert = require('assert');

const ROOT = path.resolve(__dirname, '..');
const REPO = path.resolve(ROOT, '../../fixtures/vuln-app');
const { normalize, makeRepo, classify, extractCallee } = require(path.join(ROOT, 'bin/normalize.ts'));
const { validate } = require(path.join(ROOT, 'bin/validate.ts'));
const { gate, priority, claimedRank } = require(path.join(ROOT, 'bin/gate.ts'));
const { guardDiff, sameShape, inScope } = require(path.join(ROOT, 'bin/patch-guard.cjs'));
const { stageOf, evaluateVerification, OBLIGATIONS } = require(path.join(ROOT, 'bin/stage.ts'));

let pass = 0, fail = 0;
const t = (name, fn) => {
  try { fn(); pass++; console.log(`  ok   ${name}`); }
  catch (e) { fail++; console.log(`  FAIL ${name}\n         ${e.message}`); }
};
const section = (s) => console.log(`\n${s}`);

const schema = JSON.parse(fs.readFileSync(path.join(ROOT, 'schema/finding.schema.json'), 'utf8'));
const repo = makeRepo(REPO);
const raw = {
  semgrep: JSON.parse(fs.readFileSync(path.join(ROOT, 'test/fixtures/semgrep.json'), 'utf8')),
  codeql: JSON.parse(fs.readFileSync(path.join(ROOT, 'test/fixtures/codeql.sarif'), 'utf8')),
};
const { findings } = normalize(raw, repo, 'run-test');
const byClass = (c) => findings.find((f) => f.invariant_class === c);

section('normalize: real scanner output');

t('produces schema-valid findings', () => {
  const errs = validate(schema, findings);
  assert.deepStrictEqual(errs, [], errs.join('\n'));
});

t('5 raw results fold to 3 findings', () => {
  assert.strictEqual(findings.length, 3);
});

t('FOLD 1 merges both scanners at one line (admin.js:6, identical sink_digest)', () => {
  const f = byClass('injection.command');
  assert.strictEqual(f.sites.length, 1);
  const scanners = f.sites[0].observations.map((o) => o.scanner).sort();
  assert.deepStrictEqual(scanners, ['codeql', 'semgrep']);
});

t('FOLD 1 merges across a line gap via same enclosing symbol (files.js 9 vs 10)', () => {
  const f = byClass('injection.path');
  assert.strictEqual(f.sites.length, 1, 'CodeQL line 10 and Semgrep line 9 must be one site');
  assert.strictEqual(f.sites[0].locus.symbol, 'read');
  const scanners = f.sites[0].observations.map((o) => o.scanner).sort();
  assert.deepStrictEqual(scanners, ['codeql', 'semgrep']);
});

t('evidence union: CodeQL flow AND Semgrep metadata on one record', () => {
  const f = byClass('injection.path');
  assert.strictEqual(f.flow.kind, 'traced');
  assert.strictEqual(f.flow.provenance, 'codeql_codeflows');
  const sg = f.sites[0].observations.find((o) => o.scanner === 'semgrep');
  assert.strictEqual(sg.claimed.likelihood, 'HIGH');
});

t('taint path is materialized at ingest, not left for an agent to re-read', () => {
  const f = byClass('injection.command');
  assert.ok(f.flow.steps.length >= 2);
  assert.ok(f.flow.steps.every((s) => typeof s.code === 'string' && s.code.length > 0),
    'every flow step must carry its source line');
  assert.strictEqual(f.flow.steps[0].role, 'source');
  assert.strictEqual(f.flow.steps[f.flow.steps.length - 1].role, 'sink');
});

t('sink_only is used when no scanner emitted a flow (semgrep OSS emits none)', () => {
  const f = findings.find((x) => x.flow.kind === 'sink_only');
  assert.ok(f, 'expected at least one sink_only finding');
  assert.strictEqual(f.flow.reason, 'scanner_emitted_no_flow');
  assert.ok(f.flow.sink.code.length > 0);
});

t('a null enclosing symbol never participates in a proximity merge', () => {
  const sm = { results: [
    { check_id: 'r.a', path: 'src/app.js', start: { line: 1 },
      extra: { severity: 'WARNING', metadata: { cwe: ['CWE-78'] }, message: 'a' } },
    { check_id: 'r.b', path: 'src/app.js', start: { line: 2 },
      extra: { severity: 'WARNING', metadata: { cwe: ['CWE-78'] }, message: 'b' } },
  ] };
  const out = normalize({ semgrep: sm }, repo, 'r');
  const sites = out.findings.flatMap((f) => f.sites);
  const nullSym = sites.filter((s) => s.locus.symbol === null);
  for (const s of nullSym) {
    assert.strictEqual(s.observations.length, 1,
      'sites with an unresolved symbol must not absorb a neighbour');
  }
});

t('ids are deterministic across runs', () => {
  const again = normalize(raw, repo, 'run-test').findings;
  assert.deepStrictEqual(again.map((f) => f.id), findings.map((f) => f.id));
});

t('unmapped CWE falls back to "other" rather than guessing', () => {
  assert.strictEqual(classify([], 'some.unknown.rule'), 'other');
  assert.strictEqual(classify(['CWE-89'], 'x'), 'injection.sql');
  assert.strictEqual(classify([], 'js/sql-injection'), 'injection.sql');
});

t('extractCallee finds the clustering key', () => {
  assert.strictEqual(extractCallee('  const t = path.join(ROOT, name);'), 'path.join');
  assert.strictEqual(extractCallee('  exec(`ping -c 1 ${host}`, (e) => {'), 'exec');
});

section('gate: the threshold');

const exploitable = (sev) => ({ verdict: 'exploitable', severity: sev });

t('exploitable at threshold is fixed', () => {
  assert.strictEqual(gate(exploitable('medium'), { fix_at: 'medium' }).action, 'fix');
  assert.strictEqual(gate(exploitable('critical'), { fix_at: 'medium' }).action, 'fix');
});

t('exploitable below threshold is report_only', () => {
  const g = gate(exploitable('low'), { fix_at: 'medium' });
  assert.strictEqual(g.action, 'report_only');
  assert.strictEqual(g.reason, 'below_threshold');
});

t('not_exploitable and undecidable are never fixed', () => {
  assert.strictEqual(gate({ verdict: 'not_exploitable' }, { fix_at: 'informational' }).action, 'report_only');
  assert.strictEqual(gate({ verdict: 'undecidable' }, { fix_at: 'informational' }).action, 'report_only');
});

t('gate takes only (triage, policy), so a scanner claim cannot reach it', () => {
  assert.strictEqual(gate.length, 2);
});

t('schema makes severity unrepresentable outside the exploitable branch', () => {
  const branches = schema.$defs.triage.oneOf;
  for (const b of branches) {
    if (b.properties.verdict.const === 'exploitable') {
      assert.ok('severity' in b.properties, 'exploitable must carry severity');
    } else {
      assert.ok(!('severity' in b.properties),
        `${b.properties.verdict.const} must not even have a severity field`);
      assert.strictEqual(b.additionalProperties, false);
    }
  }
});

t('a triage carrying a severity on a refuted verdict is rejected by the schema', () => {
  const f = JSON.parse(JSON.stringify(findings[0]));
  f.triage = {
    verdict: 'not_exploitable', established_by: 'agent', severity: 'critical',
    refutation: { reason: 'unreachable_code', control: null, explanation: 'x' },
  };
  assert.ok(validate(schema, [f]).length > 0, 'smuggled severity must not validate');
});

section('priority: scanner claims order, never filter');

t('semgrep likelihood/impact outranks rule-category severity', () => {
  // Measured on the real fixture: detect-child-process is ERROR with likelihood LOW, while
  // path-join-resolve-traversal is WARNING with likelihood HIGH. Ranking by severity alone
  // inverts them, which is the concrete case Constraint 3 warns about.
  const errLowLik = { kind: 'semgrep', severity: 'ERROR', likelihood: 'LOW', impact: 'HIGH', confidence: 'LOW' };
  const warnHighLik = { kind: 'semgrep', severity: 'WARNING', likelihood: 'HIGH', impact: 'MEDIUM', confidence: 'MEDIUM' };
  assert.ok(claimedRank(warnHighLik) >= claimedRank(errLowLik),
    'HIGH-likelihood WARNING must not rank below a LOW-likelihood ERROR');
});

t('codeql security-severity uses published cut points', () => {
  const at = (s) => claimedRank({ kind: 'codeql', security_severity: s, problem_severity: 'error' });
  assert.strictEqual(at(9.8), 4);
  assert.strictEqual(at(7.5), 3);
  assert.strictEqual(at(5.0), 2);
  assert.strictEqual(at(2.0), 1);
});

t('corroboration and a traced flow raise priority', () => {
  const cmd = byClass('injection.command');
  const noise = byClass('other');
  assert.ok(priority(cmd) > priority(noise));
});

section('patch-guard: the cheating diffs');

const diff = (p, removed, added) =>
  `diff --git a/${p} b/${p}\n--- a/${p}\n+++ b/${p}\n` +
  removed.map((l) => `-${l}`).join('\n') + (removed.length ? '\n' : '') +
  added.map((l) => `+${l}`).join('\n') + '\n';

const contract = {
  writable_scope: ['src/**', 'test/**'],
  witness: { tier: 'executable' },
};
const opts = { requireWitnessFile: false, sinkFiles: ['src/routes/admin.js'] };

t('adding a suppression comment fails', () => {
  const r = guardDiff(diff('src/routes/admin.js', [], ['  // nosemgrep', '  exec(cmd);']), contract, opts);
  assert.ok(!r.passed);
  assert.ok(r.violations.some((v) => v.kind === 'suppression_comment_added'));
});

t('codeql and lgtm suppression syntax is caught too', () => {
  for (const s of ['  // lgtm[js/command-line-injection]', '  # codeql[py/sql-injection]']) {
    const r = guardDiff(diff('src/routes/admin.js', [], [s]), contract, opts);
    assert.ok(r.violations.some((v) => v.kind === 'suppression_comment_added'), s);
  }
});

t('editing scanner config fails', () => {
  const r = guardDiff(diff('.semgrepignore', [], ['src/routes/']), contract, opts);
  assert.ok(r.violations.some((v) => v.kind === 'scanner_config_modified'));
});

t('editing the app harness fails (booting the app is not a place to hide a fix)', () => {
  const r = guardDiff(diff('docker-compose.yml', [], ['    command: sleep infinity']), contract, opts);
  assert.ok(r.violations.some((v) => v.kind === 'app_harness_modified'));
});

t('a pure rename is caught as cosmetic', () => {
  const r = guardDiff(
    diff('src/routes/admin.js', ['  exec(`ping -c 1 ${host}`);'], ['  exec(`ping -c 1 ${safeHost}`);']),
    contract, opts);
  assert.ok(r.violations.some((v) => v.kind === 'cosmetic_change_only'),
    JSON.stringify(r.violations));
});

t('a real fix is NOT cosmetic', () => {
  const r = guardDiff(
    diff('src/routes/admin.js',
      ['  exec(`ping -c 1 ${host}`);'],
      ['  if (!/^[a-z0-9.-]+$/.test(host)) throw new Error("bad host");', '  execFile("ping", ["-c", "1", host]);']),
    contract, opts);
  assert.ok(!r.violations.some((v) => v.kind === 'cosmetic_change_only'), JSON.stringify(r.violations));
  assert.ok(r.passed, JSON.stringify(r.violations));
});

t('weakening an existing test fails', () => {
  const r = guardDiff(
    diff('test/admin.test.js', ['  assert.throws(() => ping("x; rm -rf /"));'], ['  // removed']),
    contract, opts);
  assert.ok(r.violations.some((v) => v.kind === 'existing_test_weakened'));
});

t('skipping an existing test fails', () => {
  const r = guardDiff(diff('test/admin.test.js', [], ['  it.skip("rejects injection", () => {})']), contract, opts);
  assert.ok(r.violations.some((v) => v.kind === 'test_skipped'));
});

t('writing outside the contract scope fails', () => {
  const r = guardDiff(diff('infra/deploy.tf', [], ['  x = 1']), contract, opts);
  assert.ok(r.violations.some((v) => v.kind === 'outside_writable_scope'));
});

t('touching a dependency manifest fails (a new dep is a human decision)', () => {
  const r = guardDiff(diff('package.json', [], ['    "validator": "^13.0.0"']), contract, opts);
  assert.ok(r.violations.some((v) => v.kind === 'dependency_manifest_modified'));
});

t('a missing witness file fails when the tier requires one', () => {
  const r = guardDiff(diff('src/routes/admin.js', [], ['  const x = 1;']), contract,
    { sinkFiles: ['src/routes/admin.js'] });
  assert.ok(r.violations.some((v) => v.kind === 'witness_missing'));
});

t('a dynamic witness needs no witness file, because the attack lives in the contract', () => {
  const r = guardDiff(diff('src/routes/admin.js', [], ['  const x = 1;']),
    { ...contract, witness: { tier: 'dynamic' } }, { sinkFiles: ['src/routes/admin.js'] });
  assert.ok(!r.violations.some((v) => v.kind === 'witness_missing'));
});

t('glob scope handles ** and single-segment *', () => {
  assert.ok(inScope('src/a/b/c.js', ['src/**']));
  assert.ok(!inScope('lib/a.js', ['src/**']));
  assert.ok(inScope('src/a.js', ['src/*.js']));
  assert.ok(!inScope('src/a/b.js', ['src/*.js']));
});

t('sameShape ignores comments and whitespace but not structure', () => {
  assert.ok(sameShape('const a = f(x);', 'const  b  =  g(y); // note'));
  assert.ok(!sameShape('const a = f(x);', 'const a = f(escape(x));'));
});

section('contract: the way around rule-blindness');

// The inputs are every rule id the real scanners emit, read from the fixtures at run time.
// A denylist cannot satisfy this test by restating itself: add a scanner or upgrade a
// ruleset and the corpus grows on its own.
const INV = { ...schema.$defs.security_contract.properties.invariant, type: 'string' };
const rejects = (v) => validate(INV, v).length > 0;

const semgrepIds = [...new Set((raw.semgrep.results || []).map((r) => r.check_id))];
const codeqlResultIds = [...new Set(raw.codeql.runs.flatMap(
  (r) => (r.results || []).map((x) => x.ruleId)))];
const codeqlRuleIds = [...new Set(raw.codeql.runs.flatMap(
  (r) => ((r.tool.driver.rules || []).map((x) => x.id))))].filter((id) => id.includes('/'));

t('every rule id the scanners actually reported is rejected, bare', () => {
  const ids = [...semgrepIds, ...codeqlResultIds];
  assert.ok(ids.length >= 5, `fixture corpus too small: ${ids.length}`);
  for (const id of ids) assert.ok(rejects(id), `should reject bare id: ${id}`);
});

t('every rule id the scanners reported is rejected inside a plausible sentence', () => {
  for (const id of [...semgrepIds, ...codeqlResultIds]) {
    assert.ok(rejects(`the condition ${id} flags must no longer hold here`),
      `should reject embedded id: ${id}`);
  }
});

t('every CodeQL rule in the tool driver is rejected, not just the ones that fired', () => {
  assert.ok(codeqlRuleIds.length >= 100, `driver corpus too small: ${codeqlRuleIds.length}`);
  const leaked = codeqlRuleIds.filter((id) => !rejects(id));
  assert.deepStrictEqual(leaked, [], `${leaked.length} rule ids leak: ${leaked.slice(0, 5)}`);
});

t('paraphrases that name the tool without naming a rule are rejected', () => {
  for (const v of ['the scanner must stop reporting this line',
                   'make the static analyser quiet',
                   'suppress this at the sink',
                   'this should stop firing after the patch',
                   'the SAST check goes quiet']) {
    assert.ok(rejects(v), `should reject: ${v}`);
  }
});

t('a real invariant about values and boundaries is accepted', () => {
  const good = 'every string reaching the first argument of the process spawn at '
    + 'src/routes/admin.js is an element of the fixed ALLOWED_HOSTS list';
  assert.deepStrictEqual(validate(INV, good), []);
});

t('the filter does not swallow ordinary security prose', () => {
  for (const v of ['path joined from request input must stay inside the uploads root',
                   'the content type must be text/html before the body is rendered',
                   'order ids must belong to the authenticated tenant before the row is read',
                   'the redirect target must resolve to a host this service owns']) {
    assert.deepStrictEqual(validate(INV, v), [], `should accept: ${v}`);
  }
});

t('a merged multi-run SARIF points each result at its own run', () => {
  const two = { ...raw.codeql, runs: [{ ...raw.codeql.runs[0], results: [] }, raw.codeql.runs[0]] };
  const ptrs = normalize({ codeql: two }, repo, 'run-test').findings
    .flatMap((f) => f.sites.flatMap((s) => s.observations)).map((o) => o.raw_pointer);
  assert.ok(ptrs.length > 0, 'the fixture must produce CodeQL observations');
  assert.deepStrictEqual(ptrs.filter((p) => !p.startsWith('codeql.sarif#/runs/1/results/')), []);
});

t("Semgrep's placeholder fingerprint is not stored", () => {
  const sg = findings.flatMap((f) => f.sites.flatMap((s) => s.observations)).filter((o) => o.scanner === 'semgrep');
  assert.ok(sg.length > 0);
  assert.deepStrictEqual([...new Set(sg.map((o) => o.native_fingerprint))], [null]);
});

section('stage: one definition of where a record is');

const base = { disposition: null, triage: null, gate: null, patches: [] };
const triaged = { verdict: 'exploitable' };
const allPass = Object.fromEntries(OBLIGATIONS.map((o) => [o, { status: 'pass' }]));

t('stage is derived from shape, in order', () => {
  assert.strictEqual(stageOf(base, 'cheap'), 'triage');
  assert.strictEqual(stageOf({ ...base, triage: triaged }, 'cheap'), 'gate');
  assert.strictEqual(stageOf({ ...base, triage: triaged, gate: { action: 'fix' } }, 'cheap'), 'fix');
  assert.strictEqual(
    stageOf({ ...base, triage: triaged, gate: { action: 'report_only' } }, 'cheap'), 'report');
  assert.strictEqual(stageOf({ ...base, disposition: { state: 'fixed' } }, 'cheap'), 'done');
});

t('an unverified patch is at verify, a failed first attempt goes back to fix', () => {
  const fixing = { ...base, triage: triaged, gate: { action: 'fix' } };
  assert.strictEqual(stageOf({ ...fixing, patches: [{}] }, 'full'), 'verify');
  const failed = { verification: { ...allPass, functional_control: { status: 'fail' } } };
  assert.strictEqual(stageOf({ ...fixing, patches: [failed] }, 'full'), 'fix');
  assert.strictEqual(stageOf({ ...fixing, patches: [failed, failed] }, 'full'), 'report');
});

t('a verified patch reaches report', () => {
  assert.strictEqual(
    stageOf({ ...base, triage: triaged, gate: { action: 'fix' },
              patches: [{ verification: allPass }] }, 'full'), 'report');
});

t('stageOf judges one patch with the obligations of the run level', () => {
  const fixing = { ...base, triage: triaged, gate: { action: 'fix' } };
  const cheapPass = { frozen_target: { status: 'pass' }, deterministic_guard: { status: 'pass' },
    regression_suite: { status: 'unavailable' }, no_new_findings: { status: 'pass' } };
  const one = (verification) => ({ ...fixing, patches: [{ verification }] });
  assert.strictEqual(stageOf(one({}), 'none'), 'report');
  assert.strictEqual(stageOf(one({}), 'cheap'), 'fix');
  assert.strictEqual(stageOf(one(cheapPass), 'cheap'), 'report');
  assert.strictEqual(stageOf(one(cheapPass), 'full'), 'fix');
  assert.strictEqual(stageOf(one(allPass), 'full'), 'report');
  assert.strictEqual(stageOf(one({ ...cheapPass, no_new_findings: { status: 'fail' } }), 'cheap'), 'fix');
});

t('stageOf refuses a missing or unknown level instead of judging at full', () => {
  assert.throws(() => stageOf(base), /unknown verify level: undefined/);
  assert.throws(() => stageOf(base, 'toString'), /unknown verify level: toString/);
});

t('verified requires all seven obligations', () => {
  assert.strictEqual(evaluateVerification(allPass).verified, true);
  for (const o of OBLIGATIONS) {
    const one = { ...allPass, [o]: { status: 'fail' } };
    const r = evaluateVerification(one);
    assert.strictEqual(r.verified, false, `${o} failing should sink the verdict`);
    assert.deepStrictEqual(r.failed, [o]);
  }
});

t('a missing obligation is not a pass', () => {
  const partial = { ...allPass };
  delete partial.hostile_auditor;
  const r = evaluateVerification(partial);
  assert.strictEqual(r.verified, false);
  assert.deepStrictEqual(r.missing, ['hostile_auditor']);
});

t('a red suite on base or a rescan that could not run is excused, and nothing else is', () => {
  const red = { ...allPass, regression_suite: { status: 'unavailable' } };
  const r = evaluateVerification(red);
  assert.strictEqual(r.verified, true);
  assert.deepStrictEqual(r.unavailable, ['regression_suite']);
  const quiet = { ...allPass, no_new_findings: { status: 'unavailable' } };
  assert.deepStrictEqual(evaluateVerification(quiet).unavailable, ['no_new_findings']);
  const other = { ...allPass, hostile_auditor: { status: 'unavailable' } };
  assert.strictEqual(evaluateVerification(other).verified, false);
});

t('a quiet rescan cannot reach the verdict', () => {
  const quiet = { ...allPass, differential_witness: { status: 'fail' },
                  rescan: { original_absent: true }, original_absent: true };
  assert.strictEqual(evaluateVerification(quiet).verified, false,
    'original_absent must not rescue a failed obligation');
  const noisy = { ...allPass, rescan: { original_absent: false }, original_absent: false };
  assert.strictEqual(evaluateVerification(noisy).verified, true,
    'a still-firing rule must not sink an otherwise verified fix');
});

t('at the argued tier the witness pair may be unavailable, and at no other tier', () => {
  const pair = { ...allPass, differential_witness: { status: 'unavailable' },
    functional_control: { status: 'unavailable' } };
  assert.deepStrictEqual(evaluateVerification(pair, OBLIGATIONS, 'argued'), {
    verified: true, failed: [], unavailable: ['differential_witness', 'functional_control'],
    missing: [], skipped: [],
  });
  assert.deepStrictEqual(evaluateVerification(pair, OBLIGATIONS, 'dynamic').failed,
    ['differential_witness', 'functional_control']);
  assert.deepStrictEqual(evaluateVerification(pair).failed,
    ['differential_witness', 'functional_control']);
  assert.strictEqual(
    evaluateVerification({ ...pair, hostile_auditor: { status: 'unavailable' } }, OBLIGATIONS, 'argued').verified,
    false);
});

t('at full, an argued patch with its pair excused reaches report, and a dynamic one goes back to fix', () => {
  const withTier = (tier) => ({ ...base,
    triage: { verdict: 'exploitable', contract: { witness: { tier } } },
    gate: { action: 'fix' },
    patches: [{ verification: { ...allPass, differential_witness: { status: 'unavailable' },
      functional_control: { status: 'unavailable' } } }],
  });
  assert.strictEqual(stageOf(withTier('argued'), 'full'), 'report');
  assert.strictEqual(stageOf(withTier('dynamic'), 'full'), 'fix');
});

section('audit: cross-field rules the schema now enforces');

const agentSchema = JSON.parse(
  fs.readFileSync(path.join(ROOT, 'schema/agent-results.schema.json'), 'utf8'));
const AUDIT = agentSchema.$defs.audit;
const ref = { file: 'src/routes/files.js', line: 9, note: 'sink' };
const audit = (over) => ({
  verdict: 'enforces_invariant',
  trace: [{ step: 'attacker-controlled path reaches the read', loc: ref }],
  stopped_at: ref,
  uncovered_siblings: [],
  explanation: 'the join is resolved and prefix-checked before the read',
  ...over,
});
const auditErrs = (o) => validate(AUDIT, o, path.join(ROOT, 'schema'));

t('a well-formed enforces_invariant audit validates', () => {
  assert.deepStrictEqual(auditErrs(audit()), []);
});

t('enforces_invariant without a stopped_at is rejected', () => {
  assert.ok(auditErrs(audit({ stopped_at: null })).length > 0,
    'the auditor must point at the line where the counterexample dies');
});

t('only incomplete_enforcement may carry uncovered siblings', () => {
  assert.ok(auditErrs(audit({ uncovered_siblings: [ref] })).length > 0);
  assert.ok(auditErrs(audit({ verdict: 'silences_rule', uncovered_siblings: [ref] })).length > 0);
  assert.deepStrictEqual(
    auditErrs(audit({ verdict: 'incomplete_enforcement', uncovered_siblings: [ref] })), []);
});

t('a refuting verdict needs no stopped_at', () => {
  assert.deepStrictEqual(auditErrs(audit({ verdict: 'moves_trust', stopped_at: null })), []);
});

section('ingest: a dropped result is counted, never silent');

t('a SARIF result with no location is recorded in dropped', () => {
  // Synthetic, because the real fixtures contain no locationless result. This is the error
  // path, and the point of the test is that it leaves a trace in the summary.
  const sarif = { runs: [{ tool: { driver: { rules: [{ id: 'js/x' }] } }, results: [
    { ruleId: 'js/x' },
    { ruleId: 'js/x', locations: [{ physicalLocation: { artifactLocation: {} } }] },
  ] }] };
  const res = normalize({ codeql: sarif }, repo, 'run-drop');
  assert.strictEqual(res.findings.length, 0);
  assert.strictEqual(res.dropped.length, 2, `expected 2 drops, got ${res.dropped.length}`);
  assert.ok(res.dropped.every((d) => d.includes('js/x')), res.dropped.join('; '));
});

t('the real fixtures still drop nothing', () => {
  const res = normalize(raw, repo, 'run-test');
  assert.deepStrictEqual(res.dropped, []);
  assert.strictEqual(res.findings.length, 3);
});

section('identity: a path is repo-relative or it is dropped');

const { toRepoRelative } = require(path.join(ROOT, 'bin/normalize.ts'));

t('an absolute path inside the root is relativised, so identity survives a rescan', () => {
  assert.strictEqual(toRepoRelative('/tmp/root/src/app.js', '/tmp/root'), 'src/app.js');
  assert.strictEqual(toRepoRelative('/tmp/root/./src/app.js', '/tmp/root'), 'src/app.js');
  assert.strictEqual(toRepoRelative('src/app.js', '/tmp/root'), 'src/app.js');
});

t('a path outside the root is null, which foldSites counts as a drop', () => {
  assert.strictEqual(toRepoRelative('/etc/passwd', '/tmp/root'), null);
  assert.strictEqual(toRepoRelative('../escape.js', '/tmp/root'), null);
  assert.strictEqual(toRepoRelative(null, '/tmp/root'), null);
});

t('the same defect scanned by absolute and relative path gets ONE id', () => {
  // The live failure this guards: run.cjs rescans a worktree by absolute path, so every
  // surviving finding minted a fresh id and no_new_findings could never pass.
  const absRaw = JSON.parse(JSON.stringify(raw));
  for (const r of absRaw.semgrep.results) r.path = path.join(REPO, r.path);
  const relIds = normalize(raw, repo, 'r').findings.map((f) => f.id).sort();
  const absIds = normalize(absRaw, repo, 'r').findings.map((f) => f.id).sort();
  assert.deepStrictEqual(absIds, relIds,
    'an absolute path must not mint a different identity for the same defect');
});

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
