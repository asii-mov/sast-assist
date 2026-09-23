#!/usr/bin/env node
// A stand-in for the `claude` CLI, found on PATH by bin/agent.ts exactly as the real one is.
// It reads its behaviour from the JSON file named by SAST_FAKE_CLAUDE:
//   { log, triage: { "<file>": <triage> },
//     fix: [{ act: "patch"|"crash"|"cannot_fix"|"disable", witness, stray, commit }], audit }
// A candidate whose first site is not a key of `triage` is refuted. The n-th fixer call follows
// fix[n], and the last entry repeats. `audit` defaults to a pass; act `disable` answers a patch
// that turns the endpoint off instead of enforcing the invariant.

import fs from 'fs';
import { execFileSync } from 'child_process';

const argv = process.argv.slice(2);
const prompt = argv[argv.indexOf('-p') + 1] || '';
const scenario = JSON.parse(fs.readFileSync(process.env.SAST_FAKE_CLAUDE, 'utf8'));

const role = prompt.startsWith('Refute this candidate') ? 'triage'
  : prompt.startsWith('Make the invariant below true') ? 'fix'
    : prompt.startsWith('Disprove the claim below') ? 'audit' : 'unknown';

const priorCalls = fs.existsSync(scenario.log)
  ? fs.readFileSync(scenario.log, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l))
  : [];
fs.appendFileSync(scenario.log, `${JSON.stringify({ role, cwd: process.cwd(), argv })}\n`);

const answer = (obj) => {
  process.stdout.write(JSON.stringify([
    { type: 'system', subtype: 'init' },
    { type: 'result', subtype: 'success', is_error: false, result: `Done.\n${JSON.stringify(obj)}` },
  ]));
  process.exit(0);
};

const REFUTED = {
  verdict: 'not_exploitable', established_by: 'agent',
  refutation: { reason: 'input_is_not_attacker_controlled', control: null, explanation: 'the value is a literal' },
};

const PATCHED_SINK = [
  "  if (!ALLOWED.has(name)) { res.statusCode = 400; return res.end('unknown name'); }",
  '  const target = path.join(ROOT, path.basename(String(name)));',
].join('\n');

const WITNESS = [
  "const assert = require('assert');",
  "assert.strictEqual(statusFor('../../secret.txt'), 400);",
  "assert.strictEqual(statusFor('hello.txt'), 200);",
  '',
].join('\n');

const AUDIT_PASS = {
  verdict: 'enforces_invariant',
  trace: [{ step: 'the name is checked against the files already in the public directory',
    loc: { file: 'src/routes/files.js', line: 9, note: 'allowlist' } }],
  stopped_at: { file: 'src/routes/files.js', line: 9, note: 'unknown names are answered with 400' },
  uncovered_siblings: [], explanation: 'the traversal name is not in the allowlist, so the read never runs',
};

function patch(step) {
  const src = 'src/routes/files.js';
  const raw = fs.readFileSync(src, 'utf8');
  // `disable` keeps the sink line intact and makes it unreachable, instead of enforcing the
  // invariant: a stand-in for a fixer that games the differential by breaking the endpoint.
  const text = step.act === 'disable'
    ? raw.replace('function read(req, res) {',
      "function read(req, res) {\n  res.statusCode = 404; return res.end('not found');")
    : raw.replace(/^(const ROOT = .*)$/m, '$1\nconst ALLOWED = new Set(fs.readdirSync(ROOT));')
      .replace('  const target = path.join(ROOT, name);', PATCHED_SINK);
  fs.writeFileSync(src, text);
  const files = [src];
  if (step.witness) {
    fs.mkdirSync('test', { recursive: true });
    fs.writeFileSync('test/files.test.js', WITNESS);
    files.push('test/files.test.js');
  }
  if (step.stray) {
    fs.mkdirSync('.claude', { recursive: true });
    fs.writeFileSync('.claude/settings.json', '{"hooks":{}}\n');
  }
  if (step.commit !== false) {
    execFileSync('git', step.stray ? ['add', '-A'] : ['add', '--', ...files]);
    execFileSync('git', ['-c', 'commit.gpgsign=false', 'commit', '-q', '-m', 'enforce the allowlist']);
  }
  const note = step.act === 'disable' ? 'every request is refused'
    : 'the name must already exist in the public directory';
  answer({ outcome: 'patched', declared_files: files, enforcement_note: note });
}

if (role === 'triage') {
  const site = /^sites:\n {2}(\S+?):\d+/m.exec(prompt);
  answer((site && scenario.triage[site[1]]) || REFUTED);
}

if (role === 'fix') {
  const n = priorCalls.filter((c) => c.role === 'fix').length;
  const step = scenario.fix[Math.min(n, scenario.fix.length - 1)];
  if (step.act === 'crash') { process.stderr.write('fake fixer crashed\n'); process.exit(1); }
  if (step.act === 'cannot_fix') answer({ outcome: 'cannot_fix', reason: step.reason });
  patch(step);
}

if (role === 'audit') answer(scenario.audit || AUDIT_PASS);

process.stderr.write(`fake claude has no answer for a ${role} prompt\n`);
process.exit(3);
