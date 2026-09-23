#!/usr/bin/env node
'use strict';
// The driver. One command runs scan, normalize, pre-resolve, triage, gate, fix, verify, report.
//
// Every stage re-derives itself from what is on disk via stageOf, so re-running the command is
// the resume path and there is no --resume flag and no status field to fall out of sync.
//
// This file is also where the skill's central rule is enforced mechanically rather than by
// prose: buildFixPrompt assembles the fixer's prompt field by field from the security contract
// and the flow, and assertNoLeak refuses to send a prompt that carries a rule id, a scanner
// name, a scanner message or an observation. A finding record is never handed to a fixer whole.

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { spawnSync } = require('child_process');

const ROOT = path.resolve(__dirname, '..');
const FINDING_SCHEMA = path.join(ROOT, 'schema/finding.schema.json');
const AGENT_SCHEMA = path.join(ROOT, 'schema/agent-results.schema.json');

const { stageOf, evaluateVerification, VERIFY_LEVELS } = require('./stage.cjs');
const { gate, order } = require('./gate.cjs');
const { normalize, makeRepo } = require('./normalize.cjs');
const { validate } = require('./validate.cjs');
const { guardDiff } = require('./patch-guard.cjs');

// --out is operator-controlled and git rejects spaces, `~ ^ : ? * [ \\`, `..` and a leading dot.
const refSafe = (s) => String(s).replace(/[^A-Za-z0-9._-]+/g, '-').replace(/\.{2,}/g, '.')
  .replace(/^[-.]+|[.-]+$/g, '') || 'run';
const sha256 = (s) => crypto.createHash('sha256').update(s, 'utf8').digest('hex');

// ------------------------------------------------------------------------ cli

const USAGE = `usage: run.cjs --target=DIR [options]
  --target=DIR        repository to remediate (required)
  --out=DIR           output dir (default ~/sast-remediate/<repo>/run-<N>)
  --fix-at=LEVEL      informational|low|medium|high|critical  (default medium)
  --verify=LEVEL      none|cheap|full                          (default cheap)
  --scanners=LIST     semgrep,codeql   (default both)
  --scans=DIR         reuse existing scanner output, skip scanning
  --triage-only       stop after the gate, write no patches
  --max-findings=N    bound the run; the rest become deferred, never dropped
  --model=NAME        model for agent calls
  --allow-unverified-fixes  patch even when no test command is discoverable
  --dry-run           print the plan and exit`;

class UsageError extends Error {}

const SEVERITIES = ['informational', 'low', 'medium', 'high', 'critical'];
const SCANNERS = ['semgrep', 'codeql'];

function parseArgs(argv) {
  const opts = {
    target: null, out: null, fixAt: 'medium', verify: 'cheap',
    scanners: [...SCANNERS], scans: null, triageOnly: false, maxFindings: Infinity,
    model: null, allowUnverifiedFixes: false, dryRun: false, timeoutMs: 300000,
  };
  for (const a of argv) {
    const i = a.indexOf('=');
    const key = (i < 0 ? a : a.slice(0, i)).replace(/^--/, '');
    const val = i < 0 ? true : a.slice(i + 1);
    switch (key) {
      case 'target': opts.target = String(val); break;
      case 'out': opts.out = String(val); break;
      case 'fix-at': opts.fixAt = String(val); break;
      case 'verify': opts.verify = String(val); break;
      case 'scanners': opts.scanners = String(val).split(',').map((s) => s.trim()).filter(Boolean); break;
      case 'scans': opts.scans = String(val); break;
      case 'triage-only': opts.triageOnly = true; break;
      case 'max-findings': opts.maxFindings = Number(val); break;
      case 'model': opts.model = String(val); break;
      case 'allow-unverified-fixes': opts.allowUnverifiedFixes = true; break;
      case 'timeout-ms': opts.timeoutMs = Number(val); break;
      case 'dry-run': opts.dryRun = true; break;
      default: throw new UsageError(`unknown option: ${a}`);
    }
  }
  if (!opts.target) throw new UsageError('--target is required');
  if (!SEVERITIES.includes(opts.fixAt)) throw new UsageError(`--fix-at must be one of ${SEVERITIES.join('|')}`);
  if (!(opts.verify in VERIFY_LEVELS)) throw new UsageError(`--verify must be one of ${Object.keys(VERIFY_LEVELS).join('|')}`);
  for (const s of opts.scanners) if (!SCANNERS.includes(s)) throw new UsageError(`unknown scanner: ${s}`);
  if (!opts.scanners.length) throw new UsageError('--scanners must name at least one scanner');
  if (!(opts.maxFindings > 0)) throw new UsageError('--max-findings must be a positive integer');
  return opts;
}

// ----------------------------------------------------------------------- deps

// Everything that touches a process or an agent arrives through here, so a test drives the whole
// pipeline without a scanner, a network or a real model.
function realExec(cmd, args, o = {}) {
  const r = spawnSync(cmd, args, {
    cwd: o.cwd, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024,
    timeout: o.timeoutMs || 900000, env: process.env,
  });
  return {
    status: r.error ? -1 : r.status,
    stdout: r.stdout || '',
    stderr: r.stderr || (r.error ? r.error.message : ''),
  };
}

// Each collaborator is resolved at the moment it is used, so a plan still prints and a
// triage-only run still finishes when a module a later stage needs is missing.
function realDeps() {
  const lazy = (mod, name) => (...a) => require(mod)[name](...a);
  return {
    runAgent: lazy('./agent.cjs', 'runAgent'),
    partition: lazy('./partition.cjs', 'partition'),
    renderRemediation: lazy('./report.cjs', 'renderRemediation'),
    renderHandoff: lazy('./report.cjs', 'renderHandoff'),
    exec: realExec,
    onPath,
    log: (m) => console.error(m),
    now: () => new Date().toISOString(),
  };
}

const onPath = (bin) => (process.env.PATH || '').split(path.delimiter)
  .some((d) => d && fs.existsSync(path.join(d, bin)));

const ensureDir = (d) => fs.mkdirSync(d, { recursive: true });
const writeJson = (f, o) => { ensureDir(path.dirname(f)); fs.writeFileSync(f, JSON.stringify(o, null, 2) + '\n'); };
const readJson = (f) => JSON.parse(fs.readFileSync(f, 'utf8'));

function defaultOutDir(target) {
  const base = path.join(os.homedir(), 'sast-remediate', path.basename(target));
  let n = 1;
  if (fs.existsSync(base)) {
    for (const d of fs.readdirSync(base)) {
      const m = /^run-(\d+)$/.exec(d);
      if (m) n = Math.max(n, Number(m[1]) + 1);
    }
  }
  return path.join(base, `run-${n}`);
}

// ------------------------------------------------------------------- 1. scan

const LANGS = [
  ['javascript', ['package.json']],
  ['python', ['pyproject.toml', 'requirements.txt', 'setup.py']],
  ['go', ['go.mod']],
  ['ruby', ['Gemfile']],
  ['java', ['pom.xml', 'build.gradle', 'build.gradle.kts']],
  ['rust', ['Cargo.toml']],
];
const detectLanguage = (root) =>
  (LANGS.find(([, files]) => files.some((f) => fs.existsSync(path.join(root, f)))) || [null])[0];

const TEST_COMMANDS = [
  ['package.json', (root) => {
    const pkg = readJson(path.join(root, 'package.json'));
    return pkg.scripts && pkg.scripts.test ? 'npm test' : null;
  }],
  ['pyproject.toml', () => 'pytest'],
  ['pytest.ini', () => 'pytest'],
  ['go.mod', () => 'go test ./...'],
  ['Cargo.toml', () => 'cargo test'],
];
function discoverTestCommand(root) {
  for (const [marker, make] of TEST_COMMANDS) {
    if (!fs.existsSync(path.join(root, marker))) continue;
    try { const c = make(root); if (c) return c; } catch { /* a malformed manifest is not a test command */ }
  }
  return null;
}

// A scanner that is absent or exits non-zero is recorded and the run continues with what it has.
// Both failing is fatal, because normalizing nothing would report a clean repository.
function runScanners(opts, deps, target, scanDir) {
  const raw = {};
  const scanners = [];

  if (opts.scans) {
    for (const [name, file] of [['semgrep', 'semgrep.json'], ['codeql', 'codeql.sarif']]) {
      if (!opts.scanners.includes(name)) continue;
      const p = path.join(opts.scans, file);
      if (!fs.existsSync(p)) { scanners.push({ name, status: 'absent', detail: `${p} not found` }); continue; }
      raw[name] = readJson(p);
      scanners.push({ name, status: 'reused', detail: p });
    }
    return { raw, scanners };
  }

  ensureDir(scanDir);
  const present = deps.onPath || onPath;
  for (const name of opts.scanners) {
    if (!present(name)) { scanners.push({ name, status: 'absent', detail: 'not on PATH' }); continue; }
    if (name === 'semgrep') {
      const out = path.join(scanDir, 'semgrep.json');
      const r = deps.exec('semgrep', ['scan', '--config', 'p/default', `--json-output=${out}`, target]);
      if (!fs.existsSync(out)) { scanners.push({ name, status: 'failed', detail: trim(r.stderr) }); continue; }
      raw.semgrep = readJson(out);
      scanners.push({ name, status: r.status === 0 ? 'ok' : 'partial', detail: r.status === 0 ? out : trim(r.stderr) });
    } else {
      const lang = detectLanguage(target);
      if (!lang) { scanners.push({ name, status: 'failed', detail: 'no language detected' }); continue; }
      const db = path.join(scanDir, 'codeql-db');
      const out = path.join(scanDir, 'codeql.sarif');
      const c = deps.exec('codeql', ['database', 'create', db, `--language=${lang}`, `--source-root=${target}`, '--overwrite']);
      if (c.status !== 0) { scanners.push({ name, status: 'failed', detail: trim(c.stderr) }); continue; }
      const a = deps.exec('codeql', ['database', 'analyze', db, '--format=sarif-latest', `--output=${out}`,
        '--sarif-add-snippets', `codeql/${lang}-queries:codeql-suites/${lang}-security-extended.qls`]);
      if (!fs.existsSync(out)) { scanners.push({ name, status: 'failed', detail: trim(a.stderr) }); continue; }
      raw.codeql = readJson(out);
      scanners.push({ name, status: a.status === 0 ? 'ok' : 'partial', detail: a.status === 0 ? out : trim(a.stderr) });
    }
  }
  return { raw, scanners };
}

const trim = (s) => String(s || '').trim().split('\n').slice(-3).join(' ').slice(0, 300);

// --------------------------------------------------------- 2. normalize and validate

function normalizeAndValidate(raw, target, runId) {
  const res = normalize(raw, makeRepo(target), runId);
  const errs = validate(readJson(FINDING_SCHEMA), res.findings, path.dirname(FINDING_SCHEMA));
  if (errs.length) {
    throw new Error(`normalized findings do not validate:\n  ${errs.slice(0, 10).join('\n  ')}`);
  }
  return res;
}

// ------------------------------------------------------------- 3. pre-resolve

// Path policy. A rejection here is a policy call, not a security claim, and it produces a real
// triage with established_by deterministic_prepass rather than a skipped state, so nothing
// downstream has to special-case a finding that never saw an agent.
const POLICY_PATHS = [
  ['test', /(^|\/)(tests?|spec|specs|__tests__|testdata|fixtures?)(\/|$)|[._-](test|spec)\.[A-Za-z0-9]+$|_test\.go$/i],
  ['vendor', /(^|\/)(vendor|node_modules|third[_-]?party|bower_components|\.venv|site-packages)(\/|$)/i],
  ['generated', /(^|\/)(generated|gen|build|dist|out|target)(\/|$)|\.(pb|generated)\.[A-Za-z0-9]+$|_pb2\.py$/i],
  ['minified', /\.min\.(js|css)$|\.bundle\.js$|-min\.js$/i],
  ['migrations', /(^|\/)(migrations?|db\/migrate|alembic\/versions)(\/|$)/i],
];

function pathPolicy(finding) {
  const hits = finding.sites.map((s) => {
    const rule = POLICY_PATHS.find(([, re]) => re.test(s.locus.file));
    return rule ? { file: s.locus.file, kind: rule[0], pattern: String(rule[1]) } : null;
  });
  // Every site must match, or the finding still reaches code the operator asked about.
  return hits.every(Boolean) ? hits[0] : null;
}

function preResolve(findings) {
  let resolved = 0;
  for (const f of findings) {
    if (f.triage) continue;
    const hit = pathPolicy(f);
    if (!hit) continue;
    f.triage = {
      verdict: 'not_exploitable',
      established_by: 'deterministic_prepass',
      refutation: {
        reason: 'test_or_fixture_or_generated_code',
        control: null,
        explanation: `path policy: every site lies under ${hit.kind} code (${hit.file}). `
          + 'This is a scope decision, not a security claim.',
      },
    };
    resolved++;
  }
  return resolved;
}

// ----------------------------------------------------------------- 4. triage

const TRIAGE_FLOW_NOTE = {
  traced: 'The path below is this candidate\'s claimed route from source to sink. Attack it. Find the '
    + 'step where it is wrong. Check whether any step normalizes, validates, binds, escapes or '
    + 'authorizes the value. Compare what each component guarantees against what the next assumes.',
  sink_only: 'No dataflow path was provided. Establish reachability from an attacker-controlled entry '
    + 'point yourself before asserting anything. If you cannot reach this sink from untrusted input, '
    + 'the verdict is not_exploitable with reason input_is_not_attacker_controlled. If the entry point '
    + 'is outside this repository, the verdict is undecidable.',
};

function flowBlock(flow) {
  if (flow.kind === 'sink_only') {
    const s = flow.sink;
    return `sink: ${s.file}:${s.line}${s.symbol ? ` in ${s.symbol}` : ''}\n    ${s.code}`;
  }
  return flow.steps.map((s, i) =>
    `${String(i + 1).padStart(2)}. [${s.role}] ${s.file}:${s.line}${s.symbol ? ` in ${s.symbol}` : ''}\n    ${s.code}`
  ).join('\n');
}

// A prompt that announces "here is the return schema" has to actually carry it. The
// agent-results defs reach into finding.schema.json by $ref, and an unresolved $ref in a prompt
// is a pointer to a file the agent was never handed, so it guesses the envelope instead. That
// is not hypothetical: it cost a real triage on the fixture app, where the agent returned a
// bare contract where a verdict envelope belonged, then put mechanical-tier fields on an
// `argued` witness. Bundle every transitively referenced def under a local $defs and rewrite
// the pointers, so the shape in the prompt is the shape the validator enforces.
// agent-results carries no local $defs refs of its own, only cross-file ones, so any $defs
// pointer reached from here resolves against finding.schema.json without ambiguity.
const DEF_REF = /^(?:finding\.schema\.json)?#\/\$defs\/(.+)$/;

function bundleDef(name) {
  const agent = readJson(AGENT_SCHEMA);
  const finding = readJson(FINDING_SCHEMA);
  const defs = {};
  const walk = (node) => {
    if (Array.isArray(node)) return node.map(walk);
    if (!node || typeof node !== 'object') return node;
    const out = {};
    for (const [k, v] of Object.entries(node)) {
      const m = k === '$ref' && typeof v === 'string' ? DEF_REF.exec(v) : null;
      if (m) {
        const key = m[1];
        out.$ref = `#/$defs/${key}`;
        // Seed before recursing so a cyclic def resolves to the seed instead of looping.
        if (!(key in defs)) { defs[key] = null; defs[key] = walk(finding.$defs[key]); }
        continue;
      }
      out[k] = walk(v);
    }
    return out;
  };
  const root = walk(agent.$defs[name]);
  return JSON.stringify({ ...root, $defs: defs }, null, 2);
}

function buildTriagePrompt(f, ctx) {
  const rubric = fs.readFileSync(path.join(ROOT, 'references/TRIAGE.md'), 'utf8');
  const branch = bundleDef('triage');
  const sites = f.sites.map((s) => {
    const obs = s.observations.map((o) =>
      `    - ${o.scanner} ${o.rule_id}: ${o.message}\n      claimed: ${JSON.stringify(o.claimed)}`
      + `${o.suppressed_at_source ? '\n      suppressed at source' : ''}`).join('\n');
    return `  ${s.locus.file}:${s.locus.line_at_scan}${s.locus.symbol ? ` in ${s.locus.symbol}` : ''}\n${obs}`;
  }).join('\n');

  return [
    'Refute this candidate from repository source. You are not assessing it, you are trying to',
    'disprove it. Return exactly one JSON object and no other text.',
    '',
    `# Candidate\ninvariant class: ${f.invariant_class}\nsites:\n${sites}`,
    '',
    `# Flow (${f.flow.kind})\n${TRIAGE_FLOW_NOTE[f.flow.kind]}\n\n${flowBlock(f.flow)}`,
    '',
    `# Enclosing source\n\`\`\`\n${f.context.enclosing_excerpt}\n\`\`\``,
    '',
    `# Repository facts\ntest command: ${ctx.testCommand || 'none discovered'}`,
    `app harness: ${ctx.appHarness ? JSON.stringify(ctx.appHarness) : 'none discovered'}`,
    `enabled witness tiers: ${ctx.witnessTiers.join(', ')}`,
    '',
    `# Rubric\n${rubric}`,
    '',
    `# Return schema (the triage branch, verbatim)\n\`\`\`json\n${branch}\n\`\`\``,
  ].join('\n');
}

const TRIAGE_TOOLS = ['Read', 'Grep', 'Glob'];

async function triageAll(findings, ctx) {
  const queue = order(findings).filter((f) => stageOf(f) === 'triage');
  const budget = ctx.opts.maxFindings;
  const doing = queue.slice(0, budget);
  const deferred = queue.slice(budget).map((f) => f.id);

  for (const f of doing) {
    const res = await ctx.deps.runAgent({
      prompt: buildTriagePrompt(f, ctx),
      schemaPath: AGENT_SCHEMA, schemaPointer: '#/$defs/triage',
      cwd: ctx.target, model: ctx.opts.model, timeoutMs: ctx.opts.timeoutMs,
      allowedTools: TRIAGE_TOOLS,
    });
    if (!res.ok) {
      // Malformed output is discarded, never repaired. agent.cjs already spent its one re-run.
      f.disposition = { state: 'deferred', reason: 'triage_agent_failed', detail: res.reason };
    } else if (res.data.split) {
      // Re-emitting the split sites as separate findings is not implemented; the record is
      // handed to a human rather than silently triaged under a contract that fits neither half.
      f.disposition = { state: 'deferred', reason: 'split_requested', detail: res.data.split };
    } else {
      f.triage = res.data;
    }
    ctx.save(f);
  }
  return { triaged: doing.length, deferred };
}

// ------------------------------------------------------------------- 5. gate

function gateAll(findings, policy, ctx) {
  let n = 0;
  for (const f of findings) {
    if (stageOf(f) !== 'gate') continue;
    f.gate = gate(f.triage, policy);
    ctx.save(f);
    n++;
  }
  return n;
}

// -------------------------------------------------------------------- 6. fix

// THE CENTRAL RULE OF THIS SKILL.
//
// The fixer is never shown the rule. No rule id, no scanner name, no scanner message, no
// observation. You cannot game a matcher you were never shown. So the prompt is assembled from
// named fields of the frozen contract and the flow, and a finding record is never stringified
// into it. The flow's per-step `note` is scanner-authored text and is therefore dropped; the
// materialized source line is what the fixer actually needs.
function witnessBrief(w) {
  switch (w.tier) {
    case 'dynamic':
      return `tier: dynamic\nattack: ${JSON.stringify(w.attack)}\nobservable: ${JSON.stringify(w.observable)}\n`
        + `functional control: ${JSON.stringify(w.control)}\n`
        + 'It must fire before your change and fall silent after. The control must pass on both trees.';
    case 'executable':
      return `tier: executable\nframework: ${w.framework}\nentrypoint: ${w.entrypoint}\n`
        + `attack input: ${w.attack_input}\nasserts: ${w.asserts}\ncommand: ${w.command_template}\n`
        + `functional control: ${JSON.stringify(w.control)}\n`
        + 'Commit this test. It must fail before your change and pass after.';
    case 'structural':
      // The structural rule itself is a matcher, and handing the fixer a matcher is the exact
      // thing this rule forbids. It gets the anchor and nothing else.
      return `tier: structural\nanchor: ${w.anchor.file}:${w.anchor.line_at_scan}\n`
        + 'A structural check authored before your change will be run against the anchor.';
    case 'argued':
      return `tier: argued\nobstacle: ${w.obstacle}\n${w.why}\n`
        + 'No mechanical witness exists here. Make the enforcement legible in the code itself.';
    default:
      throw new Error(`unknown witness tier: ${w.tier}`);
  }
}

function buildFixPrompt(f, ctx, priorFailures) {
  const c = f.triage.contract;
  const parts = [
    'Make the invariant below true. You are given a property about values and boundaries, not a',
    'defect report. Return exactly one JSON object and no other text.',
    '',
    `# Invariant\n${c.invariant}`,
    '',
    `# A value that breaks it today\n${c.violating_input}`,
    '',
    `# Enforcement point\n${c.enforcement_point.file}`
      + `${c.enforcement_point.symbol ? ` in ${c.enforcement_point.symbol}` : ''}\n${c.enforcement_point.rationale}`,
    '',
    `# Route the value takes\n${flowBlock(f.flow)}`,
    '',
    `# Enclosing source\n\`\`\`\n${f.context.enclosing_excerpt}\n\`\`\``,
    '',
    `# Witness\n${witnessBrief(c.witness)}`,
    '',
    `# You may modify only\n${c.writable_scope.map((g) => `- ${g}`).join('\n')}`,
    '',
    `# Forbidden resolutions\n${c.forbidden_resolutions.map((r) => `- ${r}`).join('\n')}`,
    '',
    `# Repository commands\nbuild: ${ctx.buildCommand || 'none discovered'}`,
    `test: ${ctx.testCommand || 'none discovered'}`,
    `lint: ${ctx.lintCommand || 'none discovered'}`,
  ];
  if (priorFailures && priorFailures.length) {
    parts.push('', '# The previous attempt failed these checks\n'
      + priorFailures.map((x) => `- ${x.obligation}: ${x.reason}`).join('\n'));
  }
  parts.push('', 'Commit your change, and the witness file when the tier has one, to the current branch.',
    'Return {"outcome":"patched","declared_files":[...],"enforcement_note":"..."}',
    'or {"outcome":"cannot_fix","reason":"..."} if the contract cannot be satisfied as written.');
  return parts.join('\n');
}

// Prose cannot enforce the rule above, so this does. It is derived from the record rather than
// from a fixed word list, because the rule ids this skill has never seen are the ones that matter.
const RULE_ID_FORM =
  /\b(?:js|javascript|ts|typescript|py|python|java|cpp|cs|go|rb|ruby|swift|rust|ql|actions)\/[a-z0-9]+(?:-[a-z0-9]+)+\b(?!\.[a-z]{1,4}\b)/i;

function leakTerms(finding) {
  const terms = new Set(SCANNERS);
  for (const s of finding.sites) {
    for (const o of s.observations) {
      terms.add(o.scanner);
      terms.add(o.rule_id);
      if (o.rule_name) terms.add(o.rule_name);
      if (o.native_fingerprint) terms.add(o.native_fingerprint);
      if (o.message) terms.add(o.message.trim());
    }
  }
  return [...terms].filter((t) => t && t.length >= 4);
}

const leakError = (prompt, finding) => {
  try { assertNoLeak(prompt, finding); return null; } catch (e) { return e.message; }
};

function assertNoLeak(prompt, finding) {
  const hay = prompt.toLowerCase();
  const hit = leakTerms(finding).find((t) => hay.includes(t.toLowerCase()));
  if (hit) throw new Error(`fixer prompt leaked scanner material: ${JSON.stringify(hit.slice(0, 120))}`);
  const form = RULE_ID_FORM.exec(prompt);
  if (form) throw new Error(`fixer prompt carries a rule id: ${JSON.stringify(form[0])}`);
}

const FIX_TOOLS = ['Read', 'Grep', 'Glob', 'Edit', 'Write', 'Bash'];
const AUDIT_TOOLS = ['Read', 'Grep', 'Glob'];

function collectDiff(wt, base, ctx) {
  // add -A first so an untracked witness file is part of the diff the guard sees.
  ctx.git(['add', '-A'], wt);
  const r = ctx.git(['diff', '--cached', base], wt);
  return r.status === 0 ? r.stdout : '';
}

async function fixOne(f, ctx) {
  const attempt = f.patches.length + 1;
  // Branches live in the target repository, which outlives any one run; everything else lives
  // in the per-run output directory. Without the run id, a second run against the same
  // repository collided with the first run's branches and died before the fixer was called.
  const branch = `sast-fix/${refSafe(ctx.runId)}/${f.id}/${attempt}`;
  const wt = path.join(ctx.outDir, 'worktrees', `${f.id}-${attempt}`);
  const add = ctx.git(['worktree', 'add', '-b', branch, wt, ctx.base]);
  if (add.status !== 0) {
    f.patches.push({ attempt, branch, worktree: wt, outcome: 'error',
      detail: `worktree_failed: ${trim(add.stderr)}`, verification: {} });
    return;
  }

  const priorFailures = attempt === 2 ? (f.patches[0].typed_failures || []) : [];
  const prompt = buildFixPrompt(f, ctx, priorFailures);
  // The guard stays absolute: a leaking prompt is never sent. What changes is the blast radius.
  // It used to throw out of the whole run, so one bad contract aborted every other finding and
  // no report was written. Now it refuses this finding and the run carries on.
  const leak = leakError(prompt, f);
  if (leak) {
    f.patches.push({ attempt, branch, worktree: wt, outcome: 'refused',
      detail: `fixer_prompt_leak: ${leak}`, verification: {} });
    return;
  }
  const patch = {
    attempt, branch, worktree: wt,
    contract_hash: sha256(JSON.stringify(f.triage.contract)),
    outcome: null, declared_files: [], enforcement_note: null, verification: null,
  };
  f.patches.push(patch);

  const res = await ctx.deps.runAgent({
    prompt, schemaPath: AGENT_SCHEMA, schemaPointer: '#/$defs/fix',
    cwd: wt, model: ctx.opts.model, timeoutMs: ctx.opts.timeoutMs, allowedTools: FIX_TOOLS,
  });
  if (!res.ok) {
    patch.outcome = 'agent_failed';
    patch.detail = res.reason;
    patch.verification = {};
    return;
  }
  patch.outcome = res.data.outcome;
  if (res.data.outcome === 'cannot_fix') {
    patch.reason = res.data.reason;
    patch.verification = {};
    return;
  }
  patch.declared_files = res.data.declared_files;
  patch.enforcement_note = res.data.enforcement_note;
  patch.verification = await verifyPatch(f, patch, ctx);
  patch.typed_failures = evaluateVerification(patch.verification, VERIFY_LEVELS[ctx.opts.verify])
    .failed.map((o) => ({ obligation: o, reason: (patch.verification[o] || {}).reason || 'failed' }));
}

async function fixAll(findings, ctx) {
  const fixable = findings.filter((f) => stageOf(f) === 'fix');
  if (!fixable.length) return { waves: [], attempted: 0 };
  const waves = ctx.deps.partition(fixable);
  const byId = new Map(findings.map((f) => [f.id, f]));
  let attempted = 0;
  for (const wave of waves) {
    for (const id of wave) {
      const f = byId.get(id);
      if (!f) continue;
      // Two attempts, and the cap is in the schema as well as here.
      while (stageOf(f) === 'fix') {
        await fixOne(f, ctx);
        attempted++;
        ctx.save(f);
        const last = f.patches[f.patches.length - 1];
        if (last.outcome === 'cannot_fix' || last.outcome === 'agent_failed' || last.outcome === 'error') break;
      }
    }
  }
  return { waves, attempted };
}

// ----------------------------------------------------------------- 7. verify

// Cheapest first, short-circuit on the first failure, except the audit which always runs so
// attempt two gets a real explanation. An obligation outside the required set is never written,
// so evaluateVerification reports it as skipped rather than as anything that passed.
async function verifyPatch(f, patch, ctx) {
  const required = new Set(VERIFY_LEVELS[ctx.opts.verify]);
  const v = {};
  const contract = f.triage.contract;
  const wt = patch.worktree;
  const need = (name) => required.has(name);
  let stopped = false;

  if (need('frozen_target')) {
    const same = sha256(JSON.stringify(contract)) === patch.contract_hash;
    v.frozen_target = same ? { status: 'pass' }
      : { status: 'fail', reason: 'contract_changed_after_the_patch_was_requested' };
    stopped = !same;
  }

  const diff = collectDiff(wt, ctx.base, ctx);
  if (!stopped && need('deterministic_guard')) {
    if (!diff.trim()) {
      v.deterministic_guard = { status: 'fail', reason: 'no_diff' };
      stopped = true;
    } else {
      const g = guardDiff(diff, contract, {
        requireWitnessFile: contract.witness.tier !== 'argued',
        sinkFiles: [...new Set(f.sites.map((s) => s.locus.file))],
        sinkText: f.flow.kind === 'traced' ? f.flow.steps[f.flow.steps.length - 1].code : f.flow.sink.code,
      });
      v.deterministic_guard = g.passed ? { status: 'pass' }
        : { status: 'fail', reason: g.violations.map((x) => x.kind).join(','), violations: g.violations };
      stopped = !g.passed;
    }
  }
  patch.diff_bytes = diff.length;

  if (!stopped && need('differential_witness')) {
    v.differential_witness = await runDifferentialWitness(contract, patch, ctx);
    stopped = v.differential_witness.status !== 'pass';
  }

  if (!stopped && need('functional_control')) {
    v.functional_control = runFunctionalControl(contract, patch, ctx);
    stopped = v.functional_control.status !== 'pass';
  }

  if (!stopped && need('regression_suite')) {
    v.regression_suite = runRegressionSuite(patch, ctx);
    stopped = v.regression_suite.status === 'fail';
  }

  if (!stopped && need('no_new_findings')) {
    const r = rescan(f, patch, ctx);
    v.no_new_findings = r.obligation;
    // Recorded for the report and read by no transition. A correct fix often keeps the shape
    // the rule matches, so gating on the rule going quiet creates pressure toward pattern defeat.
    v.rescan = r.rescan;
    stopped = r.obligation.status !== 'pass';
  }

  if (need('hostile_auditor')) {
    v.hostile_auditor = await runAudit(f, patch, diff, ctx);
  }
  return v;
}

function baseTree(ctx) {
  if (ctx._baseTree) return ctx._baseTree;
  const wt = path.join(ctx.outDir, 'worktrees', 'base');
  if (!fs.existsSync(wt)) {
    const r = ctx.git(['worktree', 'add', '--detach', wt, ctx.base]);
    if (r.status !== 0) return null;
  }
  ctx._baseTree = wt;
  return wt;
}

function runCommand(cmd, cwd, ctx) {
  const parts = String(cmd).split(/\s+/);
  return ctx.deps.exec(parts[0], parts.slice(1), { cwd });
}

function runRegressionSuite(patch, ctx) {
  if (!ctx.testCommand) return { status: 'unavailable', reason: 'no_test_command_discovered' };
  const base = baseTree(ctx);
  if (base && runCommand(ctx.testCommand, base, ctx).status !== 0) {
    // A suite already red on base is not the patch's fault.
    return { status: 'unavailable', reason: 'suite_red_on_base' };
  }
  const r = runCommand(ctx.testCommand, patch.worktree, ctx);
  return r.status === 0 ? { status: 'pass' } : { status: 'fail', reason: trim(r.stdout + r.stderr) };
}

async function runDifferentialWitness(contract, patch, ctx) {
  const tier = contract.witness.tier;
  if (tier !== 'dynamic') {
    // witness-run.cjs throws on executable and structural. An argued tier can never reach
    // verified by design, so both are recorded as unavailable rather than assumed passing.
    return { status: 'unavailable', reason: `tier_not_implemented:${tier}` };
  }
  const base = baseTree(ctx);
  if (!base) return { status: 'unavailable', reason: 'no_base_tree' };
  try {
    const { runWitness } = require('./witness-run.cjs');
    const r = await runWitness(contract.witness, { base, patched: patch.worktree }, {});
    return r.differential_ok ? { status: 'pass', detail: r.classification }
      : { status: 'fail', reason: r.classification || 'witness_not_differential' };
  } catch (e) {
    return { status: 'unavailable', reason: `witness_error:${trim(e.message)}` };
  }
}

function runFunctionalControl(contract, patch, ctx) {
  const c = contract.witness.control;
  if (!c || c.kind === 'unavailable') {
    return { status: 'unavailable', reason: (c && c.why) || 'no_control_authored' };
  }
  if (c.kind === 'existing_test') {
    const base = baseTree(ctx);
    if (base && runCommand(c.command_template, base, ctx).status !== 0) {
      return { status: 'fail', reason: 'control_red_on_base' };
    }
    const r = runCommand(c.command_template, patch.worktree, ctx);
    return r.status === 0 ? { status: 'pass' } : { status: 'fail', reason: trim(r.stdout + r.stderr) };
  }
  // An http control is exercised by the dynamic witness run, which is opt-in.
  return { status: 'unavailable', reason: 'http_control_needs_the_dynamic_tier' };
}

function rescan(f, patch, ctx) {
  const dir = path.join(ctx.outDir, 'scans', `${f.id}-${patch.attempt}`);
  const { raw, scanners } = runScanners({ ...ctx.opts, scans: null }, ctx.deps, patch.worktree, dir);
  if (!Object.keys(raw).length) {
    return {
      obligation: { status: 'unavailable', reason: 'rescan_produced_no_output' },
      rescan: { ran: false, scanners, original_absent: null, new_findings: [] },
    };
  }
  const after = normalize(raw, makeRepo(patch.worktree), `${ctx.runId}-rescan`).findings;
  const before = new Set(ctx.baseIds);
  const newFindings = after.filter((x) => !before.has(x.id)).map((x) => x.id);
  const originalAbsent = !after.some((x) => x.id === f.id);
  return {
    obligation: newFindings.length
      ? { status: 'fail', reason: 'rescan_new', new_findings: newFindings }
      : { status: 'pass' },
    rescan: { ran: true, scanners, original_absent: originalAbsent, new_findings: newFindings },
  };
}

function buildAuditPrompt(f, patch, diff) {
  const c = f.triage.contract;
  return [
    'Disprove the claim below. You did not triage this and you did not write this patch. You are',
    'given the frozen contract and the diff, and nothing else. Return exactly one JSON object.',
    '',
    `# Invariant\n${c.invariant}`,
    `# A value that breaks it\n${c.violating_input}`,
    `# Enforcement point\n${c.enforcement_point.file}`
      + `${c.enforcement_point.symbol ? ` in ${c.enforcement_point.symbol}` : ''}`,
    '',
    `# The claim to disprove\n${patch.enforcement_note}`,
    '',
    `# Diff\n\`\`\`diff\n${diff}\n\`\`\``,
    '',
    'Walk the violating value through the PATCHED source and say where it dies. If it still',
    'reaches its effect, the verdict is silences_rule or moves_trust.',
    '',
    `# Return schema\n\`\`\`json\n${bundleDef('audit')}\n\`\`\``,
  ].join('\n');
}

async function runAudit(f, patch, diff, ctx) {
  if (!patch.enforcement_note) return { status: 'fail', reason: 'no_patch_to_audit' };
  const prompt = buildAuditPrompt(f, patch, diff);
  // The auditor may name the rule in its own reasoning, but it must not be handed one.
  const leak = leakError(prompt, f);
  if (leak) return { status: 'fail', reason: `auditor_prompt_leak: ${leak}` };
  const res = await ctx.deps.runAgent({
    prompt, schemaPath: AGENT_SCHEMA, schemaPointer: '#/$defs/audit',
    cwd: patch.worktree, model: ctx.opts.model, timeoutMs: ctx.opts.timeoutMs,
    allowedTools: AUDIT_TOOLS,
  });
  if (!res.ok) return { status: 'fail', reason: `audit_agent_failed:${res.reason}` };
  patch.audit = res.data;
  return res.data.verdict === 'enforces_invariant'
    ? { status: 'pass', stopped_at: res.data.stopped_at }
    : { status: 'fail', reason: res.data.verdict };
}

// ----------------------------------------------------------------- 8. report

function dispositionFor(f, level) {
  if (!f.triage) return null;
  if (!f.gate) return null;
  if (f.gate.action === 'report_only') {
    switch (f.gate.reason) {
      case 'not_exploitable':
        return { state: 'rejected', reason: f.triage.refutation.reason,
          policy: f.triage.established_by === 'deterministic_prepass' };
      case 'undecidable':
        return { state: 'undecidable', missing_fact: f.triage.blocker.missing_fact,
          resolve_by: f.triage.blocker.resolve_by };
      default:
        return { state: 'below_threshold', severity: f.triage.severity, threshold: f.gate.threshold };
    }
  }
  const last = f.patches[f.patches.length - 1];
  if (!last) return null;
  if (last.outcome === 'cannot_fix') return { state: 'fix_declined', reason: last.reason, branch: last.branch };
  const ev = evaluateVerification(last.verification, VERIFY_LEVELS[level]);
  if (!ev.verified) {
    return { state: 'fix_failed', branch: last.branch, attempts: f.patches.length,
      failed: ev.failed, missing: ev.missing, worktree: last.worktree };
  }
  const tier = f.triage.contract.witness.tier;
  return {
    state: tier === 'argued' ? 'fixed_unwitnessed' : 'fixed',
    branch: last.branch, verify_level: level, skipped_obligations: ev.skipped,
    unavailable: ev.unavailable, witness_tier: tier,
  };
}

function finalize(findings, level, ctx) {
  for (const f of findings) {
    if (f.disposition) continue;
    const d = dispositionFor(f, level);
    if (d) { f.disposition = d; ctx.save(f); }
  }
}

// ------------------------------------------------------------------- the run

function makeSaver(outDir) {
  const dir = path.join(outDir, 'findings');
  ensureDir(dir);
  return (f) => writeJson(path.join(dir, `${f.id}.json`), f);
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
    const p = prior.get(f.id);
    if (!p) return;
    findings[i] = { ...f, triage: p.triage, gate: p.gate, patches: p.patches || [], disposition: p.disposition, prior: p.prior };
    n++;
  });
  return n;
}

function planLines(opts, target, outDir, base) {
  return [
    `target        ${target}`,
    `out           ${outDir}`,
    `base commit   ${base || 'not a git repository'}`,
    `fix at        ${opts.fixAt}`,
    `verify        ${opts.verify}  [${VERIFY_LEVELS[opts.verify].join(' ') || 'nothing is checked'}]`,
    `skipped       ${VERIFY_LEVELS.full.filter((o) => !VERIFY_LEVELS[opts.verify].includes(o)).join(' ') || 'none'}`,
    `scanners      ${opts.scans ? `reused from ${opts.scans}`
      : opts.scanners.map((s) => `${s}${onPath(s) ? '' : ' (absent)'}`).join(' ')}`,
    `max findings  ${opts.maxFindings === Infinity ? 'unbounded' : opts.maxFindings}`,
    `test command  ${discoverTestCommand(target) || 'none discovered'}`,
    `stages        scan normalize pre-resolve triage gate${opts.triageOnly ? '' : ' fix verify'} report`,
  ];
}

async function run(opts, deps = realDeps()) {
  const target = path.resolve(opts.target);
  if (!fs.existsSync(target)) throw new UsageError(`--target does not exist: ${target}`);
  const outDir = path.resolve(opts.out || defaultOutDir(target));
  const git = (args, cwd = target) => deps.exec('git', ['-C', cwd, ...args]);
  const head = git(['rev-parse', 'HEAD']);
  const base = head.status === 0 ? head.stdout.trim() : null;

  if (opts.dryRun) {
    for (const l of planLines(opts, target, outDir, base)) console.log(l);
    return { dryRun: true, outDir, target, base };
  }

  ensureDir(outDir);
  const runId = path.basename(outDir);
  const policy = { fix_at: opts.fixAt };
  const startedAt = deps.now();

  // 1. scan
  const { raw, scanners } = runScanners(opts, deps, target, path.join(outDir, 'scans'));
  if (!Object.keys(raw).length) {
    throw new Error(`every requested scanner failed, so there is nothing to normalize:\n  `
      + scanners.map((s) => `${s.name}: ${s.status} ${s.detail || ''}`).join('\n  '));
  }

  // 2. normalize and validate
  const norm = normalizeAndValidate(raw, target, runId);
  const findings = norm.findings;
  const save = makeSaver(outDir);
  const resumed = mergeExisting(findings, outDir);

  const testCommand = discoverTestCommand(target);
  let appHarness = null;
  try { appHarness = require('./app-harness.cjs').discoverAppHarness(target); } catch { /* optional */ }

  const ctx = {
    opts, deps, target, outDir, runId, git, base, save, testCommand, appHarness,
    buildCommand: null, lintCommand: null,
    witnessTiers: ['argued'],
    baseIds: findings.map((f) => f.id),
  };

  // 3. pre-resolve
  const preResolved = preResolve(findings);
  for (const f of findings) save(f);

  // 4. triage
  const tr = await triageAll(findings, ctx);

  // 5. gate
  const gated = gateAll(findings, policy, ctx);

  // 6 and 7. fix and verify
  let fixSummary = { waves: [], attempted: 0 };
  let degraded = null;
  const wantsFix = findings.some((f) => stageOf(f) === 'fix');
  if (opts.triageOnly) {
    degraded = wantsFix ? 'triage_only' : null;
  } else if (!base) {
    degraded = wantsFix ? 'target_is_not_a_git_repository' : null;
  } else if (!testCommand && !opts.allowUnverifiedFixes && VERIFY_LEVELS[opts.verify].includes('regression_suite')) {
    // No patching without verification. Pass --allow-unverified-fixes to override.
    degraded = wantsFix ? 'no_test_command_discoverable' : null;
  } else {
    fixSummary = await fixAll(findings, ctx);
  }

  // 8. report
  finalize(findings, opts.verify, ctx);

  const unresolved = findings.filter((f) => !f.disposition);
  const incompleteReason = degraded
    ? `${degraded}: ${unresolved.length} finding(s) left without a terminal disposition`
    : tr.deferred.length
      ? `max_findings=${opts.maxFindings} reached, ${tr.deferred.length} finding(s) deferred to the next run`
      : unresolved.length ? `${unresolved.length} finding(s) left without a terminal disposition` : null;

  const meta = {
    run_id: runId, target, base_commit: base, policy,
    verify_level: opts.verify,
    verify_obligations: VERIFY_LEVELS[opts.verify],
    skipped_obligations: VERIFY_LEVELS.full.filter((o) => !VERIFY_LEVELS[opts.verify].includes(o)),
    run_status: incompleteReason ? 'incomplete' : 'complete',
    incomplete_reason: incompleteReason,
    dropped: norm.dropped,
    scanners,
    counts: {
      raw: norm.raw_count, sites: norm.site_count, findings: findings.length,
      resumed, pre_resolved: preResolved, triaged: tr.triaged, gated,
      deferred: tr.deferred.length, fix_attempts: fixSummary.attempted,
      waves: fixSummary.waves.length,
    },
    started_at: startedAt, finished_at: deps.now(),
  };

  writeJson(path.join(outDir, 'run-metadata.json'), meta);
  fs.writeFileSync(path.join(outDir, 'REMEDIATION.md'), deps.renderRemediation(findings, meta));
  fs.writeFileSync(path.join(outDir, 'HANDOFF.md'), deps.renderHandoff(findings, meta));
  deps.log(`${runId}: ${meta.run_status}  findings=${findings.length} ${outDir}`);
  return { findings, meta, outDir, runId };
}

async function main(argv) {
  let opts;
  try { opts = parseArgs(argv); }
  catch (e) {
    if (!(e instanceof UsageError)) throw e;
    console.error(`${e.message}\n\n${USAGE}`);
    return 2;
  }
  try { await run(opts); return 0; }
  catch (e) {
    console.error(`run failed: ${e.message}`);
    return 1;
  }
}

module.exports = {
  bundleDef,
  leakError,
  refSafe,
  parseArgs, run, main, USAGE, UsageError,
  buildFixPrompt, buildTriagePrompt, buildAuditPrompt, assertNoLeak, leakTerms, witnessBrief,
  pathPolicy, preResolve, gateAll, dispositionFor, finalize, mergeExisting,
  discoverTestCommand, detectLanguage, runScanners, normalizeAndValidate, planLines, realExec,
};

if (require.main === module) main(process.argv.slice(2)).then((c) => process.exit(c));
