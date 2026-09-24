#!/usr/bin/env node
// The driver. One command runs scan, normalize, pre-resolve, triage, gate, fix, verify, report.
//
// Every stage re-derives itself from what is on disk via stageOf, so re-running the command is
// the resume path and there is no --resume flag and no status field to fall out of sync.
//
// This file is also where the skill's central rule is enforced mechanically rather than by
// prose: buildFixPrompt assembles the fixer's prompt field by field from the security contract
// and the flow, and bin/leak-guard.ts refuses to send a prompt that carries this finding's rule
// id or message, or contract prose that names a scanner or has the form of a rule id. A finding
// record is never handed to a fixer whole.

import fs from 'fs';
import os from 'os';
import path from 'path';
import crypto from 'crypto';
import { spawnSync } from 'child_process';

const ROOT = path.resolve(import.meta.dirname, '..');
const FINDING_SCHEMA = path.join(ROOT, 'schema/finding.schema.json');
const AGENT_SCHEMA = path.join(ROOT, 'schema/agent-results.schema.json');

import { stageOf, evaluateVerification, VERIFY_LEVELS, excused, isVerifyLevel } from './stage.ts';
import type { Disposition, Evaluation, FindingRecord, Obligation, ObligationResult, Patch, Verification, VerifyLevel } from './stage.ts';
import type { Baseline, ScanConfig, ScanDeps, ScannerStatus, SyncExec } from './scan.ts';
import type { Policy } from './gate.ts';
import type { AgentFailure } from './resume.ts';
import type { AgentOpts, AgentResult, Provider } from './agent.ts';
import type { AppHarness } from './app-harness.ts';
import type { AgentAudit, AgentFix, AgentTriage, SecurityContract, Severity, TaintFlow, Witness } from '../schema/types.ts';

// run-metadata.json: written once per run by the parent, read by the report and by resume.
type RunMeta = {
  run_id: string; target: string; base_commit: string | null; policy: Policy;
  verify_level: VerifyLevel; verify_obligations: readonly Obligation[]; skipped_obligations: Obligation[];
  scan_config: ScanConfig; run_status: 'complete' | 'incomplete'; incomplete_reason: string | null;
  agent_failures: AgentFailure[]; dropped: string[]; scanners: ScannerStatus[];
  counts: Record<string, number>; started_at: string; finished_at: string;
};
import { gate, order, isSeverity, RANK } from './gate.ts';
import { normalize, makeRepo } from './normalize.ts';
import { runScanners, onPath, trim, baselineOf, rescan, DEFAULT_SCAN_CONFIG, SUITE_NAME, semgrepConfigArg, SCANNERS } from './scan.ts';
import { validate, isRecord } from './validate.ts';
import { guardDiff } from './patch-guard.ts';
import { defaultOutDir, readRecorded, mergeExisting, clearAttempt, incompleteReason } from './resume.ts';
import { assertNoLeak, leakError, recordTerms, authoredProse } from './leak-guard.ts';
import { runAgent, envFor, isProvider, PROVIDERS } from './agent.ts';
import { renderRemediation, renderHandoff } from './report.ts';
import { witnessObligations } from './witness-run.ts';
import { discoverAppHarness } from './app-harness.ts';

type Opts = {
  target: string; out: string | null; fixAt: Severity; verify: VerifyLevel; witness: 'dynamic' | null;
  scanners: string[]; scans: string | null; triageOnly: boolean; maxFindings: number;
  model: string | null; provider: Provider; dryRun: boolean; timeoutMs: number; scanConfig: ScanConfig;
};
type Deps = ScanDeps & {
  onPath: (bin: string) => boolean;
  runAgent: (opts: AgentOpts) => Promise<AgentResult>;
  renderRemediation: (findings: FindingRecord[], meta: RunMeta) => string;
  renderHandoff: (findings: FindingRecord[], meta: RunMeta) => string;
  log: (m: string) => void;
  now: () => string;
};
type Git = (args: string[], cwd?: string) => ReturnType<SyncExec>;
type Ctx = {
  opts: Opts; deps: Deps; target: string; outDir: string; runId: string; worktreeRoot: string;
  git: Git; base: string | null; save: (f: FindingRecord) => void; testCommand: string | null;
  appHarness: AppHarness[]; buildCommand: null; lintCommand: null; witnessTiers: string[];
  baseline: Baseline; baseTree?: string;
};
// Fixing needs a commit to branch from, so the fix and verify stages only ever see this.
type FixCtx = Ctx & { base: string };

// Which answer each agent-results pointer yields. runAgent has already checked the answer
// against the schema at that pointer, so the pointer is what names its type.
type AgentAnswer = { '#/$defs/triage': AgentTriage; '#/$defs/fix': AgentFix; '#/$defs/audit': AgentAudit };

async function ask<P extends keyof AgentAnswer>(ctx: Ctx, pointer: P, o: Omit<AgentOpts, 'schemaPath' | 'schemaPointer'>) {
  const res = await ctx.deps.runAgent({ ...o, provider: ctx.opts.provider, schemaPath: AGENT_SCHEMA, schemaPointer: pointer });
  return res.ok ? { ok: true as const, data: res.data as AgentAnswer[P] } : res;
}

// gate() routes only an exploitable triage to fix, so fix, verify and the audit can rely on it.
function contractOf(f: FindingRecord): SecurityContract {
  if (f.triage?.verdict !== 'exploitable') throw new Error(`${f.id} reached the fix stage without an exploitable triage`);
  return f.triage.contract;
}

// --out is operator-controlled and git rejects spaces, `~ ^ : ? * [ \\`, `..` and a leading dot.
const refSafe = (s: unknown) => String(s).replace(/[^A-Za-z0-9._-]+/g, '-').replace(/\.{2,}/g, '.')
  .replace(/^[-.]+|[.-]+$/g, '') || 'run';
const sha256 = (s: string) => crypto.createHash('sha256').update(s, 'utf8').digest('hex');

// Worktrees live outside the output directory, whose findings/ and scans/ name the rule the fixer
// is never shown. Derived from the output directory so a resumed run finds its base tree again.
const cacheHome = () => process.env.XDG_CACHE_HOME || path.join(os.homedir(), '.cache');
const worktreeRootFor = (outDir: string) =>
  path.join(cacheHome(), 'sast-remediate', 'worktrees', sha256(path.resolve(outDir)).slice(0, 16));

// ------------------------------------------------------------------------ cli

const USAGE = `usage: run.ts --target=DIR [options]
  --target=DIR        repository to remediate (required)
  --out=DIR           output dir (default: continue the latest unfinished run of this
                      commit under ~/sast-remediate/<repo>/, else start run-<N+1>)
  --fix-at=LEVEL      informational|low|medium|high|critical  (default medium)
  --verify=LEVEL      none|cheap|full                          (default cheap)
  --witness=dynamic   also offer the live-app witness (boots the app on loopback)
  --scanners=LIST     semgrep,codeql   (default both)
  --scans=DIR         reuse existing scanner output; pass the rules it was made with
  --semgrep-config=C  Semgrep --config for the scan and every rescan, repeatable or
                      comma separated (default p/default)
  --codeql-suite=S    CodeQL suite name for the scan and every rescan (default security-extended)
  --triage-only       stop after the gate, write no patches
  --max-findings=N    bound the run; the rest become deferred, never dropped
  --model=NAME        model for agent calls; with openrouter, its slug (e.g. openai/gpt-5)
  --provider=P        anthropic|openrouter  (default anthropic; openrouter reads
                      OPENROUTER_API_KEY)
  --dry-run           print the plan and exit`;

class UsageError extends Error {}

function parseArgs(argv: string[]): Opts {
  // Collected as written, then checked below before it becomes Opts.
  const opts: Omit<Opts, 'target' | 'fixAt' | 'verify' | 'witness' | 'provider'>
    & { target: string | null; fixAt: string; verify: string; witness: string | null; provider: string } = {
    target: null, out: null, fixAt: 'medium', verify: 'cheap', witness: null,
    scanners: [...SCANNERS], scans: null, triageOnly: false, maxFindings: Infinity,
    model: null, provider: 'anthropic', dryRun: false, timeoutMs: 300000,
    scanConfig: { semgrep: [], codeql_suite: DEFAULT_SCAN_CONFIG.codeql_suite },
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
      case 'witness': opts.witness = String(val); break;
      case 'scanners': opts.scanners = String(val).split(',').map((s) => s.trim()).filter(Boolean); break;
      case 'scans': opts.scans = String(val); break;
      case 'semgrep-config': {
        const items = val === true ? [] : String(val).split(',').map((s) => s.trim()).filter(Boolean);
        if (!items.length) throw new UsageError('--semgrep-config needs a value');
        opts.scanConfig.semgrep.push(...items.map(semgrepConfigArg));
        break;
      }
      case 'codeql-suite': opts.scanConfig.codeql_suite = String(val); break;
      case 'triage-only': opts.triageOnly = true; break;
      case 'max-findings': opts.maxFindings = Number(val); break;
      case 'model': opts.model = String(val); break;
      case 'provider': opts.provider = String(val); break;
      case 'timeout-ms': opts.timeoutMs = Number(val); break;
      case 'dry-run': opts.dryRun = true; break;
      default: throw new UsageError(`unknown option: ${a}`);
    }
  }
  const { target, fixAt, verify, witness, provider } = opts;
  if (!target) throw new UsageError('--target is required');
  if (!isSeverity(fixAt)) throw new UsageError(`--fix-at must be one of ${Object.keys(RANK).join('|')}`);
  if (!isVerifyLevel(verify)) throw new UsageError(`--verify must be one of ${Object.keys(VERIFY_LEVELS).join('|')}`);
  if (witness !== null && witness !== 'dynamic') throw new UsageError('--witness must be dynamic');
  if (!isProvider(provider)) throw new UsageError(`--provider must be one of ${PROVIDERS.join('|')}`);
  for (const s of opts.scanners) if (!SCANNERS.includes(s)) throw new UsageError(`unknown scanner: ${s}`);
  if (!opts.scanners.length) throw new UsageError('--scanners must name at least one scanner');
  if (!(opts.maxFindings > 0)) throw new UsageError('--max-findings must be a positive integer');
  if (!opts.scanConfig.semgrep.length) opts.scanConfig.semgrep = [...DEFAULT_SCAN_CONFIG.semgrep];
  if (!SUITE_NAME.test(opts.scanConfig.codeql_suite)) {
    throw new UsageError('--codeql-suite must be a suite name such as security-extended');
  }
  return { ...opts, target, fixAt, verify, witness, provider };
}

// ----------------------------------------------------------------------- deps

// Everything that touches a process or an agent arrives through here, so a test drives the whole
// pipeline without a scanner, a network or a real model.
function realExec(cmd: string, args: string[], o: { cwd?: string; timeoutMs?: number } = {}): ReturnType<SyncExec> {
  const r = spawnSync(cmd, args, {
    cwd: o.cwd, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024,
    timeout: o.timeoutMs || 900000, env: process.env,
  });
  return {
    status: r.error ? -1 : (r.status ?? -1),
    stdout: r.stdout || '',
    stderr: r.stderr || (r.error ? r.error.message : ''),
  };
}

function realDeps(): Deps {
  return {
    runAgent,
    renderRemediation,
    renderHandoff,
    exec: realExec,
    onPath,
    log: (m: string) => console.error(m),
    now: () => new Date().toISOString(),
  };
}

const ensureDir = (d: string) => fs.mkdirSync(d, { recursive: true });
const writeJson = (f: string, o: unknown) => { ensureDir(path.dirname(f)); fs.writeFileSync(f, JSON.stringify(o, null, 2) + '\n'); };
const readJson = (f: string): unknown => JSON.parse(fs.readFileSync(f, 'utf8'));
// Our own schema files, read for their $defs.
const readSchema = (f: string) => readJson(f) as { $defs: Record<string, unknown> };

// ------------------------------------------------------------------- 1. scan

const TEST_COMMANDS: [marker: string, make: (root: string) => string | null][] = [
  ['package.json', (root) => {
    const pkg = readJson(path.join(root, 'package.json'));
    return isRecord(pkg) && isRecord(pkg.scripts) && pkg.scripts.test ? 'npm test' : null;
  }],
  ['pyproject.toml', () => 'pytest'],
  ['pytest.ini', () => 'pytest'],
  ['go.mod', () => 'go test ./...'],
  ['Cargo.toml', () => 'cargo test'],
];
function discoverTestCommand(root: string): string | null {
  for (const [marker, make] of TEST_COMMANDS) {
    if (!fs.existsSync(path.join(root, marker))) continue;
    try { const c = make(root); if (c) return c; } catch { /* a malformed manifest is not a test command */ }
  }
  return null;
}

// --------------------------------------------------------- 2. normalize and validate

function normalizeAndValidate(raw: Parameters<typeof normalize>[0], target: string, runId: string) {
  const res = normalize(raw, makeRepo(target), runId);
  const errs = validate(readSchema(FINDING_SCHEMA), res.findings, path.dirname(FINDING_SCHEMA));
  if (errs.length) {
    throw new Error(`normalized findings do not validate:\n  ${errs.slice(0, 10).join('\n  ')}`);
  }
  // Validated just above against the schema FindingRecord is built from.
  return { ...res, findings: res.findings as FindingRecord[] };
}

// ------------------------------------------------------------- 3. pre-resolve

// Path policy. A rejection here is a policy call, not a security claim, and it produces a real
// triage with established_by deterministic_prepass rather than a skipped state, so nothing
// downstream has to special-case a finding that never saw an agent.
const POLICY_PATHS: [kind: string, pattern: RegExp][] = [
  ['test', /(^|\/)(tests?|spec|specs|__tests__|testdata|fixtures?)(\/|$)|[._-](test|spec)\.[A-Za-z0-9]+$|_test\.go$/i],
  ['vendor', /(^|\/)(vendor|node_modules|third[_-]?party|bower_components|\.venv|site-packages)(\/|$)/i],
  ['generated', /(^|\/)(generated|gen|build|dist|out|target)(\/|$)|\.(pb|generated)\.[A-Za-z0-9]+$|_pb2\.py$/i],
  ['minified', /\.min\.(js|css)$|\.bundle\.js$|-min\.js$/i],
  ['migrations', /(^|\/)(migrations?|db\/migrate|alembic\/versions)(\/|$)/i],
];

function pathPolicy(finding: FindingRecord) {
  const hits = finding.sites.map((s) => {
    const rule = POLICY_PATHS.find(([, re]) => re.test(s.locus.file));
    return rule ? { file: s.locus.file, kind: rule[0], pattern: String(rule[1]) } : null;
  });
  // Every site must match, or the finding still reaches code the operator asked about.
  return hits.every((h) => h !== null) ? hits[0] : null;
}

function preResolve(findings: FindingRecord[]): number {
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

const TRIAGE_FLOW_NOTE: Record<TaintFlow['kind'], string> = {
  traced: 'The path below is this candidate\'s claimed route from source to sink. Attack it. Find the '
    + 'step where it is wrong. Check whether any step normalizes, validates, binds, escapes or '
    + 'authorizes the value. Compare what each component guarantees against what the next assumes.',
  sink_only: 'No dataflow path was provided. Establish reachability from an attacker-controlled entry '
    + 'point yourself before asserting anything. If you cannot reach this sink from untrusted input, '
    + 'the verdict is not_exploitable with reason input_is_not_attacker_controlled. If the entry point '
    + 'is outside this repository, the verdict is undecidable.',
};

function flowBlock(flow: TaintFlow): string {
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

function bundleDef(name: string): string {
  const agent = readSchema(AGENT_SCHEMA);
  const finding = readSchema(FINDING_SCHEMA);
  const defs: Record<string, unknown> = {};
  const walk = (node: unknown): unknown => {
    if (Array.isArray(node)) return node.map(walk);
    if (!node || typeof node !== 'object') return node;
    const out: Record<string, unknown> = {};
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
  // Every agent-results def is a schema object, so the walk hands one back.
  const root = walk(agent.$defs[name]) as Record<string, unknown>;
  return JSON.stringify({ ...root, $defs: defs }, null, 2);
}

function buildTriagePrompt(f: FindingRecord, ctx: Pick<Ctx, 'testCommand' | 'witnessTiers'> & { appHarness?: AppHarness[] | null }): string {
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
    `app harness: ${ctx.appHarness && ctx.appHarness.length ? JSON.stringify(ctx.appHarness) : 'none discovered'}`,
    `enabled witness tiers: ${ctx.witnessTiers.join(', ')}`,
    '',
    `# Rubric\n${rubric}`,
    '',
    `# Return schema (the triage branch, verbatim)\n\`\`\`json\n${branch}\n\`\`\``,
  ].join('\n');
}

const TRIAGE_TOOLS = ['Read', 'Grep', 'Glob'];

async function triageAll(findings: FindingRecord[], ctx: Ctx) {
  const queue = order(findings).filter((f) => stageOf(f, ctx.opts.verify) === 'triage');
  const budget = ctx.opts.maxFindings;
  const doing = queue.slice(0, budget);
  const deferred = queue.slice(budget).map((f) => f.id);
  const failed: AgentFailure[] = [];

  for (const f of doing) {
    const res = await ask(ctx, '#/$defs/triage', {
      prompt: buildTriagePrompt(f, ctx),
      cwd: ctx.target, model: ctx.opts.model, timeoutMs: ctx.opts.timeoutMs,
      tools: TRIAGE_TOOLS,
    });
    if (!res.ok) {
      // No answer is not a verdict. The record stays at triage, so the next run asks again.
      failed.push({ id: f.id, stage: 'triage', reason: res.reason });
      continue;
    } else if ('split' in res.data) {
      // Re-emitting the split sites as separate findings is not implemented; the record is
      // handed to a human rather than silently triaged under a contract that fits neither half.
      f.disposition = { state: 'deferred', reason: 'split_requested', detail: res.data.split };
    } else {
      f.triage = res.data;
    }
    ctx.save(f);
  }
  return { triaged: doing.length - failed.length, deferred, failed };
}

// ------------------------------------------------------------------- 5. gate

function gateAll(findings: FindingRecord[], policy: Policy, ctx: Ctx): number {
  let n = 0;
  for (const f of findings) {
    if (stageOf(f, ctx.opts.verify) !== 'gate') continue;
    if (f.triage) f.gate = gate(f.triage, policy);
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
function witnessBrief(w: Witness): string {
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
    default: {
      const unknown: never = w;
      throw new Error(`unknown witness tier: ${(unknown as { tier: unknown }).tier}`);
    }
  }
}

// Only the repository commands come from the run context, and a missing one reads as undiscovered.
function buildFixPrompt(f: FindingRecord, ctx: Partial<Pick<Ctx, 'buildCommand' | 'testCommand' | 'lintCommand'>>,
  priorFailures?: Patch['typed_failures']): string {
  const c = contractOf(f);
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
    `# Repository commands\nThe harness runs these after you return. You have no shell.\nbuild: ${ctx.buildCommand || 'none discovered'}`,
    `test: ${ctx.testCommand || 'none discovered'}`,
    `lint: ${ctx.lintCommand || 'none discovered'}`,
  ];
  if (priorFailures && priorFailures.length) {
    parts.push('', '# The previous attempt failed these checks\n'
      + priorFailures.map((x) => `- ${x.obligation}: ${x.reason}`).join('\n'));
  }
  parts.push('', 'Do not commit. List every file you changed or created, the witness file included, in',
    'declared_files. Only the declared files are committed, by the harness, after its checks pass.',
    'Return {"outcome":"patched","declared_files":[...],"enforcement_note":"..."}',
    'or {"outcome":"cannot_fix","reason":"..."} if the contract cannot be satisfied as written.');
  return parts.join('\n');
}

// No shell. The harness builds, tests and rescans; a shell narrowed to the test command is no
// boundary when the fixer can edit the script that command runs.
const FIX_TOOLS = ['Read', 'Grep', 'Glob', 'Edit', 'Write'];
const AUDIT_TOOLS = ['Read', 'Grep', 'Glob'];

// Stages exactly the declared files on top of base, whether or not the fixer committed. Anything
// else the call left in the worktree, such as a hook's state file, never reaches the branch.
function collectDiff(wt: string, base: string, files: string[], ctx: Ctx): string {
  ctx.git(['reset', '-q', '--soft', base], wt);
  ctx.git(['reset', '-q'], wt);
  for (const file of files) ctx.git(['add', '-A', '--', file], wt);
  const r = ctx.git(['diff', '--cached', base], wt);
  return r.status === 0 ? r.stdout : '';
}

async function fixOne(f: FindingRecord, ctx: FixCtx): Promise<{ failed: string } | undefined> {
  const attempt = f.patches.length + 1;
  // Branches live in the target repository, which outlives any one run; worktrees live under
  // ctx.worktreeRoot and everything else in the per-run output directory. Without the run id, a
  // second run against the same repository collided with the first run's branches and died
  // before the fixer was called.
  const branch = `sast-fix/${refSafe(ctx.runId)}/${f.id}/${attempt}`;
  const wt = path.join(ctx.worktreeRoot, `${f.id}-${attempt}`);
  clearAttempt(ctx.git, branch, wt);
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
  const patch: Patch = {
    attempt, branch, worktree: wt,
    contract_hash: sha256(JSON.stringify(contractOf(f))),
    outcome: null, declared_files: [], enforcement_note: null, verification: null,
  };
  f.patches.push(patch);

  const res = await ask(ctx, '#/$defs/fix', {
    prompt, cwd: wt, model: ctx.opts.model, timeoutMs: ctx.opts.timeoutMs, tools: FIX_TOOLS,
  });
  if (!res.ok) {
    // No answer is not an attempt: it takes no attempt slot, and the next run tries again.
    f.patches.pop();
    clearAttempt(ctx.git, branch, wt);
    return { failed: res.reason };
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
  patch.typed_failures = evaluateVerification(patch.verification, VERIFY_LEVELS[ctx.opts.verify], contractOf(f).witness.tier)
    .failed.map((o) => ({ obligation: o, reason: patch.verification?.[o]?.reason || 'failed' }));
}

async function fixAll(findings: FindingRecord[], ctx: FixCtx) {
  const level = ctx.opts.verify;
  const fixable = findings.filter((f) => stageOf(f, level) === 'fix');
  let attempted = 0;
  const failed: AgentFailure[] = [];
  for (const f of order(fixable)) {
    // Two attempts, and the cap is in the schema as well as here. Only a patch that failed its
    // checks earns a retry; every other outcome is final, as dispositionFor records it.
    while (stageOf(f, level) === 'fix') {
      const r = await fixOne(f, ctx);
      attempted++;
      if (r && r.failed) { failed.push({ id: f.id, stage: 'fix', reason: r.failed }); break; }
      ctx.save(f);
      if (f.patches[f.patches.length - 1].outcome !== 'patched') break;
    }
  }
  return { attempted, failed };
}

// ----------------------------------------------------------------- 7. verify

// Cheapest first, short-circuit on the first failure, except the audit which always runs so
// attempt two gets a real explanation. An obligation outside the required set is never written,
// so evaluateVerification reports it as skipped rather than as anything that passed.
async function verifyPatch(f: FindingRecord, patch: Patch, ctx: FixCtx): Promise<Verification> {
  const required = new Set(VERIFY_LEVELS[ctx.opts.verify]);
  const v: Verification = {};
  const contract = contractOf(f);
  const wt = patch.worktree;
  const tier = contract.witness.tier;
  const need = (name: Obligation) => required.has(name);
  // `holds`, not `=== 'pass'`: an excused unavailable (the argued pair, or a red suite on base)
  // must not stop the run, exactly like a pass.
  const holds = (name: Obligation) => v[name]?.status === 'pass' || (v[name]?.status === 'unavailable' && excused(name, tier));
  let stopped = false;

  if (need('frozen_target')) {
    const same = sha256(JSON.stringify(contract)) === patch.contract_hash;
    v.frozen_target = same ? { status: 'pass' }
      : { status: 'fail', reason: 'contract_changed_after_the_patch_was_requested' };
    stopped = !same;
  }

  const diff = collectDiff(wt, ctx.base, patch.declared_files || [], ctx);
  if (!stopped && need('deterministic_guard')) {
    if (!diff.trim()) {
      v.deterministic_guard = { status: 'fail', reason: 'no_diff' };
      stopped = true;
    } else {
      const g = guardDiff(diff, contract, {
        sinkFiles: [...new Set<string>(f.sites.map((s) => s.locus.file))],
        sinkText: f.flow.kind === 'traced' ? f.flow.steps[f.flow.steps.length - 1].code : f.flow.sink.code,
      });
      v.deterministic_guard = g.passed ? { status: 'pass' }
        : { status: 'fail', reason: g.violations.map((x) => x.kind).join(','), violations: g.violations };
      stopped = !g.passed;
    }
  }
  patch.diff_bytes = diff.length;

  if (!stopped && diff.trim()) {
    // Set here, not inherited, so the commit works on a CI runner with no identity and reads as the tool's.
    const c = ctx.git(['-c', 'user.name=sast-remediate', '-c', 'user.email=sast-remediate@users.noreply.invalid',
      'commit', '-q', '-m', `sast-remediate: enforce the invariant for ${f.id}`], wt);
    if (c.status !== 0) {
      patch.outcome = 'error';
      patch.detail = `commit_failed: ${trim(c.stderr)}`;
      return v;
    }
  }

  if (!stopped && need('differential_witness')) {
    // A dynamic run answers the control too (it sends the control exchange to both trees), and
    // the argued tier has none either way, so either answers obligation 4 as well.
    const w = await runDifferentialWitness(contract, patch, ctx);
    v.differential_witness = w.differential_witness;
    if (w.functional_control) v.functional_control = w.functional_control;
    stopped = !holds('differential_witness');
  }

  if (!stopped && need('functional_control')) {
    if (!v.functional_control) v.functional_control = runFunctionalControl(contract, patch, ctx);
    stopped = !holds('functional_control');
  }

  if (!stopped && need('regression_suite')) {
    v.regression_suite = runRegressionSuite(patch, ctx);
    stopped = !holds('regression_suite');
  }

  if (!stopped && need('no_new_findings')) {
    const r = rescan(f, patch.worktree, path.join(ctx.outDir, 'scans', `${f.id}-${patch.attempt}`), ctx);
    v.no_new_findings = r.obligation;
    // Recorded for the report and read by no transition. A correct fix often keeps the shape
    // the rule matches, so gating on the rule going quiet creates pressure toward pattern defeat.
    v.rescan = r.rescan;
    stopped = !holds('no_new_findings');
  }

  if (need('hostile_auditor')) {
    v.hostile_auditor = await runAudit(f, patch, diff, ctx);
  }
  return v;
}

function baseTree(ctx: FixCtx): string | null {
  if (ctx.baseTree) return ctx.baseTree;
  const wt = path.join(ctx.worktreeRoot, 'base');
  if (!fs.existsSync(wt)) {
    const r = ctx.git(['worktree', 'add', '--detach', wt, ctx.base]);
    if (r.status !== 0) return null;
  }
  ctx.baseTree = wt;
  return wt;
}

function runCommand(cmd: string, cwd: string, ctx: Ctx) {
  const parts = String(cmd).split(/\s+/);
  return ctx.deps.exec(parts[0], parts.slice(1), { cwd });
}

function runRegressionSuite(patch: Patch, ctx: FixCtx): ObligationResult {
  if (!ctx.testCommand) return { status: 'unavailable', reason: 'no_test_command_discovered' };
  const base = baseTree(ctx);
  if (base && runCommand(ctx.testCommand, base, ctx).status !== 0) {
    // A suite already red on base is not the patch's fault.
    return { status: 'unavailable', reason: 'suite_red_on_base' };
  }
  const r = runCommand(ctx.testCommand, patch.worktree, ctx);
  return r.status === 0 ? { status: 'pass' } : { status: 'fail', reason: trim(r.stdout + r.stderr) };
}

async function runDifferentialWitness(contract: SecurityContract, patch: Patch, ctx: FixCtx): Promise<{ differential_witness: ObligationResult; functional_control?: ObligationResult }> {
  const w = contract.witness;
  try {
    return await witnessObligations(w,
      { baseDir: w.tier === 'dynamic' ? baseTree(ctx) : null, headDir: patch.worktree, harnesses: ctx.appHarness },
      { allowDynamic: ctx.opts.witness === 'dynamic' });
  } catch (e) {
    return { differential_witness: { status: 'unavailable', reason: `witness_error:${trim(e instanceof Error ? e.message : e)}` } };
  }
}

function runFunctionalControl(contract: SecurityContract, patch: Patch, ctx: FixCtx): ObligationResult {
  const w = contract.witness;
  const c = 'control' in w ? w.control : null;
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

function buildAuditPrompt(f: FindingRecord, patch: Pick<Patch, 'enforcement_note'>, diff: string): string {
  const c = contractOf(f);
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

async function runAudit(f: FindingRecord, patch: Patch, diff: string, ctx: Ctx): Promise<ObligationResult> {
  if (!patch.enforcement_note) return { status: 'fail', reason: 'no_patch_to_audit' };
  const prompt = buildAuditPrompt(f, patch, diff);
  // The auditor may name the rule in its own reasoning, but it must not be handed one.
  const leak = leakError(prompt, f);
  if (leak) return { status: 'fail', reason: `auditor_prompt_leak: ${leak}` };
  const res = await ask(ctx, '#/$defs/audit', {
    prompt, cwd: patch.worktree, model: ctx.opts.model, timeoutMs: ctx.opts.timeoutMs,
    tools: AUDIT_TOOLS,
  });
  if (!res.ok) return { status: 'fail', reason: `audit_agent_failed:${res.reason}` };
  patch.audit = res.data;
  return res.data.verdict === 'enforces_invariant'
    ? { status: 'pass', stopped_at: res.data.stopped_at }
    : { status: 'fail', reason: res.data.verdict };
}

// ----------------------------------------------------------------- 8. report

function dispositionFor(f: FindingRecord, level: VerifyLevel): Disposition | null {
  const t = f.triage;
  if (!t) return null;
  if (!f.gate) return null;
  // gate() reports every verdict but an exploitable one at or above the threshold, so the
  // verdict alone says which report-only outcome this is.
  if (f.gate.action === 'report_only') {
    switch (t.verdict) {
      case 'not_exploitable':
        return { state: 'rejected', reason: t.refutation.reason, policy: t.established_by === 'deterministic_prepass' };
      case 'undecidable':
        return { state: 'undecidable', missing_fact: t.blocker.missing_fact, resolve_by: t.blocker.resolve_by };
      case 'exploitable':
        return { state: 'below_threshold', severity: t.severity, threshold: f.gate.threshold };
    }
  }
  const last = f.patches[f.patches.length - 1];
  if (!last) return null;
  if (last.outcome === 'cannot_fix') return { state: 'fix_declined', reason: last.reason, branch: last.branch };
  // `error` means the worktree or the harness commit failed, so the branch carries no fix.
  const branch = last.outcome === 'error' ? null : last.branch;
  const tier = contractOf(f).witness.tier;
  // Only a patch is judged. A crash, a refusal or a failed worktree is a failed fix at every level,
  // including `none`, where an empty verification would otherwise count as verified.
  const ev = last.outcome === 'patched'
    ? evaluateVerification(last.verification, VERIFY_LEVELS[level], tier)
    : { verified: false, failed: [], unavailable: [], missing: [], skipped: [] } satisfies Evaluation;
  if (!ev.verified) {
    return { state: 'fix_failed', branch, attempts: f.patches.length, outcome: last.outcome,
      detail: last.detail, failed: ev.failed, missing: ev.missing, worktree: last.worktree };
  }
  return {
    state: tier === 'argued' ? 'fixed_unwitnessed' as const : 'fixed' as const,
    branch: last.branch, verify_level: level, skipped_obligations: ev.skipped,
    unavailable: ev.unavailable, witness_tier: tier,
  };
}

function finalize(findings: FindingRecord[], level: VerifyLevel, ctx: Pick<Ctx, 'save'>, open = new Set<string>()): void {
  for (const f of findings) {
    if (f.disposition || open.has(f.id)) continue;
    const d = dispositionFor(f, level);
    if (d) { f.disposition = d; ctx.save(f); }
  }
}

// ------------------------------------------------------------------- the run

function makeSaver(outDir: string) {
  const dir = path.join(outDir, 'findings');
  ensureDir(dir);
  return (f: FindingRecord) => writeJson(path.join(dir, `${f.id}.json`), f);
}

function planLines(opts: Opts, target: string, outDir: string, base: string | null): string[] {
  return [
    `target        ${target}`,
    `out           ${outDir}`,
    `worktrees     ${worktreeRootFor(outDir)}`,
    `base commit   ${base || 'not a git repository'}`,
    `fix at        ${opts.fixAt}`,
    `verify        ${opts.verify}  [${VERIFY_LEVELS[opts.verify].join(' ') || 'nothing is checked'}]`,
    `skipped       ${VERIFY_LEVELS.full.filter((o) => !VERIFY_LEVELS[opts.verify].includes(o)).join(' ') || 'none'}`,
    `scanners      ${opts.scans ? `reused from ${opts.scans}`
      : opts.scanners.map((s) => `${s}${onPath(s) ? '' : ' (absent)'}`).join(' ')}`,
    `scan config   semgrep ${opts.scanConfig.semgrep.join(' ')}; codeql ${opts.scanConfig.codeql_suite}`,
    `agents        ${opts.provider}, model ${opts.model || 'CLI default'}`,
    `max findings  ${opts.maxFindings === Infinity ? 'unbounded' : opts.maxFindings}`,
    `test command  ${discoverTestCommand(target) || 'none discovered'}`,
    `stages        scan normalize pre-resolve triage gate${opts.triageOnly ? '' : ' fix verify'} report`,
  ];
}

type RunResult =
  | { dryRun: true; outDir: string; target: string; base: string | null }
  | { dryRun?: false; findings: FindingRecord[]; meta: RunMeta; outDir: string; runId: string };

async function run(opts: Opts, deps: Deps = realDeps()): Promise<RunResult> {
  const target = path.resolve(opts.target);
  if (!fs.existsSync(target)) throw new UsageError(`--target does not exist: ${target}`);
  const git: Git = (args, cwd = target) => deps.exec('git', ['-C', cwd, ...args]);
  const head = git(['rev-parse', 'HEAD']);
  const base = head.status === 0 ? head.stdout.trim() : null;
  const outDir = path.resolve(opts.out || defaultOutDir(target, base));

  if (opts.dryRun) {
    for (const l of planLines(opts, target, outDir, base)) console.log(l);
    return { dryRun: true as const, outDir, target, base };
  }

  // A missing key would otherwise surface as every agent call failing, one finding at a time.
  try { envFor(opts.provider); } catch (e) { throw new UsageError((e as Error).message); }
  ensureDir(outDir);
  const worktreeRoot = worktreeRootFor(outDir);
  fs.mkdirSync(worktreeRoot, { recursive: true, mode: 0o700 });
  const runId = path.basename(outDir);
  // A resumed run judges its saved patches with the level they were verified at.
  const metaFile = path.join(outDir, 'run-metadata.json');
  if (fs.existsSync(metaFile)) deps.log(`resuming ${outDir}`);
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
    writeJson(metaFile, { run_id: runId, verify_level: opts.verify, scan_config: opts.scanConfig, base_commit: base });
  }
  const policy: Policy = { fix_at: opts.fixAt };
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
  let appHarness: AppHarness[] = [];
  try { appHarness = discoverAppHarness(target); } catch { /* an unreadable tree has no harness */ }
  const dynamicOffered = opts.witness === 'dynamic' && appHarness.length > 0;
  if (opts.witness === 'dynamic' && !dynamicOffered) {
    deps.log('--witness=dynamic: no app harness discovered, so triage is offered argued only');
  }

  const ctx: Ctx = {
    opts, deps, target, outDir, runId, worktreeRoot, git, base, save, testCommand, appHarness,
    buildCommand: null, lintCommand: null,
    witnessTiers: dynamicOffered ? ['dynamic', 'argued'] : ['argued'],
    baseline: baselineOf(raw, findings, opts.scanConfig, scanners),
  };

  // 3. pre-resolve
  const preResolved = preResolve(findings);
  for (const f of findings) save(f);

  // 4. triage
  const tr = await triageAll(findings, ctx);

  // 5. gate
  const gated = gateAll(findings, policy, ctx);

  // 6 and 7. fix and verify
  let fixSummary: { attempted: number; failed: AgentFailure[] } = { attempted: 0, failed: [] };
  let degraded: string | null = null;
  const wantsFix = findings.some((f) => stageOf(f, opts.verify) === 'fix');
  if (opts.triageOnly) {
    degraded = wantsFix ? 'triage_only' : null;
  } else if (!base) {
    degraded = wantsFix ? 'target_is_not_a_git_repository' : null;
  } else {
    fixSummary = await fixAll(findings, { ...ctx, base });
  }

  // 8. report
  const failures = [...tr.failed, ...fixSummary.failed];
  finalize(findings, opts.verify, ctx, new Set(failures.map((x) => x.id)));

  const unresolved = findings.filter((f) => !f.disposition);
  const why = incompleteReason({ degraded, unresolved: unresolved.length, budget: opts.maxFindings,
    deferred: tr.deferred.length, failures });

  const meta: RunMeta = {
    run_id: runId, target, base_commit: base, policy,
    verify_level: opts.verify,
    verify_obligations: VERIFY_LEVELS[opts.verify],
    skipped_obligations: VERIFY_LEVELS.full.filter((o) => !VERIFY_LEVELS[opts.verify].includes(o)),
    scan_config: opts.scanConfig,
    run_status: why ? 'incomplete' : 'complete',
    incomplete_reason: why,
    agent_failures: failures,
    dropped: norm.dropped,
    scanners,
    counts: {
      raw: norm.raw_count, sites: norm.site_count, findings: findings.length,
      resumed, pre_resolved: preResolved, triaged: tr.triaged, gated,
      deferred: tr.deferred.length, agent_failures: failures.length, fix_attempts: fixSummary.attempted,
    },
    started_at: startedAt, finished_at: deps.now(),
  };

  writeJson(metaFile, meta);
  fs.writeFileSync(path.join(outDir, 'REMEDIATION.md'), deps.renderRemediation(findings, meta));
  fs.writeFileSync(path.join(outDir, 'HANDOFF.md'), deps.renderHandoff(findings, meta));
  deps.log(`${runId}: ${meta.run_status}  findings=${findings.length} ${outDir}`);
  return { findings, meta, outDir, runId };
}

async function main(argv: string[]): Promise<number> {
  try { await run(parseArgs(argv)); return 0; }
  catch (e) {
    if (e instanceof UsageError) {
      console.error(`${e.message}\n\n${USAGE}`);
      return 2;
    }
    console.error(`run failed: ${e instanceof Error ? e.message : String(e)}`);
    return 1;
  }
}

export type { RunMeta, Opts, Deps, Ctx, RunResult };
export {
  bundleDef,
  leakError,
  refSafe,
  worktreeRootFor,
  parseArgs, run, main, USAGE, UsageError,
  buildFixPrompt, buildTriagePrompt, buildAuditPrompt, assertNoLeak, recordTerms, authoredProse, witnessBrief,
  pathPolicy, preResolve, gateAll, dispositionFor, finalize, mergeExisting, defaultOutDir,
  discoverTestCommand, normalizeAndValidate, planLines, realExec,
};

if (import.meta.main) main(process.argv.slice(2)).then((c) => process.exit(c));
