#!/usr/bin/env node
// Running the scanners, once on the target and again on each patched worktree, and deciding
// what a rescan says about the patch.

import fs from 'fs';
import path from 'path';
import { normalize, makeRepo } from './normalize.ts';
import type { RawScans } from './normalize.ts';
import type { ObligationResult, FindingRecord } from './stage.ts';
import type { Finding } from '../schema/types.ts';
import { isRecord } from './validate.ts';

const ensureDir = (d: string) => fs.mkdirSync(d, { recursive: true });
const readJson = (f: string): unknown => JSON.parse(fs.readFileSync(f, 'utf8'));
const writeJson = (f: string, v: unknown) => fs.writeFileSync(f, JSON.stringify(v, null, 2));
const trim = (s: unknown) => String(s || '').trim().split('\n').slice(-3).join(' ').slice(0, 300);

type ScanConfig = { semgrep: string[]; codeql_suite: string };
type ScannerStatus = { name: string; status: string; detail: string; config?: string; languages?: string[] };
type Rescan = { ran: boolean; scanners: ScannerStatus[]; original_absent: boolean | null; new_findings: string[] };
type SyncExec = (cmd: string, args: string[], o?: { cwd?: string; timeoutMs?: number }) => { status: number; stdout: string; stderr: string };
type ScanDeps = { exec: SyncExec; onPath?: (bin: string) => boolean };
type ScanOpts = { scans: string | null; scanners: string[]; scanConfig: ScanConfig; languages?: string[] | null };
type Baseline = { scanners: string[]; ruleFiles: Set<string>; scanConfig: ScanConfig; languages: string[] | null };

const DEFAULT_SCAN_CONFIG: Readonly<ScanConfig> = Object.freeze({ semgrep: ['p/default'], codeql_suite: 'security-extended' });
const SUITE_NAME = /^[a-z0-9][a-z0-9-]*$/;
// A local rules file is stored absolute so a resume from another directory scans identically.
const semgrepConfigArg = (c: string) => (fs.existsSync(c) ? path.resolve(c) : c);

// run-metadata.json is read back on resume, so its scan_config is parsed, not trusted.
function parseScanConfig(x: unknown): ScanConfig | null {
  if (!isRecord(x) || !Array.isArray(x.semgrep) || !x.semgrep.length) return null;
  if (!x.semgrep.every((c): c is string => typeof c === 'string' && !!c)) return null;
  if (typeof x.codeql_suite !== 'string' || !SUITE_NAME.test(x.codeql_suite)) return null;
  return { semgrep: [...x.semgrep], codeql_suite: x.codeql_suite };
}

const onPath = (bin: string) => (process.env.PATH || '').split(path.delimiter)
  .some((d) => d && fs.existsSync(path.join(d, bin)));

const SCANNERS = ['semgrep', 'codeql'];

const LANGS: [lang: string, exts: string[], markers: string[]][] = [
  // [codeql language, source extensions, root markers]
  ['javascript', ['.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx'], ['package.json']],
  ['python', ['.py'], ['pyproject.toml', 'requirements.txt', 'setup.py']],
  ['go', ['.go'], ['go.mod']],
  ['ruby', ['.rb'], ['Gemfile']],
  ['java', ['.java', '.kt'], ['pom.xml', 'build.gradle', 'build.gradle.kts']],
  ['rust', ['.rs'], ['Cargo.toml']],
];
const SKIP_DIRS = new Set(['node_modules', 'vendor', 'third_party', 'dist', 'build', 'target', 'venv', '__pycache__']);
const SAMPLE_LIMIT = 5000;

function hasWorkflows(root: string): boolean {
  try {
    const dir = path.join(root, '.github', 'workflows');
    return fs.readdirSync(dir).some((f) => /\.ya?ml$/.test(f));
  } catch { return false; }
}

// Source files decide, not markers: codeql database create fails outright on a language with a
// marker and no code.
function detectLanguages(root: string): string[] {
  const byExt = new Map(LANGS.flatMap(([lang, exts]) => exts.map((e): [string, string] => [e, lang])));
  const found = new Set<string>();
  const queue = [root];
  let examined = 0;
  let budgetHit = false;
  outer:
  while (queue.length) {
    const dir = queue.shift();
    if (dir === undefined) break;
    let entries: fs.Dirent[];
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { continue; }
    for (const e of entries) {
      if (found.size === LANGS.length) break outer;
      if (examined++ >= SAMPLE_LIMIT) { budgetHit = true; break outer; }
      if (e.isDirectory()) {
        if (e.name.startsWith('.') || SKIP_DIRS.has(e.name)) continue;
        queue.push(path.join(dir, e.name));
      } else {
        const lang = byExt.get(path.extname(e.name));
        if (lang) found.add(lang);
      }
    }
  }
  // A huge monorepo may hide its Go tree past the budget; a small repo with a stray
  // package.json and no JavaScript must not get JavaScript, so this only runs on the budget path.
  if (budgetHit) {
    for (const [lang, , markers] of LANGS) {
      if (markers.some((m) => fs.existsSync(path.join(root, m)))) found.add(lang);
    }
  }
  const langs = LANGS.map(([lang]) => lang).filter((l) => found.has(l));
  if (hasWorkflows(root)) langs.push('actions');
  return langs;
}

// A scanner that is absent or exits non-zero is recorded and the run continues with what it has.
// Both failing is fatal, because normalizing nothing would report a clean repository.
function runScanners(opts: ScanOpts, deps: ScanDeps, target: string, scanDir: string): { raw: RawScans; scanners: ScannerStatus[] } {
  const raw: RawScans = {};
  const scanners: ScannerStatus[] = [];

  if (opts.scans) {
    for (const [name, file] of [['semgrep', 'semgrep.json'], ['codeql', 'codeql.sarif']] as const) {
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
  const cfg = opts.scanConfig;
  for (const name of opts.scanners) {
    if (!present(name)) { scanners.push({ name, status: 'absent', detail: 'not on PATH' }); continue; }
    if (name === 'semgrep') {
      const out = path.join(scanDir, 'semgrep.json');
      const r = deps.exec('semgrep', ['scan', ...cfg.semgrep.flatMap((c) => ['--config', c]),
        `--json-output=${out}`, target]);
      if (!fs.existsSync(out)) {
        scanners.push({ name, status: 'failed', detail: trim(r.stderr), config: cfg.semgrep.join(' ') });
        continue;
      }
      raw.semgrep = readJson(out);
      scanners.push({ name, status: r.status === 0 ? 'ok' : 'partial',
        detail: r.status === 0 ? out : trim(r.stderr), config: cfg.semgrep.join(' ') });
    } else {
      const langs = opts.languages || detectLanguages(target);
      if (!langs.length) { scanners.push({ name, status: 'failed', detail: 'no language detected' }); continue; }
      const problems: string[] = [];
      const analyzed: string[] = [];
      let allRuns: unknown[] = [];
      let template: Record<string, unknown> | null = null;
      for (const lang of langs) {
        const db = path.join(scanDir, `codeql-db-${lang}`);
        const out = path.join(scanDir, `codeql-${lang}.sarif`);
        // A resumed run must never read a stale file from a previous attempt at this language.
        fs.rmSync(out, { force: true });
        const c = deps.exec('codeql', ['database', 'create', db, `--language=${lang}`, `--source-root=${target}`, '--overwrite']);
        if (c.status !== 0) { problems.push(`${lang}: ${trim(c.stderr)}`); continue; }
        const a = deps.exec('codeql', ['database', 'analyze', db, '--format=sarif-latest', `--output=${out}`,
          '--sarif-add-snippets', `codeql/${lang}-queries:codeql-suites/${lang}-${cfg.codeql_suite}.qls`]);
        if (!fs.existsSync(out)) { problems.push(`${lang}: ${trim(a.stderr)}`); continue; }
        if (a.status !== 0) problems.push(`${lang}: ${trim(a.stderr)}`);
        const parsed = readJson(out);
        if (!isRecord(parsed)) { problems.push(`${lang}: SARIF is not an object`); continue; }
        if (!template) template = parsed;
        allRuns = allRuns.concat(Array.isArray(parsed.runs) ? parsed.runs : []);
        analyzed.push(lang);
      }
      if (!allRuns.length) { scanners.push({ name, status: 'failed', detail: problems.join('; ') }); continue; }
      const merged = path.join(scanDir, 'codeql.sarif');
      raw.codeql = { ...template, runs: allRuns };
      writeJson(merged, raw.codeql);
      scanners.push({ name, status: problems.length ? 'partial' : 'ok',
        detail: problems.length ? problems.join('; ') : merged, config: analyzed.join(','), languages: analyzed });
    }
  }
  return { raw, scanners };
}

// A finding's id hashes its sink line, so comparing ids would count every rewritten flagged line
// as a finding the patch introduced, and the retry that follows rewards dodging the rule's shape.
// A rescan finding is new only when base had no hit of its rule in its file. The price is written
// down in references/FIX-AND-VERIFY.md.
const ruleFiles = (f: Pick<Finding, 'sites'>) => f.sites.flatMap((s) => s.observations.map((o) => `${o.rule_id}\u0000${s.locus.file}`));

function baselineOf(raw: RawScans, findings: Pick<Finding, 'sites'>[], scanConfig: ScanConfig, scanners: ScannerStatus[]): Baseline {
  return {
    scanners: Object.keys(raw),
    ruleFiles: new Set(findings.flatMap(ruleFiles)),
    scanConfig,
    languages: (scanners || []).find((s) => s.name === 'codeql')?.languages || null,
  };
}

function rescan(finding: FindingRecord, worktree: string, scanDir: string,
  { deps, runId, baseline }: { deps: ScanDeps; runId: string; baseline: Baseline }): { obligation: ObligationResult; rescan: Rescan } {
  const { raw, scanners } = runScanners(
    { scans: null, scanners: baseline.scanners, scanConfig: baseline.scanConfig, languages: baseline.languages },
    deps, worktree, scanDir);
  if (!Object.keys(raw).length) {
    return {
      obligation: { status: 'unavailable', reason: 'rescan_produced_no_output' },
      rescan: { ran: false, scanners, original_absent: null, new_findings: [] },
    };
  }
  const after = normalize(raw, makeRepo(worktree), `${runId}-rescan`).findings;
  const newFindings = after.filter((x) => ruleFiles(x).some((k) => !baseline.ruleFiles.has(k))).map((x) => x.id);
  const own = new Set(ruleFiles(finding));
  const originalAbsent = !after.some((x) => ruleFiles(x).some((k) => own.has(k)));
  return {
    obligation: newFindings.length
      ? { status: 'fail', reason: 'rescan_new', new_findings: newFindings }
      : { status: 'pass' },
    rescan: { ran: true, scanners, original_absent: originalAbsent, new_findings: newFindings },
  };
}

export type { ScanConfig, ScannerStatus, Rescan, SyncExec, ScanDeps, ScanOpts, Baseline };
export {
  runScanners, detectLanguages, onPath, trim, baselineOf, rescan,
  DEFAULT_SCAN_CONFIG, SUITE_NAME, semgrepConfigArg, parseScanConfig, SCANNERS,
};
