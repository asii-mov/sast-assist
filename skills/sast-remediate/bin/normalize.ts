#!/usr/bin/env node
// SARIF and Semgrep JSON in, Finding[] out. This is the ONLY module that knows either wire
// format exists. Everything downstream sees domain types only.
//
// Two folds run here, in order:
//   FOLD 1  cross-scanner, within a locus  -> Site
//   FOLD 2  cross-site, one root cause     -> Finding
// Both prefer a false split to a false merge. Triaging one root cause twice costs an agent
// call. Merging two different bugs produces one contract that under-describes both.

import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import type { AgentTriage, ClaimedSeverity, Finding, FlowStep, InvariantClass, Locus, Observation, TaintFlow } from '../schema/types.ts';

// Scanner output as read from disk, before normalize() parses it.
type RawScans = { semgrep?: unknown; codeql?: unknown };

// The parts of each scanner's output this file reads, every field optional because the code
// reads each one defensively. The enum-valued fields, and the rule ids read as present, are
// claims rather than checks: run.ts validates every normalized finding against
// finding.schema.json and stops the run on a mismatch.
type SemgrepClaim = Extract<ClaimedSeverity, { kind: 'semgrep' }>;
type SemgrepOutput = {
  results?: {
    path?: string; start?: { line?: number }; check_id?: string;
    extra?: {
      metadata?: { cwe?: unknown; owasp?: unknown; shortlink?: unknown;
        impact?: SemgrepClaim['impact']; likelihood?: SemgrepClaim['likelihood']; confidence?: SemgrepClaim['confidence'] };
      fingerprint?: string; message?: string; severity?: SemgrepClaim['severity']; engine_kind?: string; is_ignored?: boolean;
    };
  }[];
};
type SarifLocation = { physicalLocation?: { artifactLocation?: { uri?: string }; region?: { startLine?: number } }; message?: { text?: string } };
type SarifRule = {
  id?: string; name?: string; shortDescription?: { text?: string };
  properties?: { tags?: string[]; 'security-severity'?: string | number;
    'problem.severity'?: Extract<ClaimedSeverity, { kind: 'codeql' }>['problem_severity'] };
};
type Sarif = {
  runs?: {
    tool?: { driver?: { name?: string; semanticVersion?: string; rules?: SarifRule[] } };
    results?: {
      ruleId?: string; locations?: SarifLocation[]; message?: { text?: string }; suppressions?: unknown[];
      partialFingerprints?: Record<string, string>;
      codeFlows?: { threadFlows?: { locations?: { location?: SarifLocation }[] }[] }[];
    }[];
  }[];
};

// One scanner result before folding: where it points, what it claims, and any trace it carried.
type RawFlow = { provenance: 'codeql_codeflows'; steps: { file: string; line: number; role: FlowStep['role']; note: string | null }[] };
type RawResult = { file: string | undefined; line: number | undefined; cwes: string[]; ruleId: string; observation: Observation; flow: RawFlow | null };
type FoldedSite = { klass: InvariantClass; locus: Locus; observations: Observation[]; flows: (RawFlow | null)[] };
type Repo = ReturnType<typeof makeRepo>;

const sha256 = (s: string) => crypto.createHash('sha256').update(s, 'utf8').digest('hex');
const collapseWs = (s: string) => s.replace(/\s+/g, ' ').trim();

// ---------------------------------------------------------------- invariant class

// CWE -> our taxonomy. Deterministic, no LLM. Extend here, not at the call sites.
const CWE_CLASS: Record<string, InvariantClass> = {
  'CWE-89': 'injection.sql', 'CWE-564': 'injection.sql',
  'CWE-78': 'injection.command', 'CWE-77': 'injection.command', 'CWE-88': 'injection.command',
  'CWE-94': 'injection.code', 'CWE-95': 'injection.code',
  'CWE-1336': 'injection.template', 'CWE-917': 'injection.template',
  'CWE-22': 'injection.path', 'CWE-23': 'injection.path', 'CWE-36': 'injection.path',
  'CWE-90': 'injection.ldap', 'CWE-91': 'injection.xml', 'CWE-611': 'injection.xml',
  'CWE-117': 'injection.log', 'CWE-93': 'injection.log',
  'CWE-79': 'xss.reflected', 'CWE-80': 'xss.reflected',
  'CWE-502': 'deserialization.unsafe',
  'CWE-918': 'ssrf', 'CWE-601': 'redirect.open',
  'CWE-862': 'authz.missing', 'CWE-863': 'authz.missing', 'CWE-639': 'authz.missing',
  'CWE-287': 'authn.weak', 'CWE-306': 'authn.weak',
  'CWE-384': 'session.weak', 'CWE-613': 'session.weak',
  'CWE-327': 'crypto.weak', 'CWE-326': 'crypto.weak', 'CWE-916': 'crypto.weak',
  'CWE-323': 'crypto.misuse', 'CWE-329': 'crypto.misuse', 'CWE-347': 'crypto.misuse',
  'CWE-798': 'secret.hardcoded', 'CWE-259': 'secret.hardcoded',
  'CWE-330': 'randomness.weak', 'CWE-338': 'randomness.weak',
  'CWE-367': 'race.toctou', 'CWE-362': 'race.toctou',
  'CWE-119': 'memory.unsafe', 'CWE-787': 'memory.unsafe', 'CWE-125': 'memory.unsafe',
  'CWE-400': 'dos.uncontrolled', 'CWE-770': 'dos.uncontrolled', 'CWE-1333': 'dos.uncontrolled',
  'CWE-200': 'disclosure.sensitive', 'CWE-209': 'disclosure.sensitive', 'CWE-532': 'disclosure.sensitive',
  'CWE-16': 'config.insecure', 'CWE-1004': 'config.insecure', 'CWE-614': 'config.insecure',
  'CWE-915': 'config.insecure', 'CWE-942': 'config.insecure',
};

// Fallback only. A rule id keyword is weaker evidence than a CWE, so it is consulted second.
const RULE_KEYWORD_CLASS: [RegExp, InvariantClass][] = [
  [/sql[-_.]?inject|sqli/i, 'injection.sql'],
  [/command[-_.]?inject|child[-_.]?process|shell[-_.]?inject|os[-_.]?command/i, 'injection.command'],
  [/path[-_.]?(inject|travers)|zip[-_.]?slip/i, 'injection.path'],
  [/xss|cross[-_.]?site[-_.]?script/i, 'xss.reflected'],
  [/ssrf|request[-_.]?forgery/i, 'ssrf'],
  [/open[-_.]?redirect/i, 'redirect.open'],
  [/deserial/i, 'deserialization.unsafe'],
  [/hardcoded|hard[-_.]?coded.*(secret|password|credential)/i, 'secret.hardcoded'],
  [/insecure[-_.]?random|weak[-_.]?random/i, 'randomness.weak'],
  [/weak[-_.]?(cipher|hash|crypto)|insecure[-_.]?cipher/i, 'crypto.weak'],
  [/prototype[-_.]?pollut/i, 'config.insecure'],
  [/eval|code[-_.]?inject/i, 'injection.code'],
];

function classify(cwes: string[], ruleId: string): InvariantClass {
  for (const c of cwes) if (CWE_CLASS[c]) return CWE_CLASS[c];
  for (const [re, cls] of RULE_KEYWORD_CLASS) if (re.test(ruleId)) return cls;
  return 'other';
}

const normCwe = (s: unknown) => {
  const m = /cwe[-_ ]?(\d+)/i.exec(String(s));
  return m ? `CWE-${String(Number(m[1]))}` : null;
};

// ---------------------------------------------------------------- repo snapshot

function makeRepo(root: string) {
  const cache = new Map<string, string[] | null>();
  const readLines = (rel: string): string[] | null => {
    const hit = cache.get(rel);
    if (hit !== undefined) return hit;
    let lines: string[] | null = null;
    try {
      const abs = path.resolve(root, rel);
      // Refuse anything that escapes the repo root. Boundary validation happens here and
      // nothing downstream re-checks it.
      if (!abs.startsWith(path.resolve(root) + path.sep)) throw new Error('escapes root');
      lines = fs.readFileSync(abs, 'utf8').split('\n');
    } catch { lines = null; }
    cache.set(rel, lines);
    return lines;
  };
  return {
    root,
    exists: (rel: string) => readLines(rel) !== null,
    line: (rel: string, n: number) => {
      const ls = readLines(rel);
      return ls && ls[n - 1] !== undefined ? ls[n - 1] : '';
    },
    lines: readLines,
  };
}

// Enclosing symbol by backward scan. Heuristic and deliberately conservative: when it cannot
// name a symbol it returns null, and a null symbol never participates in a proximity merge.
const DECL = [
  /^\s*(?:async\s+)?function\s+([A-Za-z_$][\w$]*)/,
  /^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:function\b|\([^)]*\)\s*=>)/,
  /^\s*([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*\{\s*$/,
  /^\s*(?:export\s+)?class\s+([A-Za-z_$][\w$]*)/,
  /^\s*def\s+([A-Za-z_$][\w$]*)/,
  /^\s*(?:pub\s+)?fn\s+([A-Za-z_$][\w$]*)/,
  /^\s*func\s+(?:\([^)]*\)\s*)?([A-Za-z_$][\w$]*)/,
];

function enclosingSymbol(repo: Repo, file: string, line: number): string | null {
  const ls = repo.lines(file);
  if (!ls) return null;
  for (let i = Math.min(line, ls.length) - 1; i >= 0; i--) {
    for (const re of DECL) {
      const m = re.exec(ls[i]);
      if (m) return m[1];
    }
  }
  return null;
}

// The callee at the sink. This is FOLD 2's clustering key: forty call sites of one unsafe
// helper share a sink_symbol and therefore one root cause, one contract, one patch.
function extractCallee(lineText: string): string | null {
  const t = lineText.replace(/\/\/.*$/, '');
  const calls = [...t.matchAll(/([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*\(/g)]
    .map((m) => m[1])
    .filter((n) => !/^(if|for|while|switch|catch|return|typeof|function|require|new)$/.test(n));
  return calls.length ? calls[calls.length - 1] : null;
}

// ---------------------------------------------------------------- scanner parsing

function fromSemgrep(json: unknown): RawResult[] {
  const out: RawResult[] = [];
  for (const r of (json as SemgrepOutput).results || []) {
    const e = r.extra || {};
    const m = e.metadata || {};
    const cwes = (Array.isArray(m.cwe) ? m.cwe : m.cwe ? [m.cwe] : []).map(normCwe).filter((c) => c !== null);
    out.push({
      file: r.path, line: r.start && r.start.line,
      cwes, ruleId: r.check_id as string,
      observation: {
        scanner: 'semgrep',
        rule_id: r.check_id as string,
        rule_name: (m.shortlink ? String(m.shortlink) : null),
        // Semgrep OSS writes this placeholder for every result; it identifies nothing.
        native_fingerprint: e.fingerprint && e.fingerprint !== 'requires login' ? e.fingerprint : null,
        message: e.message || '',
        claimed: {
          kind: 'semgrep',
          severity: e.severity || 'INFO',
          impact: m.impact || null,
          likelihood: m.likelihood || null,
          confidence: m.confidence || null,
        },
        cwe: cwes,
        owasp: (Array.isArray(m.owasp) ? m.owasp : m.owasp ? [m.owasp] : []).map(String),
        engine: e.engine_kind || null,
        suppressed_at_source: Boolean(e.is_ignored),
        raw_pointer: `semgrep.json#/results/${out.length}`,
        seen_in_rounds: [1],
      },
      flow: null, // Semgrep OSS emits no dataflow_trace. Verified empirically, not assumed.
    });
  }
  return out;
}

// `dropped` is threaded in so a locationless SARIF result is COUNTED, not silently lost.
// foldSites already records the file-missing case; without this, the two failure modes
// were asymmetric and one of them was invisible in the summary line.
function fromSarif(sarif: unknown, dropped: string[]): RawResult[] {
  const out: RawResult[] = [];
  ((sarif as Sarif).runs || []).forEach((run, runIdx) => {
    const driver = (run.tool && run.tool.driver) || {};
    const rules = new Map((driver.rules || []).map((r) => [r.id, r]));
    (run.results || []).forEach((r, idx) => {
      const rule: SarifRule = rules.get(r.ruleId) || {};
      // security-severity and problem.severity live on the RULE, not the result.
      const props = rule.properties || {};
      const pl = r.locations && r.locations[0] && r.locations[0].physicalLocation;
      if (!pl) { dropped.push(`${r.ruleId} result ${idx}: no physicalLocation`); return; }
      const file = pl.artifactLocation && pl.artifactLocation.uri;
      const line = pl.region && pl.region.startLine;
      if (!file || !line) { dropped.push(`${r.ruleId} result ${idx}: no file or line`); return; }
      const cwes = (props.tags || []).map(normCwe).filter((c) => c !== null);
      const secsev = props['security-severity'] !== undefined
        ? Number(props['security-severity']) : null;

      let flow: RawFlow | null = null;
      const cf = r.codeFlows && r.codeFlows[0];
      const tf = cf && cf.threadFlows && cf.threadFlows[0];
      const locs = tf && Array.isArray(tf.locations) ? tf.locations : [];
      if (locs.length >= 2) {
        flow = {
          provenance: 'codeql_codeflows',
          steps: locs.map((l, i) => {
            const p = l.location && l.location.physicalLocation;
            return {
              file: (p && p.artifactLocation && p.artifactLocation.uri) || file,
              line: (p && p.region && p.region.startLine) || line,
              role: i === 0 ? 'source' : i === locs.length - 1 ? 'sink' : 'propagation',
              note: (l.location && l.location.message && l.location.message.text) || null,
            };
          }),
        };
      }

      out.push({
        file, line, cwes, ruleId: r.ruleId as string,
        observation: {
          scanner: 'codeql',
          rule_id: r.ruleId as string,
          rule_name: (rule.shortDescription && rule.shortDescription.text) || rule.name || null,
          native_fingerprint: r.partialFingerprints
            ? Object.values(r.partialFingerprints)[0] || null : null,
          message: (r.message && r.message.text) || '',
          claimed: {
            kind: 'codeql',
            problem_severity: props['problem.severity'] || null,
            security_severity: Number.isFinite(secsev) ? secsev : null,
          },
          cwe: cwes,
          owasp: (props.tags || []).filter((t) => /owasp/i.test(t)),
          engine: driver.name && driver.semanticVersion
            ? `${driver.name}@${driver.semanticVersion}` : driver.name || null,
          suppressed_at_source: Array.isArray(r.suppressions) && r.suppressions.length > 0,
          raw_pointer: `codeql.sarif#/runs/${runIdx}/results/${idx}`,
          seen_in_rounds: [1],
        },
        flow,
      });
    });
  });
  return out;
}

// ---------------------------------------------------------------- folds

// A scanner reports whatever path it was handed: run it against an absolute target and every
// result is absolute. The finding id is built from the file, so an absolute path mints a
// different identity for the same defect, and a rescan then reports every surviving finding as
// new. INGEST.md states the repo-relative guarantee; this is the line that actually enforces it.
// Returns null for anything outside the root, which foldSites counts as a drop.
function toRepoRelative(file: string | null | undefined, root: string): string | null {
  if (!file) return null;
  const absRoot = path.resolve(root);
  const abs = path.resolve(absRoot, String(file).replace(/\\/g, '/'));
  if (abs !== absRoot && !abs.startsWith(absRoot + path.sep)) return null;
  return path.relative(absRoot, abs).split(path.sep).join('/');
}

function foldSites(raws: RawResult[], repo: Repo, dropped: string[]): FoldedSite[] {
  const sites: FoldedSite[] = [];
  for (const raw of raws) {
    const rel = toRepoRelative(raw.file, repo.root);
    if (!rel || !raw.line || !repo.exists(rel)) {
      dropped.push(`${raw.file}:${raw.line} (${raw.ruleId}) path missing or escapes root`);
      continue;
    }
    raw.file = rel;
    const lineText = repo.line(rel, raw.line);
    const locus: Locus = {
      file: rel,
      symbol: enclosingSymbol(repo, rel, raw.line),
      sink_digest: sha256(collapseWs(lineText)),
      line_at_scan: raw.line,
    };
    const klass = classify(raw.cwes, raw.ruleId);

    // FOLD 1: same file AND same class AND (same digest OR within 2 lines under one symbol).
    // The proximity arm requires a resolved symbol on BOTH sides. Without it we would rather
    // triage twice than merge two different bugs.
    const hit = sites.find((s) =>
      s.klass === klass &&
      s.locus.file === locus.file &&
      (s.locus.sink_digest === locus.sink_digest ||
        (Math.abs(s.locus.line_at_scan - locus.line_at_scan) <= 2 &&
          s.locus.symbol !== null && s.locus.symbol === locus.symbol)));

    if (hit) {
      hit.observations.push(raw.observation);
      hit.flows.push(raw.flow);
      // Keep the earliest line as the anchor so the site is stable across scanner ordering.
      if (locus.line_at_scan < hit.locus.line_at_scan) hit.locus = locus;
    } else {
      sites.push({ klass, locus, observations: [raw.observation], flows: [raw.flow] });
    }
  }
  return sites;
}

function selectFlow(flows: (RawFlow | null)[], anchorSite: FoldedSite, repo: Repo): TaintFlow {
  const traced = flows.filter((f) => f !== null);
  if (traced.length) {
    // Most steps wins; tie-break codeql > semgrep.
    traced.sort((a, b) => b.steps.length - a.steps.length ||
      (a.provenance === 'codeql_codeflows' ? -1 : 1));
    const f = traced[0];
    return {
      kind: 'traced',
      provenance: f.provenance,
      steps: f.steps.map((s) => ({
        file: s.file,
        line: s.line,
        symbol: enclosingSymbol(repo, s.file, s.line),
        role: s.role,
        code: collapseWs(repo.line(s.file, s.line)), // materialized ONCE, here
        note: s.note,
      })),
    };
  }
  const l = anchorSite.locus;
  return {
    kind: 'sink_only',
    sink: {
      file: l.file, line: l.line_at_scan, symbol: l.symbol, role: 'sink',
      code: collapseWs(repo.line(l.file, l.line_at_scan)), note: null,
    },
    reason: 'scanner_emitted_no_flow',
  };
}

type ClusterKey = Finding['cluster'];
type Cluster = { key: ClusterKey; sites: FoldedSite[] };
type SplitGroup = Extract<AgentTriage, { split: unknown }>['split'][number];
type SplitResult<F> = { ok: true; children: F[] } | { ok: false; reason: string };

function foldFindings(sites: FoldedSite[], repo: Repo): Cluster[] {
  const groups: Cluster[] = [];
  for (const site of sites) {
    const callee = extractCallee(repo.line(site.locus.file, site.locus.line_at_scan));
    const key = { invariant_class: site.klass, sink_symbol: callee, source_class: null };

    // FOLD 2: one root cause. Requires a NON-NULL callee; an unresolved callee never clusters.
    const hit = callee && groups.find((g) =>
      g.key.invariant_class === key.invariant_class && g.key.sink_symbol === callee);

    if (hit) hit.sites.push(site);
    else groups.push({ key, sites: [site] });
  }
  return groups;
}

// Everything that depends on the site set is derived here, so a finding split out of another
// gets its own anchor, flow and excerpt rather than its parent's.
function buildFinding(g: Cluster, repo: Repo, runId: string, id: string, splitFrom: string | null): Finding {
  const anchor = g.sites[0];
  const ls = repo.lines(anchor.locus.file) || [];
  const from = Math.max(0, anchor.locus.line_at_scan - 12);
  const excerpt = ls.slice(from, anchor.locus.line_at_scan + 12).join('\n');
  return {
    schema_version: 1,
    id,
    run_id: runId,
    invariant_class: g.key.invariant_class,
    cluster: g.key,
    sites: g.sites
      .map((s) => ({ locus: s.locus, observations: [...s.observations].sort((a, b) =>
        a.scanner.localeCompare(b.scanner) || a.rule_id.localeCompare(b.rule_id)) }))
      .sort((a, b) => a.locus.line_at_scan - b.locus.line_at_scan),
    flow: selectFlow(g.sites.flatMap((s) => s.flows), anchor, repo),
    context: {
      scan_commit: null,
      source_hash: sha256(excerpt),
      enclosing_excerpt: excerpt,
    },
    lease: null, triage: null, gate: null, patches: [], disposition: null, prior: null, split_from: splitFrom,
  };
}

function clusterId(g: Cluster): string {
  const anchor = g.sites[0];
  const material = [g.key.invariant_class, g.key.sink_symbol ?? '', anchor.locus.file, anchor.locus.sink_digest].join('\u0000');
  return `f_${sha256(material).slice(0, 16)}`;
}

// A triage split names each part by the lines of its sites. A line names every site of the
// parent on it, so the parts must be disjoint and cover the parent between them. The child id
// hashes the parent id and the part's lines, so deriving it again from the saved split gives
// the same id.
function splitFinding(parentId: string, cluster: Cluster, groups: SplitGroup[], repo: Repo, runId: string): SplitResult<Finding> {
  const lineOf = (s: FoldedSite) => s.locus.line_at_scan;
  const claimed = new Set<number>();
  const children: Finding[] = [];
  for (const g of groups) {
    const lines = [...new Set(g.site_lines)].sort((a, b) => a - b);
    for (const l of lines) {
      if (claimed.has(l)) return { ok: false, reason: `line ${l} is in more than one part` };
      if (!cluster.sites.some((s) => lineOf(s) === l)) return { ok: false, reason: `line ${l} is not a site of ${parentId}` };
      claimed.add(l);
    }
    const sites = cluster.sites.filter((s) => lines.includes(lineOf(s)));
    const id = `f_${sha256(`${parentId}\u0000${lines.join(',')}`).slice(0, 16)}`;
    children.push(buildFinding({ key: cluster.key, sites }, repo, runId, id, parentId));
  }
  const uncovered = cluster.sites.map(lineOf).filter((l) => !claimed.has(l));
  if (uncovered.length) return { ok: false, reason: `no part holds the site(s) at line ${uncovered.join(', ')}` };
  return { ok: true, children };
}

function normalize(raw: RawScans, repo: Repo, runId: string) {
  const dropped: string[] = [];
  const raws = [
    ...(raw.semgrep ? fromSemgrep(raw.semgrep) : []),
    ...(raw.codeql ? fromSarif(raw.codeql, dropped) : []),
  ];
  const sites = foldSites(raws, repo, dropped);
  const clusters = new Map<string, Cluster>();
  for (const g of foldFindings(sites, repo)) {
    const id = clusterId(g);
    if (clusters.has(id)) throw new Error(`id collision: ${id}`);
    clusters.set(id, g);
  }
  const findings = [...clusters].map(([id, g]) => buildFinding(g, repo, runId, id, null));
  findings.sort((a, b) => a.id.localeCompare(b.id));
  const split = (parentId: string, groups: SplitGroup[]) => {
    const cluster = clusters.get(parentId);
    if (!cluster) throw new Error(`${parentId} is not a finding of this scan, so it cannot be split`);
    return splitFinding(parentId, cluster, groups, repo, runId);
  };
  return { findings, split, dropped, raw_count: raws.length, site_count: sites.length };
}

function main(argv: string[]): number {
  // Every option takes a value, so a bare flag is left out and reads as missing.
  const args: Record<string, string> = Object.fromEntries(argv.flatMap((a) => {
    const i = a.indexOf('=');
    return i < 0 ? [] : [[a.slice(2, i), a.slice(i + 1)]];
  }));
  if (!args.repo) {
    console.error('usage: normalize.ts --repo=DIR [--semgrep=F.json] [--codeql=F.sarif] [--run=ID] [--out=F.json]');
    return 2;
  }
  const repo = makeRepo(args.repo);
  const raw: RawScans = {};
  if (args.semgrep) raw.semgrep = JSON.parse(fs.readFileSync(args.semgrep, 'utf8'));
  if (args.codeql) raw.codeql = JSON.parse(fs.readFileSync(args.codeql, 'utf8'));
  const res = normalize(raw, repo, args.run || 'run-1');
  const json = JSON.stringify(res.findings, null, 2);
  if (args.out) fs.writeFileSync(args.out, json + '\n');
  else console.log(json);
  console.error(`raw=${res.raw_count} sites=${res.site_count} findings=${res.findings.length} dropped=${res.dropped.length}`);
  for (const d of res.dropped) console.error(`  dropped: ${d}`);
  return 0;
}

export type { RawScans, SplitGroup, SplitResult };
export {
  toRepoRelative, normalize, makeRepo, classify, extractCallee, enclosingSymbol, sha256, collapseWs };
if (import.meta.main) process.exit(main(process.argv.slice(2)));
