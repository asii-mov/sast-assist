#!/usr/bin/env node
// Deterministic diff guard. Runs before any test, any scan, any agent. Milliseconds, no LLM,
// and no agent can argue its way past it. This is obligation 2 of seven and it catches the
// laziest ways to make a finding disappear for free, before a single token is spent.

import fs from 'fs';

const SUPPRESSION = /\b(nosemgrep|nosem|noqa|NOSONAR|nosec|eslint-disable(?:-next-line|-line)?|@SuppressWarnings|pylint:\s*disable|type:\s*ignore)\b|\b(?:codeql|lgtm)\s*\[/;

const SCANNER_CONFIG = [
  /(^|\/)\.semgrep\.ya?ml$/, /(^|\/)\.semgrepignore$/, /(^|\/)semgrep\.ya?ml$/,
  /(^|\/)\.github\/codeql\//, /(^|\/)codeql-config\.ya?ml$/, /(^|\/)qlpack\.ya?ml$/,
  /(^|\/)\.codeqlignore$/, /(^|\/)\.semgrep\//,
];
const IGNORE_FILES = [/(^|\/)\.gitignore$/, /(^|\/)\.semgrepignore$/, /(^|\/)\.codeqlignore$/];
const HARNESS_FILES = [
  /(^|\/)docker-compose(\.\w+)?\.ya?ml$/, /(^|\/)Procfile$/,
  /(^|\/)\.sast-assist\.toml$/, /(^|\/)Dockerfile$/,
];
const MANIFESTS = [
  /(^|\/)package\.json$/, /(^|\/)package-lock\.json$/, /(^|\/)yarn\.lock$/,
  /(^|\/)requirements\.txt$/, /(^|\/)Pipfile(\.lock)?$/, /(^|\/)pyproject\.toml$/,
  /(^|\/)go\.(mod|sum)$/, /(^|\/)Cargo\.(toml|lock)$/, /(^|\/)pom\.xml$/,
  /(^|\/)build\.gradle(\.kts)?$/, /(^|\/)Gemfile(\.lock)?$/,
];
const TEST_PATH = /(^|\/)(tests?|spec|__tests__)(\/|$)|[._-](test|spec)\.[A-Za-z0-9]+$|_test\.go$/i;
const ASSERT_TOKEN = /\b(assert\w*|expect|should|t\.Error|t\.Fatal|require\.\w+|XCTAssert)\b/;
const SKIP_TOKEN = /\b(it|test|describe|context)\.(skip|todo)\b|\bxit\b|\bxdescribe\b|@Ignore\b|@Disabled\b|\bt\.Skip\(|@pytest\.mark\.skip/;

const ENFORCE_HINT = /\b(validate|valid|sanitiz|escape|allowlist|whitelist|allowed|permit|authoriz|authenticate|verify|check|assert|encode|parameteriz|bind|prepare|normaliz|resolve|realpath|clamp|limit)\w*/i;

// Only these tiers ask the fixer to commit a witness file. A dynamic witness is an HTTP
// exchange stored in the contract, not a file, so it has nothing here to be missing.
const WITNESS_FILE_TIERS = new Set<string>(['executable', 'structural']);

type DiffFile = { path: string; added: string[]; removed: string[] };

function parseDiff(text: string): DiffFile[] {
  const files: DiffFile[] = [];
  let cur: DiffFile | null = null;
  for (const line of text.split('\n')) {
    const m = /^diff --git a\/(.+?) b\/(.+)$/.exec(line);
    if (m) { cur = { path: m[2], added: [], removed: [] }; files.push(cur); continue; }
    if (!cur) continue;
    if (/^\+\+\+ |^--- |^index |^new file|^deleted file|^similarity|^rename /.test(line)) continue;
    if (line.startsWith('+')) cur.added.push(line.slice(1));
    else if (line.startsWith('-')) cur.removed.push(line.slice(1));
  }
  return files;
}

const matchesAny = (p: string, res: RegExp[]) => res.some((re) => re.test(p));

// Glob subset: ** any depth, * within a segment, no braces. Enough for writable_scope.
function globToRe(g: string): RegExp {
  const esc = g.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  return new RegExp('^' + esc.replace(/\*\*\//g, '\u0000').replace(/\*\*/g, '\u0001')
    .replace(/\*/g, '[^/]*').replace(/\u0000/g, '(?:.*/)?').replace(/\u0001/g, '.*') + '$');
}
const inScope = (p: string, globs: string[]) => globs.some((g) => globToRe(g).test(p));

// Token-TYPE sequence comparison. Identical sequences prove a rename, relabel or reformat.
// Known blind spot, stated rather than hidden: a real-shaped but behaviourally no-op call
// changes the type sequence and is NOT caught here. The differential witness catches that,
// because it exercises behaviour instead of shape.
function tokenTypes(src: string): string[] {
  const out: string[] = [];
  const re = /(\/\/[^\n]*|\/\*[\s\S]*?\*\/|#[^\n]*)|("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|`(?:[^`\\]|\\.)*`)|(\b\d+(?:\.\d+)?\b)|([A-Za-z_$][\w$]*)|([{}()[\];,.]|[+\-*/%=<>!&|^~?:]+)|(\s+)/g;
  let m;
  while ((m = re.exec(src)) !== null) {
    if (m[1] || m[6]) continue;
    if (m[2]) out.push('STR');
    else if (m[3]) out.push('NUM');
    else if (m[4]) out.push(/^(if|else|for|while|return|function|const|let|var|new|await|async|class|try|catch|throw|import|export|def|fn|func)$/.test(m[4]) ? `KW:${m[4]}` : 'ID');
    else if (m[5]) out.push(`OP:${m[5]}`);
  }
  return out;
}

const sameShape = (a: string, b: string) => {
  const x = tokenTypes(a), y = tokenTypes(b);
  return x.length === y.length && x.every((t, i) => t === y[i]);
};

type ViolationKind =
  | 'suppression_comment_added' | 'test_skipped' | 'existing_test_weakened' | 'scanner_config_modified'
  | 'ignore_file_modified' | 'app_harness_modified' | 'dependency_manifest_modified'
  | 'outside_writable_scope' | 'cosmetic_change_only' | 'sink_deleted_without_enforcement' | 'witness_missing';
type Violation = { kind: ViolationKind; [detail: string]: unknown };

const ADVISORY = new Set<ViolationKind>(['sink_deleted_without_enforcement']);

type GuardOpts = { sinkFiles?: string[]; sinkText?: string; requireWitnessFile?: boolean };

// The parts of a contract the guard reads. A SecurityContract is one.
type GuardContract = { writable_scope?: string[]; witness?: { tier: string } };

function guardDiff(diffText: string, contract: GuardContract | null, opts: GuardOpts = {}) {
  const violations: Violation[] = [];
  const files = parseDiff(diffText);
  const add = (kind: ViolationKind, extra: Record<string, unknown>) => violations.push({ kind, ...extra });

  const touched = files.map((f) => f.path);
  const scope = (contract && contract.writable_scope) || [];
  const sinkFiles = new Set(opts.sinkFiles || []);

  for (const f of files) {
    for (const [i, line] of f.added.entries()) {
      if (SUPPRESSION.test(line)) {
        add('suppression_comment_added', { file: f.path, line: i + 1, text: line.trim().slice(0, 120) });
        break;
      }
    }
    if (f.added.some((l) => SKIP_TOKEN.test(l)) && TEST_PATH.test(f.path)) {
      add('test_skipped', { files: [f.path], detail: 'a skip/ignore marker was added to a test' });
    }
    if (TEST_PATH.test(f.path)) {
      const lostAsserts = f.removed.filter((l) => ASSERT_TOKEN.test(l)).length;
      const gainedAsserts = f.added.filter((l) => ASSERT_TOKEN.test(l)).length;
      if (lostAsserts > gainedAsserts) {
        add('existing_test_weakened', {
          files: [f.path],
          detail: `${lostAsserts} assertion line(s) removed, ${gainedAsserts} added`,
        });
      }
    }
  }

  const hit = (res: RegExp[]) => touched.filter((p) => matchesAny(p, res));
  if (hit(SCANNER_CONFIG).length) add('scanner_config_modified', { files: hit(SCANNER_CONFIG) });
  if (hit(IGNORE_FILES).length) add('ignore_file_modified', { files: hit(IGNORE_FILES) });
  if (hit(HARNESS_FILES).length) add('app_harness_modified', { files: hit(HARNESS_FILES) });
  if (hit(MANIFESTS).length) add('dependency_manifest_modified', { files: hit(MANIFESTS) });

  if (scope.length) {
    const outside = touched.filter((p) => !inScope(p, scope));
    if (outside.length) add('outside_writable_scope', { files: outside });
  }

  // Cosmetic check, scoped to the files carrying the sink.
  for (const f of files) {
    if (sinkFiles.size && !sinkFiles.has(f.path)) continue;
    if (!f.added.length || !f.removed.length) continue;
    if (sameShape(f.removed.join('\n'), f.added.join('\n'))) {
      add('cosmetic_change_only', {
        detail: `${f.path}: token-type sequence unchanged, so the edit is a rename, relabel or reformat`,
      });
    }
  }

  // A deleted sink with no enforcement construct added anywhere. Loose on purpose; the
  // auditor is the real check for this one.
  for (const f of files) {
    if (sinkFiles.size && !sinkFiles.has(f.path)) continue;
    const { sinkText } = opts;
    const removedSink = sinkText && f.removed.some((l) => l.includes(sinkText));
    if (removedSink && !f.added.some((l) => ENFORCE_HINT.test(l))) {
      add('sink_deleted_without_enforcement', {
        detail: `${f.path}: the sink line was removed and no validation construct was added`,
      });
    }
  }

  const tier = contract?.witness?.tier;
  if (tier && WITNESS_FILE_TIERS.has(tier) && opts.requireWitnessFile !== false) {
    if (!touched.some((p) => TEST_PATH.test(p) || /\.(ya?ml)$/.test(p))) {
      add('witness_missing', { expected_tier: tier });
    }
  }

  // This one is a heuristic over identifier spelling, not a proof. A real fix that validates
  // with a regex and a well-named constant trips it, which happened on a live run against a
  // patch that switched exec to execFile and added a host allowlist. It is reported so a human
  // and the auditor can see it, and it does not by itself sink a patch; the under-informed
  // auditor is the check that can actually read the code. Every other violation is blocking.
  const advisory = violations.filter((v) => ADVISORY.has(v.kind));
  const blocking = violations.filter((v) => !ADVISORY.has(v.kind));
  return { passed: blocking.length === 0, violations: blocking, advisory };
}

export type { Violation, ViolationKind, DiffFile };
export { guardDiff, ADVISORY, parseDiff, tokenTypes, sameShape, globToRe, inScope };

if (import.meta.main) {
  const [diffPath, contractPath] = process.argv.slice(2);
  if (!diffPath) { console.error('usage: patch-guard.ts <diff> [contract.json]'); process.exit(2); }
  const contract = contractPath ? JSON.parse(fs.readFileSync(contractPath, 'utf8')) : null;
  const r = guardDiff(fs.readFileSync(diffPath, 'utf8'), contract, { requireWitnessFile: false });
  if (r.passed) { console.log('guard: passed'); process.exit(0); }
  for (const v of r.violations) console.error(`  ${v.kind}: ${JSON.stringify(v)}`);
  process.exit(1);
}
