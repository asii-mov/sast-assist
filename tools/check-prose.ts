#!/usr/bin/env node
// House prose rules, checked instead of restated. Covers every tracked markdown file.
// Run: node tools/check-prose.ts [path ...]   (defaults to the whole repo)
//
// This exists because an earlier version of the em dash check lived inside the skill-tree
// validator and therefore only ever looked at skills/. The design docs accumulated 162
// violations that nothing was watching.

import fs from 'fs';
import path from 'path';

const SKIP_DIRS = new Set(['node_modules', '.git', '.work', 'reference', 'fixtures', '.claude']);

// design/arena holds historical records. RUBRIC.md states it is restored verbatim and
// CANDIDATES.md reconstructs packages that no longer exist. Editing either would falsify a
// provenance claim, so they are exempt rather than fixed.
const SKIP_FILES = [/design\/arena\//];

const RULES = [
  { id: 'em-dash', re: /—/g,
    why: 'em dash: end the sentence or use a comma (unslop 13)' },
  { id: 'arrow', re: /(^|\s)(->|→)(\s|$)/g,
    why: 'arrow in prose: write the words (unslop 33)' },
  { id: 'metaphor-surface', re: /\b(operator|public|api|small|large|exposed)\s+surface\b/gi,
    why: '"surface" as metaphor: name the real thing (unslop 26)' },
  { id: 'filler', re: /\b(in order to|due to the fact that|it is important to note that|it's worth noting that)\b/gi,
    why: 'filler phrase (unslop 23)' },
  { id: 'ai-vocab', re: /\b(crucial|delve|pivotal|showcase|underscores?|intricate|garner|testament to|tapestry)\b/gi,
    why: 'AI vocabulary: use the plain word (unslop 7)' },
  { id: 'hedge', re: /\b(potentially|arguably|somewhat|rather more|fairly clearly)\b/gi,
    why: 'hedging (unslop 24)' },
  { id: 'curly-quote', re: /[‘’“”]/g,
    why: 'curly quote: use straight quotes (unslop 19)' },
  { id: 'plural-paren', re: /\w\(s\)/g,
    why: '"(s)" plural: write the plural or both words (Global English)' },
  // Only lowercase English word pairs. A path, a product pair and an enum value set all use
  // a slash legitimately, and flagging them buried the two real cases in noise.
  { id: 'slash-or', re: /(?<![\w./-])[a-z]{3,}\/[a-z]{3,}(?:\/[a-z]{3,})*(?![\w./-])/g,
    why: 'slash as "or": write "a, b, or both" (Global English)',
    allow: /^(and\/or|read\/write|unsafe\/safe|pre\/post|input\/output|skills|references|design|bin|test|tools|schema|scans|docs)$/i },
  { id: 'marker', re: /\b(TBD|TODO|FIXME|XXX)\b/g,
    why: 'unresolved marker' },
];

// Fenced code blocks, inline code, tables and link targets are exempt: they carry real
// symbols, real commands and real paths, which this skill says to write verbatim.
// Every mask must preserve newlines, or reported line numbers drift. The link mask used to
// blank newlines inside a wrapped link target and shifted every later line by two.
const blank = (m: string) => m.replace(/[^\n]/g, ' ');

function maskCode(text: string): string {
  return text
    .replace(/```[\s\S]*?```/g, blank)
    .replace(/`[^`\n]*`/g, blank)
    .replace(/^\s*\|.*\|\s*$/gm, blank)
    .replace(/\]\([^)]*\)/g, blank);
}

function walk(dir: string, out: string[]): string[] {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (e.name.startsWith('.') && e.name !== '.claude') continue;
    if (SKIP_DIRS.has(e.name)) continue;
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p, out);
    else if (e.name.endsWith('.md') && !SKIP_FILES.some((r) => r.test(p))) out.push(p);
  }
  return out;
}

type Hit = { rule: string; why: string; line: number; text: string };

function check(file: string): Hit[] {
  const raw = fs.readFileSync(file, 'utf8');
  const text = maskCode(raw);
  const lines = raw.split('\n');
  const hits: Hit[] = [];
  for (const rule of RULES) {
    rule.re.lastIndex = 0;
    let m;
    while ((m = rule.re.exec(text)) !== null) {
      if (rule.allow && rule.allow.test(m[0])) continue;
      const line = text.slice(0, m.index).split('\n').length;
      hits.push({ rule: rule.id, why: rule.why, line, text: (lines[line - 1] || '').trim().slice(0, 90) });
    }
  }
  return hits;
}

const targets = process.argv.slice(2).length
  ? process.argv.slice(2).flatMap((p) => (fs.statSync(p).isDirectory() ? walk(p, []) : [p]))
  : walk(process.cwd(), []);

let total = 0;
for (const f of targets.sort()) {
  const hits = check(f);
  if (!hits.length) continue;
  total += hits.length;
  console.log(`\n${path.relative(process.cwd(), f)}`);
  const byRule: Record<string, Hit[]> = {};
  for (const h of hits) (byRule[h.rule] ||= []).push(h);
  for (const [id, hs] of Object.entries(byRule)) {
    console.log(`  ${id} (${hs.length}): ${hs[0].why}`);
    for (const h of hs.slice(0, 3)) console.log(`      line ${h.line}: ${h.text}`);
    if (hs.length > 3) console.log(`      ... and ${hs.length - 3} more`);
  }
}

console.log(total === 0
  ? `\nprose clean across ${targets.length} file(s)`
  : `\n${total} issue(s) across ${targets.length} file(s)`);
process.exit(total === 0 ? 0 : 1);
