// One-off codemod for the TypeScript migration (docs/plans/TS-migration.md, unit 3).
// Usage: node tools/cjs-to-esm.ts [--no-git] <file.cjs>...
// Converts each file's module syntax to ES modules, renames it to .ts, and rewrites
// `<name>.cjs` to `<name>.ts` across the live files. Anything it can't convert mechanically
// is printed as a leftover for a hand edit. Deleted when the migration lands.

import fs from 'fs';
import path from 'path';
import { execFileSync } from 'child_process';

const REPO = path.resolve(import.meta.dirname, '..');
const SKILL = path.join(REPO, 'skills/sast-remediate');
const LIVE = ['skills/sast-remediate/bin', 'skills/sast-remediate/test', 'skills/sast-remediate/tools',
  'skills/sast-remediate/references', 'skills/sast-remediate/SKILL.md', 'AGENTS.md', 'tools'];

const args = process.argv.slice(2);
const useGit = !args.includes('--no-git');
const files = args.filter((a) => a !== '--no-git').map((f) => path.resolve(f));

function spec(fromFile: string, target: string): string {
  const rel = path.relative(path.dirname(fromFile), target.replace(/\.cjs$/, '.ts'));
  return rel.startsWith('.') ? rel : `./${rel}`;
}

function convert(file: string, text: string): { text: string; leftovers: string[] } {
  const out: string[] = [];
  const leftovers: string[] = [];
  let inTemplate = false;
  const lines = text.replace(/^'use strict';\n/m, '').split('\n');
  for (const [i, line] of lines.entries()) {
    const wasInTemplate = inTemplate;
    for (const m of line.matchAll(/(?<!\\)`/g)) inTemplate = !inTemplate;
    if (wasInTemplate) { out.push(line); continue; }
    let l = line;
    let m: RegExpExecArray | null;
    if ((m = /^const (\w+) = require\('([^./][^']*)'\);$/.exec(l))) {
      l = `import ${m[1]} from '${m[2]}';`;
    } else if ((m = /^const (\{[^}]+\}) = require\('([^./][^']*)'\);$/.exec(l))) {
      l = `import ${m[1]} from '${m[2]}';`;
    } else if ((m = /^const (\{[^}]+\}|\w+) = require\('(\.[^']+\.cjs)'\);$/.exec(l))) {
      l = importLine(m[1], spec(file, path.resolve(path.dirname(file), m[2])));
    } else if ((m = /^const (\{[^}]+\}|\w+) = require\(path\.join\(ROOT, '([^']+\.cjs)'\)\);$/.exec(l))) {
      l = importLine(m[1], spec(file, path.join(SKILL, m[2])));
    }
    l = l.replace(/^if \(require\.main === module\)/, 'if (import.meta.main)');
    l = l.replace(/\b__dirname\b/g, 'import.meta.dirname');
    if (/\brequire\(|\bmodule\.exports\b|\b__filename\b/.test(l) && !/^module\.exports = /.test(l)) {
      leftovers.push(`${path.relative(REPO, file)}:${i + 1}: ${l.trim()}`);
    }
    out.push(l);
  }
  let result = out.join('\n');
  result = result.replace(/^module\.exports = \{([\s\S]*?)\};$/m, (whole, body: string) => {
    if (/:/.test(body.replace(/\/\/.*$/gm, ''))) {
      leftovers.push(`${path.relative(REPO, file)}: module.exports has non-shorthand keys`);
      return whole;
    }
    return `export {${body}};`;
  });
  return { text: result, leftovers };
}

function importLine(binding: string, from: string): string {
  return binding.startsWith('{') ? `import ${binding} from '${from}';` : `import * as ${binding} from '${from}';`;
}

function liveFiles(): string[] {
  const listed = execFileSync('git', ['ls-files', '--', ...LIVE], { cwd: REPO, encoding: 'utf8' });
  return listed.split('\n').filter(Boolean).map((f) => path.join(REPO, f)).filter((f) => fs.existsSync(f));
}

const leftovers: string[] = [];
for (const file of files) {
  if (!file.endsWith('.cjs')) throw new Error(`not a .cjs file: ${file}`);
  const next = file.replace(/\.cjs$/, '.ts');
  const r = convert(file, fs.readFileSync(file, 'utf8'));
  leftovers.push(...r.leftovers);
  if (useGit) execFileSync('git', ['mv', file, next], { cwd: REPO });
  else fs.renameSync(file, next);
  fs.writeFileSync(next, r.text);
}

if (useGit) {
  const names = files.map((f) => path.basename(f, '.cjs'));
  const re = new RegExp(`\\b(${names.map((n) => n.replace(/[.-]/g, '\\$&')).join('|')})\\.cjs\\b`, 'g');
  for (const f of liveFiles()) {
    const text = fs.readFileSync(f, 'utf8');
    const next = text.replace(re, '$1.ts');
    if (next !== text) fs.writeFileSync(f, next);
  }
}

for (const l of leftovers) console.log(`leftover ${l}`);
console.log(`converted ${files.length} file(s), ${leftovers.length} leftover(s)`);
