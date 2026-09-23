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

// A target still waiting its turn keeps its .cjs name until its own conversion rewrites it.
function spec(fromFile: string, target: string): string {
  const converted = !fs.existsSync(target) || files.includes(target);
  const rel = path.relative(path.dirname(fromFile), converted ? target.replace(/\.cjs$/, '.ts') : target);
  return rel.startsWith('.') ? rel : `./${rel}`;
}

function convert(file: string, text: string): { text: string; leftovers: string[] } {
  const out: string[] = [];
  const leftovers: string[] = [];
  let inTemplate = false;
  const templateLines = new Set<number>();
  const lines = text.replace(/^'use strict';\n/m, '').split('\n');
  for (const [i, line] of lines.entries()) {
    const wasInTemplate = inTemplate;
    inTemplate = endsInTemplate(line, inTemplate);
    if (wasInTemplate) {
      templateLines.add(i);
      if (/\brequire\b|\bmodule\.exports\b|__dirname/.test(line)) {
        console.log(`skipped as template text ${path.relative(REPO, file)}:${i + 1}: ${line.trim()}`);
      }
      out.push(line);
      continue;
    }
    let l = line;
    let m: RegExpExecArray | null;
    if ((m = /^const (\w+) = require\('([^./][^']*)'\);$/.exec(l))) {
      l = `import ${m[1]} from '${m[2]}';`;
    } else if ((m = /^const (\{[^}]+\}) = require\('([^./][^']*)'\);$/.exec(l))) {
      l = `import ${m[1]} from '${m[2]}';`;
    } else if ((m = /^const (\{[^}]+\}|\w+) = require\('(\.[^']+\.(?:cjs|ts))'\);$/.exec(l))) {
      l = importLine(m[1], spec(file, path.resolve(path.dirname(file), m[2])));
    } else if ((m = /^const (\{[^}]+\}|\w+) = require\(path\.join\(ROOT, '([^']+\.(?:cjs|ts))'\)\);$/.exec(l))) {
      l = importLine(m[1], spec(file, path.join(SKILL, m[2])));
    }
    l = l.replace(/^if \(require\.main === module\)/, 'if (import.meta.main)');
    l = l.replace(/\b__dirname\b/g, 'import.meta.dirname');
    const nestedBuiltin = /^\s+const (\w+|\{[^}]+\}) = require\('[^./][^']*'\);$/.test(l);
    if (/\brequire\(|\bmodule\.exports\b|\b__filename\b/.test(l) && !/^module\.exports = /.test(l) && !nestedBuiltin) {
      leftovers.push(`${path.relative(REPO, file)}:${i + 1}: ${l.trim()}`);
    }
    out.push(l);
  }
  let result = out.join('\n');
  result = result.replace(/^module\.exports = \{([\s\S]*?)\};$/gm, (whole, body: string, offset: number) => {
    if (templateLines.has(result.slice(0, offset).split('\n').length - 1)) return whole;
    if (/:/.test(body.replace(/\/\/.*$/gm, ''))) {
      leftovers.push(`${path.relative(REPO, file)}: module.exports has non-shorthand keys`);
      return whole;
    }
    return `export {${body}};`;
  });
  // The export rewrite keeps the line count, so the template line numbers still hold here.
  const hoisted = result.split('\n');
  hoistNested(hoisted, templateLines);
  return { text: hoisted.join('\n'), leftovers };
}

// Whether a template literal is still open at the end of `line`. Quotes, comments and regex
// literals are stepped over so a backtick inside them does not count. A `/` opens a regex when
// the previous significant character could not end an expression.
function endsInTemplate(line: string, open: boolean): boolean {
  let state: 'code' | 'template' | "'" | '"' | 'regex' | 'class' = open ? 'template' : 'code';
  let prev = '';
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (state === 'template') {
      if (c === '\\') i++;
      else if (c === '`') { state = 'code'; prev = '`'; }
      continue;
    }
    if (state === "'" || state === '"') {
      if (c === '\\') i++;
      else if (c === state) { state = 'code'; prev = c; }
      continue;
    }
    if (state === 'regex' || state === 'class') {
      if (c === '\\') i++;
      else if (state === 'regex' && c === '[') state = 'class';
      else if (state === 'class' && c === ']') state = 'regex';
      else if (state === 'regex' && c === '/') { state = 'code'; prev = '/'; }
      continue;
    }
    if (c === '/' && line[i + 1] === '/') break;
    if (c === '`') state = 'template';
    else if (c === "'" || c === '"') state = c;
    else if (c === '/' && !/[\w$)\]]/.test(prev)) state = 'regex';
    if (!/\s/.test(c)) prev = c;
  }
  return state === 'template';
}

// A builtin required inside a block (usually the CLI entry) becomes a top-level import.
// Imports that landed below the top of the file move up with it, since ESM hoists them anyway.
function hoistNested(lines: string[], templateLines: Set<number>): void {
  const hoisted: string[] = [];
  let seenCode = false;
  const drop = new Set<number>();
  lines.forEach((l, i) => {
    if (templateLines.has(i)) { seenCode = true; return; }
    const m = /^\s+const (\w+|\{[^}]+\}) = require\('([^./][^']*)'\);$/.exec(l);
    const line = m ? `import ${m[1]} from '${m[2]}';` : (seenCode && /^import /.test(l) ? l : null);
    if (!/^(#!|\/\/|import |\s*$)/.test(l)) seenCode = true;
    if (!line) return;
    drop.add(i);
    if (!lines.some((x, j) => x === line && !drop.has(j) && j !== i) && !hoisted.includes(line)) hoisted.push(line);
  });
  for (const i of [...drop].sort((a, b) => b - a)) lines.splice(i, 1);
  if (!hoisted.length) return;
  let at = 0;
  while (at < lines.length && /^(#!|\/\/)/.test(lines[at])) at++;
  let lastImport = -1;
  for (let j = at; j < lines.length && /^(import |\s*$)/.test(lines[j]); j++) {
    if (lines[j].startsWith('import ')) lastImport = j;
  }
  if (lastImport >= 0) lines.splice(lastImport + 1, 0, ...hoisted);
  else lines.splice(at, 0, '', ...hoisted);
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
