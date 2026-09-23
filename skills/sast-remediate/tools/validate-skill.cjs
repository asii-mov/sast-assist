#!/usr/bin/env node
'use strict';
// Playbook step 2 as a script rather than an eyeball. Run: node tools/validate-skill.cjs
// Checks frontmatter, that every referenced file exists, that every schema ref resolves, that
// every tool parses, and the prose conventions this skill is written to.

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const ROOT = path.resolve(__dirname, '..');
let fail = 0;
const ok = (m) => console.log(`  ok   ${m}`);
const bad = (m) => { fail++; console.log(`  FAIL ${m}`); };

// ---- frontmatter
const skillPath = path.join(ROOT, 'SKILL.md');
const skill = fs.readFileSync(skillPath, 'utf8');
const fm = /^---\n([\s\S]*?)\n---\n/.exec(skill);
if (!fm) bad('SKILL.md has no frontmatter block');
else {
  const name = /^name:\s*(.+)$/m.exec(fm[1]);
  const desc = /^description:\s*(.+)$/m.exec(fm[1]);
  if (!name) bad('frontmatter missing name');
  else if (name[1].trim() !== path.basename(ROOT)) {
    bad(`frontmatter name "${name[1].trim()}" != directory "${path.basename(ROOT)}"`);
  } else ok(`frontmatter name matches directory (${name[1].trim()})`);
  if (!desc) bad('frontmatter missing description');
  else if (desc[1].trim().length < 40) bad('description is too short to trigger reliably');
  else ok(`description present (${desc[1].trim().length} chars)`);
}

// ---- referenced files exist
const mdFiles = [skillPath, ...fs.readdirSync(path.join(ROOT, 'references'))
  .map((f) => path.join(ROOT, 'references', f))];
let refCount = 0, refMissing = 0;
for (const f of mdFiles) {
  const text = fs.readFileSync(f, 'utf8');
  const cited = new Set();
  // Only paths with a known extension are OURS. `bin/rails` and `config.ru` in prose are
  // paths in the TARGET repo and must not be resolved against this skill.
  for (const m of text.matchAll(/`((?:references|schema|bin|test|tools)\/[A-Za-z0-9_.\-]+\.(?:cjs|ts|json|md))`/g)) cited.add(m[1]);
  for (const m of text.matchAll(/\]\(([^)]+\.md)\)/g)) cited.add(m[1]);
  for (const rel of cited) {
    refCount++;
    const target = rel.startsWith('references/') || rel.startsWith('schema/') ||
      rel.startsWith('bin/') || rel.startsWith('test/') || rel.startsWith('tools/')
      ? path.join(ROOT, rel) : path.join(path.dirname(f), rel);
    if (!fs.existsSync(target)) { refMissing++; bad(`${path.relative(ROOT, f)} cites missing ${rel}`); }
  }
}
if (!refMissing) ok(`all ${refCount} cited paths resolve`);

// ---- every reference file is reachable from SKILL.md
for (const f of fs.readdirSync(path.join(ROOT, 'references'))) {
  if (!skill.includes(`references/${f}`)) bad(`references/${f} is never cited by SKILL.md`);
}
ok('every reference file is cited by SKILL.md');

// ---- schemas parse and refs resolve
const { validate } = require(path.join(ROOT, 'bin/validate.cjs'));
const schemaDir = path.join(ROOT, 'schema');
for (const f of fs.readdirSync(schemaDir)) {
  const p = path.join(schemaDir, f);
  let doc;
  try { doc = JSON.parse(fs.readFileSync(p, 'utf8')); }
  catch (e) { bad(`${f} does not parse: ${e.message}`); continue; }
  const refs = [...JSON.stringify(doc).matchAll(/"\$ref":"([^"]+)"/g)].map((m) => m[1]);
  let broke = false;
  for (const r of refs) {
    try {
      // Exercise the real resolver by validating a value that must reach the ref.
      validate({ $ref: r, ...(doc.$defs ? { $defs: doc.$defs } : {}) }, null, schemaDir);
    } catch (e) { broke = true; bad(`${f}: ref ${r} does not resolve (${e.message})`); }
  }
  if (!broke) ok(`${f} parses, ${refs.length} refs resolve`);
}

// ---- tools parse
for (const dir of ['bin', 'tools', 'test']) {
  for (const f of fs.readdirSync(path.join(ROOT, dir)).filter((x) => /\.(cjs|ts)$/.test(x))) {
    const p = path.join(ROOT, dir, f);
    try { execFileSync(process.execPath, ['--check', p], { stdio: 'pipe' }); ok(`${dir}/${f} parses`); }
    catch (e) { bad(`${dir}/${f} syntax error`); }
  }
}

// ---- every camelCase identifier the prose calls canonical must exist in bin/
// This skill's recurring defect is prose naming a function that was never written. stageOf and
// evaluateVerification were both cited as "the sole definition" while existing nowhere. A
// reader cannot tell the difference between a canonical helper and an aspiration, so the check
// is mechanical: an internal capital is what separates a function name from a domain value like
// `medium` or `dynamic`.
const EXTERNAL_IDENTS = new Set([
  'partialFingerprints', // a SARIF field on the scanner's side of the boundary, not ours
]);
const defined = new Set();
for (const f of fs.readdirSync(path.join(ROOT, 'bin')).filter((x) => /\.(cjs|ts)$/.test(x))) {
  const text = fs.readFileSync(path.join(ROOT, 'bin', f), 'utf8');
  for (const m of text.matchAll(/(?:function\s+|const\s+|let\s+)([A-Za-z_$][\w$]*)\s*(?::[^=;]+)?[=(<]/g)) {
    defined.add(m[1]);
  }
}
let phantom = 0, checked = 0;
for (const f of mdFiles) {
  const text = fs.readFileSync(f, 'utf8');
  for (const m of text.matchAll(/`([a-z][a-z0-9]*[A-Z][A-Za-z0-9]*)(?:\(\))?`/g)) {
    const name = m[1];
    if (EXTERNAL_IDENTS.has(name)) continue;
    checked++;
    if (!defined.has(name)) {
      phantom++;
      bad(`${path.relative(ROOT, f)} names \`${name}\`, which is defined nowhere in bin/. `
        + 'Implement it, or stop writing it as if it exists.');
    }
  }
}
if (!phantom) ok(`all ${checked} identifiers cited in prose exist in bin/`);

// Prose conventions live in tools/check-prose.cjs at the repository root, which covers every
// markdown file rather than only this skill. An earlier copy of the em dash rule lived here
// and therefore never looked at design/, where 162 violations had accumulated unwatched.

console.log(fail === 0 ? '\nskill tree valid' : `\n${fail} problem(s)`);
process.exit(fail === 0 ? 0 : 1);
