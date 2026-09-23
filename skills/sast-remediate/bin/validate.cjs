#!/usr/bin/env node
'use strict';
// JSON Schema subset validator. Zero dependencies, nothing installed into the target repo.
// Supports the keywords our schemas use and refuses anything it does not understand, so an
// unsupported keyword fails loudly instead of silently passing.

const SUPPORTED = new Set([
  '$schema', '$id', '$ref', '$defs', 'title', 'description', 'type', 'const', 'enum',
  'required', 'properties', 'additionalProperties', 'items', 'minItems', 'maxItems',
  'minLength', 'minimum', 'maximum', 'pattern', 'oneOf', 'not',
]);

const LIMITS = { bytes: 5 * 1024 * 1024, depth: 64, errors: 100 };

function typeOf(v) {
  if (v === null) return 'null';
  if (Array.isArray(v)) return 'array';
  if (Number.isInteger(v)) return 'integer';
  return typeof v;
}

function typeMatches(want, v) {
  const t = typeOf(v);
  if (want === 'number') return t === 'number' || t === 'integer';
  return want === t;
}

// Cross-file refs keep one definition per invariant. The agent envelopes reference the
// contract and witness shapes in finding.schema.json rather than restating them, so there is
// no second copy to drift.
const FILE_CACHE = new Map();

function loadSchemaFile(file, baseDir) {
  const abs = require('path').resolve(baseDir, file);
  if (!FILE_CACHE.has(abs)) {
    FILE_CACHE.set(abs, JSON.parse(require('fs').readFileSync(abs, 'utf8')));
  }
  return FILE_CACHE.get(abs);
}

function resolve(ref, root) {
  let doc = root;
  let pointer = ref;
  const hash = ref.indexOf('#');
  if (hash > 0) {
    const file = ref.slice(0, hash);
    pointer = ref.slice(hash);
    doc = loadSchemaFile(file, root.__baseDir || '.');
    doc.__baseDir = root.__baseDir || '.';
  } else if (!ref.startsWith('#/')) {
    throw new Error(`unsupported ref: ${ref}`);
  }
  let node = doc;
  for (const part of pointer.slice(2).split('/')) {
    node = node[part.replace(/~1/g, '/').replace(/~0/g, '~')];
    if (node === undefined) throw new Error(`unresolvable ref: ${ref}`);
  }
  // A cross-file ref must resolve further refs against ITS document, not the caller's.
  return doc === root ? node : { ...node, __doc: doc };
}

// The `not: {pattern}` case we use is a *negative* string match. Anything else is rejected.
function check(schema, data, root, path, errs, depth) {
  if (errs.length >= LIMITS.errors) return;
  if (depth > LIMITS.depth) { errs.push(`${path}: exceeds max nesting depth`); return; }

  for (const k of Object.keys(schema)) {
    if (k === '__baseDir' || k === '__doc') continue;
    if (!SUPPORTED.has(k)) { errs.push(`${path}: schema uses unsupported keyword "${k}"`); return; }
  }

  if (schema.$ref) {
    const target = resolve(schema.$ref, root);
    const nextRoot = target.__doc || root;
    const clean = { ...target };
    delete clean.__doc;
    return check(clean, data, nextRoot, path, errs, depth + 1);
  }

  if (schema.type !== undefined) {
    const want = Array.isArray(schema.type) ? schema.type : [schema.type];
    if (!want.some((w) => typeMatches(w, data))) {
      errs.push(`${path}: expected ${want.join('|')}, got ${typeOf(data)}`);
      return;
    }
  }

  if (schema.const !== undefined && JSON.stringify(data) !== JSON.stringify(schema.const)) {
    errs.push(`${path}: expected const ${JSON.stringify(schema.const)}, got ${JSON.stringify(data)}`);
  }

  if (schema.enum && !schema.enum.some((e) => JSON.stringify(e) === JSON.stringify(data))) {
    errs.push(`${path}: ${JSON.stringify(data)} not in enum`);
  }

  if (schema.pattern !== undefined && typeof data === 'string') {
    const m = /^\(\?i\)(.*)$/s.exec(schema.pattern);
    const re = m ? new RegExp(m[1], 'i') : new RegExp(schema.pattern);
    if (!re.test(data)) errs.push(`${path}: does not match /${schema.pattern}/`);
  }

  if (schema.not) {
    const sub = [];
    check(schema.not, data, root, path, sub, depth + 1);
    if (sub.length === 0) {
      const why = schema.not.pattern ? ` (matched forbidden /${schema.not.pattern}/)` : '';
      errs.push(`${path}: value is forbidden here${why}`);
    }
  }

  if (schema.minLength !== undefined && typeof data === 'string' && data.length < schema.minLength) {
    errs.push(`${path}: shorter than minLength ${schema.minLength}`);
  }
  if (schema.minimum !== undefined && typeof data === 'number' && data < schema.minimum) {
    errs.push(`${path}: below minimum ${schema.minimum}`);
  }
  if (schema.maximum !== undefined && typeof data === 'number' && data > schema.maximum) {
    errs.push(`${path}: above maximum ${schema.maximum}`);
  }

  if (typeOf(data) === 'array') {
    if (schema.minItems !== undefined && data.length < schema.minItems) {
      errs.push(`${path}: needs at least ${schema.minItems} items, has ${data.length}`);
    }
    if (schema.maxItems !== undefined && data.length > schema.maxItems) {
      errs.push(`${path}: allows at most ${schema.maxItems} items, has ${data.length}`);
    }
    if (schema.items) {
      data.forEach((v, i) => check(schema.items, v, root, `${path}[${i}]`, errs, depth + 1));
    }
  }

  if (typeOf(data) === 'object') {
    for (const r of schema.required || []) {
      if (!(r in data)) errs.push(`${path}: missing required property "${r}"`);
    }
    if (schema.properties) {
      for (const [k, sub] of Object.entries(schema.properties)) {
        if (k in data) check(sub, data[k], root, `${path}.${k}`, errs, depth + 1);
      }
    }
    if (schema.additionalProperties === false && schema.properties) {
      for (const k of Object.keys(data)) {
        if (!(k in schema.properties)) errs.push(`${path}: unexpected property "${k}"`);
      }
    }
  }

  if (schema.oneOf) {
    const branchErrs = schema.oneOf.map((b) => {
      const sub = [];
      check(b, data, root, path, sub, depth + 1);
      return sub;
    });
    const passing = branchErrs.filter((e) => e.length === 0).length;
    if (passing !== 1) {
      const disc = typeOf(data) === 'object'
        ? (data.kind ?? data.verdict ?? data.tier ?? data.scanner ?? '')
        : '';
      const hint = disc ? ` (discriminator "${disc}")` : '';
      if (passing === 0) {
        // Report the branch that got closest, not all of them. All-branch dumps are unreadable.
        const best = branchErrs.reduce((a, b) => (b.length < a.length ? b : a));
        errs.push(`${path}: matched no oneOf branch${hint}; closest: ${best.join('; ')}`);
      } else {
        errs.push(`${path}: ambiguously matched ${passing} oneOf branches${hint}`);
      }
    }
  }
}

function validate(schema, data, baseDir) {
  const errs = [];
  const root = baseDir ? { ...schema, __baseDir: baseDir } : schema;
  check(root, data, root, '$', errs, 0);
  return errs;
}

function main(argv) {
  const [schemaPath, dataPath] = argv;
  if (!schemaPath || !dataPath) {
    console.error('usage: validate.cjs <schema.json> <data.json>');
    return 2;
  }
  const fs = require('fs');
  for (const p of [schemaPath, dataPath]) {
    if (fs.statSync(p).size > LIMITS.bytes) {
      console.error(`${p}: exceeds ${LIMITS.bytes} byte limit`);
      return 2;
    }
  }
  const schema = JSON.parse(fs.readFileSync(schemaPath, 'utf8'));
  const data = JSON.parse(fs.readFileSync(dataPath, 'utf8'));
  const errs = validate(schema, data, require('path').dirname(schemaPath));
  if (errs.length === 0) {
    console.log(`ok: ${dataPath} validates against ${schemaPath}`);
    return 0;
  }
  for (const e of errs.slice(0, LIMITS.errors)) console.error(`  ${e}`);
  console.error(`${errs.length} validation error(s)`);
  return 1;
}

module.exports = { validate };
if (require.main === module) process.exit(main(process.argv.slice(2)));
