#!/usr/bin/env node
'use strict';
// Run: node test/partition.test.cjs
// FIX-AND-VERIFY.md: findings conflict when a site of each shares a file and their lines fall
// within twenty of each other; connected findings must land in different waves. This is the
// first code that checks the partitioner actually enforces that, rather than a comment saying
// the parent will.

const path = require('path');
const assert = require('assert');

const ROOT = path.resolve(__dirname, '..');
const { partition, conflicts } = require(path.join(ROOT, 'bin/partition.cjs'));

let pass = 0, fail = 0;
const t = (name, fn) => {
  try { fn(); pass++; console.log(`  ok   ${name}`); }
  catch (e) { fail++; console.log(`  FAIL ${name}\n         ${e.message}`); }
};
const section = (s) => console.log(`\n${s}`);

// Minimal finding: just enough shape for conflicts() (sites[].locus) and for gate.order(),
// which partition() sorts by before colouring (invariant_class, flow.kind, sites[].observations,
// sites[].locus.file, id). Every finding below shares invariant_class/flow/observation so
// priority() ties and order() falls back to id, making wave assignment order legible.
const site = (file, line) => ({
  locus: { file, symbol: null, sink_digest: 'x'.repeat(64), line_at_scan: line },
  observations: [{
    scanner: 'semgrep',
    rule_id: 'r', rule_name: null, native_fingerprint: null, message: 'm',
    claimed: { kind: 'semgrep', severity: 'WARNING', impact: null, likelihood: null, confidence: null },
    cwe: [], owasp: [], engine: null, suppressed_at_source: false, raw_pointer: '', seen_in_rounds: [1],
  }],
});
const mk = (id, sites) => ({
  id, invariant_class: 'other', flow: { kind: 'sink_only', sink: site('x', 1).locus, reason: 'scanner_emitted_no_flow' },
  sites,
});
const finding = (id, file, line) => mk(id, [site(file, line)]);

const byId = (waves, id) => waves.findIndex((w) => w.includes(id));

section('conflicts: file and proximity');

t('same file, far apart (500 lines) does not conflict', () => {
  const a = finding('f_a', 'src/app.js', 10);
  const b = finding('f_b', 'src/app.js', 510);
  assert.strictEqual(conflicts(a, b), false);
});

t('19 lines apart conflicts', () => {
  const a = finding('f_a', 'src/app.js', 0);
  const b = finding('f_b', 'src/app.js', 19);
  assert.strictEqual(conflicts(a, b), true);
});

t('21 lines apart does not conflict', () => {
  const a = finding('f_a', 'src/app.js', 0);
  const b = finding('f_b', 'src/app.js', 21);
  assert.strictEqual(conflicts(a, b), false);
});

t('exactly 20 lines apart conflicts (boundary is inclusive)', () => {
  const a = finding('f_a', 'src/app.js', 0);
  const b = finding('f_b', 'src/app.js', 20);
  assert.strictEqual(conflicts(a, b), true);
});

t('same line in different files does not conflict', () => {
  const a = finding('f_a', 'src/app.js', 10);
  const b = finding('f_b', 'src/other.js', 10);
  assert.strictEqual(conflicts(a, b), false);
});

t('conflicts is symmetric', () => {
  const a = finding('f_a', 'src/app.js', 5);
  const b = finding('f_b', 'src/app.js', 12);
  assert.strictEqual(conflicts(a, b), conflicts(b, a));
});

section('conflicts: multi-site findings');

t('conflict via a second site, not the first', () => {
  const a = mk('f_a', [site('src/one.js', 5), site('src/shared.js', 100)]);
  const b = finding('f_b', 'src/shared.js', 105);
  assert.strictEqual(conflicts(a, b), true, 'shared.js sites are 5 lines apart');
});

t('no shared file across any site pair means no conflict', () => {
  const a = mk('f_a', [site('src/one.js', 5), site('src/two.js', 100)]);
  const b = finding('f_b', 'src/three.js', 100);
  assert.strictEqual(conflicts(a, b), false);
});

section('partition: waves');

t('no conflicts collapse to one wave, not one finding per wave', () => {
  const findings = [
    finding('f_a', 'src/a.js', 10),
    finding('f_b', 'src/b.js', 10),
    finding('f_c', 'src/c.js', 10),
  ];
  const waves = partition(findings);
  assert.strictEqual(waves.length, 1);
  assert.deepStrictEqual(waves[0].slice().sort(), ['f_a', 'f_b', 'f_c']);
});

t('a chain (A-B-C, A and C not connected) colours in 2 waves, A and C sharing one', () => {
  // A path graph is bipartite: chromatic number 2. First-fit greedy over id order (A,B,C)
  // must reuse A's wave for C, since A and C do not conflict.
  const findings = [
    finding('f_a', 'src/app.js', 0),
    finding('f_b', 'src/app.js', 15),
    finding('f_c', 'src/app.js', 30),
  ];
  const waves = partition(findings);
  assert.strictEqual(waves.length, 2, `expected 2 waves, got ${waves.length}`);
  assert.strictEqual(byId(waves, 'f_a'), byId(waves, 'f_c'), 'A and C do not conflict, must share a wave');
  assert.notStrictEqual(byId(waves, 'f_a'), byId(waves, 'f_b'), 'A and B conflict, must differ');
  assert.notStrictEqual(byId(waves, 'f_b'), byId(waves, 'f_c'), 'B and C conflict, must differ');
});

t('a clique of 3 needs 3 waves', () => {
  const findings = [
    finding('f_a', 'src/app.js', 0),
    finding('f_b', 'src/app.js', 10),
    finding('f_c', 'src/app.js', 20),
  ];
  const waves = partition(findings);
  assert.strictEqual(waves.length, 3, `expected 3 waves for a mutual conflict, got ${waves.length}`);
  for (const w of waves) assert.strictEqual(w.length, 1, 'a clique wave holds exactly one finding');
});

t('every wave is internally conflict-free', () => {
  const findings = [
    finding('f_a', 'src/app.js', 0),
    finding('f_b', 'src/app.js', 15),
    finding('f_c', 'src/app.js', 30),
    finding('f_d', 'src/other.js', 1000),
  ];
  const byIdMap = new Map(findings.map((f) => [f.id, f]));
  for (const wave of partition(findings)) {
    for (let i = 0; i < wave.length; i++) {
      for (let j = i + 1; j < wave.length; j++) {
        assert.strictEqual(conflicts(byIdMap.get(wave[i]), byIdMap.get(wave[j])), false,
          `${wave[i]} and ${wave[j]} landed in the same wave but conflict`);
      }
    }
  }
});

t('every finding appears exactly once across all waves', () => {
  const findings = [
    finding('f_a', 'src/app.js', 0),
    finding('f_b', 'src/app.js', 15),
    finding('f_c', 'src/app.js', 30),
    finding('f_d', 'src/other.js', 1000),
  ];
  const waves = partition(findings);
  const flat = waves.flat();
  assert.strictEqual(flat.length, findings.length);
  assert.deepStrictEqual(flat.slice().sort(), findings.map((f) => f.id).sort());
});

section('partition: determinism');

t('repeated calls on the same input agree', () => {
  const findings = [
    finding('f_a', 'src/app.js', 0),
    finding('f_b', 'src/app.js', 12),
    finding('f_c', 'src/app.js', 40),
    finding('f_d', 'src/app.js', 45),
    finding('f_e', 'src/other.js', 1),
  ];
  const first = partition(findings);
  const second = partition(findings);
  assert.deepStrictEqual(first, second);
});

t('input order does not change the outcome', () => {
  const findings = [
    finding('f_a', 'src/app.js', 0),
    finding('f_b', 'src/app.js', 12),
    finding('f_c', 'src/app.js', 40),
    finding('f_d', 'src/app.js', 45),
    finding('f_e', 'src/other.js', 1),
  ];
  const forward = partition(findings);
  const reversed = partition(findings.slice().reverse());
  assert.deepStrictEqual(forward, reversed);
});

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
