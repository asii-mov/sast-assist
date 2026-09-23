#!/usr/bin/env node
'use strict';
// FIX-AND-VERIFY.md: findings are partitioned into conflict-free waves before anyone is
// spawned, because it is never an agent's job to notice it is about to collide with another
// agent's edit. That rule shipped with no code behind it; this file is the code.

const { order } = require('./gate.cjs');

const PROXIMITY = 20;

// Two findings conflict when some site of each shares a file and their lines fall within
// twenty of each other. A finding may have several sites across several files, so every pair
// of sites is checked rather than just the first.
function conflicts(a, b) {
  for (const sa of a.sites) {
    for (const sb of b.sites) {
      if (sa.locus.file === sb.locus.file &&
          Math.abs(sa.locus.line_at_scan - sb.locus.line_at_scan) <= PROXIMITY) {
        return true;
      }
    }
  }
  return false;
}

// Greedy first-fit colouring over order(), not the input array, so the waves come out the
// same regardless of what order the caller happened to build findings in. A wave is a colour:
// a finding joins the first wave holding nothing it conflicts with, else starts a new one.
function partition(findings) {
  const waves = [];
  for (const f of order(findings)) {
    const wave = waves.find((w) => !w.some((g) => conflicts(f, g)));
    if (wave) wave.push(f);
    else waves.push([f]);
  }
  return waves.map((w) => w.map((f) => f.id));
}

module.exports = { partition, conflicts };

if (require.main === module) {
  const fs = require('fs');
  const [file] = process.argv.slice(2);
  if (!file) { console.error('usage: partition.cjs <findings.json>'); process.exit(2); }
  const findings = JSON.parse(fs.readFileSync(file, 'utf8'));
  const waves = partition(findings);
  waves.forEach((ids, i) => console.log(`wave ${i}: ${ids.join(', ')}`));
  console.log(`\n${findings.length} finding(s) in ${waves.length} wave(s)`);
}
