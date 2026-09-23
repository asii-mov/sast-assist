#!/usr/bin/env node
'use strict';
// The lifecycle of a finding record. Two pure functions, no LLM, no I/O.
//
// SKILL.md calls stageOf and evaluateVerification the sole definitions of "where is this
// record" and "is this fix verified". They live here so there is exactly one of each. A
// pipeline whose stage is re-derived by the parent, then again by a prompt, then again by a
// report writer has three answers to one question, which is the failure this skill exists to
// prevent.

// ---------------------------------------------------------------------- stage

// Stage is a function of the record's shape, never a stored field. There is no `status` to
// fall out of sync and no --resume flag: re-running the command IS the resume path, because
// every stage re-derives itself from what is already on disk.
const STAGES = ['triage', 'gate', 'fix', 'verify', 'report', 'done'];

function stageOf(finding) {
  if (finding.disposition !== null && finding.disposition !== undefined) return 'done';
  if (!finding.triage) return 'triage';
  if (!finding.gate) return 'gate';

  switch (finding.gate.action) {
    case 'report_only':
      return 'report';
    case 'fix': {
      const patches = finding.patches || [];
      if (patches.length === 0) return 'fix';
      const last = patches[patches.length - 1];
      if (!last.verification) return 'verify';
      if (evaluateVerification(last.verification).verified) return 'report';
      // The cap is in the type: schema/finding.schema.json bounds patches at two.
      return patches.length >= 2 ? 'report' : 'fix';
    }
    default:
      throw new Error(`unknown gate action: ${finding.gate.action}`);
  }
}

// ---------------------------------------------------------------- verification

// The seven obligations, in the order FIX-AND-VERIFY.md runs them. This table is the reason
// the function cannot read `rescan.original_absent`: evaluation indexes these keys and
// nothing else, so "the scanner went quiet" is structurally unreachable from the verdict
// rather than merely forbidden by a comment someone has to obey.
const OBLIGATIONS = [
  'frozen_target',
  'deterministic_guard',
  'differential_witness',
  'functional_control',
  'regression_suite',
  'no_new_findings',
  'hostile_auditor',
];

// A red suite on base is not the patch's fault, so regression_suite alone may be unavailable
// without sinking the verdict. Every other obligation must actually pass.
const MAY_BE_UNAVAILABLE = new Set(['regression_suite']);

// `required` narrows which obligations must hold. The orchestrator passes a smaller set when
// the operator lowers --verify, because the witness pair needs a bootable target and the
// auditor costs an agent call. An obligation outside `required` is not evaluated at all: it
// cannot pass, fail or rescue anything, and it is reported as skipped so the report can say so.
function evaluateVerification(verification, required = OBLIGATIONS) {
  const req = new Set(required);
  const failed = [];
  const unavailable = [];
  const missing = [];
  const skipped = [];

  for (const name of OBLIGATIONS) {
    if (!req.has(name)) { skipped.push(name); continue; }
    const status = verification && verification[name] && verification[name].status;
    if (status === undefined) { missing.push(name); continue; }
    if (status === 'pass') continue;
    if (status === 'unavailable' && MAY_BE_UNAVAILABLE.has(name)) { unavailable.push(name); continue; }
    failed.push(name);
  }

  return {
    verified: failed.length === 0 && missing.length === 0,
    failed,
    unavailable,
    missing,
    skipped,
  };
}

// The levels the orchestrator exposes. `full` is every obligation. `cheap` drops the witness
// pair, which needs a bootable target, and the auditor, which costs an agent call. `none`
// records the patch without judging it and is only honest because the report says which level
// ran. A fix verified at `cheap` is never reported as verified at `full`.
const VERIFY_LEVELS = {
  none: [],
  cheap: ['frozen_target', 'deterministic_guard', 'regression_suite', 'no_new_findings'],
  full: OBLIGATIONS,
};

module.exports = {
  stageOf, evaluateVerification, STAGES, OBLIGATIONS, MAY_BE_UNAVAILABLE, VERIFY_LEVELS,
};

if (require.main === module) {
  const fs = require('fs');
  const [file] = process.argv.slice(2);
  if (!file) { console.error('usage: stage.cjs <findings.json>'); process.exit(2); }
  const counts = new Map(STAGES.map((s) => [s, 0]));
  for (const f of JSON.parse(fs.readFileSync(file, 'utf8'))) {
    const s = stageOf(f);
    counts.set(s, counts.get(s) + 1);
    console.log(`${s.padEnd(8)} ${f.id}`);
  }
  console.log('\n' + STAGES.map((s) => `${s}=${counts.get(s)}`).join('  '));
}
