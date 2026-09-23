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

// `level` is the run's --verify level. A patch is judged against the obligations that level
// requires, so a fix that passed every check the run asked for is not sent back for a second try.
function stageOf(finding, level) {
  if (!Object.hasOwn(VERIFY_LEVELS, level)) throw new Error(`unknown verify level: ${level}`);
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
      const tier = finding.triage.contract?.witness?.tier ?? null;
      if (evaluateVerification(last.verification, VERIFY_LEVELS[level], tier).verified) return 'report';
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

// A red suite on base is not the patch's fault, and a rescan whose scanners produced nothing
// says nothing about the patch, so these two may be unavailable without sinking the verdict.
// Every other obligation must actually pass, except the argued-tier pair below.
const MAY_BE_UNAVAILABLE = new Set(['regression_suite', 'no_new_findings']);

// An argued witness sends no attack and has no control, so the pair is recorded unavailable
// with the obstacle and excused, and the disposition is `fixed_unwitnessed` so a human still
// reviews it.
const EXCUSED_AT_ARGUED = new Set(['differential_witness', 'functional_control']);
const excused = (name, tier) => MAY_BE_UNAVAILABLE.has(name) || (tier === 'argued' && EXCUSED_AT_ARGUED.has(name));

// `required` narrows which obligations must hold. The orchestrator passes a smaller set when
// the operator lowers --verify, because the witness pair needs a bootable target and the
// auditor costs an agent call. An obligation outside `required` is not evaluated at all: it
// cannot pass, fail or rescue anything, and it is reported as skipped so the report can say so.
// `tier` is the frozen contract's witness tier, used only to excuse the argued pair above; it
// never comes from the verification record itself, so a patch cannot excuse itself.
function evaluateVerification(verification, required = OBLIGATIONS, tier = null) {
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
    if (status === 'unavailable' && excused(name, tier)) { unavailable.push(name); continue; }
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
  stageOf, evaluateVerification, STAGES, OBLIGATIONS, MAY_BE_UNAVAILABLE, VERIFY_LEVELS, excused,
};

if (require.main === module) {
  const fs = require('fs');
  const [file, level] = process.argv.slice(2);
  if (!file || !Object.hasOwn(VERIFY_LEVELS, level)) {
    console.error(`usage: stage.cjs <findings.json> <${Object.keys(VERIFY_LEVELS).join('|')}>`);
    process.exit(2);
  }
  const counts = new Map(STAGES.map((s) => [s, 0]));
  for (const f of JSON.parse(fs.readFileSync(file, 'utf8'))) {
    const s = stageOf(f, level);
    counts.set(s, counts.get(s) + 1);
    console.log(`${s.padEnd(8)} ${f.id}`);
  }
  console.log('\n' + STAGES.map((s) => `${s}=${counts.get(s)}`).join('  '));
}
