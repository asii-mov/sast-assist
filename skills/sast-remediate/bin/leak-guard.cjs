#!/usr/bin/env node
'use strict';
// This module is the mechanical half of the rule that the fixer is never shown the rule. It
// separates what the triage agent wrote from what the repository contains.

const { SCANNERS } = require('./scan.cjs');

// Prose cannot enforce the rule above, so this does. It is derived from the record rather than
// from a fixed word list, because the rule ids this skill has never seen are the ones that matter.
const RULE_ID_FORM =
  /(?<![\w./@-])(?:js|javascript|ts|typescript|py|python|java|cpp|cs|go|rb|ruby|swift|rust|ql|actions)\/[a-z0-9]+(?:-[a-z0-9]+)+(?![@\w-]|\.[a-z]{1,4}\b)/i;

const observations = (finding) => finding.sites.flatMap((s) => s.observations);
const usable = (terms) => [...new Set(terms)].filter((t) => t && t.length >= 4);

// Checked against the whole prompt, repository source included: only this finding's own
// rule ids, fingerprints and messages, which ordinary code does not contain.
const recordTerms = (finding) => usable(observations(finding)
  .flatMap((o) => [o.rule_id, o.native_fingerprint, o.message && o.message.trim()]));

// Checked against triage-authored prose only. A workflow that runs the scanner, or a docs
// folder named after it, is repository content and tells the fixer nothing about the rule.
const proseTerms = (finding) => usable([...SCANNERS,
  ...observations(finding).flatMap((o) => [o.scanner, o.rule_name])]);

function authoredProse(contract) {
  if (!contract) return [];
  const w = contract.witness || {};
  return [contract.invariant, contract.violating_input,
    contract.enforcement_point && contract.enforcement_point.rationale,
    ...(contract.forbidden_resolutions || []),
    w.attack_input, w.asserts, w.obstacle, w.why].filter((s) => typeof s === 'string' && s);
}

function assertNoLeak(prompt, finding) {
  const found = (hay, terms) => terms.find((t) => hay.includes(t.toLowerCase()));
  const hit = found(prompt.toLowerCase(), recordTerms(finding));
  if (hit) throw new Error(`fixer prompt leaked scanner material: ${JSON.stringify(hit.slice(0, 120))}`);
  const prose = authoredProse(finding.triage && finding.triage.contract).join('\n');
  const named = found(prose.toLowerCase(), proseTerms(finding));
  if (named) throw new Error(`fixer prompt leaked scanner material: ${JSON.stringify(named.slice(0, 120))}`);
  const form = RULE_ID_FORM.exec(prose);
  if (form) throw new Error(`fixer prompt carries a rule id: ${JSON.stringify(form[0])}`);
}

const leakError = (prompt, finding) => {
  try { assertNoLeak(prompt, finding); return null; } catch (e) { return e.message; }
};

module.exports = { RULE_ID_FORM, recordTerms, proseTerms, authoredProse, assertNoLeak, leakError };
