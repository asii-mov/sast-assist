#!/usr/bin/env node
// The ONLY place the threshold is interpreted. Pure, total, no LLM, thirty lines of policy.
//
// gate() takes a Triage and a Policy. It takes NOTHING ELSE, and that is the whole point:
// a Triage carries no scanner claim and there is no ceiling parameter, so rule-category
// severity cannot reach the fix decision even by accident. Two of the four arena candidates
// clamped instance severity to a scanner-derived ceiling and called it a spend optimization.
// It is not. It lets the scanner's guess cap what the fix decision can see.

import fs from 'fs';
import type { ClaimedSeverity, Finding, GateDecision, InvariantClass, Severity } from '../schema/types.ts';
import type { FindingRecord } from './stage.ts';

const RANK: Record<Severity, number> = { informational: 0, low: 1, medium: 2, high: 3, critical: 4 };
const rank = (s: string): number => (RANK as Record<string, number>)[s] ?? -1;
const isSeverity = (s: string): s is Severity => Object.hasOwn(RANK, s);

type Policy = { fix_at: Severity };

// Only the verdict, and an exploitable triage's severity, decide the gate.
type GateInput = { verdict: 'exploitable'; severity: Severity } | { verdict: 'not_exploitable' | 'undecidable' };

function gate(triage: GateInput, policy: Policy): GateDecision {
  switch (triage.verdict) {
    case 'not_exploitable':
      return { action: 'report_only', reason: 'not_exploitable' };
    case 'undecidable':
      return { action: 'report_only', reason: 'undecidable' };
    case 'exploitable':
      return rank(triage.severity) >= rank(policy.fix_at)
        ? { action: 'fix', threshold: policy.fix_at, reason: 'at_or_above_threshold' }
        : { action: 'report_only', reason: 'below_threshold' };
    default: {
      const unknown: never = triage;
      throw new Error(`unknown verdict: ${(unknown as { verdict: unknown }).verdict}`);
    }
  }
}

// ------------------------------------------------------------------ priority

// Ordering ONLY. Never filters. This is the one consumer of a scanner's claim besides the
// report, and ordering is lossy-tolerant in a way filtering is not: a mis-ordered finding
// still gets triaged, a filtered one never does.
const CLASS_RISK: Record<InvariantClass, number> = {
  'injection.sql': 3, 'injection.command': 3, 'injection.code': 3, 'injection.path': 3,
  'injection.template': 3, 'deserialization.unsafe': 3, 'authz.missing': 3,
  'xss.stored': 2, 'ssrf': 2, 'authn.weak': 2, 'secret.hardcoded': 2, 'injection.ldap': 2,
  'injection.xml': 2, 'xss.reflected': 2, 'memory.unsafe': 2, 'session.weak': 2,
  'xss.dom': 1, 'redirect.open': 1, 'crypto.weak': 1, 'crypto.misuse': 1,
  'randomness.weak': 1, 'race.toctou': 1, 'disclosure.sensitive': 1, 'injection.log': 1,
  'dos.uncontrolled': 1, 'config.insecure': 1, 'other': 0,
};

const TRI: Record<string, number> = { HIGH: 3, MEDIUM: 2, LOW: 1 };

// Each scanner is ranked in its OWN vocabulary. There is no shared scale and we do not invent
// one. Semgrep's own likelihood/impact metadata is better signal than its rule-category
// severity, so it is preferred when present; measured on real output, `detect-child-process`
// is ERROR with likelihood LOW while `path-join-resolve-traversal` is WARNING with
// likelihood HIGH, and ranking by severity alone inverts them.
function claimedRank(claimed: ClaimedSeverity): number {
  switch (claimed.kind) {
    case 'semgrep': {
      if (claimed.likelihood || claimed.impact) {
        return ((TRI[claimed.likelihood ?? ''] || 0) + (TRI[claimed.impact ?? ''] || 0)) / 2;
      }
      return ({ ERROR: 3, WARNING: 2, INFO: 1 } as const)[claimed.severity] || 0;
    }
    case 'codeql': {
      if (claimed.security_severity !== null && claimed.security_severity !== undefined) {
        // GitHub's published cut points: <4 low, 4-6.9 medium, 7-8.9 high, >=9 critical.
        const s = claimed.security_severity;
        return s >= 9 ? 4 : s >= 7 ? 3 : s >= 4 ? 2 : 1;
      }
      return claimed.problem_severity ? ({ error: 3, warning: 2, recommendation: 1 } as const)[claimed.problem_severity] : 0;
    }
    default: {
      const unknown: never = claimed;
      throw new Error(`unknown claim kind: ${(unknown as { kind: unknown }).kind}`);
    }
  }
}

const ENTRY_HINT = /(^|\/)(routes?|controllers?|handlers?|api|endpoints?|cmd|views?|pages?)(\/|\.)/i;

type Prioritized = Pick<Finding, 'sites' | 'flow' | 'invariant_class'>;

function priority(f: Prioritized): number {
  const obs = f.sites.flatMap((s) => s.observations);
  const maxClaim = obs.length ? Math.max(...obs.map((o) => claimedRank(o.claimed))) : 0;
  const scanners = new Set(obs.map((o) => o.scanner));
  const allSuppressed = obs.length > 0 && obs.every((o) => o.suppressed_at_source);
  return (
    3 * (CLASS_RISK[f.invariant_class] ?? 0) +
    2 * maxClaim +
    2 * (f.flow.kind === 'traced' ? 1 : 0) +
    1 * (scanners.size > 1 ? 1 : 0) +
    1 * (f.sites.some((s) => ENTRY_HINT.test(s.locus.file)) ? 1 : 0) +
    1 * Math.log2(f.sites.length + 1) -
    3 * (allSuppressed ? 1 : 0)
  );
}

const order = <T extends Prioritized & { id: string }>(findings: T[]): T[] =>
  [...findings].sort((a, b) => priority(b) - priority(a) || a.id.localeCompare(b.id));

export type { Policy };
export { gate, priority, order, rank, claimedRank, isSeverity, RANK };

if (import.meta.main) {
  const [file, fixAt = 'medium'] = process.argv.slice(2);
  if (!file || !isSeverity(fixAt)) { console.error('usage: gate.ts <findings.json> [fix_at]'); process.exit(2); }
  const findings = JSON.parse(fs.readFileSync(file, 'utf8')) as FindingRecord[];
  for (const f of order(findings)) {
    const g = f.triage ? gate(f.triage, { fix_at: fixAt }) : null;
    console.log(`${priority(f).toFixed(2).padStart(6)}  ${f.id}  ${f.invariant_class.padEnd(20)} ${g ? g.action : 'untriaged'}`);
  }
}
