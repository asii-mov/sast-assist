#!/usr/bin/env node
// REMEDIATION.md and HANDOFF.md, built only from finding records and the run's meta.
// Each finding's saved disposition is its outcome; this module files it under that and never
// re-judges a patch. The seven-obligation model is easy to describe correctly
// and easy to summarize dishonestly, so every helper here exists to keep those the same
// sentence: a fix checked at a partial verify level is never described as fully verified, a
// path-policy rejection is a scope decision and not a security claim, rescan quiet is an
// observation and never a verdict, and only an exploitable finding ever carries a severity.

import { VERIFY_LEVELS, OBLIGATIONS } from './stage.ts';
import { claimedRank } from './gate.ts';
import fs from 'fs';
import path from 'path';
import type { Disposition, FindingRecord, Obligation, Verification } from './stage.ts';
import type { ClaimedSeverity, SecurityContract } from '../schema/types.ts';
import type { ScannerStatus } from './scan.ts';
import type { RunMeta } from './run.ts';

type State = Disposition['state'];
// A finding filed under one of `S`, so its disposition is known to be one of those states.
type In<S extends State> = FindingRecord & { disposition: Extract<Disposition, { state: S }> };
type Cell = string | number;

// ---------------------------------------------------------------------- markdown primitives

const cellText = (s: Cell) => String(s).replace(/\r?\n/g, ' ').replace(/\|/g, '\\|');
const code = (s: unknown) => `\`${s}\``;
const noun = (n: number, singular: string, plural?: string) => `${n} ${n === 1 ? singular : (plural || `${singular}s`)}`;

function table(headers: string[], rows: Cell[][]): string {
  if (!rows.length) return '_none._\n';
  const head = `| ${headers.join(' | ')} |`;
  const sep = `| ${headers.map(() => '---').join(' | ')} |`;
  const body = rows.map((r) => `| ${r.map(cellText).join(' | ')} |`).join('\n');
  return `${head}\n${sep}\n${body}\n`;
}

function truncate(text: unknown, max: number): string {
  const t = String(text).replace(/\s+/g, ' ').trim();
  return t.length > max ? `${t.slice(0, max - 3).trimEnd()}...` : t;
}

// ---------------------------------------------------------------------- finding readers

// exploitable and undecidable both carry a security_contract (the second under `hypothesis`,
// not `contract`, precisely so a hypothesis can never be mistaken for an established one by a
// reader who only checks the field name). Reading either through one accessor is safe here
// because both call sites already gate on which verdict they are looking at.
const contractOf = (f: FindingRecord): SecurityContract | null => {
  if (!f.triage) return null;
  if (f.triage.verdict === 'exploitable') return f.triage.contract;
  if (f.triage.verdict === 'undecidable') return f.triage.hypothesis;
  return null;
};
// Only an exploitable finding carries a severity; every state that shows one implies that verdict.
const severityOf = (f: FindingRecord) => (f.triage?.verdict === 'exploitable' ? f.triage.severity : 'none');

function primarySite(f: FindingRecord) { return f.sites[0]; }

function titleFor(f: FindingRecord): string {
  const c = contractOf(f);
  if (c) return truncate(c.invariant, 100);
  const s = primarySite(f);
  return `${f.invariant_class} at ${code(`${s.locus.file}:${s.locus.line_at_scan}`)}`;
}

function boundaryFor(f: FindingRecord): string {
  const c = contractOf(f);
  if (c && c.enforcement_point) {
    const ep = c.enforcement_point;
    return ep.symbol ? code(`${ep.file} (${ep.symbol})`) : code(ep.file);
  }
  if (f.triage && f.triage.verdict === 'not_exploitable' && f.triage.refutation.control) {
    const ctl = f.triage.refutation.control;
    return code(`${ctl.file}:${ctl.line}`);
  }
  const s = primarySite(f);
  return code(`${s.locus.file}:${s.locus.line_at_scan}`);
}

// ---------------------------------------------------------------------- disposition reading

// bin/run.ts judges each finding once, with the run's verify level. A finding it has not
// judged yet is `pending`.
function byState(findings: FindingRecord[]) {
  const groups = new Map<State | 'pending', FindingRecord[]>();
  for (const f of findings) {
    const state = f.disposition ? f.disposition.state : 'pending';
    groups.set(state, [...(groups.get(state) || []), f]);
  }
  // Grouped by disposition.state above, so each group holds exactly the states asked for.
  return <S extends State>(...states: S[]) => states.flatMap((s) => groups.get(s) || []) as In<S>[];
}

const lastPatch = (f: FindingRecord) => f.patches[f.patches.length - 1];
const requiredFor = (meta: RunMeta) => VERIFY_LEVELS[meta.verify_level] || [];
const obligationList = (names: readonly string[]) => (names.length ? names.map(code).join(', ') : 'none');
const branchCell = (d: { branch: string | null }) => (d.branch ? code(d.branch) : 'none');

// The one sentence this whole file protects. "Verified" alone is exactly the phrase that
// erases the difference between cheap and full, so it never appears without the level and the
// skipped obligations named beside it. `unavailable` is named too: only the obligations in
// bin/stage.ts MAY_BE_UNAVAILABLE may land there, and an excused obligation is not a passed one.
function verificationSummary(d: Extract<Disposition, { state: 'fixed' | 'fixed_unwitnessed' }>): string {
  const parts: string[] = [];
  if (d.skipped_obligations.length === 0) {
    parts.push(`verified at ${code('full')}: all seven obligations ${d.unavailable.length ? 'checked' : 'passed'}`);
  } else {
    const ran = OBLIGATIONS.filter((o) => !d.skipped_obligations.includes(o));
    parts.push(`verified at ${code(d.verify_level)} (${ran.length} of 7 obligations checked: `
      + `${obligationList(ran)}; skipped: ${obligationList(d.skipped_obligations)})`);
  }
  if (d.unavailable.length) {
    parts.push(`${obligationList(d.unavailable)} unavailable and excused, not passed`);
  }
  return parts.join('; ');
}

function obligationCell(f: In<'fixed' | 'fixed_unwitnessed'>, name: Obligation, read: (o: { status?: string }) => string): string {
  if (f.disposition.skipped_obligations.includes(name)) return 'skipped at this verify level';
  return read(lastPatch(f).verification?.[name] || {});
}

// Saved verification records vary by obligation and by the version that wrote them, so any
// detail field is read if present.
function failureDetail(rawVerification: Verification | null, name: Obligation): string {
  const o: Record<string, unknown> | undefined = rawVerification?.[name];
  if (!o) return 'no detail recorded';
  if (o.detail) return String(o.detail);
  if (o.reason) return String(o.reason);
  if (o.explanation) return String(o.explanation);
  if (Array.isArray(o.violations) && o.violations.length) return o.violations.join('; ');
  return `status ${o.status}`;
}

function whyNotFixed(d: Extract<Disposition, { state: 'fix_declined' | 'fix_failed' }>): string {
  if (d.state === 'fix_declined') return `the fixer declined: ${d.reason}`;
  if (d.outcome !== 'patched') return `${code(d.outcome)}: ${d.detail || 'no detail recorded'}`;
  return `failed on ${obligationList([...d.failed, ...d.missing])}`;
}

function attemptSummary(p: FindingRecord['patches'][number]): string {
  if (p.outcome !== 'patched') return `attempt ${p.attempt}: ${p.outcome}`;
  const failed = (p.typed_failures || []).map((x) => x.obligation);
  return `attempt ${p.attempt}: ${failed.length ? `failed on ${obligationList(failed)}` : 'passed its checks'}`;
}

// ---------------------------------------------------------------------- scanner disagreement

function describeClaim(c: ClaimedSeverity): string {
  if (c.kind === 'semgrep') {
    return (c.likelihood || c.impact)
      ? `severity ${c.severity} (likelihood ${c.likelihood || 'n/a'}, impact ${c.impact || 'n/a'})`
      : `severity ${c.severity}`;
  }
  if (c.kind === 'codeql') {
    return c.security_severity !== null && c.security_severity !== undefined
      ? `security-severity ${c.security_severity}`
      : `problem-severity ${c.problem_severity || 'n/a'}`;
  }
  return 'unrecognized claim';
}

// Location disagreement beyond a couple of lines is resolved upstream by normalize.ts's two
// folds (FOLD 1 merges within a locus, FOLD 2 merges by root cause), so by the time a report
// runs there is no independent "the scanners picked different lines" signal left to read. What
// remains, and is cheap because the record already holds it: one scanner's claim outranking
// another's at the same site, and a site only one scanner ever reported.
function scannerDisagreements(findings: FindingRecord[]) {
  const out: { finding: string; file: string; line: number; detail: string }[] = [];
  // A split parent's sites are its children's, so they are read once, from the children.
  for (const f of findings.filter((x) => x.disposition?.state !== 'split')) {
    for (const s of f.sites) {
      const obs = s.observations;
      if (obs.length < 2) {
        out.push({ finding: f.id, file: s.locus.file, line: s.locus.line_at_scan,
          detail: `only ${obs[0].scanner} reported this site` });
        continue;
      }
      const ranks = obs.map((o) => claimedRank(o.claimed));
      if (Math.max(...ranks) - Math.min(...ranks) >= 1) {
        out.push({ finding: f.id, file: s.locus.file, line: s.locus.line_at_scan,
          detail: obs.map((o) => `${o.scanner} ${describeClaim(o.claimed)}`).join(' vs ') });
      }
    }
  }
  return out;
}

// Older runs recorded a scanner as a bare name, or with a version and an error.
function describeScanners(scanners: (string | (ScannerStatus & { version?: string; error?: string }))[] | undefined): string {
  if (!scanners || !scanners.length) return 'none recorded';
  return scanners.map((s) => {
    if (typeof s === 'string') return code(s);
    const name = [s.name, s.version].filter(Boolean).join('@') || 'unknown';
    const config = s.config ? ` (${s.config})` : '';
    const status = s.status && s.status !== 'ok' ? ` [${s.status}${s.error ? `: ${s.error}` : ''}]` : '';
    return `${code(name)}${config}${status}`;
  }).join(', ');
}

// ---------------------------------------------------------------------- REMEDIATION.md

function renderRemediation(findings: FindingRecord[], meta: RunMeta): string {
  const of = byState(findings);
  const fixed = of('fixed');
  const unwitnessed = of('fixed_unwitnessed');
  const shipped = of('fixed', 'fixed_unwitnessed');
  const pending = findings.filter((f) => !f.disposition);
  const rejected = new Map<string, FindingRecord[]>();
  for (const f of of('rejected').filter((x) => !x.disposition.policy)) {
    rejected.set(f.disposition.reason, [...(rejected.get(f.disposition.reason) || []), f]);
  }
  const triagedCount = findings.filter((f) => f.triage || f.disposition).length;
  const L: string[] = [];

  L.push(`# Remediation report: ${code(meta.target)}`, '');
  L.push('**1. Run header.**', '');
  L.push(`- Run: ${code(meta.run_id)}`);
  L.push(`- Scope: ${code(meta.target)}`);
  L.push(`- Base commit: ${code(meta.base_commit)}`);
  L.push(`- Fix threshold: ${code((meta.policy && meta.policy.fix_at) || 'unspecified')} and above`);
  L.push(`- Verify level: ${code(meta.verify_level || 'unspecified')} `
    + `(obligations checked: ${obligationList(requiredFor(meta))})`);
  L.push(`- Scanners: ${describeScanners(meta.scanners)}`);
  if (meta.scan_config) {
    L.push(`- Rescan configuration: semgrep ${code(meta.scan_config.semgrep.join(' '))}, `
      + `CodeQL suite ${code(meta.scan_config.codeql_suite)}`);
    if ((meta.scanners || []).some((s) => s.status === 'reused')) {
      L.push('- Reused scans were made outside this run. Rescans ran the configuration above, so '
        + 'a rule it runs that the reused scan did not is counted as introduced by the patch.');
    }
  }
  L.push(`- Findings processed: ${triagedCount} of ${findings.length} `
    + `(${findings.length - triagedCount} not triaged yet)`);
  for (const f of of('split')) {
    L.push(`- ${code(f.id)} was split by triage into ${f.disposition.children.map((c) => code(c.id)).join(', ')}, `
      + 'each reported under its own id');
  }
  if (meta.dropped && meta.dropped.length) {
    L.push(`- Raw scanner results dropped before analysis: ${meta.dropped.length} `
      + '(path missing or outside the repository root)');
  }
  L.push('');
  if (findings.length === 0) {
    L.push('Both scanners returned zero findings this run. That can mean the code is clean, or '
      + 'it can mean the vulnerable flow left the taint model neither scanner runs on; the scan '
      + `output cannot tell those apart. See ${code('references/INGEST.md')}.`, '');
  }
  if (meta.run_status === 'incomplete') {
    L.push(`**This run is incomplete.** Reason: ${meta.incomplete_reason || 'not stated'}.`);
  } else if (pending.length) {
    L.push(`**This run is not fully resolved.** ${noun(pending.length, 'finding')} `
      + `${pending.length === 1 ? 'has' : 'have'} no outcome and no incomplete reason recorded.`);
  } else {
    L.push('This run completed. Every finding below has a terminal outcome.');
  }

  L.push('', '**2. What changed.**', '');
  if (fixed.length || unwitnessed.length) {
    L.push(`Each patched finding has its own branch off ${code(meta.base_commit)}. `
      + 'The one action left is to review and merge them.', '');
    for (const f of fixed) L.push(`- ${code(f.id)}: ${code(f.disposition.branch)}`);
    for (const f of unwitnessed) {
      L.push(`- ${code(f.id)}: ${code(f.disposition.branch)} (not mechanically witnessed, see section 4)`);
    }
  } else {
    L.push('No finding was patched this run. Nothing is waiting on review.');
  }

  L.push('', '**3. Fixed findings.**', '');
  if (!fixed.length) {
    L.push('No findings were fixed and verified this run.');
  } else {
    const rows = fixed.map((f) => [
      code(f.id), code(severityOf(f)), titleFor(f), boundaryFor(f),
      obligationCell(f, 'differential_witness', (o) => `${code(f.disposition.witness_tier)}: ${o.status || 'unknown'}`),
      obligationCell(f, 'hostile_auditor', () => code(lastPatch(f).audit?.verdict)),
    ]);
    L.push(table(['id', 'severity', 'title', 'boundary', 'witness', 'audit'], rows), '');
    for (const f of fixed) L.push(`- ${code(f.id)}: ${verificationSummary(f.disposition)}.`);
  }

  L.push('', '**4. Patched but unwitnessed.**', '');
  if (!unwitnessed.length) {
    L.push(`No patch landed on the ${code('argued')} witness tier this run.`);
  } else {
    L.push(`These patches passed the checks this run asked for, but the ${code('argued')} tier has no `
      + 'mechanical witness, so no check showed the attack stop. Review each one by hand.', '');
    const rows = unwitnessed.map((f) => [code(f.id), code(severityOf(f)), titleFor(f), branchCell(f.disposition)]);
    L.push(table(['id', 'severity', 'title', 'branch'], rows), '');
    for (const f of unwitnessed) L.push(`- ${code(f.id)}: ${verificationSummary(f.disposition)}.`);
  }

  L.push('', '**5. Not fixed.**', '');
  const notFixed = of('fix_declined', 'fix_failed');
  if (!notFixed.length) {
    L.push('No fix was declined or failed this run.');
  } else {
    const rows = notFixed.map((f) => [code(f.id), code(f.disposition.state),
      branchCell(f.disposition), whyNotFixed(f.disposition)]);
    L.push(table(['id', 'outcome', 'branch', 'why'], rows), 'The handoff document has the detail for each.');
  }

  L.push('', '**6. Evidence strength.**', '');
  if (!shipped.length) {
    L.push('No findings were patched this run, so there is no evidence mix to report.');
  } else {
    const counts = new Map<string, number>();
    for (const f of shipped) counts.set(f.disposition.witness_tier, (counts.get(f.disposition.witness_tier) || 0) + 1);
    const rows = [...counts.entries()].sort((x, y) => y[1] - x[1]).map(([tier, n]) => [code(tier), n]);
    L.push(table(['witness tier', 'count'], rows));
    if ((counts.get('argued') || 0) / shipped.length > 0.5) {
      L.push('', `Most patched findings fell back to the ${code('argued')} tier, meaning no mechanical `
        + 'check ran. That says something real about this repository, not about the fixes: treat '
        + 'these as human-reviewed, not machine-proven.');
    }
  }

  L.push('', '**7. Rejected findings.**', '');
  if (!rejected.size) {
    L.push('No findings were rejected as not exploitable this run.');
  } else {
    const rows = [...rejected.entries()].sort((x, y) => y[1].length - x[1].length)
      .map(([reason, list]) => [code(reason), list.length, list.map((f) => code(f.id)).join(', ')]);
    L.push(table(['reason', 'count', 'ids'], rows));
    const dig = rejected.get('defense_in_depth_gap_only');
    if (dig && dig.length) {
      L.push('', `${noun(dig.length, 'finding')} were rejected as ${code('defense_in_depth_gap_only')}: `
        + 'a control already on the path prevents the attack, so the missing second layer is a '
        + 'hardening note, not a vulnerability.');
    }
  }

  L.push('', '**8. Policy rejections.**', '');
  L.push('These findings were never sent to an agent. Path policy resolved them by matching test, '
    + 'vendor, generated, minified or migration code. This is a scope decision, not a claim that '
    + `the code is safe; ${code('--include-tests')} disables it.`, '');
  const policyRejected = of('rejected').filter((f) => f.disposition.policy);
  if (policyRejected.length) {
    const rows = policyRejected.map((f) => [code(f.id), boundaryFor(f),
      truncate(f.triage?.verdict === 'not_exploitable' ? f.triage.refutation.explanation : '', 100)]);
    L.push(table(['id', 'matched', 'why'], rows));
  } else {
    L.push('No findings were rejected by path policy this run.');
  }

  L.push('', '**9. Below threshold.**', '');
  const below = of('below_threshold');
  if (!below.length) {
    L.push('No exploitable findings fell below the fix threshold this run.');
  } else {
    const rows = below.map((f) => [code(f.id), code(severityOf(f)), titleFor(f), boundaryFor(f)]);
    L.push(table(['id', 'severity', 'title', 'boundary'], rows));
  }

  L.push('', '**10. Scanner disagreement.**', '');
  const disagreements = scannerDisagreements(findings);
  if (!disagreements.length) {
    L.push('No scanner disagreement to report: every multi-scanner site agreed closely enough, '
      + 'and no site was seen by only one scanner.');
  } else {
    L.push("These are the scanners' own claims, not this run's severity verdict; only exploitable "
      + 'findings carry one of those.', '');
    const rows = disagreements.map((d) => [code(d.finding), code(`${d.file}:${d.line}`), d.detail]);
    L.push(table(['id', 'site', 'detail'], rows));
  }

  L.push('', '**11. Scanner-quiet status.**', '');
  if (!shipped.length) {
    L.push('No findings were patched this run, so there is no rescan status to report.');
  } else {
    const rows = shipped.map((f) => {
      if (f.disposition.skipped_obligations.includes('no_new_findings')) return [code(f.id), 'rescan skipped at this verify level'];
      const absent = lastPatch(f).verification?.rescan?.original_absent;
      const status = absent === null ? 'the rescan produced no output'
        : absent ? 'scanner is quiet on the original rule' : 'scanner still fires on the original rule';
      return [code(f.id), `${status} (observation only; the outcome above does not depend on this)`];
    });
    L.push(table(['id', 'original rule status'], rows));
  }

  return `${L.join('\n')}\n`;
}

// ---------------------------------------------------------------------- HANDOFF.md

function renderHandoff(findings: FindingRecord[], meta: RunMeta): string {
  const of = byState(findings);
  const auditRequired = requiredFor(meta).includes('hostile_auditor');
  const L: string[] = [];

  L.push(`# Handoff: ${code(meta.target)}`, '');
  L.push(`Run ${code(meta.run_id)}, verify level ${code(meta.verify_level || 'unspecified')}. `
    + 'Everything below is something a human owns next.');
  if (meta.run_status === 'incomplete') {
    L.push('', `**This run is incomplete.** Reason: ${meta.incomplete_reason || 'not stated'}.`);
  }

  L.push('', '**Not fixed.**', '');
  const notFixed = of('fix_declined', 'fix_failed');
  if (!notFixed.length) {
    L.push('No fix was declined or failed this run.');
  } else {
    for (const f of notFixed) {
      const d = f.disposition;
      const last = lastPatch(f);
      L.push(`- ${code(f.id)} (${code(severityOf(f))}): branch ${branchCell(d)}, `
        + `${noun(f.patches.length, 'attempt')} made. ${titleFor(f)}`);
      L.push(`  Why: ${whyNotFixed(d)}.`);
      if (d.state === 'fix_failed' && d.outcome === 'patched') {
        const audit = !auditRequired ? 'not run at this verify level'
          : (last.audit ? last.audit.verdict : 'not recorded');
        L.push(`  Last audit verdict: ${code(audit)}.`);
        L.push(`  Failed obligations: ${d.failed.length
          ? d.failed.map((n) => `${code(n)} (${failureDetail(last.verification, n)})`).join('; ')
          : 'none recorded'}.`);
      }
      if (f.patches.length > 1) {
        L.push(`  Earlier attempts: ${f.patches.slice(0, -1).map(attemptSummary).join('; ')}.`);
      }
    }
  }

  L.push('', '**Undecidable.**', '');
  const undecidable = of('undecidable');
  if (!undecidable.length) {
    L.push('No finding is undecidable this run.');
  } else {
    for (const f of undecidable) {
      if (f.triage?.verdict !== 'undecidable') continue;
      L.push(`- ${code(f.id)}: ${f.triage.blocker.missing_fact}`);
      L.push(`  Resolve by ${code(f.triage.blocker.resolve_by)}: ${f.triage.blocker.plan}`);
      L.push('  This is a hypothesis, not a confirmed vulnerability, and carries no severity.');
    }
  }

  L.push('', '**Split again.**', '');
  const splitAgain = of('deferred');
  if (!splitAgain.length) {
    L.push('No finding split out of another asked to split again this run.');
  } else {
    for (const f of splitAgain) {
      const d = f.disposition;
      L.push(`- ${code(f.id)}, split out of ${code(d.split_from)}, asked to split again. Decide its enforcement points by hand.`);
      for (const g of d.groups) L.push(`  Lines ${g.site_lines.join(', ')}: ${g.why}`);
    }
  }

  L.push('', '**Patched but unwitnessed.**', '');
  const unwitnessed = of('fixed_unwitnessed');
  if (!unwitnessed.length) {
    L.push('No finding landed on the argued tier this run.');
  } else {
    for (const f of unwitnessed) {
      const w = contractOf(f)?.witness;
      L.push(`- ${code(f.id)} (${code(severityOf(f))}): ${titleFor(f)}`);
      if (w?.tier === 'argued') L.push(`  Obstacle: ${code(w.obstacle)}. ${w.why}`);
      L.push(`  Branch: ${branchCell(f.disposition)}.`);
    }
  }

  return `${L.join('\n')}\n`;
}

export { renderRemediation, renderHandoff };

if (import.meta.main) {
  const [findingsFile, metaFile, outDir] = process.argv.slice(2);
  if (!findingsFile || !metaFile) {
    console.error('usage: report.ts <findings.json> <meta.json> [outDir]');
    process.exit(2);
  }
  const findings = JSON.parse(fs.readFileSync(findingsFile, 'utf8'));
  const meta = JSON.parse(fs.readFileSync(metaFile, 'utf8'));
  const remediation = renderRemediation(findings, meta);
  const handoff = renderHandoff(findings, meta);
  if (outDir) {
    fs.writeFileSync(path.join(outDir, 'REMEDIATION.md'), remediation);
    fs.writeFileSync(path.join(outDir, 'HANDOFF.md'), handoff);
    console.error(`wrote ${path.join(outDir, 'REMEDIATION.md')} and HANDOFF.md`);
  } else {
    console.log(remediation);
    console.log('\n---\n');
    console.log(handoff);
  }
}
