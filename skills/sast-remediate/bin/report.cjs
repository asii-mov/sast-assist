#!/usr/bin/env node
'use strict';
// REMEDIATION.md and HANDOFF.md, built only from finding records and the run's meta.
// evaluateVerification in bin/stage.cjs is the sole definition of "verified"; this module
// calls it and never re-derives it. The seven-obligation model is easy to describe correctly
// and easy to summarize dishonestly, so every helper here exists to keep those the same
// sentence: a fix checked at a partial verify level is never described as fully verified, a
// path-policy rejection is a scope decision and not a security claim, rescan quiet is an
// observation and never a verdict, and only an exploitable finding ever carries a severity.

const { evaluateVerification, VERIFY_LEVELS, OBLIGATIONS } = require('./stage.cjs');
const { claimedRank } = require('./gate.cjs');

// ---------------------------------------------------------------------- markdown primitives

const cellText = (s) => String(s).replace(/\r?\n/g, ' ').replace(/\|/g, '\\|');
const code = (s) => `\`${s}\``;
const noun = (n, singular, plural) => `${n} ${n === 1 ? singular : (plural || `${singular}s`)}`;

function table(headers, rows) {
  if (!rows.length) return '_none._\n';
  const head = `| ${headers.join(' | ')} |`;
  const sep = `| ${headers.map(() => '---').join(' | ')} |`;
  const body = rows.map((r) => `| ${r.map(cellText).join(' | ')} |`).join('\n');
  return `${head}\n${sep}\n${body}\n`;
}

function truncate(text, max) {
  const t = String(text).replace(/\s+/g, ' ').trim();
  return t.length > max ? `${t.slice(0, max - 3).trimEnd()}...` : t;
}

// ---------------------------------------------------------------------- finding readers

// exploitable and undecidable both carry a security_contract (the second under `hypothesis`,
// not `contract`, precisely so a hypothesis can never be mistaken for an established one by a
// reader who only checks the field name). Reading either through one accessor is safe here
// because both call sites already gate on which verdict they are looking at.
const contractOf = (f) => f.triage && (f.triage.contract || f.triage.hypothesis);

function primarySite(f) { return f.sites[0]; }

function titleFor(f) {
  const c = contractOf(f);
  if (c) return truncate(c.invariant, 100);
  const s = primarySite(f);
  return `${f.invariant_class} at ${code(`${s.locus.file}:${s.locus.line_at_scan}`)}`;
}

function boundaryFor(f) {
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

// ---------------------------------------------------------------------- verification reading

const requiredFor = (meta) => VERIFY_LEVELS[meta.verify_level] || [];
const obligationList = (names) => (names.length ? names.map(code).join(', ') : 'none');

// The one sentence this whole file protects. "Verified" alone is exactly the phrase that
// erases the difference between cheap and full, so it never appears without the level and the
// skipped obligations named beside it. `unavailable` is named too: only regression_suite may
// land there (bin/stage.cjs MAY_BE_UNAVAILABLE), and an excused obligation is not a passed one.
function verificationSummary(ev, level) {
  const parts = [];
  if (ev.skipped.length === 0) {
    parts.push(`verified at ${code('full')}: all seven obligations passed`);
  } else {
    const ran = OBLIGATIONS.filter((o) => !ev.skipped.includes(o));
    parts.push(`verified at ${code(level)} (${ran.length} of 7 obligations checked: `
      + `${obligationList(ran)}; skipped: ${obligationList(ev.skipped)})`);
  }
  if (ev.unavailable.length) {
    parts.push(`${obligationList(ev.unavailable)} unavailable and excused, not passed`);
  }
  return parts.join('; ');
}

function witnessCell(f, last, ev) {
  if (ev.skipped.includes('differential_witness')) return 'skipped at this verify level';
  const tier = contractOf(f).witness.tier;
  const raw = last.verification.differential_witness || {};
  return `${code(tier)}: ${raw.status || 'unknown'}`;
}

function auditCell(last, ev) {
  if (ev.skipped.includes('hostile_auditor')) return 'skipped at this verify level';
  const raw = last.verification.hostile_auditor || {};
  return raw.verdict ? code(raw.verdict) : (raw.status || 'unknown');
}

function failureDetail(rawVerification, name) {
  const o = rawVerification && rawVerification[name];
  if (!o) return 'no detail recorded';
  if (o.detail) return o.detail;
  if (o.reason) return o.reason;
  if (o.explanation) return o.explanation;
  if (Array.isArray(o.violations) && o.violations.length) return o.violations.join('; ');
  return `status ${o.status}`;
}

function attemptSummary(patch, i, required) {
  if (patch.fix && patch.fix.outcome === 'cannot_fix') {
    return `attempt ${i + 1}: fixer declined (${patch.fix.reason})`;
  }
  if (!patch.verification) return `attempt ${i + 1}: no verification recorded`;
  const ev = evaluateVerification(patch.verification, required);
  return ev.verified
    ? `attempt ${i + 1}: verified, superseded by a later attempt`
    : `attempt ${i + 1}: failed on ${obligationList(ev.failed)}`;
}

// ---------------------------------------------------------------------- classification

// One patched finding, three possible fates. `fixed_unwitnessed` exists because the `argued`
// witness tier can never mechanically pass (FIX-AND-VERIFY.md): when differential_witness is
// the ONLY failure and the contract's own tier is `argued`, that is the designed degraded
// path, not a broken fix, and it must never be folded into either "verified" or "unfixable".
function classifyPatch(f, required) {
  const patches = f.patches || [];
  if (!patches.length) return { kind: 'pending' };
  const last = patches[patches.length - 1];
  if (last.fix && last.fix.outcome === 'cannot_fix') {
    return patches.length >= 2 ? { kind: 'unfixable', last, ev: null } : { kind: 'pending', last };
  }
  if (!last.verification) return { kind: 'pending', last };
  const ev = evaluateVerification(last.verification, required);
  if (ev.verified) return { kind: 'fixed', last, ev };
  const tier = contractOf(f).witness.tier;
  const onlyWitnessFailed = ev.failed.length === 1 && ev.failed[0] === 'differential_witness'
    && ev.missing.length === 0;
  if (tier === 'argued' && onlyWitnessFailed) return { kind: 'fixed_unwitnessed', last, ev };
  return patches.length >= 2 ? { kind: 'unfixable', last, ev } : { kind: 'pending', last, ev };
}

// A single pass so REMEDIATION.md and HANDOFF.md can never disagree about which bucket a
// finding is in. `disposition.outcome === 'split_escalated'` is the one case a Triage cannot
// represent (TRIAGE.md: a second split escalates to a human, and no code tracks that count
// yet), so it is checked before triage is even read.
function classify(findings, meta) {
  const required = requiredFor(meta);
  const b = {
    deferred: [], splitEscalated: [], pending: [],
    fixed: [], fixedUnwitnessed: [], unfixable: [],
    rejected: new Map(), policyRejected: [], belowThreshold: [], undecidable: [],
  };
  for (const f of findings) {
    if (f.disposition && f.disposition.outcome === 'split_escalated') { b.splitEscalated.push(f); continue; }
    if (!f.triage) { b.deferred.push(f); continue; }
    if (!f.gate) { b.pending.push(f); continue; }
    switch (f.gate.reason) {
      case 'undecidable': b.undecidable.push(f); break;
      case 'not_exploitable':
        if (f.triage.established_by === 'deterministic_prepass') {
          b.policyRejected.push(f);
        } else {
          const list = b.rejected.get(f.triage.refutation.reason) || [];
          list.push(f);
          b.rejected.set(f.triage.refutation.reason, list);
        }
        break;
      case 'below_threshold': b.belowThreshold.push(f); break;
      case 'at_or_above_threshold': {
        const c = classifyPatch(f, required);
        if (c.kind === 'pending') b.pending.push(f);
        else b[c.kind === 'fixed' ? 'fixed' : c.kind === 'fixed_unwitnessed' ? 'fixedUnwitnessed' : 'unfixable']
          .push({ f, last: c.last, ev: c.ev });
        break;
      }
      default: b.pending.push(f);
    }
  }
  return b;
}

// ---------------------------------------------------------------------- scanner disagreement

function describeClaim(c) {
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

// Location disagreement beyond a couple of lines is resolved upstream by normalize.cjs's two
// folds (FOLD 1 merges within a locus, FOLD 2 merges by root cause), so by the time a report
// runs there is no independent "the scanners picked different lines" signal left to read. What
// remains, and is cheap because the record already holds it: one scanner's claim outranking
// another's at the same site, and a site only one scanner ever reported.
function scannerDisagreements(findings) {
  const out = [];
  for (const f of findings) {
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

function describeScanners(scanners) {
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

function renderRemediation(findings, meta) {
  const required = requiredFor(meta);
  const b = classify(findings, meta);
  const triagedCount = findings.filter((f) => f.triage).length;
  const shipped = [...b.fixed, ...b.fixedUnwitnessed];
  const L = [];

  L.push(`# Remediation report: ${code(meta.target)}`, '');
  L.push('**1. Run header.**', '');
  L.push(`- Run: ${code(meta.run_id)}`);
  L.push(`- Scope: ${code(meta.target)}`);
  L.push(`- Base commit: ${code(meta.base_commit)}`);
  L.push(`- Fix threshold: ${code((meta.policy && meta.policy.fix_at) || 'unspecified')} and above`);
  L.push(`- Verify level: ${code(meta.verify_level || 'unspecified')} `
    + `(obligations checked: ${obligationList(required)})`);
  L.push(`- Scanners: ${describeScanners(meta.scanners)}`);
  L.push(`- Findings processed: ${triagedCount} of ${findings.length} `
    + `(${findings.length - triagedCount} deferred)`);
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
  } else if (b.pending.length) {
    L.push(`**This run is not fully resolved.** ${noun(b.pending.length, 'finding')} `
      + `${b.pending.length === 1 ? 'is' : 'are'} still mid-fix with no incomplete reason recorded.`);
  } else {
    L.push('This run completed. Every finding below has a terminal outcome.');
  }

  L.push('', '**2. What changed.**', '');
  if (b.fixed.length) {
    L.push(`Branch ${code(`sast-fix/integration-${meta.run_id}`)} carries ${noun(b.fixed.length, 'commit')}, `
      + `one per verified finding, cherry-picked in id order off ${code(meta.base_commit)}.`);
    L.push('The one action left is to review and merge it.');
  } else {
    L.push('No finding reached a verified fix this run, so no integration branch was built. '
      + 'Nothing is waiting on review.');
  }
  if (b.fixedUnwitnessed.length) {
    L.push(`${noun(b.fixedUnwitnessed.length, 'finding')} patched but not mechanically witnessed `
      + 'sit outside that branch; see the handoff document.');
  }

  L.push('', '**3. Fixed findings.**', '');
  if (!b.fixed.length) {
    L.push('No findings were fixed and verified this run.');
  } else {
    const rows = b.fixed.map(({ f, last, ev }) => [
      code(f.id), code(f.triage.severity), titleFor(f), boundaryFor(f),
      witnessCell(f, last, ev), auditCell(last, ev),
    ]);
    L.push(table(['id', 'severity', 'title', 'boundary', 'witness', 'audit'], rows), '');
    for (const { f, ev } of b.fixed) L.push(`- ${code(f.id)}: ${verificationSummary(ev, meta.verify_level)}.`);
  }

  L.push('', '**4. Evidence strength.**', '');
  if (!shipped.length) {
    L.push('No findings were patched this run, so there is no evidence mix to report.');
  } else {
    const counts = new Map();
    for (const { f } of shipped) {
      const tier = contractOf(f).witness.tier;
      counts.set(tier, (counts.get(tier) || 0) + 1);
    }
    const rows = [...counts.entries()].sort((x, y) => y[1] - x[1]).map(([tier, n]) => [code(tier), n]);
    L.push(table(['witness tier', 'count'], rows));
    const argued = counts.get('argued') || 0;
    if (argued / shipped.length > 0.5) {
      L.push('', `Most patched findings fell back to the ${code('argued')} tier, meaning no mechanical `
        + 'check ran. That says something real about this repository, not about the fixes: treat '
        + 'these as human-reviewed, not machine-proven.');
    }
  }

  L.push('', '**5. Rejected findings.**', '');
  if (!b.rejected.size) {
    L.push('No findings were rejected as not exploitable this run.');
  } else {
    const rows = [...b.rejected.entries()].sort((x, y) => y[1].length - x[1].length)
      .map(([reason, list]) => [code(reason), list.length, list.map((f) => code(f.id)).join(', ')]);
    L.push(table(['reason', 'count', 'ids'], rows));
    const dig = b.rejected.get('defense_in_depth_gap_only');
    if (dig && dig.length) {
      L.push('', `${noun(dig.length, 'finding')} were rejected as ${code('defense_in_depth_gap_only')}: `
        + 'a control already on the path prevents the attack, so the missing second layer is a '
        + 'hardening note, not a vulnerability.');
    }
  }

  L.push('', '**6. Policy rejections.**', '');
  L.push('These findings were never sent to an agent. Path policy resolved them by matching test, '
    + 'vendor, generated, minified or migration code. This is a scope decision, not a claim that '
    + `the code is safe; ${code('--include-tests')} disables it.`, '');
  if (b.policyRejected.length) {
    const rows = b.policyRejected.map((f) => [code(f.id), boundaryFor(f),
      truncate(f.triage.refutation.explanation, 100)]);
    L.push(table(['id', 'matched', 'why'], rows));
  } else {
    L.push('No findings were rejected by path policy this run.');
  }

  L.push('', '**7. Below threshold.**', '');
  if (!b.belowThreshold.length) {
    L.push('No exploitable findings fell below the fix threshold this run.');
  } else {
    const rows = b.belowThreshold.map((f) => [code(f.id), code(f.triage.severity), titleFor(f), boundaryFor(f)]);
    L.push(table(['id', 'severity', 'title', 'boundary'], rows));
  }

  L.push('', '**8. Scanner disagreement.**', '');
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

  L.push('', '**9. Scanner-quiet status.**', '');
  if (!shipped.length) {
    L.push('No findings were patched this run, so there is no rescan status to report.');
  } else {
    const rows = shipped.map(({ f, last, ev }) => {
      if (ev.skipped.includes('no_new_findings')) return [code(f.id), 'rescan skipped at this verify level'];
      const rescan = (last.verification.no_new_findings || {}).rescan || {};
      const status = rescan.original_absent
        ? 'scanner is quiet on the original rule' : 'scanner still fires on the original rule';
      return [code(f.id), `${status} (observation only; the outcome above does not depend on this)`];
    });
    L.push(table(['id', 'original rule status'], rows));
  }

  return `${L.join('\n')}\n`;
}

// ---------------------------------------------------------------------- HANDOFF.md

function renderHandoff(findings, meta) {
  const required = requiredFor(meta);
  const b = classify(findings, meta);
  const L = [];

  L.push(`# Handoff: ${code(meta.target)}`, '');
  L.push(`Run ${code(meta.run_id)}, verify level ${code(meta.verify_level || 'unspecified')}. `
    + 'Everything below is something a human owns next.');
  if (meta.run_status === 'incomplete') {
    L.push('', `**This run is incomplete.** Reason: ${meta.incomplete_reason || 'not stated'}.`);
  }

  L.push('', '**Unfixable.**', '');
  if (!b.unfixable.length) {
    L.push('No finding exhausted its fix attempts this run.');
  } else {
    for (const { f, last, ev } of b.unfixable) {
      const patches = f.patches || [];
      const branch = last.branch || `sast-fix/${f.id}/${patches.length}`;
      L.push(`- ${code(f.id)} (${code(f.triage.severity)}): branch ${code(branch)}, `
        + `${noun(patches.length, 'attempt')} made. ${titleFor(f)}`);
      if (last.fix && last.fix.outcome === 'cannot_fix') {
        L.push(`  The fixer declined on the final attempt: ${last.fix.reason}`);
      } else {
        const witnessPath = last.fix && last.fix.witness_path;
        L.push(`  Red witness: ${witnessPath ? code(witnessPath) : 'none recorded'}.`);
        const auditText = ev.skipped.includes('hostile_auditor')
          ? 'not run at this verify level'
          : ((last.verification.hostile_auditor || {}).verdict || 'not recorded');
        L.push(`  Last audit verdict: ${code(auditText)}.`);
        L.push(`  Failed obligations: ${ev.failed.length
          ? ev.failed.map((n) => `${code(n)} (${failureDetail(last.verification, n)})`).join('; ')
          : 'none recorded'}.`);
      }
      if (patches.length > 1) {
        L.push(`  Earlier attempts: ${patches.slice(0, -1)
          .map((p, i) => attemptSummary(p, i, required)).join('; ')}.`);
      }
    }
  }

  L.push('', '**Undecidable.**', '');
  if (!b.undecidable.length) {
    L.push('No finding is undecidable this run.');
  } else {
    for (const f of b.undecidable) {
      L.push(`- ${code(f.id)}: ${f.triage.blocker.missing_fact}`);
      L.push(`  Resolve by ${code(f.triage.blocker.resolve_by)}: ${f.triage.blocker.plan}`);
      L.push('  This is a hypothesis, not a confirmed vulnerability, and carries no severity.');
    }
  }

  L.push('', '**Fixed but unwitnessed.**', '');
  if (!b.fixedUnwitnessed.length) {
    L.push('No finding landed on the argued tier this run.');
  } else {
    for (const { f, last } of b.fixedUnwitnessed) {
      const w = contractOf(f).witness;
      L.push(`- ${code(f.id)} (${code(f.triage.severity)}): ${titleFor(f)}`);
      L.push(`  Obstacle: ${code(w.obstacle)}. ${w.why}`);
      L.push(`  Branch: ${code(last.branch || `sast-fix/${f.id}/${(f.patches || []).length}`)}.`);
    }
  }

  L.push('', '**Split escalations.**', '');
  if (!b.splitEscalated.length) {
    L.push('No finding split twice this run.');
  } else {
    for (const f of b.splitEscalated) {
      const why = ((f.disposition && f.disposition.groups) || []).map((g) => g.why).join(' / ');
      L.push(`- ${code(f.id)}: proposed a second split. ${why}`);
    }
  }

  return `${L.join('\n')}\n`;
}

module.exports = { renderRemediation, renderHandoff };

if (require.main === module) {
  const fs = require('fs');
  const path = require('path');
  const [findingsFile, metaFile, outDir] = process.argv.slice(2);
  if (!findingsFile || !metaFile) {
    console.error('usage: report.cjs <findings.json> <meta.json> [outDir]');
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
