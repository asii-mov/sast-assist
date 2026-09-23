#!/usr/bin/env node
'use strict';
// What one run leaves for the next, and how the next one picks it up. Re-running the command is
// the resume path, so every function here answers "what if the last run stopped here?"

const fs = require('fs');
const path = require('path');
const os = require('os');
const { VERIFY_LEVELS } = require('./stage.cjs');
const { trim, parseScanConfig } = require('./scan.cjs');

const readJson = (f) => JSON.parse(fs.readFileSync(f, 'utf8'));

// The latest run of this target is continued while it is unfinished and was started on the
// same commit. A finished run has nothing left to resume, and an unfinished run of other code
// holds triage and branches that describe a different tree.
function defaultOutDir(target, base, root = path.join(os.homedir(), 'sast-remediate')) {
  const dir = path.join(root, path.basename(target));
  const nums = fs.existsSync(dir)
    ? fs.readdirSync(dir).map((d) => /^run-(\d+)$/.exec(d)).filter(Boolean).map((m) => Number(m[1]))
    : [];
  if (!nums.length) return path.join(dir, 'run-1');
  const latest = Math.max(...nums);
  const latestDir = path.join(dir, `run-${latest}`);
  let meta = {};
  try { meta = readJson(path.join(latestDir, 'run-metadata.json')) || {}; } catch { /* died before writing it */ }
  const sameBase = meta.base_commit === undefined || meta.base_commit === base;
  return meta.run_status !== 'complete' && sameBase ? latestDir : path.join(dir, `run-${latest + 1}`);
}

// Read back what the run was started with, so a resume rescans the same way it verified before.
function readRecorded(metaFile) {
  let m = null;
  try { m = readJson(metaFile); } catch { /* a fresh run */ }
  m = m || {};
  return {
    level: Object.hasOwn(VERIFY_LEVELS, m.verify_level) ? m.verify_level : null,
    scanConfig: parseScanConfig(m.scan_config),
  };
}

// Records written before a failed agent call became retryable carry it as an outcome. Reopen
// them, so a call that died on a rate limit is asked again instead of standing as a verdict.
function reopenAgentFailure(r) {
  const d = r.disposition;
  if (d && d.state === 'deferred' && d.reason === 'triage_agent_failed') return { ...r, disposition: null };
  if (d && d.state === 'fix_failed' && d.outcome === 'agent_failed') {
    return { ...r, disposition: null, patches: (r.patches || []).slice(0, -1) };
  }
  return r;
}

// Records already on disk win, so triage, gate and patches survive a re-run and stageOf decides
// what each record still needs. This is the whole of resume.
function mergeExisting(findings, outDir) {
  const dir = path.join(outDir, 'findings');
  if (!fs.existsSync(dir)) return 0;
  const prior = new Map();
  for (const file of fs.readdirSync(dir)) {
    if (!file.endsWith('.json')) continue;
    try { const r = readJson(path.join(dir, file)); prior.set(r.id, r); } catch { /* a truncated record is re-derived */ }
  }
  let n = 0;
  findings.forEach((f, i) => {
    if (!prior.has(f.id)) return;
    const p = reopenAgentFailure(prior.get(f.id));
    findings[i] = { ...f, triage: p.triage, gate: p.gate, patches: p.patches || [], disposition: p.disposition, prior: p.prior };
    n++;
  });
  return n;
}

// A run that died between creating an attempt's branch and saving its record left both behind,
// and `worktree add -b` refuses an existing branch or directory. No record names that attempt,
// so its leftovers go and the attempt starts again from base. Each step makes something absent,
// so a failing step means it already was.
function clearAttempt(git, branch, wt) {
  git(['worktree', 'remove', '--force', '--force', wt]);
  fs.rmSync(wt, { recursive: true, force: true });
  git(['worktree', 'prune']);
  git(['branch', '-D', branch]);
}

// Every reason the run is not finished, so a budget stop and a failed agent call never read alike.
function incompleteReason({ degraded, unresolved, budget, deferred, failures }) {
  const parts = [];
  if (degraded) parts.push(`${degraded}: ${unresolved} finding(s) left without a terminal disposition`);
  if (deferred) parts.push(`max_findings=${budget} reached, ${deferred} finding(s) deferred to the next run`);
  if (failures.length) {
    parts.push(`agent_failed: ${failures.length} agent call(s) failed and will be retried on the next run (`
      + `${failures.map((x) => `${x.id} ${x.stage}: ${trim(x.reason)}`).join(', ')})`);
  }
  if (!parts.length && unresolved) parts.push(`${unresolved} finding(s) left without a terminal disposition`);
  return parts.length ? parts.join('; ') : null;
}

module.exports = { defaultOutDir, readRecorded, reopenAgentFailure, mergeExisting, clearAttempt, incompleteReason };
