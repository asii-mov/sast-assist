#!/usr/bin/env node
// What one run leaves for the next, and how the next one picks it up. Re-running the command is
// the resume path, so every function here answers "what if the last run stopped here?"

import fs from 'fs';
import path from 'path';
import os from 'os';
import { trim, parseScanConfig } from './scan.ts';
import { isVerifyLevel } from './stage.ts';
import { isRecord } from './validate.ts';
import type { FindingRecord, VerifyLevel } from './stage.ts';
import type { ScanConfig, SyncExec } from './scan.ts';

const readJson = (f: string): unknown => JSON.parse(fs.readFileSync(f, 'utf8'));

// The latest run of this target is continued while it is unfinished and was started on the
// same commit. A finished run has nothing left to resume, and an unfinished run of other code
// holds triage and branches that describe a different tree.
function defaultOutDir(target: string, base: string | null, root = path.join(os.homedir(), 'sast-remediate')) {
  const dir = path.join(root, path.basename(target));
  const nums = fs.existsSync(dir)
    ? fs.readdirSync(dir).map((d) => /^run-(\d+)$/.exec(d)).filter((m) => m !== null).map((m) => Number(m[1]))
    : [];
  if (!nums.length) return path.join(dir, 'run-1');
  const latest = Math.max(...nums);
  const latestDir = path.join(dir, `run-${latest}`);
  let meta: { base_commit?: string; run_status?: string } = {};
  try {
    const m = readJson(path.join(latestDir, 'run-metadata.json'));
    if (isRecord(m)) {
      meta = {
        base_commit: typeof m.base_commit === 'string' ? m.base_commit : undefined,
        run_status: typeof m.run_status === 'string' ? m.run_status : undefined,
      };
    }
  } catch { /* died before writing it */ }
  const sameBase = meta.base_commit === undefined || meta.base_commit === base;
  return meta.run_status !== 'complete' && sameBase ? latestDir : path.join(dir, `run-${latest + 1}`);
}

// Read back what the run was started with, so a resume rescans the same way it verified before.
function readRecorded(metaFile: string): { level: VerifyLevel | null; scanConfig: ScanConfig | null } {
  let m: unknown = null;
  try { m = readJson(metaFile); } catch { /* a fresh run */ }
  if (!isRecord(m)) m = {};
  const r = m as Record<string, unknown>;
  return {
    level: typeof r.verify_level === 'string' && isVerifyLevel(r.verify_level) ? r.verify_level : null,
    scanConfig: parseScanConfig(r.scan_config),
  };
}

// Records written before a failed agent call became retryable carry it as an outcome. Reopen
// them, so a call that died on a rate limit is asked again instead of standing as a verdict.
function reopenAgentFailure(r: FindingRecord): FindingRecord {
  const d = r.disposition;
  if (d && d.state === 'deferred' && d.reason === 'triage_agent_failed') return { ...r, disposition: null };
  // `agent_failed` is an outcome only older runs wrote, so it is compared as a plain string.
  if (d && d.state === 'fix_failed' && (d.outcome as string | null) === 'agent_failed') {
    return { ...r, disposition: null, patches: (r.patches || []).slice(0, -1) };
  }
  return r;
}

// Records already on disk win, so triage, gate and patches survive a re-run and stageOf decides
// what each record still needs. This is the whole of resume.
function mergeExisting(findings: FindingRecord[], outDir: string): number {
  const dir = path.join(outDir, 'findings');
  if (!fs.existsSync(dir)) return 0;
  const prior = new Map<string, FindingRecord>();
  for (const file of fs.readdirSync(dir)) {
    if (!file.endsWith('.json')) continue;
    // These are this skill's own saved records, so they are trusted as written rather than re-validated.
    try { const r = readJson(path.join(dir, file)) as FindingRecord; prior.set(r.id, r); } catch { /* a truncated record is re-derived */ }
  }
  let n = 0;
  findings.forEach((f, i) => {
    const saved = prior.get(f.id);
    if (!saved) return;
    const p = reopenAgentFailure(saved);
    findings[i] = { ...f, triage: p.triage, gate: p.gate, patches: p.patches || [], disposition: p.disposition, prior: p.prior };
    n++;
  });
  return n;
}

// A run that died between creating an attempt's branch and saving its record left both behind,
// and `worktree add -b` refuses an existing branch or directory. No record names that attempt,
// so its leftovers go and the attempt starts again from base. Each step makes something absent,
// so a failing step means it already was.
function clearAttempt(git: (args: string[]) => unknown, branch: string, wt: string): void {
  git(['worktree', 'remove', '--force', '--force', wt]);
  fs.rmSync(wt, { recursive: true, force: true });
  git(['worktree', 'prune']);
  git(['branch', '-D', branch]);
}

// Every reason the run is not finished, so a budget stop and a failed agent call never read alike.
type AgentFailure = { id: string; stage: string; reason: string };

function incompleteReason({ degraded, unresolved, budget, deferred, failures }: {
  degraded: string | null; unresolved: number; budget: number; deferred: number; failures: AgentFailure[];
}): string | null {
  const parts: string[] = [];
  if (degraded) parts.push(`${degraded}: ${unresolved} finding(s) left without a terminal disposition`);
  if (deferred) parts.push(`max_findings=${budget} reached, ${deferred} finding(s) deferred to the next run`);
  if (failures.length) {
    parts.push(`agent_failed: ${failures.length} agent call(s) failed and will be retried on the next run (`
      + `${failures.map((x) => `${x.id} ${x.stage}: ${trim(x.reason)}`).join(', ')})`);
  }
  if (!parts.length && unresolved) parts.push(`${unresolved} finding(s) left without a terminal disposition`);
  return parts.length ? parts.join('; ') : null;
}

export type { AgentFailure };
export { defaultOutDir, readRecorded, reopenAgentFailure, mergeExisting, clearAttempt, incompleteReason };
