#!/usr/bin/env node
// A triage agent that finds a finding's sites need different enforcement points returns a split
// instead of a verdict. The parent becomes one child finding per part, triaged in the same run.
// A child knows its parent, so a child that asks to split again goes to a human instead.

import type { FindingRecord } from './stage.ts';
import type { SplitGroup, SplitResult } from './normalize.ts';

type Split = (parentId: string, groups: SplitGroup[]) => SplitResult<FindingRecord>;

// Settles the parent and returns its children, or the reason the split is invalid, in which
// case the parent is left untouched so the next run asks again.
function applySplit(f: FindingRecord, groups: SplitGroup[], split: Split): { children: FindingRecord[] } | { failed: string } {
  if (f.split_from) {
    f.disposition = { state: 'deferred', reason: 'split_again', split_from: f.split_from, groups };
    return { children: [] };
  }
  const r = split(f.id, groups);
  if (!r.ok) return { failed: `invalid_split: ${r.reason}` };
  f.disposition = {
    state: 'split',
    children: r.children.map((c, i) => ({
      id: c.id, site_lines: [...new Set(c.sites.map((s) => s.locus.line_at_scan))], why: groups[i].why,
    })),
  };
  return { children: r.children };
}

export type { Split };
export { applySplit };
