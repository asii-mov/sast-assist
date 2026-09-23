# Report

Derived from the final records. Each finding's saved `disposition` is its outcome, and the report
files the finding under that state and nothing else. The report never re-judges a patch. The
prose never changes a verdict, a severity or a demonstrated impact. If the prose and the JSON
disagree, the JSON is right and the report is broken.

## `REMEDIATION.md`

**1. Run header.** Scope, threshold, base commit, scanners and rule packs (the rescan
configuration, and a warning when a reused scan's rules may differ from it), budget spent against
planned, and whether the run is complete. A partial run says so in the first section.

**2. What changed.** Each `fixed` and `fixed_unwitnessed` finding's own branch, the unwitnessed
ones marked as such, and the one action the operator has left, which is to review and merge them.

**3. Fixed findings.** State `fixed`. One row each: severity, title, boundary, witness tier, audit
verdict, then the verify level and the obligations it skipped.

**4. Patched but unwitnessed.** State `fixed_unwitnessed`. The patch passed every check the run's
verify level asked for, but its witness tier is `argued`, so no check showed the attack stop.
Never listed under Fixed.

**5. Not fixed.** States `fix_declined` and `fix_failed`, with the branch when one exists and the
reason. A declined fix is terminal after one fixer call, so it never reads as mid-fix.

**6. Evidence strength.** Count patched findings by witness tier. A run where most contracts fell
back to `structural` or `argued` is telling you something real about the repository, and uniform
confidence would be a lie. Say it here.

**7. Rejected findings.** Grouped by refutation reason with counts. This is the rule-tuning
signal. `defense_in_depth_gap_only: 37` is something a security team can act on.

**8. Policy rejections, under their own heading.** Findings dropped by path policy are not
security claims. A vulnerability in test infrastructure is real and out of the requested scope.
Say which glob matched and note that `--include-tests` disables it.

**9. Below threshold.** Real findings the gate did not fix, with their severities.

**10. Scanner disagreement.** Where the scanners disagreed about severity or location, and where
only one scanner saw a finding. Useful and cheap, since the record already holds both claims.

**11. Scanner-quiet status.** Report `original_absent` per patched finding, clearly labelled as
an observation and not a verdict. A fix that is verified while the rule still fires is normal and
worth seeing.

## `HANDOFF.md`

Everything a human owns. For each entry give the contract, the trace, and what to do next.

**Not fixed.** States `fix_declined` and `fix_failed`. Give the branch when one exists, the
number of attempts, why the last one ended, the last audit verdict and the failed obligations.

**Undecidable.** The exact missing fact and the plan that resolves it. No severity. Never
presented as a confirmed vulnerability.

**Patched but unwitnessed.** The `argued` tier cases. State the obstacle plainly.

## Rules

Do not describe a rejected finding as a vulnerability. Do not assign a severity to anything that
is not `exploitable`. Do not claim coverage the scanners did not provide, and state which rule
packs ran. A clean run may have zero fixed findings, which is a result worth reporting plainly
rather than padding with low-severity noise.

A zero-result scanner run is reported as what it is. Either the code is clean or the flow left
the model, and the output cannot distinguish them. See `INGEST.md`.
