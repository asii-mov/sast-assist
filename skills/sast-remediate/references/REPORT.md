# Report

Derived from the final records. The prose never changes a verdict, a severity or a demonstrated
impact. If the prose and the JSON disagree, the JSON is right and the report is broken.

## `REMEDIATION.md`

**1. Run header.** Scope, threshold, base commit, scanners and rule packs, budget spent against
planned, and whether the run is complete. A partial run says so in the first section.

**2. What changed.** The integration branch, the commit count, and the one action the operator
has left, which is to review and merge it.

**3. Fixed findings.** One row each: severity, title, boundary, witness tier, audit verdict.

**4. Evidence strength.** Count findings by witness tier. A run where most contracts fell back to
`structural` is telling you something real about the repository, and uniform confidence would be
a lie. Say it here.

**5. Rejected findings.** Grouped by refutation reason with counts. This is the rule-tuning
signal. `defense_in_depth_gap_only: 37` is something a security team can act on.

**6. Policy rejections, under their own heading.** Findings dropped by path policy are not
security claims. A vulnerability in test infrastructure is real and out of the requested scope.
Say which glob matched and note that `--include-tests` disables it.

**7. Below threshold.** Real findings the gate did not fix, with their severities.

**8. Scanner disagreement.** Where the scanners disagreed about severity or location, and where
only one scanner saw a finding. Useful and cheap, since the record already holds both claims.

**9. Scanner-quiet status.** Report `original_absent` per fixed finding, clearly labelled as an
observation and not a verdict. A fix that is verified while the rule still fires is normal and
worth seeing.

## `HANDOFF.md`

Everything a human owns. For each entry give the contract, the trace, and what to do next.

**Unfixable.** Two attempts failed. Give the retained branch, the red witness path, the last
audit verdict and the typed failures.

**Undecidable.** The exact missing fact and the plan that resolves it. No severity. Never
presented as a confirmed vulnerability.

**Fixed but unwitnessed.** The `argued` tier cases. State the obstacle plainly.

**Split escalations.** Findings that split twice.

## Rules

Do not describe a rejected finding as a vulnerability. Do not assign a severity to anything that
is not `exploitable`. Do not claim coverage the scanners did not provide, and state which rule
packs ran. A clean run may have zero fixed findings, which is a result worth reporting plainly
rather than padding with low-severity noise.

A zero-result scanner run is reported as what it is. Either the code is clean or the flow left
the model, and the output cannot distinguish them. See `INGEST.md`.
