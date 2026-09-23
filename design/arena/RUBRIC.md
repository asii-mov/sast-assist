# Arena rubric — SAST triage/fix/verify skill design

Written before any candidate was read. Six criteria, scored 1-5.
(Restored verbatim after the scratchpad wipe; this text is unchanged from the original.)

## C1. Record type quality (weight: highest)
The thing that flows ingest -> triage -> gate -> fix -> verify. Score high when:
- One record per root cause, stable fingerprint preserved across every state transition.
- Later stages never re-derive what earlier stages established (the taint path survives
  from SARIF into the fix prompt without a second read of the scanner output).
- State transitions are idempotent and the run is resumable after a crash mid-fix.
- Verdict vocabulary is richer than a boolean and handles the "decisive fact is not in
  source" case without forcing a wrong call.
Score low when: the record is a bag of scanner fields; separate types per stage with
lossy hand-offs; resumability unaddressed; triage verdict is true/false.

## C2. Anti-pattern-defeat (the Constraint 4 failure mode)
Does the design structurally prevent a fixer from silencing the rule instead of fixing
the bug? Score high for a mechanism with teeth: an invariant stated before the patch is
written and checked after, adversarial review by an agent that did not write the patch,
suppression-comment and diff-shape detection, a regression test that fails pre-patch and
passes post-patch. Score low for "the verify agent checks the fix is real" with no
mechanism, or for treating a quiet re-scan as sufficient.

## C3. Threshold + normalization rigor
Takes an explicit, defended position on pre- vs post-triage gating. Handles three
incompatible severity vocabularies (Semgrep ERROR/WARNING/INFO, Semgrep
impact x likelihood x confidence, CodeQL security-severity 0-10, CodeQL problem.severity)
with a stated mapping. Does not silently gate on the scanner's rule-category severity
while claiming to gate on instance severity. Cross-scanner dedup answered concretely.

## C4. Interface depth (per design-red-flags.md)
Small operator surface hiding substantial machinery. One entry point that runs the whole
thing with sane defaults beats nine hand-orchestrated stages. Penalize shallow modules,
pass-through layers, temporal decomposition (modules named for pipeline stages that each
re-handle the same representation), and wire types (raw SARIF) on the public surface.

## C5. Prior-art judgment
Steals what transfers from the reference skill (adversarial validation, three verdicts,
fingerprints, parent-sole-writer, schema-as-gate, severity-requires-impact) and drops
what does not (coverage ledger, hunting waves, the fstat promotion ritual) — with
reasons stated, not silently. Penalize both cargo-culting all six phases and ignoring
the prior art's hard-won lessons.

## C6. Buildability as skills
Is this actually a Claude Code / agent-neutral skill tree? Progressive disclosure,
sane file split, subagent prompt contracts specified as contracts (what goes in, what
shape must come back, what happens to malformed output), zero-dependency validators,
guidance-vs-full-run mode split, and a believable story for write isolation across N
parallel triage agents. Penalize a design that is really a Python service wearing a
skill costume, unless it argues that case convincingly.

## Tie-break
Per the Laziness Protocol: prefer the cleaner boundary and smaller API. Then prefer the
candidate a maintainer can extend (new scanner, new language, new verify strategy)
without touching the core record type.
