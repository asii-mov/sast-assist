# Phase A grounding: a skill system that triages, fixes and verifies SAST findings

## What we are building

A set of LLM skills (Claude Code / agent-neutral) that wrap existing Semgrep + CodeQL
scanning with: parallel false-positive triage, a severity threshold gate, automated
patching, and post-patch verification. The working directory
`/home/asiimov/Projects/code-scanning` is empty. This is greenfield. There is no
surrounding codebase to integrate with, so Phase A grounds in the **external
contracts** the design must honor: the two scanners' output formats, and the prior-art
skill the user pointed at.

## Constraint 1: the reference skill's security-audit skill is the prior art, but inverted

Read in full at `github.com/reference/security-audit-skill` (22 files, ~5.4k lines).
Six phases run in order. Reconnaissance, then coverage-led hunting, then candidate
validation, then structured output, then independent record verification, then
target-neutral reporting.

**The inversion that matters.** the reference skill's skill *generates* findings: LLM hunter
agents read source and propose vulnerabilities, and the expensive machinery
(coverage ledger, hunting waves, coverage critics) exists to answer "did we look
everywhere?" Our problem is the opposite. Semgrep and CodeQL already answered "did we
look everywhere" deterministically. Our expensive question is "which of these hundreds
of findings are real, and can we fix them without breaking the build?"

So the mapping is:

| the reference phase | Our system |
|---|---|
| 1. Reconnaissance + coverage ledger | **Replaced** by the scanners. Coverage is the rule packs that ran. |
| 2. Coverage-led hunting waves | **Replaced** by scan ingestion + normalization + dedup. |
| 3. Candidate validation (fresh verifier tries to refute) | **Reused almost verbatim**. This *is* false-positive triage. |
| 4. Structured output + zero-dep validator | **Reused**, schema as a hard gate. |
| 5. Independent record verification | **Reused**, narrowed to records that cross the fix threshold. |
| 6. Target-neutral reporting | **Reused**, extended with patch outcomes. |
| *(none, CF explicitly refuses to patch)* | **New: fix + verify.** This is our novel surface. |

the reference skill's SKILL.md states the boundary explicitly: *"The audit describes fixes; it
does not modify target source."* Everything about applying, verifying, and rolling back
a patch is design space the prior art does not cover. We inherit no shape there.

### Patterns worth stealing, named

- **Adversarial validation.** "The agent that checks a finding is never the agent that
  found it." For us: the triage agent must be told to *refute*, not to *assess*. An
  agent asked "is this a true positive?" anchors on the scanner's claim. An agent told
  "disprove this" produces a usable verdict.
- **Three verdicts, not a boolean.** `confirmed` / `needs_validation` / `rejected`.
  `needs_validation` carries "an exact unresolved fact" and *has no severity*. This is
  the single most important borrowed idea for a triage pipeline: the failure mode of
  naive FP filtering is forcing a binary call on a finding whose decisive fact
  (a deployment config, a framework's default, a caller outside the repo) isn't in the
  source. A binary filter either drops a real bug or ships a noisy false alarm.
- **Stable fingerprints across state changes.** One record per root cause, preserved
  through every verdict transition. This is what makes runs additive and makes
  "don't re-triage what we already rejected" possible.
- **Parent is the sole writer of shared state.** Each subagent gets
  `agents/<id>/scratch/`; agents never write shared files or each other's files.
  Directly relevant: N parallel triage agents writing one findings file is a data race.
- **Schema + zero-dependency validator as a hard gate** (`report-schema.json`,
  `validate-findings.cjs`, run after every write). Structured agent output that is only
  *asked for* in a prompt is not structured output. the reference skill's rule: discard a
  malformed or prose-wrapped agent result, never repair it, re-run with a fresh agent.
- **Severity requires demonstrated impact**, and "overall severity cannot exceed
  demonstrated impact." Their anchors (`critical`, `high`, `medium`, `low` and `informational`) are
  written against *observed results*, not rule categories. Our threshold gate is only
  as good as the severity it gates on, see Constraint 3.
- **Defense-in-depth gaps are not vulnerabilities.** A large fraction of SAST noise is
  exactly this: the rule fires on a missing Layer B while Layer A already prevents the
  attack. This belongs in the triage rubric as a named rejection reason.
- **Multiple runs improve coverage; prior runs are inputs.** Prior `rejected` suppresses
  only the unchanged claim; changed source reopens it.

### Patterns to deliberately *not* carry over

- The coverage ledger and coverage-critic waves. Our coverage claim is "these rule packs
  ran against this commit," which is a scanner fact, not an LLM judgment. Importing the
  ledger would be ceremony over a question we already have a deterministic answer to.
- The 11-step `fstat`-based artifact promotion procedure, copied verbatim into every
  prompt. It exists because their hunters execute target-controlled fuzzers and parsers.
  Our triage agents read source and our verification runs the project's own test suite.
  The sandboxing *principle* carries; that specific ritual is a cost we should not pay
  unless the design actually executes untrusted target code.
- Recon/hunting prompts and the domain attack-class companion files. Those are for
  finding vulnerabilities. The scanners find ours.

## Constraint 2: the two scanners emit different shapes (verified against current docs)

**Semgrep** (`/semgrep/semgrep-docs`, verified): `semgrep scan --json --json-output=f.json`
and `--sarif --sarif-output=f.sarif`; both can be emitted in one run. Per-result JSON
shape:

- `check_id`, `path`, `start` and `end`, each with `line`, `col` and `offset`
- `extra.severity`: `ERROR` | `WARNING` | `INFO`
- `extra.metadata.likelihood` / `.impact` / `.confidence`: `LOW` | `MEDIUM` | `HIGH`
- `extra.metadata.cwe[]`, `.owasp[]`, `.category`, `.vulnerability_class[]`, `.subcategory[]`
- `extra.fingerprint`, `extra.lines` (the source line), `extra.metavars` (bound pattern vars)
- `extra.is_ignored`, `extra.engine_kind` (`OSS` | `PRO`)
- Canonical schema: `semgrep/semgrep-interfaces/semgrep_output_v1.jsonschema`

Note `extra.severity` is *not* the same axis as `metadata.impact`. Semgrep's own
security metadata already carries a likelihood x impact x confidence triple, the same
decomposition the reference skill's severity model uses. A threshold built on `extra.severity`
alone throws that away.

**CodeQL** (`/github/codeql`, verified): `codeql database analyze --format=sarif-latest
--output=results <db> <pack-or-suite>`; query packs and suites are named
(`codeql/cpp-queries:codeql-suites/cpp-security-and-quality.qls`), optionally with
semver ranges. Output is SARIF 2.1.0 only. Severity lives in the rule's property bag as
`problem.severity`, one of `error`, `warning` or `recommendation` and `security-severity`
(a CVSS-style 0-10 float). `--sarif-run-property` can stamp run-level key/values.

**The load-bearing asymmetry**: CodeQL SARIF carries `codeFlows`/`threadFlows`, the
full taint path from source to sink. Semgrep Pro carries a dataflow trace; Semgrep OSS
often does not. Triage quality depends almost entirely on whether the agent sees the
*path* or only the sink line. A design that normalizes to "file + line + message" has
thrown away the most decision-relevant evidence before triage starts.

## Constraint 3: "medium and above" is not a field either scanner emits

The user's threshold ("fix medium and above") has to be computed. Three incompatible
vocabularies are in play:

- Semgrep `extra.severity`: 3 levels, ERROR/WARNING/INFO
- Semgrep `metadata.impact` x `likelihood` x `confidence`: 3x3x3
- CodeQL `security-severity`: continuous 0-10; GitHub's published cut points are
  <4.0 low, 4.0-6.9 medium, 7.0-8.9 high, >=9.0 critical
- CodeQL `problem.severity`: 3 levels, `error`, `warning` and `recommendation`

Whether the threshold is applied to the *scanner's* claimed severity or to the
*triage agent's* post-validation severity is a real fork in the design, with different
consequences. Applying it pre-triage saves agent spend but gates on the number the
scanner guessed. And scanner severity is rule-category severity, not
instance-severity. Applying it post-triage costs a triage pass on every INFO finding.
Candidates should take an explicit position and defend it.

## Constraint 4: verification has two distinct obligations that are easy to conflate

The user said: "Once the fix is in we need to verify that it still works." That is one
sentence hiding two questions:

1. **Does the code still work?**, the project's build/tests/type-check still pass.
   Regression safety.
2. **Is the vulnerability actually gone?**, the finding no longer fires, *and* it
   stopped firing because the invariant is now enforced, not because the patch moved
   the code out of the rule's pattern.

(2) has a nasty failure mode that a naive "re-run the scanner, finding gone, done" loop
rewards directly: the cheapest way to silence a SAST rule is to defeat its pattern
matcher. Renaming a variable, adding an indirection, or inserting a nosemgrep comment
all make the finding disappear without fixing anything. Any verification design that
uses "scanner is quiet" as its success signal is training the fixer to do this. There is
also a third obligation nobody asks for until it bites: the patch must not introduce
*new* findings.

## Constraint 5: platform mechanics

- Skills are `SKILL.md` + reference files, loaded progressively; frontmatter `name` +
  `description` drive triggering. the reference skill's skill splits ~5.4k lines across 22 files
  so a run loads only the companions it selected.
- Parallel subagents are spawned in a single message, each with its own prompt and
  isolated working area. Subagent results return to the parent; subagents do not share
  context with each other. Fan-out is the natural fit for per-finding triage.
- the reference skill's skill ships Node.js zero-dependency validators. Zero-dep matters: the
  skill must run in a target repo without installing anything into it.
- Operating-mode split (guidance vs. Full run) prevents a skill from creating
  directories and running a 6-phase workflow when someone asked a question.

## The design questions a candidate must answer

1. What is the unit of state that flows through the pipeline, and what does it look like
   after ingestion, after triage, after patching, after verification?
2. Is this one skill or several, and if several, where are the seams?
3. Pre-triage or post-triage threshold gate?
4. How is normalization done such that the taint path survives into the triage prompt?
5. What makes the fixer unable to "fix" by defeating the pattern matcher?
6. What is the contract for rollback and failure when verification fails, and what stops the
   fix-verify loop from spinning?
7. Cross-scanner dedup: Semgrep and CodeQL flag the same SQL injection. One fingerprint
   or two? Triaged once or twice?
