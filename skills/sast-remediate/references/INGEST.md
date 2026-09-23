# Ingest

Everything this system knows about scanner wire formats lives here and in `bin/normalize.ts`.
SARIF, `extra.metavars`, `partialFingerprints` and `security-severity` floats stop at this
boundary. Nothing downstream imports a scanner type.

## Running the scanners

Semgrep writes two formats in one run. One primary flag plus `--<fmt>-output=` for the rest.
Passing `--json` and `--sarif` together is an error.

```sh
semgrep scan --config <each --semgrep-config value, default p/default> \
  --json-output=<out>/scans/semgrep.json \
  --sarif-output=<out>/scans/semgrep.sarif <target>
```

CodeQL needs a database per language, then an analyze pass per database. `detectLanguages` in
`bin/scan.ts` picks the languages from the source files it finds (a bounded walk that skips
`node_modules`, `vendor`, build output and dot directories), plus `actions` when
`.github/workflows` holds a workflow. A root marker such as `package.json` alone does not count,
because `codeql database create` fails on a language with no code. Each language's SARIF is
merged into one `codeql.sarif` with one run per language. A language that fails is recorded and
the others still count. The rescan of a patch reuses the baseline's languages. Use
`--sarif-add-snippets` so results carry their source text.

```sh
codeql database create <out>/scans/codeql-db-<lang> --language=<lang> --source-root=<target> --overwrite
codeql database analyze <out>/scans/codeql-db-<lang> \
  --format=sarif-latest --output=<out>/scans/codeql-<lang>.sarif --sarif-add-snippets \
  'codeql/<lang>-queries:codeql-suites/<lang>-<--codeql-suite, default security-extended>.qls'
```

The rescan in `bin/scan.ts` runs these same commands with the run's recorded configuration.

`normalize.ts` reads Semgrep's JSON, not its SARIF, because the JSON carries
`extra.metadata.likelihood`, `.impact` and `.confidence`, which the SARIF flattens away.

## Zero results does not mean clean

**This is the most important operational fact in this file.** A scanner that reports nothing is
either telling you the code is clean or telling you the flow left its model, and the output does
not distinguish the two.

Measured on this skill's own fixture with CodeQL 2.26.4. The same command injection, with the
same source and the same sink, in one file:

```js
exec(req.url);                                                    // reported
const h = new URL(req.url, 'http://x').searchParams.get('host');
exec(`ping -c 1 ${h}`);                                           // NOT reported
const q = url.parse(req.url, true).query;
exec(`ping -c 1 ${q.host}`);                                      // reported, 5-step flow
```

Taint does not propagate through `new URL(...).searchParams.get()` in that version. It does
propagate through `url.parse(..., true).query`. Nothing in the SARIF says a step was missed.

Two consequences. Never present a clean CodeQL run as evidence of absence. And when a run
returns zero on code you expect to be flagged, suspect the taint model before you conclude the
code is safe. Dynamic dispatch through an object literal and taint crossing an unmodeled helper
both produce silent zeros.

## What normalization establishes

Validate here, trust the types after. Nothing downstream re-checks these.

Every `file` is repository-relative, POSIX-separated, does not escape the root, and exists at the
scanned commit. Anything else is dropped and counted. Every `id` is unique. A `traced` flow
starts at a source and ends at a sink. Every site has at least one observation.

## Identity

`id` is `f_` plus the first 16 hex of a sha256 over the invariant class, the callee, the anchor
file and the sink digest. The `sink_digest` is a sha256 of the sink line with inner whitespace
collapsed.

Two properties, both deliberate. It is **stable under reformatting** because whitespace is
collapsed and line numbers are excluded, so a formatter run does not invent findings and prior
verdicts carry. It is **unstable under a rename at the sink** because identifiers are preserved,
so `exec(cmd)` becoming `exec(safeCmd)` yields a different id.

That instability is the conservative direction and it is load-bearing. A rename must never
inherit a prior `not_exploitable`. It is also why a frozen triage never needs unfreezing. Changed
source produces a new record with a `prior` link, so reopening is a new record rather than a
mutated one.

Never use `extra.fingerprint` or `partialFingerprints` as identity. They differ per scanner, per
engine tier and across version bumps. They are retained inside the observation so the report can
tell a rule owner which of their results were rejected.

## The two folds

**FOLD 1, cross-scanner within a locus.** Two raw results become one site when the file and the
invariant class match, and either the sink digests are identical or the lines are within two of
each other under the same non-null enclosing symbol.

The proximity arm is not theoretical. On the fixture, CodeQL reports path injection at the
`fs.readFile` sink on line 10 while Semgrep reports it at the `path.join` on line 9. Same bug,
different idea of where it lives.

The arm requires a resolved symbol on both sides. Without one, triage twice rather than merge two
different bugs into one contract.

**FOLD 2, cross-site root cause.** Sites become one finding when the invariant class and the
callee match and the callee resolved. Forty call sites of one unsafe helper are one root cause,
one contract, one patch, one witness, one commit. This is the cost lever that makes gating after
triage affordable. An unresolved callee never clusters.

A triage agent that finds two sites need different enforcement points returns a `split`, and the
parent re-emits them as separate findings. One split per finding per run.

## Severity stays in the scanner's own words

Four vocabularies are in play and no meaning-preserving mapping exists between them. Semgrep's
`ERROR`/`WARNING`/`INFO`, Semgrep's likelihood-impact-confidence triple, CodeQL's continuous
`security-severity`, and CodeQL's `problem.severity`. Any single collapsed enum is a lie that
every consumer downstream would then trust.

So each claim is kept in its own vocabulary and exactly two things read it. `priority()`, which
only orders. And the report, which prints both claims beside our instance severity.

Ranking on `extra.severity` alone inverts real findings. Measured on the fixture,
`detect-child-process` is `ERROR` with likelihood `LOW`, and `path-join-resolve-traversal` is
`WARNING` with likelihood `HIGH`. The rule-category severity ranks the less likely finding
higher. `claimedRank` prefers the metadata triple when present for exactly this reason.

## The flow

`TaintFlow` has two constructors and the triage prompt switches on which one it got. There is no
path field that is sometimes empty.

`traced` carries ordered steps, each with its source line materialized at ingest by the parent.
For a nine-step CodeQL threadFlow this is the difference between a prompt the agent reasons over
and a scavenger hunt it abandons.

`sink_only` means no scanner produced a path. Semgrep OSS produces none, verified on the fixture,
so this is the common case rather than the exception.

Selection prefers the most steps, then CodeQL over Semgrep. A flow is never fabricated.
