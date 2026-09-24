# R4. Leak guard precision and multi-language CodeQL

## 1. Plain-language summary

The tool refuses to hand the fixing agent anything that names the scanner or the rule, so the agent cannot cheat by dodging the rule. That check is too eager. It reads the target's own source code as if the triage agent had written it, so ordinary lines like `uses: actions/setup-node@v4` or a folder called `docs/semgrep-notes` get a finding refused. The schema has the same fault. It rejects the plain English words "alert", "warning" and "finding", and any chain like `req.params.user.id`. This unit narrows both checks so they only catch real leaks. It also makes CodeQL scan every language in the repository instead of only the first one it spots.

## 2. Problem, with evidence

All paths are relative to `skills/sast-assist/`. All line numbers were checked against the current tree.

### 2a. The runtime guard reads repository source as if the triage agent wrote it

- `bin/run.cjs:413-414` defines `RULE_ID_FORM`, a regex for the shape of a CodeQL rule id (`js/...`, `actions/...`).
- `bin/run.cjs:416-428` `leakTerms(finding)` returns `SCANNERS` (`['semgrep','codeql']`, defined at `bin/run.cjs:52`), plus each observation's `scanner`, `rule_id`, `rule_name`, `native_fingerprint` and `message`.
- `bin/run.cjs:434-440` `assertNoLeak(prompt, finding)` runs both checks against the WHOLE prompt string.
- `bin/run.cjs:373-407` `buildFixPrompt` puts repository text into that prompt: `flowBlock(f.flow)` (source lines), `f.context.enclosing_excerpt` (up to a dozen lines around the sink), file paths, and the build, test and lint commands.
- `bin/run.cjs:474` (fixer) and `bin/run.cjs:693` (auditor) call `leakError(prompt, f)`. The auditor prompt also carries the patch diff and the fixer's `enforcement_note`.

Probed over-matches, measured by reading the regex:

| Text in the excerpt | Why it trips |
|---|---|
| `uses: actions/setup-node@v4` | `actions/setup-node` matches `RULE_ID_FORM`; the lookahead only excludes `.ext` |
| `/static/js/admin-panel/main.js` | `js/admin-panel` matches; the next char is `/`, not `.ext` |
| `./go/some-pkg/util` | `go/some-pkg` matches |
| `docs/semgrep-notes` | the scanner name `semgrep` is in `leakTerms` |
| `uses: github/codeql-action/init@v3` | the scanner name `codeql` is in `leakTerms` |
| `// this route requires login` | Semgrep writes the placeholder `"requires login"` as `extra.fingerprint` for every result, and `bin/normalize.cjs:152` stores it as `native_fingerprint` |

On-disk evidence for the last row: every Semgrep observation in `.work/targets/run-full4/findings/*.json` has `native_fingerprint: "requires login"` (measured).

A GitHub Actions run-shell-injection finding sits in a workflow file, and its excerpt almost always holds a `uses: actions/setup-*` line, so today it is always refused with `fixer_prompt_leak`.

A probe this session built a CodeQL `actions` database on a one-file workflow (`uses: actions/setup-node@v4` then `run: echo "${{ github.event.comment.body }}"`) and got `actions/code-injection/critical` and `actions/missing-workflow-permissions` (measured). Real Actions rule ids have three segments, so the runtime form cannot be tightened by refusing a following `/`.

### 2b. The schema rejects ordinary invariant prose

`schema/finding.schema.json:270` is the `invariant` `not.pattern`. It contains:

- `\bwarning\b|\bfinding\b|\balert\b`. These reject "the warning banner text must not carry markup", "each finding id in the URL must belong to the caller", "a field named alert".
- `\b[a-z][a-z0-9_]*(?:\.[a-z0-9_-]+){3,}\b`. It was added to catch dotted Semgrep ids, but it also rejects `req.params.user.id` and hostnames like `api.my-service.example.com`.
- The slash form `\b(?:js|...|actions)/[a-z0-9]+(?:-[a-z0-9]+)*(?:/[a-z0-9-]+)*\b` has no lookbehind. It rejects `src/go/util.go`, `./go/some-pkg/util` and `uses: actions/setup-node@v4`.

A rejected contract fails triage validation. Triage is retried once and then the finding is parked (deferred), so one ordinary word costs two agent calls and the fix.

`references/TRIAGE.md:120-121` tells the triage agent those three words are banned.

### 2c. CodeQL analyses one language

`bin/scan.cjs:17-26` `LANGS` plus `detectLanguage(root)` returns the FIRST language whose root marker exists. `package.json` is first, so a Go or Python repository with a root `package.json` (common for tooling) gets only JavaScript. `bin/scan.cjs:57-68` builds one database `scans/codeql-db` and one `scans/codeql.sarif`.

Markers alone are also wrong in the other direction. Measured this session: `codeql database create --language=javascript` on a directory holding `package.json` and `main.go` exits 32 with "CodeQL detected code written in Go, but not any written in JavaScript/TypeScript". So detection must look at source files, not only markers.

`bin/normalize.cjs:232` hardcodes `raw_pointer: codeql.sarif#/runs/0/results/${idx}`. `fromSarif` already loops over `sarif.runs` (`bin/normalize.cjs:179`), so a merged multi-run SARIF normalizes correctly but every pointer past run 0 is wrong.

`bin/scan.cjs:83-85` `baselineOf` records only which scanners produced output. `bin/scan.cjs:87` `rescan` calls `runScanners` again, which re-detects languages on the patched worktree. Nothing ties the rescan to the baseline's languages.

## 3. Design

### 3a. Data shape: two kinds of prompt text, two vocabularies

The prompt is not one kind of text. It has two sources.

1. **Authored prose.** Free text the triage agent wrote into the contract. Exactly these string fields:
   `invariant`, `violating_input`, `enforcement_point.rationale`, every `forbidden_resolutions[i]`, and on the witness `attack_input`, `asserts`, `obstacle`, `why` (whichever exist on its tier).
   Excluded on purpose: `enforcement_point.file`, `enforcement_point.symbol`, `writable_scope`, the structural `anchor`, `entrypoint`, `command_template`, `framework`, and the dynamic `attack`/`observable`/`control` objects. These are paths, identifiers, commands and request shapes taken from the repository.
2. **Everything else in the prompt.** Repository source, paths, commands, the diff, the fixer's `enforcement_note`, harness failure reasons, and the fixed template text.

Two vocabularies, both derived from the finding record:

```js
// bin/leak-guard.cjs
recordTerms(finding)  // string[]: every observation's rule_id, native_fingerprint, message.trim(); length >= 4
proseTerms(finding)   // string[]: SCANNERS, every observation's scanner and rule_name; length >= 4
authoredProse(contract) // string[]: the fields listed in 1, non-empty strings only; [] when contract is absent
```

The check:

- The whole prompt must contain no `recordTerms` entry (case-insensitive substring). This still catches a finding's own rule id or message anywhere, including in the excerpt.
- The authored prose (joined with `\n`) must contain no `proseTerms` entry and must not match `RULE_ID_FORM`.

Error strings stay as they are, so existing callers and `detail` prefixes do not change: `fixer prompt leaked scanner material: "<term>"` and `fixer prompt carries a rule id: "<match>"`.

`assertNoLeak(prompt, finding)` keeps its signature. It reads `finding.triage && finding.triage.contract` for the authored prose. The auditor prompt does not include every authored field, so the auditor check can refuse on a field it did not send. That is acceptable because the fixer check on the same contract runs first and would have refused already.

`RULE_ID_FORM` becomes:

```js
/(?<![\w./@-])(?:js|javascript|ts|typescript|py|python|java|cpp|cs|go|rb|ruby|swift|rust|ql|actions)\/[a-z0-9]+(?:-[a-z0-9]+)+(?![@\w-]|\.[a-z]{1,4}\b)/i
```

The lookbehind means a rule id never starts in the middle of a path (`static/js/...`, `./go/...`). The lookahead adds `@` (`actions/setup-node@v4`) to the existing `.ext` exclusion.

Scanner names move out of the whole-prompt check. This deliberately departs from the caller's scope line ("check the source excerpt against ... scanner names"). The scope's own probe `docs/semgrep-notes` and the very common `github/codeql-action` workflow line can only pass if scanner names are not checked against repository text. A scanner name in the repository tells the fixer nothing about which rule fired. `rule_name` moves to the prose check for the same reason: CodeQL rule names are vulnerability class titles ("Code injection", "Uncontrolled command line"), and a fixer's `enforcement_note` or a code comment in the diff naturally uses them.

`bin/normalize.cjs:152` stores `null` instead of Semgrep's `"requires login"` placeholder. That string is not a fingerprint. Fixing it at the boundary is cheaper than filtering it in every reader.

The leak guard moves to its own module `bin/leak-guard.cjs` (`RULE_ID_FORM`, `recordTerms`, `proseTerms`, `authoredProse`, `assertNoLeak`, `leakError`). It is the mechanical half of the skill's central rule and has no other dependency on `run.cjs`. `SCANNERS` moves to `bin/scan.cjs`, its natural owner, and both `run.cjs` and `leak-guard.cjs` import it. This frees about 30 lines in `run.cjs` for the units that follow.

Rejected alternatives:

- Tag each prompt section with its source and return `{text, sections}` from `buildFixPrompt`. More plumbing for the same answer, since the authored fields are already named on the contract.
- Keep scanner names in the whole-prompt check and special-case workflow files. A per-file-type exception list is the kind of list that never closes.
- Drop the runtime form check and rely on the schema. The schema never form-checks `violating_input`, `rationale` or `forbidden_resolutions`, and the existing test `a leak that slips past the schema refuses that finding and the run still completes` depends on the runtime catching a rule id in `violating_input`.

### 3b. Data shape: the schema's invariant vocabulary

The new `invariant` `not.pattern` (JSON-escaped in the file; shown here unescaped):

```
(?i)(nosemgrep|semgrep|codeql|lgtm|sonar|snyk|bandit|brakeman|gosec|checkmarx|fortify|veracode|\bsast\b|static[ -]analy(?:sis|ser|zer)|\bscanner\b|\blinter\b|\brule[ _-]?id\b|\bcheck[ _-]?id\b|\bquery[ _-]?id\b|\bsarif\b|suppress|stops? firing|goes? quiet|false positive|(?<![\w./@-])(?:js|javascript|ts|typescript|py|python|java|cpp|cs|go|rb|ruby|swift|rust|ql|actions)/[a-z0-9]+(?:-[a-z0-9]+)*(?:/[a-z0-9-]+)*(?![@\w/-]|\.[a-z]{1,4}\b)|\b(?:javascript|typescript|python|go|java|kotlin|ruby|php|csharp|c|cpp|rust|scala|swift|ocaml|solidity|elixir|apex|bash|dockerfile|generic|html|json|yaml|terraform|hcl|problem-based-packs|trailofbits|gitlab|contrib)\.[a-z0-9_-]+(?:\.[a-z0-9_-]+){2,}\b)
```

Changes from today:

1. `\bwarning\b|\bfinding\b|\balert\b` removed. Ordinary words; they do not name a scanner.
2. The generic dotted form is replaced by a Semgrep registry id form: a known Semgrep namespace as the first segment, then at least three more dotted segments. `req.params.user.id` and `api.my-service.example.com` pass. Every Semgrep id seen locally (`javascript.*`, `problem-based-packs.*`, `trailofbits.*`) and the p/default Actions id `yaml.github-actions.security.run-shell-injection.run-shell-injection` (known from the registry, not measured here) are rejected.
3. The slash form gains the same lookbehind as the runtime, plus a lookahead refusing `@`, a word char, `-`, `/` or a file extension after the match. The hyphen stays optional here (`*`), unlike the runtime (`+`), so bare `js/xss` is still rejected at the triage boundary as today.

`fixer_visible_text` (`schema/finding.schema.json:287-291`) is unchanged. It never had the three words or the dotted form.

`validate.cjs:96-99` turns a leading `(?i)` into the `i` flag and compiles with `new RegExp`, so the lookbehind works on Node 22.

### 3c. Data shape: languages

```js
// bin/scan.cjs
const LANGS = [
  // [codeql language, source extensions, root markers]
  ['javascript', ['.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx'], ['package.json']],
  ['python', ['.py'], ['pyproject.toml', 'requirements.txt', 'setup.py']],
  ['go', ['.go'], ['go.mod']],
  ['ruby', ['.rb'], ['Gemfile']],
  ['java', ['.java', '.kt'], ['pom.xml', 'build.gradle', 'build.gradle.kts']],
  ['rust', ['.rs'], ['Cargo.toml']],
];
detectLanguages(root) // string[] in LANGS order, then 'actions' last when present
```

The CodeQL scanner entry in `scanners` gains two fields:

```js
{ name: 'codeql', status: 'ok' | 'partial' | 'failed', detail, config: 'javascript,python', languages: ['javascript', 'python'] }
```

`languages` lists the languages that produced SARIF. `config` is the same list joined with `,`, which `describeScanners` in `bin/report.cjs:170-178` already prints as `codeql (javascript,python)`, so the report needs no change.

`baselineOf` returns `{ scanners, ruleFiles, languages }`, where `languages` is the CodeQL entry's `languages` or `null` (CodeQL absent, failed, or `--scans` reuse).

Behaviour of `detectLanguages(root)`:

1. Breadth-first walk from `root` with `fs.readdirSync(dir, { withFileTypes: true })`. Skip any directory whose name starts with `.` or is in `SKIP_DIRS = new Set(['node_modules', 'vendor', 'third_party', 'dist', 'build', 'target', 'venv', '__pycache__'])`. Symlinks are not followed (`Dirent.isDirectory()` is false for them).
2. Count every directory entry examined. Stop at `SAMPLE_LIMIT = 5000` entries, or as soon as every `LANGS` language has been found.
3. A file's extension (`path.extname`) adds its language.
4. Only if the walk stopped on the budget, also add each language whose root marker exists. A huge monorepo may hide its Go tree past the budget; a small repo with a stray `package.json` and no JavaScript must not get JavaScript (measured failure, section 2c).
5. Add `actions` when `root/.github/workflows` holds at least one `.yml` or `.yaml` file.
6. Return the found languages in `LANGS` order, then `actions`.

Behaviour of the CodeQL branch of `runScanners`:

1. `langs = opts.languages || detectLanguages(target)`. Empty: push `{ name, status: 'failed', detail: 'no language detected' }` and continue, as today.
2. For each `lang`, in order: `db = scanDir/codeql-db-<lang>`, `out = scanDir/codeql-<lang>.sarif`. Remove `out` first (`fs.rmSync(out, { force: true })`) so a resumed run never reads a stale file. Run `database create db --language=<lang> --source-root=<target> --overwrite`. On non-zero exit record `"<lang>: <trim(stderr)>"` in `problems` and go to the next language. Run `database analyze` with the same arguments as today and the suite `codeql/<lang>-queries:codeql-suites/<lang>-security-extended.qls`. If `out` is missing, record the problem and continue. If it exists but the exit was non-zero, record the problem and still keep the file. Append the parsed file's `runs` and push `lang` to `analyzed`.
3. No runs at all: push `{ name, status: 'failed', detail: problems.join('; ') }`.
4. Otherwise `raw.codeql = { ...firstParsedSarif, runs: allRuns }`, written to `scanDir/codeql.sarif` with `JSON.stringify(..., null, 2)`. Push `{ name, status: problems.length ? 'partial' : 'ok', detail: problems.length ? problems.join('; ') : mergedPath, config: analyzed.join(','), languages: analyzed }`.

`rescan` passes `{ scans: null, scanners: baseline.scanners, languages: baseline.languages }`. With `null` it falls back to detection on the worktree, which is today's behaviour for `--scans` reuse.

Per-language databases run one after another. That costs the same wall time as a `--db-cluster` build for interpreted languages, since each extractor runs once either way.

Rejected alternatives:

- `codeql database create --db-cluster --language=a,b` (confirmed available in `codeql database create --help`, CodeQL 2.26.4). One failing extractor fails the whole cluster, so a stray `package.json` would cost every language. Per-language keeps partial results.
- Marker-only detection. Measured to fail (section 2c).
- Adding `cpp`, `csharp` and `swift`. They need a working build; out of scope.
- Passing `--build-mode`. Today's behaviour passes none; changing Java and Go build modes is a separate decision.

## 4. Steps

Symbols touched, for sequencing with other units:

- `bin/run.cjs`: header comment (lines 8-11), `SCANNERS` (removed, now imported), the `require('./scan.cjs')` line, the block from the comment above `RULE_ID_FORM` through `assertNoLeak` (lines 411-440, removed), the `baselineOf(raw, findings)` call in `run()`, and `module.exports`.
- `bin/scan.cjs`: `LANGS`, `detectLanguage` (deleted), new `detectLanguages`, `runScanners` CodeQL branch, `baselineOf`, `rescan`, `module.exports`, new export `SCANNERS`.
- `bin/leak-guard.cjs`: new.
- `bin/normalize.cjs`: `fromSarif` run index, Semgrep `native_fingerprint`.
- `schema/finding.schema.json`: `security_contract.properties.invariant` only.
- Prose: `SKILL.md`, `references/TRIAGE.md`, `references/INGEST.md`, `references/FIX-AND-VERIFY.md`.

Steps:

1. **`bin/scan.cjs`, `SCANNERS`.** Add `const SCANNERS = ['semgrep', 'codeql'];` near the top and add `SCANNERS` to `module.exports`.
2. **`bin/run.cjs`, `SCANNERS`.** Delete `const SCANNERS = ['semgrep', 'codeql'];` (line 52). Change the scan import to `const { runScanners, onPath, trim, baselineOf, rescan, SCANNERS } = require('./scan.cjs');`. The uses at lines 57 and 82 are unchanged.
3. **Create `bin/leak-guard.cjs`.** Start with `#!/usr/bin/env node`, `'use strict';` and a two-line header comment: this module is the mechanical half of the rule that the fixer is never shown the rule, and it separates what the triage agent wrote from what the repository contains. Move the comment `// Prose cannot enforce the rule above ...` with `RULE_ID_FORM`. Then:

   ```js
   const { SCANNERS } = require('./scan.cjs');

   const RULE_ID_FORM =
     /(?<![\w./@-])(?:js|javascript|ts|typescript|py|python|java|cpp|cs|go|rb|ruby|swift|rust|ql|actions)\/[a-z0-9]+(?:-[a-z0-9]+)+(?![@\w-]|\.[a-z]{1,4}\b)/i;

   const observations = (finding) => finding.sites.flatMap((s) => s.observations);
   const usable = (terms) => [...new Set(terms)].filter((t) => t && t.length >= 4);

   // Checked against the whole prompt, repository source included: only this finding's own
   // rule ids, fingerprints and messages, which ordinary code does not contain.
   const recordTerms = (finding) => usable(observations(finding)
     .flatMap((o) => [o.rule_id, o.native_fingerprint, o.message && o.message.trim()]));

   // Checked against triage-authored prose only. A workflow that runs the scanner, or a docs
   // folder named after it, is repository content and tells the fixer nothing about the rule.
   const proseTerms = (finding) => usable([...SCANNERS,
     ...observations(finding).flatMap((o) => [o.scanner, o.rule_name])]);

   function authoredProse(contract) {
     if (!contract) return [];
     const w = contract.witness || {};
     return [contract.invariant, contract.violating_input,
       contract.enforcement_point && contract.enforcement_point.rationale,
       ...(contract.forbidden_resolutions || []),
       w.attack_input, w.asserts, w.obstacle, w.why].filter((s) => typeof s === 'string' && s);
   }

   function assertNoLeak(prompt, finding) {
     const found = (hay, terms) => terms.find((t) => hay.includes(t.toLowerCase()));
     const hit = found(prompt.toLowerCase(), recordTerms(finding));
     if (hit) throw new Error(`fixer prompt leaked scanner material: ${JSON.stringify(hit.slice(0, 120))}`);
     const prose = authoredProse(finding.triage && finding.triage.contract).join('\n');
     const named = found(prose.toLowerCase(), proseTerms(finding));
     if (named) throw new Error(`fixer prompt leaked scanner material: ${JSON.stringify(named.slice(0, 120))}`);
     const form = RULE_ID_FORM.exec(prose);
     if (form) throw new Error(`fixer prompt carries a rule id: ${JSON.stringify(form[0])}`);
   }

   const leakError = (prompt, finding) => {
     try { assertNoLeak(prompt, finding); return null; } catch (e) { return e.message; }
   };

   module.exports = { RULE_ID_FORM, recordTerms, proseTerms, authoredProse, assertNoLeak, leakError };
   ```

4. **`bin/run.cjs`, remove the old guard.** Delete lines 411-440 (the comment above `RULE_ID_FORM` through the end of `assertNoLeak`). Add `const { assertNoLeak, leakError } = require('./leak-guard.cjs');` with the other requires. In `module.exports`, drop `leakTerms`, keep `assertNoLeak` and `leakError` as re-exports, and add `recordTerms` and `authoredProse` taken from the leak-guard require (import them in the same destructuring). Nothing else calls `leakTerms` (checked with grep).
5. **`bin/run.cjs`, header comment lines 8-11.** Replace the sentence about `assertNoLeak` with: `buildFixPrompt assembles the fixer's prompt field by field from the security contract and the flow, and bin/leak-guard.cjs refuses to send a prompt that carries this finding's rule id or message, or contract prose that names a scanner or has the form of a rule id.`
6. **`bin/normalize.cjs:152`.** Replace with `native_fingerprint: e.fingerprint && e.fingerprint !== 'requires login' ? e.fingerprint : null,` and a one-line comment: `// Semgrep OSS writes this placeholder for every result; it identifies nothing.`
7. **`bin/normalize.cjs:179`.** Change `for (const run of sarif.runs || [])` to `(sarif.runs || []).forEach((run, runIdx) => {` (close it with `});` where the `for` closed), and line 232 so the template literal reads `codeql.sarif#/runs/${runIdx}/results/${idx}`.
8. **`schema/finding.schema.json:270`.** Replace the `invariant` `not.pattern` with the section 3b pattern, JSON-escaped (each `\` doubled). Update the `invariant` `description` to: `About VALUES and BOUNDARIES, never about rules. validate.cjs rejects scanner proper nouns, scanner-artifact vocabulary, and the SYNTACTIC FORM of a CodeQL rule id or a Semgrep registry id. A rule-id form never starts inside a path and never runs into @ or a file extension, so action references and source paths pass. Form rather than a name list, because no list closes on rule ids this skill has never seen. bin/stage.cjs holds no copy of this; the schema is the only definition.`
9. **`bin/scan.cjs`, languages.** Replace `LANGS` and `detectLanguage` with the section 3c `LANGS`, `SKIP_DIRS`, `SAMPLE_LIMIT` and `detectLanguages(root)` exactly as specified there. Add a helper `hasWorkflows(root)` that returns true when `path.join(root, '.github', 'workflows')` is a readable directory holding a name ending `.yml` or `.yaml`; wrap its `readdirSync` in a `try` block that returns false on any error. Add one comment above `detectLanguages`: `// Source files decide, not markers: codeql database create fails outright on a language with a marker and no code.`
10. **`bin/scan.cjs`, `runScanners` CodeQL branch.** Replace the current `else { ... }` body (lines 57-68) with the section 3c loop. Add `const writeJson = (f, v) => fs.writeFileSync(f, JSON.stringify(v, null, 2));` next to `readJson`. Keep the Semgrep branch and the `opts.scans` branch unchanged.
11. **`bin/scan.cjs`, `baselineOf`.** Signature `baselineOf(raw, findings, scanners)`. Return `{ scanners: Object.keys(raw), ruleFiles: ..., languages: ((scanners || []).find((s) => s.name === 'codeql') || {}).languages || null }`.
12. **`bin/scan.cjs`, `rescan`.** The `runScanners` call becomes `runScanners({ scans: null, scanners: baseline.scanners, languages: baseline.languages }, deps, worktree, scanDir)`.
13. **`bin/scan.cjs`, exports.** `module.exports = { runScanners, detectLanguages, onPath, trim, baselineOf, rescan, SCANNERS };`. `detectLanguage` is deleted; grep confirms no other caller in `bin/`, `test/` or `tools/`.
14. **`bin/run.cjs`, `run()`.** Change `baseline: baselineOf(raw, findings),` to `baseline: baselineOf(raw, findings, scanners),`.
15. **`SKILL.md` lines 126-131.** Replace the paragraph with:

    > **The fixer is never shown the rule.** No rule id, no scanner name, no scanner message, no observation, and no scanner tool access. You cannot game a matcher you were never shown. `assertNoLeak` in `bin/leak-guard.cjs` enforces it on every fixer and auditor prompt. The whole prompt must not contain this finding's own rule id, fingerprint or message. The contract prose the triage agent wrote must also not name a scanner or a rule, or carry the syntactic form of a CodeQL rule id. Repository source is exempt from those last two checks, because a workflow that runs `github/codeql-action` or a line like `uses: actions/setup-node@v4` names nothing about the rule that fired. The schema closes the way around it too. A contract `invariant` fails validation when it names a scanner, borrows scanner-artifact vocabulary, or carries the form of a Semgrep or CodeQL rule id. Form rather than a name list, because no list closes on ids this skill has never seen.

    In the module list near line 170, add a sentence after the `bin/scan.cjs` sentence: ``bin/leak-guard.cjs` holds `assertNoLeak`, the check that keeps scanner material out of fixer and auditor prompts.`` Change the `bin/scan.cjs` sentence to say it runs the scanners, CodeQL once per detected language, and decides which rescan results a patch introduced.
16. **`references/TRIAGE.md:119-122`.** Replace the sentence starting "The schema rejects" with: `The schema rejects any mention of a scanner name, scanner-artifact vocabulary such as "suppress" or "false positive", and anything shaped like a rule id, because the fixer is never shown the rule and the contract must not leak it back in. Ordinary words like warning or alert, and property chains like \`req.params.user.id\`, are fine.`
17. **`references/INGEST.md:18-26`.** Replace the CodeQL paragraph and code block with prose plus a block showing `<lang>`:

    > CodeQL needs a database per language, then an analyze pass per database. `detectLanguages` in `bin/scan.cjs` picks the languages from the source files it finds (a bounded walk that skips `node_modules`, `vendor`, build output and dot directories), plus `actions` when `.github/workflows` holds a workflow. A root marker such as `package.json` alone does not count, because `codeql database create` fails on a language with no code. Each language's SARIF is merged into one `codeql.sarif` with one run per language. A language that fails is recorded and the others still count. The rescan of a patch reuses the baseline's languages. Use `--sarif-add-snippets` so results carry their source text.

    ```sh
    codeql database create <out>/scans/codeql-db-<lang> --language=<lang> --source-root=<target> --overwrite
    codeql database analyze <out>/scans/codeql-db-<lang> \
      --format=sarif-latest --output=<out>/scans/codeql-<lang>.sarif --sarif-add-snippets \
      'codeql/<lang>-queries:codeql-suites/<lang>-security-extended.qls'
    ```

18. **`references/FIX-AND-VERIFY.md:23`.** After the "Never receives" sentence list, add one sentence: `It does see repository source, which may name a scanner (a workflow, a docs folder); only this finding's own rule id, fingerprint and message are refused there.`
19. **Prose hygiene.** Wrap every rule id, path, and `a/b` token in backticks (check-prose's `slash-or` rule flags bare `word/word`). No long dashes, no arrows.

## 5. Tests

Write each test with its fix. For each new test, prove it fails without the fix by the mutation named in section 6. All tests use the helpers already in each file (`t`, `tmp`, `pathFinding`, `exploitable`, `contract`, `contractErrs`, `raw`, `REPO`, `ROOT`, `validate`, `INV`).

### 5a. `test/run.test.cjs`, section `the fixer prompt: the rule this skill exists to enforce`

Update, deliberately:

- **`assertNoLeak rejects a prompt that carries a rule id, a message or a scanner name`.** Keep lines 258-263. Replace line 264 (`${good}\nreported by semgrep` appended to the prompt) with a contract-prose case. Reason: a scanner name in repository text is no longer refused, by design; a scanner name in triage prose still is.

  ```js
  const named = pathFinding();
  named.triage = exploitable({ contract: { invariant: 'the value reported by semgrep must be escaped' } });
  assert.throws(() => R.assertNoLeak(R.buildFixPrompt(named, {}, []), named), /leaked scanner material: "semgrep"/);
  ```

- **`assertNoLeak also rejects a rule id shape it has never seen on this finding`.** Replace `R.assertNoLeak('satisfy py/reflected-xss here', f)` with a contract-prose case. Reason: the form check now reads only triage prose. Keep the `js/some-file.js and ts/index.js` line.

  ```js
  const f = pathFinding();
  f.triage = exploitable({ contract: { enforcement_point: {
    file: 'src/routes/files.js', symbol: 'read', rationale: 'satisfy py/reflected-xss here' } } });
  assert.throws(() => R.assertNoLeak(R.buildFixPrompt(f, {}, []), f), /carries a rule id: "py\/reflected-xss"/);
  R.assertNoLeak('edit js/some-file.js and ts/index.js', f);
  ```

  `R.assertNoLeak('edit js/some-file.js ...', f)` passes because that string is the prompt, not prose, and holds none of the record terms.

New tests, same section:

1. **`repository source that looks like a rule id or names a scanner still reaches the fixer`.**

   ```js
   const f = pathFinding();
   f.triage = exploitable();
   f.context.enclosing_excerpt = [
     '      - uses: actions/setup-node@v4',
     "app.use(express.static('/static/js/admin-panel/main.js'));",
     "const util = require('./go/some-pkg/util');",
     '// notes live in docs/semgrep-notes',
     '      - uses: github/codeql-action/init@v3',
     '// this route requires login',
   ].join('\n');
   const prompt = R.buildFixPrompt(f, {}, []);
   assert.ok(prompt.includes('actions/setup-node@v4'), 'the excerpt must reach the prompt');
   assert.strictEqual(R.leakError(prompt, f), null);
   ```

2. **`this finding's own rule id and message are refused even inside the source excerpt`.**

   ```js
   const f = pathFinding();
   f.triage = exploitable();
   const msg = f.sites.flatMap((s) => s.observations).find((o) => o.rule_id === RULE_ID).message.trim();
   f.context.enclosing_excerpt = `// ${RULE_ID}`;
   assert.strictEqual(R.leakError(R.buildFixPrompt(f, {}, []), f), `fixer prompt leaked scanner material: "${RULE_ID}"`);
   f.context.enclosing_excerpt = `// ${msg}`;
   assert.match(R.leakError(R.buildFixPrompt(f, {}, []), f), /^fixer prompt leaked scanner material: /);
   ```

3. **`a path given as the violating value is not a rule id`.**

   ```js
   const f = pathFinding();
   f.triage = exploitable({ contract: { violating_input: '../../static/js/admin-panel/main.js' } });
   assert.strictEqual(R.leakError(R.buildFixPrompt(f, {}, []), f), null);
   f.triage = exploitable({ contract: { violating_input: 'py/reflected-xss' } });
   assert.strictEqual(R.leakError(R.buildFixPrompt(f, {}, []), f), 'fixer prompt carries a rule id: "py/reflected-xss"');
   ```

4. **`the auditor sees the fixer's own words about the vulnerability class`.**

   ```js
   const f = pathFinding();
   f.triage = exploitable();
   const name = f.sites.flatMap((s) => s.observations).find((o) => o.rule_name && !o.rule_name.startsWith('http')).rule_name;
   const p = R.buildAuditPrompt(f, { enforcement_note: `closes the ${name} by resolving against the public root` }, DIFF_SRC);
   assert.strictEqual(R.leakError(p, f), null);
   ```

   The CodeQL `rule_name` in the fixture is `Uncontrolled data used in path expression` (measured in a real run's records).

### 5b. `test/run.test.cjs`, section `leaks: ...`

5. **`an invariant in plain words and property paths is accepted at the triage boundary`.**

   ```js
   for (const v of [
     'the warning banner text must not carry markup taken from the query string',
     'each finding id in the URL must belong to the authenticated caller',
     'a form field named alert is HTML-escaped before it is rendered',
     'req.params.user.id must equal the session user id before the row is read',
     'the comment body never reaches the shell in the step after uses: actions/setup-node@v4',
     'every name resolved under ./go/some-pkg/util stays inside the module root',
     'files under /static/js/admin-panel/ are served read-only',
     'the redirect target resolves to api.my-service.example.com and nothing else',
   ]) assert.deepStrictEqual(contractErrs(contract({ invariant: v })), [], v);
   ```

6. **`rule ids of every shape are still rejected in the invariant`.**

   ```js
   for (const id of ['actions/code-injection/critical', 'actions/missing-workflow-permissions', 'js/xss',
     'yaml.github-actions.security.run-shell-injection.run-shell-injection',
     'trailofbits.go.unsafe-dll-loading.unsafe-dll-loading']) {
     assert.ok(contractErrs(contract({ invariant: `the condition ${id} describes must not hold` })).length > 0, id);
   }
   ```

   The existing selftest corpus tests (every fixture rule id rejected bare and in a sentence, all 103 driver rules) stay unchanged and must stay green.

### 5c. `test/run.test.cjs`, new section `languages: CodeQL sees every language in the repository`

Add `const S = require(path.join(ROOT, 'bin/scan.cjs'));` at the top of the file with the other requires. Add helpers in the section:

```js
const tree = (files) => {
  const d = tmp();
  for (const [rel, body] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(d, rel)), { recursive: true });
    fs.writeFileSync(path.join(d, rel), body);
  }
  return d;
};
// A fake codeql: each analyze writes a one-run SARIF whose driver name is its language.
const codeqlDeps = (failCreate = []) => ({
  onPath: () => true,
  exec: (cmd, args) => {
    const lang = (args.find((a) => a.startsWith('--language=')) || '').slice('--language='.length)
      || path.basename(args[2]).replace('codeql-db-', '');
    if (args[1] === 'create') return failCreate.includes(lang)
      ? { status: 32, stdout: '', stderr: `no ${lang} source seen` } : { status: 0, stdout: '', stderr: '' };
    const out = args.find((a) => a.startsWith('--output=')).slice('--output='.length);
    fs.writeFileSync(out, JSON.stringify({ version: '2.1.0', runs: [{ tool: { driver: { name: lang, rules: [] } }, results: [] }] }));
    return { status: 0, stdout: '', stderr: '' };
  },
});
const scanOpts = (over = {}) => ({ scans: null, scanners: ['codeql'], ...over });
```

7. **`every language with source files is detected, and vendored code is not`.**

   ```js
   const d = tree({ 'package.json': '{}', 'src/a.js': '', 'svc/main.go': '', 'go.mod': '', 'tools/x.py': '',
     'node_modules/dep/index.rb': '', 'vendor/lib/X.java': '', '.hidden/y.rs': '',
     '.github/workflows/ci.yml': 'on: push\n' });
   assert.deepStrictEqual(S.detectLanguages(d), ['javascript', 'python', 'go', 'actions']);
   ```

8. **`a root marker with no source files is not a language`.**

   ```js
   assert.deepStrictEqual(S.detectLanguages(tree({ 'package.json': '{}', 'main.go': '' })), ['go']);
   ```

9. **`one database per language, merged into one SARIF with a run each`.**

   ```js
   const target = tree({ 'a.js': '', 'b.py': '' });
   const scanDir = path.join(tmp(), 'scans');
   const { raw: r, scanners } = S.runScanners(scanOpts(), codeqlDeps(), target, scanDir);
   assert.deepStrictEqual(r.codeql.runs.map((x) => x.tool.driver.name), ['javascript', 'python']);
   assert.deepStrictEqual(scanners, [{ name: 'codeql', status: 'ok', detail: path.join(scanDir, 'codeql.sarif'),
     config: 'javascript,python', languages: ['javascript', 'python'] }]);
   assert.deepStrictEqual(JSON.parse(fs.readFileSync(path.join(scanDir, 'codeql.sarif'), 'utf8')).runs.length, 2);
   ```

10. **`a language that fails is recorded and the others still count`.**

    ```js
    const target = tree({ 'a.js': '', 'b.py': '' });
    const { raw: r, scanners } = S.runScanners(scanOpts(), codeqlDeps(['python']), target, path.join(tmp(), 'scans'));
    assert.deepStrictEqual(r.codeql.runs.map((x) => x.tool.driver.name), ['javascript']);
    assert.deepStrictEqual([scanners[0].status, scanners[0].languages, scanners[0].detail],
      ['partial', ['javascript'], 'python: no python source seen']);
    ```

11. **`the rescan analyses the baseline's languages, not whatever the patch left behind`.**

    ```js
    const target = tree({ 'a.js': '', 'b.py': '' });
    const deps = codeqlDeps(['python']);
    const base = S.runScanners(scanOpts(), deps, target, path.join(tmp(), 'scans'));
    const baseline = S.baselineOf(base.raw, [], base.scanners);
    assert.deepStrictEqual(baseline.languages, ['javascript']);
    const worktree = tree({ 'a.js': '', 'b.py': '', 'c.go': '' });
    const f = pathFinding();
    const res = S.rescan(f, worktree, path.join(tmp(), 'rescan'),
      { deps: codeqlDeps(), runId: 'run-test', baseline });
    assert.deepStrictEqual(res.rescan.scanners.map((s) => [s.name, s.languages]), [['codeql', ['javascript']]]);
    ```

    `rescan` normalizes the empty runs against `makeRepo(worktree)`, which yields no findings, so `obligation.status` is `pass`; the assertion is on the languages.

### 5d. `test/selftest.cjs`, section `contract: the way around rule-blindness`

12. **`a merged multi-run SARIF points each result at its own run`.**

    ```js
    const two = { ...raw.codeql, runs: [{ ...raw.codeql.runs[0], results: [] }, raw.codeql.runs[0]] };
    const ptrs = normalize({ codeql: two }, repo, 'run-test').findings
      .flatMap((f) => f.sites.flatMap((s) => s.observations)).map((o) => o.raw_pointer);
    assert.ok(ptrs.length > 0, 'the fixture must produce CodeQL observations');
    assert.deepStrictEqual(ptrs.filter((p) => !p.startsWith('codeql.sarif#/runs/1/results/')), []);
    ```

13. **`Semgrep's placeholder fingerprint is not stored`.**

    ```js
    const sg = findings.flatMap((f) => f.sites.flatMap((s) => s.observations)).filter((o) => o.scanner === 'semgrep');
    assert.ok(sg.length > 0);
    assert.deepStrictEqual([...new Set(sg.map((o) => o.native_fingerprint))], [null]);
    ```

    The fixture carries `"fingerprint":"requires login"` on all 3 Semgrep results (measured with `grep -o '"fingerprint": *"[^"]*"' test/fixtures/semgrep.json`).

Both regexes in sections 3a and 3b were run this session against every string in tests 1, 3, 5 and 6, the existing selftest prose cases, and the full fixture corpus (103 CodeQL driver ids and 3 Semgrep ids, bare and inside a sentence). Every result matched the expectation in this plan (measured).

Total new tests: 13 (4 in 5a, 2 in 5b, 5 in 5c, 2 in 5d). Updated tests: 2.

## 6. Verification

1. `cd /home/asiimov/Projects/sast-assist/skills/sast-assist && sh test/run-all.sh`. Pass means the last line is `all green`, `node test/run.test.cjs` and `node test/selftest.cjs` both end `N passed, 0 failed`, and the prose and skill-tree checks print no `FAIL`.
2. `wc -l bin/run.cjs` prints under 1000 (expected about 910).
3. `grep -rn "detectLanguage\b\|leakTerms" bin test tools` prints nothing.
4. Mutation checks. Apply each, run the named file, confirm the named test FAILS, then revert. Record each result in the hand-back.

   | Mutation | Run | Must fail |
   |---|---|---|
   | In `assertNoLeak`, check `proseTerms` against `prompt` instead of `prose` | `node test/run.test.cjs` | test 1 |
   | In `assertNoLeak`, run `RULE_ID_FORM` on `prompt` instead of `prose` | `node test/run.test.cjs` | test 1 |
   | Remove `(?<![\w./@-])` from `RULE_ID_FORM` | `node test/run.test.cjs` | test 3 |
   | Drop `o.rule_id` from `recordTerms` | `node test/run.test.cjs` | test 2 |
   | Move `o.rule_name` into `recordTerms` | `node test/run.test.cjs` | test 4 |
   | Put `\\bwarning\\b` back into the invariant pattern | `node test/run.test.cjs` | test 5 |
   | Delete the Semgrep-namespace dotted alternative from the invariant pattern | `node test/run.test.cjs` | test 6 |
   | In `detectLanguages`, stop skipping `node_modules` | `node test/run.test.cjs` | test 7 |
   | In `detectLanguages`, always add root-marker languages | `node test/run.test.cjs` | test 8 |
   | In `runScanners`, keep only the last language's runs | `node test/run.test.cjs` | test 9 |
   | In `runScanners`, `continue` the outer scanner loop on the first failed language | `node test/run.test.cjs` | test 10 |
   | In `rescan`, drop `languages: baseline.languages` | `node test/run.test.cjs` | test 11 |
   | Put `runs/0` back in `normalize.cjs` | `node test/selftest.cjs` | test 12 |
   | Revert step 6 in `normalize.cjs` | `node test/selftest.cjs` | test 13 |

5. One real CodeQL probe, budgeted. No agent calls, only local CodeQL. Takes about 30 seconds (measured this session: python create 5s, actions create 4s, actions analyze 9s).

   ```sh
   d=$(mktemp -d); mkdir -p $d/src $d/.github/workflows
   echo '{"name":"x"}' > $d/package.json
   echo 'require("child_process").exec(process.argv[2]);' > $d/src/a.js
   printf 'import os,sys\nos.system(sys.argv[1])\n' > $d/main.py
   printf 'on: issue_comment\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/setup-node@v4\n      - run: echo "${{ github.event.comment.body }}"\n' > $d/.github/workflows/ci.yml
   cd /home/asiimov/Projects/sast-assist/skills/sast-assist && node -e '
   const S = require("./bin/scan.cjs"); const R = require("./bin/run.cjs");
   const r = S.runScanners({ scans: null, scanners: ["codeql"] }, { exec: R.realExec }, process.argv[1], process.argv[1] + "-scans");
   console.log(JSON.stringify(r.scanners), r.raw.codeql.runs.flatMap((x) => (x.results || []).map((y) => y.ruleId)).join(" "));
   ' $d
   ```

   Pass means the scanner entry shows `"status":"ok"` and `"languages":["javascript","python","actions"]`, and the rule ids include at least one `js/`, one `py/` and `actions/code-injection/critical`. Confirm `R.realExec` exists (`grep -n realExec bin/run.cjs`); it is used by `test/pipeline.real.test.cjs:110`. Delete `$d` and `$d-scans` afterwards.

6. Never run `node bin/run.cjs` without `--triage-only` against a real target in this unit, and never call the `claude` CLI.

## 7. Risks and what stays out of scope

- **Top risk: time.** Every detected language adds a database build and an analyze pass to the baseline and to EVERY patch's rescan. A repository with JavaScript, Python and workflows now pays three CodeQL passes per rescan instead of one. Stray files count too: a Python service with one `.js` test fixture gets a JavaScript pass. This unit does not cap the language count. If run times become a problem, the next step is a per-language minimum file count or a `--codeql-languages` override, not a change here.
- The prose check can refuse a contract the schema accepted, for example a `rationale` naming a CodeQL rule title such as "Code injection". That refusal is final for the finding, as today. Narrowing it further needs a real run showing it happen.
- Scanner names in repository text now reach the fixer. The fixer learns that a scanner exists in the repository, not which rule fired. This is the deliberate trade for the `github/codeql-action` and `docs/semgrep-notes` cases.
- The Semgrep namespace list in the schema is not closed. A Semgrep id from an unlisted namespace in an invariant passes the schema. The runtime still refuses this finding's own id anywhere in the prompt, so the exposure is naming some other rule.
- `--scans` reuse has no recorded languages, so its rescan re-detects on the worktree, the same as today.
- Out of scope: `cpp`, `csharp`, `swift`, `--build-mode`, `--db-cluster`, the Semgrep stale-output case, and `describeScanners` reading `s.error` where scanner entries carry `detail` (an existing mismatch in `bin/report.cjs:175`).
