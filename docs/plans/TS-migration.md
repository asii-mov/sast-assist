# Plan: move sast-remediate from JavaScript to TypeScript

## Done means

All of these hold on the final commit:

1. No `.cjs` file is left under `skills/sast-remediate/` or `tools/`. Every one is a `.ts` file that Node runs directly, with no build step.
2. `tsc --noEmit` passes with `strict: true` and `erasableSyntaxOnly: true`, so the checker rejects any TypeScript syntax that Node can't run.
3. `test/run-all.sh` passes and runs the type check too. Every suite passes the same number of tests as the baseline (62, 23, 105, 18, 8) or more.
4. A real run against `.work/targets/vuln-app-git` with `--verify=full --witness=dynamic --model=opus` gives the same results as `run-full5`: 2 fixed, 1 rejected, and `dynamic` witnesses passing.

## Facts this plan rests on (checked 2026-09-23)

- Node here is v22.22.1. It runs `.ts`, `.cts` and `.mts` files directly by erasing the types. It rejects syntax it can't erase, such as `enum`. `import.meta.main` and `import.meta.dirname` work.
- In a TypeScript file, `const x = require('./y')` is typed `any`, so every module boundary would go unchecked. `import fs = require()` would fix that, but it isn't erasable. So the files move to ES modules (`import` and `export`), not `.cts`.
- The skill has no `package.json` and no dependencies. It has to stay that way at run time.
- The installed `tsc` is 5.6.2, which is older than `erasableSyntaxOnly` (added in 5.8). The npm registry is reachable.
- `fake-claude.cjs` is symlinked as `claude` in the real-git pipeline test. Node has to recognise the symlink target as TypeScript.

## Who notices

- **People running the skill.** The command becomes `node bin/run.ts`, and it needs Node 22.18 or newer. Nothing else changes.
- **The next engineer.** Types across every module, one `npm install` for the type checker, and no build step.

## Out of scope

- `reference/`. It's vendored prior art, not ours.
- `fixtures/vuln-app`. It is deliberately a JavaScript app for the scanners to find bugs in.
- Past plans and design notes in `docs/` and `design/`. They record what was true at the time. Only live docs are updated: `SKILL.md`, `references/`, `AGENTS.md` and `run-all.sh`.

## Units, riskiest first. Each one ends in a check.

0. **Baseline.** Record each suite's pass count, and the finding outcomes from `run-full5`. Check: the numbers are saved in the decision log.
1. **Scaffold.** Add a dev-only `package.json` at the repo root with `typescript` and `@types/node`, pinned, plus a lockfile. Add a `tsconfig.json` with `strict`, `noEmit`, `erasableSyntaxOnly`, `verbatimModuleSyntax`, `module: nodenext` and `allowImportingTsExtensions`. Add `skills/sast-remediate/package.json` holding only `"type": "module"` and `engines.node >=22.18`, so the shipped skill states its Node floor. Check: `tsc` runs and reports nothing to check yet.
2. **Spike the risky path.** Convert `test/fake-claude` and `bin/agent` by hand. Check: `agent.test` and `pipeline.real.test` pass with a `.ts` target behind the `claude` symlink.
3. **Lever.** Write `tools/cjs-to-esm.mjs`, a one-off codemod for the mechanical part: `git mv` to `.ts`, `require` to `import`, `module.exports` to `export`, `__dirname` to `import.meta.dirname`, `require.main === module` to `import.meta.main`, and `.cjs` path strings to `.ts`. Prove it by rerunning it on the unit 2 files and diffing against the hand-made version. Check: that diff is empty, or only in formatting.
4. **Convert, leaf modules first.** Apply the codemod one module at a time, in dependency order (gate, stage, leak-guard, validate, normalize, patch-guard, app-harness, witness-run, scan, resume, report, run), then the tests and tools. Check after each: the whole suite passes. `tsc` runs with `noImplicitAny` off for now. This intermediate state is planned and ends in unit 6.
5. **Types from the schemas.** Generate `schema/*.d.ts` from `finding.schema.json` and `agent-results.schema.json` with a committed script, and add a check that fails when the generated file is stale. Hand-written finding types would drift from the schema. Check: the generated types compile, and the staleness check fails when the schema is edited without regenerating.
6. **Strict.** Annotate module by module and turn `strict` on. Each `as` cast has to name the boundary check that justifies it. Check: `tsc` passes strict, and the suite still passes.
7. **Docs and tooling.** Update `SKILL.md`, `references/`, `AGENTS.md`, `run-all.sh` and `validate-skill`. Delete the codemod, since it was one-off. Check: `validate-skill` and `check-prose` pass.
8. **Final.** Run the full suite and the real run from "Done means" item 4, and compare against the baseline.

## How it runs

Serially, by one agent. Parallel subagents have died on rate limits (HTTP 429) several times in this repo, and the conversion order is mostly a chain anyway. One commit per unit, on a branch. The decision log is `.audit/ts-migration.tsv`.
