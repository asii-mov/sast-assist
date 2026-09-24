# sast-remediate

Static analysis tools such as Semgrep and CodeQL flag code that looks dangerous, and many of those flags turn out to be false positives: the input is not attacker-controlled, a check earlier on the path already stops the attack, or the code never runs. sast-remediate takes the scanners' output and has an AI agent try to disprove each finding from the repository's own source. Findings it can disprove are set aside with a written reason, so a reviewer only spends time on the ones that hold up. For the findings that remain, it can also write a fix on its own branch and check it with set rules, the project's tests and a fresh scan. Those checks do not prove the attack is gone.

## How it works

1. **Scan.** Semgrep and CodeQL run against the repository, or their existing output is reused.
2. **Merge.** Results that point at the same flaw are folded into one finding.
3. **Set aside by path.** Test, vendor, generated, minified and migration code is set aside by rule. This is a scope decision, not a claim that the code is safe.
4. **Triage.** An agent tries to refute each finding. The result is a verdict of exploitable, not exploitable or undecidable, and an exploitable finding also gets a written statement of what must be true for the code to be safe.
5. **Threshold.** Plain code, with no AI involved, decides which exploitable findings are severe enough to fix (medium and above by default).
6. **Fix and check.** A second agent writes a fix in a separate worktree. It never sees the scanner's rule or message. By default (`--verify=cheap`) the tool then checks that the security goal is unchanged, that the change does not just silence the scanner or touch files it should not, that the tests pass and that a rescan finds nothing new. The last two count as unavailable, not failed, when there is no test command or no scanner output. A fix that fails gets one more attempt.
7. **Report.** `REMEDIATION.md` lists every finding and what happened to it. `HANDOFF.md` lists what needs a human.

Each finding the run decides gets a recorded outcome and reason. A finding left open by a failed agent call or by `--max-findings` waits for the next run, and the report says which.

## Requirements

- Node.js 22.18 or newer. The tool is TypeScript that Node runs directly, with no build step and no dependencies.
- Semgrep, CodeQL or both on `PATH`. Only a run with both `--scans` and `--triage-only` can do without them, because the fix stage rescans every fix.
- The [Claude Code](https://claude.com/claude-code) CLI on `PATH` as `claude`. It runs the agents and keeps each one to the tools its role needs. The model behind it can come from either of two places:
  - Anthropic (the default): sign in to the CLI or set `ANTHROPIC_API_KEY`.
  - [OpenRouter](https://openrouter.ai): set `OPENROUTER_API_KEY` and pass `--provider=openrouter`. Then `--model` takes any OpenRouter model name, such as `openai/gpt-5` or `google/gemini-2.5-pro`. The CLI is tuned for Claude models, so other models may be worse at using its tools. Findings they fail to answer stay open for the next run rather than being dropped.
- The target must be a git repository for the fix stage. Triage works on any directory. The tool commits each fix under its own name, so the machine needs no git identity.

## Usage

From the root of this repository:

```sh
node skills/sast-remediate/bin/run.ts --target=/path/to/repo
```

Useful options:

| Option | Effect |
| --- | --- |
| `--out=DIR` | Write output to `DIR`. The default is under `~/sast-remediate/<repo>/`. |
| `--triage-only` | Triage and report, but write no fixes. |
| `--fix-at=high` | Fix only findings rated high or critical. |
| `--verify=full` | Run all seven checks, adding an independent AI review and a check that normal use still works. The default, `cheap`, runs four. |
| `--witness=dynamic` | With `--verify=full`, start the app locally and try the attack before and after the fix. It needs a way to start the app, found in the repository or set in `.sast-remediate.toml`, and a finding that triage gives a live test. See `skills/sast-remediate/references/DYNAMIC-WITNESS.md`. |
| `--scans=DIR` | Reuse `semgrep.json` and `codeql.sarif` from `DIR` instead of scanning. |
| `--scanners=semgrep` | Run only Semgrep. |
| `--semgrep-config=p/owasp-top-ten` | Choose the Semgrep rules. The default is `p/default`. |
| `--codeql-suite=NAME` | Choose the CodeQL suite. The default is `security-extended`. |
| `--max-findings=N` | Triage at most N findings. The rest wait for the next run. Fixes are not limited. |
| `--model=NAME` | Choose the model the agents use. With OpenRouter, use its model name, such as `openai/gpt-5`. |
| `--provider=openrouter` | Send the agents' requests through OpenRouter using `OPENROUTER_API_KEY`. The default is `anthropic`. |
| `--dry-run` | Print the plan and exit. |

Keep the output directory outside the target repository. It contains `REMEDIATION.md`, `HANDOFF.md`, `run-metadata.json`, the scanner output in `scans/` and one JSON record per finding in `findings/`. Each fix attempt is left on a branch named `sast-fix/<run>/<finding>/<attempt>` in the target repository, where `<run>` is the name of the output directory. Nothing is merged automatically.

Running the command again picks up where an unfinished run stopped. Without `--out`, it continues the latest unfinished run of the same commit, or starts a new one. With `--out`, it continues that directory whatever the commit. A continued run keeps its original `--verify` level and scanner rules.

The command exits with `2` for a usage error, such as a missing `--target` directory or `OPENROUTER_API_KEY`, and `1` when the run fails. `0` means only that the run ended without an error. Agent calls may still have failed, so check `run_status` in `run-metadata.json` and the finding records.

## CI/CD

A typical setup runs triage on every pull request and publishes the report, then runs the fix stage on a schedule or by hand.

GitHub Actions example for triage. If this repository is private, its checkout needs a token secret that can read it:

```yaml
name: sast-triage
on: pull_request

jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          path: target
      - uses: actions/checkout@v4
        with:
          repository: your-org/code-scanning
          token: ${{ secrets.SAST_REMEDIATE_TOKEN }}
          path: tool
      - uses: actions/setup-node@v4
        with:
          node-version: 22
      - uses: astral-sh/setup-uv@v10
      - run: |
          uv tool install semgrep
          echo "$(uv tool dir --bin)" >> "$GITHUB_PATH"
      - run: npm install -g @anthropic-ai/claude-code
      - name: Triage
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
        run: |
          node tool/skills/sast-remediate/bin/run.ts \
            --target=target --out="$RUNNER_TEMP/sast" --scanners=semgrep --triage-only
      - uses: actions/upload-artifact@v4
        with:
          name: sast-report
          path: ${{ runner.temp }}/sast
      - name: Fail on confirmed or undecided findings
        shell: bash
        run: |
          find "$RUNNER_TEMP/sast/findings" -name '*.json' -exec cat {} + |
            jq -se '[.[] | select(.disposition.state != "split") | select(.gate == null or .gate.action == "fix" or .disposition.state == "deferred")] | length == 0'
```

The last step fails the build when a finding is confirmed at or above the threshold or left undecided by a failed agent call or `--max-findings`. A finding that triage split into parts passes, and each part is judged on its own. A part that asks to split again fails the build, because a human has to decide it. A clean scan passes. `shell: bash` makes the step fail if the output directory is missing.

For the fix stage, change the workflow as follows:

- Give the job `permissions: contents: write` so it can push.
- Drop `--triage-only`.
- Give each run its own output directory, such as `--out="$RUNNER_TEMP/sast-${{ github.run_id }}"`. The branch names include the directory name, so a fixed name gives every run the same branches and later pushes are rejected.
- Push the branches so they can be reviewed as pull requests:

```sh
git -C target push origin 'refs/heads/sast-fix/*:refs/heads/sast-fix/*'
```

Notes for CI:

- If your pipeline already runs Semgrep or CodeQL, save their output as `semgrep.json` and `codeql.sarif` and pass `--scans=DIR` to avoid scanning twice. Pass the same rules with `--semgrep-config` and `--codeql-suite`, or the rescan after each fix will count unfamiliar rules as new findings. The fix stage still needs the scanners installed for that rescan.
- Agents run with only the tools their role needs and no shell, and the target's own Claude settings and hooks are ignored.
- Use `--max-findings` to bound the triage time and cost of a single job.
- To use OpenRouter in CI, set `OPENROUTER_API_KEY` from a secret in place of `ANTHROPIC_API_KEY` and add `--provider=openrouter --model=<name>` to the command.

## Development

Install the type checker once at the repository root, then run every check:

```sh
npm install
cd skills/sast-remediate && sh test/run-all.sh
```

The types in `schema/types.ts` are generated from `schema/finding.schema.json` and `schema/agent-results.schema.json`. After changing either schema, run `node tools/gen-schema-types.ts` from `skills/sast-remediate`.
