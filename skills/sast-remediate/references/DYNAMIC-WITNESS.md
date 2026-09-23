# Dynamic witness

**Status: built and proven, not enabled by default.** No tier-selection function exists yet, so
nothing chooses this tier automatically. The operator opts in with `--witness=dynamic`. It is tracked as a planned
improvement in `design/FUTURE-IMPROVEMENTS.md`, which lists what to settle before turning it on.

Drive the running application over its real network interface. This is the only tier that tests
the boundary an attacker actually reaches.

Load this file only when the operator enabled the tier, a harness was discovered, and the
finding's flow source is a network entry surface. A repository with no runnable service never
loads it and pays nothing.

## Why it earns its cost

Source analysis and unit tests both reason about the handler. The vulnerability frequently lives
in the gap between the handler and the wire. Middleware running in the wrong order. A framework
re-parsing a parameter the validator already checked. A serializer re-introducing the payload. A
router normalizing a traversal differently than the check did.

A fix verified only at the function boundary can leave every one of those intact.

## Harness discovery

Discovered from the repository, never invented. `bin/app-harness.cjs` returns every candidate and
the triage agent picks.

Precedence: an explicit `[harness]` block in `.sast-remediate.toml` always wins. Then
`docker-compose` with a service exposing a port, a `Procfile` web entry, a `package.json` start
or dev script, `manage.py`, `config.ru` or `bin/rails`, then `go.mod`. Those are the ones
`discoverAppHarness` implements. Anything else needs an explicit `[harness]` block.

Derive readiness from a health route when one exists, otherwise a request to `/` expecting any
status below 500. Always bind an ephemeral port on loopback. Never a fixed port. Never `0.0.0.0`.

If no candidate is found, the tier is unavailable and the witness falls back with obstacle
`no_app_harness`.

## The differential, in order

The parent performs every request itself. Four steps, and the control brackets the attack on both
sides.

1. Reset fixture state. Send the control to **base**. It must satisfy its expected observable. If
   it fails here the control is not a valid baseline, which is `witness_control_failed`.
2. Reset. Send the attack to **base**. The observable must fire. If it does not, the attack does
   not work and nothing has been proven, which is `witness_vacuous`.
3. Reset. Send the attack to **head**. The observable must not fire.
4. Reset. Send the control to **head**. It must still pass. This is the step that catches fixing
   the bug by breaking the endpoint.

## Observables are a closed set

`status_code`, `body_contains` with a planted canary, `body_json_path`, `header_present`,
`reflected_unescaped`, and `latency_exceeds` for blind injection only.
`row_appears` is specified in the schema but **not implemented**. `observed()` throws on it,
because it needs a fixture database adapter nobody has written.

The set is closed on purpose. It keeps the blast radius of a successful witness a design-time
decision rather than an agent's judgment in the middle of a request. Stop at the first status
code, canary or unauthorized fixture row that establishes the boundary failure. Do not escalate,
pivot or persist.

## Execution sandbox

Every other obligation reads source or runs the project's own tests. This tier runs
target-controlled code as a service, which is a different risk class. These controls are not
optional.

**Never a deployed environment.** No staging, no shared instance, no provider API, no real
credential, no live control plane. The harness boots a fresh local instance and tears it down. If
a decisive fact lives only in a deployment, that is `undecidable` with an owner-observed plan, not
a request we send somewhere.

**Isolated loopback, ephemeral port**, in its own network namespace where the platform provides
one. External networking disabled. A harness that cannot start without reaching the internet
makes the tier unavailable rather than earning an exception.

**Empty allowlisted environment.** Scratch-local `HOME`, temp directories and caches. Never the
ambient environment.

**Dummy everything.** Fixture database, dummy principals minted by the harness, planted canaries.
Never real data, never a real tenant, never another user's records.

**Resource and wall-clock limits**, with teardown guaranteed on timeout.

**No dependency installation.** A harness that needs to fetch packages makes the tier unavailable.

If any control cannot be enforced, the tier is unavailable, not best-effort.

## Evidence never crosses the boundary

The parent sends the request, reads the response and writes the transcript. Evidence therefore
never originates inside the target-controlled process and never has to be promoted out of it.

This is why this skill does not carry a file-promotion procedure. There is no file to promote.
The sandboxed process writes only to its own scratch, and nothing in scratch is ever read as
evidence.

Header values are redacted by name against an allowlist before a transcript is retained.

## Cost containment

App boot is the most expensive operation in a run. It amortizes across a conflict-free wave. Boot
once per tree per wave, base and head, run every dynamic witness in that wave against those two
instances, and reset fixture state between exchanges.

This gives waves a second justification beyond collision safety.
