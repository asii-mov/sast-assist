# Future improvements

Planned work, deferred out of current scope. Ordered by value.

## 1. Dynamic verification (wired in behind `--witness=dynamic`, not the default)

Drive the running application over its real network interface and verify a patch against the
boundary an attacker actually reaches.

**Status: implemented and proven end to end, opt-in via `--witness=dynamic`.**
`bin/run.cjs` offers triage the `dynamic` tier only when the operator passes that flag and
`discoverAppHarness` finds a harness in the target; otherwise triage is offered `argued` only.

Why it is worth turning on later. Source analysis and unit tests both reason about the handler.
The vulnerability frequently lives in the gap between the handler and the wire: middleware
ordering, a framework re-parsing a parameter the validator already checked, a serializer
re-introducing the payload, a router normalizing a traversal differently than the check did. A
fix verified only at the function boundary can leave all of those intact.

What already exists:

- `skills/sast-assist/bin/app-harness.cjs` discovers, boots, probes and tears down the app.
  Discovery reads the repo and never invents a command.
- `skills/sast-assist/bin/witness-run.cjs` runs the four-step differential.
- `skills/sast-assist/references/DYNAMIC-WITNESS.md` holds the sandbox rules.
- `skills/sast-assist/test/e2e-witness.cjs` boots three trees of the fixture app and passes.

What is measured, from that e2e run. An honest fix produced `differential_ok=true` with the
control green on both trees. A fix that disabled the endpoint **also** produced
`differential_ok=true`, because the attack genuinely stopped working, and was caught only by the
functional control.

Before enabling it on a real repo, answer these:

- Does the service boot cold with no network, no real credentials and no production-shaped data?
  If it needs a VPN or a secrets manager, the tier silently degrades and the defense is weaker
  than it looks.
- Who writes the fixture data and the dummy principals? A cross-tenant witness needs at least
  two dummy tenants with distinguishable data.
- Is per-attempt app boot affordable against your CI budget?

**The functional control is NOT deferred.** It was discovered while designing this tier but it
applies to every tier. It stays active, because without it a patch can satisfy every other
obligation by disabling the functionality.

## 2. `ledger.cjs`: leases, resume and prior-run carry

Parent-owned read/write with TTL leases, so a crashed agent is distinguishable from a slow one.

## 3. Remaining witness tiers in the runner

`witness-run.cjs` implements `dynamic` and `argued`. The `executable` and `structural` tiers
throw rather than pretending. `executable` becomes the default once implemented.

Why `executable` is deferred rather than built cheaply. The witness file would be written by the
fixer during the fix, which breaks the rule that a witness is authored before the fix exists: a
fixer can write a test that imports something only the patch adds, so it fails on base and passes
on the patch, looking exactly like a valid differential. Telling "assertion failed" apart from
"crashed because it needs new code" needs each framework's own result format, TAP, pytest, go
test; exit codes alone cannot do it. Done with exit codes anyway, the tier would label a gamed fix
`fixed` instead of `fixed_unwitnessed`, which is worse than not having it.

## 4. Scanner coverage gaps found during the build

Neither scanner caught the SQL injection in `fixtures/vuln-app/src/routes/orders.js`, a template
string interpolated straight into a query. Worth understanding before trusting either tool's
silence. See the silent-zero section in `references/INGEST.md`.

## 5. Rescan delta against a same-rules scan of base

With `--scans`, the delta baseline comes from a scan whose rules the tool cannot see. Scanning
base once with the configured rules and diffing against that would remove the operator's burden,
at the cost of the scan `--scans` skips.
