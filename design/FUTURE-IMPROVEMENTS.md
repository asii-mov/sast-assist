# Future improvements

Planned work, deferred out of current scope. Ordered by value.

## 1. Dynamic verification (built, proven, not wired in)

Drive the running application over its real network interface and verify a patch against the
boundary an attacker actually reaches.

**Status: implemented and proven end to end, but deliberately not the default.**
`selectWitnessTier` does not auto-select it. Enable explicitly with `--witness=dynamic`.

Why it is worth turning on later. Source analysis and unit tests both reason about the handler.
The vulnerability frequently lives in the gap between the handler and the wire: middleware
ordering, a framework re-parsing a parameter the validator already checked, a serializer
re-introducing the payload, a router normalizing a traversal differently than the check did. A
fix verified only at the function boundary can leave all of those intact.

What already exists:

- `skills/sast-remediate/bin/app-harness.cjs` discovers, boots, probes and tears down the app.
  Discovery reads the repo and never invents a command.
- `skills/sast-remediate/bin/witness-run.cjs` runs the four-step differential.
- `skills/sast-remediate/references/DYNAMIC-WITNESS.md` holds the sandbox rules.
- `skills/sast-remediate/test/e2e-witness.cjs` boots three trees of the fixture app and passes.

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
- Is per-wave app boot affordable against your CI budget?

**The functional control is NOT deferred.** It was discovered while designing this tier but it
applies to every tier. It stays active, because without it a patch can satisfy every other
obligation by disabling the functionality.

## 2. Orchestration driver

The stage that spawns triage, fix and audit agents. `DESIGN.md` section 11, step 5. The
deterministic core and every agent contract exist; nothing drives them yet.

## 3. `partition.cjs`: conflict-graph fix waves

Partition findings into maximal independent sets so parallel fixers cannot collide. Specified in
`DESIGN.md` section 4.6. Needed only once a fixer is actually writing patches.

## 4. `ledger.cjs`: leases, resume and prior-run carry

Parent-owned read/write with TTL leases, so a crashed agent is distinguishable from a slow one.

## 5. Remaining witness tiers in the runner

`witness-run.cjs` implements `dynamic` and `argued`. The `executable` and `structural` tiers
throw rather than pretending. `executable` becomes the default once implemented, so this blocks
the driver.

## 6. Scanner coverage gaps found during the build

Neither scanner caught the SQL injection in `fixtures/vuln-app/src/routes/orders.js`, a template
string interpolated straight into a query. Worth understanding before trusting either tool's
silence. See the silent-zero section in `references/INGEST.md`.
