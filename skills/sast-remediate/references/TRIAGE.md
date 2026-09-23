# Triage

One agent per finding. The agent's job is to **refute**, not to assess. An agent asked "is this a
true positive" anchors on the scanner's claim. An agent told "disprove this" produces a usable
verdict.

The agent that triages never fixes. The agent that fixes never audits.

## What the agent returns

Exactly one JSON object matching the `triage` branch of `schema/agent-results.schema.json`,
with no surrounding prose. Malformed or prose-wrapped output is discarded whole, never repaired.
Re-run once with a fresh agent, then leave the finding open. The run ends `incomplete` and the
next run asks again.

Three verdicts, and the third is the one that makes this work.

**`exploitable`** carries a `SecurityContract`, an instance severity, and concrete impact,
likelihood and blast radius.

**`not_exploitable`** carries a closed-set reason and the code reference that already enforces
the invariant. It has no severity field.

**`undecidable`** carries a hypothesis contract and the exact missing fact. It has no severity
field.

`undecidable` is not a parking place for a weak hunch. It means a specific, source-grounded
hypothesis is blocked on a fact that is genuinely not in the repository. A deployment setting, a
proxy behavior, an identity policy, a caller outside this codebase. Name the fact and give a plan
that resolves it, either an owner observation or a bounded local check.

Forcing a binary call on those findings is how naive triage either drops real bugs or ships noise.

## Refutation reasons are a closed set

`input_is_not_attacker_controlled`, `control_on_path_already_enforces_invariant`,
`sink_is_not_the_dangerous_overload`, `defense_in_depth_gap_only`, `unreachable_code`,
`test_or_fixture_or_generated_code`, `rule_semantics_mismatch`.

Closed because a rejection has to be countable. "Thirty-seven rejected as
`defense_in_depth_gap_only`" is a rule-tuning signal a security team can act on. A paragraph of
prose per rejection is not.

`defense_in_depth_gap_only` deserves its own note. A large share of SAST noise is a rule firing
on a missing second layer while the first layer already prevents the attack. That is a hardening
note, not a vulnerability. Say which layer prevents it and where.

## The prompt

Include, in this order.

1. The role. Refute this candidate from repository source. Return exactly one JSON object.
2. The finding: invariant class, every site, every observation with its scanner's own claim.
3. The flow, in full, with each step's materialized source line.
4. The enclosing excerpt.
5. The discovered app harnesses and test command, so the agent can author the strongest witness.
6. This file's rubric and severity anchors.
7. The schema branch, verbatim.

Never include another agent's conclusion. Never include a prior verdict for this same finding.

### Switch on the flow

When `flow.kind` is `traced`:

> The path below is the scanner's claim. Attack it. Find the step where it is wrong. Check
> whether any step normalizes, validates, binds, escapes or authorizes the value. Compare what
> each component guarantees against what the next one assumes.

When `flow.kind` is `sink_only`:

> No dataflow path was provided. Establish reachability from an attacker-controlled entry point
> yourself before asserting anything. If you cannot reach this sink from untrusted input, the
> verdict is `not_exploitable` with reason `input_is_not_attacker_controlled`. If the entry point
> is outside this repository, the verdict is `undecidable`.

## Method

Name the lower-trust principal and its starting capability. Name the value, action or resource
selector it controls. Locate the control that should reject, bind, isolate or revoke it. Trace
the source path after that decision point. Stop at the smallest concrete result: a wrong return
value, an unauthorized record, a value reaching a dangerous sink.

Read sibling paths. Legacy, batch, retry, cancellation and error paths often reach the same sink
with weaker checks. Compare controls for equivalence, not mere presence.

A deployment, proxy, browser, broker or identity fact outside the source is not proof in either
direction. If it is decisive, return `undecidable`.

## Severity anchors

Only `exploitable` gets a severity, and it reflects demonstrated impact, not rule category.

**critical.** An unauthenticated actor gains code execution, full data-store access, or takeover
of arbitrary accounts.

**high.** An actor fully defeats an explicit control with real consequences. Authentication
bypass, cross-tenant read or write, stored script execution affecting other users, authenticated
code execution.

**medium.** A real boundary violation with limited blast radius, uncommon preconditions, or
consequences confined to a narrow resource set.

**low.** Disclosure of non-secret internals, or an effect needing sustained effort for minimal
gain.

**informational.** A confirmed but minimal observation, useful mainly as a prerequisite inside a
larger finding.

The discriminator between high and medium: does the demonstrated result fully defeat an explicit
control for an action with real consequences, or only weaken it? If you cannot state the concrete
damage, the severity is lower than it feels.

Overall severity never exceeds demonstrated impact.

## The contract

This is the deliverable. Everything downstream reads it and nothing downstream re-derives it.

**`invariant`.** The property that must hold, stated about values and boundaries. Never about
rules. The schema rejects any mention of a scanner name, scanner-artifact vocabulary such as
"suppress" or "false positive", and anything shaped like a rule id, because the fixer is never
shown the rule and the contract must not leak it back in. Ordinary words like warning or alert,
and property chains like `req.params.user.id`, are fine.

Good: "every string reaching the first argument of the process spawn in `ping` is an element of
the fixed `ALLOWED_HOSTS` list, and user input may only select an index into it."

Rejected: "the `js/command-line-injection` finding at line 6 must stop firing."

**`violating_input`.** A concrete value that breaks the invariant today. A value, not a category.

**`enforcement_point`.** File, symbol, and why this is the last trusted decision point rather
than the nearest place a patch would compile. The right place is frequently upstream of the sink
the scanner flagged.

**`witness`.** The strongest tier the repo supports, chosen from the enabled witness tiers listed
under Repository facts. See `FIX-AND-VERIFY.md` and `DYNAMIC-WITNESS.md`. Author it now, before
any fix exists. That is what makes the pre-patch run expressible, because by construction it only
touches API that already exists on the base commit.

**`writable_scope`.** Globs the fixer may modify. Anything else it touches is a guard violation.

**`forbidden_resolutions`.** Start from this fixed list, then add anything specific to this
finding. Every entry reaches the fixer, so name the forbidden move by its effect and never by the
tool that would notice it. The schema rejects scanner names here.

- a comment or annotation that turns off checking for a line, a block or a file
- editing checker configuration or an ignore file
- deleting, skipping or weakening an existing test
- removing the route, endpoint or feature instead of constraining its input
- rejecting every request, so the legitimate path breaks along with the attack
- adding, removing or upgrading a dependency
- touching any file outside `writable_scope`

## Splitting

If the sites in one finding need different enforcement points, they are not one root cause.
Return `{"split": [{"sites": [...], "why": "..."}]}` instead of a verdict. One split per finding
per run. A second split escalates to the human queue. No code tracks the split count; that
bookkeeping belongs to the parent and does not exist yet.
