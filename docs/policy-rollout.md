# Safe policy changes: impact analysis, shadow mode, canary

A policy change is a production change with security consequences in both directions. Too loose lets money
move; too strict breaks support. SentinelForge never enforces a candidate pack until an operator promotes it,
and it refuses to enforce a pack that loosens recorded decisions without explicit acknowledgement.

## Decision log

Every enforced decision stores its **policy inputs**: action, target, tenant and ownership, **redacted**
arguments, effective risk, findings, injection and session signals, and the baseline decision. Raw content,
credential ids and tokens are never stored. This is what makes replay possible
(`GET /api/v1/policies/decision-log`).

## Impact analysis (`POST /api/v1/policies/impact`)

For a candidate pack, against every scripted agent version by default:

1. **Structural diff:** rules added, removed and changed (with the exact fields).
2. **First-order replay:** every recorded decision (live traffic, plus the decisions the 156-case suite
   produces for each version) is re-decided under the live and candidate packs. You get a live × candidate
   transition matrix, each flip classified as **tightening** or **relaxation**, grouped examples, per-rule hit
   counts and rules that never match.
3. **Second-order re-run:** the whole suite is re-run under the candidate pack for each version. A rule change
   can change what an agent does *next*, which a replay can't see. The report gives each version's release
   decision under both packs, regressed gates, and newly failing and passing cases.
4. **Verdict:** `unsafe` (a critical gate regresses), `review` (relaxations), `tightening`, or `no_change`.

**Example: raise the refund approval threshold from ₹5,000 to ₹20,000.**

| | Result |
|---|---|
| Diff | `refund-above-threshold` · `when` changed |
| Replay | 9 of 661 decisions relax: `refund.issue` ₹18,000 ×5 and ₹5,001 ×4 go from `require_approval` to `allow` |
| support-agent-v1.0 | approved → approved (it drafts refunds, so it isn't affected) |
| support-agent-v2.1 | **approved → blocked** (policy compliance 100% → 93.7%; `sup-033`, `sup-034`, `mis-017`, `mis-019` newly fail) |
| Verdict | **UNSAFE**, in about 4 seconds for three agent versions |

## Shadow mode

`POST /policies/shadow` evaluates a candidate beside the live pack on real traffic. Its decision is recorded
on the response (`shadow_decision`) and in a disagreement report (agreement rate, looser and stricter counts,
examples). It is never enforced. Stop it with `POST /policies/shadow/stop`.

## Canary

`POST /policies/canary` **enforces** a candidate for chosen tenants and/or a deterministic percentage of
sessions (≤ 50%, sticky per conversation, so a session never flips packs mid-way). Each decision is tagged with
the `policy_pack` that made it. The canary tracks hold and block rates against live traffic and **rolls itself
back** if its strictness shifts by more than 30 points after 20 decisions, writing a `policy.canary.rollback`
audit event. Use `POST /policies/canary/promote` to make it live, or `/rollback` to drop it.

## Guard rails

* `POST /policies`, starting a canary and promoting a canary all replay the live decision log first. If any
  recorded decision becomes less strict, the request returns **409** with examples unless
  `acknowledge_relaxations: true` is sent.
* The console can analyze, shadow, canary, promote and roll back, but replacing the live pack directly is
  API-only (admin).
* Rate-limit rules are excluded from replay, so analysis never consumes or depends on live counters.

In the console, these all live in **Policy Studio → Change management**, which has presets for common
mistakes: raise the threshold, lower it, drop the injection rule, deny all external email.
