# Policy language

Policies are declarative rules evaluated on **every** tool call after identity, permission and credential
checks. A pack is YAML or JSON:

```yaml
version: fintech-support-2026.10
policies:
  - id: refund-above-threshold
    description: Refunds above 5,000 need finance manager approval.
    when:
      action: refund.issue
      amount_greater_than: 5000
    decision: require_human_approval
    approver_role: finance_manager
```

Load one with `AGENTGUARD_POLICY_FILE=policy/rules/fintech_support.yaml`, or replace the live pack
atomically with `POST /api/v1/policies` (admin). An invalid pack never loads.

## Decisions and precedence

When several rules match, the **strictest** wins. The baseline risk policy still runs, and rules can only
make a decision stricter.

| Decision | Aliases | Effect |
|---|---|---|
| `block` | `deny` | Never executes. |
| `escalate_to_human` | | Pauses for an operator (e.g. a production write). |
| `require_approval` | `require_human_approval` | Pauses for `approver_role`. |
| `allow_with_redaction` | | Executes with PII and secrets redacted from content and payload. |
| `rate_limit` | | Allows until the rule's limit is exceeded, then blocks with `retry_after_seconds`. |
| `allow` | | Executes. |

Precedence: `block > escalate_to_human > require_approval > allow_with_redaction > rate_limit > allow`.
Rate-limit tokens are only consumed by requests that would otherwise run.

## Conditions (all ANDed)

| Condition | Type | Matches when |
|---|---|---|
| `tool`, `action`, `environment`, `user_role`, `data_classification`, `content_source`, `tenant_id` | string or list | the request value is in the list |
| `not_<any of the above>` | string or list | the request value is **not** in the list (an absent value counts as not in it) |
| `amount_greater_than` / `amount_at_most` | number | `execution_payload.amount` is numeric and compares (non-numeric amounts never match) |
| `risk_at_least` / `risk_below` | number | the effective risk score after inspection compares |
| `session_risk_at_least` | number | the conversation's cumulative session risk compares (see [session guard](session-guard.md)) |
| `has_findings` | bool | PII or secrets were found in content or payload |
| `injection_detected` | bool | the content's injection score is ≥ 40 |
| `target_external` | bool | the target is a URL, contains "external", or is an email outside internal domains |
| `owner_mismatch` | bool | `user_id` ≠ `resource_owner_id` (resolved server-side) |
| `tenant_mismatch` | bool | `tenant_id` ≠ `resource_tenant_id` |
| `arg_equals` | mapping | each payload argument equals the value (`null` matches missing) |

Unknown condition keys and wrong types are rejected at load time, so a typo cannot silently weaken a rule.

## Rate limits

```yaml
- id: refund-request-rate-limit
  when: { action: refund.request }
  decision: rate_limit
  rate_limit: { limit: 5, window_seconds: 60, scope: agent }   # agent | tenant | global
```

## Testing a rule before shipping it

* `POST /api/v1/policies/validate` checks a pack without loading it.
* `POST /api/v1/policies/simulate` (or the console's Policy Studio) previews the decision for any request
  with no audit event, approval or rate-limit token used.
* `python scripts/release_gate.py <version>` replays all 156 evaluation cases against the live rules.
* `POST /api/v1/policies/impact` replays recorded decisions and re-runs the suite under the candidate for every
  agent version; shadow mode and canaries let you try it on live traffic ([policy-rollout.md](policy-rollout.md)).
* `policy/opa/sentinelforge.rego` mirrors the pack for OPA. `opa test policy/opa` runs the parity tests.
