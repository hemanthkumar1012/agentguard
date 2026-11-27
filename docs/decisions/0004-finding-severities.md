# 0004. Only high-severity findings force an approval

Date: 2026-11-27. Status: accepted.

## Context

Since 2026-11-22 any inspector finding in outbound data forced a human approval. The inspector reported
email addresses, so every `send_email` needed approval because of the recipient's own address. On the
benign traces the old engine asked for approval on 5 of 7 flows. The card-number pattern also matched
epoch timestamps and tracking numbers.

## Decision

- Findings have a severity. **High** (keys, tokens, passwords, connection strings, card numbers, Aadhaar
  and PAN numbers) forces approval. **Low** (email addresses, phone numbers) is recorded in the audit
  trail and does not change the decision by itself. Real personal-data leaks are handled by the data-flow
  rules, which know *whose* data it is and where it is going.
- Detectors must be validated, not just matched: Luhn + card network prefix for cards, Verhoeff +
  grouping/keyword for Aadhaar, entropy + word-likeness for unlabelled tokens, and placeholders like
  `password: ********` or `api_key=YOUR_API_KEY` are skipped.
- Quality is measured on a labelled corpus (`backend/benchmarks/corpus.py`), with a CI gate on recall and
  false-positive rate.
- Only high-severity findings go to the policy engines (Python and Rego), so the Rego parity test now
  passes `blocking` findings.

## Consequences

- Corpus results: the old detector had 0.082 recall and 0.452 false-positive rate; the new one
  scores 1.000 and 0.000. The corpus is synthetic and was written alongside the detectors, so these
  numbers are for comparing versions, not a real-world claim. Five known-gap categories (passwords
  without a label, secrets split across lines, hex of random bytes, a Telugu password label, spaced-out
  markers) are reported separately: 0 of 50 caught.
- An email body that contains only customer contact details no longer needs approval through the
  inspector. If that data came from a private tool, the flow rules decide.
