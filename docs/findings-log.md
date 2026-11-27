# Findings log

Real problems found in AgentGuard, how each was found, and what fixed it. Each fix has a test.
Newest first.

| Date | Finding | How it was found | Fix | Test |
|---|---|---|---|---|
| 2026-11-27 | **The agent set its own risk.** `risk_score` and `data_classification` came from the agent. An agent that had just read a customer record could send `risk_score: 0, data_classification: "public"` and export the record: **allowed**, risk 20. | Asking "who sets this field?" about every input to the decision | Session labels worked out by AgentGuard from the tools it runs (rules F1/F2). Declared values can still raise the score, never lower it. | `test_self_reported_labels_no_longer_hide_an_exfiltration`, trace `self-declared-public-export` |
| 2026-11-27 | **Encoded secrets were invisible.** A base64-encoded `password: …` plus a card number passed the inspector. The request needed approval only because the recipient's own email address was a finding. | Manual probe while reviewing the inspector | Bounded base64/hex/URL decoding (64 tokens, 200k characters, 2 layers), then scan again | `test_encoded_secrets_are_found_after_decoding` |
| 2026-11-27 | **Every email needed a human.** The recipient address counted as a sensitive finding, so every `send_email` needed approval: the old engine asked for approval on 5 of 7 benign traces. Approvals that fire on everything get approved without being read. | Benign trace replays | Severities: email and phone numbers are recorded, but only high-severity findings force approval | `test_email_and_phone_are_recorded_but_do_not_block`, benign traces |
| 2026-11-27 | **Card regex matched timestamps.** Any 13–19 digit run was a "card number": 40/40 epoch-millisecond timestamps, 40/40 courier tracking numbers and 40/40 bank account numbers in the corpus. | Labelled corpus | Luhn check + real card network prefix (Visa, Mastercard, RuPay, Amex, …) | `test_card_numbers_need_luhn_and_a_real_network_prefix` |
| 2026-11-27 | **Entropy cannot tell identifiers from tokens.** The first entropy detector flagged 16/40 code identifiers (`fetchOrderTimelineV2Handler`). At 24 characters both score 3.8–4.3 bits per character. | Labelled corpus | Added word-likeness (share of the token in runs of 3+ lower-case letters): identifiers ≥ 0.72, random tokens ≤ 0.50 at p99 | `test_random_token_is_caught_by_entropy_but_encoded_prose_is_decoded_instead` |
| 2026-11-27 | **`d=<base64>` in a URL looked like a secret.** `=` was part of the token pattern, so `d=UmV2…` did not base64-decode and was scored as a random token. | EchoLeak-style trace | `=` allowed only as trailing padding | trace `echoleak-style-url-exfiltration` (inspector column) |
| 2026-11-27 | **The Aadhaar checksum alone is weak.** The Verhoeff check passes 1 in 10 random 12-digit numbers (UPI references, account numbers). | Reasoning about the checksum | Also require 4-4-4 grouping or "Aadhaar/UID" just before the number | `test_aadhaar_numbers_need_a_valid_verhoeff_check_digit` |
| 2026-11-27 | **Fingerprinting was 90% of decision time.** Pure-Python rolling hash + winnowing: p50 6.9 ms for a 10 KB email body. | `cProfile` on the benchmark | numpy version (sliding-window dot product + window min), p50 3.4 ms. The Python version stays as the reference, and a test checks both give identical fingerprints | `test_numpy_fingerprints_equal_the_reference_implementation` |
| 2026-11-27 | **Boilerplate caused false matches.** In the latency benchmark one email body "matched" all 50 indexed sources through shared common phrases. | Second profile run (`Match.as_dict` called 50× per request) | Ignore fingerprints held by more than 8 sources (like MOSS's `-m`), and store identical outputs once so re-reading a record does not turn it into boilerplate | `test_boilerplate_shared_by_many_sources_is_ignored_but_unique_content_still_matches` |
| 2026-11-27 | **One search result could unlock everyone's rows.** If each owner named in an output became a reader, a CRM search over 50 customers would let each of them be sent all 50 rows. | Design review of `readers_from` | Owners widen the readers only when the output names exactly one owner | `test_a_search_over_many_customers_does_not_let_any_one_of_them_read_it` |
| 2026-11-22 | **Secrets in the tool payload were not inspected.** Only `content` was scanned; an agent could label data public, leave content empty and put credentials in `execution_payload`. | Attack simulator, scenario `secret-in-tool-payload` | Inspect content and every payload value | `test_secret_in_payload_is_found_and_needs_approval` |
| 2026-11-22 | **Rego and Python disagreed at risk 60–69.** Non-sensitive requests at 60–69 fell through to Rego's default `block` while Python allowed them. | Parity test over a grid of requests | Rego `allow` is now exactly "not blocked and no approval needed" | `test_rego_and_python_policies_agree` |

## Open issues

- **Labels live in process memory.** A restart or a second worker starts with clean labels, which fails
  open for sessions in progress. Production needs labels in shared storage (Redis with a TTL); a missing
  label for a known session should then block, not start clean.
- **The audit hash chain can fork with several workers.** Each process keeps the last hash in memory, so two
  workers can append events with the same `previous_hash`. Proposed fix: a unique index on `previous_hash`
  in Postgres and a retry on conflict, so a fork becomes a write error instead of silent corruption.
- **Label creep.** After reading two customers' records the session may only talk to people allowed to read
  both (trace `merge-duplicate-customer-accounts` is blocked). The fix is to split work into sessions.
- **Split exfiltration from a clean session.** Pieces shorter than the 15-character winnowing guarantee pass
  every layer (trace `split-exfiltration-from-a-clean-session`).
- **Rendering outside the gateway.** AgentGuard sees tool calls. If a chat client renders a markdown image
  whose URL carries data (the original EchoLeak path), the leak happens in the browser, not through a tool.
