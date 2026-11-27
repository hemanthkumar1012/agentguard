# 0003. Winnowing fingerprints for exfiltration evidence

Date: 2026-11-27. Status: accepted.

## Context

Session labels (0002) answer "could this session leak?". They cannot see data that crosses a session
boundary, for example something read on Monday, kept in the agent's memory and sent from a clean session
on Tuesday. They also give a reviewer no evidence: "the session is tainted" does not show *what* is leaving.

## Decision

When AgentGuard runs a tool that returns private data, it fingerprints each string value of the output
with **winnowing** (Schleimer, Wilkerson and Aiken, SIGMOD 2003, the algorithm behind MOSS):

1. normalise: lower case, keep only letters and digits, so formatting changes do not matter;
2. hash every k-gram (K = 10) with a polynomial rolling hash modulo 2^64;
3. keep the minimum hash of each window of W = 6 hashes.

Guarantee: any shared run of at least W + K − 1 = **15 normalised characters** produces a shared
fingerprint. An outgoing request is fingerprinted the same way, also after bounded base64/hex/URL
decoding, and looked up in a per-agent inverted index. A match names the source event, session, tool and
readers, which becomes the request's `lineage` and an audit finding.

Tuning:

- `MIN_SHARED_FINGERPRINTS = 2`: one shared hash can be chance; two rarely are.
- Fingerprints held by more than 8 sources are ignored as boilerplate (like MOSS's `-m`), and identical
  outputs are stored once so re-reading a record does not turn it into boilerplate.
- 256 sources per agent, 4,096 fingerprints per source, LRU eviction.

## Alternatives considered

- **Exact substring search of every stored output.** O(stored × request) per request and broken by any
  change in whitespace or case.
- **Hash of each whole value.** Misses any partial copy ("ships to Flat 12B, Lakshmi Nagar…").
- **Embeddings / semantic similarity.** Would catch paraphrases, but needs a model in the decision path,
  is not deterministic, and the threshold is a guess. Paraphrases are left to the label rule instead.

## Consequences

- Catches verbatim, reformatted and encoded copies across sessions (`leak-from-memory-in-a-new-session`
  is stopped only by this layer). Cannot catch paraphrases or pieces shorter than 15 characters
  (`split-exfiltration-from-a-clean-session` is a known gap).
- A power-of-two modulus makes deliberate hash collisions easy to build. A collision can only create a
  false match, never hide a leak, so this was accepted for speed.
- Performance: the pure-Python version cost 6.9 ms p50 for a 10 KB body (90% of decision time). The
  numpy version brings the whole decision to 3.4 ms. The Python version is kept as the reference
  implementation and tested for identical output.
