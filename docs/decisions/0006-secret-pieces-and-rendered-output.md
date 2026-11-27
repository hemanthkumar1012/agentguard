# 0006. Secrets in pieces, and URLs in rendered replies

Date: 2026-11-27. Status: accepted.

## Context

Two leaks passed every layer in the first benchmark:

1. **A secret sent in pieces.** Winnowing (0003) only guarantees a match for runs of 15+ characters, so a
   token sent 8 characters at a time from a clean session got through.
2. **A URL in the reply.** In EchoLeak (CVE-2025-32711) the model wrote a markdown image whose URL carried
   internal data, and the client fetched it while rendering. No tool call was involved, so a gateway that
   only sees tool calls never saw it.

## Decision

**Rule F5, secret pieces.** For short values (8–256 characters) that a private tool returned and the
inspector rates high severity, AgentGuard keeps the set of 4-character pieces (q-grams). Every outbound
request adds the pieces it contains to a running total per (agent, destination domain, secret) over 24
hours. Once more than half of a secret's pieces have reached a domain that may not read it, F5 fires:
block if the session is untrusted, otherwise approval.

- q = 4, because cutting a 23-character token into 8-character pieces leaves only 39% of its 6-grams
  visible (the ones spanning the cuts are lost) but 65% of its 4-grams.
- Keyed by domain, so rotating addresses at the attacker's domain does not reset the count.
- Only secret-like values: 4-grams of names and addresses ("tiru", "naga") are common in ordinary text
  and would add up to false matches; 4-grams of random tokens are not.
- Pieces are kept as keyed hashes, not text, so the structure does not spell the secret out in a log
  or dump.

**Rule O1, rendered output.** `POST /flow/check-output` finds every URL in a reply (markdown images and
links, reference definitions, HTML `src`/`href`, bare URLs) and treats it as egress:

- a URL carrying fingerprints or secret pieces of earlier private output is removed, whatever the label;
- in a session holding private data, an image to a host outside the data's readers is removed, because
  the client fetches it with zero clicks; a link is removed only when it is shaped to carry data (query,
  fragment, long path segments), because it needs a click and a plain documentation link is ordinary;
- removed URLs become `#agentguard-removed`, which keeps the markdown valid and fetches nothing.

## Alternatives considered

- **Lower winnowing's K.** Short k-grams match common words everywhere; the false matches would land on
  every kind of data, not only secrets.
- **Block repeated sends to a domain.** Rate limits slow the attack down, but do not tell a secret leaking
  from a newsletter going out.
- **Strip every URL from replies in tainted sessions.** That was the first version; the benign trace with a
  documentation link showed it removes ordinary links. Images and links carry different risks.
- **Render images through a proxy that checks them.** Works for one client; the output check works for any
  client that calls it.

## Consequences

- `split-exfiltration-from-a-clean-session`, `split-exfiltration-across-addresses` and
  `echoleak-markdown-image-in-the-reply` are stopped; no other layer catches them.
- Known gaps: pieces of 3 characters or fewer; data spread over short path segments of a plain link.
- Clients must call the output check: AgentGuard cannot see what a client renders unless asked.
- Cost: with 20 secrets tracked, a 10 KB request takes 4.1 ms p50 (see `docs/benchmarks.md`).
