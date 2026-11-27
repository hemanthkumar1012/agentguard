"""Checks model output before a client renders it: every URL in it is an outbound request.

EchoLeak (CVE-2025-32711) did not need a tool call. The model was steered into writing a markdown
image whose URL carried internal data; the client rendered the reply, the browser fetched the image,
and the data reached the attacker's server with zero clicks. A gateway that only sees tool calls
misses this, so clients should pass replies through POST /flow/check-output before rendering them.

Each URL in the text (markdown images and links, reference definitions, HTML src/href, bare URLs)
is treated as egress to its host:
- if private data seen earlier (fingerprints) or pieces of a tracked secret appear in the URL,
  it is removed whatever the session label says;
- if the session holds private data and the host's audience may not read it:
  - images are removed: the client fetches them with zero clicks;
  - links are removed when they are shaped to carry data (a query string, a fragment, or long path
    segments). A plain link such as https://fastapi.tiangolo.com/tutorial/ stays: it needs a click and
    has nowhere to hide much data. Data spread over short path segments can still slip through a link.
- otherwise it stays.
A removed URL is replaced with "#agentguard-removed", which keeps the markdown valid and fetches nothing.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import re
from urllib.parse import urlparse

from app.flow.labels import covers, flows_to

REMOVED = "#agentguard-removed"
_PATTERNS = [
    ("image", re.compile(r"!\[[^\]]*\]\(\s*<?(?P<url>[^)\s>]+)>?(?:\s+\"[^\"]*\")?\s*\)")),
    ("link", re.compile(r"(?<!!)\[[^\]]*\]\(\s*<?(?P<url>[^)\s>]+)>?(?:\s+\"[^\"]*\")?\s*\)")),
    ("reference", re.compile(r"^\s*\[[^\]]+\]:\s*<?(?P<url>\S+?)>?(?:\s+\"[^\"]*\")?\s*$", re.M)),
    ("html", re.compile(r"(?:src|href)\s*=\s*[\"'](?P<url>[^\"']+)[\"']", re.I)),
    ("bare", re.compile(r"(?<![(\"'<=])(?P<url>https?://[^\s)<>\"']+)")),
]


@dataclass(frozen=True)
class RemovedUrl:
    url: str
    kind: str
    host: str
    reason: str
    lineage: list[dict] = field(default_factory=list)


@dataclass(frozen=True)
class OutputCheck:
    text: str
    removed: list[RemovedUrl]
    urls_checked: int

    @property
    def sanitised(self) -> bool:
        return bool(self.removed)


AUTO_FETCHED = {"image", "html"}   # <img src> is fetched like a markdown image; <a href> is treated the same, to be safe


def data_shaped(url: str) -> bool:
    parsed = urlparse(url)
    segments = [s for s in parsed.path.split("/") if s]
    return bool(parsed.query or parsed.fragment or any(len(s) > 24 for s in segments) or len(parsed.path) > 80)


def find_urls(text: str) -> list[tuple[str, str]]:
    found: dict[str, str] = {}
    for kind, pattern in _PATTERNS:
        for match in pattern.finditer(text):
            url = match.group("url")
            if kind == "bare":
                url = url.rstrip(".,;:!?")   # auto-linkers leave trailing punctuation out of the link
            if urlparse(url).scheme in {"http", "https"} and url not in found:
                found[url] = kind
    return list(found.items())


def check_output(engine, agent_id: str, session_id: str | None, text: str) -> OutputCheck | None:
    """None if the session does not resolve (the caller should refuse to render)."""
    label = engine.sessions.resolve(agent_id, session_id)
    if label is None:
        return None
    removed: list[RemovedUrl] = []
    urls = find_urls(text)
    for url, kind in urls:
        host = urlparse(url).hostname or url
        audience = engine.destinations.audience(url)
        matches = [m for m in engine.index.match(agent_id, url) if not all(covers(m.source.readers, p) for p in audience)]
        pieces = [p for p in engine.pieces.observe(agent_id, url, url)
                  if not all(covers(p.secret.readers, a) for a in audience)]
        if matches or pieces:
            evidence = [m.as_dict() for m in matches] + [p.as_dict() for p in pieces]
            removed.append(RemovedUrl(url, kind, host, "the URL carries private data seen earlier", evidence))
        elif label.holds_private and not flows_to(label.readers, audience):
            if kind in AUTO_FETCHED:
                removed.append(RemovedUrl(url, kind, host,
                                          "this session read private data that this host may not read, and the "
                                          "client would fetch this URL without a click"))
            elif data_shaped(url):
                removed.append(RemovedUrl(url, kind, host,
                                          "this session read private data that this host may not read, and the "
                                          "link has room to carry it (query, fragment or long path)"))
    sanitised = text
    for item in removed:
        sanitised = sanitised.replace(item.url, REMOVED)
    return OutputCheck(text=sanitised, removed=removed, urls_checked=len(urls))
