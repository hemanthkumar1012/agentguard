import base64
import hashlib
import hmac
import json
import time
from typing import Any

from app.config import settings


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + ("=" * (-len(value) % 4)))


def _sign(message: str) -> str:
    if not settings.api_key:
        raise RuntimeError("AGENTGUARD_API_KEY is required for browser tokens")
    return _b64(hmac.new(settings.api_key.encode("utf-8"), message.encode("utf-8"), hashlib.sha256).digest())


def issue_browser_token(agent_id: str, ttl_seconds: int = 86_400) -> tuple[str, int]:
    now = int(time.time())
    payload = {
        "iss": "agentguard",
        "aud": "agentguard-browser",
        "sub": agent_id,
        "scope": ["browser:inspect", "browser:approval"],
        "iat": now,
        "exp": now + ttl_seconds,
        "jti": _b64(hashlib.sha256(f"{agent_id}:{now}".encode("utf-8")).digest()[:12]),
    }
    header = {"alg": "HS256", "typ": "AGT"}
    encoded_header = _b64(json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    encoded_payload = _b64(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    unsigned = f"{encoded_header}.{encoded_payload}"
    return f"{unsigned}.{_sign(unsigned)}", payload["exp"]


def verify_browser_token(token: str) -> dict[str, Any]:
    try:
        header, payload, signature = token.split(".", 2)
        unsigned = f"{header}.{payload}"
        expected = _sign(unsigned)
        if not hmac.compare_digest(signature, expected):
            raise ValueError("Invalid browser token signature")
        claims = json.loads(_unb64(payload).decode("utf-8"))
        if header != _b64(json.dumps({"alg": "HS256", "typ": "AGT"}, separators=(",", ":"), sort_keys=True).encode("utf-8")):
            raise ValueError("Invalid browser token header")
        if claims.get("iss") != "agentguard" or claims.get("aud") != "agentguard-browser":
            raise ValueError("Invalid browser token audience")
        if "browser:inspect" not in claims.get("scope", []):
            raise ValueError("Browser inspection scope is missing")
        if int(claims.get("exp", 0)) <= int(time.time()):
            raise ValueError("Browser token has expired")
        if not claims.get("sub"):
            raise ValueError("Browser token subject is missing")
        return claims
    except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid browser token") from exc
