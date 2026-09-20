from app.rate_limit import RateLimiter


def test_rate_limiter_blocks_after_limit():
    limiter = RateLimiter(limit=2, window_seconds=60)

    assert limiter.allow("client")[0] is True
    assert limiter.allow("client")[0] is True
    allowed, retry_after = limiter.allow("client")

    assert allowed is False
    assert retry_after >= 1
