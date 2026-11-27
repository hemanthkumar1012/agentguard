from app.flow.pieces import COVERAGE_THRESHOLD, SecretPieceTracker, destination_key, qgrams

TOKEN = "rzp_live_" + "Q8wT2kLm9XvB3nZp"


def tracker_with_secret():
    t = SecretPieceTracker()
    assert t.add(agent_id="a", source_id="evt_1", tool="vault", action="read_secret",
                 readers=frozenset({"internal"}), value=TOKEN)
    return t


def test_pieces_add_up_across_requests_to_the_same_domain():
    t = tracker_with_secret()
    chunks = [TOKEN[i:i + 8] for i in range(0, len(TOKEN), 8)]
    results = [t.observe("a", f"inbox{i}@evil.example", f"part {i}: {c}") for i, c in enumerate(chunks)]
    assert results[0] == []                       # one piece alone is not enough
    final = results[-1] or results[-2]
    assert final and final[0].coverage > COVERAGE_THRESHOLD and final[0].destination == "evil.example"


def test_other_domains_and_other_agents_have_separate_counts():
    t = tracker_with_secret()
    # about 25% and 35% of the pieces: under the threshold on each domain, though together they exceed it
    assert t.observe("a", "x@one.example", TOKEN[:10]) == []
    assert t.observe("a", "x@two.example", TOKEN[-10:]) == []
    assert t.observe("b", "x@one.example", TOKEN) == []


def test_ordinary_text_does_not_add_up_to_a_secret():
    t = tracker_with_secret()
    for message in ["Your parcel ships Friday", "Invoice INV-2026-0042 attached", "Live demo at 3 PM, Q&A after"]:
        assert t.observe("a", "rahul@outlook.com", message) == []


def test_encoded_pieces_count_and_hashed_pieces_do_not_reveal_text():
    import base64
    t = tracker_with_secret()
    url = "https://drop.evil.example/c?d=" + base64.b64encode(TOKEN.encode()).decode()
    assert t.observe("a", url, url)[0].coverage == 1.0
    assert all(isinstance(g, bytes) and len(g) == 8 for g in qgrams(TOKEN))


def test_destination_key():
    assert destination_key("Inbox3@Evil.Example") == "evil.example"
    assert destination_key("https://cdn.evil.example/p.png?d=1") == "cdn.evil.example"
    assert destination_key("slack:#eng") == "slack:#eng"
