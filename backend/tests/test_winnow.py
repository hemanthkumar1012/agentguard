import base64
import random
import string
from urllib.parse import quote

from app.flow.winnow import (
    GUARANTEED_MATCH_LENGTH,
    K,
    decoded_variants,
    fingerprints,
    kgram_hashes,
    normalise,
    winnow,
)

rng = random.Random(20261127)
ALPHABET = string.ascii_lowercase + string.digits


def random_text(n: int) -> str:
    return "".join(rng.choice(ALPHABET) for _ in range(n))


def test_rolling_hash_matches_direct_hash_of_each_kgram():
    text = normalise("Flat 12B, Lakshmi Nagar, Tirupati 517501")
    rolled = kgram_hashes(text)
    direct = kgram_hashes(text[3:3 + K])  # one k-gram hashed from scratch
    assert rolled[3] == direct[0]
    assert len(rolled) == len(text) - K + 1


def test_numpy_fingerprints_equal_the_reference_implementation():
    for n in [0, 9, 10, 11, 15, 16, 40, 400, 3000]:
        for _ in range(20):
            text = "".join(rng.choice(ALPHABET + " ,.-తెలుగు") for _ in range(n))
            assert fingerprints(text) == winnow(kgram_hashes(normalise(text)))


def test_winnowing_guarantee_holds_for_random_documents():
    # Any shared run of at least w + k - 1 normalised characters must share a fingerprint.
    for _ in range(300):
        shared = random_text(GUARANTEED_MATCH_LENGTH + rng.randint(0, 20))
        a = random_text(rng.randint(0, 300)) + shared + random_text(rng.randint(0, 300))
        b = random_text(rng.randint(0, 300)) + shared + random_text(rng.randint(0, 300))
        assert fingerprints(a) & fingerprints(b), shared


def test_unrelated_random_documents_almost_never_share_fingerprints():
    collisions = sum(bool(fingerprints(random_text(500)) & fingerprints(random_text(500))) for _ in range(200))
    assert collisions <= 2


def test_formatting_changes_do_not_change_fingerprints():
    original = "Account: 5521-8890-1123, holder Priya Raman, branch Tirupati Main"
    reformatted = "account 55218890 1123 HOLDER priya raman / branch: tirupati-main"
    assert fingerprints(original) == fingerprints(reformatted)


def test_winnow_picks_the_window_minimum():
    assert winnow([5, 1, 7, 3, 9, 2, 8, 6], w=3) == {1, 3, 2}
    assert winnow([4, 4, 4], w=6) == {4}
    assert winnow([]) == set()


def test_decodes_base64_hex_url_and_nested_layers():
    secret = "password: Hunter2! for the payroll admin"
    b64 = base64.b64encode(secret.encode()).decode()
    variants = dict(decoded_variants(f"data={b64}"))
    assert variants["base64"] == secret
    assert dict(decoded_variants(secret.encode().hex()))["hex"] == secret
    nested = dict(decoded_variants("https://x.io/c?d=" + quote(b64, safe="")))
    assert nested["url+base64"] == secret


def test_hashes_and_ids_do_not_decode_into_findings():
    git_sha = "9fceb02d0ae598e95dc970b74767f19372d61af8"
    uuid = "3f2b8c1e-7d4a-4e9b-a6f0-12c3d4e5f607"
    sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert decoded_variants(f"{git_sha} {uuid} {sha256}") == []


def test_decoding_work_is_bounded():
    token = base64.b64encode(b"x" * 64).decode()
    variants = decoded_variants(" ".join([token] * 500))
    assert len(variants) <= 64


def test_boilerplate_shared_by_many_sources_is_ignored_but_unique_content_still_matches():
    from app.flow.fingerprints import FingerprintIndex

    index = FingerprintIndex(max_sources_per_fingerprint=3)
    boilerplate = "Thank you for contacting Acme support, your request has been received"
    for i in range(6):
        index.add(agent_id="a", session_id="s", source_id=f"evt_{i}", tool="crm", action="read",
                  readers=frozenset({"internal"}), output={"footer": boilerplate, "note": random_text(60)})
    assert index.match("a", "Hello! " + boilerplate) == []
    unique = "Flat 12B, Lakshmi Nagar, Tirupati 517501, landmark near the water tank"
    index.add(agent_id="a", session_id="s", source_id="evt_unique", tool="crm", action="read",
              readers=frozenset({"internal"}), output={"address": unique})
    assert [m.source.source_id for m in index.match("a", "ship to " + unique)] == ["evt_unique"]


def test_reading_the_same_record_again_does_not_make_it_boilerplate():
    from app.flow.fingerprints import FingerprintIndex

    index = FingerprintIndex(max_sources_per_fingerprint=3)
    record = {"address": "Flat 12B, Lakshmi Nagar, Tirupati 517501"}
    for i in range(10):
        index.add(agent_id="a", session_id="s", source_id=f"evt_{i}", tool="crm", action="read",
                  readers=frozenset({"internal"}), output=record)
    assert index.count("a") == 1
    assert index.match("a", record["address"])[0].source.source_id == "evt_0"
