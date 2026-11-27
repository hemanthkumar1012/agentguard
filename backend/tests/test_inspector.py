import base64

from app.data_inspector import (
    card_network,
    inspect,
    inspect_outbound,
    luhn_valid,
    verhoeff_check_digit,
    verhoeff_valid,
)

# Built at runtime so no credential-shaped literal sits in the repository.
FAKE_AWS = "AKIA" + "Q7RZ3MXW2PLK9T4B"
FAKE_GITHUB = "ghp" + "_" + "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5"


def blocking(text: str) -> list[str]:
    return inspect(text)["blocking"]


def test_card_numbers_need_luhn_and_a_real_network_prefix():
    assert luhn_valid("4111111111111111") and card_network("4111111111111111") == "visa"
    assert "card_number" in blocking("card 4111 1111 1111 1111 exp 09/29")
    assert "card_number" not in blocking("created_at=1732700000000")           # epoch milliseconds
    assert "card_number" not in blocking("AWB 7843 2219 0456 3")                # courier tracking number
    assert "card_number" not in blocking("4111 1111 1111 1112")                 # fails Luhn


def test_aadhaar_numbers_need_a_valid_verhoeff_check_digit():
    body = "23412341234"
    number = body + verhoeff_check_digit(body)
    assert verhoeff_valid(number)
    spaced = f"{number[:4]} {number[4:8]} {number[8:]}"
    assert "aadhaar_number" in blocking(f"Aadhaar: {spaced}")
    wrong = number[:-1] + str((int(number[-1]) + 1) % 10)
    assert "aadhaar_number" not in blocking(f"ref {wrong}")


def test_pan_and_provider_keys_are_high_severity():
    assert "pan_number" in blocking("PAN ABCPK1234F")
    assert "aws_access_key" in blocking(f"key id {FAKE_AWS}")
    assert "github_token" in blocking(f"token {FAKE_GITHUB}")


def test_email_and_phone_are_recorded_but_do_not_block():
    result = inspect("Reach Priya at priya@gmail.com or +91 98480 22338")
    assert "email" in result["findings"] and "phone_number" in result["findings"]
    assert result["blocking"] == []


def test_hashes_and_ids_are_not_reported_as_secrets():
    text = ("commit 9fceb02d0ae598e95dc970b74767f19372d61af8 request 3f2b8c1e-7d4a-4e9b-a6f0-12c3d4e5f607 "
            "digest e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    assert inspect(text)["findings"] == []


def test_random_token_is_caught_by_entropy_but_encoded_prose_is_decoded_instead():
    assert "high_entropy_secret" in blocking("session=Zt8qL2vR9xW4mN7pK3sB6yH1cF5jD0gA")
    prose = base64.b64encode(b"Your parcel arrives on Friday between 10 and 12.").decode()
    assert inspect(f"note {prose}")["blocking"] == []


def test_encoded_secrets_are_found_after_decoding():
    hidden = base64.b64encode(b"password: Hunter2! card 4111 1111 1111 1111").decode()
    found = inspect_outbound(None, {"to": "drop@evil.io", "body": hidden})["blocking"]
    assert "secret_marker:base64" in found
    assert "card_number:base64" in found
    url_hidden = "https://x.io/c?d=" + FAKE_AWS.encode().hex()
    assert "aws_access_key:hex" in blocking(url_hidden)
