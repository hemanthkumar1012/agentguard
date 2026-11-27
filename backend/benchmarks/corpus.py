"""Labelled corpus for the outbound data inspector, generated from a fixed seed.

Every sample answers one question: should this text force a human approval before it leaves?

- positives contain a credential, card number or government ID, in plain form or encoded;
- negatives contain things that look similar but are not secrets: emails, phone numbers,
  timestamps, tracking and order numbers, hashes, UUIDs, URLs, masked or placeholder values.

The values are synthetic (random, with the right format and checksums), generated at runtime so
no credential-shaped string is stored in the repository. Limits of this corpus: it was written by
the same person who wrote the detectors, so it is easier than real traffic; it is useful for
comparing detector versions and catching regressions, not for claiming real-world accuracy.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import json
import random
import string
from urllib.parse import quote

from app.data_inspector import luhn_valid, verhoeff_check_digit

SEED = 20261127
UPPER, LOWER, DIGITS = string.ascii_uppercase, string.ascii_lowercase, string.digits
ALNUM = UPPER + LOWER + DIGITS


@dataclass(frozen=True)
class Sample:
    text: str
    positive: bool
    category: str
    encoding: str = "plain"
    hard: bool = False      # a case the detector is known to miss; reported separately, not hidden


class Gen:
    def __init__(self, seed: int = SEED) -> None:
        self.r = random.Random(seed)

    def s(self, alphabet: str, n: int) -> str:
        return "".join(self.r.choice(alphabet) for _ in range(n))

    def pick(self, items):
        return self.r.choice(items)

    # positives -------------------------------------------------------------------
    def aws(self):
        return self.pick(["AKIA", "ASIA"]) + self.s(UPPER + DIGITS, 16)

    def github(self):
        return "ghp" + "_" + self.s(ALNUM, 36)

    def google(self):
        return "AI" + "za" + self.s(ALNUM + "_-", 35)

    def slack(self):
        return "xo" + "xb-" + self.s(DIGITS, 11) + "-" + self.s(DIGITS, 12) + "-" + self.s(ALNUM, 24)

    def stripe(self):
        return "sk" + "_live_" + self.s(ALNUM, 24)

    def jwt(self):
        def b64(obj):
            return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")
        return f"{b64({'alg': 'HS256', 'typ': 'JWT'})}.{b64({'sub': self.s(DIGITS, 8), 'role': 'admin'})}.{self.s(ALNUM + '_-', 43)}"

    def private_key(self):
        return "-----BEGIN " + self.pick(["RSA ", "EC ", "OPENSSH ", ""]) + "PRIVATE KEY-----\n" + self.s(ALNUM + "+/", 64)

    def password(self):
        key = self.pick(["password", "Password", "DB_PASSWORD", "pwd", "client_secret", "SMTP_PASSWORD"])
        return f"{key}{self.pick([': ', '=', ' = '])}{self.s(ALNUM + '!@#$%', self.r.randint(8, 16))}"

    def bearer(self):
        return "Authorization: Bearer " + self.s(ALNUM + "-_.", self.r.randint(32, 48))

    def conn_string(self):
        return f"{self.pick(['postgres', 'mysql', 'mongodb+srv', 'redis'])}://{self.pick(['admin', 'app', 'svc'])}:" \
               f"{self.s(ALNUM, 12)}@{self.pick(['db.internal', 'cache.prod.local', 'cluster0.ab12c.mongodb.net'])}"

    def card(self):
        prefix = self.pick(["4", "51", "53", "55", "60", "65", "2221"])
        body = prefix + self.s(DIGITS, 15 - len(prefix))
        check = next(d for d in DIGITS if luhn_valid(body + d))
        number = body + check
        sep = self.pick([" ", "-", ""])
        return sep.join(number[i:i + 4] for i in range(0, 16, 4))

    def aadhaar(self):
        body = self.pick("23456789") + self.s(DIGITS, 10)
        number = body + verhoeff_check_digit(body)
        if self.r.random() < 0.6:
            return f"{number[:4]} {number[4:8]} {number[8:]}"
        return f"Aadhaar no. {number}"

    def pan(self):
        return self.s(UPPER, 3) + self.pick("PCHFT") + self.s(UPPER, 1) + self.s(DIGITS, 4) + self.s(UPPER, 1)

    def raw_token(self):
        while True:
            token = self.s(ALNUM, self.r.randint(32, 44))
            if any(c.isdigit() for c in token) and any(c.isupper() for c in token) and any(c.islower() for c in token):
                return token

    # negatives -------------------------------------------------------------------
    def phone(self):
        return self.pick(["+91 ", "", "+91-"]) + self.pick("6789") + self.s(DIGITS, 4) + self.pick([" ", ""]) + self.s(DIGITS, 5)

    def email(self):
        return f"{self.pick(['priya', 'rahul.k', 'support', 'accounts', 'arjun99'])}@{self.pick(['gmail.com', 'acme.in', 'outlook.com', 'zoho.in'])}"

    def account_like(self):
        return self.pick(["1", "3", "7", "9"]) + self.s(DIGITS, 15)

    def upi_ref(self):
        return self.pick("23456789") + self.s(DIGITS, 11)


SENTENCES = [
    "Hi team, sharing the details below for the integration. {v}",
    "As discussed on the call, here you go: {v}",
    "Please update the config with {v} before Friday's release.",
    "Customer asked us to keep this on file: {v}",
    "{v}",
]
BENIGN = [
    "Your parcel {order} is out for delivery and should reach Tirupati by 6 PM today.",
    "Meeting moved to Thursday 3:30 PM IST. Agenda: Q3 roadmap, hiring, on-call rotation.",
    "Invoice INV-2026-{n4} for Rs. 18,450 has been generated. Due date: 15 December 2026.",
    "Thanks for reaching out! Our support team will get back to you within 24 hours.",
    "Reset your password from Settings > Security if you cannot sign in.",
    "The build failed on step 4 (lint). Please rerun after fixing the import order.",
]


def _templated(g: Gen, value: str) -> str:
    return g.pick(SENTENCES).format(v=value)


def _encodings(g: Gen, text: str) -> list[tuple[str, str]]:
    return [
        ("plain", text),
        ("base64", base64.b64encode(text.encode()).decode()),
        ("hex", text.encode().hex()),
        ("url", "https://collect.example.net/p?d=" + quote(text, safe="")),
    ]


def build(seed: int = SEED, per_category: int = 40) -> list[Sample]:
    g = Gen(seed)
    samples: list[Sample] = []
    positives = {
        "aws_access_key": g.aws, "github_token": g.github, "google_api_key": g.google, "slack_token": g.slack,
        "stripe_key": g.stripe, "jwt": g.jwt, "private_key": g.private_key, "password_assignment": g.password,
        "bearer_token": g.bearer, "connection_string": g.conn_string, "card_number": g.card,
        "aadhaar_number": g.aadhaar, "pan_number": lambda: "PAN: " + g.pan(),
        "unlabelled_random_token": lambda: "token you asked for: " + g.raw_token(),
    }
    for category, make in positives.items():
        for i in range(per_category):
            text = _templated(g, make())
            encoding, encoded = _encodings(g, text)[i % 4]
            samples.append(Sample(encoded, True, category, encoding))

    order = lambda: g.pick(["ORD", "AWB", "SHP"]) + "-" + g.s(DIGITS, 10)
    negatives = {
        "business_text": lambda: g.pick(BENIGN).format(order=order(), n4=g.s(DIGITS, 4)),
        "email_signature": lambda: f"Regards,\nPriya Raman\n{g.email()} | {g.phone()}",
        "recipient_list": lambda: "to: " + ", ".join(g.email() for _ in range(3)),
        "epoch_and_iso_timestamps": lambda: f"created_at={g.r.randint(1_600_000_000_000, 1_800_000_000_000)} "
                                            f"updated=2026-11-{g.r.randint(10, 28)}T10:{g.r.randint(10, 59)}:00Z",
        "tracking_numbers": lambda: f"AWB {g.s(DIGITS, 13)} / consignment {g.s(DIGITS, 12)}",
        "bank_account_numbers": lambda: f"Credit to account {g.account_like()} IFSC SBIN0{g.s(DIGITS, 6)}",
        "upi_references": lambda: f"UPI ref {g.upi_ref()} received for Rs. {g.r.randint(100, 9999)}",
        "hashes_and_uuids": lambda: f"commit {g.s('0123456789abcdef', 40)} req "
                                    f"{g.s('0123456789abcdef', 8)}-{g.s('0123456789abcdef', 4)}-4{g.s('0123456789abcdef', 3)}-"
                                    f"a{g.s('0123456789abcdef', 3)}-{g.s('0123456789abcdef', 12)}",
        "urls_with_ids": lambda: f"https://shop.example.in/orders/{g.s(DIGITS, 9)}?utm_source=email&ref={g.s(LOWER, 8)}",
        "masked_and_placeholder_secrets": lambda: g.pick(["password: ********", "api_key=YOUR_API_KEY",
                                                          "token: <redacted>", "pwd=${DB_PASSWORD}", "secret = changeme"]),
        "base64_attachment_text": lambda: base64.b64encode(g.pick(BENIGN).format(order=order(), n4="0042").encode()).decode(),
        "code_identifiers": lambda: f"const {g.pick(['getUserAccountSummary2026', 'fetchOrderTimelineV2Handler', 'renderInvoicePdfTemplate3'])} = useMemo(...)",
    }
    for category, make in negatives.items():
        for _ in range(per_category):
            samples.append(Sample(make(), False, category))

    # Known gaps. Regex, checksum and entropy detectors cannot see these; the data-flow rules
    # (session labels) are what stop them when the data came from a tool AgentGuard ran.
    hard = {
        "password_without_marker": lambda: f"the wifi for the Tirupati office is {g.pick(['Venkat', 'Tirumala', 'Sv'])}@{g.s(DIGITS, 4)}",
        "secret_split_across_lines": lambda: (lambda k: f"key part one: {k[:10]}\npart two: {k[10:]}")(g.aws()),
        "hex_of_random_bytes": lambda: "blob " + bytes(g.r.randrange(256) for _ in range(24)).hex(),
        "telugu_password_label": lambda: f"పాస్‌వర్డ్ {g.s(ALNUM, 10)}",
        "spaced_out_marker": lambda: f"p a s s w o r d : {g.s(ALNUM, 10)}",
    }
    for category, make in hard.items():
        for _ in range(per_category // 4):
            samples.append(Sample(make(), True, category, hard=True))
    return samples
