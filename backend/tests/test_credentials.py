from datetime import datetime, timezone

from app.credentials import CredentialBroker


def test_credential_requires_token_proof() -> None:
    broker = CredentialBroker()
    credential = broker.issue("agt_test", "crm", {"read"})

    assert broker.validate(credential.credential_id, "agt_test", "crm", "read", credential.token)
    assert not broker.validate(credential.credential_id, "agt_test", "crm", "read", "wrong-token")
    assert not broker.validate(credential.credential_id, "agt_test", "crm", "delete", credential.token)


def test_credential_expires() -> None:
    broker = CredentialBroker()
    credential = broker.issue("agt_test", "crm", {"read"}, ttl_seconds=30)
    broker._credentials[credential.credential_id] = credential.__class__(
        **{**credential.__dict__, "expires_at": datetime.now(timezone.utc)}
    )

    assert not broker.validate(credential.credential_id, "agt_test", "crm", "read", credential.token)
