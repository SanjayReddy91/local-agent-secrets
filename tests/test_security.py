import base64
import json

import pytest

from local_agent_vault.security import (
    Redactor,
    SafeError,
    require_public_ip,
    validate_target,
)


@pytest.mark.parametrize(
    "target",
    [
        "http://api.example.com/data",
        "https://api.example.com.evil.test/data",
        "https://api.example.com@evil.test/data",
        "https://user@api.example.com/data",
        "https://api.example.com:444/data",
        "https://api.example.com./data",
        "https://api.example.com/data#fragment",
        "https://api.example.com\\@evil.test/data",
        "https://api.example.com/\ndata",
    ],
)
def test_disallowed_targets(target):
    with pytest.raises(SafeError):
        validate_target(target, ["https://api.example.com"])


def test_exact_origin():
    assert (
        validate_target("https://api.example.com/v1?q=1", ["https://api.example.com"])
        == "api.example.com"
    )


@pytest.mark.parametrize(
    "address",
    ["127.0.0.1", "10.0.0.1", "169.254.169.254", "::1", "::ffff:8.8.8.8"],
)
def test_private_and_mapped_ips_are_blocked(address):
    with pytest.raises(SafeError):
        require_public_ip(address)


def test_redaction_covers_nested_keys_values_and_encoded_credentials():
    secret = 'canary-secret-"/42'
    redactor = Redactor([secret])
    payload = {
        secret: [
            secret,
            base64.b64encode(secret.encode()).decode(),
            secret.encode().hex(),
        ],
        "escaped": json.dumps(secret)[1:-1],
    }
    output = json.dumps(redactor.scrub(payload))
    assert secret not in output
    assert base64.b64encode(secret.encode()).decode() not in output
    assert secret.encode().hex() not in output
    assert "REDACTED" in output


def test_numeric_secret_does_not_escape_as_json_number():
    assert Redactor(["12345"]).scrub({"token": 12345}) == {"token": "[REDACTED]"}
