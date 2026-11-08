import json

import pytest
from test_engine import CANARY

from local_agent_vault.broker import Broker
from local_agent_vault.engine import Call
from local_agent_vault.security import SafeError


@pytest.fixture
def broker(vault):
    vault.set("API_KEY", CANARY, ["https://api.example.com"], ["GET"])
    return Broker(vault.home)


@pytest.mark.parametrize("operation", ["get", "export", "set", "delete", "stop", "env"])
def test_agent_interface_cannot_manage_or_retrieve(broker, operation):
    response = json.loads(broker.respond({"op": operation, "name": "API_KEY"}))
    assert response["ok"] is False
    assert CANARY not in json.dumps(response)


def test_upstream_exception_never_reaches_agent_or_logs(broker, monkeypatch):
    def fail(call: Call):
        raise RuntimeError(f"Authorization: Bearer {CANARY}")

    monkeypatch.setattr(broker.engine, "execute", fail)
    response = broker.respond(
        {
            "op": "call",
            "call": {
                "url": "https://api.example.com/data",
                "secret": "API_KEY",
            },
        }
    )
    assert CANARY.encode() not in response
    assert json.loads(response)["error"] == "operation_failed"
    for audit in broker.home.glob("audit*.jsonl"):
        assert CANARY.encode() not in audit.read_bytes()


def test_validation_error_never_echoes_invalid_input(broker):
    response = broker.respond({"op": "call", "call": {"url": CANARY}})
    assert CANARY.encode() not in response
    assert json.loads(response)["error"] == "invalid_request"


def test_management_returns_metadata_only(broker):
    result = broker.respond(
        {
            "op": "set",
            "name": "NEW_KEY",
            "value": "new-canary-123456",
            "origins": ["https://api.example.com"],
            "methods": ["GET"],
        },
        management=True,
    )
    assert b"new-canary-123456" not in result
    assert json.loads(result)["result"] == {"stored": True}


def test_agent_unknown_operation_has_no_plaintext(broker):
    with pytest.raises(SafeError, match="operation_not_allowed"):
        broker.dispatch({"op": "get", "name": "API_KEY"})
