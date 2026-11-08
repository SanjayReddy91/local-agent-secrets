import base64
import json

import httpx
import pytest

from local_agent_vault.engine import Call, Engine, public_addresses
from local_agent_vault.security import SafeError

CANARY = "canary-api-token-987654321"


@pytest.fixture
def engine(vault, monkeypatch):
    vault.set("API_KEY", CANARY, ["https://api.example.com"], ["GET"])
    monkeypatch.setattr(
        "local_agent_vault.engine.public_addresses", lambda host: ["8.8.8.8"]
    )
    return Engine(vault)


def mock_upstream(monkeypatch, handler):
    client_class = httpx.Client
    monkeypatch.setattr(
        "local_agent_vault.engine.httpx.Client",
        lambda **kwargs: client_class(transport=httpx.MockTransport(handler), **kwargs),
    )


def test_injection_and_response_redaction(engine, monkeypatch):
    def upstream(request):
        assert request.url.host == "8.8.8.8"
        assert request.headers["host"] == "api.example.com"
        assert request.extensions["sni_hostname"] == "api.example.com"
        assert request.headers["authorization"] == f"Bearer {CANARY}"
        return httpx.Response(
            200,
            stream=httpx.ByteStream(
                json.dumps(
                    {
                        "echo": CANARY,
                        "encoded": base64.b64encode(CANARY.encode()).decode(),
                    }
                ).encode()
            ),
            headers={"Content-Type": "application/json", "X-Echo": CANARY},
        )

    mock_upstream(monkeypatch, upstream)
    result = engine.execute(Call(url="https://api.example.com/data", secret="API_KEY"))
    serialized = json.dumps(result)
    assert CANARY not in serialized
    assert base64.b64encode(CANARY.encode()).decode() not in serialized
    assert "X-Echo" not in serialized
    assert result["redacted"] is True


@pytest.mark.parametrize("status_code", [301, 302, 307, 308])
def test_redirects_never_followed(engine, monkeypatch, status_code):
    mock_upstream(
        monkeypatch,
        lambda request: httpx.Response(
            status_code, headers={"location": f"https://evil.test/{CANARY}"}
        ),
    )
    with pytest.raises(SafeError, match="redirect_blocked"):
        engine.execute(Call(url="https://api.example.com/data", secret="API_KEY"))


def test_method_rejected_before_network(engine):
    with pytest.raises(SafeError, match="method_not_allowed"):
        engine.execute(
            Call(url="https://api.example.com/data", secret="API_KEY", method="DELETE")
        )


def test_other_origin_rejected(engine):
    with pytest.raises(SafeError, match="destination_not_allowed"):
        engine.execute(Call(url="https://evil.test/data", secret="API_KEY"))


@pytest.mark.parametrize("location", ["url", "headers", "body"])
def test_literal_secret_in_request_is_forwarded(engine, monkeypatch, location):
    def upstream(request):
        if location == "url":
            assert request.url.params["token"] == CANARY
        elif location == "headers":
            assert request.headers["x-example"] == CANARY
        else:
            assert json.loads(request.content) == {"token": CANARY}
        return httpx.Response(
            200,
            headers={"Content-Type": "application/json"},
            stream=httpx.ByteStream(json.dumps({"echo": CANARY}).encode()),
        )

    mock_upstream(monkeypatch, upstream)
    result = engine.execute(
        Call(
            url=(
                f"https://api.example.com/data?token={CANARY}"
                if location == "url"
                else "https://api.example.com/data"
            ),
            secret="API_KEY",
            headers={"X-Example": CANARY} if location == "headers" else {},
            body={"token": CANARY} if location == "body" else None,
        )
    )
    assert result["status_code"] == 200
    assert result["body"] == {"echo": "[REDACTED]"}
    assert result["redacted"] is True


def test_basic_username_in_origin_is_allowed(engine, monkeypatch):
    credential = "postman:password"
    engine.vault.set("POSTMAN_BASIC", credential, ["https://postman-echo.com"], ["GET"])

    def upstream(request):
        assert request.headers["host"] == "postman-echo.com"
        assert request.url.path == "/basic-auth"
        encoded = base64.b64encode(credential.encode()).decode()
        assert request.headers["authorization"] == f"Basic {encoded}"
        return httpx.Response(
            200,
            headers={"Content-Type": "application/json"},
            stream=httpx.ByteStream(b'{"authenticated": true}'),
        )

    mock_upstream(monkeypatch, upstream)
    result = engine.execute(
        Call(
            url="https://postman-echo.com/basic-auth",
            secret="POSTMAN_BASIC",
            auth_style="basic",
        )
    )
    assert result["status_code"] == 200
    assert result["body"] == {"authenticated": True}


@pytest.mark.parametrize("auth_style", ["basic", "header"])
def test_other_injection_styles_and_echoes(engine, monkeypatch, auth_style):
    def upstream(request):
        if auth_style == "basic":
            encoded = base64.b64encode(CANARY.encode()).decode()
            assert request.headers["authorization"] == f"Basic {encoded}"
        else:
            assert request.headers["x-api-key"] == CANARY
        return httpx.Response(
            401,
            headers={"Content-Type": "application/json"},
            stream=httpx.ByteStream(json.dumps({"error": CANARY}).encode()),
        )

    mock_upstream(monkeypatch, upstream)
    result = engine.execute(
        Call(
            url="https://api.example.com/data",
            secret="API_KEY",
            auth_style=auth_style,
            header_name="X-Api-Key" if auth_style == "header" else None,
        )
    )
    assert CANARY not in json.dumps(result)
    assert result["status_code"] == 401
    assert result["redacted"] is True


@pytest.mark.parametrize(
    "headers,content,error",
    [
        ({"Content-Type": "text/html"}, CANARY.encode(), "non_json_response_blocked"),
        (
            {"Content-Type": "application/json"},
            CANARY.encode(),
            "invalid_json_response",
        ),
        (
            {"Content-Type": "application/json", "Content-Encoding": "gzip"},
            b"",
            "encoded_response_blocked",
        ),
        (
            {"Content-Type": "application/json"},
            b"a" * (1024 * 1024 + 1),
            "response_too_large",
        ),
    ],
)
def test_unsafe_responses_blocked(engine, monkeypatch, headers, content, error):
    mock_upstream(
        monkeypatch,
        lambda request: httpx.Response(
            200, headers=headers, stream=httpx.ByteStream(content)
        ),
    )
    with pytest.raises(SafeError, match=error):
        engine.execute(Call(url="https://api.example.com/data", secret="API_KEY"))


@pytest.mark.parametrize("name", ["Host", "Authorization", "Cookie", "Accept-Encoding"])
def test_reserved_headers_blocked(engine, name):
    with pytest.raises(SafeError, match="invalid_headers"):
        engine.execute(
            Call(
                url="https://api.example.com/data",
                secret="API_KEY",
                headers={name: "value"},
            )
        )


def test_mixed_dns_answer_fails_closed(monkeypatch):
    monkeypatch.setattr(
        "socket.getaddrinfo",
        lambda *args, **kwargs: [
            (2, 1, 6, "", ("8.8.8.8", 443)),
            (2, 1, 6, "", ("127.0.0.1", 443)),
        ],
    )
    with pytest.raises(SafeError, match="unsafe_destination"):
        public_addresses("api.example.com")
