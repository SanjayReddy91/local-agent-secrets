import base64
import json
import re
import socket
import time

import httpx
from pydantic import BaseModel, ConfigDict, Field

from .security import SafeError, require_public_ip, validate_name, validate_target
from .vault import METHODS, Vault

MAX_RESPONSE_BYTES = 1024 * 1024
MAX_REQUEST_BYTES = 64 * 1024
BLOCKED_HEADERS = {
    "host",
    "authorization",
    "proxy-authorization",
    "cookie",
    "connection",
    "content-length",
    "transfer-encoding",
    "accept-encoding",
    "upgrade",
    "te",
    "trailer",
    "proxy-connection",
}


class Call(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    url: str = Field(max_length=8192)
    secret: str = Field(max_length=64)
    method: str = "GET"
    auth_style: str = "bearer"
    header_name: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    body: dict | list | None = None


def public_addresses(host: str) -> list[str]:
    try:
        records = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except OSError:
        raise SafeError("destination_lookup_failed") from None
    addresses = list(dict.fromkeys(record[4][0] for record in records))
    if not addresses:
        raise SafeError("destination_lookup_failed")
    for address in addresses:
        require_public_ip(address)
    return addresses


def validate_headers(headers: dict[str, str]) -> None:
    if len(headers) > 32:
        raise SafeError("invalid_headers")
    for name, value in headers.items():
        if (
            not re.fullmatch(r"[A-Za-z0-9-]{1,64}", name)
            or name.lower() in BLOCKED_HEADERS
            or len(value) > 4096
            or any(ord(character) < 32 or ord(character) > 126 for character in value)
        ):
            raise SafeError("invalid_headers")


class Engine:
    def __init__(self, vault: Vault) -> None:
        self.vault = vault

    def execute(self, call: Call) -> dict:
        started = time.monotonic()
        validate_name(call.secret)
        credential = self.vault.credential(call.secret)
        host = validate_target(call.url, credential.origins)
        if call.method not in METHODS or call.method not in credential.methods:
            raise SafeError("method_not_allowed")
        validate_headers(call.headers)
        if call.auth_style not in ("bearer", "basic", "header"):
            raise SafeError("invalid_auth_style")
        if call.auth_style == "header":
            if (
                not call.header_name
                or not re.fullmatch(r"[A-Za-z0-9-]{1,64}", call.header_name)
                or call.header_name.lower() in BLOCKED_HEADERS
            ):
                raise SafeError("invalid_auth_header")
        elif call.header_name is not None:
            raise SafeError("invalid_auth_header")
        redactor = self.vault.redactor()
        addresses = public_addresses(host)
        headers = dict(call.headers)
        headers["Host"] = host
        headers["Accept"] = "application/json"
        headers["Accept-Encoding"] = "identity"
        if call.auth_style == "bearer":
            headers["Authorization"] = f"Bearer {credential.value}"
        elif call.auth_style == "basic":
            encoded = base64.b64encode(credential.value.encode()).decode("ascii")
            headers["Authorization"] = f"Basic {encoded}"
        else:
            headers[call.header_name] = credential.value
        body = (
            json.dumps(call.body, allow_nan=False).encode()
            if call.body is not None
            else None
        )
        if body is not None:
            if len(body) > MAX_REQUEST_BYTES:
                raise SafeError("request_too_large")
            headers["Content-Type"] = "application/json"
        destination = httpx.URL(call.url).copy_with(host=addresses[0])
        with httpx.Client(
            trust_env=False,
            follow_redirects=False,
            timeout=httpx.Timeout(30, connect=10, read=5, write=10, pool=5),
        ) as client:
            with client.stream(
                call.method,
                destination,
                headers=headers,
                content=body,
                extensions={"sni_hostname": host},
            ) as response:
                if 300 <= response.status_code < 400:
                    raise SafeError("redirect_blocked")
                if response.headers.get("content-encoding", "identity") != "identity":
                    raise SafeError("encoded_response_blocked")
                content_type = (
                    response.headers.get("content-type", "").split(";", 1)[0].lower()
                )
                if response.status_code in (204, 205) or call.method == "HEAD":
                    payload = None
                elif content_type != "application/json" and not content_type.endswith(
                    "+json"
                ):
                    raise SafeError("non_json_response_blocked")
                else:
                    content = bytearray()
                    for chunk in response.iter_raw():
                        content.extend(chunk)
                        if len(content) > MAX_RESPONSE_BYTES:
                            raise SafeError("response_too_large")
                        if time.monotonic() - started > 30:
                            raise SafeError("upstream_timeout")
                    try:
                        payload = json.loads(content.decode("utf-8"))
                    except (ValueError, UnicodeError, RecursionError):
                        raise SafeError("invalid_json_response") from None
                clean = redactor.scrub(payload)
                return {
                    "status_code": response.status_code,
                    "body": clean,
                    "redacted": clean != payload,
                }
