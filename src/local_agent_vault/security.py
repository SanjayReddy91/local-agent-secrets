import base64
import html
import ipaddress
import json
import re
from collections.abc import Iterable
from urllib.parse import quote, quote_plus, urlsplit

ERROR_CODES = frozenset(
    {
        "invalid_secret_name",
        "invalid_origin",
        "invalid_target",
        "destination_not_allowed",
        "unsafe_destination",
        "unsafe_file_permissions",
        "invalid_vault",
        "already_initialized",
        "secret_not_found",
        "invalid_secret_policy",
        "invalid_secret_value",
        "destination_lookup_failed",
        "invalid_headers",
        "method_not_allowed",
        "invalid_auth_style",
        "invalid_auth_header",
        "request_too_large",
        "redirect_blocked",
        "encoded_response_blocked",
        "non_json_response_blocked",
        "response_too_large",
        "upstream_timeout",
        "invalid_json_response",
        "unsupported_response",
        "invalid_message",
        "unsafe_socket_permissions",
        "invalid_request",
        "operation_not_allowed",
        "operation_failed",
        "response_blocked",
        "vault_write_failed",
    }
)


class SafeError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def validate_name(name: str) -> str:
    if not re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", name):
        raise SafeError("invalid_secret_name")
    return name


def validate_origin(origin: str) -> str:
    parts = urlsplit(origin)
    try:
        port = parts.port
    except ValueError:
        raise SafeError("invalid_origin") from None
    if (
        parts.scheme != "https"
        or not parts.hostname
        or parts.username is not None
        or parts.password is not None
        or parts.path not in ("", "/")
        or parts.query
        or parts.fragment
        or port not in (None, 443)
    ):
        raise SafeError("invalid_origin")
    host = parts.hostname.encode("idna").decode("ascii").lower()
    if ":" in host or not re.fullmatch(r"[a-z0-9.-]+", host):
        raise SafeError("invalid_origin")
    if host.endswith(".") or ".." in host:
        raise SafeError("invalid_origin")
    return f"https://{host}"


def validate_target(target: str, origins: Iterable[str]) -> str:
    if not isinstance(target, str) or len(target) > 8192:
        raise SafeError("invalid_target")
    if any(ord(character) <= 32 for character in target) or "\\" in target:
        raise SafeError("invalid_target")
    try:
        parts = urlsplit(target)
        host = parts.hostname
        port = parts.port
    except ValueError:
        raise SafeError("invalid_target") from None
    if (
        parts.scheme != "https"
        or not host
        or parts.username is not None
        or parts.password is not None
        or parts.fragment
        or port not in (None, 443)
    ):
        raise SafeError("invalid_target")
    origin = validate_origin(f"https://{host}")
    if origin not in origins:
        raise SafeError("destination_not_allowed")
    return host.encode("idna").decode("ascii").lower()


def require_public_ip(address: str) -> None:
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        raise SafeError("unsafe_destination") from None
    if not parsed.is_global or getattr(parsed, "ipv4_mapped", None):
        raise SafeError("unsafe_destination")


class Redactor:
    marker = "[REDACTED]"

    def __init__(self, values: Iterable[str]) -> None:
        variants: set[str] = set()
        for value in values:
            if not value:
                continue
            encoded = value.encode("utf-8")
            variants.update(
                (
                    value,
                    quote(value, safe=""),
                    quote_plus(value, safe=""),
                    html.escape(value),
                    json.dumps(value, ensure_ascii=True)[1:-1],
                    base64.b64encode(encoded).decode("ascii"),
                    base64.urlsafe_b64encode(encoded).decode("ascii"),
                    encoded.hex(),
                )
            )
            if ":" in value:
                variants.update(part for part in value.split(":", 1) if part)
        variants.update(value.rstrip("=") for value in tuple(variants))
        self._variants = sorted(variants, key=len, reverse=True)

    def contains(self, text: str) -> bool:
        return any(value in text for value in self._variants)

    def scrub_text(self, text: str) -> str:
        for value in self._variants:
            text = text.replace(value, self.marker)
        return text

    def scrub(self, value: object) -> object:
        if isinstance(value, str):
            return self.scrub_text(value)
        if isinstance(value, dict):
            return {
                self.scrub_text(str(key)): self.scrub(item)
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [self.scrub(item) for item in value]
        if value is None or isinstance(value, (bool, int, float)):
            if self.contains(json.dumps(value)):
                return self.marker
            return value
        raise SafeError("unsupported_response")
