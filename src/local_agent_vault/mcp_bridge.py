import logging
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from .broker import request
from .security import SafeError


def build_mcp(home: Path) -> FastMCP:
    server = FastMCP("Local Agent Vault", log_level="CRITICAL")

    def invoke(payload: dict) -> dict:
        try:
            return request(home, payload)
        except SafeError as error:
            return {"error": error.code}
        except Exception:
            return {"error": "broker_request_failed"}

    @server.tool()
    def list_credentials() -> dict:
        """List available credential names, never their values."""
        return invoke({"op": "list"})

    @server.tool()
    def vault_status() -> dict:
        """Return local broker availability and the credential count."""
        return invoke({"op": "status"})

    @server.tool()
    def api_call(
        url: str,
        secret: str,
        method: str = "GET",
        auth_style: str = "bearer",
        header_name: str | None = None,
        headers: dict[str, str] | None = None,
        body: dict | list | None = None,
    ) -> dict:
        """Call an approved HTTPS JSON API using a credential name.

        auth_style is bearer, basic, or header. For header, supply header_name.
        Only approved origins and methods are permitted. Redirects, streaming,
        binary responses, and non-JSON responses are blocked. No raw response
        headers or credential values are returned.
        """
        return invoke(
            {
                "op": "call",
                "call": {
                    "url": url,
                    "secret": secret,
                    "method": method,
                    "auth_style": auth_style,
                    "header_name": header_name,
                    "headers": headers or {},
                    "body": body,
                },
            }
        )

    return server


def run_mcp(home: Path) -> None:
    logging.disable(logging.CRITICAL)
    build_mcp(home).run(transport="stdio")
