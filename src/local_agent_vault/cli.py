import json
import os
import subprocess
import sys
import time
from functools import wraps
from pathlib import Path

import click

from .broker import request, serve
from .security import SafeError
from .vault import Vault, default_home


def guarded(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except SafeError as error:
            raise click.ClickException(error.code) from None
        except Exception:
            raise click.ClickException("operation_failed") from None

    return wrapper


def output(result: dict) -> None:
    click.echo(json.dumps(result, allow_nan=False))


@click.group()
@click.option(
    "--home",
    type=click.Path(path_type=Path),
    envvar="LOCAL_VAULT_HOME",
    help="Private state directory; defaults to the XDG data directory.",
)
@click.pass_context
def main(context: click.Context, home: Path | None) -> None:
    """Local-only credential broker. No accounts, cloud, or application tokens."""
    os.umask(0o077)
    context.obj = (home or default_home()).absolute()


@main.command("init")
@click.pass_obj
@guarded
def initialize(home: Path) -> None:
    """Create the local encrypted vault and automatic keyfile."""
    Vault.initialize(home)
    click.echo("Vault initialized. Run local-vault start.")


@main.command("serve")
@click.pass_obj
@guarded
def foreground(home: Path) -> None:
    """Run the single broker daemon in the foreground."""
    serve(home)


@main.command("start")
@click.pass_obj
@guarded
def start(home: Path) -> None:
    """Start the broker in the background without unlocking prompts."""
    if not (home / "secrets.kdbx").exists():
        raise SafeError("not_initialized")
    try:
        request(home, {"op": "status"})
        click.echo("Broker already running.")
        return
    except SafeError:
        pass
    process = subprocess.Popen(
        [sys.executable, "-m", "local_agent_vault.cli", "--home", str(home), "serve"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
        close_fds=True,
    )
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise SafeError("broker_start_failed")
        try:
            request(home, {"op": "status"})
            click.echo("Broker running.")
            return
        except SafeError:
            time.sleep(0.1)
    process.terminate()
    process.wait(timeout=15)
    raise SafeError("broker_start_failed")


@main.command("stop")
@click.pass_obj
@guarded
def stop(home: Path) -> None:
    """Stop the local broker."""
    output(request(home, {"op": "stop"}, management=True))


@main.command("status")
@click.pass_obj
@guarded
def status(home: Path) -> None:
    """Show broker status without reading credential values."""
    output(request(home, {"op": "status"}))


@main.command("doctor")
@click.pass_obj
@guarded
def doctor(home: Path) -> None:
    """Check broker connectivity and private storage permissions."""
    from .vault import check_private

    check_private(home, directory=True)
    check_private(home / "vault.key")
    check_private(home / "secrets.kdbx")
    result = request(home, {"op": "status"})
    result["private_permissions"] = True
    output(result)


@main.command("set")
@click.argument("name")
@click.option(
    "--origin", multiple=True, required=True, help="Exact HTTPS origin to allow."
)
@click.option("--method", multiple=True, default=("GET",), help="Allowed HTTP method.")
@click.option(
    "--stdin", "read_stdin", is_flag=True, help="Read the value from stdin, not argv."
)
@click.pass_obj
@guarded
def set_secret(
    home: Path, name: str, origin: tuple, method: tuple, read_stdin: bool
) -> None:
    """Add or replace a credential and its policy. Never accepts a value in argv."""
    if read_stdin:
        value = sys.stdin.buffer.read(8193)
        if len(value) > 8192:
            raise SafeError("invalid_secret_value")
        value = value.decode("utf-8").removesuffix("\n").removesuffix("\r")
    else:
        value = click.prompt("Credential value", hide_input=True)
    request(
        home,
        {
            "op": "set",
            "name": name,
            "value": value,
            "origins": list(origin),
            "methods": list(method),
        },
        management=True,
    )
    click.echo("Credential stored.")


@main.command("list")
@click.pass_obj
@guarded
def list_names(home: Path) -> None:
    """List names only."""
    output(request(home, {"op": "list"}))


@main.command("delete")
@click.argument("name")
@click.pass_obj
@guarded
def delete_secret(home: Path, name: str) -> None:
    """Delete a credential from the local vault."""
    output(request(home, {"op": "delete", "name": name}, management=True))


@main.command("call")
@click.argument("url")
@click.option("--secret", required=True)
@click.option("--method", default="GET")
@click.option(
    "--auth-style", type=click.Choice(["bearer", "basic", "header"]), default="bearer"
)
@click.option("--header-name")
@click.option("--body-stdin", is_flag=True, help="Read a JSON body from stdin.")
@click.pass_obj
@guarded
def call_api(home, url, secret, method, auth_style, header_name, body_stdin) -> None:
    body = None
    if body_stdin:
        raw = sys.stdin.buffer.read(65537)
        if len(raw) > 65536:
            raise SafeError("request_too_large")
        body = json.loads(raw)
    output(
        request(
            home,
            {
                "op": "call",
                "call": {
                    "url": url,
                    "secret": secret,
                    "method": method,
                    "auth_style": auth_style,
                    "header_name": header_name,
                    "body": body,
                },
            },
        )
    )


@main.command("mcp")
@click.pass_obj
@guarded
def mcp(home: Path) -> None:
    """Run a stdio MCP bridge exposing only call, names, and status."""
    from .mcp_bridge import run_mcp

    run_mcp(home)


@main.command("mcp-config")
@click.option("--client", type=click.Choice(["copilot", "claude"]), required=True)
@click.pass_obj
def mcp_config(home: Path, client: str) -> None:
    """Print credential-free MCP configuration for the selected client."""
    definition = {
        "command": sys.executable,
        "args": ["-m", "local_agent_vault.cli", "--home", str(home), "mcp"],
    }
    if client == "copilot":
        definition["type"] = "stdio"
    output(
        {
            "servers" if client == "copilot" else "mcpServers": {
                "local-vault": definition
            }
        }
    )


if __name__ == "__main__":
    main()
