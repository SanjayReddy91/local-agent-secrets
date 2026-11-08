# Local Agent Vault

A local-only, CLI-managed credential broker for Copilot and Claude. One daemon
holds a KeePass-compatible encrypted vault and makes approved HTTPS API calls.
CLI and stdio MCP processes are thin clients; there is no web backend, cloud
endpoint, account, login, telemetry, or application access token.

## Run

Requires Python 3.12+ on Linux, macOS, or WSL. Linux is tested in this workspace;
macOS and WSL still require platform validation. State belongs on a native Linux
filesystem in WSL, not a shared Windows mount.

From this directory:

```sh
uv sync --group dev
uv run local-vault init
uv run local-vault start
uv run local-vault set GITHUB_TOKEN --origin https://api.github.com
uv run local-vault list
uv run local-vault call https://api.github.com/user --secret GITHUB_TOKEN
uv run local-vault doctor
uv run local-vault stop
```

`set` captures the supplied credential at a hidden terminal prompt. There are no
vault unlock or login prompts. For automation, `set --stdin` reads a value from
stdin. Never put real credentials in shell commands, model conversations, or
agent configuration. The CLI deliberately has no value argument.

GET is the default permitted method. Pass repeated `--method` options to allow
other methods. Replacing a credential also replaces its entire policy. Origins
must be exact HTTPS origins, with no path or wildcard; only port 443 is supported.

For API-key headers:

```sh
uv run local-vault call https://api.example.com/v1/data \
  --secret SERVICE_KEY --auth-style header --header-name X-Api-Key
```

Basic authentication stores `username:password` as one credential and uses
`--auth-style basic`. JSON request bodies can be read using `call --body-stdin`.
MCP calls also support ordinary, non-sensitive request headers.

## Source-only ZIP

Share source rather than `.venv/`: the virtual environment contains the Python
runtime and installed dependencies, is large, and is machine-specific.
Build outputs (`dist/`), caches, and local agent configuration are not needed
to rebuild the project.

From the parent directory, create a fresh source archive:

```sh
zip -r local-agent-vault-source.zip \
  local-agent-vault/src local-agent-vault/tests \
  local-agent-vault/pyproject.toml local-agent-vault/uv.lock \
  local-agent-vault/README.md \
  -x '*/__pycache__/*' '*/__pycache__/' '*.pyc'
```

Use a new archive name or remove an old source ZIP first; `zip` updates existing
archives and does not automatically remove stale entries.
After extraction, run `uv sync --locked --group dev` from `local-agent-vault/`
to recreate the environment, then use the commands above. Python 3.12+ and `uv`
are required; dependency installation needs internet access or a populated
package cache. Keep `uv.lock` for reproducible dependency versions. Regenerate
agent configuration after moving the project; do not copy absolute environment
paths or private vault data into a source archive.

## Connect an Agent

Start the daemon first, then print configuration for the desired client:

```sh
uv run local-vault mcp-config --client copilot
uv run local-vault mcp-config --client claude
```

The Copilot output is the configuration for VS Code's workspace MCP file. The
Claude output uses `mcpServers` for Claude Desktop or Claude Code. Paths point to
the current Python environment; regenerate configuration after moving it.
No credential values or credential environment variables appear in configuration.

Only three tools are exposed:

- `list_credentials`: names only.
- `vault_status`: availability and credential count.
- `api_call`: approved call with `url`, `secret`, optional `method`, `auth_style`,
  `header_name`, `headers`, and JSON `body`.

Example tool arguments, with a name rather than a value:

```json
{"url": "https://api.github.com/user", "secret": "GITHUB_TOKEN"}
```

There are no MCP tools for secret reads, writes, exports, policy changes, process
spawning, or environment injection. Existing credential-dependent MCP servers
must be adapted to use this call interface; wrapping them with environment
injection is intentionally not supported.

## Security Boundary

- Each secret has an explicit origin and method allowlist; empty policies deny.
- Requests are not scanned for credential values. The broker injects the selected
  credential and forwards the request under the existing destination/method policy.
- DNS results must all be public IPs. Connections use a vetted IP and the
  original hostname for TLS certificate verification; redirects are never followed.
- No local TCP listener is opened. Owner-only Unix sockets separate the agent
  call interface from the management interface. This is not same-user isolation.
- Only bounded UTF-8 JSON responses are returned. Streaming, compressed, binary,
  and non-JSON responses are rejected. Upstream response headers are not returned.
- Configured vault values are scrubbed from nested response keys/values, including
  common URL, HTML, JSON, base64, and hex representations. Error details, HTTP
  exception messages, request URLs, headers, and payloads are never logged.
- Audit logs contain only fixed operation/outcome fields and rotate at 1 MiB.
- The encrypted vault and automatic keyfile are owner-only. Vault saves use
  atomic replacement; old entry history is removed when credentials change.

The accepted v1 threat model trusts processes running as your OS user. An agent
with unrestricted host shell access can read both the keyfile and vault, access
the management socket, or change this application. Protecting against that needs
a separately enforced sandbox or OS identity. Full-disk encryption is recommended;
copying both vault and keyfile defeats the vault's at-rest protection.

Credential values necessarily exist in daemon memory and in the outbound request
sent to the authorized provider. Python does not guarantee memory zeroization.
Response scrubbing is defense-in-depth, not a proof against an adversarial upstream
that arbitrarily transforms credentials. Newly minted secrets not yet stored in
the vault cannot be identified reliably either. Approve trusted destinations and
use least-privilege provider tokens. This app does not make malicious credential
use impossible or protect secrets already supplied to a model by other means.

## Storage and Lifecycle

Default state is `$XDG_DATA_HOME/local-agent-vault`, or
`~/.local/share/local-agent-vault`. `--home` / `LOCAL_VAULT_HOME` selects a private
alternative; paths must fit the Unix socket length limit. Permissions must be
0700 for the state directory and 0600 for key, vault, and sockets. Unsafe
permissions fail closed; there is no insecure keyring or plaintext fallback.

State includes `secrets.kdbx`, `vault.key`, sockets, a singleton lock, and bounded
audit logs. Back up the KDBX and key separately using trusted OS tooling while
the daemon is stopped. Losing the key means losing the secrets; there is no
remote recovery. No synchronization or provider rotation is implemented.

`start` runs a detached daemon; it does not install a login/startup service.
`serve` runs in the foreground for an OS service manager. Restart after editing
the vault outside the application. Calls are processed serially in v1.

For installation outside the source directory, use `uv tool install .` or
`pipx install .`. No container or database service is required.

## Development

```sh
uv run pytest -q
uv run ruff check .
```

Tests use synthetic credentials, mocked upstream HTTP, real Unix sockets, and a
real MCP stdio session. They check encrypted persistence, permissions, policies,
redaction, non-JSON/oversized responses, safe errors, and rejected agent-side
management operations. No real provider credentials are needed.