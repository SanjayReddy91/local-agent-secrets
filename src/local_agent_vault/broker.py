import fcntl
import json
import logging
import os
import signal
import socket
import socketserver
import stat
from pathlib import Path

from pydantic import ValidationError

from .engine import MAX_REQUEST_BYTES, Call, Engine
from .security import ERROR_CODES, SafeError
from .vault import Vault, check_private

MAX_WIRE_BYTES = 8 * 1024 * 1024
PUBLIC_OPERATIONS = {"call", "list", "status"}


def encode(payload: object) -> bytes:
    return (
        json.dumps(payload, allow_nan=False, ensure_ascii=True).encode("utf-8") + b"\n"
    )


def read_message(stream, maximum: int) -> dict:
    raw = stream.readline(maximum + 1)
    if len(raw) > maximum or not raw.endswith(b"\n"):
        raise SafeError("invalid_message")
    try:
        payload = json.loads(raw)
    except (ValueError, UnicodeError, RecursionError):
        raise SafeError("invalid_message") from None
    if not isinstance(payload, dict):
        raise SafeError("invalid_message")
    return payload


def request(home: Path, payload: dict, *, management: bool = False) -> dict:
    socket_path = home / ("management.sock" if management else "agent.sock")
    try:
        check_private(home, directory=True)
        metadata = socket_path.lstat()
        if (
            not stat.S_ISSOCK(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            raise SafeError("unsafe_socket_permissions")
        data = encode(payload)
        if len(data) > MAX_REQUEST_BYTES:
            raise SafeError("request_too_large")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(60)
            connection.connect(str(socket_path))
            connection.sendall(data)
            with connection.makefile("rb") as stream:
                response = read_message(stream, MAX_WIRE_BYTES)
    except SafeError:
        raise
    except (OSError, ValueError, RecursionError):
        raise SafeError("broker_unavailable") from None
    if response.get("ok") is not True:
        error = response.get("error")
        if isinstance(error, str) and error in ERROR_CODES:
            raise SafeError(error)
        raise SafeError("request_rejected")
    result = response.get("result")
    if not isinstance(result, dict):
        raise SafeError("invalid_broker_response")
    return result


class Broker:
    def __init__(self, home: Path) -> None:
        self.home = home
        self.vault = Vault(home)
        self.engine = Engine(self.vault)
        self.stopping = False

    def dispatch(self, payload: dict, *, management: bool = False) -> dict:
        operation = payload.get("op")
        if not isinstance(operation, str):
            raise SafeError("invalid_request")
        if not management and operation not in PUBLIC_OPERATIONS:
            raise SafeError("operation_not_allowed")
        if operation == "call":
            if set(payload) != {"op", "call"}:
                raise SafeError("invalid_request")
            result = self.engine.execute(Call.model_validate(payload["call"]))
            self.audit("call", "completed")
            return result
        if operation in ("list", "status", "stop") and set(payload) != {"op"}:
            raise SafeError("invalid_request")
        if operation == "list":
            return {"names": self.vault.names()}
        if operation == "status":
            return {"running": True, "secret_count": len(self.vault.names())}
        if operation == "set" and management:
            if set(payload) != {"op", "name", "value", "origins", "methods"}:
                raise SafeError("invalid_request")
            if (
                not isinstance(payload["name"], str)
                or not isinstance(payload["value"], str)
                or not isinstance(payload["origins"], list)
                or not all(isinstance(origin, str) for origin in payload["origins"])
                or not isinstance(payload["methods"], list)
                or not all(isinstance(method, str) for method in payload["methods"])
            ):
                raise SafeError("invalid_request")
            self.vault.set(
                payload["name"],
                payload["value"],
                payload["origins"],
                payload["methods"],
            )
            self.audit("set", "completed")
            return {"stored": True}
        if operation == "delete" and management:
            if set(payload) != {"op", "name"} or not isinstance(payload["name"], str):
                raise SafeError("invalid_request")
            self.vault.delete(payload["name"])
            self.audit("delete", "completed")
            return {"deleted": True}
        if operation == "stop" and management:
            self.stopping = True
            return {"stopped": True}
        raise SafeError("operation_not_allowed")

    def respond(self, payload: dict, *, management: bool = False) -> bytes:
        try:
            response = {
                "ok": True,
                "result": self.dispatch(payload, management=management),
            }
        except SafeError as error:
            self.audit("request", "blocked")
            response = {"ok": False, "error": error.code}
        except (ValidationError, TypeError, ValueError, RecursionError):
            response = {"ok": False, "error": "invalid_request"}
        except Exception:
            response = {"ok": False, "error": "operation_failed"}
        try:
            clean = self.vault.redactor().scrub(response)
            data = encode(clean)
            if len(data) > MAX_WIRE_BYTES:
                return encode({"ok": False, "error": "response_too_large"})
            return data
        except Exception:
            return encode({"ok": False, "error": "response_blocked"})

    def audit(self, operation: str, outcome: str) -> None:
        audit_path = self.home / "audit.jsonl"
        try:
            if audit_path.exists():
                check_private(audit_path)
                if audit_path.stat().st_size > 1024 * 1024:
                    os.replace(audit_path, self.home / "audit.previous.jsonl")
            descriptor = os.open(
                audit_path,
                os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW,
                0o600,
            )
            with os.fdopen(descriptor, "ab") as stream:
                stream.write(
                    encode(
                        self.vault.redactor().scrub(
                            {
                                "operation": operation,
                                "outcome": outcome,
                            }
                        )
                    )
                )
        except Exception:
            pass


class Handler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        self.connection.settimeout(5)
        try:
            payload = read_message(self.rfile, MAX_REQUEST_BYTES)
            self.wfile.write(
                self.server.broker.respond(
                    payload,
                    management=self.server.management,
                )
            )
        except Exception:
            try:
                self.wfile.write(encode({"ok": False, "error": "invalid_message"}))
            except OSError:
                pass


class LocalServer(socketserver.UnixStreamServer):
    def __init__(self, address: str, broker: Broker, *, management: bool) -> None:
        self.broker = broker
        self.management = management
        super().__init__(address, Handler)
        self.timeout = 0.2

    def handle_error(self, request, client_address) -> None:
        pass


def serve(home: Path) -> None:
    import selectors

    logging.disable(logging.CRITICAL)
    check_private(home, directory=True)
    lock_fd = os.open(
        home / "broker.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600
    )
    servers: list[LocalServer] = []
    owns_lock = False
    previous_handlers = {}
    try:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            owns_lock = True
        except BlockingIOError:
            raise SafeError("already_running") from None
        broker = Broker(home)
        for management in (False, True):
            socket_path = home / ("management.sock" if management else "agent.sock")
            if len(os.fsencode(socket_path)) > 100:
                raise SafeError("socket_path_too_long")
            if socket_path.exists() or socket_path.is_symlink():
                metadata = socket_path.lstat()
                if (
                    not stat.S_ISSOCK(metadata.st_mode)
                    or metadata.st_uid != os.getuid()
                ):
                    raise SafeError("unsafe_socket_permissions")
                socket_path.unlink()
            server = LocalServer(str(socket_path), broker, management=management)
            servers.append(server)
            os.chmod(socket_path, 0o600)
        for signum in (signal.SIGINT, signal.SIGTERM):
            previous_handlers[signum] = signal.signal(
                signum, lambda signum, frame: setattr(broker, "stopping", True)
            )
        with selectors.DefaultSelector() as selector:
            for server in servers:
                selector.register(server, selectors.EVENT_READ)
            while not broker.stopping:
                for key, events in selector.select(timeout=0.5):
                    key.fileobj.handle_request()
                    if broker.stopping:
                        break
    finally:
        for signum, previous in previous_handlers.items():
            signal.signal(signum, previous)
        for server in servers:
            server.server_close()
            Path(server.server_address).unlink(missing_ok=True)
        if owns_lock:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)
