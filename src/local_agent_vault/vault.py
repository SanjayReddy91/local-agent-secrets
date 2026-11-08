import io
import json
import os
import secrets
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path

from pykeepass import PyKeePass, create_database

from .security import Redactor, SafeError, validate_name, validate_origin

METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}


def default_home() -> Path:
    base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    return base / "local-agent-vault"


def check_private(path: Path, directory: bool = False) -> None:
    metadata = path.lstat()
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    if (
        not expected(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise SafeError("unsafe_file_permissions")


def private_directory(home: Path) -> None:
    home.mkdir(mode=0o700, parents=True, exist_ok=True)
    check_private(home, directory=True)


def atomic_write(destination: Path, content: bytes) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=".vault-", dir=destination.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
        directory_fd = os.open(destination.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


@dataclass(frozen=True)
class Credential:
    value: str
    origins: tuple[str, ...]
    methods: tuple[str, ...]


class Vault:
    def __init__(self, home: Path) -> None:
        self.home = home
        self.database_path = home / "secrets.kdbx"
        key_path = home / "vault.key"
        check_private(home, directory=True)
        check_private(key_path)
        check_private(self.database_path)
        self._database = PyKeePass(str(self.database_path), keyfile=str(key_path))
        self._group = self._database.find_groups(name="Credentials", first=True)
        if self._group is None:
            raise SafeError("invalid_vault")

    @classmethod
    def initialize(cls, home: Path) -> None:
        private_directory(home)
        if (home / "secrets.kdbx").exists() or (home / "vault.key").exists():
            raise SafeError("already_initialized")
        key_path = home / "vault.key"
        descriptor = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(secrets.token_bytes(32))
            stream.flush()
            os.fsync(stream.fileno())
        buffer = io.BytesIO()
        database = create_database(buffer, keyfile=str(key_path))
        database.add_group(database.root_group, "Credentials")
        buffer = io.BytesIO()
        database.save(buffer)
        atomic_write(home / "secrets.kdbx", buffer.getvalue())

    def _save(self) -> None:
        try:
            buffer = io.BytesIO()
            self._database.save(buffer)
            atomic_write(self.database_path, buffer.getvalue())
        except Exception:
            self.__init__(self.home)
            raise SafeError("vault_write_failed") from None

    def names(self) -> list[str]:
        return sorted(entry.title for entry in self._group.entries)

    def _entry(self, name: str):
        validate_name(name)
        return next(
            (entry for entry in self._group.entries if entry.title == name), None
        )

    def credential(self, name: str) -> Credential:
        entry = self._entry(name)
        if entry is None:
            raise SafeError("secret_not_found")
        try:
            policy = json.loads(entry.notes)
            origins = tuple(validate_origin(origin) for origin in policy["origins"])
            methods = tuple(policy["methods"])
            if (
                not origins
                or not methods
                or any(method not in METHODS for method in methods)
            ):
                raise ValueError
        except (KeyError, TypeError, ValueError, SafeError):
            raise SafeError("invalid_secret_policy") from None
        return Credential(entry.password, origins, methods)

    def redactor(self) -> Redactor:
        return Redactor(entry.password for entry in self._group.entries)

    def set(
        self, name: str, value: str, origins: list[str], methods: list[str]
    ) -> None:
        validate_name(name)
        if not value or len(value.encode("utf-8")) > 8192:
            raise SafeError("invalid_secret_value")
        if not origins or len(origins) > 32 or not methods:
            raise SafeError("invalid_secret_policy")
        normalized = sorted({validate_origin(origin) for origin in origins})
        if any(method not in METHODS for method in methods):
            raise SafeError("invalid_secret_policy")
        notes = json.dumps({"origins": normalized, "methods": sorted(set(methods))})
        entry = self._entry(name)
        if entry is None:
            self._database.add_entry(self._group, name, "", value, notes=notes)
        else:
            entry.password = value
            entry.notes = notes
            if entry.history:
                entry.delete_history(all=True)
        self._save()

    def delete(self, name: str) -> None:
        entry = self._entry(name)
        if entry is None:
            raise SafeError("secret_not_found")
        self._database.delete_entry(entry)
        self._save()
