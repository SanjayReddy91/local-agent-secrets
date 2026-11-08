import os
import stat

import pytest

from local_agent_vault.security import SafeError
from local_agent_vault.vault import Vault


def test_encrypted_roundtrip_and_private_files(vault):
    canary = "canary-secret-456789"
    vault.set("API_KEY", canary, ["https://api.example.com"], ["GET"])
    assert vault.names() == ["API_KEY"]
    reopened = Vault(vault.home)
    assert reopened.credential("API_KEY").value == canary
    assert canary.encode() not in vault.database_path.read_bytes()
    for name in ("secrets.kdbx", "vault.key"):
        assert stat.S_IMODE((vault.home / name).stat().st_mode) == 0o600
    assert stat.S_IMODE(vault.home.stat().st_mode) == 0o700


def test_update_and_delete(vault):
    vault.set("API_KEY", "old-value", ["https://api.example.com"], ["GET"])
    vault.set("API_KEY", "new-value", ["https://api.example.com"], ["POST"])
    assert Vault(vault.home).credential("API_KEY").value == "new-value"
    assert vault.credential("API_KEY").methods == ("POST",)
    vault.delete("API_KEY")
    assert Vault(vault.home).names() == []


def test_empty_policy_is_not_unrestricted(vault):
    with pytest.raises(SafeError):
        vault.set("API_KEY", "secret", [], ["GET"])


def test_world_readable_key_is_rejected(vault):
    os.chmod(vault.home / "vault.key", 0o644)
    with pytest.raises(SafeError, match="unsafe_file_permissions"):
        Vault(vault.home)


def test_failed_save_does_not_leave_unsaved_secret_in_memory(vault, monkeypatch):
    vault.set("API_KEY", "original-secret", ["https://api.example.com"], ["GET"])

    def fail_write(*args):
        raise OSError("disk unavailable")

    monkeypatch.setattr("local_agent_vault.vault.atomic_write", fail_write)
    with pytest.raises(SafeError, match="vault_write_failed"):
        vault.set("API_KEY", "unsaved-secret", ["https://api.example.com"], ["GET"])
    assert vault.credential("API_KEY").value == "original-secret"
    assert Vault(vault.home).credential("API_KEY").value == "original-secret"


def test_update_removes_old_history(vault):
    vault.set("API_KEY", "old-secret", ["https://api.example.com"], ["GET"])
    vault._entry("API_KEY").save_history()
    vault.set("API_KEY", "new-secret", ["https://api.example.com"], ["GET"])
    assert vault._entry("API_KEY").history == []
