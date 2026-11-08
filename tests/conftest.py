import pytest

from local_agent_vault.vault import Vault


@pytest.fixture
def vault(tmp_path):
    home = tmp_path / "state"
    Vault.initialize(home)
    return Vault(home)
