"""Fixtures compartilhadas entre os testes do kerberos-chat."""
from unittest.mock import MagicMock

import pytest


@pytest.fixture
def conn_mock():
    """Cria um mock de socket para simular conexao TCP."""
    return MagicMock()
