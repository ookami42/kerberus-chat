"""Testes unitarios para _deletar em service/service_server.py.

Cobre delecao de nota existente, nota inexistente, nome vazio
e path traversal.
"""

import os
from unittest.mock import patch, MagicMock

import pytest

from common.config import TAMANHO_CHAVE
from common.protocol import MSG_NOTE_DELETE


# --------------------------------------------------------------------------
# Fixture: ServicoKerberos com chave temporaria
# --------------------------------------------------------------------------


@pytest.fixture
def svc(tmp_path):
    """Cria um ServicoKerberos com chave e diretorio de notas temporarios."""
    chave = tmp_path / "service_master.key"
    chave.write_bytes(os.urandom(TAMANHO_CHAVE))
    notas_raiz = str(tmp_path / "notas")

    with patch("service.service_server.SVC_MASTER_KEY_PATH", str(chave)):
        from service.service_server import ServicoKerberos
        servico = ServicoKerberos.__new__(ServicoKerberos)
        servico.service_master_key = chave.read_bytes()
        servico._notas_raiz = notas_raiz
        return servico


def _criar_nota(svc, usuario, nome, conteudo="conteudo"):
    """Cria uma nota diretamente no filesystem para testes."""
    dir_usuario = svc._caminho_usuario(usuario)
    os.makedirs(dir_usuario, exist_ok=True)
    caminho = svc._caminho_nota(usuario, nome)
    with open(caminho, "w") as f:
        f.write(conteudo)
    return caminho


# --------------------------------------------------------------------------
# _deletar
# --------------------------------------------------------------------------


class TestDeletarNota:
    """Delecao de notas."""

    def test_deleta_nota_existente(self, svc):
        _criar_nota(svc, "alice", "antiga.txt", "velho conteudo")
        resposta, erro = svc._deletar("alice", b"antiga.txt")
        assert resposta == "OK: nota deletada."
        assert erro is None
        assert not os.path.exists(svc._caminho_nota("alice", "antiga.txt"))

    def test_nota_inexistente(self, svc):
        resposta, erro = svc._deletar("alice", b"fantasma.txt")
        assert resposta == ""
        assert erro == "Nota nao encontrada."

    def test_nome_vazio(self, svc):
        resposta, erro = svc._deletar("alice", b"")
        assert resposta == ""
        assert erro == "Nome de arquivo invalido."

    def test_nome_so_espacos(self, svc):
        resposta, erro = svc._deletar("alice", b"   ")
        assert resposta == ""
        assert erro == "Nome de arquivo invalido."

    def test_path_traversal(self, svc):
        """Path traversal e sanitizado: ../../etc/passwd vira passwd."""
        _criar_nota(svc, "alice", "passwd", "conteudo")
        resposta, erro = svc._deletar("alice", b"../../etc/passwd")
        assert resposta == "OK: nota deletada."
        assert erro is None
        assert not os.path.exists(svc._caminho_nota("alice", "passwd"))

    def test_deleta_apenas_do_dono(self, svc):
        """Alice deleta sua propria nota; a do Bob permanece."""
        _criar_nota(svc, "alice", "minha.txt", "de alice")
        _criar_nota(svc, "bob", "minha.txt", "de bob")
        svc._deletar("alice", b"minha.txt")
        assert not os.path.exists(svc._caminho_nota("alice", "minha.txt"))
        assert os.path.exists(svc._caminho_nota("bob", "minha.txt"))

    def test_deleta_apenas_arquivo_pedido(self, svc):
        """Deletar um arquivo nao remove os outros."""
        _criar_nota(svc, "alice", "a.txt", "a")
        _criar_nota(svc, "alice", "b.txt", "b")
        svc._deletar("alice", b"a.txt")
        assert not os.path.exists(svc._caminho_nota("alice", "a.txt"))
        assert os.path.exists(svc._caminho_nota("alice", "b.txt"))
