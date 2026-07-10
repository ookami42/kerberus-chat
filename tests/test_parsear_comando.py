"""Testes unitarios para _parsear_comando em client/client.py.

Cobre os quatro comandos (/notas, /ler, /escrever, /deletar), com e sem
argumentos, e linhas desconhecidas.
"""

from unittest.mock import patch

import pytest

from common.protocol import MSG_NOTE_LIST, MSG_NOTE_READ, MSG_NOTE_WRITE, MSG_NOTE_DELETE
from client.client import ClienteKerberos


@pytest.fixture
def cliente():
    """Cria um ClienteKerberos sem conexao de rede."""
    return ClienteKerberos()


# --------------------------------------------------------------------------
# /notas
# --------------------------------------------------------------------------


class TestParsearNotas:
    """Comando /notas — sempre retorna MSG_NOTE_LIST."""

    def test_notas(self, cliente):
        assert cliente._parsear_comando("/notas") == (MSG_NOTE_LIST, b"")


# --------------------------------------------------------------------------
# /ler
# --------------------------------------------------------------------------


class TestParsearLer:
    """Comando /ler com e sem argumento."""

    def test_ler_com_arquivo(self, cliente):
        assert cliente._parsear_comando("/ler aula1.txt") == (
            MSG_NOTE_READ,
            b"aula1.txt",
        )

    def test_ler_sem_argumento(self, cliente):
        with patch("client.client.mostrar_erro") as mock_erro:
            resultado = cliente._parsear_comando("/ler")
        assert resultado is None
        mock_erro.assert_called_once_with("Uso: /ler <arquivo>")

    def test_ler_espacos_em_branco(self, cliente):
        with patch("client.client.mostrar_erro") as mock_erro:
            resultado = cliente._parsear_comando("/ler   ")
        assert resultado is None
        mock_erro.assert_called_once_with("Uso: /ler <arquivo>")

    def test_ler_com_espacos_no_nome(self, cliente):
        assert cliente._parsear_comando("/ler minhas notas.txt") == (
            MSG_NOTE_READ,
            b"minhas notas.txt",
        )


# --------------------------------------------------------------------------
# /escrever
# --------------------------------------------------------------------------


class TestParsearEscrever:
    """Comando /escrever com e sem argumento."""

    def test_escrever_com_arquivo(self, cliente):
        with patch("client.client.perguntar_conteudo", return_value="conteudo"):
            resultado = cliente._parsear_comando("/escrever nota.txt")
        assert resultado == (MSG_NOTE_WRITE, b"nota.txt\nconteudo")

    def test_escrever_sem_argumento(self, cliente):
        with patch("client.client.mostrar_erro") as mock_erro:
            resultado = cliente._parsear_comando("/escrever")
        assert resultado is None
        mock_erro.assert_called_once_with("Uso: /escrever <arquivo>")

    def test_escrever_espacos_em_branco(self, cliente):
        with patch("client.client.mostrar_erro") as mock_erro:
            resultado = cliente._parsear_comando("/escrever   ")
        assert resultado is None
        mock_erro.assert_called_once_with("Uso: /escrever <arquivo>")

    def test_escrever_conteudo_multilinha(self, cliente):
        with patch("client.client.perguntar_conteudo", return_value="linha1\nlinha2"):
            resultado = cliente._parsear_comando("/escrever prova.txt")
        assert resultado == (MSG_NOTE_WRITE, b"prova.txt\nlinha1\nlinha2")


# --------------------------------------------------------------------------
# /deletar
# --------------------------------------------------------------------------


class TestParsearDeletar:
    """Comando /deletar com e sem argumento."""

    def test_deletar_com_arquivo(self, cliente):
        assert cliente._parsear_comando("/deletar antiga.txt") == (
            MSG_NOTE_DELETE,
            b"antiga.txt",
        )

    def test_deletar_sem_argumento(self, cliente):
        with patch("client.client.mostrar_erro") as mock_erro:
            resultado = cliente._parsear_comando("/deletar")
        assert resultado is None
        mock_erro.assert_called_once_with("Uso: /deletar <arquivo>")

    def test_deletar_espacos_em_branco(self, cliente):
        with patch("client.client.mostrar_erro") as mock_erro:
            resultado = cliente._parsear_comando("/deletar   ")
        assert resultado is None
        mock_erro.assert_called_once_with("Uso: /deletar <arquivo>")


# --------------------------------------------------------------------------
# Comando desconhecido
# --------------------------------------------------------------------------


class TestParsearDesconhecido:
    """Linhas que nao casam com nenhum comando."""

    def test_comando_sem_barra(self, cliente):
        assert cliente._parsear_comando("notas") is None

    def test_texto_aleatorio(self, cliente):
        assert cliente._parsear_comando("ola mundo") is None

    def test_barra_sozinha(self, cliente):
        assert cliente._parsear_comando("/") is None

    def test_comando_errado(self, cliente):
        assert cliente._parsear_comando("/apagar") is None
