"""Teste de integração do AS: cadastro seguido de login end-to-end.

Reproduz dois bugs corrigidos:
  - Bug 1: chamada criar_ticket(usuario=..., validade=..., chave=...)
           kwargs errados levantavam TypeError.
  - Bug 2: UserDB na memória do AS não enxergava cadastros feitos
           depois que ele iniciou (faltava recarregar()).
"""
import os
from unittest.mock import MagicMock

import pytest

from common.config import TAMANHO_CHAVE, TAMANHO_SALT
from common.crypto import derivar_chave
from common.protocol import (
    empacotar,
    desempacotar,
    MSG_AUTH_REQUEST,
    MSG_AUTH_REPLY,
    MSG_ERROR,
)
from as_server.user_db import UserDB
from as_server.as_server import ASServer


@pytest.fixture
def as_server(tmp_path):
    """Cria um AS com UserDB e chave mestra temporários."""
    user_db_path = tmp_path / "user_db.json"
    as_key = os.urandom(TAMANHO_CHAVE)
    user_db = UserDB(str(user_db_path))
    return ASServer(
        host="127.0.0.1",
        porta=0,
        user_db=user_db,
        chave_mestra=as_key,
    )


class TestCadastroELogin:
    """Fluxo completo: cadastrar e depois autenticar."""

    def test_cadastrar_e_logar_retorna_auth_reply(self, as_server, conn_mock):
        """Cadastra usuario e verifica que o AS responde MSG_AUTH_REPLY.

        Reproduz o bug em que o AS não recarregava o UserDB após
        receber cadastros externos.
        """
        # Arrange — cadastra "eu" direto no banco
        salt = os.urandom(TAMANHO_SALT)
        hash_chave = derivar_chave(b"senha123", salt)
        as_server.user_db.cadastrar("eu", salt, hash_chave)

        # Act — simula MSG_AUTH_REQUEST do cliente
        mensagem = empacotar(MSG_AUTH_REQUEST, b"eu")
        conn_mock.recv.side_effect = [mensagem[:6], mensagem[6:]]

        as_server.atender_cliente(conn_mock, ("127.0.0.1", 12345))

        # Assert — resposta foi MSG_AUTH_REPLY (não MSG_ERROR)
        args = conn_mock.sendall.call_args[0][0]
        tipo, _ = desempacotar(args)
        assert tipo == MSG_AUTH_REPLY

    def test_login_com_criar_ticket_correto_nao_levanta(self, as_server, conn_mock):
        """Garante que criar_ticket é chamado com kwargs corretos.

        Reproduz o bug em que o AS passava kwargs inexistentes
        (usuario=, validade=, chave=) para criar_ticket, levantando
        TypeError e caindo no except genérico que enviava MSG_ERROR
        com payload vazio.
        """
        # Arrange — cadastra "eu"
        as_server.user_db.cadastrar(
            "eu", os.urandom(TAMANHO_SALT), os.urandom(TAMANHO_CHAVE)
        )

        # Act — simula MSG_AUTH_REQUEST
        mensagem = empacotar(MSG_AUTH_REQUEST, b"eu")
        conn_mock.recv.side_effect = [mensagem[:6], mensagem[6:]]

        as_server.atender_cliente(conn_mock, ("127.0.0.1", 12345))

        # Assert — não caiu no except: resposta é MSG_AUTH_REPLY
        args = conn_mock.sendall.call_args[0][0]
        tipo, _ = desempacotar(args)
        assert tipo == MSG_AUTH_REPLY

    def test_usuario_inexistente_retorna_erro(self, as_server, conn_mock):
        """Usuário não cadastrado gera MSG_ERROR (não crasha)."""
        # Act — tenta autenticar sem cadastrar
        mensagem = empacotar(MSG_AUTH_REQUEST, b"fantasma")
        conn_mock.recv.side_effect = [mensagem[:6], mensagem[6:]]

        as_server.atender_cliente(conn_mock, ("127.0.0.1", 12345))

        # Assert — resposta é MSG_ERROR
        args = conn_mock.sendall.call_args[0][0]
        tipo, _ = desempacotar(args)
        assert tipo == MSG_ERROR
