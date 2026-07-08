"""Testes unitarios para tgs_server/tgs_server.py.

Testa os metodos do TGSServer usando sockets mockados.
Cobre a extracao de TGS request (4 bytes por campo),
montagem de TGS reply, leitura de bytes exatos, carregamento
de chaves e o fluxo completo de atender_cliente.
"""

import os
import struct
import time
from unittest.mock import MagicMock, patch

import pytest
from cryptography.exceptions import InvalidTag

from common.config import TAMANHO_CHAVE, LIFETIME_TICKET
from common.crypto import cifrar_aes_gcm
from common.protocol import (
    empacotar,
    desempacotar,
    criar_ticket,
    extrair_ticket,
    MSG_TGS_REQUEST,
    MSG_TGS_REPLY,
    MSG_ERROR,
)
from tgs_server.tgs_server import TGSServer, HEADER_FORMAT, HEADER_SIZE


# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------


@pytest.fixture
def chaves(tmp_path):
    """Cria arquivos temporarios de chaves e retorna (as_path, svc_path)."""
    as_path = tmp_path / "as_master.key"
    svc_path = tmp_path / "service_master.key"
    as_path.write_bytes(os.urandom(TAMANHO_CHAVE))
    svc_path.write_bytes(os.urandom(TAMANHO_CHAVE))
    return str(as_path), str(svc_path)


@pytest.fixture
def servidor(chaves):
    """Cria um TGSServer com chaves temporarias."""
    as_path, svc_path = chaves
    with (
        patch("tgs_server.tgs_server.AS_MASTER_KEY_PATH", as_path),
        patch("tgs_server.tgs_server.SVC_MASTER_KEY_PATH", svc_path),
    ):
        return TGSServer()


@pytest.fixture
def conn_mock():
    """Cria um mock de socket para simular conexao TCP."""
    return MagicMock()


# --------------------------------------------------------------------------
# Testes de _carregar_chave
# --------------------------------------------------------------------------


class TestCarregarChave:
    """Testes do carregamento de chaves de arquivo."""

    def test_carrega_chave_de_arquivo_valido(self, tmp_path):
        """Carrega 16 bytes de um arquivo existente."""
        arquivo = tmp_path / "chave.key"
        chave = os.urandom(TAMANHO_CHAVE)
        arquivo.write_bytes(chave)
        resultado = TGSServer._carregar_chave(str(arquivo), "teste")
        assert resultado == chave

    def test_arquivo_inexistente_raises_file_not_found(self, tmp_path):
        """Arquivo que nao existe levanta FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            TGSServer._carregar_chave(str(tmp_path / "nao_existe.key"), "t")

    def test_chave_com_tamanho_errado_raises_value_error(self, tmp_path):
        """Arquivo com tamanho diferente de 16 bytes levanta ValueError."""
        arquivo = tmp_path / "chave_errada.key"
        arquivo.write_bytes(os.urandom(10))
        with pytest.raises(ValueError, match="esperado 16 bytes"):
            TGSServer._carregar_chave(str(arquivo), "teste")


# --------------------------------------------------------------------------
# Testes de _receber_exato
# --------------------------------------------------------------------------


class TestReceberExato:
    """Testes da leitura exata de bytes do socket."""

    def test_le_todos_os_bytes_de_uma_vez(self):
        """Quando recv retorna todos os bytes de uma so vez."""
        conn = MagicMock()
        conn.recv.return_value = b"123456"
        resultado = TGSServer._receber_exato(conn, 6)
        assert resultado == b"123456"

    def test_le_em_partes(self):
        """Quando recv retorna bytes em partes (TCP fragmentation)."""
        conn = MagicMock()
        conn.recv.side_effect = [b"12", b"34", b"56"]
        resultado = TGSServer._receber_exato(conn, 6)
        assert resultado == b"123456"

    def test_conexao_fechada_retorna_parcial(self):
        """Quando recv retorna b'' (conexao fechada), retorna o que tem."""
        conn = MagicMock()
        conn.recv.side_effect = [b"12", b""]
        resultado = TGSServer._receber_exato(conn, 6)
        assert resultado == b"12"


# --------------------------------------------------------------------------
# Testes de _extrair_tgs_request
# --------------------------------------------------------------------------


class TestExtrairTgsRequest:
    """Testes de extracao do payload MSG_TGS_REQUEST."""

    def test_extrai_tgt_e_nome_servico(self, servidor):
        """Extrai TGT e nome do servico de payload com prefixos de 4 bytes."""
        tgt = b"tgt_ficticio_123"
        nome = b"chat"
        payload = (
            struct.pack(">I", len(tgt))
            + tgt
            + struct.pack(">I", len(nome))
            + nome
        )
        resultado = servidor._extrair_tgs_request(payload)
        assert resultado == (tgt, nome)

    def test_payload_vazio_raises_value_error(self, servidor):
        """Payload vazio levanta ValueError."""
        with pytest.raises(ValueError, match="insuficiente"):
            servidor._extrair_tgs_request(b"")

    def test_tgt_incompleto_raises_value_error(self, servidor):
        """TGT com tamanho declarado maior que payload levanta ValueError."""
        payload = struct.pack(">I", 100) + b"curto"
        with pytest.raises(ValueError, match="insuficiente"):
            servidor._extrair_tgs_request(payload)


# --------------------------------------------------------------------------
# Testes de _montar_tgs_reply
# --------------------------------------------------------------------------


class TestMontarTgsReply:
    """Testes de montagem do payload MSG_TGS_REPLY."""

    def test_formato_correto(self):
        """Monta payload com prefixos de 4 bytes para ST e K_c_svc."""
        st = b"service_ticket_cifrado"
        ks = b"chave_sessao_cifrada"
        resultado = TGSServer._montar_tgs_reply(st, ks)

        # Primeiro 4 bytes: tamanho do ST
        tam_st = int.from_bytes(resultado[:4], "big")
        assert tam_st == len(st)

        # Proximos tam_st bytes: ST
        assert resultado[4 : 4 + tam_st] == st

        # Proximos 4 bytes: tamanho de K_c_svc
        offset = 4 + tam_st
        tam_ks = int.from_bytes(resultado[offset : offset + 4], "big")
        assert tam_ks == len(ks)

        # Restante: K_c_svc
        assert resultado[offset + 4 :] == ks


# --------------------------------------------------------------------------
# Testes de atender_cliente
# --------------------------------------------------------------------------


class TestAtenderCliente:
    """Testes do fluxo completo de atendimento de cliente."""

    def _montar_tgs_request(self, tgt_cifrado, nome_servico):
        """Monta payload no formato esperado: [4B tam][TGT][4B tam][nome]."""
        return (
            struct.pack(">I", len(tgt_cifrado))
            + tgt_cifrado
            + struct.pack(">I", len(nome_servico))
            + nome_servico
        )

    def test_fluxo_feliz_retorna_tgs_reply(self, servidor):
        """Fluxo completo: recebe TGS_REQUEST, retorna TGS_REPLY."""
        k_c_as = os.urandom(TAMANHO_CHAVE)
        nome = b"alice"
        timestamp = int(time.time())

        tgt = criar_ticket(nome, k_c_as, timestamp, LIFETIME_TICKET)
        tgt_cif = cifrar_aes_gcm(servidor.as_master_key, tgt)
        payload = self._montar_tgs_request(tgt_cif, b"chat")
        mensagem = empacotar(MSG_TGS_REQUEST, payload)

        conn = MagicMock()
        conn.recv.side_effect = [mensagem[:6], mensagem[6:]]

        servidor.atender_cliente(conn, ("127.0.0.1", 12345))

        args = conn.sendall.call_args[0][0]
        tipo, reply = desempacotar(args)
        assert tipo == MSG_TGS_REPLY

        tam_st = int.from_bytes(reply[:4], "big")
        assert tam_st > 0

        tam_ks = int.from_bytes(reply[4 + tam_st : 4 + tam_st + 4], "big")
        assert tam_ks > 0

    def test_tipo_invalido_retorna_erro(self, servidor, conn_mock):
        """Mensagem que nao e MSG_TGS_REQUEST gera MSG_ERROR."""
        msg_erro = empacotar(MSG_ERROR, b"lixo")
        conn_mock.recv.side_effect = [msg_erro[:6], msg_erro[6:]]

        servidor.atender_cliente(conn_mock, ("127.0.0.1", 9999))

        args = conn_mock.sendall.call_args[0][0]
        tipo, _ = desempacotar(args)
        assert tipo == MSG_ERROR

    def test_tgt_com_chave_errada_retorna_erro(self, servidor):
        """TGT cifrado com chave diferente gera MSG_ERROR."""
        tgt_cif = cifrar_aes_gcm(os.urandom(TAMANHO_CHAVE), b"dados")
        payload = self._montar_tgs_request(tgt_cif, b"chat")
        mensagem = empacotar(MSG_TGS_REQUEST, payload)

        conn = MagicMock()
        conn.recv.side_effect = [mensagem[:6], mensagem[6:]]

        servidor.atender_cliente(conn, ("127.0.0.1", 12345))

        args = conn.sendall.call_args[0][0]
        tipo, erro = desempacotar(args)
        assert tipo == MSG_ERROR

    def test_ticket_expirado_retorna_erro(self, servidor):
        """TGT com timestamp antigo gera MSG_ERROR."""
        k_c_as = os.urandom(TAMANHO_CHAVE)
        nome = b"alice"
        timestamp_antigo = int(time.time()) - 100000

        tgt = criar_ticket(nome, k_c_as, timestamp_antigo, LIFETIME_TICKET)
        tgt_cif = cifrar_aes_gcm(servidor.as_master_key, tgt)
        payload = self._montar_tgs_request(tgt_cif, b"chat")
        mensagem = empacotar(MSG_TGS_REQUEST, payload)

        conn = MagicMock()
        conn.recv.side_effect = [mensagem[:6], mensagem[6:]]

        servidor.atender_cliente(conn, ("127.0.0.1", 12345))

        args = conn.sendall.call_args[0][0]
        tipo, erro = desempacotar(args)
        assert tipo == MSG_ERROR
