"""Testes unitários para tgs_server/message.py.

Testa as constantes de tipos de mensagem (issue #6), as funções de
empacotar/desempacotar (issue #5) e criar/extrair ticket (issue #7).
"""

import os

from tgs_server.message import (
    MSG_AUTH_REQUEST,
    MSG_AUTH_REPLY,
    MSG_TGS_REQUEST,
    MSG_TGS_REPLY,
    MSG_SVC_REQUEST,
    MSG_SVC_REPLY,
    MSG_CHAT,
    MSG_ECHO,
    MSG_ERROR,
    empacotar,
    desempacotar,
    criar_ticket,
    extrair_ticket,
)
from common.config import TAMANHO_CHAVE


class TestConstantesMensagem:
    """Constantes dos tipos de mensagem (issue #6)."""

    def test_auth_request_e_1(self):
        assert MSG_AUTH_REQUEST == 1

    def test_auth_reply_e_2(self):
        assert MSG_AUTH_REPLY == 2

    def test_tgs_request_e_3(self):
        assert MSG_TGS_REQUEST == 3

    def test_tgs_reply_e_4(self):
        assert MSG_TGS_REPLY == 4

    def test_svc_request_e_5(self):
        assert MSG_SVC_REQUEST == 5

    def test_svc_reply_e_6(self):
        assert MSG_SVC_REPLY == 6

    def test_chat_e_7(self):
        assert MSG_CHAT == 7

    def test_echo_e_8(self):
        assert MSG_ECHO == 8

    def test_error_e_9(self):
        assert MSG_ERROR == 9


class TestEmpacotarDesempacotar:
    """Testes de serialização de mensagens (issue #5)."""

    def test_empacotar_retorna_9_bytes(self):
        """empacotar(5, b"abc") deve retornar 6 bytes (header) + 3 bytes = 9 bytes."""
        resultado = empacotar(5, b"abc")
        assert len(resultado) == 9

    def test_roundtrip_retorna_tipo_e_dados(self):
        """desempacotar(empacotar(t, d)) deve retornar (t, d)."""
        tipo, dados = 3, b"mensagem de teste"
        pacote = empacotar(tipo, dados)
        resultado = desempacotar(pacote)
        assert resultado == (tipo, dados)

    def test_tipo_decodifica_em_big_endian(self):
        """Os primeiros 2 bytes decodificam o tipo como unsigned short big-endian.
        
        struct.pack('>H', 257) produz b'\x01\x01' (big-endian).
        """
        pacote = empacotar(257, b"")
        assert pacote[0] == 0x01
        assert pacote[1] == 0x01

    def test_tamanho_decodifica_em_big_endian(self):
        """Os próximos 4 bytes decodificam o tamanho como unsigned int big-endian.
        
        struct.pack('>I', 260) produz b'\x00\x00\x01\x04'.
        """
        dados = b"a" * 260
        pacote = empacotar(1, dados)
        assert pacote[2:6] == b"\x00\x00\x01\x04"

    def test_empacotar_dados_vazios(self):
        """empacotar(1, b"") retorna apenas os 6 bytes de cabeçalho."""
        pacote = empacotar(1, b"")
        assert len(pacote) == 6

    def test_tipos_diferentes_funcionam(self):
        """Roundtrip funciona com todos os tipos definidos."""
        for tipo in range(1, 10):
            dados = f"msg tipo {tipo}".encode()
            pacote = empacotar(tipo, dados)
            t, d = desempacotar(pacote)
            assert t == tipo
            assert d == dados

    def test_dados_grandes_funcionam(self):
        """Roundtrip com payload de 10KB funciona."""
        dados = os.urandom(10240)
        pacote = empacotar(7, dados)
        t, d = desempacotar(pacote)
        assert t == 7
        assert d == dados


class TestCriarExtrairTicket:
    """Testes de criação e extração de tickets (issue #7)."""

    def test_criar_ticket_tamanho_correto(self):
        """criar_ticket com nome de 5 bytes retorna 8+4+2+5+16 = 35 bytes."""
        chave = os.urandom(TAMANHO_CHAVE)
        ticket = criar_ticket(b"alice", chave, 1000, 480)
        assert len(ticket) == 8 + 4 + 2 + 5 + 16

    def test_roundtrip_retorna_campos_originais(self):
        """extrair_ticket(criar_ticket(...)) devolve os mesmos campos."""
        chave = os.urandom(TAMANHO_CHAVE)
        ticket = criar_ticket(b"alice", chave, 1000, 480)
        nome, chave_sessao, timestamp, lifetime = extrair_ticket(ticket)
        assert nome == b"alice"
        assert chave_sessao == chave
        assert timestamp == 1000
        assert lifetime == 480

    def test_nomes_de_tamanhos_diferentes(self):
        """Funciona com nomes de comprimentos variados."""
        chave = os.urandom(TAMANHO_CHAVE)
        for nome in [b"bob", b"alice", b"charlie"]:
            ticket = criar_ticket(nome, chave, 2000, 240)
            nome_out, chave_out, ts, lt = extrair_ticket(ticket)
            assert nome_out == nome
            assert chave_out == chave

    def test_chave_sessao_tem_16_bytes(self):
        """Chave de sessão extraída tem TAMANHO_CHAVE bytes."""
        chave = os.urandom(TAMANHO_CHAVE)
        ticket = criar_ticket(b"dave", chave, 3000, 120)
        _, chave_out, _, _ = extrair_ticket(ticket)
        assert len(chave_out) == TAMANHO_CHAVE

    def test_timestamp_e_lifetime_min_corretos(self):
        """Timestamp e lifetime são preservados no roundtrip."""
        chave = os.urandom(TAMANHO_CHAVE)
        ticket = criar_ticket(b"eve", chave, 1234567890, 60)
        _, _, ts, lt = extrair_ticket(ticket)
        assert ts == 1234567890
        assert lt == 60

    def test_tickets_diferentes_com_mesmo_nome(self):
        """Dois tickets para o mesmo usuário com chaves diferentes são distintos."""
        chave1 = os.urandom(TAMANHO_CHAVE)
        chave2 = os.urandom(TAMANHO_CHAVE)
        ticket1 = criar_ticket(b"frank", chave1, 100, 10)
        ticket2 = criar_ticket(b"frank", chave2, 100, 10)
        assert ticket1 != ticket2
