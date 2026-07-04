"""Testes de empacotar/desempacotar do cabeçalho de rede (tgs_server/message.py)."""

from tgs_server.message import criar_ticket, desempacotar, empacotar, extrair_ticket


def test_empacotar_retorna_tamanho_correto():
    resultado = empacotar(5, b"abc")
    assert len(resultado) == 9


def test_desempacotar_round_trip():
    resultado = empacotar(5, b"abc")
    assert desempacotar(resultado) == (5, b"abc")


def test_tipo_big_endian():
    resultado = empacotar(5, b"abc")
    assert resultado[:2] == b"\x00\x05"


def test_tamanho_big_endian():
    resultado = empacotar(5, b"abc")
    assert resultado[2:6] == b"\x00\x00\x00\x03"


def test_criar_ticket_retorna_tamanho_correto():
    chave = bytes(range(16))
    resultado = criar_ticket(b"alice", chave, 1000, 480)
    assert len(resultado) == 8 + 4 + 2 + 5 + 16


def test_extrair_ticket_round_trip():
    chave = bytes(range(16))
    resultado = criar_ticket(b"alice", chave, 1000, 480)
    assert extrair_ticket(resultado) == (b"alice", chave, 1000, 480)


def test_ticket_com_nomes_de_tamanhos_diferentes():
    chave = bytes(range(16))
    for nome in (b"bob", b"charlie"):
        resultado = criar_ticket(nome, chave, 2000, 60)
        assert extrair_ticket(resultado) == (nome, chave, 2000, 60)
