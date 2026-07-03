"""Testes de empacotar/desempacotar do cabeçalho de rede (tgs_server/message.py)."""

from tgs_server.message import empacotar, desempacotar


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
