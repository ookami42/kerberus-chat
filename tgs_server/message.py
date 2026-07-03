"""Serialização de mensagens: empacotar, desempacotar, constantes dos tipos."""

import struct

_HEADER_FORMAT = ">HI"  # unsigned short (tipo) + unsigned int (tamanho), big-endian
_HEADER_SIZE = struct.calcsize(_HEADER_FORMAT)  # 6


def empacotar(tipo: int, dados: bytes) -> bytes:
    """Monta o cabeçalho de rede de uma mensagem.

    Args:
        tipo: Identificador do tipo da mensagem (cabe em unsigned short, 0-65535).
        dados: Payload da mensagem.

    Returns:
        Bytes no formato [2 bytes tipo][4 bytes tamanho][N bytes dados].
    """
    return struct.pack(_HEADER_FORMAT, tipo, len(dados)) + dados


def desempacotar(buffer: bytes) -> tuple[int, bytes]:
    """Desmonta o cabeçalho de rede de uma mensagem.

    Args:
        buffer: Bytes com pelo menos 6 bytes (cabeçalho) seguidos do payload.

    Returns:
        Tupla (tipo, payload) decodificada do buffer.
    """
    tipo, tamanho = struct.unpack(_HEADER_FORMAT, buffer[:_HEADER_SIZE])
    return tipo, buffer[_HEADER_SIZE:_HEADER_SIZE + tamanho]
