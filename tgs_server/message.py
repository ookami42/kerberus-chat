"""Serialização de mensagens: empacotar, desempacotar, constantes dos tipos."""

import struct

MSG_AUTH_REQUEST = 1  # Cliente → AS
MSG_AUTH_REPLY = 2    # AS → Cliente
MSG_TGS_REQUEST = 3   # Cliente → TGS
MSG_TGS_REPLY = 4     # TGS → Cliente
MSG_SVC_REQUEST = 5   # Cliente → Serviço
MSG_SVC_REPLY = 6     # Serviço → Cliente
MSG_CHAT = 7          # Cliente → Serviço (dados do chat)
MSG_ECHO = 8          # Serviço → Cliente (eco da mensagem)
MSG_ERROR = 9         # Qualquer direção

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


_TICKET_HEADER_FORMAT = ">QIH"  # timestamp (8) + lifetime_min (4) + len(nome) (2)
_TICKET_HEADER_SIZE = struct.calcsize(_TICKET_HEADER_FORMAT)  # 14


def criar_ticket(nome: bytes, chave_sessao: bytes, timestamp: int, lifetime_min: int) -> bytes:
    """Monta o formato binário interno de um ticket (TGT ou Service Ticket).

    Args:
        nome: Nome do usuário.
        chave_sessao: Chave de sessão de 16 bytes.
        timestamp: Timestamp de emissão do ticket.
        lifetime_min: Tempo de vida do ticket em minutos.

    Returns:
        Bytes no formato [8 bytes timestamp][4 bytes lifetime_min][2 bytes
        len(nome)][N bytes nome][16 bytes chave_sessao].
    """
    cabecalho = struct.pack(_TICKET_HEADER_FORMAT, timestamp, lifetime_min, len(nome))
    return cabecalho + nome + chave_sessao


def extrair_ticket(blob: bytes) -> tuple[bytes, bytes, int, int]:
    """Desmonta o formato binário interno de um ticket.

    Args:
        blob: Bytes gerados por `criar_ticket`.

    Returns:
        Tupla (nome, chave_sessao, timestamp, lifetime_min).
    """
    timestamp, lifetime_min, tamanho_nome = struct.unpack(
        _TICKET_HEADER_FORMAT, blob[:_TICKET_HEADER_SIZE]
    )
    nome = blob[_TICKET_HEADER_SIZE:_TICKET_HEADER_SIZE + tamanho_nome]
    chave_sessao = blob[_TICKET_HEADER_SIZE + tamanho_nome:]
    return nome, chave_sessao, timestamp, lifetime_min
