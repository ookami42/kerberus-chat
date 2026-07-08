import socket
import time

from common.crypto import cifrar_aes_gcm, decifrar_aes_gcm
from tgs_server.message import (
    criar_ticket,
    extrair_ticket,
    empacotar,
    desempacotar,
    MSG_TGS_REQUEST,
    MSG_TGS_REPLY,
)

HOST = "127.0.0.1"
PORT = 5451

CHAVE_AS = b"0123456789abcdef"
CHAVE_SERVICO = b"fedcba9876543210"

# Simula o TGT emitido pelo AS
K_C_AS = b"abcdefghijklmnop"

ticket = criar_ticket(
    nome=b"alice",
    chave_sessao=K_C_AS,
    timestamp=int(time.time()),
    lifetime_min=10,
)

tgt_cif = cifrar_aes_gcm(CHAVE_AS, ticket)

payload = (
    len(tgt_cif).to_bytes(2, "big")
    + tgt_cif
    + b"chat"
)

mensagem = empacotar(
    MSG_TGS_REQUEST,
    payload,
)

sock = socket.socket()
sock.connect((HOST, PORT))
sock.sendall(mensagem)

resposta = sock.recv(4096)

sock.close()

tipo, payload = desempacotar(resposta)

assert tipo == MSG_TGS_REPLY

tam_ticket = int.from_bytes(payload[:2], "big")

service_ticket = payload[2:2 + tam_ticket]

k_c_svc_cif = payload[2 + tam_ticket:]

# Cliente recupera K_c_svc
K_C_SVC = decifrar_aes_gcm(
    K_C_AS,
    k_c_svc_cif,
)

# Apenas o serviço consegue abrir o ticket
ticket = decifrar_aes_gcm(
    CHAVE_SERVICO,
    service_ticket,
)

nome, chave_ticket, ts, lifetime = extrair_ticket(ticket)

assert nome == b"alice"
assert chave_ticket == K_C_SVC

print("Teste OK")