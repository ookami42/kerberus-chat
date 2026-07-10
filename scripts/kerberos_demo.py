"""Lanca os 3 servidores Kerberos (AS, TGS, Servico) em threads.

Uso:
  python scripts/kerberos_demo.py

Os tres servidores rodam em segundo plano no mesmo terminal.
Pressione Ctrl+C para encerrar todos.

Antes de rodar, certifique-se de que:
  1. As chaves foram geradas:  python scripts/gerar_chaves.py
  2. Ha usuarios cadastrados:  cadastrar-usuario
"""

import threading
import time
import sys

# Importa os servidores
from as_server.as_server import ASServer
from tgs_server.tgs_server import TGSServer
from service.service_server import ServicoKerberos
from as_server.user_db import UserDB
from common.config import (
    AS_HOST, AS_PORT,
    TGS_HOST, TGS_PORT,
    SVC_HOST, SVC_PORT,
    USER_DB_PATH,
    AS_MASTER_KEY_PATH,
    SVC_MASTER_KEY_PATH,
)


def _carregar_chave(path, nome):
    """Carrega uma chave de 16 bytes do arquivo."""
    with open(path, "rb") as f:
        chave = f.read()
    if len(chave) != 16:
        raise ValueError(f"Chave {nome} invalida: {len(chave)} bytes")
    return chave


def main():
    print("=" * 50)
    print("  KERBEROS CHAT — Servidores")
    print("=" * 50)
    print()

    # Carrega recursos compartilhados
    user_db = UserDB(USER_DB_PATH)
    try:
        as_key = _carregar_chave(AS_MASTER_KEY_PATH, "AS")
        svc_key = _carregar_chave(SVC_MASTER_KEY_PATH, "Servico")
    except FileNotFoundError as e:
        print(f"\n[ERRO] Chave nao encontrada: {e}")
        print("Execute 'gerar-chaves' primeiro para gerar as chaves mestras.")
        sys.exit(1)

    # Cria os servidores (ainda nao iniciam)
    as_srv = ASServer(
        host=AS_HOST, porta=AS_PORT,
        user_db=user_db, chave_mestra=as_key,
    )
    tgs_srv = TGSServer(host=TGS_HOST, port=TGS_PORT)
    svc_srv = ServicoKerberos(host=SVC_HOST, porta=SVC_PORT)

    # Dispara cada servidor em uma thread daemon
    threads = [
        threading.Thread(target=as_srv.iniciar, daemon=True,
                         name="AS"),
        threading.Thread(target=tgs_srv.iniciar, daemon=True,
                         name="TGS"),
        threading.Thread(target=svc_srv.iniciar, daemon=True,
                         name="Servico"),
    ]

    for t in threads:
        t.start()

    print()
    print("Servidores iniciados:")
    print(f"  AS      — {AS_HOST}:{AS_PORT}")
    print(f"  TGS     — {TGS_HOST}:{TGS_PORT}")
    print(f"  Servico — {SVC_HOST}:{SVC_PORT}")
    print()
    print("Abra outro terminal e execute:")
    print("  kerberos-cliente")
    print()
    print("Pressione Ctrl+C para encerrar todos os servidores.")
    print()

    try:
        # Mantem o processo vivo enquanto os servidores rodam
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nEncerrando servidores...")
        sys.exit(0)


if __name__ == "__main__":
    main()
