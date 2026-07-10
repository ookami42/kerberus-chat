"""Cliente Kerberos: orquestra o fluxo AS -> TGS -> Servico -> Chat.

Executa os 3 passos do protocolo, realiza autenticacao mutua e entra
no chat relay. Uma thread separada escuta mensagens recebidas de
outros usuarios enquanto o loop principal le o teclado.

Formato de envio: "destinatario mensagem"
  Exemplo: "bob Ola, tudo bem?"
"""

import getpass
import socket
import struct
import sys
import threading
import time

from common.config import AS_HOST, AS_PORT, TGS_HOST, TGS_PORT, SVC_HOST, SVC_PORT
from common.crypto import derivar_chave, decifrar_aes_gcm, cifrar_aes_gcm
from common.protocol import (
    empacotar,
    MSG_AUTH_REQUEST, MSG_AUTH_REPLY,
    MSG_TGS_REQUEST, MSG_TGS_REPLY,
    MSG_SVC_REQUEST, MSG_SVC_REPLY,
    MSG_CHAT, MSG_RELAY, MSG_ERROR,
)


class ClienteKerberos:
    """Cliente do protocolo Kerberos com chat relay."""

    def __init__(self):
        self.usuario = None
        self.k_c_as = None      # Chave de sessao Cliente-TGS
        self.k_c_svc = None     # Chave de sessao Cliente-Servico
        self.tgt_cifrado = None
        self.st_cifrado = None
        self.ts_original = 0
        self.socket = None
        self._conectado = False

        # Lock para evitar que as duas threads escrevam no terminal
        # ao mesmo tempo (thread principal + thread de escuta)
        self._print_lock = threading.Lock()

    # --- UTILITARIOS ---

    def _conectar(self, host, porta):
        """Conecta um socket TCP ao host:porta."""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((host, porta))

    def _receber_msg(self):
        """Le uma mensagem completa do socket.

        Retorna (tipo, payload) ou (None, None) se a conexao cair.
        Usa struct.unpack direto no cabecalho, nao desempacotar().
        """
        try:
            header = self._receber_exato(6)
            if header is None:
                return None, None
            tipo, tamanho = struct.unpack(">HI", header)
            payload = self._receber_exato(tamanho)
            if payload is None:
                return None, None
            return tipo, payload
        except (ConnectionError, OSError):
            return None, None

    def _receber_exato(self, n):
        """Le exatamente n bytes do socket, bloqueando ate completar.

        Retorna None se a conexao for fechada antes de completar.
        """
        partes = []
        recebido = 0
        while recebido < n:
            try:
                chunk = self.socket.recv(n - recebido)
            except (ConnectionError, OSError):
                return None
            if not chunk:
                return None
            partes.append(chunk)
            recebido += len(chunk)
        return b"".join(partes)

    def _imprimir(self, texto):
        """Print thread-safe: garante que duas threads nao misturem
        saida no terminal."""
        with self._print_lock:
            print(texto)

    def fechar(self):
        """Fecha o socket e sinaliza desconexao."""
        self._conectado = False
        if self.socket:
            try:
                self.socket.close()
            except OSError:
                pass
            self.socket = None

    # --- PASSO 1: AS (Authentication Server) ---

    def executar_passo1(self):
        """Envia MSG_AUTH_REQUEST ao AS, recebe salt + TGT + K_c_AS."""
        self.usuario = input("Usuario: ").strip()
        self._conectar(AS_HOST, AS_PORT)
        self.socket.sendall(
            empacotar(MSG_AUTH_REQUEST, self.usuario.encode())
        )

        tipo, payload = self._receber_msg()
        self.fechar()

        if tipo is None:
            raise Exception("Erro no AS: conexao perdida.")

        if tipo == MSG_ERROR:
            raise Exception(f"Erro no AS: {payload.decode()}")

        # Extrai: Salt(16B) + TGT + K_c_AS
        salt = payload[:16]
        offset = 16
        tam_tgt = struct.unpack(">I", payload[offset:offset + 4])[0]
        self.tgt_cifrado = payload[offset + 4:offset + 4 + tam_tgt]
        offset += 4 + tam_tgt
        tam_k = struct.unpack(">I", payload[offset:offset + 4])[0]
        k_as_cifrada = payload[offset + 4:offset + 4 + tam_k]

        senha = getpass.getpass("Senha: ")
        k_c = derivar_chave(senha.encode(), salt)
        self.k_c_as = decifrar_aes_gcm(k_c, k_as_cifrada)
        self._imprimir("[OK] Autenticado no AS.")

    # --- PASSO 2: TGS (Ticket Granting Server) ---

    def executar_passo2(self):
        """Envia MSG_TGS_REQUEST ao TGS, recebe Service Ticket + K_c_svc."""
        self._conectar(TGS_HOST, TGS_PORT)
        payload = (
            struct.pack(">I", len(self.tgt_cifrado))
            + self.tgt_cifrado
            + struct.pack(">I", 4)
            + b"chat"
        )

        self.socket.sendall(empacotar(MSG_TGS_REQUEST, payload))
        tipo, payload = self._receber_msg()
        self.fechar()

        if tipo is None:
            raise Exception("Erro no TGS: conexao perdida.")

        if tipo == MSG_ERROR:
            raise Exception(f"Erro no TGS: {payload.decode()}")

        offset = 0
        tam_st = struct.unpack(">I", payload[offset:offset + 4])[0]
        self.st_cifrado = payload[offset + 4:offset + 4 + tam_st]
        offset += 4 + tam_st
        tam_ks = struct.unpack(">I", payload[offset:offset + 4])[0]
        ks_cifrada = payload[offset + 4:offset + 4 + tam_ks]

        self.k_c_svc = decifrar_aes_gcm(self.k_c_as, ks_cifrada)
        self._imprimir("[OK] Ticket de servico obtido.")

    # --- PASSO 3: SERVICO (Autenticacao Mutua) ---

    def executar_passo3(self):
        """Envia MSG_SVC_REQUEST ao Servico, realiza autenticacao mutua."""
        self._conectar(SVC_HOST, SVC_PORT)
        self.ts_original = int(time.time())

        # Authenticator: [2B len_nome][nome][8B timestamp]
        nome_b = self.usuario.encode()
        auth = (
            struct.pack(">H", len(nome_b))
            + nome_b
            + struct.pack(">Q", self.ts_original)
        )
        auth_cifrado = cifrar_aes_gcm(self.k_c_svc, auth)

        payload = (
            struct.pack(">I", len(self.st_cifrado))
            + self.st_cifrado
            + struct.pack(">I", len(auth_cifrado))
            + auth_cifrado
        )

        self.socket.sendall(empacotar(MSG_SVC_REQUEST, payload))
        tipo, payload = self._receber_msg()

        if tipo is None:
            self.fechar()
            raise Exception("Erro no Servico: conexao perdida.")

        if tipo == MSG_ERROR:
            raise Exception(f"Erro no Servico: {payload.decode()}")

        resp_decifrada = decifrar_aes_gcm(self.k_c_svc, payload)
        ts_resp = struct.unpack(">Q", resp_decifrada)[0]

        if ts_resp == self.ts_original + 1:
            self._imprimir("[OK] Autenticacao mutua concluida.")
            self._imprimir("[OK] Conectado ao chat.")
        else:
            self.fechar()
            raise Exception("Falha na autenticacao mutua!")

    # --- THREAD DE ESCUTA ---

    def _escutar(self):
        """Thread que ouve mensagens recebidas de outros usuarios.

        Fica em loop recebendo MSG_RELAY do servico. Cada MSG_RELAY
        contem: [2B len_remetente][remetente][texto da mensagem].

        Quando recebe algo, imprime na tela. O loop principal
        continua lendo o teclado normalmente.
        """
        while self._conectado and self.socket:
            tipo, payload = self._receber_msg()
            if tipo is None:
                break

            if tipo == MSG_RELAY:
                # Extrai: [2B len_rem][rem][mensagem]
                len_rem = struct.unpack(">H", payload[:2])[0]
                remetente = payload[2:2 + len_rem].decode()
                texto = payload[2 + len_rem:].decode("utf-8",
                                                      errors="replace")
                self._imprimir(f"\n{remetente}: {texto}\n> ")

            elif tipo == MSG_ERROR:
                self._imprimir(
                    f"\n[ERRO] {payload.decode()}"
                )
                break

    # --- CHAT ---

    def loop_chat(self):
        """Loop principal: le mensagens do teclado e envia ao servico.

        Formato: "destinatario texto da mensagem"
        Exemplo: "bob Ola, como vai?"

        Comandos especiais:
          /sair  — encerra o chat
        """
        # Inicia a thread de escuta
        self._conectado = True
        escuta = threading.Thread(target=self._escutar, daemon=True)
        escuta.start()

        print("\nFormato: destinatario mensagem")
        print("Exemplo: bob Ola, tudo bem?")
        print("Digite /sair para encerrar.\n")

        try:
            while self._conectado:
                linha = input("> ").strip()

                if not linha:
                    continue

                if linha.lower() == "/sair":
                    self._imprimir("[CLIENTE] Encerrando chat...")
                    break

                # Envia a mensagem para o servico (MSG_CHAT)
                # O servico extrai o destinatario da primeira palavra
                try:
                    self.socket.sendall(
                        empacotar(MSG_CHAT, linha.encode())
                    )
                except OSError:
                    self._imprimir("[CLIENTE] Conexao perdida.")
                    break

        except KeyboardInterrupt:
            self._imprimir("\n[CLIENTE] Chat interrompido.")
        finally:
            self.fechar()


def _cadastrar_usuario():
    """Fluxo de cadastro de novo usuario (idem scripts/cadastrar_usuario.py)."""
    from os import urandom
    from common.config import USER_DB_PATH, TAMANHO_SALT
    from common.crypto import derivar_chave
    from as_server.user_db import UserDB

    banco = UserDB(USER_DB_PATH)

    print("\n### Cadastrar usuario ###")
    nome = input("Usuario: ").strip()
    senha = getpass.getpass("Senha: ")

    if banco.buscar(nome) is not None:
        print(f"Usuario '{nome}' ja existe.")
    else:
        salt = urandom(TAMANHO_SALT)
        hash_chave = derivar_chave(senha.encode(), salt)
        banco.cadastrar(nome, salt, hash_chave)
        print(f"Usuario '{nome}' cadastrado com sucesso!")


def _login():
    """Fluxo Kerberos completo: AS -> TGS -> Servico -> Chat."""
    cliente = ClienteKerberos()
    try:
        cliente.executar_passo1()
        cliente.executar_passo2()
        cliente.executar_passo3()
        cliente.loop_chat()
    except Exception as e:
        print(f"\n[FALHA] {e}")
        cliente.fechar()


def main():
    """Ponto de entrada do cliente Kerberos com menu de cadastro/login."""
    while True:
        print("\n" + "=" * 40)
        print("  KERBEROS CHAT — Cliente")
        print("=" * 40)
        print("  1. Cadastrar usuario")
        print("  2. Fazer login")
        print("  0. Sair")
        print()

        opcao = input("Opcao: ").strip()

        if opcao == "1":
            _cadastrar_usuario()
        elif opcao == "2":
            _login()
        elif opcao == "0":
            print("Ate logo!")
            break
        else:
            print("Opcao invalida.")


if __name__ == "__main__":
    main()
