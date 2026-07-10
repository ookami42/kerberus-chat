"""Cliente Kerberos: orquestra o fluxo AS -> TGS -> Servico de Notas.

Executa os passos 1 e 2 do protocolo (AS e TGS) para obter um
Service Ticket. Em seguida, entra no loop de comandos de notas,
onde cada comando abre uma nova conexao TCP e reutiliza o ticket.

Formatos de comando:
  /notas              — listar notas
  /ler <arquivo>      — ler uma nota
  /escrever <arquivo> — criar ou sobrescrever nota
  /sair               — encerrar
"""

import getpass
import socket
import struct
import sys
import time

from cryptography.exceptions import InvalidTag

from common.config import AS_HOST, AS_PORT, TGS_HOST, TGS_PORT, SVC_HOST, SVC_PORT
from common.crypto import derivar_chave, decifrar_aes_gcm, cifrar_aes_gcm
from common.protocol import (
    empacotar,
    MSG_AUTH_REQUEST, MSG_AUTH_REPLY,
    MSG_TGS_REQUEST, MSG_TGS_REPLY,
    MSG_SVC_REQUEST, MSG_SVC_REPLY,
    MSG_NOTE_LIST, MSG_NOTE_READ, MSG_NOTE_WRITE,
    MSG_NOTE_REPLY, MSG_ERROR,
)


class ClienteKerberos:
    """Cliente do protocolo Kerberos com servico de notas."""

    def __init__(self):
        self.usuario = None
        self.k_c_as = None      # Chave de sessao Cliente-TGS
        self.k_c_svc = None     # Chave de sessao Cliente-Servico
        self.tgt_cifrado = None
        self.st_cifrado = None
        self.socket = None

    # --- UTILITARIOS ---

    def _conectar(self, host, porta):
        """Conecta um socket TCP ao host:porta."""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((host, porta))

    def _receber_msg(self):
        """Le uma mensagem completa do socket.

        Returns:
            tuple[int | None, bytes | None]: (tipo, payload) ou (None, None)
            se a conexao cair.
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
        """Le exatamente n bytes do socket.

        Args:
            n: Numero de bytes a ler.

        Returns:
            bytes | None: Bytes lidos ou None se a conexao for fechada.
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

    def fechar(self):
        """Fecha o socket."""
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
        print("[OK] Autenticado no AS.")

    # --- PASSO 2: TGS (Ticket Granting Server) ---

    def executar_passo2(self):
        """Envia MSG_TGS_REQUEST ao TGS, recebe Service Ticket + K_c_svc."""
        self._conectar(TGS_HOST, TGS_PORT)
        payload = (
            struct.pack(">I", len(self.tgt_cifrado))
            + self.tgt_cifrado
            + struct.pack(">I", 5)
            + b"notas"
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
        print("[OK] Ticket de servico obtido.")

    # --- LOOP DE NOTAS ---

    def loop_notas(self):
        """Loop de comandos do servico de notas.

        Cada comando abre uma nova conexao TCP com o Servico,
        realiza o handshake Kerberos completo (ticket + authenticator +
        autenticacao mutua) e entao envia o comando de nota.

        O ticket e reutilizado entre comandos — Single Sign-On.
        """
        print()
        print("Comandos:")
        print("  /notas                — listar suas notas")
        print("  /ler <arquivo>        — ler uma nota")
        print("  /escrever <arquivo>   — criar ou sobrescrever nota")
        print("  /sair                 — encerrar")
        print()

        while True:
            try:
                linha = input("> ").strip()
                if not linha:
                    continue
                if linha == "/sair":
                    break

                comando = self._parsear_comando(linha)
                if comando is None:
                    print("Comando desconhecido. Use /notas, /ler ou /escrever.")
                    continue

                cmd_tipo, cmd_payload = comando

                # 1. Conectar ao Servico
                self._conectar(SVC_HOST, SVC_PORT)

                # 2. Handshake Kerberos
                ts_auth = int(time.time())
                self._enviar_svc_request(ts_auth)

                tipo, payload = self._receber_msg()
                if tipo is None:
                    print("[ERRO] Conexao perdida com o servico.")
                    self.fechar()
                    continue

                if tipo == MSG_ERROR:
                    msg = payload.decode() if payload else "Falha na autenticacao."
                    print(f"[ERRO] {msg}")
                    self.fechar()
                    continue

                if tipo != MSG_SVC_REPLY:
                    print(f"[ERRO] Resposta inesperada do servico (tipo={tipo}).")
                    self.fechar()
                    continue

                # 3. Autenticacao mutua: verificar timestamp+1
                try:
                    resp = decifrar_aes_gcm(self.k_c_svc, payload)
                    ts_resp = struct.unpack(">Q", resp)[0]
                except InvalidTag:
                    print("[ERRO] Falha ao decifrar resposta de autenticacao mutua.")
                    self.fechar()
                    continue

                if ts_resp != ts_auth + 1:
                    print("[ERRO] Falha na autenticacao mutua (timestamp incorreto).")
                    self.fechar()
                    continue

                # 4. Enviar comando de nota
                self.socket.sendall(empacotar(cmd_tipo, cmd_payload))
                tipo_resp, payload_resp = self._receber_msg()

                if tipo_resp == MSG_NOTE_REPLY:
                    print(payload_resp.decode())
                elif tipo_resp == MSG_ERROR:
                    print(f"[ERRO] {payload_resp.decode()}")
                else:
                    print(f"[ERRO] Resposta inesperada (tipo={tipo_resp}).")

                self.fechar()

            except KeyboardInterrupt:
                print()
                break
            except Exception as e:
                print(f"[ERRO] {e}")
                self.fechar()
                continue

        self.fechar()

    def _parsear_comando(self, linha):
        """Interpreta a linha digitada e retorna (tipo_msg, payload).

        Args:
            linha: Texto digitado pelo usuario.

        Returns:
            tuple[int, bytes] | None: (tipo_da_mensagem, payload) ou None
            se o comando nao for reconhecido.
        """
        if linha == "/notas":
            return MSG_NOTE_LIST, b""

        if linha.startswith("/ler "):
            nome = linha[5:].strip()
            if not nome:
                print("Uso: /ler <arquivo>")
                return None
            return MSG_NOTE_READ, nome.encode()

        if linha.startswith("/escrever "):
            nome = linha[10:].strip()
            if not nome:
                print("Uso: /escrever <arquivo>")
                return None
            conteudo = input("Conteudo: ")
            return MSG_NOTE_WRITE, (nome + "\n" + conteudo).encode()

        return None

    def _enviar_svc_request(self, ts_auth):
        """Monta e envia MSG_SVC_REQUEST com Service Ticket e Authenticator.

        O Authenticator contem: [2 bytes len_nome][nome][8 bytes timestamp].
        Ambos, ticket e authenticator, sao enviados com prefixo de 4 bytes.

        Args:
            ts_auth: Timestamp atual (int) usado no authenticator.
        """
        nome_b = self.usuario.encode()
        auth = (
            struct.pack(">H", len(nome_b))
            + nome_b
            + struct.pack(">Q", ts_auth)
        )
        auth_cifrado = cifrar_aes_gcm(self.k_c_svc, auth)

        payload = (
            struct.pack(">I", len(self.st_cifrado))
            + self.st_cifrado
            + struct.pack(">I", len(auth_cifrado))
            + auth_cifrado
        )

        self.socket.sendall(empacotar(MSG_SVC_REQUEST, payload))


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
    """Fluxo Kerberos completo: AS -> TGS -> Servico de Notas."""
    cliente = ClienteKerberos()
    try:
        cliente.executar_passo1()
        cliente.executar_passo2()
        cliente.loop_notas()
    except Exception as e:
        print(f"\n[FALHA] {e}")
        cliente.fechar()


def main():
    """Ponto de entrada do cliente Kerberos com menu de cadastro/login."""
    while True:
        print("\n" + "=" * 40)
        print("  KERBEROS NOTAS — Cliente")
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
