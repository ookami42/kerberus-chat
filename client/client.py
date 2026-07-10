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

import socket
import struct
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
    MSG_NOTE_REPLY, MSG_NOTE_DELETE, MSG_ERROR,
)
from client.ui import (
    exibir_banner,
    exibir_menu_principal,
    exibir_ajuda,
    perguntar_usuario,
    perguntar_senha,
    perguntar_conteudo,
    mostrar_status,
    mostrar_erro,
    mostrar_resultado,
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
        self.usuario = perguntar_usuario()
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

        senha = perguntar_senha()
        k_c = derivar_chave(senha.encode(), salt)
        self.k_c_as = decifrar_aes_gcm(k_c, k_as_cifrada)
        mostrar_status("Autenticado no AS.")

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
        mostrar_status("Ticket de servico obtido.")

    # --- LOOP DE NOTAS ---

    def loop_notas(self):
        """Loop de comandos do servico de notas.

        Cada comando abre uma nova conexao TCP com o Servico,
        realiza o handshake Kerberos completo (ticket + authenticator +
        autenticacao mutua) e entao envia o comando de nota.

        O ticket e reutilizado entre comandos — Single Sign-On.
        """
        exibir_ajuda()

        while True:
            try:
                linha = input("> ").strip()
                if not linha:
                    continue
                if linha == "/sair":
                    break

                comando = self._parsear_comando(linha)
                if comando is None:
                    mostrar_erro("Comando desconhecido. Use /notas, /ler ou /escrever.")
                    continue

                cmd_tipo, cmd_payload = comando

                # 1. Conectar ao Servico
                self._conectar(SVC_HOST, SVC_PORT)

                # 2. Handshake Kerberos
                ts_auth = int(time.time())
                self._enviar_svc_request(ts_auth)

                tipo, payload = self._receber_msg()
                if tipo is None:
                    mostrar_erro("Conexao perdida com o servico.")
                    self.fechar()
                    continue

                if tipo == MSG_ERROR:
                    msg = payload.decode() if payload else "Falha na autenticacao."
                    mostrar_erro(msg)
                    self.fechar()
                    continue

                if tipo != MSG_SVC_REPLY:
                    mostrar_erro(f"Resposta inesperada do servico (tipo={tipo}).")
                    self.fechar()
                    continue

                # 3. Autenticacao mutua: verificar timestamp+1
                try:
                    resp = decifrar_aes_gcm(self.k_c_svc, payload)
                    ts_resp = struct.unpack(">Q", resp)[0]
                except InvalidTag:
                    mostrar_erro("Falha ao decifrar resposta de autenticacao mutua.")
                    self.fechar()
                    continue

                if ts_resp != ts_auth + 1:
                    mostrar_erro("Falha na autenticacao mutua (timestamp incorreto).")
                    self.fechar()
                    continue

                # 4. Enviar comando de nota
                self.socket.sendall(empacotar(cmd_tipo, cmd_payload))
                tipo_resp, payload_resp = self._receber_msg()

                if tipo_resp == MSG_NOTE_REPLY:
                    mostrar_resultado(payload_resp.decode())
                elif tipo_resp == MSG_ERROR:
                    mostrar_erro(payload_resp.decode())
                else:
                    mostrar_erro(f"Resposta inesperada (tipo={tipo_resp}).")

                self.fechar()

            except KeyboardInterrupt:
                print()
                break
            except Exception as e:
                mostrar_erro(str(e))
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

        if linha.startswith("/ler"):
            nome = linha[4:].strip()
            if not nome:
                mostrar_erro("Uso: /ler <arquivo>")
                return None
            return MSG_NOTE_READ, nome.encode()

        if linha.startswith("/escrever"):
            nome = linha[9:].strip()
            if not nome:
                mostrar_erro("Uso: /escrever <arquivo>")
                return None
            conteudo = perguntar_conteudo()
            return MSG_NOTE_WRITE, (nome + "\n" + conteudo).encode()

        if linha.startswith("/deletar"):
            nome = linha[8:].strip()
            if not nome:
                mostrar_erro("Uso: /deletar <arquivo>")
                return None
            return MSG_NOTE_DELETE, nome.encode()

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
    nome = perguntar_usuario()
    senha = perguntar_senha()

    if banco.buscar(nome) is not None:
        mostrar_erro(f"Usuario '{nome}' ja existe.")
    else:
        salt = urandom(TAMANHO_SALT)
        hash_chave = derivar_chave(senha.encode(), salt)
        banco.cadastrar(nome, salt, hash_chave)
        mostrar_status(f"Usuario '{nome}' cadastrado com sucesso!")


def _login():
    """Fluxo Kerberos completo: AS -> TGS -> Servico de Notas."""
    cliente = ClienteKerberos()
    try:
        cliente.executar_passo1()
        cliente.executar_passo2()
        cliente.loop_notas()
    except Exception as e:
        mostrar_erro(str(e))
        cliente.fechar()


def main():
    """Ponto de entrada do cliente Kerberos com menu de cadastro/login."""
    while True:
        exibir_banner()
        opcao = exibir_menu_principal()

        if opcao == "1":
            _cadastrar_usuario()
        elif opcao == "2":
            _login()
        elif opcao == "0":
            mostrar_status("Ate logo!")
            break
        else:
            mostrar_erro("Opcao invalida.")


if __name__ == "__main__":
    main()
