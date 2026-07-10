"""Authentication Server: autentica usuarios e emite Ticket Granting Ticket.

Recebe MSG_AUTH_REQUEST com nome do usuario, busca no UserDB,
deriva a chave do cliente, gera K_c_AS, monta o TGT cifrado com
as_master_key e envia MSG_AUTH_REPLY.
"""

import os
import socket
import struct
import threading
import time

from common.config import (
    AS_HOST,
    AS_PORT,
    USER_DB_PATH,
    AS_MASTER_KEY_PATH,
    LIFETIME_TICKET,
)
from common.protocol import (
    MSG_AUTH_REQUEST,
    MSG_AUTH_REPLY,
    MSG_ERROR,
    desempacotar,
    empacotar,
    criar_ticket,
)
from common.crypto import cifrar_aes_gcm
from as_server.user_db import UserDB


# Tamanho fixo do salt utilizado na derivação da chave do cliente
SALT_TAMANHO = 16


class ASServer:
    """Servidor de Autenticação (AS) para o projeto kerberos-chat.

    Responsável por receber conexões de clientes e emitir tickets iniciais
    (TGT). Esta versão integra a issue #1 (configurações centralizadas), a
    issue #9 (UserDB) e a issue #2 (funções de criptografia AES-GCM).
    """

    def __init__(self, host: str = AS_HOST, porta: int = AS_PORT,
                 user_db: UserDB | None = None, chave_mestra: bytes | None = None):
        self.host = host
        self.porta = porta
        self.user_db = user_db
        self.chave_mestra = chave_mestra if chave_mestra is not None else b""
        self._socket: socket.socket | None = None
        self._rodando = False

    def iniciar(self) -> None:
        """Inicia o servidor TCP e aceita conexões em loop.

        Cada conexão aceita é tratada em uma nova thread, permitindo
        atendimento concorrente de múltiplos clientes.
        """
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self._socket.bind((self.host, self.porta))
        self._socket.listen(5)
        self._rodando = True

        print(f"[AS] Servidor de Autenticação ouvindo em {self.host}:{self.porta}")

        try:
            while self._rodando:
                con, addr = self._socket.accept()
                thread = threading.Thread(
                    target=self.atender_cliente,
                    args=(con, addr),
                    daemon=True
                )
                thread.start()
        except KeyboardInterrupt:
            print("\n[AS] Encerrando servidor via interrupção do teclado.")
        finally:
            self._rodando = False
            if self._socket is not None:
                self._socket.close()
                self._socket = None

    def _recv_exato(self, con: socket.socket, tamanho: int) -> bytes | None:
        """Lê exatamente `tamanho` bytes do socket.

        Retorna None se a conexão for fechada antes de completar a leitura.
        """
        dados = b""
        while len(dados) < tamanho:
            chunk = con.recv(tamanho - len(dados))
            if not chunk:
                return None
            dados += chunk
        return dados

    def _enviar_erro(self, con: socket.socket) -> None:
        """Envia uma mensagem de erro e encerra a conexão com o cliente."""
        try:
            con.sendall(empacotar(MSG_ERROR, b""))
        except OSError:
            pass

    def _extrair_salt(self, usuario) -> bytes:
        """Extrai o salt (16 bytes) do registro do usuário.

        Aceita registros em formato dict ou objetos com atributo `salt`.
        Retorna um salt de 16 bytes ou bytes vazios quando indisponível.
        """
        salt = None
        if isinstance(usuario, dict):
            salt = (
                usuario.get("salt")
                or usuario.get("salt_hash")
                or usuario.get("password_salt")
                or usuario.get("senha_salt")
            )
        else:
            salt = getattr(usuario, "salt", None)

        if salt is None:
            return b""

        if isinstance(salt, str):
            try:
                salt = bytes.fromhex(salt)
            except ValueError:
                salt = salt.encode("utf-8")

        return salt

    def _extrair_chave_cliente(self, usuario) -> bytes:
        """Extrai a chave do cliente (K_c) a partir do registro do usuário.

        O hash armazenado serve como chave derivada da senha do cliente.
        """
        if isinstance(usuario, dict):
            hash_usuario = (
                usuario.get("hash_chave")
                or usuario.get("hash")
                or usuario.get("password_hash")
                or usuario.get("senha_hash")
                or b""
            )
        else:
            hash_usuario = getattr(usuario, "hash", None) or getattr(
                usuario, "password_hash", None
            ) or getattr(usuario, "senha_hash", None) or b""

        if isinstance(hash_usuario, str):
            try:
                return bytes.fromhex(hash_usuario)
            except ValueError:
                return hash_usuario.encode("utf-8")
        return hash_usuario

    def atender_cliente(self, con: socket.socket, addr) -> None:
        """Atende um cliente conectado implementando o fluxo de autenticação.

        Fluxo:
        1. Lê o cabeçalho de 6 bytes e extrai tipo/tamanho.
        2. Valida que a mensagem é MSG_AUTH_REQUEST.
        3. Lê o payload contendo o nome do usuário.
        4. Busca o usuário no UserDB.
        5. Recupera o salt e a chave do cliente (K_c).
        6. Gera a chave de sessão K_c_AS.
        7. Monta o TGT com criar_ticket.
        8. Cifra o TGT com a chave mestra do AS e K_c_AS com a chave do cliente.
        9. Envia MSG_AUTH_REPLY com salt, TGT cifrado e K_c_AS cifrada.
        """
        try:
            print(f"[AS] Conexão recebida de {addr}")

            # Cabeçalho fixo de 6 bytes: tipo + tamanho
            header = self._recv_exato(con, 6)
            if header is None:
                return

            tipo, tamanho = desempacotar(header)
            if tipo != MSG_AUTH_REQUEST:
                self._enviar_erro(con)
                return

            # Payload contendo o nome do usuário
            payload = self._recv_exato(con, tamanho)
            if payload is None:
                self._enviar_erro(con)
                return

            nome_usuario = payload.decode("utf-8", errors="replace").strip()

            if self.user_db is None:
                self._enviar_erro(con)
                return

            usuario = self.user_db.buscar(nome_usuario)
            if usuario is None:
                self._enviar_erro(con)
                return

            # Recupera o salt do usuário para que o cliente possa derivar K_c
            salt = self._extrair_salt(usuario)
            if len(salt) != SALT_TAMANHO:
                # Garante que o salt tenha exatamente 16 bytes no payload
                salt = salt[:SALT_TAMANHO].ljust(SALT_TAMANHO, b"\x00")

            # Recupera a chave do cliente (K_c) a partir do hash armazenado
            K_c = self._extrair_chave_cliente(usuario)
            if not K_c:
                self._enviar_erro(con)
                return

            # Chave de sessão cliente/AS
            K_c_AS = os.urandom(16)

            # Monta o TGT
            timestamp = int(time.time())
            validade = 3600
            ticket = criar_ticket(
                usuario=nome_usuario,
                servico="TGS",
                timestamp=timestamp,
                validade=validade,
                chave=K_c_AS,
            )

            # Cifra o TGT com a chave mestra do AS (issue #2)
            ticket_cifrado = cifrar_aes_gcm(self.chave_mestra, ticket)

            # Cifra a chave de sessão K_c_AS com a chave do cliente K_c (issue #2)
            K_c_AS_cifrada = cifrar_aes_gcm(K_c, K_c_AS)

            # Payload final da MSG_AUTH_REPLY:
            #   [salt (16 bytes)]
            #   + [tamanho_tgt (4 bytes)] + [TGT_cifrado]
            #   + [tamanho_k_c_as (4 bytes)] + [K_c_AS_cifrada]
            payload_resposta = (
                salt
                + struct.pack("!I", len(ticket_cifrado))
                + ticket_cifrado
                + struct.pack("!I", len(K_c_AS_cifrada))
                + K_c_AS_cifrada
            )

            con.sendall(empacotar(MSG_AUTH_REPLY, payload_resposta))

        except Exception as exc:
            print(f"[AS] Erro ao atender cliente {addr}: {exc}")
            self._enviar_erro(con)
        finally:
            try:
                con.close()
            except OSError:
                pass


def _carregar_chave_mestra() -> bytes:
    """Carrega a chave mestra do Authentication Server (AS).

    Returns:
        Chave mestra em bytes. Caso o arquivo não exista, retorna
        ``b""``.
    """
    if not os.path.exists(AS_MASTER_KEY_PATH):
        print(
            f"[AS] Aviso: arquivo de chave mestra não encontrado em "
            f"{AS_MASTER_KEY_PATH}"
        )
        return b""

    with open(AS_MASTER_KEY_PATH, "rb") as arquivo:
        return arquivo.read()

def main():
    """Ponto de entrada do Authentication Server."""
    banco_usuarios = UserDB(USER_DB_PATH)
    chave_mestra_as = _carregar_chave_mestra()
    servidor = ASServer(
        host=AS_HOST,
        porta=AS_PORT,
        user_db=banco_usuarios,
        chave_mestra=chave_mestra_as,
    )
    servidor.iniciar()


if __name__ == "__main__":
    main()