"""Servico Protegido: valida Service Ticket, autenticacao mutua e relay.

Recebe requisicoes do cliente (MSG_SVC_REQUEST), valida o Service Ticket
e o authenticator, realiza autenticacao mutua (timestamp+1) e encaminha
mensagens de chat entre usuarios conectados (relay).

Cada cliente, apos autenticado, envia mensagens no formato:
  "destinatario texto da mensagem"
O servico extrai o destinatario (primeira palavra) e encaminha ao socket
correspondente.
"""

import os
import socket
import struct
import threading
import time

from common.config import SVC_HOST, SVC_PORT, SVC_MASTER_KEY_PATH, JANELA_AUTH
from common.crypto import decifrar_aes_gcm, cifrar_aes_gcm
from common.protocol import (
    empacotar, extrair_ticket,
    MSG_SVC_REQUEST, MSG_SVC_REPLY, MSG_CHAT, MSG_RELAY, MSG_ERROR,
)


class ServicoKerberos:
    """Servidor de Servico: relay de mensagens entre clientes Kerberos.

    Mantem um dicionario de clientes conectados (nome -> socket) e
    encaminha mensagens entre eles. Cada mensagem do cliente carrega
    o nome do destinatario como primeira palavra.
    """

    def __init__(self, host=SVC_HOST, porta=SVC_PORT):
        self.host = host
        self.porta = porta
        self.service_master_key = self._carregar_chave()
        self._socket = None
        self._rodando = False

        # Tabela de clientes conectados: {nome_usuario: socket}
        self._clientes: dict[str, socket.socket] = {}
        self._lock = threading.Lock()

    def _carregar_chave(self):
        """Carrega a chave mestra do servico."""
        caminho = SVC_MASTER_KEY_PATH
        if not os.path.exists(caminho):
            raise FileNotFoundError(
                f"Chave mestra do servico nao encontrada em {caminho}"
            )
        with open(caminho, "rb") as f:
            return f.read()

    def iniciar(self):
        """Inicia o loop do servidor, aceitando conexoes em threads."""
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.bind((self.host, self.porta))
        self._socket.listen(5)
        self._rodando = True
        print(f"[SERVICO] Escutando em {self.host}:{self.porta}")

        try:
            while self._rodando:
                con, addr = self._socket.accept()
                threading.Thread(
                    target=self.atender_cliente,
                    args=(con, addr),
                    daemon=True,
                ).start()
        except KeyboardInterrupt:
            print("\n[SERVICO] Encerrando...")
        finally:
            if self._socket:
                self._socket.close()

    def _recv_exato(self, con, n):
        """Le exatamente n bytes do socket.

        Retorna None se a conexao for fechada antes de completar.
        """
        dados = b""
        while len(dados) < n:
            chunk = con.recv(n - len(dados))
            if not chunk:
                return None
            dados += chunk
        return dados

    # ------------------------------------------------------------------
    # Relay: encaminhamento de mensagens entre clientes
    # ------------------------------------------------------------------

    def _loop_relay(self, con, nome_usuario):
        """Loop de relay: recebe mensagens e encaminha ao destinatario.

        Formato da mensagem do cliente (MSG_CHAT):
          "destinatario texto livre ate o fim"

        O servico extrai o destinatario (tudo antes do primeiro espaco)
        e encaminha o restante como MSG_RELAY para o socket do destino.

        Formato do MSG_RELAY enviado ao destinatario:
          [2 bytes len_remetente][remetente][texto da mensagem]

        Args:
            con: Socket do cliente remetente.
            nome_usuario: Nome do cliente remetente (bytes).
        """
        nome_str = nome_usuario.decode()
        print(f"[SERVICO] {nome_str} entrou no chat.")

        while True:
            # Le cabecalho: 2B tipo + 4B tamanho
            header = self._recv_exato(con, 6)
            if not header:
                break

            tipo, tamanho = struct.unpack(">HI", header)

            # Le o payload
            payload = self._recv_exato(con, tamanho)
            if not payload:
                break

            if tipo == MSG_CHAT:
                texto = payload.decode("utf-8", errors="replace")

                # Extrai destinatario (primeira palavra antes do espaco)
                partes = texto.split(" ", 1)
                if len(partes) < 2:
                    # Sem destinatario — ignora
                    continue

                destinatario = partes[0]
                mensagem = partes[1]

                print(f"[SERVICO] {nome_str} -> {destinatario}: {mensagem}")

                # Busca o socket do destinatario
                with self._lock:
                    dest_con = self._clientes.get(destinatario)

                if dest_con:
                    # Monta MSG_RELAY: [2B len_remet][remet][mensagem]
                    rem_bytes = nome_usuario
                    fwd = (
                        struct.pack(">H", len(rem_bytes))
                        + rem_bytes
                        + mensagem.encode("utf-8")
                    )
                    try:
                        dest_con.sendall(empacotar(MSG_RELAY, fwd))
                    except OSError:
                        print(
                            f"[SERVICO] Falha ao enviar para {destinatario}"
                        )
                else:
                    print(
                        f"[SERVICO] Destinatario '{destinatario}' "
                        f"nao encontrado."
                    )
            else:
                # Tipo inesperado — encerra
                break

    # ------------------------------------------------------------------
    # Handler de conexao (autenticacao Kerberos + relay)
    # ------------------------------------------------------------------

    def atender_cliente(self, con, addr):
        """Autentica o cliente via Kerberos e entra no loop de relay.

        Fluxo:
          1. Recebe MSG_SVC_REQUEST (Service Ticket + Authenticator)
          2. Valida o ticket e o authenticator
          3. Autenticacao mutua (timestamp + 1)
          4. Registra o cliente na tabela de conectados
          5. Entra no loop de relay
          6. Remove o cliente ao desconectar
        """
        nome_str = None
        try:
            # 1. Receber MSG_SVC_REQUEST
            header = self._recv_exato(con, 6)
            if not header:
                return

            tipo, tamanho = struct.unpack(">HI", header)
            if tipo != MSG_SVC_REQUEST:
                raise ValueError("Tipo de mensagem incorreto.")

            payload = self._recv_exato(con, tamanho)
            if not payload:
                return

            # Extrai: [4B tam_st][ST] + [4B tam_auth][Auth]
            offset = 0
            tam_st = struct.unpack(">I", payload[offset:offset + 4])[0]
            st_cifrado = payload[offset + 4:offset + 4 + tam_st]

            offset += 4 + tam_st
            tam_auth = struct.unpack(">I", payload[offset:offset + 4])[0]
            auth_cifrado = payload[offset + 4:offset + 4 + tam_auth]

            # 2. Validar Service Ticket
            print(f"[SERVICO] Validando ticket de {addr}...")
            st_decifrado = decifrar_aes_gcm(
                self.service_master_key, st_cifrado
            )
            nome_tk, k_c_svc, ts_tk, life_tk = extrair_ticket(st_decifrado)

            # 3. Validar Authenticator
            auth_decifrado = decifrar_aes_gcm(k_c_svc, auth_cifrado)

            # Formato Auth: [2B len_nome][nome][8B timestamp]
            len_n = struct.unpack(">H", auth_decifrado[:2])[0]
            nome_auth = auth_decifrado[2:2 + len_n]
            ts_auth = struct.unpack(
                ">Q", auth_decifrado[2 + len_n:2 + len_n + 8]
            )[0]

            if nome_auth != nome_tk:
                raise PermissionError(
                    "Usuario do Authenticator nao condiz com o Ticket."
                )

            if abs(time.time() - ts_auth) > JANELA_AUTH:
                raise PermissionError(
                    "Timestamp fora da janela (possivel Replay Attack)."
                )

            # 4. Autenticacao Mutua
            nome_str = nome_tk.decode()
            print(f"[SERVICO] Autenticacao mutua OK para {nome_str}.")
            resp_cifrada = cifrar_aes_gcm(
                k_c_svc, struct.pack(">Q", ts_auth + 1)
            )
            con.sendall(empacotar(MSG_SVC_REPLY, resp_cifrada))

            # 5. Registrar cliente na tabela de conectados
            with self._lock:
                self._clientes[nome_str] = con
            print(f"[SERVICO] {nome_str} registrado. "
                  f"Conectados: {list(self._clientes.keys())}")

            # 6. Loop de relay
            self._loop_relay(con, nome_tk)

        except Exception as e:
            print(f"[SERVICO] Erro ({addr}): {e}")
            try:
                con.sendall(empacotar(MSG_ERROR, str(e).encode()))
            except OSError:
                pass
        finally:
            # Remove o cliente da tabela ao desconectar
            if nome_str:
                with self._lock:
                    self._clientes.pop(nome_str, None)
                print(f"[SERVICO] {nome_str} desconectado. "
                      f"Conectados: {list(self._clientes.keys())}")
            try:
                con.close()
            except OSError:
                pass


def main():
    """Ponto de entrada do servidor de servico (relay)."""
    svc = ServicoKerberos()
    svc.iniciar()


if __name__ == "__main__":
    main()
