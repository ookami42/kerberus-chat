import os
import socket
import struct
import threading
import time

from cryptography.exceptions import InvalidTag

from common.config import (
    TGS_HOST,
    TGS_PORT,
    AS_MASTER_KEY_PATH,
    SVC_MASTER_KEY_PATH,
    LIFETIME_TICKET,
)
from common.crypto import decifrar_aes_gcm, cifrar_aes_gcm
from common.protocol import (
    empacotar,
    desempacotar,
    MSG_TGS_REQUEST,
    MSG_TGS_REPLY,
    MSG_ERROR,
    extrair_ticket,
    criar_ticket,
)

HEADER_FORMAT = ">HI"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
CHAVE_SESSAO_LENGTH = 16


class TGSServer:
    """
    Servidor TGS (Ticket Granting Server) do protocolo Kerberos.

    Responsavel por:
      - Receber MSG_TGS_REQUEST do cliente contendo o TGT cifrado e o
        nome do servico desejado.
      - Decifrar o TGT usando a chave as_master_key.
      - Validar a autenticidade e a expiracao do ticket.
      - Gerar um Service Ticket e uma chave de sessao K_c_svc.
      - Enviar MSG_TGS_REPLY com o Service Ticket cifrado e K_c_svc cifrada.
    """

    def __init__(self, host: str = TGS_HOST, port: int = TGS_PORT):
        self.host = host
        self.port = port
        self.socket: socket.socket | None = None
        self.running = False
        self.as_master_key: bytes = self._carregar_chave(
            AS_MASTER_KEY_PATH, "AS"
        )
        self.service_master_key: bytes = self._carregar_chave(
            SVC_MASTER_KEY_PATH, "servico"
        )

    # ------------------------------------------------------------------
    # Carregamento de chaves
    # ------------------------------------------------------------------

    @staticmethod
    def _carregar_chave(caminho: str, nome: str) -> bytes:
        """
        Carrega uma chave mestra de 16 bytes a partir de um arquivo.

        Args:
            caminho: Caminho do arquivo de chave.
            nome: Nome descritivo para mensagens de log.

        Returns:
            bytes: Chave de 16 bytes.

        Raises:
            FileNotFoundError: Se o arquivo nao existir.
            ValueError: Se o conteudo nao tiver exatamente 16 bytes.
        """
        if not os.path.exists(caminho):
            raise FileNotFoundError(
                f"Arquivo de chave nao encontrado: {caminho}"
            )
        with open(caminho, "rb") as arquivo:
            chave = arquivo.read()
        if len(chave) != 16:
            raise ValueError(
                f"Chave invalida ({nome}): esperado 16 bytes, "
                f"obtido {len(chave)} bytes"
            )
        print(f"[TGS] Chave mestra {nome} carregada de {caminho}")
        return chave

    # ------------------------------------------------------------------
    # Ciclo de vida do servidor
    # ------------------------------------------------------------------

    def iniciar(self) -> None:
        """Inicia o servidor TGS e aceita conexoes em loop usando threads."""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((self.host, self.port))
        self.socket.listen(5)
        self.running = True
        print(f"[TGS] Servidor TGS iniciado em {self.host}:{self.port}")

        try:
            while self.running:
                conn, addr = self.socket.accept()
                print(f"[TGS] Nova conexao de {addr}")
                thread = threading.Thread(
                    target=self.atender_cliente,
                    args=(conn, addr),
                    daemon=True,
                )
                thread.start()
        except KeyboardInterrupt:
            print("[TGS] Encerrando servidor (Ctrl+C)...")
        finally:
            self.fechar()

    def fechar(self) -> None:
        """Fecha o socket do servidor se estiver aberto."""
        self.running = False
        if self.socket is not None:
            try:
                self.socket.close()
            except OSError:
                pass
            finally:
                self.socket = None
        print("[TGS] Servidor encerrado.")

    # ------------------------------------------------------------------
    # Atendimento de cliente (Issues #17, #18, #19 e #20)
    # ------------------------------------------------------------------

    def atender_cliente(self, conn: socket.socket, addr) -> None:
        """
        Atende um cliente conectado ao TGS.

        Passos:
          1. Le o cabecalho de 6 bytes e desempacota tipo e tamanho.
          2. Valida se o tipo e MSG_TGS_REQUEST (Tipo 3).
          3. Le o payload completo.
          4. Extrai o TGT cifrado e o nome do servico do payload.
          5. Decifra o TGT usando as_master_key e decifrar_aes_gcm.
          6. Extrai os campos do ticket (nome, K_c_AS, timestamp, lifetime).
          7. Valida a expiracao do ticket.
          8. Gera a chave de sessao K_c_svc de 16 bytes.
          9. Monta o Service Ticket usando criar_ticket.
          10. Cifra o Service Ticket com a service_master_key.
          11. Cifra K_c_svc com a chave de sessao K_c_AS extraida do TGT.
          12. Monta e envia MSG_TGS_REPLY (Tipo 4) ao cliente.
        """
        print(f"[TGS] Atendendo cliente {addr}")
        try:
            # 1. Ler cabecalho de 6 bytes e desempacotar tipo e tamanho
            cabecalho = self._receber_exato(conn, HEADER_SIZE)
            if len(cabecalho) < HEADER_SIZE:
                print(f"[TGS] Cabecalho incompleto de {addr}")
                self._enviar_erro(conn, "Cabecalho incompleto")
                return

            tipo, tamanho = struct.unpack(HEADER_FORMAT, cabecalho)
            print(f"[TGS] Cabecalho recebido: tipo={tipo}, tamanho={tamanho}")

            # 2. Validar se o tipo e MSG_TGS_REQUEST (Tipo 3)
            if tipo != MSG_TGS_REQUEST:
                print(
                    f"[TGS] Tipo invalido: {tipo} "
                    f"(esperado MSG_TGS_REQUEST={MSG_TGS_REQUEST})"
                )
                self._enviar_erro(conn, "Tipo de mensagem invalido")
                return

            # 3. Ler o payload completo
            payload = self._receber_exato(conn, tamanho)
            if len(payload) < tamanho:
                print(f"[TGS] Payload incompleto de {addr}")
                self._enviar_erro(conn, "Payload incompleto")
                return

            print(f"[TGS] Payload recebido: {len(payload)} bytes")

            # 4. Extrair TGT cifrado e nome do servico do payload
            # Formato: [4 bytes tam_tgt][TGT] + [4 bytes tam_svc][nome_svc]
            try:
                tgt_cifrado, nome_svc = self._extrair_tgs_request(payload)
            except ValueError as exc:
                print(f"[TGS] Erro ao extrair TGS request: {exc}")
                self._enviar_erro(conn, "Formato de payload invalido")
                return

            print(f"[TGS] TGT cifrado: {len(tgt_cifrado)} bytes")
            print(
                f"[TGS] Servico solicitado: "
                f"{nome_svc.decode('utf-8', errors='replace')}"
            )

            # 5. Decifrar o TGT usando as_master_key e decifrar_aes_gcm
            try:
                tgt_decifrado = decifrar_aes_gcm(
                    self.as_master_key, tgt_cifrado
                )
                print("[TGS] TGT decifrado com sucesso usando as_master_key")
            except InvalidTag:
                print("[TGS] Falha ao decifrar TGT: InvalidTag (chave errada)")
                self._enviar_erro(conn, "TGT invalido")
                return

            # 6. Extrair os campos do ticket usando extrair_ticket
            try:
                nome, k_c_as, timestamp, lifetime = extrair_ticket(tgt_decifrado)
                nome_str = nome.decode("utf-8", errors="replace")
                print(f"[TGS] Ticket extraido: usuario={nome_str}")
                print(f"[TGS] K_c_AS: {k_c_as.hex()}")
                print(f"[TGS] Timestamp: {timestamp}, Lifetime: {lifetime} min")
            except Exception as exc:
                print(f"[TGS] Falha ao extrair ticket: {exc}")
                self._enviar_erro(conn, "Ticket invalido")
                return

            # 7. Validar a expiracao do ticket
            tempo_atual = int(time.time())
            if (timestamp + lifetime * 60) <= tempo_atual:
                print(
                    f"[TGS] Ticket expirado para o usuario {nome_str} "
                    f"(expirou em {timestamp + lifetime * 60})"
                )
                self._enviar_erro(conn, "Ticket expirado")
                return

            print(f"[TGS] TGT validado para o usuario {nome_str}")

            # ------------------------------------------------------------------
            # Issue #19: Gerar K_c_svc e o Service Ticket
            # ------------------------------------------------------------------

            # 8. Gerar nova chave de sessao K_c_svc de 16 bytes
            k_c_svc = os.urandom(CHAVE_SESSAO_LENGTH)
            print(f"[TGS] K_c_svc gerada: {k_c_svc.hex()}")

            # 9. Montar o Service Ticket usando criar_ticket
            service_ticket = criar_ticket(
                nome, k_c_svc, tempo_atual, LIFETIME_TICKET
            )
            print(
                f"[TGS] Service Ticket montado para o usuario {nome_str} "
                f"(lifetime={LIFETIME_TICKET} min)"
            )

            # ------------------------------------------------------------------
            # Issue #20: Cifrar e montar MSG_TGS_REPLY
            # ------------------------------------------------------------------

            # 10. Cifrar o Service Ticket com a service_master_key
            try:
                service_ticket_cifrado = cifrar_aes_gcm(
                    self.service_master_key, service_ticket
                )
                print(
                    f"[TGS] Service Ticket cifrado com service_master_key "
                    f"({len(service_ticket_cifrado)} bytes)"
                )
            except Exception as exc:
                print(f"[TGS] Falha ao cifrar Service Ticket: {exc}")
                self._enviar_erro(conn, "Falha ao cifrar Service Ticket")
                return

            # 11. Cifrar K_c_svc com a chave de sessao K_c_AS (extraida do TGT)
            try:
                k_c_svc_cifrado = cifrar_aes_gcm(k_c_as, k_c_svc)
                print(
                    f"[TGS] K_c_svc cifrada com K_c_AS "
                    f"({len(k_c_svc_cifrado)} bytes)"
                )
            except Exception as exc:
                print(f"[TGS] Falha ao cifrar K_c_svc: {exc}")
                self._enviar_erro(conn, "Falha ao cifrar K_c_svc")
                return

            # 12. Montar o payload da MSG_TGS_REPLY
            # Formato: [4 bytes tam_ticket][Service_Ticket_cifrado]
            #        + [4 bytes tam_k_c_svc][K_c_svc_cifrada]
            reply_payload = self._montar_tgs_reply(
                service_ticket_cifrado, k_c_svc_cifrado
            )
            print(
                f"[TGS] Payload MSG_TGS_REPLY montado: "
                f"{len(reply_payload)} bytes"
            )

            # Enviar MSG_TGS_REPLY (Tipo 4) ao cliente
            mensagem = empacotar(MSG_TGS_REPLY, reply_payload)
            conn.sendall(mensagem)
            print(
                f"[TGS] MSG_TGS_REPLY (Tipo {MSG_TGS_REPLY}) enviada para "
                f"o usuario {nome_str}"
            )

        except Exception as exc:
            print(f"[TGS] Erro ao atender cliente {addr}: {exc}")
            try:
                self._enviar_erro(conn, "Erro interno do servidor")
            except Exception:
                pass
        finally:
            try:
                conn.close()
            except OSError:
                pass
            print(f"[TGS] Conexao encerrada com {addr}")

    # ------------------------------------------------------------------
    # Metodos auxiliares de protocolo
    # ------------------------------------------------------------------

    def _extrair_tgs_request(self, payload: bytes) -> tuple[bytes, bytes]:
        """
        Extrai do payload da MSG_TGS_REQUEST:
          - TGT cifrado: [4 bytes tam_tgt][TGT]
          - Nome do servico: [4 bytes tam_svc][nome_svc]
        """
        offset = 0

        tgt_cifrado = self._extrair_blob_com_tamanho(payload, offset)
        offset += 4 + len(tgt_cifrado)

        nome_svc = self._extrair_blob_com_tamanho(payload, offset)

        return tgt_cifrado, nome_svc

    @staticmethod
    def _extrair_blob_com_tamanho(payload: bytes, offset: int) -> bytes:
        """Extrai um blob precedido por um inteiro de 4 bytes (big-endian)."""
        if offset + 4 > len(payload):
            raise ValueError(
                f"Payload insuficiente para ler tamanho do blob em offset {offset}"
            )
        tamanho = int.from_bytes(
            payload[offset : offset + 4], byteorder="big", signed=False
        )
        inicio = offset + 4
        fim = inicio + tamanho
        if fim > len(payload):
            raise ValueError(
                f"Payload insuficiente para ler blob de {tamanho} bytes "
                f"em offset {inicio}"
            )
        return payload[inicio:fim]

    @staticmethod
    def _montar_tgs_reply(
        service_ticket_cifrado: bytes, k_c_svc_cifrado: bytes
    ) -> bytes:
        """
        Monta o payload da MSG_TGS_REPLY:
          - [4 bytes tam_ticket_servico][Service_Ticket_cifrado]
          - [4 bytes tam_k_c_svc][K_c_svc_cifrada]
        """
        st_len = len(service_ticket_cifrado).to_bytes(
            4, byteorder="big", signed=False
        )
        k_len = len(k_c_svc_cifrado).to_bytes(
            4, byteorder="big", signed=False
        )
        return st_len + service_ticket_cifrado + k_len + k_c_svc_cifrado

    def _enviar_erro(self, conn: socket.socket, mensagem: str) -> None:
        """Envia uma mensagem de erro (MSG_ERROR) ao cliente."""
        try:
            payload = mensagem.encode("utf-8")
            msg = empacotar(MSG_ERROR, payload)
            conn.sendall(msg)
            print(f"[TGS] MSG_ERROR enviada: {mensagem}")
        except OSError:
            pass

    @staticmethod
    def _receber_exato(conn: socket.socket, n: int) -> bytes:
        """Le exatamente n bytes do socket, bloqueando ate completar."""
        partes: list[bytes] = []
        recebido = 0
        while recebido < n:
            chunk = conn.recv(n - recebido)
            if not chunk:
                break
            partes.append(chunk)
            recebido += len(chunk)
        return b"".join(partes)


def main() -> None:
    """Ponto de entrada do servidor TGS."""
    servidor = TGSServer()
    try:
        servidor.iniciar()
    except Exception as exc:
        print(f"[TGS] Erro fatal: {exc}")
    finally:
        servidor.fechar()


if __name__ == "__main__":
    main()