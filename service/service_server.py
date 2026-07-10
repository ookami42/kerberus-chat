"""Servico de Notas Protegido: valida Service Ticket, autenticacao mutua e
gerencia notas por usuario.

Recebe requisicoes do cliente (MSG_SVC_REQUEST), valida o Service Ticket
e o authenticator, realiza autenticacao mutua (timestamp+1) e entao
processa comandos de notas (listar, ler, escrever).

Cada usuario so acessa o proprio diretorio de notas (/notas/<nome>/).
A identidade vem do Service Ticket validado pelo Kerberos.
"""

import os
import socket
import struct
import threading
import time

from cryptography.exceptions import InvalidTag

from common.config import SVC_HOST, SVC_PORT, SVC_MASTER_KEY_PATH, JANELA_AUTH, NOTAS_RAIZ_PATH
from common.crypto import decifrar_aes_gcm, cifrar_aes_gcm
from common.protocol import (
    empacotar, extrair_ticket,
    MSG_SVC_REQUEST, MSG_SVC_REPLY, MSG_ERROR,
    MSG_NOTE_LIST, MSG_NOTE_READ, MSG_NOTE_WRITE, MSG_NOTE_REPLY,
    MSG_NOTE_DELETE,
)


class ServicoKerberos:
    """Servidor de Notas: valida ticket Kerberos e gerencia notas por usuario.

    Cada conexao recebe um Service Ticket + Authenticator, realiza a
    autenticacao mutua e entao processa um unico comando de notas.
    O diretorio de notas e resolvido a partir da identidade do ticket,
    garantindo isolamento entre usuarios.
    """

    def __init__(self, host=SVC_HOST, porta=SVC_PORT):
        self.host = host
        self.porta = porta
        self.service_master_key = self._carregar_chave()
        self._notas_raiz = NOTAS_RAIZ_PATH
        self._socket = None
        self._rodando = False

    def _carregar_chave(self):
        """Carrega a chave mestra do servico.

        Returns:
            bytes: Chave de 16 bytes.

        Raises:
            FileNotFoundError: Se o arquivo de chave nao existir.
        """
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

        Args:
            con: Socket conectado.
            n: Numero de bytes a ler.

        Returns:
            bytes | None: Bytes lidos ou None se a conexao for fechada.
        """
        dados = b""
        while len(dados) < n:
            chunk = con.recv(n - len(dados))
            if not chunk:
                return None
            dados += chunk
        return dados

    # ------------------------------------------------------------------
    # Handler de conexao (autenticacao Kerberos + comando de notas)
    # ------------------------------------------------------------------

    def atender_cliente(self, con, addr):
        """Autentica o cliente via Kerberos e processa um comando de notas.

        Fluxo:
          1. Recebe MSG_SVC_REQUEST (Service Ticket + Authenticator)
          2. Valida o ticket e o authenticator
          3. Autenticacao mutua (timestamp + 1)
          4. Processa um comando de notas (LIST/READ/WRITE)
          5. Envia resposta e fecha conexao
        """
        try:
            # 1. Receber MSG_SVC_REQUEST
            header = self._recv_exato(con, 6)
            if not header:
                return

            tipo, tamanho = struct.unpack(">HI", header)
            if tipo != MSG_SVC_REQUEST:
                raise ValueError("Tipo de mensagem incorreto.")

            payload = self._recv_exato(con, tamanho)

            if payload is None:
                con.sendall(
                    empacotar(
                        MSG_ERROR,
                        b"Payload invalido",
                    )
                )
                return
            
            # Extracao: [4b tam_st][ST] + [4b tam_auth][Auth]
            offset = 0

            if len(payload) < offset + 4:
                raise ValueError("Payload incompleto")

            tam_st = struct.unpack(">I", payload[offset:offset+4])[0]

            if len(payload) < offset + 4 + tam_st:
                raise ValueError("Service ticket incompleto")

            st_cifrado = payload[offset+4 : offset+4+tam_st]
            
            offset += 4 + tam_st

            if len(payload) < offset + 4:
                raise ValueError("Payload incompleto")

            tam_auth = struct.unpack(">I", payload[offset:offset+4])[0]

            if len(payload) < offset + 4 + tam_auth:
                raise ValueError("Authenticator incompleto")
            
            auth_cifrado = payload[offset+4 : offset+4+tam_auth]

            # 2. Validar Service Ticket
            print(f"[SERVIÇO] Validando ticket de {addr}...")
            st_decifrado = decifrar_aes_gcm(self.service_master_key, st_cifrado)
            nome_tk, k_c_svc, ts_tk, life_tk = extrair_ticket(st_decifrado) 
            agora = int(time.time())

            if agora > ts_tk + life_tk * 60:
                print(f"[SERVIÇO] Service Ticket expirado de {addr}")

                con.sendall(
                    empacotar(
                        MSG_ERROR,
                        b"Service Ticket expirado",
                    )
                )
                return

            # 3. Validar Authenticator
            auth_decifrado = decifrar_aes_gcm(k_c_svc, auth_cifrado)

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

            # 5. Processar comando de notas
            self._processar_comando(con, nome_str)

        except InvalidTag:
            print(f"[SERVICO] Falha de autenticacao ({addr}): InvalidTag")
            try:
                con.sendall(empacotar(MSG_ERROR, b"Ticket ou authenticator invalido"))
            except OSError:
                pass
        except Exception as e:
            print(f"[SERVICO] Erro ({addr}): {e}")
            try:
                con.sendall(empacotar(MSG_ERROR, str(e).encode()))
            except OSError:
                pass
        finally:
            try:
                con.close()
            except OSError:
                pass

    # ------------------------------------------------------------------
    # Servico de notas: comandos LIST, READ, WRITE
    # ------------------------------------------------------------------

    def _processar_comando(self, con, nome_usuario):
        """Le um comando do cliente e executa a operacao correspondente.

        O nome_usuario ja foi validado pelo ticket Kerberos. O diretorio
        de notas e resolvido a partir dessa identidade, garantindo que
        Alice nunca acesse as notas do Bob.

        Args:
            con: Socket do cliente.
            nome_usuario: Nome extraido do Service Ticket (str).
        """
        header = self._recv_exato(con, 6)
        if not header:
            return

        tipo, tamanho = struct.unpack(">HI", header)
        payload = self._recv_exato(con, tamanho) if tamanho > 0 else b""

        if tipo == MSG_NOTE_LIST:
            resposta = self._listar(nome_usuario)

        elif tipo == MSG_NOTE_READ:
            resposta, erro = self._ler(nome_usuario, payload)
            if erro:
                con.sendall(empacotar(MSG_ERROR, erro.encode()))
                return

        elif tipo == MSG_NOTE_WRITE:
            resposta, erro = self._escrever(nome_usuario, payload)
            if erro:
                con.sendall(empacotar(MSG_ERROR, erro.encode()))
                return

        elif tipo == MSG_NOTE_DELETE:
            resposta, erro = self._deletar(nome_usuario, payload)
            if erro:
                con.sendall(empacotar(MSG_ERROR, erro.encode()))
                return

        else:
            con.sendall(empacotar(MSG_ERROR, b"Comando desconhecido."))
            return

        con.sendall(empacotar(MSG_NOTE_REPLY, resposta.encode()))

    def _listar(self, nome_usuario):
        """Lista os arquivos do diretorio de notas do usuario.

        Args:
            nome_usuario: Nome do usuario (str).

        Returns:
            str: Nomes dos arquivos separados por quebra de linha,
                 ou "(vazio)" se nao houver notas.
        """
        dir_usuario = self._caminho_usuario(nome_usuario)
        if not os.path.isdir(dir_usuario):
            return "(vazio)"

        arquivos = os.listdir(dir_usuario)
        if not arquivos:
            return "(vazio)"

        return "\n".join(sorted(arquivos))

    def _ler(self, nome_usuario, payload):
        """Le o conteudo de uma nota.

        Args:
            nome_usuario: Nome do dono da nota (str).
            payload: Bytes com o nome do arquivo.

        Returns:
            tuple[str, str | None]: (conteudo, None) em caso de sucesso,
                                    ou ("", mensagem_de_erro) em caso de falha.
        """
        nome_arquivo = payload.decode(errors="replace").strip()
        nome_seguro = os.path.basename(nome_arquivo)

        if not nome_seguro:
            return "", "Nome de arquivo invalido."

        caminho = self._caminho_nota(nome_usuario, nome_seguro)

        try:
            with open(caminho, "r") as f:
                return f.read(), None
        except FileNotFoundError:
            return "", "Nota nao encontrada."

    def _escrever(self, nome_usuario, payload):
        """Cria ou sobrescreve uma nota.

        O payload contem o nome do arquivo na primeira linha e o
        conteudo nas linhas seguintes.

        Args:
            nome_usuario: Nome do dono da nota (str).
            payload: Bytes no formato "nome_arquivo\\n<conteudo>".

        Returns:
            tuple[str, str | None]: ("OK: nota salva.", None) em caso de
                                    sucesso, ou ("", mensagem_de_erro).
        """
        texto = payload.decode(errors="replace")
        partes = texto.split("\n", 1)

        nome_arquivo = partes[0].strip()
        conteudo = partes[1] if len(partes) > 1 else ""

        nome_seguro = os.path.basename(nome_arquivo)

        if not nome_seguro:
            return "", "Nome de arquivo invalido."

        caminho = self._caminho_nota(nome_usuario, nome_seguro)
        os.makedirs(os.path.dirname(caminho), exist_ok=True)

        with open(caminho, "w") as f:
            f.write(conteudo)

        return "OK: nota salva.", None

    def _deletar(self, nome_usuario, payload):
        """Deleta uma nota existente.

        Args:
            nome_usuario: Nome do dono da nota (str).
            payload: Bytes com o nome do arquivo.

        Returns:
            tuple[str, str | None]: ("OK: nota deletada.", None) em caso de
                                    sucesso, ou ("", mensagem_de_erro).
        """
        nome_arquivo = payload.decode(errors="replace").strip()
        nome_seguro = os.path.basename(nome_arquivo)

        if not nome_seguro:
            return "", "Nome de arquivo invalido."

        caminho = self._caminho_nota(nome_usuario, nome_seguro)

        try:
            os.remove(caminho)
            return "OK: nota deletada.", None
        except FileNotFoundError:
            return "", "Nota nao encontrada."

    def _caminho_usuario(self, nome):
        """Retorna o diretorio de notas do usuario.

        Args:
            nome: Nome do usuario (str).

        Returns:
            str: Caminho absoluto para o diretorio de notas do usuario.
        """
        return os.path.join(self._notas_raiz, nome)

    def _caminho_nota(self, nome_usuario, nome_arquivo):
        """Retorna o caminho completo de uma nota.

        Usa os.path.basename() para prevenir path traversal
        (ex: "../../etc/passwd" vira so "passwd").

        Args:
            nome_usuario: Nome do dono (str).
            nome_arquivo: Nome do arquivo, ja sanitizado (str).

        Returns:
            str: Caminho absoluto do arquivo da nota.
        """
        return os.path.join(self._caminho_usuario(nome_usuario), nome_arquivo)


def main():
    """Ponto de entrada do servidor de notas."""
    svc = ServicoKerberos()
    svc.iniciar()


if __name__ == "__main__":
    main()
