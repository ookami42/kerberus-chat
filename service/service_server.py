import socket
import threading
import struct
import time
import os

from common.config import SVC_HOST, SVC_PORT, JANELA_AUTH
from common.crypto import decifrar_aes_gcm, cifrar_aes_gcm
from common.protocol import (
    desempacotar, empacotar, extrair_ticket,
    MSG_SVC_REQUEST, MSG_SVC_REPLY, MSG_ERROR
)

class ServicoKerberos:
    """
    Servidor de Serviço (Grupo 4).
    Valida o Service Ticket e o Authenticator para estabelecer o canal seguro.
    """

    def __init__(self, host=SVC_HOST, porta=SVC_PORT):
        self.host = host
        self.porta = porta
        self.service_master_key = self._carregar_chave()
        self._socket = None
        self._rodando = False

    def _carregar_chave(self):
        """Carrega a chave mestra do serviço (Issue #21)."""
        caminho = "keys/service_master.key"
        if not os.path.exists(caminho):
            raise FileNotFoundError(f"Chave mestra do serviço não encontrada em {caminho}")
        with open(caminho, "rb") as f:
            return f.read()

    def iniciar(self):
        """Inicia o loop do servidor (Issue #21)."""
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.bind((self.host, self.porta))
        self._socket.listen(5)
        self._rodando = True
        print(f"[SERVIÇO] Escutando em {self.host}:{self.porta}")

        try:
            while self._rodando:
                con, addr = self._socket.accept()
                threading.Thread(target=self.atender_cliente, args=(con, addr), daemon=True).start()
        except KeyboardInterrupt:
            print("\n[SERVIÇO] Encerrando...")
        finally:
            if self._socket: self._socket.close()

    def _recv_exato(self, con, n):
        dados = b""
        while len(dados) < n:
            chunk = con.recv(n - len(dados))
            if not chunk: return None
            dados += chunk
        return dados

    def atender_cliente(self, con, addr):
        """Handler principal (Issues #22 a #25)."""
        try:
            # 1. Receber Requisição (Issue #22)
            header = self._recv_exato(con, 6)
            if not header: return
            tipo, tamanho = desempacotar(header)
            
            if tipo != MSG_SVC_REQUEST:
                raise ValueError("Tipo de mensagem incorreto.")

            payload = self._recv_exato(con, tamanho)
            
            # Extração: [4b tam_st][ST] + [4b tam_auth][Auth]
            offset = 0
            tam_st = struct.unpack(">I", payload[offset:offset+4])[0]
            st_cifrado = payload[offset+4 : offset+4+tam_st]
            
            offset += 4 + tam_st
            tam_auth = struct.unpack(">I", payload[offset:offset+4])[0]
            auth_cifrado = payload[offset+4 : offset+4+tam_auth]

            # 2. Validar Service Ticket (Issue #23)
            print(f"[SERVIÇO] Validando ticket de {addr}...")
            st_decifrado = decifrar_aes_gcm(self.service_master_key, st_cifrado)
            nome_tk, k_c_svc, ts_tk, life_tk = extrair_ticket(st_decifrado)
            
            # 3. Validar Authenticator (Issue #24)
            auth_decifrado = decifrar_aes_gcm(k_c_svc, auth_cifrado)
            
            # Formato Auth: [2b len_nome][nome][8b timestamp]
            len_n = struct.unpack(">H", auth_decifrado[:2])[0]
            nome_auth = auth_decifrado[2 : 2+len_n]
            ts_auth = struct.unpack(">Q", auth_decifrado[2+len_n : 2+len_n+8])[0]

            # Verificações de segurança
            if nome_auth != nome_tk:
                raise PermissionError("Usuário do Authenticator não condiz com o Ticket.")
            
            if abs(time.time() - ts_auth) > JANELA_AUTH:
                raise PermissionError("Timestamp fora da janela (possível Replay Attack).")

            # 4. Autenticação Mútua (Issue #25)
            print(f"[SERVIÇO] Autenticação mútua OK para {nome_tk.decode()}.")
            resp_cifrada = cifrar_aes_gcm(k_c_svc, struct.pack(">Q", ts_auth + 1))
            con.sendall(empacotar(MSG_SVC_REPLY, resp_cifrada))

            # Aqui entraríamos no loop de chat futuramente (#26)
            print(f"[SERVIÇO] Canal seguro estabelecido com {nome_tk.decode()}.")

        except Exception as e:
            print(f"[SERVIÇO] Erro: {e}")
            try: con.sendall(empacotar(MSG_ERROR, str(e).encode()))
            except: pass
        finally:
            con.close()

if __name__ == "__main__":
    svc = ServicoKerberos()
    svc.iniciar()