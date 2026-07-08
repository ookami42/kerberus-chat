"""Cliente Kerberos: orquestra o fluxo AS -> TGS -> Servico -> Chat.

Executa os 3 passos do protocolo e, apos autenticacao mutua,
abre um chat no terminal com o servico protegido.
"""

import getpass
import socket
import sys
import struct
import time
from common.config import AS_HOST, AS_PORT, TGS_HOST, TGS_PORT, SVC_HOST, SVC_PORT
from common.crypto import derivar_chave, decifrar_aes_gcm, cifrar_aes_gcm
from common.protocol import (
    empacotar, desempacotar,
    MSG_AUTH_REQUEST, MSG_AUTH_REPLY,
    MSG_TGS_REQUEST, MSG_TGS_REPLY,
    MSG_SVC_REQUEST, MSG_SVC_REPLY,
    MSG_ERROR
)

class ClienteKerberos:
    def __init__(self):
        self.usuario = None
        self.k_c_as = None      # Chave de sessão Cliente-TGS
        self.k_c_svc = None     # Chave de sessão Cliente-Serviço
        self.tgt_cifrado = None
        self.st_cifrado = None
        self.ts_original = 0
        self.socket = None

    # --- UTILITÁRIOS ---
    def _conectar(self, host, porta):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((host, porta))

    def _receber_msg(self):
        header = self.socket.recv(6)
        if not header: return None, None
        tipo, tamanho = desempacotar(header)
        payload = self.socket.recv(tamanho)
        return tipo, payload

    def fechar(self):
        if self.socket:
            self.socket.close()
            self.socket = None

    # --- PASSO 1: AS (Authentication Server) ---
    def executar_passo1(self):
        self.usuario = input("Usuário: ").strip()
        self._conectar(AS_HOST, AS_PORT)
        self.socket.sendall(empacotar(MSG_AUTH_REQUEST, self.usuario.encode()))
        
        tipo, payload = self._receber_msg()
        self.fechar()

        if tipo == MSG_ERROR: raise Exception(f"Erro no AS: {payload.decode()}")
        
        # Extração: Salt(16b) + TGT + K_c_AS
        salt = payload[:16]
        offset = 16
        tam_tgt = struct.unpack(">I", payload[offset:offset+4])[0]
        self.tgt_cifrado = payload[offset+4 : offset+4+tam_tgt]
        offset += 4 + tam_tgt
        tam_k = struct.unpack(">I", payload[offset:offset+4])[0]
        k_as_cifrada = payload[offset+4 : offset+4+tam_k]

        senha = getpass.getpass("Senha: ")
        k_c = derivar_chave(senha.encode(), salt)
        self.k_c_as = decifrar_aes_gcm(k_c, k_as_cifrada)
        print("[OK] Autenticado no AS.")

    # --- PASSO 2: TGS (Ticket Granting Server) ---
    def executar_passo2(self):
        self._conectar(TGS_HOST, TGS_PORT)
        # Payload: [4b tam_tgt][TGT] + [4b tam_svc][nome_svc]
        payload = struct.pack(">I", len(self.tgt_cifrado)) + self.tgt_cifrado + \
                  struct.pack(">I", 4) + b"chat"
        
        self.socket.sendall(empacotar(MSG_TGS_REQUEST, payload))
        tipo, payload = self._receber_msg()
        self.fechar()

        if tipo == MSG_ERROR: raise Exception(f"Erro no TGS: {payload.decode()}")

        offset = 0
        tam_st = struct.unpack(">I", payload[offset:offset+4])[0]
        self.st_cifrado = payload[offset+4 : offset+4+tam_st]
        offset += 4 + tam_st
        tam_ks = struct.unpack(">I", payload[offset:offset+4])[0]
        ks_cifrada = payload[offset+4 : offset+4+tam_ks]

        self.k_c_svc = decifrar_aes_gcm(self.k_c_as, ks_cifrada)
        print("[OK] Ticket de serviço obtido.")

    # --- PASSO 3: SERVIÇO (Autenticação Mútua) ---
    def executar_passo3(self):
        self._conectar(SVC_HOST, SVC_PORT)
        self.ts_original = int(time.time())
        
        # Authenticator: [2b len_nome][nome][8b timestamp]
        nome_b = self.usuario.encode()
        auth = struct.pack(">H", len(nome_b)) + nome_b + struct.pack(">Q", self.ts_original)
        auth_cifrado = cifrar_aes_gcm(self.k_c_svc, auth)

        payload = struct.pack(">I", len(self.st_cifrado)) + self.st_cifrado + \
                  struct.pack(">I", len(auth_cifrado)) + auth_cifrado
        
        self.socket.sendall(empacotar(MSG_SVC_REQUEST, payload))
        tipo, payload = self._receber_msg()

        if tipo == MSG_ERROR: raise Exception(f"Erro no Serviço: {payload.decode()}")

        resp_decifrada = decifrar_aes_gcm(self.k_c_svc, payload)
        ts_resp = struct.unpack(">Q", resp_decifrada)[0]
        
        if ts_resp == self.ts_original + 1:
            print("[OK] Autenticação mútua concluída. O servidor é confiável.")
            print("--- CONECTADO AO CHAT ---")
        else:
            self.fechar()
            raise Exception("Falha na autenticação mútua!")

    # --- ISSUE #32: Interface de Chat ---
    def loop_chat(self):
        """
        Loop de interação do usuário com o serviço de eco.
        """
        print("\nComandos: 'sair' para encerrar.")
        try:
            while True:
                mensagem = input("> ").strip()
                
                if not mensagem:
                    continue
                if mensagem.lower() == 'sair':
                    print("[CLIENTE] Encerrando chat...")
                    break

                # Envia a mensagem (Tipo 7)
                self.socket.sendall(empacotar(MSG_CHAT, mensagem.encode()))
                
                # Recebe o eco (Tipo 8)
                tipo, payload = self._receber_msg()
                
                if tipo == MSG_ECHO:
                    print(f"Servidor: {payload.decode()}")
                elif tipo == MSG_ERROR:
                    print(f"[ERRO] Servidor retornou: {payload.decode()}")
                    break
                else:
                    print(f"[AVISO] Tipo de mensagem inesperado: {tipo}")
        except KeyboardInterrupt:
            print("\n[CLIENTE] Chat interrompido.")
        finally:
            self.fechar()
            
def main():
    """Ponto de entrada do cliente Kerberos."""
    cliente = ClienteKerberos()
    try:
        cliente.executar_passo1()
        cliente.executar_passo2()
        cliente.executar_passo3()
        cliente.loop_chat()
    except Exception as e:
        print(f"\n[FALHA] Não foi possível completar o fluxo: {e}")
        cliente.fechar()


if __name__ == "__main__":
    main()