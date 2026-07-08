import os
import time
import socket
import threading
from cryptography.exceptions import InvalidTag
from common.config import LIFETIME_TICKET
from common.crypto import cifrar_aes_gcm
from common.crypto import decifrar_aes_gcm
from .message import (
    criar_ticket,
    extrair_ticket,
    desempacotar,
    empacotar,
    MSG_TGS_REQUEST,
    MSG_TGS_REPLY,
    MSG_ERROR,
)

class TGSServer:
    """Servidor do Ticket Granting Server (TGS).

    O TGS recebe requisições contendo um Ticket Granting Ticket (TGT),
    valida sua autenticidade e validade, gera uma nova chave de sessão
    Cliente↔Serviço, cria um Service Ticket cifrado com a chave do
    serviço e envia uma resposta ao cliente.

    Attributes:
        host: Endereço IP onde o servidor escuta conexões.
        porta: Porta TCP utilizada pelo servidor.
        chave_as: Chave mestra compartilhada com o Authentication Server
            (AS), utilizada para decifrar TGTs.
        chave_servico: Chave mestra do serviço protegido, utilizada para
            cifrar Service Tickets.
    """
    def __init__(self, host, porta, chave_as, chave_servico): 
        """Inicia o servidor TCP do TGS.

        Cria o socket de escuta, associa-o ao endereço configurado e aceita
        conexões de clientes continuamente. Cada conexão é tratada em uma
        thread independente.
        """      
        self.host = host
        self.porta = porta
        self.chave_as = chave_as
        self.chave_servico = chave_servico

    def iniciar(self):
        """Inicia o servidor TCP do TGS.

        Cria o socket de escuta, associa-o ao endereço configurado e aceita
        conexões de clientes continuamente. Cada conexão é tratada em uma
        thread independente.
        """   
        servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        servidor.bind((self.host, self.porta))
        servidor.listen()

        print(f"TGS escutando em {self.host}:{self.porta}")

        while True:
            con, addr = servidor.accept()

            thread = threading.Thread(
                target=self.atender_cliente,
                args=(con, addr),
                daemon=True,
            )
            thread.start()

    def atender_cliente(self, con, addr):
        """Processa uma requisição recebida de um cliente.

        O método executa o fluxo do protocolo Kerberos no TGS:

        1. Recebe a mensagem da rede.
        2. Valida o tipo da mensagem.
        3. Extrai o TGT e o nome do serviço solicitado.
        4. Decifra e valida o TGT.
        5. Gera um Service Ticket e uma nova chave de sessão Cliente↔Serviço.
        6. Monta e envia uma resposta do tipo ``MSG_TGS_REPLY``.

        Caso qualquer etapa falhe, uma mensagem ``MSG_ERROR`` é enviada ao
        cliente.

        Args:
            con: Socket da conexão estabelecida com o cliente.
            addr: Endereço do cliente conectado.
        """
        try:
            # 1. Recebe a mensagem
            dados = con.recv(4096)

            if not dados:
                return

            # 2. Desempacota cabeçalho + payload
            tipo, payload = desempacotar(dados)

            # 3. Verifica o tipo
            if tipo != MSG_TGS_REQUEST:
                con.sendall(
                    empacotar(MSG_ERROR, b"Tipo de mensagem invalido")
                )
                return

            # 4. Payload mínimo: tamanho do TGT
            if len(payload) < 2:
                con.sendall(
                    empacotar(MSG_ERROR, b"Payload invalido")
                )
                return

            # 5. Extrai TGT e nome do serviço
            tam_tgt = int.from_bytes(payload[:2], "big")

            if len(payload) < 2 + tam_tgt:
                con.sendall(
                    empacotar(MSG_ERROR, b"TGT incompleto")
                )
                return

            tgt_cif = payload[2:2 + tam_tgt]
            nome_servico = payload[2 + tam_tgt:].decode("utf-8")

            if not nome_servico:
                con.sendall(
                    empacotar(MSG_ERROR, b"Servico invalido")
                )
                return

            # 6. Decifra o TGT
            try:
                nome_usuario, chave_cliente_tgs = self._validar_tgt(tgt_cif)

                service_ticket_cifrado, chave_cliente_servico = (
                    self._gerar_service_ticket(nome_usuario)
                )
                
                resposta = self._montar_resposta_tgs(
                    service_ticket_cifrado,
                    chave_cliente_servico,
                    chave_cliente_tgs,
                )
                
                con.sendall(resposta)

                print(f"[TGS] Service Ticket gerado ({len(service_ticket_cifrado)} bytes)")
            except ValueError as e:
                con.sendall(
                    empacotar(MSG_ERROR, str(e).encode())
                )
                return

            print(f"[TGS] Cliente: {addr}")
            print(f"[TGS] Usuario: {nome_usuario.decode()}")
            print(f"[TGS] Servico: {nome_servico}")
            print("[TGS] TGT valido")

        except Exception as e:
            print(f"Erro ao atender {addr}: {e}")

            try:
                con.sendall(
                    empacotar(MSG_ERROR, b"Erro interno")
                )
            except Exception:
                pass

        finally:
            con.close()
    
    def _validar_tgt(self, tgt_cif: bytes):
        """Decifra e valida um Ticket Granting Ticket (TGT).

        O ticket é decifrado utilizando a chave mestra compartilhada com o
        Authentication Server (AS). Após a decifragem, são extraídos os
        campos do ticket e verificada sua validade temporal.

        Args:
            tgt_cif: TGT cifrado (nonce + ciphertext AES-GCM).

        Returns:
            tuple[bytes, bytes]:
                Tupla contendo o nome do usuário e a chave de sessão
                Cliente↔TGS.

        Raises:
            ValueError: Se o ticket for inválido, corrompido ou expirado.
        """
        try:
            ticket = decifrar_aes_gcm(self.chave_as, tgt_cif)
        except InvalidTag as exc:
            raise ValueError("TGT invalido") from exc

        try:
            nome_usuario, chave_sessao, timestamp, lifetime = extrair_ticket(ticket)
        except Exception as exc:
            raise ValueError("Ticket invalido") from exc

        agora = int(time.time())

        if agora > timestamp + lifetime * 60:
            raise ValueError("TGT expirado")

        return nome_usuario, chave_sessao
    
    def _gerar_service_ticket(self, nome_usuario: bytes):
        """Gera um Service Ticket para o serviço solicitado.

        Cria uma nova chave de sessão Cliente↔Serviço, monta um Service
        Ticket contendo as informações do usuário autenticado e cifra o
        ticket utilizando a chave mestra do serviço.

        Args:
            nome_usuario: Nome do usuário autenticado.

        Returns:
            tuple[bytes, bytes]:
                Tupla contendo:

                - o Service Ticket cifrado;
                - a nova chave de sessão Cliente↔Serviço.
        """
        chave_cliente_servico = os.urandom(16)

        timestamp = int(time.time())

        ticket = criar_ticket(
            nome=nome_usuario,
            chave_sessao=chave_cliente_servico,
            timestamp=timestamp,
            lifetime_min=LIFETIME_TICKET,
        )

        ticket_cifrado = cifrar_aes_gcm(
            self.chave_servico,
            ticket,
        )

        return ticket_cifrado, chave_cliente_servico
    
    def _montar_resposta_tgs(
        self,
        service_ticket_cif: bytes,
        chave_cliente_servico: bytes,
        chave_cliente_tgs: bytes,
    ):
        """Monta a resposta enviada ao cliente pelo TGS.

        A chave de sessão Cliente↔Serviço é cifrada utilizando a chave de
        sessão Cliente↔TGS. O payload resultante contém o Service Ticket
        cifrado e a chave de sessão protegida.

        Args:
            service_ticket_cif: Service Ticket cifrado com a chave do serviço.
            chave_cliente_servico: Nova chave de sessão Cliente↔Serviço.
            chave_cliente_tgs: Chave de sessão Cliente↔TGS extraída do TGT.

        Returns:
            bytes: Mensagem serializada do tipo ``MSG_TGS_REPLY`` pronta para
            envio ao cliente.
        """

        chave_cliente_servico_cif = cifrar_aes_gcm(
            chave_cliente_tgs,
            chave_cliente_servico,
        )

        payload = (
            len(service_ticket_cif).to_bytes(2, "big")
            + service_ticket_cif
            + chave_cliente_servico_cif
        )

        return empacotar(
            MSG_TGS_REPLY,
            payload,
        )

if __name__ == "__main__":
    servidor = TGSServer(
        "127.0.0.1",
        5451,
        chave_as=b"0123456789abcdef",
        chave_servico=b"fedcba9876543210",
    )
    servidor.iniciar()