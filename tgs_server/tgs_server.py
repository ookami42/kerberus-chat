import socket
import threading


class TGSServer:
    def __init__(self, host, porta, chave_as, chave_servico):       
        self.host = host
        self.porta = porta
        self.chave_as = chave_as
        self.chave_servico = chave_servico

    def iniciar(self):    
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
        print(f"Cliente conectado: {addr}")

        try:
            while True:
                dados = con.recv(4096)

                if not dados:
                    break

                # Placeholder para implementação futura
                print(f"Recebido de {addr}: {dados!r}")

        except Exception as e:
            print(f"Erro com {addr}: {e}")

        finally:
            con.close()
            print(f"Cliente desconectado: {addr}")

if __name__ == "__main__":
    servidor = TGSServer(
        "127.0.0.1",
        5451,
        chave_as="chave_as",
        chave_servico="chave_servico",
    )
    servidor.iniciar()