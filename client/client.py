"""Cliente — orquestra fluxo Kerberos: AS → TGS → Serviço."""
import socket
import sys

from common.config import AS_HOST, AS_PORT
from common.protocol import (
    empacotar,
    desempacotar,
    MSG_AUTH_REQUEST,
    MSG_AUTH_REPLY,
    MSG_ERROR,
)


class ClienteKerberos:
    """
    Cliente Kerberos conforme o Grupo 5 do projeto.

    Passo 1 (implementado):
      - Conecta no AS (Authentication Server).
      - Envia MSG_AUTH_REQUEST com o nome do usuario.
      - Recebe MSG_AUTH_REPLY (salt + TGT cifrado + K_c_AS cifrada)
        ou MSG_ERROR.
    """

    SALT_LENGTH = 16

    def __init__(self, host: str = AS_HOST, port: int = AS_PORT):
        self.host = host
        self.port = port
        self.socket: socket.socket | None = None
        self.usuario: str | None = None
        self.salt: bytes | None = None
        self.tgt_cifrado: bytes | None = None
        self.k_c_as_cifrada: bytes | None = None

    # ------------------------------------------------------------------
    # Passo 1: Autenticacao no AS
    # ------------------------------------------------------------------

    def passo1_solicitar_usuario(self) -> str:
        """Solicita o nome do usuario via entrada padrao."""
        usuario = input("Digite o nome do usuario: ").strip()
        if not usuario:
            raise ValueError("Nome de usuario nao pode ser vazio.")
        self.usuario = usuario
        return usuario

    def passo1_conectar_as(self) -> None:
        """Conecta via socket TCP ao Authentication Server."""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.settimeout(30)
        self.socket.connect((self.host, self.port))
        print(f"[CLIENTE] Conectado ao AS em {self.host}:{self.port}")

    def passo1_enviar_auth_request(self) -> None:
        """Envia MSG_AUTH_REQUEST contendo o nome do usuario."""
        if self.socket is None:
            raise RuntimeError("Socket nao inicializado.")
        if self.usuario is None:
            raise RuntimeError("Usuario nao definido.")

        payload = self.usuario.encode("utf-8")
        mensagem = empacotar(MSG_AUTH_REQUEST, payload)
        self.socket.sendall(mensagem)
        print(f"[CLIENTE] MSG_AUTH_REQUEST enviada para usuario '{self.usuario}'")

    def passo1_receber_resposta(self) -> None:
        """
        Recebe a resposta do AS e valida o tipo da mensagem.

        Em caso de sucesso (MSG_AUTH_REPLY), extrai do payload:
          - salt (16 bytes)
          - TGT cifrado
          - K_c_AS cifrada
        """
        if self.socket is None:
            raise RuntimeError("Socket nao inicializado.")

        dados = self._receber_mensagem_completa()
        tipo, payload = desempacotar(dados)

        if tipo == MSG_ERROR:
            erro = payload.decode("utf-8", errors="replace")
            raise RuntimeError(f"AS retornou erro: {erro}")

        if tipo != MSG_AUTH_REPLY:
            raise RuntimeError(
                f"Tipo de mensagem inesperado do AS: {tipo} "
                f"(esperado MSG_AUTH_REPLY={MSG_AUTH_REPLY} ou MSG_ERROR={MSG_ERROR})"
            )

        self._extrair_auth_reply(payload)
        print("[CLIENTE] MSG_AUTH_REPLY recebida com sucesso.")
        print(f"[CLIENTE] Salt: {self.salt.hex() if self.salt else None}")
        print(
            f"[CLIENTE] TGT cifrado: {len(self.tgt_cifrado)} bytes "
            if self.tgt_cifrado
            else "[CLIENTE] TGT cifrado: None"
        )
        print(
            f"[CLIENTE] K_c_AS cifrada: {len(self.k_c_as_cifrada)} bytes "
            if self.k_c_as_cifrada
            else "[CLIENTE] K_c_AS cifrada: None"
        )

    def _extrair_auth_reply(self, payload: bytes) -> None:
        """
        Extrai do payload da MSG_AUTH_REPLY:
          - salt: 16 bytes iniciais
          - tgt_cifrado: proximos 4 bytes indicam o tamanho, seguidos do TGT
          - k_c_as_cifrada: proximos 4 bytes indicam o tamanho, seguidos da chave
        """
        offset = 0

        if len(payload) < self.SALT_LENGTH:
            raise ValueError(
                f"Payload insuficiente para salt: "
                f"{len(payload)} bytes (esperado >= {self.SALT_LENGTH})"
            )

        self.salt = payload[offset : offset + self.SALT_LENGTH]
        offset += self.SALT_LENGTH

        self.tgt_cifrado = self._extrair_blob_com_tamanho(payload, offset)
        offset += 4 + len(self.tgt_cifrado)

        self.k_c_as_cifrada = self._extrair_blob_com_tamanho(payload, offset)

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

    def _receber_mensagem_completa(self) -> bytes:
        """
        Recebe a mensagem completa do socket.

        Assume que o cabecalho definido pelo protocolo indica o tamanho total
        da mensagem. Caso o protocolo utilize um cabecalho de tamanho fixo,
        este metodo le o cabecalho primeiro e em seguida o restante do payload.
        """
        if self.socket is None:
            raise RuntimeError("Socket nao inicializado.")

        # Le os primeiros 8 bytes (cabecalho tipico: tipo + tamanho).
        # Ajuste conforme a implementacao real de empacotar/desempacotar.
        cabecalho = self._receber_exato(8)
        if len(cabecalho) < 8:
            raise RuntimeError("Conexao encerrada antes do cabecalho completo.")

        tamanho_payload = int.from_bytes(
            cabecalho[4:8], byteorder="big", signed=False
        )
        payload = self._receber_exato(tamanho_payload)

        return cabecalho + payload

    def _receber_exato(self, n: int) -> bytes:
        """Le exatamente n bytes do socket, bloqueando ate completar."""
        if self.socket is None:
            raise RuntimeError("Socket nao inicializado.")

        partes: list[bytes] = []
        recebido = 0
        while recebido < n:
            chunk = self.socket.recv(n - recebido)
            if not chunk:
                break
            partes.append(chunk)
            recebido += len(chunk)
        return b"".join(partes)

    # ------------------------------------------------------------------
    # Passos futuros (placeholders conforme o playbook da skill)
    # ------------------------------------------------------------------

    def passo2_solicitar_tgs(self) -> None:
        """Passo 2: Conectar no TGS e solicitar ticket de servico. (A implementar)"""
        raise NotImplementedError("Passo 2 ainda nao implementado.")

    def passo3_acessar_servico(self) -> None:
        """Passo 3: Conectar no servico e validar o ticket. (A implementar)"""
        raise NotImplementedError("Passo 3 ainda nao implementado.")

    # ------------------------------------------------------------------
    # Ciclo de vida
    # ------------------------------------------------------------------

    def fechar(self) -> None:
        """Fecha o socket se estiver aberto."""
        if self.socket is not None:
            try:
                self.socket.close()
            except OSError:
                pass
            finally:
                self.socket = None

    def executar_passo1(self) -> None:
        """Executa o Passo 1 completo do protocolo Kerberos."""
        try:
            self.passo1_solicitar_usuario()
            self.passo1_conectar_as()
            self.passo1_enviar_auth_request()
            self.passo1_receber_resposta()
        finally:
            self.fechar()


def main() -> None:
    cliente = ClienteKerberos()
    try:
        cliente.executar_passo1()
    except Exception as exc:
        print(f"[CLIENTE] Erro: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()