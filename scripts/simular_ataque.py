"""Simula ataques contra o sistema Kerberos para demonstrar as proteções.

Cada cenário de ataque tenta burlar uma camada de segurança do protocolo
e verifica se o sistema bloqueia corretamente.

Cenários:
  1. Replay de TGT expirado       — envia um TGT antigo para o TGS
  2. Replay de authenticator       — envia authenticator com timestamp antigo
  3. Ticket com chave errada       — envia Service Ticket cifrado com chave inválida
  4. Usuário inexistente           — tenta autenticar com nome não cadastrado
  5. Path traversal                — tenta ler nota de outro usuário com ../

Uso:
  python scripts/simular_ataque.py

Requer que os servidores (AS, TGS, Serviço) estejam rodando.
"""

import os
import shutil
import socket
import struct
import time
import sys

from common.config import (
    AS_HOST, AS_PORT,
    TGS_HOST, TGS_PORT,
    SVC_HOST, SVC_PORT,
    JANELA_AUTH, LIFETIME_TICKET, TAMANHO_CHAVE,
    AS_MASTER_KEY_PATH, SVC_MASTER_KEY_PATH, NOTAS_RAIZ_PATH,
)
from common.crypto import cifrar_aes_gcm, decifrar_aes_gcm
from common.protocol import (
    empacotar,
    criar_ticket,
    MSG_AUTH_REQUEST, MSG_AUTH_REPLY,
    MSG_TGS_REQUEST, MSG_TGS_REPLY,
    MSG_SVC_REQUEST, MSG_SVC_REPLY,
    MSG_ERROR,
    MSG_NOTE_READ, MSG_NOTE_REPLY,
)

# ─── Utilitários de conexão ────────────────────────────────────────────

def _conectar(host: str, porta: int) -> socket.socket:
    """Cria e conecta um socket TCP.

    Retorna o socket conectado.
    Levanta ConnectionRefusedError se o servidor estiver offline.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)  # timeout de 5 segundos para não travar
    sock.connect((host, porta))
    return sock


def _receber_resposta(sock: socket.socket) -> "tuple[int | None, bytes | None]":
    """Lê cabeçalho (6 bytes) + payload de uma mensagem do socket.

    Usa struct.unpack diretamente no cabeçalho (não desempacotar, que
    espera a mensagem completa com payload).

    Returns:
        Tupla (tipo, payload).
        Retorna (None, None) se a conexão for fechada ou der timeout.
    """
    try:
        header = sock.recv(6)
        if not header:
            return None, None
        # Desempacota manualmente: 2 bytes tipo (H) + 4 bytes tamanho (I)
        tipo, tamanho = struct.unpack(">HI", header)
        # Lê o payload com o tamanho extraído do cabeçalho
        payload = sock.recv(tamanho) if tamanho > 0 else b""
        return tipo, payload
    except (socket.timeout, ConnectionError):
        return None, None


def _carregar_chave(caminho: str, nome: str) -> bytes:
    """Carrega uma chave mestra do arquivo.

    Args:
        caminho: Caminho do arquivo .key.
        nome: Nome descritivo para mensagens de erro.

    Returns:
        Chave de 16 bytes.

    Raises:
        FileNotFoundError: Se o arquivo não existir.
    """
    if not os.path.exists(caminho):
        raise FileNotFoundError(
            f"Arquivo de chave '{nome}' não encontrado em {caminho}. "
            f"Execute 'gerar-chaves' primeiro."
        )
    with open(caminho, "rb") as f:
        chave = f.read()
    if len(chave) != TAMANHO_CHAVE:
        raise ValueError(
            f"Chave '{nome}' tem {len(chave)} bytes, esperado {TAMANHO_CHAVE}."
        )
    return chave


# ─── Cenário 1: Replay de TGT expirado ─────────────────────────────────

def teste_replay_tgt(as_master_key: bytes) -> "bool | None":
    """Tenta reenviar um TGT já expirado para o TGS.

    Estratégia:
      - Cria um TGT com timestamp muito antigo (epoch = 0) e lifetime curto.
      - Cifra o TGT com a chave mestra do AS (que o TGS conhece).
      - Envia MSG_TGS_REQUEST ao TGS.
      - Espera receber MSG_ERROR (ticket expirado).

    O que está sendo testado:
      A proteção do TGS contra replay de tickets expirados.
      Mesmo que o TGT seja criptograficamente válido (cifrado com a
      chave correta), o TGS deve rejeitá-lo porque o timestamp
      mostra que ele já expirou.

    Returns:
        True se o ataque foi BLOQUEADO (recebeu MSG_ERROR).
        False se o ataque foi ACEITO (recebeu MSG_TGS_REPLY).
    """
    print("\n" + "=" * 60)
    print("[TESTE 1] Replay de TGT expirado")
    print("=" * 60)
    print("Objetivo: enviar um TGT expirado ao TGS e ver se ele rejeita.\n")

    # Passo 1: Montar um TGT com timestamp antigo e lifetime mínimo
    nome = b"alice"
    k_c_as = os.urandom(TAMANHO_CHAVE)

    # timestamp = 0 (epoch Unix: 1 de janeiro de 1970)
    # lifetime = 1 minuto (para garantir que está expirado)
    timestamp_antigo = 0
    lifetime_curto = 1

    print(f"  -> Criando TGT para '{nome.decode()}'")
    print(f"     Timestamp: {timestamp_antigo} (epoch)")
    print(f"     Lifetime:  {lifetime_curto} minuto(s)")
    print(f"     K_c_AS:    {k_c_as.hex()}")

    tgt = criar_ticket(nome, k_c_as, timestamp_antigo, lifetime_curto)
    tgt_cifrado = cifrar_aes_gcm(as_master_key, tgt)
    print(f"     TGT cifrado: {len(tgt_cifrado)} bytes")

    # Passo 2: Montar a MSG_TGS_REQUEST
    # Formato: [4 bytes tam_tgt][TGT] + [4 bytes tam_svc][nome_svc]
    nome_servico = b"notas"
    payload = (
        struct.pack(">I", len(tgt_cifrado))
        + tgt_cifrado
        + struct.pack(">I", len(nome_servico))
        + nome_servico
    )

    # Passo 3: Conectar no TGS e enviar o ataque
    try:
        sock = _conectar(TGS_HOST, TGS_PORT)
    except (ConnectionRefusedError, socket.timeout) as e:
        print(f"\n  ⚠️  TGS offline ({e}). Pulando teste.")
        return None  # None = inconclusivo

    print(f"  -> Enviando TGT expirado ao TGS ({TGS_HOST}:{TGS_PORT})...")
    sock.sendall(empacotar(MSG_TGS_REQUEST, payload))

    # Passo 4: Verificar a resposta
    tipo, resposta = _receber_resposta(sock)
    sock.close()

    if tipo == MSG_ERROR:
        print(f"  ✅ BLOQUEADO! TGS rejeitou o ticket expirado.")
        print(f"     Mensagem de erro: {resposta.decode()}")
        return True
    elif tipo == MSG_TGS_REPLY:
        print(f"  ❌ FALHA! TGS aceitou um ticket expirado!")
        return False
    else:
        print(f"  ❌ FALHA! Resposta inesperada (tipo={tipo}).")
        return False


# ─── Cenário 2: Replay de authenticator ────────────────────────────────

def teste_replay_authenticator(service_master_key: bytes) -> "bool | None":
    """Tenta enviar um authenticator com timestamp muito antigo ao Serviço.

    Estratégia:
      - Cria um Service Ticket válido (cifrado com service_master_key).
      - Cria um authenticator com timestamp antigo (fora da JANELA_AUTH).
      - Envia MSG_SVC_REQUEST ao Serviço.
      - Espera receber MSG_ERROR (timestamp fora da janela).

    O que está sendo testado:
      A proteção contra replay de authenticator. Mesmo que o atacante
      capture um authenticator válido, ele não pode reutilizá-lo depois
      que o timestamp sair da janela de tolerância (JANELA_AUTH = 5 min).

    Returns:
        True se o ataque foi BLOQUEADO.
        False se o ataque foi ACEITO.
    """
    print("\n" + "=" * 60)
    print("[TESTE 2] Replay de authenticator")
    print("=" * 60)
    print("Objetivo: enviar authenticator com timestamp antigo e ver se")
    print("          o Serviço rejeita por suspeita de replay.\n")

    # Passo 1: Criar um Service Ticket válido
    nome = b"alice"
    k_c_svc = os.urandom(TAMANHO_CHAVE)
    timestamp_atual = int(time.time())

    print(f"  -> Criando Service Ticket para '{nome.decode()}'")
    print(f"     K_c_svc gerada: {k_c_svc.hex()}")

    st = criar_ticket(nome, k_c_svc, timestamp_atual, LIFETIME_TICKET)
    st_cifrado = cifrar_aes_gcm(service_master_key, st)
    print(f"     Service Ticket cifrado: {len(st_cifrado)} bytes")

    # Passo 2: Criar um authenticator com timestamp muito antigo
    # O authenticator contém: [2 bytes len_nome][nome][8 bytes timestamp]
    timestamp_antigo = 0  # 1 de janeiro de 1970 — muito fora da janela!

    print(f"  -> Criando authenticator com timestamp antigo")
    print(f"     Timestamp do auth: {timestamp_antigo}")
    print(f"     Timestamp atual:   {timestamp_atual}")
    print(f"     Diferença:         {timestamp_atual - timestamp_antigo}s")
    print(f"     Janela tolerada:   {JANELA_AUTH}s")

    auth = (
        struct.pack(">H", len(nome))
        + nome
        + struct.pack(">Q", timestamp_antigo)
    )
    auth_cifrado = cifrar_aes_gcm(k_c_svc, auth)

    # Passo 3: Montar a MSG_SVC_REQUEST
    # Formato: [4 bytes tam_st][ST] + [4 bytes tam_auth][Auth]
    payload = (
        struct.pack(">I", len(st_cifrado))
        + st_cifrado
        + struct.pack(">I", len(auth_cifrado))
        + auth_cifrado
    )

    # Passo 4: Enviar ao Serviço
    try:
        sock = _conectar(SVC_HOST, SVC_PORT)
    except (ConnectionRefusedError, socket.timeout) as e:
        print(f"\n  ⚠️  Serviço offline ({e}). Pulando teste.")
        return None

    print(f"  -> Enviando authenticator antigo ao Serviço ({SVC_HOST}:{SVC_PORT})...")
    sock.sendall(empacotar(MSG_SVC_REQUEST, payload))

    tipo, resposta = _receber_resposta(sock)
    sock.close()

    if tipo == MSG_ERROR:
        print(f"  ✅ BLOQUEADO! Serviço rejeitou o authenticator antigo.")
        print(f"     Mensagem de erro: {resposta.decode()}")
        return True
    elif tipo == MSG_SVC_REPLY:
        print(f"  ❌ FALHA! Serviço aceitou authenticator com timestamp antigo!")
        return False
    else:
        print(f"  ❌ FALHA! Resposta inesperada (tipo={tipo}).")
        return False


# ─── Cenário 3: Ticket com chave errada ────────────────────────────────

def teste_ticket_chave_errada() -> "bool | None":
    """Tenta enviar um Service Ticket cifrado com uma chave que o
    Serviço não conhece.

    Estratégia:
      - Gera uma chave aleatória (não é a service_master_key).
      - Cria um Service Ticket e cifra com essa chave falsa.
      - Cria um authenticator válido (com a K_c_svc dentro do ticket).
      - Envia MSG_SVC_REQUEST ao Serviço.
      - Espera receber MSG_ERROR (InvalidTag ao decifrar).

    O que está sendo testado:
      A integridade criptográfica do ticket. Um atacante não consegue
      forjar um ticket válido sem conhecer a service_master_key.
      O AES-GCM detecta a violação e lança InvalidTag.

    Returns:
        True se o ataque foi BLOQUEADO.
        False se o ataque foi ACEITO.
    """
    print("\n" + "=" * 60)
    print("[TESTE 3] Ticket com chave errada")
    print("=" * 60)
    print("Objetivo: enviar Service Ticket cifrado com chave falsa e ver")
    print("          se o Serviço detecta a violação criptográfica.\n")

    # Passo 1: Criar um Service Ticket com chave FALSA
    nome = b"alice"
    k_c_svc = os.urandom(TAMANHO_CHAVE)
    timestamp_atual = int(time.time())

    # ATENÇÃO: esta chave NÃO é a service_master_key!
    chave_falsa = os.urandom(TAMANHO_CHAVE)

    print(f"  -> Criando Service Ticket FALSIFICADO para '{nome.decode()}'")
    print(f"     Chave usada (falsa):    {chave_falsa.hex()}")
    print(f"     Chave real (serviço):   (desconhecida pelo atacante)")

    st = criar_ticket(nome, k_c_svc, timestamp_atual, LIFETIME_TICKET)
    st_cifrado = cifrar_aes_gcm(chave_falsa, st)

    # Passo 2: Criar um authenticator válido
    # O authenticator usa K_c_svc, que está dentro do ticket.
    # Mas o Serviço nunca vai conseguir extrair K_c_svc porque
    # não consegue decifrar o ticket com a chave falsa.
    auth = (
        struct.pack(">H", len(nome))
        + nome
        + struct.pack(">Q", timestamp_atual)
    )
    auth_cifrado = cifrar_aes_gcm(k_c_svc, auth)

    # Passo 3: Montar MSG_SVC_REQUEST
    payload = (
        struct.pack(">I", len(st_cifrado))
        + st_cifrado
        + struct.pack(">I", len(auth_cifrado))
        + auth_cifrado
    )

    # Passo 4: Enviar ao Serviço
    try:
        sock = _conectar(SVC_HOST, SVC_PORT)
    except (ConnectionRefusedError, socket.timeout) as e:
        print(f"\n  ⚠️  Serviço offline ({e}). Pulando teste.")
        return None

    print(f"  -> Enviando ticket falsificado ao Serviço ({SVC_HOST}:{SVC_PORT})...")
    sock.sendall(empacotar(MSG_SVC_REQUEST, payload))

    tipo, resposta = _receber_resposta(sock)
    sock.close()

    if tipo == MSG_ERROR:
        print(f"  ✅ BLOQUEADO! Serviço rejeitou o ticket com chave errada.")
        print(f"     Mensagem de erro: {resposta.decode()}")
        return True
    elif tipo == MSG_SVC_REPLY:
        print(f"  ❌ FALHA! Serviço aceitou um ticket forjado!")
        return False
    else:
        print(f"  ❌ FALHA! Resposta inesperada (tipo={tipo}).")
        return False


# ─── Cenário 4: Usuário inexistente ────────────────────────────────────

def teste_usuario_inexistente() -> "bool | None":
    """Tenta autenticar com um nome de usuário que não está cadastrado
    no UserDB.

    Estratégia:
      - Conecta no AS e envia MSG_AUTH_REQUEST com um nome aleatório.
      - Espera receber MSG_ERROR (usuário não encontrado).

    O que está sendo testado:
      A primeira linha de defesa: o AS só responde a usuários
      previamente cadastrados. Um atacante não pode simplesmente
      inventar um nome e começar o fluxo Kerberos.

    Returns:
        True se o ataque foi BLOQUEADO.
        False se o ataque foi ACEITO.
    """
    print("\n" + "=" * 60)
    print("[TESTE 4] Usuário inexistente")
    print("=" * 60)
    print("Objetivo: tentar autenticar com um nome não cadastrado e ver")
    print("          se o AS rejeita a requisição.\n")

    # Passo 1: Gerar um nome que certamente não existe no banco
    nome_falso = f"hacker_{os.urandom(4).hex()}"
    print(f"  -> Tentando autenticar como '{nome_falso}'")

    # Passo 2: Conectar no AS e enviar MSG_AUTH_REQUEST
    try:
        sock = _conectar(AS_HOST, AS_PORT)
    except (ConnectionRefusedError, socket.timeout) as e:
        print(f"\n  ⚠️  AS offline ({e}). Pulando teste.")
        return None

    print(f"  -> Enviando requisição ao AS ({AS_HOST}:{AS_PORT})...")
    sock.sendall(empacotar(MSG_AUTH_REQUEST, nome_falso.encode()))

    # Passo 3: Verificar a resposta
    tipo, resposta = _receber_resposta(sock)
    sock.close()

    if tipo == MSG_ERROR:
        print(f"  ✅ BLOQUEADO! AS rejeitou o usuário inexistente.")
        return True
    elif tipo == MSG_AUTH_REPLY:
        print(f"  ❌ FALHA! AS respondeu a um usuário inexistente!")
        return False
    else:
        print(f"  ❌ FALHA! Resposta inesperada (tipo={tipo}).")
        return False


# ─── Cenário 5: Path traversal no serviço de notas ───────────────────

def teste_path_traversal(service_master_key: bytes) -> "bool | None":
    """Tenta acessar notas de outro usuário injetando ../ no nome do arquivo.

    Estratégia:
      - Cria um Service Ticket válido para 'alice'.
      - Prepara um arquivo secreto em /notas/bob/segredo.txt.
      - Realiza o handshake Kerberos completo (autenticação mútua).
      - Envia MSG_NOTE_READ com payload '../bob/segredo.txt'.
      - Espera receber MSG_ERROR (o servidor resolve para
        /notas/alice/segredo.txt, que não existe).

    O que está sendo testado:
      O isolamento entre usuários no serviço de notas. Mesmo que o
      atacante tenha um ticket válido, ele não consegue escapar do
      próprio diretório de notas graças a os.path.basename().
      Se o path traversal furasse, receberia MSG_NOTE_REPLY com o
      conteúdo do arquivo secreto do Bob.

    Returns:
        True se o ataque foi BLOQUEADO.
        False se o ataque foi ACEITO (o conteúdo do Bob foi exposto).
    """
    print("\n" + "=" * 60)
    print("[TESTE 5] Path traversal no serviço de notas")
    print("=" * 60)
    print("Objetivo: usar '../' no nome do arquivo para ler notas de")
    print("          outro usuário, e verificar se o serviço bloqueia.\n")

    # --- Setup: criar arquivo secreto para o Bob ---
    bob_dir = os.path.join(NOTAS_RAIZ_PATH, "bob")
    bob_arquivo = os.path.join(bob_dir, "segredo.txt")
    conteudo_secreto = "senha do bob: admin123"
    teste_executado = False

    try:
        os.makedirs(bob_dir, exist_ok=True)
        with open(bob_arquivo, "w") as f:
            f.write(conteudo_secreto)
        print(f"  -> Arquivo secreto criado: {bob_arquivo}")
        print(f"     Conteúdo: '{conteudo_secreto}'")

        # --- Passo 1: Criar Service Ticket válido para Alice ---
        nome = b"alice"
        k_c_svc = os.urandom(TAMANHO_CHAVE)
        timestamp_atual = int(time.time())

        print(f"\n  -> Criando Service Ticket válido para '{nome.decode()}'")

        st = criar_ticket(nome, k_c_svc, timestamp_atual, LIFETIME_TICKET)
        st_cifrado = cifrar_aes_gcm(service_master_key, st)

        # --- Passo 2: Authenticator com timestamp válido ---
        auth = (
            struct.pack(">H", len(nome))
            + nome
            + struct.pack(">Q", timestamp_atual)
        )
        auth_cifrado = cifrar_aes_gcm(k_c_svc, auth)

        # --- Passo 3: Montar MSG_SVC_REQUEST ---
        payload = (
            struct.pack(">I", len(st_cifrado))
            + st_cifrado
            + struct.pack(">I", len(auth_cifrado))
            + auth_cifrado
        )

        try:
            sock = _conectar(SVC_HOST, SVC_PORT)
        except (ConnectionRefusedError, socket.timeout) as e:
            print(f"\n  ⚠️  Serviço offline ({e}). Pulando teste.")
            return None

        # --- Passo 4: Handshake Kerberos ---
        print(f"  -> Enviando MSG_SVC_REQUEST ao Serviço ({SVC_HOST}:{SVC_PORT})...")
        sock.sendall(empacotar(MSG_SVC_REQUEST, payload))

        # Ler MSG_SVC_REPLY (autenticação mútua — não precisamos validar)
        tipo_auth, payload_auth = _receber_resposta(sock)
        if tipo_auth != MSG_SVC_REPLY:
            print(f"  ❌ Autenticação falhou (tipo={tipo_auth}).")
            sock.close()
            return None

        print("  -> Autenticação mútua OK. Enviando ataque de path traversal...")

        # --- Passo 5: Enviar MSG_NOTE_READ com path traversal ---
        payload_traversal = b"../bob/segredo.txt"
        print(f"     Payload: MSG_NOTE_READ com '{payload_traversal.decode()}'")
        print(f"     (Servidor deveria resolver para notas/alice/segredo.txt,")
        print(f"      não para notas/bob/segredo.txt)")

        sock.sendall(empacotar(MSG_NOTE_READ, payload_traversal))

        # --- Passo 6: Verificar resposta ---
        tipo, resposta = _receber_resposta(sock)
        sock.close()
        teste_executado = True

        if tipo == MSG_NOTE_REPLY:
            conteudo = resposta.decode(errors="replace")
            print(f"\n  ❌ CRÍTICO! Path traversal FUNCIONOU!")
            print(f"     O servidor retornou o conteúdo do arquivo do Bob:")
            print(f"     '{conteudo}'")
            print(f"     (Esperado: MSG_ERROR com 'Nota nao encontrada.')")
            return False

        elif tipo == MSG_ERROR:
            print(f"  ✅ BLOQUEADO! Serviço rejeitou o path traversal.")
            print(f"     Mensagem de erro: {resposta.decode()}")
            print(f"     O servidor resolveu para o diretório de Alice,")
            print(f"     não para o diretório secreto do Bob.")
            return True

        else:
            print(f"  ❌ FALHA! Resposta inesperada (tipo={tipo}).")
            return False

    finally:
        # --- Teardown: remover arquivo secreto do Bob ---
        if os.path.exists(bob_arquivo):
            os.remove(bob_arquivo)
        if os.path.isdir(bob_dir):
            try:
                os.rmdir(bob_dir)
            except OSError:
                pass


# ─── Função principal ──────────────────────────────────────────────────

def main():
    """Executa os 4 cenários de ataque e exibe o resultado final.

    Cada teste retorna:
      - True:  ataque bloqueado (sistema seguro contra este vetor)
      - False: ataque aceito   (vulnerabilidade encontrada!)
      - None:  teste pulado   (servidor offline)

    O script requer que AS, TGS e Serviço estejam rodando.
    As chaves mestras são carregadas de keys/as_master.key e
    keys/service_master.key.
    """
    print("=" * 60)
    print("  SCRIPTS DE TESTE DE ATAQUE — Kerberos Notas")
    print("=" * 60)
    print()
    print("Este script tenta 5 ataques contra o sistema Kerberos")
    print("para demonstrar que as proteções funcionam.\n")
    print("Requer: AS (porta 5450), TGS (5451) e Serviço (5452) rodando.\n")

    # Carregar chaves mestras para os testes que precisam delas
    try:
        as_master_key = _carregar_chave(AS_MASTER_KEY_PATH, "as_master")
        print(f"✓ Chave AS carregada: {len(as_master_key)} bytes")
    except (FileNotFoundError, ValueError) as e:
        print(f"✗ Erro ao carregar chave AS: {e}")
        sys.exit(1)

    try:
        service_master_key = _carregar_chave(SVC_MASTER_KEY_PATH, "service_master")
        print(f"✓ Chave Serviço carregada: {len(service_master_key)} bytes")
    except (FileNotFoundError, ValueError) as e:
        print(f"✗ Erro ao carregar chave Serviço: {e}")
        sys.exit(1)

    # Executar cada teste
    resultados = []

    # Teste 1: Replay de TGT expirado (precisa do TGS + as_master_key)
    r1 = teste_replay_tgt(as_master_key)
    resultados.append(("Replay de TGT expirado", r1))

    # Teste 2: Replay de authenticator (precisa do Serviço + service_master_key)
    r2 = teste_replay_authenticator(service_master_key)
    resultados.append(("Replay de authenticator", r2))

    # Teste 3: Ticket com chave errada (precisa apenas do Serviço)
    r3 = teste_ticket_chave_errada()
    resultados.append(("Ticket com chave errada", r3))

    # Teste 4: Usuário inexistente (precisa apenas do AS)
    r4 = teste_usuario_inexistente()
    resultados.append(("Usuário inexistente", r4))

    # Teste 5: Path traversal no serviço de notas (precisa do Serviço + service_master_key)
    r5 = teste_path_traversal(service_master_key)
    resultados.append(("Path traversal (notas)", r5))

    # ─── Resumo final ──────────────────────────────────────────────
    print("\n" + "=" * 60)
    print("  RESULTADO FINAL")
    print("=" * 60)

    aprovados = 0
    falhas = 0
    pulados = 0

    for nome, resultado in resultados:
        if resultado is True:
            print(f"  ✅ {nome}: BLOQUEADO")
            aprovados += 1
        elif resultado is False:
            print(f"  ❌ {nome}: VULNERÁVEL!")
            falhas += 1
        else:
            print(f"  ⚠️  {nome}: PULADO (servidor offline)")
            pulados += 1

    print(f"\n  Total: {aprovados} bloqueados, {falhas} falhas, {pulados} pulados")

    if falhas > 0:
        print("\n  ⚠️  ATENÇÃO: Alguns ataques NÃO foram bloqueados!")
        print("      O sistema tem vulnerabilidades que precisam ser corrigidas.")
    elif aprovados == 0:
        print("\n  ⚠️  Nenhum teste executado. Inicie os servidores e tente novamente.")
    else:
        print("\n  ✅ Todos os ataques testados foram bloqueados com sucesso!")


if __name__ == "__main__":
    main()
