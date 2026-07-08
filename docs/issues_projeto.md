# Issues do Projeto Kerberos

> Cada issue é uma tarefa atômica. Qualquer pessoa do grupo pode pegar qualquer issue.
> Ao terminar, abre um PR, outra pessoa revisa e mergeia. Depois pega outra issue.

## 🏗️ Grupo 0 — Fundação

### #1 — Criar constantes de configuração

**Arquivo:** `common/config.py`

**Descrição:** Definir as constantes que todo o projeto vai usar — portas dos servidores, host, tamanhos de chave, lifetime de tickets, janela de autenticação.

```python
AS_HOST     = "127.0.0.1"
AS_PORT     = 5450
TGS_HOST    = "127.0.0.1"
TGS_PORT    = 5451
SVC_HOST    = "127.0.0.1"
SVC_PORT    = 5452
TAMANHO_CHAVE = 16     # 128 bits
LIFETIME_TICKET = 480  # minutos (8h)
JANELA_AUTH = 300      # segundos (5 min)
```

**Critério de aceite:**
- [ ] `from common.config import AS_PORT` funciona sem erro
- [ ] Todas as constantes acima existem com os valores corretos

**Dependências:** nenhuma

---

### #2 — Criar função de cifrar AES-GCM

**Arquivo:** `common/crypto.py`

**Descrição:** Implementar `cifrar_aes_gcm(chave, dados)` que cifra dados com AES-128-GCM. Retorna `nonce(12 bytes) + ciphertext`. O nonce deve ser aleatório a cada chamada.

```python
def cifrar_aes_gcm(chave: bytes, dados: bytes) -> bytes:
    # chave: 16 bytes
    # dados: bytes a cifrar
    # retorno: nonce(12) + ciphertext (tag já embutida no ciphertext)
```

**Critério de aceite:**
- [ ] `cifrar_aes_gcm(os.urandom(16), b"teste")` retorna 12 + 16 = 28 bytes (nonce + ciphertext + tag)
- [ ] Duas chamadas com mesmos argumentos geram resultados diferentes (nonces diferentes)
- [ ] Importa `AESGCM` de `cryptography.hazmat.primitives.ciphers.aead`

**Dependências:** nenhuma

---

### #3 — Criar função de decifrar AES-GCM

**Arquivo:** `common/crypto.py`

**Descrição:** Implementar `decifrar_aes_gcm(chave, dados)` que recebe `nonce(12) + ciphertext` e retorna os dados originais. Deve lançar exceção se os dados forem violados.

```python
def decifrar_aes_gcm(chave: bytes, dados: bytes) -> bytes:
    # chave: 16 bytes
    # dados: nonce(12) + ciphertext
    # retorno: dados decifrados
```

**Critério de aceite:**
- [ ] `decifrar_aes_gcm(chave, cifrar_aes_gcm(chave, b"teste"))` retorna `b"teste"`
- [ ] Alterar 1 byte do ciphertext faz `decrypt()` lançar `InvalidTag`
- [ ] Teste unitário com 3 mensagens diferentes

**Dependências:** #2 (precisa de `cifrar_aes_gcm` pra testar)

---

### #4 — Criar função KDF (PBKDF2)

**Arquivo:** `common/crypto.py`

**Descrição:** Implementar `derivar_chave(senha, salt)` que deriva 16 bytes a partir de senha + salt usando PBKDF2-HMAC-SHA256 com 100.000 iterações.

```python
def derivar_chave(senha: bytes, salt: bytes) -> bytes:
    # senha: bytes (ex: b"minha_senha")
    # salt: 16 bytes aleatórios
    # retorno: 16 bytes (chave AES)
```

**Critério de aceite:**
- [ ] `derivar_chave(b"senha", b"salte_salgado__")` retorna 16 bytes
- [ ] Mesma senha + mesmo salt → mesmo resultado
- [ ] Mesma senha + salt diferente → resultado diferente
- [ ] Senha diferente + mesmo salt → resultado diferente

**Dependências:** nenhuma

---

### #5 — Criar empacotar/desempacotar mensagens

**Arquivo:** `tgs_server/message.py`

**Descrição:** Implementar funções para montar e desmontar o cabeçalho de rede de toda mensagem.

```python
def empacotar(tipo: int, dados: bytes) -> bytes:
    # retorna: [2 bytes tipo][4 bytes tamanho][N bytes dados]

def desempacotar(buffer: bytes) -> tuple[int, bytes]:
    # recebe: buffer com pelo menos 6 bytes
    # retorna: (tipo, payload)
```

**Formato:**
```
[2 bytes] tipo (unsigned short, big-endian)
[4 bytes] tamanho do payload (unsigned int, big-endian)
[N bytes] payload
```

**Critério de aceite:**
- [ ] `empacotar(5, b"abc")` retorna bytes com 6+3 = 9 bytes
- [ ] `desempacotar(resultado)` retorna `(5, b"abc")`
- [ ] Os primeiros 2 bytes decodificam o tipo correto em big-endian
- [ ] Os próximos 4 bytes decodificam o tamanho correto

**Dependências:** nenhuma

---

### #6 — Criar constantes dos tipos de mensagem

**Arquivo:** `tgs_server/message.py`

**Descrição:** Definir os números de cada tipo de mensagem como constantes do módulo `message.py`.

```python
MSG_AUTH_REQUEST = 1   # Cliente → AS
MSG_AUTH_REPLY   = 2   # AS → Cliente
MSG_TGS_REQUEST  = 3   # Cliente → TGS
MSG_TGS_REPLY    = 4   # TGS → Cliente
MSG_SVC_REQUEST  = 5   # Cliente → Serviço
MSG_SVC_REPLY    = 6   # Serviço → Cliente
MSG_CHAT         = 7   # Cliente → Serviço (dados do chat)
MSG_ECHO         = 8   # Serviço → Cliente (eco da mensagem)
MSG_ERROR        = 9   # Qualquer direção
```

**Critério de aceite:**
- [ ] `from tgs_server.message import MSG_AUTH_REQUEST` → `1`
- [ ] Todas as 9 constantes existem e são inteiros de 1 a 9

**Dependências:** nenhuma

---

### #7 — Criar funções de montar/desmontar tickets

**Arquivo:** `tgs_server/message.py`

**Descrição:** Implementar funções para criar e extrair tickets (TGT e Service Ticket). O formato binário interno do ticket (antes de cifrar).

```python
def criar_ticket(nome: bytes, chave_sessao: bytes,
                 timestamp: int, lifetime_min: int) -> bytes:
    """
    [8 bytes]  timestamp (Q, big-endian)
    [4 bytes]  lifetime_min (I, big-endian)
    [2 bytes]  len(nome) (H, big-endian)
    [N bytes]  nome do usuário
    [16 bytes] chave de sessão
    """

def extrair_ticket(blob: bytes) -> tuple[bytes, bytes, int, int]:
    """
    retorna: (nome, chave_sessao, timestamp, lifetime_min)
    """
```

**Critério de aceite:**
- [ ] `criar_ticket(b"alice", 16_bytes, 1000, 480)` retorna 8+4+2+5+16 = 35 bytes
- [ ] `extrair_ticket(resultado)` devolve `(b"alice", 16_bytes, 1000, 480)`
- [ ] Funciona com nomes de tamanhos diferentes (ex: "bob" vs "charlie")

**Dependências:** #6 (tipos de mensagem), #5 (empacotar)

---

### #8 — Script de geração de chaves mestras

**Arquivo:** `scripts/gerar_chaves.py`

**Descrição:** Script que gera 2 chaves aleatórias de 16 bytes usando `os.urandom(16)` e salva em arquivos na pasta `keys/`.

```
keys/as_master.key       → 16 bytes
keys/service_master.key  → 16 bytes
```

**Critério de aceite:**
- [ ] `python scripts/gerar_chaves.py` cria os 2 arquivos
- [ ] Cada arquivo tem exatamente 16 bytes
- [ ] Se executar de novo, sobrescreve os arquivos
- [ ] A pasta `keys/` é criada se não existir

**Dependências:** nenhuma

---

## 👤 Grupo 1 — Usuários

### #9 — Criar classe UserDB

**Arquivo:** `as_server/user_db.py`

**Descrição:** Classe que gerencia o arquivo `user_db.json`. Deve carregar, salvar e buscar usuários.

```python
class UserDB:
    def __init__(self, caminho: str):
        # Carrega user_db.json

    def buscar(self, nome: str) -> dict | None:
        # Retorna {"salt": hex, "hash": hex} ou None

    def cadastrar(self, nome: str, salt: bytes, hash_chave: bytes):
        # Adiciona novo usuário e salva no JSON
```

**Estrutura do JSON:**
```json
{
  "users": {
    "alice": {
      "salt": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
      "hash": "..."  # PBKDF2(senha, salt) em hex
    }
  }
}
```

**Critério de aceite:**
- [ ] `buscar("alice")` retorna dict com salt e hash se existir
- [ ] `buscar("inexistente")` retorna `None`
- [ ] `cadastrar()` persiste no arquivo entre execuções
- [ ] JSON é legível por humanos

**Dependências:** #1 (config — caminho do arquivo)

---

### #10 — Script de cadastro de usuário

**Arquivo:** `scripts/cadastrar_usuario.py`

**Descrição:** Script CLI que pergunta nome de usuário e senha, gera salt, deriva chave com PBKDF2 e salva no `user_db.json`. Usa `UserDB` e `derivar_chave`.

```bash
$ python scripts/cadastrar_usuario.py
Usuário: alice
Senha: [oculta]
Usuário alice cadastrado com sucesso!
```

**Critério de aceite:**
- [ ] `python scripts/cadastrar_usuario.py` cria entrada no JSON
- [ ] Salt é diferente para cada usuário
- [ ] Hash armazenado corresponde a PBKDF2(senha, salt)
- [ ] Se usuário já existe, pergunta se quer sobrescrever

**Dependências:** #9 (UserDB), #4 (derivar_chave)

---

## 🖥️ Grupo 2 — AS (Authentication Server)

### #11 — Esqueleto do AS (socket + loop)

**Arquivo:** `as_server/as_server.py`

**Descrição:** Criar classe `ASServer` com servidor TCP que aceita conexões e atende cada cliente em uma thread separada.

```python
class ASServer:
    def __init__(self, host, porta, user_db, chave_mestra):
        ...

    def iniciar(self):
        # bind, listen, accept loop, threading.Thread por cliente

    def atender_cliente(self, con, addr):
        # placeholder: apenas imprime "cliente conectou" e fecha
```

**Critério de aceite:**
- [ ] `ASServer("127.0.0.1", 5450, ...).iniciar()` roda sem erro
- [ ] Servidor escuta na porta 5450
- [ ] `nc 127.0.0.1 5450` consegue conectar
- [ ] Servidor aceita múltiplas conexões simultâneas (testar com 2 `nc`)
- [ ] Thread é limpa quando cliente desconecta

**Dependências:** #1 (config), #9 (UserDB)

---

### #12 — Handler: receber MSG_AUTH_REQUEST

**Arquivo:** `as_server/as_server.py` (método `atender_cliente`)

**Descrição:** Implementar a recepção da mensagem. Ler o cabeçalho de 6 bytes, identificar tipo `MSG_AUTH_REQUEST`, extrair nome do usuário, buscar no UserDB.

```python
def atender_cliente(self, con, addr):
    # 1. Recebe 6 bytes de header (usar função recv_tudo)
    tipo, payload = desempacotar(header)
    # 2. Verifica se tipo == MSG_AUTH_REQUEST
    # 3. Extrai nome do usuário de payload
    # 4. Busca no UserDB
    #    Se não existir → enviar MSG_ERROR e fechar
```

**Critério de aceite:**
- [ ] Cliente envia `empacotar(MSG_AUTH_REQUEST, b"alice")` → servidor extrai "alice"
- [ ] Usuário inexistente → servidor responde com `MSG_ERROR`
- [ ] Tipo inesperado → servidor responde com `MSG_ERROR`

**Dependências:** #11 (esqueleto AS), #5 (empacotar/desempacotar), #6 (tipos)

---

### #13 — Handler: derivar chave do cliente e gerar session key

**Arquivo:** `as_server/as_server.py` (método `atender_cliente`)

**Descrição:** Após encontrar o usuário, derivar a chave do cliente a partir da senha armazenada (hash + salt — o AS deriva a mesma chave que o cliente teria) e gerar `K_c_AS = os.urandom(16)`.

```python
# 5. Recupera salt e hash do user_db
# 6. Deriva chave: a partir da senha? Não! O AS precisa
#    verificar que o cliente sabe a senha.
#    Na verdade, o AS precisa derivar a mesma chave que o
#    cliente: PBKDF2(senha_digitada, salt) para cifrar K_c_AS.
#    Mas o AS não TEM a senha. Ele tem o hash.
#    → SOLUÇÃO: O AS usa o hash_armazenado como chave?
#    → Na verdade, o hash já É PBKDF2(senha, salt).
#      O AS pode usar esse hash como a chave K_c.
```

> **Nota:** discutir com o grupo se o AS armazena o hash PBKDF2 e o usa diretamente como chave, ou se o fluxo é diferente. Uma abordagem comum didática: o AS guarda `PBKDF2(senha, salt)` como hash, e re-deriva pra ter certeza, ou simplesmente usa o hash como chave.

**Critério de aceite:**
- [ ] Gera `K_c_AS = os.urandom(16)` não nulo
- [ ] Deriva a chave do cliente corretamente (a mesma que o cliente obtém ao digitar a senha)

**Dependências:** #12 (handler receber request), #4 (derivar_chave)

---

### #14 — Handler: montar e cifrar TGT

**Arquivo:** `as_server/as_server.py` (método `atender_cliente`)

**Descrição:** Montar o TGT com `criar_ticket(nome, K_c_AS, timestamp, lifetime)` e cifrar com `as_master_key`.

```python
# 7. Monta TGT: ticket = criar_ticket(nome, K_c_AS, now, LIFETIME_TICKET)
# 8. Cifra TGT: tgt_cif = cifrar_aes_gcm(as_master_key, ticket)
```

**Critério de aceite:**
- [ ] TGT contém nome, K_c_AS, timestamp e lifetime corretos
- [ ] TGT cifrado tem nonce(12) + ciphertext
- [ ] `extrair_ticket(decifrar_aes_gcm(as_master_key, tgt_cif))` devolve os campos originais

**Dependências:** #13 (derivar chave), #7 (criar_ticket), #2 (cifrar aes-gcm)

---

### #15 — Handler: cifrar session key e enviar resposta

**Arquivo:** `as_server/as_server.py` (método `atender_cliente`)

**Descrição:** Cifrar `K_c_AS` com a chave derivada da senha do cliente, montar payload com `TGT_cif + K_c_AS_cif`, e enviar `MSG_AUTH_REPLY`.

```python
# 9. Cifra K_c_AS: k_c_as_cif = cifrar_aes_gcm(chave_cliente, K_c_AS)
# 10. Monta payload: tgt_cif + k_c_as_cif
# 11. Envia: con.send(empacotar(MSG_AUTH_REPLY, payload))
# 12. Fecha conexão
```

**Critério de aceite:**
- [ ] `MSG_AUTH_REPLY` é enviada com tipo 2
- [ ] Payload contém TGT cifrado (29+ bytes) + K_c_AS cifrado (28 bytes)
- [ ] Cliente consegue decifrar K_c_AS com a própria chave
- [ ] Cliente consegue decifrar TGT com as_master_key (quem tem acesso)

**Dependências:** #14 (montar TGT), #2 (cifrar), #5 (empacotar)

---

## 🎫 Grupo 3 — TGS (Ticket Granting Server)

### #16 — Esqueleto do TGS (socket + loop)

**Arquivo:** `tgs_server/tgs_server.py`

**Descrição:** Classe `TGSServer` similar ao AS — servidor TCP com thread por cliente.

```python
class TGSServer:
    def __init__(self, host, porta, chave_as, chave_servico):
        self.chave_as = chave_as
        self.chave_servico = chave_servico

    def iniciar(self):
        # bind, listen, accept, threading por cliente

    def atender_cliente(self, con, addr):
        # placeholder
```

**Critério de aceite:**
- [ ] Servidor escuta na porta 5451
- [ ] `nc 127.0.0.1 5451` conecta
- [ ] Aceita múltiplas conexões simultâneas

**Dependências:** #1 (config)

---

### #17 — Handler: receber MSG_TGS_REQUEST

**Arquivo:** `tgs_server/tgs_server.py` (método `atender_cliente`)

**Descrição:** Receber a requisição do TGS, extrair TGT cifrado + nome do serviço.

```python
def atender_cliente(self, con, addr):
    # 1. Recebe header + payload
    # 2. Confirma tipo == MSG_TGS_REQUEST
    # 3. Extrai: tgt_cif(12+16+...) + nome_servico(bytes)
    #    (não tem separador — definir com o grupo o tamanho do TGT ou
    #     usar um separador. Sugestão: TGT cifrado sempre é nonce(12) + ticket_cif,
    #     e ticket_cif tem tamanho fixo = 8+4+2+len(nome)+16+16(tag AES)
    #     → Ou melhor: colocar o tam_tgt como 2 bytes no início)
```

> **Nota:** definir com o grupo como separar TGT cifrado de nome_servico. Sugestão: incluir `[2 bytes] tamanho do TGT cifrado` no início do payload.

**Critério de aceite:**
- [ ] Recebe MSG_TGS_REQUEST e extrai TGT + nome_servico
- [ ] Se tipo inesperado, responde MSG_ERROR

**Dependências:** #16 (esqueleto TGS), #5 (empacotar/desempacotar)

---

### #18 — Handler: decifrar e validar TGT

**Arquivo:** `tgs_server/tgs_server.py`

**Descrição:** Decifrar o TGT com `chave_as`, extrair campos, verificar expiração.

```python
# 4. Decifra TGT: ticket = decifrar_aes_gcm(self.chave_as, tgt_cif)
# 5. Extrai: nome, K_c_AS, ts, lifetime = extrair_ticket(ticket)
# 6. Verifica: ts + lifetime*60 > time.time()?
#    Se expirado → MSG_ERROR
```

**Critério de aceite:**
- [ ] Decifra TGT corretamente com chave do AS
- [ ] TGT expirado é rejeitado com MSG_ERROR
- [ ] TGT válido permite continuar o fluxo

**Dependências:** #17 (receber request), #3 (decifrar), #7 (extrair_ticket)

---

### #19 — Handler: gerar Service Ticket e session key

**Arquivo:** `tgs_server/tgs_server.py`

**Descrição:** Gerar nova session key `K_c_svc`, montar Service Ticket com os mesmos campos do TGT mas nova chave, cifrar com `chave_servico`.

```python
# 7. Gera K_c_svc = os.urandom(16)
# 8. Monta Service Ticket: criar_ticket(nome, K_c_svc, now, LIFETIME_TICKET)
# 9. Cifra Service Ticket: cifrar_aes_gcm(self.chave_servico, ticket)
```

**Critério de aceite:**
- [ ] Service Ticket contém nome, K_c_svc, timestamp, lifetime
- [ ] `decifrar_aes_gcm(service_master_key, ticket_cif)` funciona
- [ ] K_c_svc é diferente de K_c_AS

**Dependências:** #18 (decifrar TGT), #7 (criar_ticket), #2 (cifrar)

---

### #20 — Handler: montar e enviar resposta do TGS

**Arquivo:** `tgs_server/tgs_server.py`

**Descrição:** Cifrar `K_c_svc` com `K_c_AS` (a session key do TGT), montar payload, enviar `MSG_TGS_REPLY`.

```python
# 10. Cifra K_c_svc com K_c_AS
# 11. Payload = svc_ticket_cif + k_c_svc_cif
# 12. Envia MSG_TGS_REPLY
```

**Critério de aceite:**
- [ ] `MSG_TGS_REPLY` é enviada com tipo 4
- [ ] Cliente consegue decifrar K_c_svc com K_c_AS
- [ ] Cliente consegue usar K_c_svc pra decifrar o Service Ticket (não — o ticket é cifrado com service_key, o cliente não decifra o ticket)

**Dependências:** #19 (gerar service ticket), #2 (cifrar), #5 (empacotar)

---

## 🔐 Grupo 4 — Serviço Protegido

### #21 — Esqueleto do Serviço (socket + loop)

**Arquivo:** `service/service_server.py`

**Descrição:** Classe `ServicoKerberos` — servidor TCP com thread por cliente.

```python
class ServicoKerberos:
    def __init__(self, host, porta, chave_servico):
        self.chave_servico = chave_servico

    def iniciar(self):
        # bind, listen, accept, threading por cliente

    def atender_cliente(self, con, addr):
        # placeholder
```

**Critério de aceite:**
- [ ] Servidor escuta na porta 5452
- [ ] `nc 127.0.0.1 5452` conecta
- [ ] Aceita múltiplas conexões

**Dependências:** #1 (config)

---

### #22 — Handler: receber MSG_SVC_REQUEST

**Arquivo:** `service/service_server.py`

**Descrição:** Receber requisição, extrair Service Ticket cifrado + authenticator cifrado.

```python
def atender_cliente(self, con, addr):
    # 1. Recebe MSG_SVC_REQUEST
    # 2. Extrai: svc_ticket_cif + authenticator_cif
```

**Critério de aceite:**
- [ ] Extrai corretamente ticket e authenticator
- [ ] Tipo inesperado → MSG_ERROR

**Dependências:** #21 (esqueleto), #5 (desempacotar)

---

### #23 — Handler: decifrar e validar Service Ticket

**Arquivo:** `service/service_server.py`

**Descrição:** Decifrar o Service Ticket com `chave_servico`, extrair nome e `K_c_svc`.

```python
# 3. Decifra Service Ticket: decifrar_aes_gcm(self.chave_servico, ticket_cif)
# 4. Extrai: nome, K_c_svc, ts, lifetime = extrair_ticket(ticket)
# 5. Verifica expiração
```

**Critério de aceite:**
- [ ] Ticket válido → extrai nome e K_c_svc
- [ ] Ticket expirado → MSG_ERROR
- [ ] Ticket cifrado com chave errada → erro de decifra (exceção capturada)

**Dependências:** #22 (receber request), #3 (decifrar), #7 (extrair_ticket)

---

### #24 — Handler: decifrar e validar authenticator

**Arquivo:** `service/service_server.py`

**Descrição:** Decifrar o authenticator com `K_c_svc`, verificar se nome coincide com o do ticket e se timestamp está dentro da janela.

```python
# 6. Decifra authenticator: decifrar_aes_gcm(K_c_svc, auth_cif)
# 7. Extrai: nome_auth (2+*), ts_auth (8)
# 8. Verifica: nome_auth == nome_ticket?
# 9. Verifica: |time.time() - ts_auth| <= JANELA_AUTH?
```

Formato do authenticator (antes de cifrar):
```
[2 bytes]  len(nome)
[N bytes]  nome
[8 bytes]  timestamp (Q, big-endian)
```

**Critério de aceite:**
- [ ] Nome do authenticator diferente do ticket → MSG_ERROR
- [ ] Timestamp fora da janela → MSG_ERROR (indica replay)
- [ ] Authenticator inválido (tentativa de forjar) → exceção de decifra

**Dependências:** #23 (decifrar ticket), #3 (decifrar)

---

### #25 — Handler: autenticação mútua

**Arquivo:** `service/service_server.py`

**Descrição:** Provar ao cliente que o serviço conhece `K_c_svc`. Pegar timestamp do authenticator, somar 1, cifrar com `K_c_svc` e enviar `MSG_SVC_REPLY`.

```python
# 10. timestamp_resposta = ts_auth + 1
# 11. resposta_cif = cifrar_aes_gcm(K_c_svc, struct.pack('>Q', timestamp_resposta))
# 12. Envia MSG_SVC_REPLY(resposta_cif)
```

**Critério de aceite:**
- [ ] `MSG_SVC_REPLY` é enviada com tipo 6
- [ ] Payload = nonce(12) + ciphertext(8+16) = 36 bytes
- [ ] Cliente consegue decifrar e confirmar que é `ts_auth + 1`

**Dependências:** #24 (validar authenticator), #2 (cifrar), #5 (empacotar)

---

### #26 — Handler: echo chat

**Arquivo:** `service/handler.py`

**Descrição:** Após autenticação mútua, entrar em loop recebendo `MSG_CHAT` e respondendo `MSG_ECHO` com o mesmo texto.

```python
def loop_chat(con, K_c_svc):
    while True:
        tipo, payload = receber_mensagem(con)
        if tipo == MSG_CHAT:
            texto = payload  # mensagem em claro (ou cifrada? decidir com grupo)
            # Sugestão: chat em claro após autenticação (foco no Kerberos)
            con.send(empacotar(MSG_ECHO, b"eco: " + texto))
        elif tipo == MSG_ERROR:
            break
```

**Critério de aceite:**
- [ ] Cliente envia MSG_CHAT → recebe MSG_ECHO de volta
- [ ] Chat pode continuar por várias mensagens
- [ ] Cliente pode encerrar a qualquer momento

**Dependências:** #25 (autenticação mútua OK), #5 (empacotar)

---

### #27 — Script de teste de ataque

**Arquivo:** `scripts/testar_ataque.py`

**Descrição:** Script que simula ataques básicos contra o sistema para demonstrar que as proteções funcionam.

**Cenários de ataque:**
1. **Replay de TGT**: capturar um TGT legítimo e reenviar pro TGS depois de expirado
2. **Replay de authenticator**: capturar um authenticator e reenviar pro Serviço
3. **Ticket com chave errada**: enviar um Service Ticket cifrado com chave aleatória
4. **Usuário inexistente**: tentar se autenticar com nome que não está no UserDB

```bash
$ python scripts/testar_ataque.py
[TESTE 1] Replay de TGT expirado → BLOQUEADO ✓
[TESTE 2] Replay de authenticator → BLOQUEADO ✓
[TESTE 3] Ticket com chave errada → BLOQUEADO ✓
[TESTE 4] Usuário inexistente → BLOQUEADO ✓
```

**Critério de aceite:**
- [ ] Cada teste produz saída clara de "passou" ou "falhou"
- [ ] Testes rodam sem intervenção manual
- [ ] Código comentado explicando cada ataque

**Dependências:** #18 (TGS validar TGT), #24 (Serviço validar authenticator), #5 (empacotar)

---

## 💻 Grupo 5 — Cliente

### #28 — Cliente: conectar no AS e enviar MSG_AUTH_REQUEST

**Arquivo:** `client/client.py`

**Descrição:** Implementar a primeira etapa do fluxo: conectar no AS, enviar nome do usuário, receber resposta.

```python
import socket
from common.config import AS_HOST, AS_PORT
from tgs_server.message import empacotar, desempacotar, MSG_AUTH_REQUEST, MSG_ERROR

# 1. Pede nome ao usuário
# 2. Conecta em (AS_HOST, AS_PORT)
# 3. Envia MSG_AUTH_REQUEST(nome)
# 4. Recebe resposta
# 5. Se for MSG_ERROR, exibe e sai
# 6. Se for MSG_AUTH_REPLY, guarda TGT_cif + K_c_AS_cif
# 7. Fecha conexão
```

**Critério de aceite:**
- [ ] Conecta no AS na porta 5450
- [ ] Envia requisição com tipo 1
- [ ] Recebe resposta e identifica se é erro ou sucesso

**Dependências:** #15 (AS responder), #5 (empacotar/desempacotar), #6 (tipos), #1 (config)

---

### #29 — Cliente: derivar chave e decifrar K_c_AS

**Arquivo:** `client/client.py`

**Descrição:** Após receber a resposta do AS, ler a senha do usuário, derivar a chave com PBKDF2, decifrar `K_c_AS`.

```python
# 8. Pede senha (getpass)
# 9. Deriva chave: chave = derivar_chave(senha.encode(), bytes.fromhex(salt))
#    (como o cliente sabe o salt? → definir: ou vem no MSG_AUTH_REPLY
#     ou o cliente busca o salt primeiro. Sugestão: incluir salt na resposta)
# 10. Decifra K_c_AS: K_c_AS = decifrar_aes_gcm(chave, K_c_AS_cif)
```

> **Nota sobre o salt:** o cliente precisa saber o salt para derivar a mesma chave. Opções:
> 1. AS inclui o salt na resposta `MSG_AUTH_REPLY`
> 2. Cliente busca o salt primeiro em uma mensagem separada
>
> Sugestão: incluir `salt(16)` no payload de `MSG_AUTH_REPLY`, antes do TGT.

**Critério de aceite:**
- [ ] Decifra K_c_AS com sucesso
- [ ] Senha errada → erro de decifra (AES-GCM rejeita)
- [ ] K_c_AS tem 16 bytes

**Dependências:** #28 (receber resposta AS), #4 (derivar_chave), #3 (decifrar)

---

### #30 — Cliente: conectar no TGS

**Arquivo:** `client/client.py`

**Descrição:** Segunda etapa: conectar no TGS, enviar TGT cifrado + nome do serviço, receber Service Ticket.

```python
# 11. Conecta em (TGS_HOST, TGS_PORT)
# 12. Envia MSG_TGS_REQUEST(TGT_cif + b"chat")
# 13. Recebe resposta
# 14. Se MSG_TGS_REPLY: extrai svc_ticket_cif + K_c_svc_cif
# 15. Decifra K_c_svc: decifrar_aes_gcm(K_c_AS, K_c_svc_cif)
```

**Critério de aceite:**
- [ ] Conecta no TGS na porta 5451
- [ ] Envia requisição com tipo 3
- [ ] Recebe MSG_TGS_REPLY
- [ ] Decifra K_c_svc com sucesso

**Dependências:** #20 (TGS responder), #29 (ter K_c_AS), #5 (empacotar)

---

### #31 — Cliente: conectar no Serviço com autenticação mútua

**Arquivo:** `client/client.py`

**Descrição:** Terceira etapa: montar authenticator, conectar no Serviço, enviar ticket + authenticator, verificar autenticação mútua.

```python
# 16. Monta authenticator: nome(2+*) + timestamp(8), cifra com K_c_svc
# 17. Conecta em (SVC_HOST, SVC_PORT)
# 18. Envia MSG_SVC_REQUEST(svc_ticket_cif + authenticator_cif)
# 19. Recebe MSG_SVC_REPLY
# 20. Decifra: decifrar_aes_gcm(K_c_svc, payload)
# 21. Extrai timestamp_resposta
# 22. Verifica: timestamp_resposta == timestamp_original + 1?
```

**Critério de aceite:**
- [ ] Authenticator cifrado com K_c_svc
- [ ] Envia MSG_SVC_REQUEST com tipo 5
- [ ] Serviço responde com MSG_SVC_REPLY
- [ ] Cliente confirma timestamp+1 → "Autenticação mútua OK!"
- [ ] Se timestamp estiver errado → "Falha na autenticação mútua!"

**Dependências:** #30 (ter K_c_svc e Service Ticket), #25 (Serviço responder), #2 (cifrar), #3 (decifrar), #5 (empacotar)

---

### #32 — Cliente: interface de terminal (UI)

**Arquivo:** `client/ui.py`

**Descrição:** Implementar a interface de terminal para o usuário.

```python
def perguntar_usuario() -> str:
    # input("Usuário: ")

def perguntar_senha() -> str:
    # getpass.getpass("Senha: ")

def mostrar_status(msg: str):
    # print(f"[{timestamp}] {msg}")

def menu_chat():
    # loop: input("> ") → enviar MSG_CHAT → print eco
    # digitar "sair" encerra
```

**Critério de aceite:**
- [ ] Mostra mensagens claras pro usuário
- [ ] Senha não aparece ao digitar
- [ ] Chat funcional com input/print

**Dependências:** nenhuma (só Python puro)

---

### #33 — Cliente: orquestrar fluxo completo

**Arquivo:** `client/client.py` (método principal)

**Descrição:** Juntar todas as etapas no método `autenticar()` e no `main()`.

```python
class ClienteKerberos:
    def autenticar(self):
        self.passo1_conectar_as()
        self.passo2_decifrar_k_as()
        self.passo3_conectar_tgs()
        self.passo4_conectar_servico()
        self.passo5_autenticacao_mutua()
        print("[OK] Conectado! Iniciando chat...")
        self.loop_chat()

if __name__ == "__main__":
    cliente = ClienteKerberos()
    cliente.autenticar()
```

**Critério de aceite:**
- [ ] `python client/client.py` executa o fluxo completo do zero
- [ ] Fluxo: AS → TGS → Serviço → Chat
- [ ] Mensagens de status claras em cada etapa
- [ ] Erros são tratados com mensagem amigável (não traceback)

**Dependências:** #28 a #32 completas

---

## 📝 Grupo 6 — Documentação e Relatório

### #34 — README final

**Arquivo:** `README.md`

**Descrição:** Manter README atualizado com instruções de execução, estrutura do projeto, formato das mensagens, responsabilidades e tecnologias.

**Critério de aceite:**
- [ ] Instruções passo a passo pra rodar o projeto
- [ ] Formato das mensagens documentado
- [ ] Divisão de issues explicada

**Dependências:** projeto funcionando

---

### #35 a #40 — Relatório e Vídeo

> Issues abertas perto da entrega. Cada pessoa contribui com as seções que implementou.

| # | Seção | Responsável |
|---|-------|-------------|
| 35 | Arquitetura geral | Quem fez issues do Grupo 0 |
| 36 | KDF e AS | Quem fez issues do Grupo 2 |
| 37 | TGS e fluxo de tickets | Quem fez issues do Grupo 3 |
| 38 | Serviço e autenticação mútua | Quem fez issues do Grupo 4 |
| 39 | Algoritmos criptográficos | Qualquer pessoa |
| 40 | Dificuldades e conclusão | TODOS |
