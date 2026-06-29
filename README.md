# Kerberos Chat — Autenticação Kerberos com Chat Simples

**Disciplina:** Segurança Computacional — UnB  
**Professor:** Prof. Roberto Rodrigues Filho  
**Grupo:** Welton (Cliente/Integração) + Pessoas A (AS), B (TGS), C (Serviço)

---

## Descrição

Implementação didática do **protocolo Kerberos** utilizando exclusivamente criptografia de chave simétrica. O sistema é composto por quatro componentes que implementam o fluxo completo de autenticação:

1. **Authentication Server (AS)** — emite o Ticket Granting Ticket (TGT)
2. **Ticket Granting Server (TGS)** — valida o TGT e emite o Service Ticket
3. **Serviço Protegido** — valida o Service Ticket e realiza autenticação mútua
4. **Cliente** — orquestra o fluxo AS → TGS → Serviço

---

## Estrutura do Projeto

```
kerberos-chat/
│
├── common/                         ← Código compartilhado (todos usam)
│   ├── config.py                   # Portas, hosts, constantes  [WELTON]
│   └── crypto.py                   # AES-GCM, PBKDF2           [WELTON]
│
├── as_server/                      ← Pessoa A — Authentication Server
│   ├── as_server.py                # Servidor TCP que emite TGTs
│   ├── kdf.py                      # PBKDF2: senha → chave de 16 bytes
│   └── user_db.py                  # Cadastro de usuários (JSON)
│
├── tgs_server/                     ← Pessoa B — Ticket Granting Server
│   ├── tgs_server.py               # Valida TGT, emite Service Ticket
│   └── message.py                  # Empacotar/desempacotar, tipos, tickets
│
├── service/                        ← Pessoa C — Serviço Protegido
│   ├── service_server.py           # Valida Service Ticket + autenticação mútua
│   └── handler.py                  # Lógica do chat (echo)
│
├── client/                         ← Welton — Cliente
│   ├── client.py                   # Orquestra fluxo Kerberos completo
│   └── ui.py                       # Interface de terminal
│
├── keys/                           ← Chaves mestras (geradas na execução)
│   ├── as_master.key               # [PESSOA A]
│   ├── tgs_master.key              # [PESSOA B]
│   └── service_master.key          # [PESSOA C]
│
├── scripts/
│   ├── gerar_chaves.py             # [PESSOA A] Gera as 3 chaves mestras
│   ├── cadastrar_usuario.py        # [PESSOA A] Adiciona usuário ao JSON
│   └── testar_ataque.py            # [PESSOA C] Simula ataques
│
├── requirements.txt                # cryptography
├── .gitignore
└── README.md                       # [WELTON]
```

---

## Tecnologias Utilizadas

| Componente | Tecnologia | Por quê |
|------------|-----------|---------|
| **Linguagem** | Python 3 | Todos conhecem |
| **Criptografia simétrica** | AES-128-GCM (`cryptography`) | Cifra + autentica em 1 operação |
| **Derivação de chave** | PBKDF2-HMAC-SHA256 (`cryptography`) | Nativo, bem documentado, 100.000 iterações |
| **Serialização** | `struct.pack` / `struct.unpack` | Binário, sem dependências externas |
| **Rede** | `socket` TCP puro | Simples, didático |
| **Concorrência** | `threading.Thread` | Servidores atendem múltiplos clientes |
| **Banco de usuários** | JSON (`user_db.json`) | Arquivo texto, sem banco de dados |
| **Interface** | Terminal (`input()` / `print()`) | Sem GUI, mínimo viável |

---

## Portas

| Servidor | Host | Porta |
|----------|------|-------|
| Authentication Server (AS) | 127.0.0.1 | 5550 |
| Ticket Granting Server (TGS) | 127.0.0.1 | 5551 |
| Serviço Protegido | 127.0.0.1 | 5552 |

---

## Fluxo Kerberos

```
CLIENTE                    AS                        TGS                    SERVIÇO
  │                        │                         │                       │
  ├── MSG_AUTH_REQUEST ───►│                         │                       │
  │   "alice"              │                         │                       │
  │                        │  Deriva chave da senha  │                       │
  │                        │  Gera K_c_AS            │                       │
  │                        │  Monta TGT cifrado      │                       │
  │◄── MSG_AUTH_REPLY ─────┤                         │                       │
  │   TGT || K_c_AS_cif    │                         │                       │
  │                        │                         │                       │
  ├── MSG_TGS_REQUEST ─────►                         │                       │
  │   TGT || "chat"                                  │                       │
  │                                                  │  Decifra TGT          │
  │                                                  │  Verifica validade    │
  │                                                  │  Gera K_c_svc         │
  │                                                  │  Monta SvcTicket      │
  │◄── MSG_TGS_REPLY ────────────────────────────────┤                       │
  │   SvcTicket || K_c_svc_cif                                              │
  │                                                                          │
  ├── MSG_SVC_REQUEST ─────────────────────────────────────────────────────►│
  │   SvcTicket || Authenticator_cif                                        │
  │                                                                          │  Decifra ticket
  │                                                                          │  Decifra authenticator
  │                                                                          │  Verifica nome + timestamp
  │◄── MSG_SVC_REPLY ──────────────────────────────────────────────────────┤  Soma 1 no timestamp
  │   timestamp+1 cifrado                                                    │  Cifra e envia
  │                                                                          │
  │  Verifica timestamp+1                                                    │
  │  -> Autenticação mútua OK!                                              │
  │                                                                          │
  ├── MSG_CHAT ────────────────────────────────────────────────────────────►│
  │  "Olá, servidor!"                                                        │
  │◄── MSG_ECHO ────────────────────────────────────────────────────────────┤
  │  "eco: Olá, servidor!"                                                   │
```

---

## Responsabilidades por Pessoa

### Pessoa A — Authentication Server (AS)
**Arquivos:** `as_server/as_server.py`, `as_server/kdf.py`, `as_server/user_db.py`
- Implementa KDF (PBKDF2) para derivar chave da senha
- Gerencia cadastro de usuários em JSON (username + salt + hash)
- Servidor TCP que emite TGT cifrado com chave mestra do AS
- **Gera e compartilha:** `keys/as_master.key`
- **Também faz:** `scripts/gerar_chaves.py` e `scripts/cadastrar_usuario.py`

### Pessoa B — Ticket Granting Server (TGS)
**Arquivos:** `tgs_server/tgs_server.py`, `tgs_server/message.py`
- Valida TGT (decifra com chave do AS, verifica expiração)
- Emite Service Ticket cifrado com chave mestra do Serviço
- **Depende de:** `keys/as_master.key` (da Pessoa A) e `keys/service_master.key` (da Pessoa C)

### Pessoa C — Serviço Protegido
**Arquivos:** `service/service_server.py`, `service/handler.py`, `scripts/testar_ataque.py`
- Valida Service Ticket
- Implementa autenticação mútua (timestamp+1 cifrado)
- Serviço echo simples para demonstrar o canal autenticado
- **Gera e compartilha:** `keys/service_master.key`

### Welton — Cliente + crypto/config
**Arquivos:** `common/crypto.py`, `common/config.py`, `client/client.py`, `client/ui.py`, `README.md`
- Pacote `common/` com funções criptográficas (`crypto.py`) e configuração (`config.py`)
- Cliente que orquestra fluxo Kerberos completo
- README e estrutura do projeto

---

## Formato das Mensagens

Toda mensagem trafega na rede com um **cabeçalho de 6 bytes** seguido do payload:

```
[2 bytes] tipo da mensagem (unsigned short, big-endian)
[4 bytes] tamanho do payload em bytes (unsigned int, big-endian)
[N bytes] payload (o conteúdo em si)
```

Esse cabeçalho é montado pela função `empacotar()` em `tgs_server/message.py` (Pessoa B).

### Tipos de Mensagem

| # | Constante | Origem → Destino | Payload | Quem define |
|---|-----------|-------------------|---------|-------------|
| 1 | `MSG_AUTH_REQUEST` | Cliente → AS | `nome_usuario (bytes)` | Pessoa A |
| 2 | `MSG_AUTH_REPLY` | AS → Cliente | `TGT_cif(12+*) + K_c_AS_cif(12+*)` | Pessoa A |
| 3 | `MSG_TGS_REQUEST` | Cliente → TGS | `TGT_cif(12+*) + nome_servico(bytes)` | Pessoa B |
| 4 | `MSG_TGS_REPLY` | TGS → Cliente | `svc_ticket_cif(12+*) + K_c_svc_cif(12+*)` | Pessoa B |
| 5 | `MSG_SVC_REQUEST` | Cliente → Serviço | `svc_ticket_cif(12+*) + authenticator_cif(12+*)` | Pessoa C |
| 6 | `MSG_SVC_REPLY` | Serviço → Cliente | `timestamp+1 cifrado(12+8)` | Pessoa C |
| 7 | `MSG_CHAT` | Cliente → Serviço | `texto (bytes)` | TODOS |
| 8 | `MSG_ECHO` | Serviço → Cliente | `eco do texto (bytes)` | TODOS |
| 9 | `MSG_ERROR` | Qualquer → Qualquer | `mensagem de erro (bytes)` | TODOS |

> `(12+*)` = nonce AES-GCM (12 bytes) + ciphertext de tamanho variável  
> `(12+8)` = nonce (12 bytes) + ciphertext de 8 bytes (apenas um timestamp)

### Observações importantes

- **MSG_AUTH_REPLY**: contém **dois blocos** cifrados independentemente — o TGT (cifrado com `as_master_key`) e a session key (cifrada com a chave derivada da senha do usuário). Cada bloco tem seu próprio nonce de 12 bytes.
- **MSG_TGS_REPLY**: mesma lógica — Service Ticket cifrado com `service_master_key` e nova session key cifrada com a chave do TGT anterior.
- **MSG_SVC_REQUEST**: o authenticator é a estrutura `{nome_usuario(2+*) + timestamp(8)}` cifrada com `K_c_svc`.
- **MSG_SVC_REPLY**: o timestamp do authenticator **+1**, cifrado com `K_c_svc` — prova que o serviço conhece a chave (autenticação mútua).
- O `nome_servico` em `MSG_TGS_REQUEST` é um identificador simples em bytes (ex: `b"chat"`, `b"arquivos"`).

---

## Como Executar

### 1. Instalar dependências

```bash
cd kerberos-chat
pip install -r requirements.txt
```

### 2. Gerar chaves mestras (Pessoa A)

```bash
python scripts/gerar_chaves.py
```

### 3. Cadastrar usuários (Pessoa A)

```bash
python scripts/cadastrar_usuario.py
```

### 4. Iniciar os servidores (em terminais separados)

```bash
# Terminal 1 — AS
python as_server/as_server.py

# Terminal 2 — TGS
python tgs_server/tgs_server.py

# Terminal 3 — Serviço
python service/service_server.py
```

### 5. Executar o cliente

```bash
python client/client.py
```

---

## Algoritmos

### AES-128-GCM
- Cifra simétrica autenticada (confidencialidade + integridade)
- Nonce de 12 bytes aleatório a cada operação
- Uma única chamada = cifra + tag de autenticação

### PBKDF2-HMAC-SHA256
- Deriva uma chave de 16 bytes a partir de senha + salt
- 100.000 iterações para dificultar ataques de força bruta
- Salt único de 16 bytes por usuário

---

## Relatório (seções)

| Seção | Responsável |
|-------|-------------|
| 1. Arquitetura geral | Welton |
| 2. KDF adotado (PBKDF2) | Pessoa A |
| 3. Implementação do AS | Pessoa A |
| 4. Implementação do TGS | Pessoa B |
| 5. Fluxo de tickets | Pessoa B |
| 6. Autenticação mútua | Pessoa C |
| 7. Algoritmos criptográficos | Pessoa C |
| 8. Dificuldades + aprendizados | TODOS |
| 9. Conclusão | Welton |

---

## Vídeo (apresentação)

| Pessoa | O que mostrar |
|--------|---------------|
| Pessoa A | KDF e AS: cadastrar usuário, login, emissão de TGT |
| Pessoa B | TGS: validar TGT, emitir Service Ticket |
| Pessoa C | Serviço: validar ticket, autenticação mútua |
| Welton | Visão geral do fluxo completo + teste de ataque |
