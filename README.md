# Kerberos Chat — Autenticação Kerberos com Chat Simples

**Disciplina:** Segurança Computacional — UnB  
**Professor:** Prof. Roberto Rodrigues Filho  
**Grupo:** 4 integrantes

---

## Descrição

Implementação didática do **protocolo Kerberos** utilizando exclusivamente criptografia de chave simétrica. O sistema é composto por quatro componentes que implementam o fluxo completo de autenticação:

1. **Authentication Server (AS)** — emite o Ticket Granting Ticket (TGT)
2. **Ticket Granting Server (TGS)** — valida o TGT e emite o Service Ticket
3. **Serviço Protegido** — valida o Service Ticket e realiza autenticação mútua
4. **Cliente** — orquestra o fluxo AS → TGS → Serviço

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

## Como Executar

> Pré-requisito: Python 3 com virtualenv. Execute uma vez:
> ```bash
> cd kerberos-chat
> python3 -m venv .venv
> source .venv/bin/activate
> pip install -e .
> ```

### 1. Gerar chaves mestras

```bash
gerar-chaves
```

Gera `keys/as_master.key` e `keys/service_master.key` (16 bytes cada).

### 2. Cadastrar usuários

```bash
cadastrar-usuario
```

### 3. Iniciar os servidores (em terminais separados)

```bash
# Terminal 1 — AS (porta 5450)
as-server

# Terminal 2 — TGS (porta 5451)
tgs-server

# Terminal 3 — Serviço (porta 5452)
service-server
```

### 4. Executar o cliente

```bash
kerberos-cliente
```

---

## Estrutura do Projeto

```
kerberos-chat/
│
├── common/                         ← Código compartilhado (todos usam)
│   ├── config.py                   # Portas, hosts, constantes, caminhos de chave
│   ├── crypto.py                   # AES-GCM, PBKDF2
│   └── protocol.py                 # Re-exporta tgs_server/message.py
│
├── as_server/                      ← Authentication Server
│   └── as_server.py                # Servidor TCP que emite TGTs
│
├── tgs_server/                     ← Ticket Granting Server
│   ├── message.py                  # Empacotar/desempacotar, tipos, tickets
│   └── tgs_server.py               # Valida TGT, emite Service Ticket
│
├── service/                        ← Serviço Protegido
│   └── service_server.py           # Valida Service Ticket + autenticação mútua
│
├── client/                         ← Cliente
│   └── client.py                   # Orquestra fluxo Kerberos completo
│
├── keys/                           ← Chaves mestras (geradas com gerar-chaves)
│   ├── as_master.key
│   └── service_master.key
│
├── docs/
│   ├── issues_projeto.md           # 40 tarefas (issues) do projeto
│   └── planejamento.md             # Divisão de tarefas, relatório, vídeo
│
├── scripts/
│   ├── __init__.py
│   ├── gerar_chaves.py             # Gera as chaves mestras
│   ├── cadastrar_usuario.py        # Adiciona usuário ao JSON
│   └── simular_ataque.py            # Simula ataques (4 cenários)
│
├── tests/                          ← Testes unitários (pytest)
│   ├── test_cadastrar_usuario.py
│   ├── test_config.py
│   ├── test_crypto.py
│   ├── test_gerar_chaves.py
│   ├── test_message.py
│   ├── test_tgs_server.py
│   └── test_user_db.py
│
├── pyproject.toml                  # Configuração do projeto + console_scripts
├── requirements.txt                # cryptography, pytest
├── .gitignore
└── README.md
```

---

## Tecnologias

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

### AES-128-GCM
- Cifra simétrica autenticada (confidencialidade + integridade)
- Nonce de 12 bytes aleatório a cada operação
- Uma única chamada = cifra + tag de autenticação

### PBKDF2-HMAC-SHA256
- Deriva uma chave de 16 bytes a partir de senha + salt
- 100.000 iterações para dificultar ataques de força bruta
- Salt único de 16 bytes por usuário

### Portas

| Servidor | Host | Porta |
|----------|------|-------|
| Authentication Server (AS) | 127.0.0.1 | 5450 |
| Ticket Granting Server (TGS) | 127.0.0.1 | 5451 |
| Serviço Protegido | 127.0.0.1 | 5452 |

---

## Formato das Mensagens

Toda mensagem trafega na rede com um **cabeçalho de 6 bytes** seguido do payload:

```
[2 bytes] tipo da mensagem (unsigned short, big-endian)
[4 bytes] tamanho do payload em bytes (unsigned int, big-endian)
[N bytes] payload (o conteúdo em si)
```

Esse cabeçalho é montado pela função `empacotar()` em `common/protocol.py`.

### Tipos de Mensagem

| # | Constante | Origem → Destino | Payload |
|---|-----------|-------------------|---------|
| 1 | `MSG_AUTH_REQUEST` | Cliente → AS | `nome_usuario (bytes)` |
| 2 | `MSG_AUTH_REPLY` | AS → Cliente | `TGT_cif(12+*) + K_c_AS_cif(12+*)` |
| 3 | `MSG_TGS_REQUEST` | Cliente → TGS | `[4B tam_tgt][TGT][4B tam_svc][nome]` |
| 4 | `MSG_TGS_REPLY` | TGS → Cliente | `[4B tam_st][ST][4B tam_ks][K_c_svc]` |
| 5 | `MSG_SVC_REQUEST` | Cliente → Serviço | `[4B tam_st][ST][4B tam_auth][authenticator]` |
| 6 | `MSG_SVC_REPLY` | Serviço → Cliente | `timestamp+1 cifrado(12+8)` |
| 7 | `MSG_CHAT` | Cliente → Serviço | `texto (bytes)` |
| 8 | `MSG_ECHO` | Serviço → Cliente | `eco do texto (bytes)` |
| 9 | `MSG_ERROR` | Qualquer → Qualquer | `mensagem de erro (bytes)` |

> `(12+*)` = nonce AES-GCM (12 bytes) + ciphertext de tamanho variável  
> `(12+8)` = nonce (12 bytes) + ciphertext de 8 bytes (apenas um timestamp)  
> `[4B tam]` = prefixo de 4 bytes (unsigned int, big-endian) indicando tamanho do blob seguinte

### Observações importantes

- **MSG_TGS_REQUEST e MSG_TGS_REPLY**: blocos de tamanho variável (TGT, Service Ticket, chave de sessão) são sempre precedidos por um **prefixo de 4 bytes** com seu comprimento.
- **MSG_SVC_REQUEST**: mesma lógica — Service Ticket e authenticator têm prefixos de 4 bytes.
- **MSG_AUTH_REPLY**: contém **dois blocos** cifrados independentemente — o TGT (cifrado com `as_master_key`) e a session key (cifrada com a chave derivada da senha do usuário). Cada bloco tem seu próprio nonce de 12 bytes e prefixo de 4 bytes.
- **MSG_SVC_REQUEST**: o authenticator é a estrutura `{nome_usuario(2+*) + timestamp(8)}` cifrada com `K_c_svc`.
- **MSG_SVC_REPLY**: o timestamp do authenticator **+1**, cifrado com `K_c_svc` — prova que o serviço conhece a chave (autenticação mútua).
- O `nome_servico` em `MSG_TGS_REQUEST` é um identificador simples em bytes (ex: `b"chat"`, `b"arquivos"`).

---

> Para planejamento da equipe (divisão de tarefas, relatório, vídeo), veja [`docs/planejamento.md`](docs/planejamento.md).
