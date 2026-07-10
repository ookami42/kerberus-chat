# Kerberos Notas — Autenticação Kerberos com Serviço de Notas Protegido

**Disciplina:** Segurança Computacional — UnB  
**Professor:** Prof. Roberto Rodrigues Filho  
**Grupo:** 4 integrantes

---

## Descrição

Implementação didática do **protocolo Kerberos** utilizando exclusivamente criptografia de chave simétrica. O sistema é composto por quatro componentes que implementam o fluxo completo de autenticação:

1. **Authentication Server (AS)** — emite o Ticket Granting Ticket (TGT)
2. **Ticket Granting Server (TGS)** — valida o TGT e emite o Service Ticket
3. **Serviço Protegido** — valida o Service Ticket, realiza autenticação mútua e gerencia notas por usuário
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
  │   TGT || "notas"                                 │                       │
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
  │                                                                          │  Verifica expiração
  │◄── MSG_SVC_REPLY ──────────────────────────────────────────────────────┤  Soma 1 no timestamp
  │   timestamp+1 cifrado                                                    │  Cifra e envia
  │                                                                          │
  │  Verifica timestamp+1                                                    │
  │  -> Autenticação mútua OK!                                              │
  │                                                                          │
  ├── MSG_NOTE_* ──────────────────────────────────────────────────────────►│
  │  /notas, /ler, /escrever                                                │  Lista, lê ou salva nota
  │◄── MSG_NOTE_REPLY ─────────────────────────────────────────────────────┤
  │  conteúdo da nota / confirmação                                         │
  │                                                                          │
  │         ┌─────────────────────────────────────────────────────────────┐  │
  │         │  Cada comando abre NOVA conexão TCP, reutilizando o mesmo   │  │
  │         │  Service Ticket (Single Sign-On).                           │  │
  │         └─────────────────────────────────────────────────────────────┘  │
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

> Alternativa: inicie os 3 servidores de uma vez em um único terminal.
> ```bash
> kerberos-servidor
> ```

### 4. Executar o cliente

```bash
kerberos-cliente
```

O cliente exibe um menu:
```
  1. Cadastrar usuario
  2. Fazer login
  0. Sair
```

A opção 1 registra um novo usuário e retorna ao menu. A opção 2 inicia o fluxo Kerberos (AS → TGS → Serviço → Notas).

### 5. Testes de ataque (opcional)

```bash
simular-ataque
```

Executa 4 cenários de ataque contra o sistema (requer servidores rodando).

### 6. Testes unitários

```bash
pytest tests/ -v
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
│   ├── as_server.py                # Servidor TCP que emite TGTs
│   └── user_db.py                  # Banco de usuários (JSON)
│
├── tgs_server/                     ← Ticket Granting Server
│   ├── message.py                  # Empacotar/desempacotar, tipos, tickets
│   └── tgs_server.py               # Valida TGT, emite Service Ticket
│
├── service/                        ← Serviço Protegido
│   └── service_server.py           # Valida Service Ticket + gerencia notas
│
├── client/                         ← Cliente
│   ├── client.py                   # Orquestra fluxo Kerberos + menu cadastro/login
│   └── ui.py                       # Stub: interface de terminal
│
├── keys/                           ← Chaves mestras (geradas com gerar-chaves)
│   ├── as_master.key
│   └── service_master.key
│
├── data/                           ← Dados de usuários (runtime)
│   └── user_db.json                # {"users": {"nome": {"salt": hex, "hash_chave": hex}}}
│
├── docs/
│   ├── issues_projeto.md           # 40 tarefas (issues) do projeto
│   ├── issues_pendentes.md         # Issues de auditoria e correções
│   ├── plano_servidor_notas.md     # Design do serviço de notas
│   ├── servico_notas.md            # Por que substituímos o chat relay pelo serviço de notas
│   ├── plano_apresentacao_bloco3.md # Roteiro da apresentação — Bloco 3
│   └── planejamento.md             # Divisão de tarefas, relatório, vídeo
│
├── scripts/
│   ├── gerar_chaves.py             # Gera as chaves mestras
│   ├── cadastrar_usuario.py        # Adiciona usuário ao JSON
│   ├── kerberos_demo.py            # Lança os 3 servidores em threads
│   └── simular_ataque.py           # 4 cenários de ataque (requer servidores)
│
├── tests/                          ← Testes unitários (pytest, 83 testes)
│   ├── conftest.py                 # Fixtures compartilhadas
│   ├── test_cadastrar_usuario.py
│   ├── test_config.py
│   ├── test_crypto.py
│   ├── test_gerar_chaves.py
│   ├── test_message.py
│   ├── test_tgs_server.py
│   ├── test_user_db.py
│   └── test_as_server_e2e.py       # Testes de integração do AS
│
├── pyproject.toml                  # Configuração do projeto + entry-points
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
| 2 | `MSG_AUTH_REPLY` | AS → Cliente | `salt(16) + [4B tam_tgt][TGT_cif] + [4B tam_k][K_c_AS_cif]` |
| 3 | `MSG_TGS_REQUEST` | Cliente → TGS | `[4B tam_tgt][TGT][4B tam_svc][nome]` |
| 4 | `MSG_TGS_REPLY` | TGS → Cliente | `[4B tam_st][ST][4B tam_ks][K_c_svc]` |
| 5 | `MSG_SVC_REQUEST` | Cliente → Serviço | `[4B tam_st][ST][4B tam_auth][authenticator]` |
| 6 | `MSG_SVC_REPLY` | Serviço → Cliente | `timestamp+1 cifrado(12+8)` |
| 7 | `MSG_CHAT` | (legado) | — |
| 8 | `MSG_ECHO` | (legado) | — |
| 9 | `MSG_ERROR` | Qualquer → Qualquer | `mensagem de erro (bytes)` |
| 10 | `MSG_NOTE_LIST` | Cliente → Serviço | `(vazio)` |
| 11 | `MSG_NOTE_READ` | Cliente → Serviço | `nome_do_arquivo (bytes)` |
| 12 | `MSG_NOTE_WRITE` | Cliente → Serviço | `nome_arquivo\n<conteudo> (bytes)` |
| 13 | `MSG_NOTE_REPLY` | Serviço → Cliente | `conteúdo ou confirmação (bytes)` |

> `(12+*)` = nonce AES-GCM (12 bytes) + ciphertext de tamanho variável  
> `(12+8)` = nonce (12 bytes) + ciphertext de 8 bytes (apenas um timestamp)  
> `[4B tam]` = prefixo de 4 bytes (unsigned int, big-endian) indicando tamanho do blob seguinte

### Observações importantes

- **MSG_TGS_REQUEST e MSG_TGS_REPLY**: blocos de tamanho variável (TGT, Service Ticket, chave de sessão) são sempre precedidos por um **prefixo de 4 bytes** com seu comprimento.
- **MSG_SVC_REQUEST**: mesma lógica — Service Ticket e authenticator têm prefixos de 4 bytes.
- **MSG_AUTH_REPLY**: contém **salt de 16 bytes** no início, seguido por **dois blocos** cifrados independentemente — o TGT (cifrado com `as_master_key`) e K_c_AS (cifrada com a chave derivada da senha do usuário). Cada bloco cifrado tem prefixo de 4 bytes com seu tamanho.
- **MSG_SVC_REQUEST**: o authenticator é a estrutura `{nome_usuario(2+*) + timestamp(8)}` cifrada com `K_c_svc`.
- **MSG_SVC_REPLY**: o timestamp do authenticator **+1**, cifrado com `K_c_svc` — prova que o serviço conhece a chave (autenticação mútua).
- O `nome_servico` em `MSG_TGS_REQUEST` é um identificador simples em bytes (ex: `b"notas"`, `b"chat"`).
- **MSG_NOTE_LIST**: payload vazio — o ticket já identifica o usuário.
- **MSG_NOTE_READ**: payload contém apenas o nome do arquivo a ser lido.
- **MSG_NOTE_WRITE**: a primeira linha do payload é o nome do arquivo; o resto é o conteúdo a salvar.

---

> Para planejamento da equipe (divisão de tarefas, relatório, vídeo), veja [`docs/planejamento.md`](docs/planejamento.md).  
> O design detalhado do serviço de notas está em [`docs/plano_servidor_notas.md`](docs/plano_servidor_notas.md).  
> A justificativa da substituição do chat relay pelo serviço de notas está em [`docs/servico_notas.md`](docs/servico_notas.md).
