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

### 1. Instalar dependências

```bash
cd kerberos-chat
pip install -r requirements.txt
```

### 2. Gerar chaves mestras

```bash
python scripts/gerar_chaves.py
```

### 3. Cadastrar usuários

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

## Estrutura do Projeto

```
kerberos-chat/
│
├── common/                         ← Código compartilhado (todos usam)
│   ├── config.py                   # Portas, hosts, constantes
│   └── crypto.py                   # AES-GCM, PBKDF2
│
├── as_server/                      ← Authentication Server
│   ├── as_server.py                # Servidor TCP que emite TGTs
│   ├── kdf.py                      # PBKDF2: senha → chave de 16 bytes
│   └── user_db.py                  # Cadastro de usuários (JSON)
│
├── tgs_server/                     ← Ticket Granting Server
│   ├── tgs_server.py               # Valida TGT, emite Service Ticket
│   └── message.py                  # Empacotar/desempacotar, tipos, tickets
│
├── service/                        ← Serviço Protegido
│   ├── service_server.py           # Valida Service Ticket + autenticação mútua
│   └── handler.py                  # Lógica do chat (echo)
│
├── client/                         ← Cliente
│   ├── client.py                   # Orquestra fluxo Kerberos completo
│   └── ui.py                       # Interface de terminal
│
├── keys/                           ← Chaves mestras (geradas na execução)
│   ├── as_master.key
│   ├── tgs_master.key
│   └── service_master.key
│
├── scripts/
│   ├── gerar_chaves.py             # Gera as 3 chaves mestras
│   ├── cadastrar_usuario.py        # Adiciona usuário ao JSON
│   └── testar_ataque.py            # Simula ataques
│
├── requirements.txt                # cryptography
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

Esse cabeçalho é montado pela função `empacotar()` em `tgs_server/message.py`.

### Tipos de Mensagem

| # | Constante | Origem → Destino | Payload |
|---|-----------|-------------------|---------|
| 1 | `MSG_AUTH_REQUEST` | Cliente → AS | `nome_usuario (bytes)` |
| 2 | `MSG_AUTH_REPLY` | AS → Cliente | `TGT_cif(12+*) + K_c_AS_cif(12+*)` |
| 3 | `MSG_TGS_REQUEST` | Cliente → TGS | `TGT_cif(12+*) + nome_servico(bytes)` |
| 4 | `MSG_TGS_REPLY` | TGS → Cliente | `svc_ticket_cif(12+*) + K_c_svc_cif(12+*)` |
| 5 | `MSG_SVC_REQUEST` | Cliente → Serviço | `svc_ticket_cif(12+*) + authenticator_cif(12+*)` |
| 6 | `MSG_SVC_REPLY` | Serviço → Cliente | `timestamp+1 cifrado(12+8)` |
| 7 | `MSG_CHAT` | Cliente → Serviço | `texto (bytes)` |
| 8 | `MSG_ECHO` | Serviço → Cliente | `eco do texto (bytes)` |
| 9 | `MSG_ERROR` | Qualquer → Qualquer | `mensagem de erro (bytes)` |

> `(12+*)` = nonce AES-GCM (12 bytes) + ciphertext de tamanho variável  
> `(12+8)` = nonce (12 bytes) + ciphertext de 8 bytes (apenas um timestamp)

### Observações importantes

- **MSG_AUTH_REPLY**: contém **dois blocos** cifrados independentemente — o TGT (cifrado com `as_master_key`) e a session key (cifrada com a chave derivada da senha do usuário). Cada bloco tem seu próprio nonce de 12 bytes.
- **MSG_TGS_REPLY**: mesma lógica — Service Ticket cifrado com `service_master_key` e nova session key cifrada com a chave do TGT anterior.
- **MSG_SVC_REQUEST**: o authenticator é a estrutura `{nome_usuario(2+*) + timestamp(8)}` cifrada com `K_c_svc`.
- **MSG_SVC_REPLY**: o timestamp do authenticator **+1**, cifrado com `K_c_svc` — prova que o serviço conhece a chave (autenticação mútua).
- O `nome_servico` em `MSG_TGS_REQUEST` é um identificador simples em bytes (ex: `b"chat"`, `b"arquivos"`).

---

## 🎯 Divisão do Trabalho (Issues)

O projeto foi dividido em **40 tarefas atômicas** no estilo GitHub Issues.
Cada pessoa escolhe uma issue, implementa, abre PR, outra revisa. Depois pega outra.

> Lista completa em [`issues_projeto.md`](../issues_projeto.md)

### 🏗️ Grupo 0 — Fundação (qualquer pessoa)

| # | Tarefa | Arquivo |
|---|--------|---------|
| 1 | Constantes de configuração | `common/config.py` |
| 2 | `cifrar_aes_gcm()` | `common/crypto.py` |
| 3 | `decifrar_aes_gcm()` | `common/crypto.py` |
| 4 | `derivar_chave()` (PBKDF2) | `common/crypto.py` |
| 5 | `empacotar()` / `desempacotar()` | `tgs_server/message.py` |
| 6 | Constantes dos tipos de mensagem | `tgs_server/message.py` |
| 7 | `criar_ticket()` / `extrair_ticket()` | `tgs_server/message.py` |
| 8 | Script de geração de chaves | `scripts/gerar_chaves.py` |

### 👤 Grupo 1 — Usuários

| # | Tarefa | Arquivo |
|---|--------|---------|
| 9 | Classe UserDB | `as_server/user_db.py` |
| 10 | Script de cadastro de usuário | `scripts/cadastrar_usuario.py` |

### 🖥️ Grupo 2 — AS (Authentication Server)

| # | Tarefa | Arquivo |
|---|--------|---------|
| 11 | Esqueleto do AS (socket + thread) | `as_server/as_server.py` |
| 12 | Receber `MSG_AUTH_REQUEST` | `as_server/as_server.py` |
| 13 | Derivar chave e gerar session key | `as_server/as_server.py` |
| 14 | Montar e cifrar TGT | `as_server/as_server.py` |
| 15 | Cifrar session key e responder | `as_server/as_server.py` |

### 🎫 Grupo 3 — TGS (Ticket Granting Server)

| # | Tarefa | Arquivo |
|---|--------|---------|
| 16 | Esqueleto do TGS (socket + thread) | `tgs_server/tgs_server.py` |
| 17 | Receber `MSG_TGS_REQUEST` | `tgs_server/tgs_server.py` |
| 18 | Decifrar e validar TGT | `tgs_server/tgs_server.py` |
| 19 | Gerar Service Ticket | `tgs_server/tgs_server.py` |
| 20 | Montar e enviar resposta | `tgs_server/tgs_server.py` |

### 🔐 Grupo 4 — Serviço Protegido

| # | Tarefa | Arquivo |
|---|--------|---------|
| 21 | Esqueleto do Serviço (socket + thread) | `service/service_server.py` |
| 22 | Receber `MSG_SVC_REQUEST` | `service/service_server.py` |
| 23 | Decifrar e validar Service Ticket | `service/service_server.py` |
| 24 | Decifrar e validar authenticator | `service/service_server.py` |
| 25 | Autenticação mútua (timestamp+1) | `service/service_server.py` |
| 26 | Echo chat | `service/handler.py` |
| 27 | Script de teste de ataque | `scripts/testar_ataque.py` |

### 💻 Grupo 5 — Cliente

| # | Tarefa | Arquivo |
|---|--------|---------|
| 28 | Conectar no AS | `client/client.py` |
| 29 | Decifrar K_c_AS | `client/client.py` |
| 30 | Conectar no TGS | `client/client.py` |
| 31 | Conectar no Serviço + aut. mútua | `client/client.py` |
| 32 | Interface de terminal (UI) | `client/ui.py` |
| 33 | Orquestrar fluxo completo | `client/client.py` |

### 📝 Grupo 6 — Documentação

| # | Tarefa | Responsável |
|---|--------|-------------|
| 34 | README final | Quem pegar |
| 35-40 | Relatório + vídeo | TODOS |

### Ordem sugerida

```
1º  Issues #1 a #8  (fundação — paralelizável)
2º  Issue #9, #10   (usuários)
3º  Issues #11-#15  (AS)
    Issues #16-#20  (TGS)          ← em paralelo com AS
    Issues #21-#26  (Serviço)      ← em paralelo com AS
4º  Issues #28-#33  (Cliente)      ← depois dos servidores prontos
5º  Issue #27       (teste ataque)
6º  Issues #34-#40  (documentação)
```

> 💡 **Vantagem:** cada pessoa pode pegar issues de grupos diferentes — uma hora faz crypto, outra hora faz um handler do AS. Ninguém fica preso a um módulo só.

---

## Relatório (seções)

| # | Seção |
|---|-------|
| 1 | Arquitetura geral |
| 2 | KDF adotado (PBKDF2) |
| 3 | Implementação do AS |
| 4 | Implementação do TGS |
| 5 | Fluxo de tickets |
| 6 | Autenticação mútua |
| 7 | Algoritmos criptográficos |
| 8 | Dificuldades + aprendizados |
| 9 | Conclusão |

---

## Vídeo (apresentação)

| Quem | O que mostrar |
|------|---------------|
| Pessoa responsável pelo AS | KDF e AS: cadastrar usuário, login, emissão de TGT |
| Pessoa responsável pelo TGS | TGS: validar TGT, emitir Service Ticket |
| Pessoa responsável pelo Serviço | Serviço: validar ticket, autenticação mútua |
| Pessoa responsável pelo Cliente | Visão geral do fluxo completo + teste de ataque |
