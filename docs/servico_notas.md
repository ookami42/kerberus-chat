# Serviço de Notas: Por que substituímos o chat relay

> **Decisão de design** tomada após questionamento do Welton (Pessoa D):
> "O chat relay demonstra bem o Kerberos?"
> Resposta: não. Substituído por servidor de notas com arquivos txt por usuário.

---

## 1. O que havia antes: chat relay

O sistema original implementava um chat relay após a autenticação Kerberos:

```
Serviço mantinha:
  - self._clientes: dict[nome_usuario → socket]  ← estado!
  - self._lock: threading.Lock                     ← concorrência!
  - _loop_relay(): loop infinito de mensagens
```

O cliente enviava `MSG_CHAT` e o servidor retransmitia para todos os outros clientes conectados.

### Problemas

| Problema | Explicação |
|----------|------------|
| **Não demonstra Kerberos** | O chat funcionaria igual com qualquer sistema de autenticação. O Kerberos era só um "porteiro" — depois que entrava, virava um chat genérico. |
| **Stateful** | O servidor mantinha estado (lista de clientes) entre requisições. Kerberos foi projetado para serviços **stateless** — cada requisição carrega o ticket como prova de identidade. |
| **Não exercita SSO** | Uma vez no chat, o usuário ficava lá. Não havia múltiplos acessos com o mesmo ticket. |
| **Não testa autorização** | Todos os clientes viam todas as mensagens. Não existia isolamento por identidade. |
| **Complexidade desnecessária** | `threading.Lock`, dicionário compartilhado, loop de broadcast — distraía do foco didático. |

---

## 2. O que temos agora: serviço de notas

Após a autenticação Kerberos, o cliente acessa um **serviço de notas pessoal** — arquivos `.txt` organizados por usuário:

```
data/notas/
├── alice/
│   ├── aula1.txt       "hoje vimos AES com 128 bits..."
│   └── duvidas.txt     "PBKDF2 usa quantas iterações?"
└── bob/
    └── resumo.txt       "criptografia simétrica é..."
```

### Arquitetura (stateless)

```
┌──────────┐     ┌──────┐     ┌──────┐     ┌──────────────────┐
│  CLIENTE │────▶│  AS  │────▶│ TGS  │────▶│ SERVIÇO DE NOTAS │
│          │◀────│ :5450│◀────│ :5451│◀────│      :5452       │
└──────────┘     └──────┘     └──────┘     │                  │
                                           │ data/notas/      │
  1. Login (senha)                         │   alice/         │
  2. Ganha TGT                             │     aula1.txt    │
  3. Pede ticket "notas"                   │     duvidas.txt  │
  4. Ganha Service Ticket                  │   bob/           │
  5. Usa ticket p/ acessar notas           │     resumo.txt   │
                                           └──────────────────┘
```

### Comandos

| Comando | Mensagem | O que faz |
|---------|----------|-----------|
| `/notas` | `MSG_NOTE_LIST` (tipo 10, payload vazio) | Lista os arquivos do diretório do usuário |
| `/ler <arquivo>` | `MSG_NOTE_READ` (tipo 11) | Lê o conteúdo de uma nota |
| `/escrever <arquivo>` | `MSG_NOTE_WRITE` (tipo 12) | Cria ou sobrescreve uma nota |

Cada comando abre uma **nova conexão TCP** e reutiliza o **mesmo Service Ticket** — demonstrando Single Sign-On.

### Isolamento por identidade

```python
def _caminho_nota(self, nome_usuario, nome_arquivo):
    """Sempre resolve para data/notas/<usuario_do_ticket>/"""
    nome_seguro = os.path.basename(nome_arquivo)  # bloqueia ../
    return os.path.join(self._notas_raiz, nome_usuario, nome_seguro)
```

- O `nome_usuario` **não vem do cliente** — vem do Service Ticket validado criptograficamente
- Alice nunca acessa `data/notas/bob/`, mesmo que tente `../bob/segredo.txt` (barrado pelo `os.path.basename`)
- Autorização = decorrência natural da autenticação Kerberos, sem ACLs explícitas

---

## 3. O que o serviço de notas demonstra (que o chat não mostrava)

| Propriedade do Kerberos | Como o serviço de notas demonstra |
|--------------------------|-----------------------------------|
| **Single Sign-On** | Um login → um TGT → um Service Ticket → **múltiplos comandos** (`/notas`, `/ler`, `/escrever`) sem redigitar senha |
| **Autorização por identidade** | Alice acessa `data/notas/alice/`, Bob acessa `data/notas/bob/`. Isolamento garantido pelo ticket. |
| **Serviço stateless** | O servidor não mantém sessão. Cada comando é uma conexão independente. A identidade vem do ticket, não de "estado de login". |
| **Expiração de ticket** | Reduzindo `LIFETIME_TICKET` para 2 minutos, o usuário perde acesso — precisa novo TGT → demonstra renovação. |
| **Path traversal bloqueado** | `os.path.basename()` impede `../bob/segredo.txt`. Cenário 5 do `simular_ataque` testa isso. |
| **Autenticação mútua** | Antes de qualquer comando de nota, o servidor prova sua identidade devolvendo `timestamp+1` cifrado. |

---

## 4. Implementação

### Fluxo por conexão (`service_server.py`)

```
1. Recebe MSG_SVC_REQUEST (Service Ticket + Authenticator)
2. Decifra ticket com service_master.key → extrai nome, K_c_svc, timestamp
3. Verifica expiração do ticket
4. Decifra authenticator com K_c_svc → confere nome + janela de 5 min
5. Autenticação mútua: envia cifra(ts_auth + 1)
6. Lê comando do cliente (MSG_NOTE_LIST/READ/WRITE)
7. Processa no diretório data/notas/<nome_usuario>/
8. Envia MSG_NOTE_REPLY ou MSG_ERROR
9. Fecha conexão
```

### Tratamento de erros

| Erro | Resposta |
|------|----------|
| `InvalidTag` (AES-GCM) | `MSG_ERROR`: "Ticket ou authenticator inválido" |
| Ticket expirado | `MSG_ERROR`: "Service Ticket expirado" |
| Nome do auth ≠ nome do ticket | `MSG_ERROR`: "Usuário do Authenticator não condiz..." |
| Timestamp fora da janela (replay) | `MSG_ERROR`: "Timestamp fora da janela..." |
| Nota não encontrada | `MSG_ERROR`: "Nota não encontrada." |
| Path traversal (`../`) | Bloqueado por `os.path.basename()` — resolve para diretório do usuário |

---

## 5. Testes de segurança

O script `scripts/simular_ataque.py` cobre a camada de autenticação + o serviço de notas:

| # | Cenário | Relação com serviço de notas |
|---|---------|------------------------------|
| 1 | Replay de TGT expirado | Testa o TGS (bloco anterior) |
| 2 | Replay de authenticator | Testa a janela de 5 min do serviço |
| 3 | Ticket com chave errada | Testa a integridade criptográfica do ticket |
| 4 | Usuário inexistente | Testa o AS (bloco anterior) |
| **5** | **Path traversal** | **Testa o isolamento do serviço de notas — `../bob/segredo.txt` é barrado** |

---

## 6. Comparação final: chat vs notas

| Critério | Chat relay (antes) | Serviço de notas (agora) |
|----------|-------------------|--------------------------|
| Demonstra Kerberos? | ❌ Só como porteiro | ✅ Cada acesso depende do ticket |
| SSO visível? | ❌ Uma conexão longa | ✅ Múltiplas conexões, mesmo ticket |
| Stateless? | ❌ Mantinha `_clientes` + `_lock` | ✅ Nenhum estado entre requisições |
| Autorização por identidade? | ❌ Todos viam tudo | ✅ Isolamento por diretório |
| Código didático? | ❌ Thread lock, broadcast, loop infinito | ✅ Funções curtas, fluxo linear |
| Testável? | ❌ Difícil testar isoladamente | ✅ `test_service_notas.py` com mocks |
| Ataques demonstráveis? | ❌ Nenhum específico | ✅ Path traversal (cenário 5) |
