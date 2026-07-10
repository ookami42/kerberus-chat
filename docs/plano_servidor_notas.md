# Plano de Implementação: Servidor de Notas Protegido por Kerberos

> **Objetivo:** Substituir o chat relay por um servidor de notas (arquivos de texto)
> que demonstre Single Sign-On, expiração de tickets e autorização por identidade.
> O foco é o protocolo Kerberos — o serviço é simples e didático.

---

## 1. Arquitetura

```
┌──────────┐     ┌──────┐     ┌──────┐     ┌──────────────────┐
│  CLIENTE │────▶│  AS  │────▶│ TGS  │────▶│ SERVIDOR DE NOTAS│
│          │◀────│ :5450│◀────│ :5451│◀────│      :5452       │
└──────────┘     └──────┘     └──────┘     │                  │
                                           │ /notas/alice/    │
   1. Login (senha)                        │   aula1.txt      │
   2. Ganha TGT                            │   resumo.txt     │
   3. Pede ticket "notas"                  │                  │
   4. Ganha Service Ticket                 │ /notas/bob/      │
   5. Usa ticket p/ acessar notas          │   duvidas.txt    │
                                           └──────────────────┘
```

### Regras de autorização

- O ticket carrega o **nome do usuário** (ex: `alice`)
- O servidor só permite acesso a `/notas/<seu_nome>/*`
- Alice não pode ler nem escrever nas notas do Bob
- O ticket expira em `LIFETIME_TICKET` minutos (atual: 480 = 8h)
- Ticket expirado → acesso negado, precisa novo login

---

## 2. Protocolo (mensagens)

### 2.1 Constantes (em `tgs_server/message.py`)

Manter as existentes. Remover `MSG_RELAY = 10` (não será usado).

Adicionar constantes para os comandos do serviço de notas:

```python
# Tipos de mensagem do serviço de notas
MSG_NOTE_LIST   = 10  # Cliente → Serviço: listar notas
MSG_NOTE_READ   = 11  # Cliente → Serviço: ler uma nota
MSG_NOTE_WRITE  = 12  # Cliente → Serviço: escrever/salvar nota
MSG_NOTE_CREATE = 13  # Cliente → Serviço: criar nova nota
MSG_NOTE_REPLY  = 14  # Serviço → Cliente: resposta (conteúdo da nota, lista, confirmação)
```

### 2.2 Fluxo de cada comando

#### LISTAR (`MSG_NOTE_LIST`)

```
Cliente → Serviço:
  [6 bytes cabeçalho: tipo=10, tamanho=0]
  (payload vazio — o ticket já identifica o usuário)

Serviço → Cliente:
  [6 bytes cabeçalho: tipo=14, tamanho=N]
  [N bytes: "aula1.txt (2 KB)\naula2.txt (4 KB)\n"]
```

#### LER (`MSG_NOTE_READ`)

```
Cliente → Serviço:
  [6 bytes cabeçalho: tipo=11, tamanho=N]
  [N bytes: nome do arquivo, ex: "aula1.txt"]

Serviço → Cliente:
  [6 bytes cabeçalho: tipo=14, tamanho=N]
  [N bytes: conteúdo do arquivo]
```

#### CRIAR (`MSG_NOTE_CREATE`)

```
Cliente → Serviço:
  [6 bytes cabeçalho: tipo=13, tamanho=N]
  [N bytes: "nome_do_arquivo.txt\n<conteúdo>"]
  (primeira linha = nome, resto = conteúdo)

Serviço → Cliente:
  [6 bytes cabeçalho: tipo=14, tamanho=N]
  [N bytes: "OK: nota criada."]
```

#### ESCREVER/SALVAR (`MSG_NOTE_WRITE`)

```
Cliente → Serviço:
  [6 bytes cabeçalho: tipo=12, tamanho=N]
  [N bytes: "nome_do_arquivo.txt\n<novo conteúdo>"]
  (sobrescreve o arquivo inteiro)

Serviço → Cliente:
  [6 bytes cabeçalho: tipo=14, tamanho=N]
  [N bytes: "OK: nota salva."]
```

---

## 3. O que fazer — passo a passo

### Passo 1: Remover chat relay

| Arquivo | Ação |
|---|---|
| `tgs_server/message.py` | Remover `MSG_RELAY = 10`. Adicionar `MSG_NOTE_LIST` a `MSG_NOTE_REPLY` (10-14) |
| `common/protocol.py` | Atualizar imports: remover `MSG_RELAY`, adicionar novos tipos |
| `service/service_server.py` | Remover `_loop_relay()`, `_clientes`, `_lock`. Substituir por processamento stateless de comandos |
| `client/client.py` | Remover `_escutar()`, `_print_lock`, thread de escuta. Substituir `loop_chat()` por loop de comandos |

### Passo 2: Reescrever `service/service_server.py`

O servidor volta a ser **stateless** — processa uma requisição, responde, fecha conexão. Não mantém estado entre requisições.

```python
class ServicoKerberos:
    def __init__(self, host, porta):
        self.host = host
        self.porta = porta
        self.service_master_key = self._carregar_chave()
        self._notas_raiz = "data/notas"  # raiz do sistema de arquivos de notas

    def atender_cliente(self, con, addr):
        """
        Fluxo por conexão:
        1. Recebe MSG_SVC_REQUEST (ticket + authenticator)
        2. Valida ticket e authenticator (autenticação Kerberos)
        3. Autenticação mútua (timestamp + 1)
        4. Recebe segundo comando (MSG_NOTE_LIST/READ/WRITE/CREATE)
        5. Processa comando se usuário autorizado
        6. Responde MSG_NOTE_REPLY ou MSG_ERROR
        7. Fecha conexão
        """
```

**Método `_processar_comando(con, nome_usuario)`:**
```python
def _processar_comando(self, con, nome_usuario):
    # Lê segundo cabeçalho (o comando)
    header = self._recv_exato(con, 6)
    if not header: return
    tipo, tamanho = struct.unpack(">HI", header)
    payload = self._recv_exato(con, tamanho) if tamanho > 0 else b""

    if tipo == MSG_NOTE_LIST:
        arquivos = os.listdir(self._caminho_usuario(nome_usuario))
        resposta = "\n".join(arquivos) if arquivos else "(vazio)"
    elif tipo == MSG_NOTE_READ:
        nome_arquivo = payload.decode().strip()
        caminho = self._caminho_nota(nome_usuario, nome_arquivo)
        with open(caminho, "r") as f:
            resposta = f.read()
    elif tipo == MSG_NOTE_WRITE:
        partes = payload.decode().split("\n", 1)
        nome_arquivo = partes[0].strip()
        conteudo = partes[1] if len(partes) > 1 else ""
        caminho = self._caminho_nota(nome_usuario, nome_arquivo)
        with open(caminho, "w") as f:
            f.write(conteudo)
        resposta = "OK: nota salva."
    elif tipo == MSG_NOTE_CREATE:
        partes = payload.decode().split("\n", 1)
        nome_arquivo = partes[0].strip()
        conteudo = partes[1] if len(partes) > 1 else ""
        caminho = self._caminho_nota(nome_usuario, nome_arquivo)
        with open(caminho, "w") as f:
            f.write(conteudo)
        resposta = "OK: nota criada."
    else:
        con.sendall(empacotar(MSG_ERROR, b"Comando desconhecido"))
        return

    con.sendall(empacotar(MSG_NOTE_REPLY, resposta.encode()))

def _caminho_usuario(self, nome):
    """Retorna o diretório de notas do usuário."""
    return os.path.join(self._notas_raiz, nome)

def _caminho_nota(self, nome_usuario, nome_arquivo):
    """Retorna o caminho completo de uma nota. Cria diretório se necessário."""
    dir_usuario = self._caminho_usuario(nome_usuario)
    os.makedirs(dir_usuario, exist_ok=True)
    # Previne path traversal: remove ../ do nome do arquivo
    nome_seguro = os.path.basename(nome_arquivo)
    return os.path.join(dir_usuario, nome_seguro)
```

**Autorização implícita:** o `nome_usuario` já veio do ticket validado. O método `_caminho_usuario()` sempre resolve para `data/notas/<nome_do_ticket>/`. Alice nunca acessa o diretório do Bob.

### Passo 3: Reescrever `client/client.py`

Remover toda a parte de chat relay. O loop de interação vira:

```python
def loop_notas(self):
    """
    Loop de comandos do serviço de notas.
    Cada comando abre uma NOVA conexão com o servidor
    (o ticket é reutilizado, mas a conexão TCP é nova).
    """
    print("\nComandos:")
    print("  /notas           — listar suas notas")
    print("  /ler <arquivo>   — ler uma nota")
    print("  /criar <arquivo> — criar nova nota")
    print("  /escrever <arquivo> — sobrescrever nota")
    print("  /sair            — encerrar")
    print()

    while True:
        try:
            linha = input("> ").strip()
            if not linha:
                continue

            if linha == "/sair":
                break

            # Cada comando: conecta → envia ticket+auth → envia comando → recebe resposta
            self._conectar(SVC_HOST, SVC_PORT)

            # --- Enviar ticket + authenticator (sempre igual) ---
            nome_b = self.usuario.encode()
            ts = int(time.time())
            auth = (
                struct.pack(">H", len(nome_b))
                + nome_b
                + struct.pack(">Q", ts)
            )
            auth_cifrado = cifrar_aes_gcm(self.k_c_svc, auth)
            payload_svc = (
                struct.pack(">I", len(self.st_cifrado))
                + self.st_cifrado
                + struct.pack(">I", len(auth_cifrado))
                + auth_cifrado
            )
            self.socket.sendall(empacotar(MSG_SVC_REQUEST, payload_svc))
            tipo, _ = self._receber_msg()

            if tipo == MSG_ERROR:
                print("[ERRO] Falha na autenticação. Ticket expirado?")
                self.fechar()
                break

            # Autenticação mútua (receber ts+1)
            # (já feito no passo anterior, confirmar se ok)
            if tipo != MSG_SVC_REPLY:
                print("[ERRO] Resposta inesperada do serviço.")
                self.fechar()
                break

            # --- Enviar comando ---
            if linha.startswith("/notas"):
                comando_tipo = MSG_NOTE_LIST
                payload = b""
            elif linha.startswith("/ler "):
                comando_tipo = MSG_NOTE_READ
                payload = linha[5:].strip().encode()
            elif linha.startswith("/criar "):
                comando_tipo = MSG_NOTE_CREATE
                nome = linha[7:].strip()
                conteudo = input("Conteúdo (Ctrl+D para terminar): ")
                # Lê múltiplas linhas
                linhas = []
                while True:
                    try:
                        l = input()
                        linhas.append(l)
                    except EOFError:
                        break
                payload = (nome + "\n" + "\n".join(linhas)).encode()
            elif linha.startswith("/escrever "):
                comando_tipo = MSG_NOTE_WRITE
                nome = linha[10:].strip()
                print(f"Escrevendo em {nome} (Ctrl+D para terminar):")
                linhas = []
                while True:
                    try:
                        l = input()
                        linhas.append(l)
                    except EOFError:
                        break
                payload = (nome + "\n" + "\n".join(linhas)).encode()
            else:
                print("Comando desconhecido.")
                self.fechar()
                continue

            self.socket.sendall(empacotar(comando_tipo, payload))
            tipo, resposta = self._receber_msg()

            if tipo == MSG_NOTE_REPLY:
                print(resposta.decode())
            elif tipo == MSG_ERROR:
                print(f"[ERRO] {resposta.decode()}")
            else:
                print(f"[ERRO] Tipo inesperado: {tipo}")

            self.fechar()

        except KeyboardInterrupt:
            print()
            break
        except Exception as e:
            print(f"[ERRO] {e}")
            self.fechar()
            break

    self.fechar()
```

**Nota sobre o fluxo acima:** O ideal é que o cliente reutilize a mesma conexão TCP para ticket + comando. Ou seja:

1. Conecta
2. Envia MSG_SVC_REQUEST (ticket + authenticator)
3. Recebe MSG_SVC_REPLY (autenticação mútua)
4. Envia MSG_NOTE_* (comando)
5. Recebe MSG_NOTE_REPLY
6. Fecha

Isso exige que o servidor processe **duas mensagens** na mesma conexão: primeiro o ticket, depois o comando. É o que o `atender_cliente` do serviço já faz — só substituir o `_loop_relay` por `_processar_comando`.

### Passo 4: Atualizar `common/protocol.py`

```python
from tgs_server.message import (
    MSG_AUTH_REQUEST, MSG_AUTH_REPLY,
    MSG_TGS_REQUEST, MSG_TGS_REPLY,
    MSG_SVC_REQUEST, MSG_SVC_REPLY,
    MSG_CHAT, MSG_ECHO, MSG_ERROR,
    MSG_NOTE_LIST, MSG_NOTE_READ, MSG_NOTE_WRITE,
    MSG_NOTE_CREATE, MSG_NOTE_REPLY,
    empacotar, desempacotar,
    criar_ticket, extrair_ticket,
)
```

(Manter `MSG_CHAT` e `MSG_ECHO` por compatibilidade, mesmo não sendo usados.)

### Passo 5: Atualizar `pyproject.toml`

Nenhuma mudança necessária. Os entry points continuam os mesmos.

### Passo 6: Atualizar `scripts/simular_ataque.py`

Os testes de ataque continuam válidos — eles testam a camada de autenticação (AS, TGS, Serviço), não o serviço em si. Não precisa mudar.

### Passo 7: Atualizar `AGENTS.md`

Atualizar a seção de arquitetura e o diagrama de fluxo para refletir o servidor de notas.

---

## 4. Pontos de atenção

### 4.1 Segurança: path traversal

O nome do arquivo vem do cliente. É essencial usar `os.path.basename()` para evitar que o cliente envie `../../etc/passwd` e acesse arquivos fora do diretório dele.

```python
nome_seguro = os.path.basename(nome_arquivo)  # "aula1.txt", nunca "../alice/..."
```

### 4.2 Ticket expirado

O servidor NÃO verifica expiração do ticket — isso é responsabilidade do TGS. Mas o authenticator tem timestamp, e o servidor verifica `JANELA_AUTH` (5 min). Se o cliente reutilizar o mesmo ticket 6 minutos depois, o authenticator com timestamp fresco vai gerar um novo `ts_auth` que passa na janela. O ticket em si expira em 8h — isso é tratado pelo TGS, não pelo serviço.

Para demonstrar expiração na apresentação: reduzir `LIFETIME_TICKET` para 2 minutos no `common/config.py`, fazer login, acessar notas, esperar 2 minutos, tentar acessar de novo → o TGS rejeita o ticket (não o serviço). Ou seja, a renovação do ticket falha.

### 4.3 Testes

Criar `tests/test_service_notas.py` com:
- `test_listar_notas_usuario`: cria arquivos fake, lista, verifica
- `test_ler_nota_existente`: lê conteúdo
- `test_criar_nota`: cria arquivo, verifica que existe
- `test_path_traversal_bloqueado`: tenta `../bob/nota.txt`, verifica que salva no diretório correto
- `test_usuario_nao_acessa_outro`: Alice tenta ler nota do Bob, verifica que o caminho resolve pro diretório da Alice

Os testes devem mockar o socket e a autenticação, testando apenas a lógica de `_processar_comando`.

---

## 5. Resumo do que muda

| Arquivo | Ação | Linhas (~) |
|---|---|---|
| `tgs_server/message.py` | Remover `MSG_RELAY`, adicionar `MSG_NOTE_*` | +5, -1 |
| `common/protocol.py` | Atualizar imports | +2, -2 |
| `service/service_server.py` | Reescrever: remover relay, adicionar processamento de notas | ~120 (reescrito) |
| `client/client.py` | Reescrever `loop_chat` → `loop_notas` | ~80 (reescrito) |
| `tests/test_service_notas.py` | **Novo** — testes do servidor de notas | ~100 |
| `AGENTS.md` | Atualizar arquitetura e comandos | ~20 |

---

## 6. Como fica a apresentação (3 terminais)

```bash
# Terminal 1 — Kerberos
$ kerberos-servidor

# Terminal 2 — Alice
$ kerberos-cliente
Usuário: alice
Senha: ****
> /notas
  aula1.txt (2 KB)
  resumo.txt (1 KB)
> /ler aula1.txt
  "hoje vimos AES com 128 bits de chave..."
> /criar duvidas.txt
  Conteúdo: PBKDF2 usa quantas iterações?
> /notas
  aula1.txt (2 KB)
  resumo.txt (1 KB)
  duvidas.txt (1 KB)    ← nova nota apareceu!

# Terminal 3 — Bob
$ kerberos-cliente
Usuário: bob
Senha: ****
> /notas
  (vazio)
> /criar resumo.txt
  Conteúdo: criptografia simétrica é...
> /notas
  resumo.txt (1 KB)

# Bob NÃO vê as notas da Alice. Alice NÃO vê as do Bob.
# Cada um acessa múltiplas notas com o MESMO ticket (SSO).
```
