# Issues Pendentes — Kerberos Chat

> Complemento de `docs/issues_projeto.md`. Issues existentes com pendências
> e novas issues descobertas durante auditoria do código.

---

## ⚠️ Correções (issues existentes reabertas)

---

### #14 — AS: corrigir chamada a `criar_ticket()`

**Arquivo:** `as_server/as_server.py` (linhas 229–241)

**Descrição:** A chamada atual a `criar_ticket()` usa nomes de parâmetros
incorretos (`usuario=`, `servico=`, `validade=`, `chave=`), passa
`timestamp` como float, e `nome_usuario` como `str`. O método quebraria
em runtime, bloqueando a emissão de qualquer TGT.

**Assinatura correta:** `criar_ticket(nome: bytes, chave_sessao: bytes, timestamp: int, lifetime_min: int) -> bytes`

**Plano:**

1. Remover a variável `validade = 3600` e trocar por `LIFETIME_TICKET` do config
2. Substituir `time.time()` por `int(time.time())`
3. Converter `nome_usuario` de `str` para `bytes` via `.encode()`
4. Corrigir a chamada:
   ```python
   timestamp = int(time.time())

   # Monta o TGT
   ticket = criar_ticket(
       nome=nome_usuario.encode(),
       chave_sessao=K_c_AS,
       timestamp=timestamp,
       lifetime_min=LIFETIME_TICKET,
   )
   ```

**Critério de aceite:**
- [ ] `python -m as_server.as_server` não quebra ao receber requisição
- [ ] TGT gerado pode ser decifrado com `as_master.key`
- [ ] `extrair_ticket(decifrar_aes_gcm(as_master_key, tgt_cif))` devolve campos originais

**Dependências:** #13, #7, #2

---

### #23 — Serviço: adicionar verificação de expiração do Service Ticket

**Arquivo:** `service/service_server.py` (linhas 90–94)

**Descrição:** `ts_tk` e `life_tk` são extraídos de `extrair_ticket()` mas nunca
comparados com `time.time()`. Um Service Ticket expirado seria aceito,
violando o fluxo Kerberos.

**Plano:**

1. Após linha 93 (onde `extrair_ticket` já foi chamada), adicionar:
   ```python
   agora = int(time.time())
   if agora > ts_tk + life_tk * 60:
       print(f"[SERVIÇO] Service Ticket expirado de {addr}")
       con.sendall(empacotar(MSG_ERROR, b"Service Ticket expirado"))
       return
   ```

2. Tratar como erro — ticket expirado → `MSG_ERROR` + fecha conexão

**Critério de aceite:**
- [ ] Service Ticket com `ts + lifetime*60` anterior a `time.time()` é rejeitado
- [ ] `MSG_ERROR` é enviado antes de fechar conexão
- [ ] Fluxo normal continua se ticket válido

**Dependências:** #22, #3, #7

---

## ❌ Implementações (issues existentes não iniciadas)

---

### #26 — Serviço: implementar loop de echo chat

**Arquivos:** `service/service_server.py`, opcional `service/handler.py`

**Descrição:** Após autenticação mútua (linha 113), o servidor fecha a
conexão. Falta implementar o loop que recebe `MSG_CHAT` e responde com
`MSG_ECHO`.

**Plano:**

1. Após a linha `"Canal seguro estabelecido..."`, adicionar:
   ```python
   print(f"[SERVIÇO] Chat iniciado com {nome_tk.decode()}")
   try:
       while True:
           cabecalho = self._recv_exato(con, HEADER_SIZE)
           if not cabecalho:
               break
           tipo, tam = struct.unpack(HEADER_FORMAT, cabecalho)
           dados = self._recv_exato(con, tam)
           if tipo == MSG_CHAT:
               texto = dados.decode("utf-8", errors="replace")
               print(f"[SERVIÇO] Chat: {texto}")
               eco = f"eco: {texto}".encode("utf-8")
               con.sendall(empacotar(MSG_ECHO, eco))
           elif tipo == MSG_ERROR:
               break
           else:
               con.sendall(empacotar(MSG_ERROR, b"Tipo invalido no chat"))
               break
   except (ConnectionError, OSError) as e:
       print(f"[SERVIÇO] Cliente desconectou: {e}")
   except ValueError as e:
       print(f"[SERVIÇO] Erro no chat: {e}")
   ```

2. Verificar imports de `HEADER_FORMAT`, `HEADER_SIZE`, `MSG_CHAT`, `MSG_ECHO`
3. `_recv_exato` já existe como método estático da classe

**Critério de aceite:**
- [ ] Cliente envia `MSG_CHAT` com texto → recebe `MSG_ECHO` de volta
- [ ] Chat continua por múltiplas mensagens até cliente desconectar
- [ ] `MSG_ERROR` no chat encerra loop

**Dependências:** #25

---

### #27 — Script de teste de ataque (4 cenários)

**Arquivo:** `scripts/testar_ataque.py`

**Descrição:** Implementar 4 cenários de ataque que demonstram que as
proteções do protocolo funcionam. Script requer servidores rodando.

**Cenário 1 — Replay de TGT expirado:**

1. Gerar TGT com timestamp antigo (`int(time.time()) - 100000`)
2. Cifrar com `as_master.key`, enviar `MSG_TGS_REQUEST` ao TGS
3. Verificar resposta é `MSG_ERROR` (tipo 9) com mensagem "expirado"
4. Imprimir: `[TESTE 1] Replay de TGT expirado → BLOQUEADO ✓`

**Cenário 2 — Replay de authenticator:**

1. Capturar authenticator válido com timestamp fora da `JANELA_AUTH`
2. Enviar `MSG_SVC_REQUEST` ao Serviço com o authenticator capturado
3. Verificar resposta é `MSG_ERROR` com mensagem de replay
4. Imprimir: `[TESTE 2] Replay de authenticator → BLOQUEADO ✓`

**Cenário 3 — Ticket com chave errada:**

1. Gerar Service Ticket cifrado com chave aleatória
2. Enviar `MSG_SVC_REQUEST` ao Serviço
3. Verificar resposta é `MSG_ERROR` (decifragem falha)
4. Imprimir: `[TESTE 3] Ticket com chave errada → BLOQUEADO ✓`

**Cenário 4 — Usuário inexistente:**

1. Conectar no AS e enviar `MSG_AUTH_REQUEST` com nome não cadastrado
2. Verificar resposta é `MSG_ERROR` com "não encontrado"
3. Imprimir: `[TESTE 4] Usuário inexistente → BLOQUEADO ✓`

**Função `main()`:**

```python
def main():
    print("=== Testes de Ataque — Kerberos Chat ===\n")
    testes = [
        ("Replay de TGT expirado", teste_replay_tgt_expirado),
        ("Replay de authenticator", teste_replay_authenticator),
        ("Ticket com chave errada", teste_ticket_chave_errada),
        ("Usuário inexistente", teste_usuario_inexistente),
    ]
    for nome, func in testes:
        try:
            func()
        except Exception as e:
            print(f"[FALHA] {nome}: {e}")
    print("\n=== Fim dos testes ===")
```

**Critério de aceite:**
- [ ] Cada teste produz saída `BLOQUEADO ✓` ou `FALHA ✗`
- [ ] Script roda sem intervenção manual (usa constantes do config)
- [ ] Código comentado explicando cada ataque
- [ ] Requer servidores AS, TGS, Serviço rodando (documentar no topo)

**Dependências:** #14 (AS funcionando), #23 (expiração), #26 (chat)

---

### #32 — Cliente: extrair lógica de UI para `ui.py`

**Arquivos:** `client/ui.py`, `client/client.py`

**Descrição:** `ui.py` é stub de 1 linha. Lógica de interface está inline
em `client.py`. Extrair para módulo separado como previsto na spec.

**Plano:**

1. Em `client/ui.py`, implementar as 4 funções:
   ```python
   def perguntar_usuario() -> str:
       return input("Usuário: ").strip()

   def perguntar_senha() -> str:
       import getpass
       return getpass.getpass("Senha: ")

   def mostrar_status(msg: str) -> None:
       print(msg)

   def menu_chat() -> str:
       return input("> ").strip()
   ```

2. Em `client/client.py`, importar e usar as funções de `ui.py`

**Critério de aceite:**
- [ ] `ui.py` contém as 4 funções com assinaturas corretas
- [ ] `client.py` não chama `input()`/`getpass()`/`print()` diretamente
- [ ] Comportamento do cliente inalterado
- [ ] Testes existentes continuam passando

**Dependências:** nenhuma

**Nota:** Baixa prioridade. Fechar como "wontfix" se preferir manter inline.

---

## 🆕 Novas issues

---

### #41 — AS: refatorar imports para `common.*`

**Arquivo:** `as_server/as_server.py` (linhas 14–43)

**Descrição:** O AS usa imports relativos com fallback
(`try: from .config ... except ImportError: from config ...`).
O fallback assume que `config.py`, `protocol.py`, `crypto.py` existem
em `as_server/` — não existem. O AS só funciona com `python -m`.
Demais servidores usam `from common.*` sem fallback.

**Plano:**

1. Remover todo o bloco `try/except ImportError`
2. Substituir por:
   ```python
   from common.config import AS_HOST, AS_PORT, USER_DB_PATH, AS_MASTER_KEY_PATH, LIFETIME_TICKET
   from common.protocol import MSG_AUTH_REQUEST, MSG_AUTH_REPLY, MSG_ERROR, desempacotar, empacotar, criar_ticket
   from common.crypto import cifrar_aes_gcm
   from as_server.user_db import UserDB
   ```
3. Atualizar `_carregar_chave_mestra()` para usar `AS_MASTER_KEY_PATH`

**Critério de aceite:**
- [ ] `python as_server/as_server.py` funciona como script standalone
- [ ] `python -m as_server.as_server` também funciona
- [ ] Sem blocos `try/except ImportError`

**Dependências:** nenhuma

---

### #42 — AS: usar `AS_MASTER_KEY_PATH` do config

**Arquivo:** `as_server/as_server.py` (linha 280)

**Descrição:** Caminho `"keys/as_master.key"` está hardcoded na chamada a
`_carregar_chave_mestra()`. TGS já usa config — alinhar o AS.

**Plano:**

1. Substituir `_carregar_chave_mestra("keys/as_master.key")` por
   `_carregar_chave_mestra(AS_MASTER_KEY_PATH)`

**Critério de aceite:**
- [ ] Nenhum caminho hardcoded no AS
- [ ] AS carrega chave do caminho indicado no config

**Dependências:** #41

---

### #43 — AS: catch `InvalidTag` em vez de `Exception` genérico

**Arquivo:** `as_server/as_server.py`

**Descrição:** AGENTS.md exige catch específico de `InvalidTag` para
AES-GCM. TGS já corrigido. AS ainda usa `except Exception` genérico.

**Plano:**

1. Adicionar import: `from cryptography.exceptions import InvalidTag`
2. Substituir `except Exception` envolvendo `decifrar_aes_gcm()` por:
   ```python
   except InvalidTag:
       # chave errada ou dados violados
   except Exception as exc:
       # outros erros inesperados
   ```

**Critério de aceite:**
- [ ] Nenhum `except Exception` genérico em operações AES-GCM
- [ ] `InvalidTag` produz MSG_ERROR

**Dependências:** #41

---

### #44 — Remover stubs órfãos

**Arquivos:** `as_server/kdf.py`, `service/handler.py`, `client/ui.py`

**Descrição:** Três arquivos de 1 linha (só docstring). Funcionalidades
já existem em outros lugares:
- `kdf.py`: KDF em `common/crypto.py`
- `handler.py`: chat será implementado em `service_server.py` (#26)
- `ui.py`: se #32 for wontfix, UI permanece inline

**Plano:**

1. Verificar com `grep -r "from.*kdf\|from.*handler\|from.*ui"` se
   algum import referencia os arquivos
2. Remover com `git rm` para cada stub confirmado como não referenciado:
   `as_server/kdf.py`, `service/handler.py`, `client/ui.py`

**Critério de aceite:**
- [ ] Nenhum import quebrado
- [ ] Testes continuam passando

**Dependências:** #26, #32 (decisão sobre cada stub)

---

## Resumo de dependências

```
#14 (AS fix TGT) ──┬── #41 (AS imports) ── #42 (config key) ── #43 (InvalidTag)
                   │
                   └── fluxo ponta-a-ponta funcional
                        │
                        ├── #23 (Serviço expiração)
                        ├── #26 (Echo chat)
                        │        │
                        │        └── #27 (Teste ataque)
                        │
                        ├── #32 (UI) → opcional
                        └── #44 (stubs) → após #26 e decisão #32
```
