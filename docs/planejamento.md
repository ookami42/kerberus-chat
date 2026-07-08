# Planejamento e Coordenação

> Planejamento da equipe, divisão de tarefas, relatório e apresentação.
> Conteúdo extraído do README principal para manter a documentação técnica
> separada da coordenação acadêmica.

---

## Divisão do Trabalho (Issues)

O projeto foi dividido em **40 tarefas atômicas** no estilo GitHub Issues.
Cada pessoa escolhe uma issue, implementa, abre PR, outra revisa. Depois pega outra.

> Lista completa em [`issues_projeto.md`](issues_projeto.md)

---

### Ordem sugerida para começar

**Legenda:** `#N` = número da issue. Dependências indicam issues que precisam estar prontas antes.

1. **Issues #2, #3, #4** (crypto) — 1 pessoa, 1-2 dias
2. **Issues #5, #6, #7** (message) — 1 pessoa, 1 dia
3. **Issue #1** (config) — 1 pessoa, 30 min
4. **Issues #8, #9, #10** (chaves + usuários) — 1 pessoa, 1 dia
5. **Issues #11, #12, #13, #14, #15** (AS) — 1 pessoa, 2-3 dias
6. **Issues #16, #17, #18, #19, #20** (TGS) — 1 pessoa, 2-3 dias
7. **Issues #21, #22, #23, #24, #25, #26** (Serviço) — 1 pessoa, 2-3 dias
8. **Issues #28, #29, #30, #31, #32, #33** (Cliente) — 1 pessoa, 3-4 dias
9. **Issue #27** (teste de ataque) — 1 pessoa, 1 dia
10. **Issues #34 a #40** (docs + relatório) — TODOS

---

### Resumo de Dependências

```
#1  (config)
 ├─ #9  (UserDB)
 │   └─ #10 (cadastrar usuário)
 ├─ #11 (esqueleto AS)
 │   └─ #12 (receber request AS)
 │       └─ #13 (derivar chave AS)
 │           └─ #14 (montar TGT)
 │               └─ #15 (responder AS) ← depende de #2
 ├─ #16 (esqueleto TGS)
 │   └─ #17 (receber request TGS)
 │       └─ #18 (decifrar TGT TGS)
 │           └─ #19 (gerar Service Ticket)
 │               └─ #20 (responder TGS) ← depende de #2
 ├─ #21 (esqueleto Serviço)
 │   └─ #22 (receber request Serviço)
 │       └─ #23 (decifrar ticket Serviço)
 │           └─ #24 (validar authenticator)
 │               └─ #25 (autenticação mútua)
 │                   └─ #26 (echo chat)
 └─ #28 (cliente AS)
     └─ #29 (decifrar K_c_AS)
         └─ #30 (cliente TGS)
             └─ #31 (cliente Serviço)
                 └─ #33 (cliente completo)
```

**Issues independentes (qualquer hora):** #2, #3, #4, #5, #6, #7, #8, #32, #34

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
