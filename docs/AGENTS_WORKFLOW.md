# Contratos Operacionais dos Agentes — Sentinel Guard

Este documento define a topologia e os contratos de responsabilidade para execução coordenada dos Marcos do **Sentinel Guard**.

## Topologia

```text
                  ┌──────────────────────────────────┐
                  │   AGENTE 0: ORQUESTRADOR         │
                  │ (Tech Lead / Arquiteto / Git)    │
                  └─────────────────┬────────────────┘
                                    │ Decompõe tarefas e valida contratos
        ┌───────────────────────────┼───────────────────────────┐
        ▼                           ▼                           ▼
┌───────────────────┐     ┌───────────────────┐     ┌───────────────────┐
│ AGENTE 1: CODER   │     │ AGENTE 2: QA /    │     │ AGENTE 3: APPSEC  │
│ (Rust & Vue Dev)  │────▶│ TEST ENGINEER     │────▶│ (Security Auditor)│
└───────────────────┘     └───────────────────┘     └───────────────────┘
```

## Contratos

### Agente 0: Orquestrador (Tech Lead)
- Lê `docs/ARCHITECTURE.md` e decompõe o Marco em tarefas atômicas por branch `feat/<marco>-<escopo>`.
- Cria a branch a partir de `develop`.
- Garante a sequência: Implementação (Agente 1) → Testes e Qualidade (Agente 2) → Auditoria AppSec (Agente 3) → Commit Conventional → Merge `--no-ff` em `develop`.
- **Regra de Bloqueio:** Nunca permitir imports de infraestrutura dentro de `src/domain/`.

### Agente 1: Engenheiro de Implementação (`coder_agent`)
- Implementa seguindo SOLID, DRY e as traits em `src/domain/ports.rs`.
- **Proibições absolutas:**
  - `.unwrap()` ou `.expect()` em código de produção (`src/` fora de `#[cfg(test)]`).
  - Carregamento integral de arquivos em memória (`tokio::fs::read` / `std::fs::read` banidos para arquivos inspecionados; utilizar streaming em chunks de 64 KB = `65536` bytes).
  - Hardcoding de caminhos operacionais ou tokens.
  - Imports de infraestrutura (`sqlx`, `notify`, `tokio::fs`, `infer`, `dotenvy`, `axum`) em `src/domain/` ou `src/application/`.

### Agente 2: Engenheiro de QA e Testes (`qa_agent`)
- Escreve testes unitários e de integração cobrindo caminho feliz e casos de borda:
  - Arquivos vazios (0 bytes).
  - Spoofing de Magic Bytes (ex: ELF `0x7F 0x45 0x4C 0x46` com extensão `.pdf`, PE `0x4D 0x5A` com `.jpg`).
  - Streaming > 64 KB (ex: 256 KB).
  - Path Traversal (`../`) e bloqueio de diretórios críticos (`/etc`, `/bin`, `/usr`, `/root`).
  - Escrita lenta em disco aguardando `IN_CLOSE_WRITE`.
- Executa `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` e `cargo test --all-targets`.
- Nunca altera regra de negócio para forçar passagem de testes.

### Agente 3: Auditor de Segurança (`appsec_agent`)
- Audita `git diff` antes de cada commit verificando:
  1. Proteção de segredos (`SecretString`) e ausência de exposição em logs ou `Debug`.
  2. Prevenção de Path Traversal (`canonicalize`, lista de diretórios críticos bloqueados, sanitização de `file_name()`).
  3. Mitigação de TOCTOU e aplicação de permissões não-executáveis (`chmod -x`).
  4. Ausência de `.unwrap()`/`.expect()` em produção e ausência de command injection.
- Emite parecer obrigatório `APPROVED` ou `REJECTED` (com arquivo e linha exata).
