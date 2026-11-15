# Especificação Técnica e Arquitetura: Sentinel Guard

**Versão:** 1.0.0  
**Status:** Aprovado para Desenvolvimento (Marco 1 → Marco 3)  
**Stack Principal:** Rust (Tokio, Axum, tokio-rusqlite / rusqlite, Notify), Vue 3 (SPA Estática via `rust-embed`), SQLite (`bundled` >= 3.54), Suricata IDS, ClamAV.

## 1. Visão Geral e Escopo do Sistema

O **Sentinel Guard** é um daemon de segurança de baixo consumo de recursos (target: `< 25 MB` RAM em operação) projetado para atuar como uma camada de inspeção e quarentena automatizada entre uma rede não confiável (máquina de downloads/torrents conectada via VPN) e um servidor Homelab (armazenamento final via Samba/SFTP).

### 1.1 Objetivos Arquiteturais

- **Zero-Trust na Ingestão:** Nenhum arquivo transferido via VPN/Samba/SFTP entra diretamente nos diretórios de produção sem passar por validação de integridade, *magic bytes*, assinatura antivírus e correlação de alertas de rede.
- **Eficiência de Memória (Streaming I/O):** Arquivos grandes (ISOs, cursos compactados de dezenas de GB) devem ser processados em *chunks* de 64 KB (`65536` bytes), proibindo o carregamento integral em memória RAM.
- **Binário Único Autônomo:** O frontend web compilado é embutido no binário Rust (`rust-embed`), eliminando a necessidade de runtimes Node.js ou servidores web externos no Homelab.
- **Configuração Híbrida (Bootstrap vs. Runtime):** Segredos e parâmetros de inicialização residem em `.env`; caminhos operacionais (ex: diretório do Samba, diretório de destino) são carregados inicialmente via `.env` e persistidos em SQLite para alteração dinâmica via Interface Web sem reiniciar o daemon.

## 2. Arquitetura de Software (SOLID, DRY & Clean Architecture)

Para aplicar **SOLID** e **DRY** em Rust, o sistema adota **Composição, Traits (Interfaces) e Injeção de Dependência via `Arc<dyn Trait>`**.

### 2.1 Estrutura de Diretórios (Workspace)

```text
Sentinel Guard/
├── sentinel_guard/               # Backend Rust (Daemon, Core, Docs, Migrations)
│   ├── Cargo.toml
│   ├── Makefile
│   ├── .env.example
│   ├── .gitignore
│   ├── docs/
│   │   ├── ARCHITECTURE.md       # Este documento (Contexto mestre para Agentes)
│   │   └── AGENTS_WORKFLOW.md    # Contratos dos agentes orquestrados
│   ├── migrations/               # Scripts SQL versionados (aplicados via execute_batch no startup)
│   ├── tests/                    # Testes de integração
│   └── src/
│       ├── main.rs               # Composition Root (Injeção de dependências e bootstrap)
│       ├── domain/               # Camada Core (Regras de negócio puras, sem I/O)
│       │   ├── mod.rs
│       │   ├── entities.rs       # Structs: FileArtifact, SecurityVerdict, NetworkAlert, RuntimeConfig
│       │   ├── errors.rs         # Enum unificado de erros de domínio (thiserror)
│       │   └── ports.rs          # Traits (Interfaces): HashCalculator, MimeValidator, FileScanner, QuarantineMover, ConfigStore, QuarantineRepo
│       ├── application/          # Casos de Uso (Orquestração SOLID)
│       │   ├── mod.rs
│       │   ├── inspect_file.rs   # Caso de uso: Pipeline de validação de arquivo
│       │   └── update_config.rs  # Caso de uso: Atualização dinâmica de caminhos Samba
│       ├── infrastructure/       # Adaptadores Externos (Implementações das Traits)
│       │   ├── mod.rs
│       │   ├── config_env.rs     # Leitura segura de .env (secrecy crate)
│       │   ├── fs_watcher.rs     # Implementação Linux inotify (notify) e movimentação segura
│       │   ├── magic_bytes.rs    # Streaming SHA-256 + Inspetor de cabeçalho binário (infer)
│       │   ├── clamav_client.rs  # Cliente Unix Socket para clamd (Marco 2)
│       │   ├── suricata_tail.rs  # Leitor assíncrono de eve.json (Marco 2)
│       │   └── sqlite_repo.rs    # Persistência de logs, hashes e configs dinâmicas
│       └── presentation/         # Camada Web e Tempo Real (Marco 3)
│           ├── mod.rs
│           ├── api_routes.rs     # Handlers Axum REST (/api/v1/...)
│           ├── sse_broadcaster.rs# Stream Server-Sent Events para alertas live
│           └── static_assets.rs  # Embedding do build Vue (`../vue_sentinel_guard/dist`)
└── vue_sentinel_guard/           # Frontend Web (Vue 3 + Vite + TypeScript)
```

### 2.2 Aplicação dos Princípios SOLID no Rust

1. **Single Responsibility (SRP):** `fs_watcher.rs` apenas escuta eventos `IN_CLOSE_WRITE` e publica o caminho em um canal `mpsc`. Não calcula hashes nem inspeciona conteúdo.
2. **Open/Closed (OCP):** `InspectFileUseCase` recebe `Vec<Arc<dyn FileScanner>>`. Adicionar o ClamAV no Marco 2 significa implementar `FileScanner` e registrá-lo em `main.rs`, sem alterar a lógica de orquestração existente.
3. **Liskov Substitution (LSP):** Qualquer implementação de `ConfigStore` (em memória para testes ou SQLite em produção) comporta-se de maneira idêntica sob o contrato da trait.
4. **Interface Segregation (ISP):** Traits pequenas e focadas (`HashCalculator`, `MimeValidator`, `FileScanner`, `QuarantineMover`, `ConfigStore`, `QuarantineRepo`).
5. **Dependency Inversion (DIP):** As camadas `domain` e `application` nunca importam crates de infraestrutura (`tokio-rusqlite`, `rusqlite`, `notify`, `tokio::fs`, `infer`, `dotenvy`, `axum`). Elas dependem apenas de abstrações definidas em `domain/ports.rs`.

## 3. Gerenciamento de Configuração, Segredos e Segurança

### 3.1 Política de Variáveis de Ambiente (`.env` vs. Banco Dinâmico)

- **Camada 1 — Bootstrap (`.env`):** `APP_ENV`, `BIND_ADDRESS`, `ADMIN_API_TOKEN` (`secrecy::SecretString`), `DATABASE_URL`, `DEFAULT_QUARANTINE_DIR`, `DEFAULT_APPROVED_DIR`, `CLAMD_SOCKET_PATH`, `SURICATA_EVE_PATH`.
- **Camada 2 — Runtime Dinâmico (SQLite + `Arc<RwLock<RuntimeConfig>>`):**
  - Ao iniciar, o daemon lê a tabela `system_config` do SQLite. Se estiver vazia (primeiro boot), popula com os valores `DEFAULT_*` do `.env`.
  - Quando o usuário altera o caminho pela camada de aplicação/web:
    1. Valida se o novo diretório existe e possui permissões de escrita/leitura (`fs::metadata`).
    2. Previne **Path Traversal** canonicalizando o caminho (`std::fs::canonicalize`) e bloqueando diretórios críticos do SO (`/etc`, `/bin`, `/usr`, `/root`, `/sbin`, `/lib`, `/lib64`, `/proc`, `/sys`, `/dev`, `/boot`).
    3. Atualiza o SQLite e o estado em memória (`RwLock`), sinalizando ao `fs_watcher` via canal `watch` para reiniciar o monitoramento no novo caminho sem derrubar o daemon.

### 3.2 Controles Obrigatórios de Segurança (AppSec)

1. **Proteção de Segredos em Memória:** Utilizar `secrecy::SecretString` para armazenar `ADMIN_API_TOKEN`, impedindo vazamento acidental em logs (`Debug`).
2. **Prevenção de Path Traversal na Movimentação:** Extrair estritamente o `file_name()` sanitizado, rejeitando componentes `..`, `/`, `\` ou bytes nulos.
3. **Permissões Restritas (Least Privilege):** Forçar `chmod -x` em arquivos na quarentena (`0o640` em processamento, `0o600` quando isolado como malicioso, `0o640` no destino aprovado).
4. **Proibição de `.unwrap()` / `.expect()`:** Todo código de produção deve propagar erros via `?` com `DomainError`.
5. **Auditoria de Dependências e Persistência Segura (SQLite):** `cargo audit` (Rust) e `npm audit` (Frontend) antes de cada merge em `main`.
   - **Decisão Técnica de Segurança (`sec/migrate-tokio-rusqlite`):** A camada de persistência utiliza `tokio-rusqlite` / `rusqlite` com SQLite `bundled` (>= 3.54 / `libsqlite3-sys >= 0.40`) em substituição ao `sqlx`, eliminando as vulnerabilidades `RUSTSEC-2026-0459` (`libsqlite3-sys 0.30.1`) e `RUSTSEC-2023-0071` (`rsa 0.9.10`, transitiva do driver MySQL do `sqlx`). A abertura do banco aplica validação estrita de `DATABASE_URL` (bloqueio de `..`, bytes nulos, diretórios críticos do SO e arquivos/sidecars `.db` que sejam symlinks), `OpenFlags` explícitas sem `SQLITE_OPEN_URI`, modo WAL com `busy_timeout(5s)`, endurecimento de permissões (`0o600` em `.db`, `-wal` e `-shm`) e queries exclusivamente parametrizadas (`params!`).

## 4. Fluxo Git, Estratégia de Branches e Padrão de Commits

- `main`: Código estável e testado.
- `develop`: Branch de integração contínua entre marcos.
- `feat/<marco>-<escopo>`: Novas funcionalidades.
- `fix/<escopo>`: Correções de bugs.
- `sec/<escopo>`: Hardening ou correções de segurança.
- `test/<escopo>`: Adição de testes.
- **Conventional Commits:** `<tipo>(<escopo>): <descrição curta no imperativo em até 72 caracteres>`.

## 5. Pirâmide de Testes e Critérios de Aceite

1. **Testes Unitários:** Mocks das traits em `domain::ports`.
2. **Testes de Integração (`tests/`):** Diretórios temporários reais (`tempfile::tempdir()`), escrita lenta aguardando `IN_CLOSE_WRITE`, isolamento de ELF spoofado e recarga dinâmica.
3. **Qualidade Estática:** `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test --all-targets`.

## 6. Protocolo de Orquestração de Agentes de IA

- **Agente 0 (Orquestrador / Tech Lead):** Decompõe tarefas, gerencia branches/commits e coordena os agentes.
- **Agente 1 (Coder):** Implementa em Rust/Vue respeitando SOLID, DRY e proibições de segurança.
- **Agente 2 (QA / Test Engineer):** Escreve e executa testes unitários e de integração + Clippy/Fmt.
- **Agente 3 (AppSec Auditor):** Revisa `git diff` antes de cada commit e emite `APPROVED` ou `REJECTED`.

## 7. Roadmap de Execução por Sprints (Marcos)

- **Sprint 1 (Marco 1 — Core & File Inspection):**
  - `feat/m1-project-setup`
  - `feat/m1-streaming-inspector`
  - `feat/m1-inotify-quarantine`
- **Sprint 2 (Marco 2 — Integração IDS & Antivírus no Homelab):**
  - `feat/m2-clamav-adapter`
  - `feat/m2-suricata-correlator`
- **Sprint 3 (Marco 3 — Interface Web Vue & Single Binary):**
  - `feat/m3-axum-api-sse`
  - `feat/m3-vue-dashboard`
