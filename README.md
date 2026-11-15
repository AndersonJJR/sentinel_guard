# Sentinel Guard — Daemon & Backend Rust

**Sentinel Guard** é um daemon de segurança **Zero-Trust** de baixíssimo consumo de recursos (alvo `< 25 MB` de RAM), construído em **Rust** (`tokio`, `axum`, `tokio-rusqlite`/SQLite e `notify`), que embute o dashboard web **Vue 3** em um **binário único** via `rust-embed`.

Ele atua como uma camada automatizada de inspeção, quarentena e contenção entre uma **origem ou rede não confiável** (downloads, torrents via VPN, compartilhamentos Samba ou SFTP) e o **diretório de armazenamento final do Homelab**, garantindo que nenhum arquivo entre no repositório confiável sem passar por validação criptográfica, assinatura binária (*magic bytes*), varredura antivírus e correlação com telemetria de rede.

---

## Sumário

1. [Como Funciona (Pipeline de Inspeção Zero-Trust)](#como-funciona-pipeline-de-inspeção-zero-trust)
2. [Arquitetura e Estrutura de Diretórios](#arquitetura-e-estrutura-de-diretórios)
3. [Pré-requisitos](#pré-requisitos)
4. [Passo a Passo: Configuração e Execução](#passo-a-passo-configuração-e-execução)
5. [Endpoints da API REST e SSE](#endpoints-da-api-rest-e-sse)
6. [Comandos de Desenvolvimento, Testes e Auditoria](#comandos-de-desenvolvimento-testes-e-auditoria)

---

## Como Funciona (Pipeline de Inspeção Zero-Trust)

```text
  Origem não confiável (VPN / Samba / SFTP / Downloads)
                         │
                         ▼  evento IN_CLOSE_WRITE (Linux inotify)
         ┌───────────────────────────────┐
         │ 1. InotifyWatcher             │  src/infrastructure/fs_watcher.rs
         └───────────────┬───────────────┘
                         ▼  hardening de path, anti-symlink e chmod não executável
         ┌───────────────────────────────┐
         │ 2. Streaming Hash + Magic     │  src/infrastructure/magic_bytes.rs
         │    (buffers de 64 KB)         │  SHA-256 + infer (extension spoofing)
         └───────────────┬───────────────┘
                         ▼  socket Unix zINSTREAM\0 (chunks de 64 KB)
         ┌───────────────────────────────┐
         │ 3. ClamAV (clamd)             │  src/infrastructure/clamav_client.rs
         └───────────────┬───────────────┘
                         ▼  tail incremental NDJSON (linhas <= 64 KB)
         ┌───────────────────────────────┐
         │ 4. Suricata IDS (eve.json)    │  src/infrastructure/suricata_tail.rs
         └───────────────┬───────────────┘
                         │
            ┌────────────┴────────────┐
            ▼                         ▼
    [Veredito: Clean]        [Suspeito / Reprovado]
            │                         │
            ▼                         ▼
   Movimentação segura       Isolamento em .isolated
    para approved_dir         (chmod 0o600 / dir 0o700)
     (chmod 0o640)                    │
            └────────────┬────────────┘
                         ▼
      Persistência SQLite WAL (src/infrastructure/sqlite_repo.rs)
      + Transmissão em tempo real via SSE (/api/v1/events/stream)
```

Cada etapa do pipeline segue o princípio de **Zero-Trust** e I/O em streaming com memória constante:

1. **Monitoramento em tempo real (`IN_CLOSE_WRITE`) — `src/infrastructure/fs_watcher.rs`**:
   - O `InotifyWatcher` monitora de forma não recursiva o diretório de quarentena via Linux `inotify` (crate `notify`), disparando a inspeção somente em eventos `AccessKind::Close(AccessMode::Write)` (`IN_CLOSE_WRITE`), ou seja, após o término da escrita do arquivo.
   - Suporta *hot-reload* automático do diretório observado sempre que a configuração é alterada via API.

2. **Sanitização de caminho, proteção contra *Path Traversal* e *Hardening* — `src/domain/path_policy.rs` e `src/infrastructure/fs_watcher.rs`**:
   - Rejeita nomes inválidos, `..`, *null bytes*, symlinks (inclusive em diretórios ancestrais), diretórios críticos do sistema (`/etc`, `/bin`, `/usr`, `/root`, `/sbin`, `/lib`, `/lib64`, `/proc`, `/sys`, `/dev`, `/boot`, `/`) e desvios TOCTOU verificando identidade (`dev`/`ino`).
   - Remove permissões de execução imediatamente antes da análise (`0o640` em quarentena/aprovados; `0o600` para arquivos isolados).

3. **Leitura em streaming de `64 KB`, Hash SHA-256 e *Magic Bytes* — `src/infrastructure/magic_bytes.rs`**:
   - **Nunca carrega arquivos inteiros na RAM**: o `StreamingHasher` lê o arquivo em *chunks* fixos de `64 KB` (`65.536` bytes) via `tokio::fs::File` para calcular o digest SHA-256 e o tamanho total.
   - O `MagicBytesInspector` inspeciona os primeiros até `8 KB` do arquivo utilizando a crate `infer` (e detecção auxiliar de executáveis/binários) e confronta o MIME real com a extensão declarada para identificar **extension spoofing** (ex.: binário ELF/PE renomeado para `.pdf` ou `.jpg`) e bloquear extensões executáveis/ativas perigosas.

4. **Varredura Antivírus via socket Unix `INSTREAM` no ClamAV — `src/infrastructure/clamav_client.rs`**:
   - O `ClamAvScanner` conecta-se diretamente ao Unix domain socket do `clamd` e transmite o conteúdo em *streaming* usando o comando `zINSTREAM\0` em blocos de `64 KB`, sem jamais expor caminhos do sistema de arquivos ao daemon antivírus e com timeout configurável (padrão de `30s`).

5. **Correlação assíncrona com alertas de rede do Suricata IDS — `src/infrastructure/suricata_tail.rs`**:
   - O `SuricataCorrelator` realiza *tail* assíncrono incremental do arquivo NDJSON `eve.json` com `BufReader` (limite estrito de `64 KB` por linha e janela inicial máxima de `256 KB`), tratando rotação/truncamento de logs via `dev`/`ino` e tamanho.
   - Mantém um *ring buffer* limitado em memória (máximo de `1.024` alertas dentro da janela padrão de `600s` e severidade `<= 2`). Caso haja alerta ativo compatível durante a inspeção, emite o veredito `SuspiciousNetworkCorrelation`.

6. **Disposição final e Persistência SQLite — `src/infrastructure/fs_watcher.rs` e `src/infrastructure/sqlite_repo.rs`**:
   - **Aprovados (`SecurityVerdict::Clean`)**: movidos de forma atômica (ou por cópia segura em streaming de `64 KB` + `fsync` entre filesystems diferentes) para `approved_dir` com permissão `0o640` e proteção contra colisão de nomes.
   - **Reprovados (`MaliciousSpoofing`, `MaliciousSignature`, `SuspiciousNetworkCorrelation`, `CorruptedOrUnreadable`)**: isolados em `<quarantine_dir>/.isolated` (diretório `0o700`, arquivo `0o600` sem permissão de execução).
   - **Persistência**: o `SqliteStore` utiliza `tokio-rusqlite` (SQLite embutido em modo `WAL`) para gravar relatórios de auditoria (`quarantine_logs`) e configurações operacionais (`system_config`).

7. **Servidor Web Único (API REST + SSE + SPA Vue 3) — `src/presentation/`**:
   - O servidor **Axum** serve no mesmo endereço/porta a API autenticada `/api/v1/...`, o stream em tempo real **Server-Sent Events** (`/api/v1/events/stream`) e os assets compilados do dashboard Vue 3 embutidos no binário via `rust-embed`.

---

## Arquitetura e Estrutura de Diretórios

O projeto segue estritamente **Clean Architecture**, **SOLID** e separação clara de responsabilidades:

```text
sentinel_guard/
├── Cargo.toml                         # Dependências Rust (Edition 2024)
├── Makefile                           # Automação de build (Vue + Rust), testes, lint e auditoria
├── .env.example                       # Modelo de variáveis de ambiente para bootstrap
├── migrations/
│   └── 20261114000001_init.sql        # Schema inicial SQLite (system_config, quarantine_logs)
├── src/
│   ├── lib.rs                         # Exposição pública das camadas da arquitetura
│   ├── main.rs                        # Composition root, validação fail-fast e loop do daemon
│   ├── domain/                        # Núcleo puro de domínio (sem dependências de infraestrutura)
│   │   ├── entities.rs                # FileArtifact, SecurityVerdict, InspectionReport, RuntimeConfig, NetworkAlert
│   │   ├── errors.rs                  # Enum DomainError (thiserror)
│   │   ├── path_policy.rs             # Políticas de sanitização, bloqueio de dirs do sistema e anti-traversal
│   │   └── ports.rs                   # Traits/Portas: HashCalculator, MimeValidator, FileScanner, QuarantineMover, ConfigStore, QuarantineRepo
│   ├── application/                   # Casos de uso orquestrando regras e portas do domínio
│   │   ├── inspect_file.rs            # InspectFileUseCase (pipeline completo de inspeção e disposição)
│   │   └── update_config.rs           # UpdateConfigUseCase (validação de caminhos, persistência e hot-reload)
│   ├── infrastructure/                # Adaptadores concretos de I/O e serviços externos
│   │   ├── config_env.rs              # BootstrapConfig (.env com proteção secrecy::SecretString)
│   │   ├── fs_watcher.rs              # InotifyWatcher (IN_CLOSE_WRITE) e FsQuarantineMover
│   │   ├── magic_bytes.rs             # StreamingHasher (64 KB) e MagicBytesInspector (infer)
│   │   ├── clamav_client.rs           # ClamAvScanner (socket Unix + zINSTREAM\0)
│   │   ├── suricata_tail.rs           # SuricataCorrelator (tail assíncrono de eve.json)
│   │   └── sqlite_repo.rs             # SqliteStore (ConfigStore + QuarantineRepo em WAL mode)
│   └── presentation/                  # Interface HTTP, SSE e assets estáticos do SPA
│       ├── api_routes.rs              # Rotas /api/v1/*, auth Bearer em tempo constante e headers de segurança
│       ├── sse_broadcaster.rs         # SseBroadcaster (/api/v1/events/stream com keep-alive de 15s)
│       └── static_assets.rs           # EmbeddedFrontendAssets (rust-embed de ../vue_sentinel_guard/dist)
└── tests/                             # Testes de integração de ponta a ponta
    ├── integration_quarantine.rs
    ├── m1_setup_integration.rs
    ├── m1_streaming_inspector_integration.rs
    ├── m2_clamav_integration.rs
    ├── m2_suricata_integration.rs
    ├── m3_api_sse_integration.rs
    └── m3_static_assets_integration.rs
```

---

## Pré-requisitos

### Para compilar e testar localmente
- **Rust / Cargo** com suporte à **Edition 2024** (Rust `1.85+`).
- **Node.js** (`^22.18.0` ou `>= 24.12.0`) e **npm** — necessários para compilar o frontend irmão em `../vue_sentinel_guard` durante o `make build`.
  - Na primeira compilação do frontend, certifique-se de ter executado `npm install` dentro de `../vue_sentinel_guard`.
- **SQLite**: já vem embutido na compilação via feature `bundled` do `tokio-rusqlite` (não exige instalação de biblioteca externa em runtime).
- **Linux com `inotify`**: necessário para monitoramento nativo de eventos `IN_CLOSE_WRITE` e sockets Unix.

### Para ambiente completo / produção
- **ClamAV (`clamd`)**: daemon antivírus em execução expondo o socket Unix configurado em `CLAMD_SOCKET_PATH` (ex.: `/var/run/clamav/clamd.ctl`) e com permissões de leitura/escrita para o usuário do Sentinel Guard.
- **Suricata IDS**: serviço gerando eventos NDJSON no caminho configurado em `SURICATA_EVE_PATH` (ex.: `/var/log/suricata/eve.json`) com permissão de leitura para o Sentinel Guard.
- **Opcional (auditoria de vulnerabilidades)**: `cargo-audit` (`cargo install cargo-audit`).

---

## Passo a Passo: Configuração e Execução

### Passo 1 — Configurar o `.env`

Copie o arquivo de exemplo para criar o seu `.env` local (nunca versione o `.env` real):

```bash
cp .env.example .env
```

Gere um token administrativo aleatório e forte de 64 caracteres hexadecimais:

```bash
openssl rand -hex 32
```

Edite o arquivo `.env` preenchendo o valor gerado em `ADMIN_API_TOKEN` e ajustando as demais variáveis conforme o ambiente:

| Variável | Exemplo (`.env.example`) | Descrição |
| :--- | :--- | :--- |
| `APP_ENV` | `production` | Identificador do ambiente de execução (ex.: `production`, `development`). |
| `BIND_ADDRESS` | `127.0.0.1:8080` | Endereço IP e porta (`SocketAddr`) onde o servidor Axum (API + SSE + Dashboard) irá escutar. |
| `ADMIN_API_TOKEN` | `change_me_to_a_64_char_random_hex_string` | Token secreto Bearer exigido em todos os endpoints `/api/v1/*` e no login do dashboard. |
| `DATABASE_URL` | `sqlite://sentinel.db?mode=rwc` | String de conexão do banco SQLite (cria o arquivo automaticamente se não existir; também aceita `sqlite::memory:` em testes). |
| `DEFAULT_QUARANTINE_DIR` | `/mnt/samba_quarantine` | Diretório inicial monitorado para arquivos não confiáveis (*seed* inicial gravado no SQLite na 1ª execução). |
| `DEFAULT_APPROVED_DIR` | `/mnt/homelab_storage/incoming` | Diretório inicial de destino para arquivos aprovados como `Clean` (*seed* inicial no SQLite). |
| `CLAMD_SOCKET_PATH` | `/var/run/clamav/clamd.ctl` | Caminho absoluto do Unix domain socket do daemon `clamd` (ClamAV). |
| `SURICATA_EVE_PATH` | `/var/log/suricata/eve.json` | Caminho absoluto do arquivo `eve.json` gerado pelo Suricata IDS. |

> **Nota sobre persistência de caminhos:** Na primeira execução, `DEFAULT_QUARANTINE_DIR`, `DEFAULT_APPROVED_DIR`, `CLAMD_SOCKET_PATH` e `SURICATA_EVE_PATH` são gravados na tabela `system_config` do SQLite. Alterações posteriores feitas via API (`PATCH /api/v1/config`) ou pelo dashboard sobrescrevem os valores persistidos no banco sem exigir reinício do daemon.

---

### Passo 2 — Preparar diretórios locais para teste rápido

Antes de iniciar o daemon, os diretórios configurados para quarentena e aprovados **devem existir**, ser **diretórios reais** (não symlinks), possuir permissão de escrita e **não podem ser iguais nem aninhados entre si**.

Para testar rapidamente na máquina local sem usar `/mnt/...`:

```bash
mkdir -p /tmp/sentinel_quarantine /tmp/sentinel_approved
```

Em seguida, ajuste o seu `.env`:

```dotenv
DEFAULT_QUARANTINE_DIR=/tmp/sentinel_quarantine
DEFAULT_APPROVED_DIR=/tmp/sentinel_approved
```

> **Dica de validação no startup:** No boot, `CLAMD_SOCKET_PATH` e `SURICATA_EVE_PATH` ainda podem não existir fisicamente (desde que seus caminhos sejam absolutos, sem `..`, sem symlinks e fora de diretórios proibidos do sistema). Porém, durante a inspeção de um arquivo real, `ClamAvScanner` precisará conectar ao socket do `clamd` e o diretório pai de `SURICATA_EVE_PATH` precisará existir para o `SuricataCorrelator` sincronizar alertas.

---

### Passo 3 — Compilar o Binário Único (Frontend Vue + Backend Rust)

Caso ainda não tenha instalado as dependências do frontend irmão:

```bash
cd ../vue_sentinel_guard && npm install && cd ../sentinel_guard
```

Execute o build completo de produção usando o `Makefile`:

```bash
make build
```

Esse comando executa duas etapas em sequência:
1. `make frontend-build`: entra em `../vue_sentinel_guard`, valida tipos com `npm run type-check` e gera os arquivos estáticos em `../vue_sentinel_guard/dist` via `npm run build`.
2. `cargo build --release`: compila o backend Rust e embute `../vue_sentinel_guard/dist` diretamente no binário final via `rust-embed`, gerando:

```text
./target/release/sentinel_guard
```

---

### Passo 4 — Executar o Daemon e Acessar o Dashboard

Inicie o binário compilado (ou rode em modo desenvolvimento com `cargo run`):

```bash
./target/release/sentinel_guard
```

*(Para logs mais detalhados durante testes, você pode definir `RUST_LOG=debug ./target/release/sentinel_guard`.)*

Com o daemon em execução:

1. Abra o navegador em **`http://127.0.0.1:8080`** (ou no endereço configurado em `BIND_ADDRESS`).
2. Na tela inicial do dashboard **Sentinel Guard**, informe o valor exato do seu **`ADMIN_API_TOKEN`** para autenticar a sessão.
3. Após autenticado, o dashboard passa a consumir os endpoints `/api/v1/*` e abre automaticamente a assinatura em tempo real via SSE (`/api/v1/events/stream`).

---

## Endpoints da API REST e SSE

Todas as rotas sob `/api/v1/*` exigem autenticação obrigatória via header HTTP:

```text
Authorization: Bearer <ADMIN_API_TOKEN>
```

> **Segurança da API:** A validação do token é feita em tempo constante (comparação SHA-256 via `subtle`), tokens passados via *query string* (`?token=...`) são rejeitados com `401 Unauthorized`, o tamanho máximo de payload JSON é de `64 KB` e todas as respostas incluem headers de endurecimento (`X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Content-Security-Policy` e `Cache-Control: no-store` nas rotas `/api/*`).

### Resumo das Rotas

| Método | Rota | Descrição |
| :--- | :--- | :--- |
| `GET` | `/api/v1/health` | Verifica saúde do serviço (`status: "ok"`), retorna o snapshot atual de `RuntimeConfig` e a contagem `sse_subscribers`. |
| `GET` | `/api/v1/reports` | Lista os relatórios recentes de inspeção (`?limit=50` por padrão; valor limitado entre `1` e `500`), ordenados do mais recente para o mais antigo. |
| `GET` | `/api/v1/alerts` | Sincroniza o `eve.json` do Suricata e retorna os alertas ativos dentro da janela de correlação (`alerts` e `count`). |
| `GET` | `/api/v1/config` | Retorna o `RuntimeConfig` ativo (`quarantine_dir`, `approved_dir`, `clamd_socket_path`, `suricata_eve_path`, `updated_at`). |
| `PATCH` | `/api/v1/config` | Valida e persiste novos caminhos no SQLite, atualiza a configuração em memória, realiza *hot-reload* do `InotifyWatcher` e transmite o evento SSE `config_updated`. |
| `GET` | `/api/v1/events/stream` | Stream contínuo **Server-Sent Events (`text/event-stream`)** com *keep-alive* a cada `15s` emitindo eventos `inspection_completed`, `network_alert_detected`, `config_updated` e `lagged`. |

### Exemplos de uso com `curl`

Defina seu token em uma variável temporária no shell para testar:

```bash
export SENTINEL_TOKEN="seu_admin_api_token_aqui"
```

**1. Verificar saúde e configuração ativa (`GET /api/v1/health`):**

```bash
curl -sS -H "Authorization: Bearer $SENTINEL_TOKEN" \
  http://127.0.0.1:8080/api/v1/health | jq .
```

**2. Consultar relatórios recentes (`GET /api/v1/reports`):**

```bash
curl -sS -H "Authorization: Bearer $SENTINEL_TOKEN" \
  "http://127.0.0.1:8080/api/v1/reports?limit=20" | jq .
```

**3. Consultar alertas ativos do Suricata (`GET /api/v1/alerts`):**

```bash
curl -sS -H "Authorization: Bearer $SENTINEL_TOKEN" \
  http://127.0.0.1:8080/api/v1/alerts | jq .
```

**4. Consultar configuração atual (`GET /api/v1/config`):**

```bash
curl -sS -H "Authorization: Bearer $SENTINEL_TOKEN" \
  http://127.0.0.1:8080/api/v1/config | jq .
```

**5. Atualizar diretórios/caminhos em tempo real (`PATCH /api/v1/config`):**

```bash
curl -sS -X PATCH \
  -H "Authorization: Bearer $SENTINEL_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "quarantine_dir": "/tmp/sentinel_quarantine",
    "approved_dir": "/tmp/sentinel_approved",
    "clamd_socket_path": "/var/run/clamav/clamd.ctl",
    "suricata_eve_path": "/var/log/suricata/eve.json"
  }' \
  http://127.0.0.1:8080/api/v1/config | jq .
```

*(Os campos `clamd_socket_path` e `suricata_eve_path` são opcionais e podem receber `null` para manter os caminhos atualmente configurados.)*

**6. Assinar eventos em tempo real via SSE (`GET /api/v1/events/stream`):**

```bash
curl -N -H "Authorization: Bearer $SENTINEL_TOKEN" \
  http://127.0.0.1:8080/api/v1/events/stream
```

---

## Comandos de Desenvolvimento, Testes e Auditoria

O `Makefile` na raiz do repositório centraliza os alvos de compilação, qualidade e verificação:

| Comando | Ação executada |
| :--- | :--- |
| `make frontend-build` | Executa `npm run type-check && npm run build` em `../vue_sentinel_guard`. |
| `make build` | Executa `frontend-build` e compila o binário único otimizado (`cargo build --release`). |
| `make test` | Executa toda a suíte de testes unitários e de integração (`cargo test --all-targets`). |
| `make lint` | Executa o linter Clippy tratando avisos como erros (`cargo clippy --all-targets -- -D warnings`). |
| `make fmt` | Formata o código Rust com `cargo fmt`. |
| `make fmt-check` | Verifica a formatação sem alterar arquivos (`cargo fmt --check`). |
| `make audit` | Executa `cargo audit` (se instalado) no backend e `npm audit` em `../vue_sentinel_guard`. |
| `make check` | Executa a rotina completa de verificação: `fmt-check`, `lint` e `test`. |

*(Para limpar artefatos de compilação Rust quando necessário, utilize o comando padrão do Cargo: `cargo clean`.)*
