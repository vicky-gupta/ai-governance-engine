# AI Governance Engine

[![CI](https://github.com/vicky-gupta/ai-governance-engine/actions/workflows/ci.yml/badge.svg)](https://github.com/vicky-gupta/ai-governance-engine/actions/workflows/ci.yml)

**An open-source AI governance gateway for EU companies.** It sits between your applications and LLM providers, and checks every AI request before it leaves the company: it redacts personal data, keeps high-risk systems on EU-hosted models, applies policy-as-code rules, holds sensitive decisions for human review, and writes every decision to a tamper-evident audit log.

> **Status:** early development, built in public. 7 of 16 modules are done ([roadmap](#roadmap)). Not production-ready yet.

---

## Why

Teams across a company call LLMs directly, each with their own keys and no shared rules. Personal data ends up in prompts, nobody can say which AI systems exist, and nobody can prove afterwards what was sent or decided.

The **EU AI Act** and **GDPR** ask companies to know their AI systems, control how they use personal data, keep humans in charge of important decisions, and keep records. This project turns those requirements into technical controls that run on every request, in one place.

## What it does today

| Control | What happens |
|---|---|
| **AI system registry** | Every app is registered with an owner, a purpose and an EU AI Act risk tier (`minimal`, `limited`, `high`, `unacceptable`), and gets its own gateway API key. Provider keys never leave the gateway. |
| **Prohibited systems** | Systems classified as `unacceptable` (AI Act Article 5) can be recorded in the inventory but can never call a model. |
| **Model allowlist and EU routing** | Only models listed in `providers.json` can be used. Each risk tier has allowed regions, so high-risk systems can be limited to EU-hosted providers. |
| **PII redaction** | IBANs, payment cards, emails, international phone numbers, German tax IDs and Spanish national IDs are replaced with tokens like `[IBAN_1]`. Checksums (mod 97, Luhn, official check digits) keep false positives low. |
| **Encrypted PII vault** | Original values are stored with AES-256-GCM, so authorised admins can look them up (every lookup is audited) and a person's data can be erased on request (GDPR Article 17). |
| **Policy-as-code** | Rules are written in [Rego](https://www.openpolicyagent.org/docs/latest/policy-language/) (Open Policy Agent): block, hold for human review, or cap tokens. Policies have their own tests and reload without a restart; a broken edit is rejected and the previous version stays active. |
| **Tamper-evident audit log** | Every decision is written to a SHA-256 hash chain in an append-only table. Editing, deleting or reordering any record is detected, down to the exact entry. The log stores hashes of request bodies, never the prompts themselves. |
| **OpenAI-compatible API** | Apps change one line (the base URL) to adopt it. Streaming works. |

## How it works

```mermaid
flowchart LR
    Apps["Your AI apps<br/>(any OpenAI-compatible client)"] -->|gateway key| Auth

    subgraph Gateway["AI Governance Gateway"]
        direction TB
        Auth["1. Identify the AI system<br/>and its risk tier"] --> Model["2. Approved model?<br/>Allowed region?"]
        Model --> PII["3. Redact personal data"]
        PII --> Policy["4. Apply policy (OPA)<br/>allow · modify · block · hold"]
        Policy --> Audit["5. Write the audit log"]
    end

    Audit --> Providers["LLM providers<br/>OpenAI · Mistral · Groq · …"]
    Gateway -.-> DB[("PostgreSQL<br/>registry · audit log · encrypted vault")]
```

Every response carries an `X-Request-ID` (the key to its audit entry) and an `X-Aigov-Decision` header (`allow`, `modify`, `block` or `hold`).

**Example:** a user writes *"Transfer 500 EUR from DE89 3704 0044 0532 0130 00 and confirm to anna.schmidt@example.com"*. The model receives *"Transfer 500 EUR from [IBAN_1] and confirm to [EMAIL_1]"*.

## Tech stack

Go (standard library HTTP server and reverse proxy) · PostgreSQL (pgx) · Open Policy Agent · AES-256-GCM and HMAC-SHA256 · Docker Compose · GitHub Actions

---

## Quick start

### Prerequisites

- [Go](https://go.dev/dl/) (the version in `go.mod` or newer)
- [Docker](https://www.docker.com/products/docker-desktop/) with Docker Compose
- An API key for an OpenAI-compatible provider (for example Groq, Mistral or OpenAI)

### 1. Clone and start PostgreSQL

```bash
git clone https://github.com/vicky-gupta/ai-governance-engine.git
cd ai-governance-engine
docker compose up -d
```

### 2. Configure your provider

Edit `providers.json` and list the model IDs you want to allow. API keys are not stored in this file; it names the environment variable that holds each key:

```json
{
  "providers": [
    {
      "name": "groq",
      "base_url": "https://api.groq.com/openai",
      "api_key_env": "GROQ_API_KEY",
      "region": "us",
      "models": ["your-model-id"]
    }
  ],
  "allowed_regions": {
    "minimal": ["eu", "us"],
    "limited": ["eu", "us"],
    "high": ["eu"]
  }
}
```

> The `region` is what the gateway enforces. Whether a provider really processes data in that region depends on your contract with it.

### 3. Set the secrets and run

**Linux / macOS:**

```bash
export GROQ_API_KEY="your-provider-key"
export ADMIN_TOKEN="$(openssl rand -hex 24)"
export PII_VAULT_KEY="$(openssl rand -base64 32)"
go run ./cmd/gateway
```

**Windows (PowerShell):**

```powershell
$env:GROQ_API_KEY = "your-provider-key"
$env:ADMIN_TOKEN = [guid]::NewGuid().ToString("N")
$b = New-Object byte[] 32; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
$env:PII_VAULT_KEY = [Convert]::ToBase64String($b)
go run ./cmd/gateway
```

Keep `PII_VAULT_KEY` safe: if you lose or change it, values already in the vault can no longer be decrypted.

On start, the gateway applies database migrations, loads the catalog and policies, and listens on `:8080`.

### 4. Register an AI system and get a key

```bash
curl -X POST http://localhost:8080/admin/systems \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"support-bot","owner":"customer-service","purpose":"Answers customer questions","risk_tier":"limited"}'

# Use the "id" from the response:
curl -X POST http://localhost:8080/admin/systems/SYSTEM_ID/keys \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

The response contains the gateway key (`aigov_…`). It is shown once; only its hash is stored.

### 5. Send a request through the gateway

```bash
curl -i http://localhost:8080/v1/chat/completions \
  -H "Authorization: Bearer aigov_YOUR_KEY" -H "Content-Type: application/json" \
  -d '{"model":"your-model-id","messages":[{"role":"user","content":"My IBAN is DE89 3704 0044 0532 0130 00. Repeat it back."}]}'
```

The model only ever sees `[IBAN_1]`. Then check the audit trail:

```bash
curl http://localhost:8080/admin/audit?limit=5 -H "Authorization: Bearer $ADMIN_TOKEN"
curl http://localhost:8080/admin/audit/verify -H "Authorization: Bearer $ADMIN_TOKEN"
```

Using the OpenAI SDK? Point its base URL at `http://localhost:8080/v1` and use your gateway key as the API key.

---

## Configuration

| Variable | Required | Default | Description |
|---|---|---|---|
| `ADMIN_TOKEN` | yes | | Protects the `/admin` API. At least 16 characters. |
| `PII_VAULT_KEY` | yes | | 32 random bytes, base64-encoded. Encrypts the PII vault. |
| Provider keys | yes | | One per provider, named by `api_key_env` in `providers.json` (e.g. `GROQ_API_KEY`). |
| `DATABASE_URL` | no | `postgres://aigov:aigov@localhost:5432/aigov?sslmode=disable` | PostgreSQL connection string. |
| `PROVIDERS_FILE` | no | `providers.json` | Provider and model catalog. |
| `POLICY_DIR` | no | `policies` | Folder with the Rego policy files. |
| `GATEWAY_ADDR` | no | `:8080` | Address the gateway listens on. |

The gateway refuses to start if a required setting is missing, the catalog is invalid, or the policies don't compile.

## Policies

Rules live in [`policies/aigov.rego`](policies/aigov.rego), with tests in [`policies/aigov_test.rego`](policies/aigov_test.rego). The gateway evaluates `data.aigov` and reads three results:

| Rule | Effect |
|---|---|
| `deny` | Any reason blocks the request (`403 policy_violation`). |
| `hold` | Any reason pauses it for human review (`403 approval_required` until the approval workflow lands). |
| `max_tokens` | Caps the response length; requests above the limit are modified. |

The included rules block internal terms (e.g. `project falcon`), hold credit decisions made by high-risk systems for human review (GDPR Art. 22, AI Act Art. 14), and give high-risk systems a lower token limit. Edit the file while the gateway runs: the new version is active within seconds, and its version hash is recorded in every audit entry.

## API reference

**Model API** (requires a gateway key: `Authorization: Bearer aigov_…`)

| Method and path | Description |
|---|---|
| `POST /v1/chat/completions` | OpenAI-compatible chat completions, including streaming. |
| `GET /v1/models` | The models the calling system is allowed to use. |

**Admin API** (requires `Authorization: Bearer $ADMIN_TOKEN`)

| Method and path | Description |
|---|---|
| `POST /admin/systems` | Register an AI system. |
| `GET /admin/systems` | List AI systems. |
| `POST /admin/systems/{id}/keys` | Issue a gateway key (shown once). |
| `DELETE /admin/keys/{id}` | Revoke a key. |
| `GET /admin/audit?limit=50` | Recent audit entries. |
| `GET /admin/audit/verify` | Verify the whole hash chain. |
| `GET /admin/pii/{request_id}` | Reveal the original values behind a request's tokens (audited). |
| `POST /admin/pii/erase` | Erase every stored copy of a value: `{"kind":"EMAIL","value":"…"}`. |

**Health:** `GET /healthz` (process alive), `GET /readyz` (database reachable), `GET /version`.

## Compliance mapping

How the current controls relate to the regulations. This is a technical aid, **not legal advice**: compliance also depends on your organisation's processes, contracts and documentation.

| Requirement | Control in this project |
|---|---|
| EU AI Act Art. 5: prohibited practices | `unacceptable` systems can never call a model. |
| EU AI Act Art. 12: record-keeping | Hash-chained, append-only audit log of every decision. |
| EU AI Act Art. 14: human oversight | Policy can hold requests for human review (approval workflow on the roadmap). |
| GDPR Art. 5(1)(c): data minimisation | PII is redacted before leaving the company; the audit log stores hashes, not prompts. |
| GDPR Art. 17: right to erasure | Erase endpoint deletes a person's values from the vault without breaking the audit chain. |
| GDPR Art. 22: automated decisions | Credit decisions by high-risk systems are held for a human. |
| GDPR Art. 32: security of processing | AES-256-GCM vault, hashed API keys, keyed fingerprints. |
| GDPR Chapter V: international transfers | High-risk systems can be restricted to EU-hosted providers. |

## Project structure

```
cmd/gateway/          entry point: config, wiring, graceful shutdown
internal/
  admin/              admin API: registry, keys, audit, PII vault
  audit/              hash-chained audit log
  auth/               gateway key authentication
  catalog/            providers, models, regions; GET /v1/models
  checks/             governance checks (model policy, PII, policy)
  config/             environment configuration
  db/                 connection pool and SQL migrations
  pii/                PII detection, validation and redaction
  pipeline/           decision pipeline and its HTTP middleware
  policy/             OPA engine with hot reload
  proxy/              reverse proxy and per-provider routing
  registry/           AI systems and API keys
  server/             routes and health endpoints
  vault/              encrypted PII vault
policies/             Rego policies and their tests
providers.json        provider and model catalog
```

## Development

```bash
go test ./...                 # unit tests, including the Rego policy tests
```

Database tests run when `TEST_DATABASE_URL` is set. Use a separate database, because the tests empty their tables:

```bash
docker compose exec postgres createdb -U aigov aigov_test
export TEST_DATABASE_URL="postgres://aigov:aigov@localhost:5432/aigov_test?sslmode=disable"
go test ./...
```

CI runs formatting, `go vet`, all tests with the race detector, and a build on every push.

## Roadmap

- [x] 0 · Project setup and CI
- [x] 1 · OpenAI-compatible reverse proxy with streaming
- [x] 2 · AI system registry and gateway keys
- [x] 3 · Decision pipeline (allow, modify, block, hold)
- [x] 4 · Tamper-evident audit log
- [x] 5 · Model allowlist and EU data-residency routing
- [x] 6 · PII redaction and encrypted vault with GDPR erasure
- [ ] 7 · Policy-as-code with OPA *(in progress)*
- [ ] 8 · Budgets and rate limits
- [ ] 9 · Response checks and AI agent tool-call control
- [ ] 10 · Human-in-the-loop approvals
- [ ] 11 · Multilingual PII detection (names, addresses)
- [ ] 12 · Compliance evidence reports
- [ ] 13 · Observability (OpenTelemetry, Prometheus, Grafana)
- [ ] 14 · Dashboard
- [ ] 15 · One-command demo and launch

## Contributing

Contributions are very welcome, and so are stars, which help others find the project.

Good places to start (see issues labelled [`good first issue`](https://github.com/vicky-gupta/ai-governance-engine/labels/good%20first%20issue)):

- **PII detectors for more EU countries**, such as the French NIR or the Italian Codice Fiscale. Each one is a regex, a checksum and tests in `internal/pii`.
- **New policy rules** in `policies/aigov.rego`, with tests in Rego.
- **Provider integrations and docs** for more OpenAI-compatible providers.

Before opening a pull request, run `gofmt -w .`, `go vet ./...` and `go test ./...`. Please use test values only, never real personal data.

## License

[LICENSE NAME] — see [LICENSE](LICENSE).
