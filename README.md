# AI Governance Engine (aigov)

An open-source AI governance gateway for EU companies. It sits between
applications and LLM providers, enforcing policy on every AI call:
PII redaction, model allowlists, human approval for high-risk actions,
and tamper-evident audit logs mapped to the EU AI Act and GDPR.

> Status: early development (Module 0 of 16: project skeleton).

## Quick start

    docker compose up -d
    go run ./cmd/gateway
    curl http://localhost:8080/healthz