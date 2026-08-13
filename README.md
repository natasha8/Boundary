# BOUNDARY

Self-hosted Web and API security scanner focused on controlled attack-surface
discovery, authorization testing, and reproducible evidence.

It is intended for systems the operator owns or is explicitly authorized to
test. Active scanning is disabled by default.

## Focus

- Strict target scope and origin allowlisting
- Deterministic, bounded discovery instead of general crawling
- Controlled HTTP transport with pinned connections and redirect revalidation
- Reproducible findings backed by evidence, not noisy weak signals
- Authorization and object-access testing in later milestones

## Current foundation

- **Scope Engine** — validates URLs, enforces exact-origin allowlists and address policy
- **Controlled HTTP Transport** — issues scoped requests with size/timeout limits and safe redirect handling
- **Discovery Engine** — in progress: bounded frontier, HTML reference extraction, and candidate filtering toward crawl orchestration
