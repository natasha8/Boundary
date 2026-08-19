# BOUNDARY

Evidence-driven Web and API security scanner focused on controlled discovery,
deterministic validation and reproducible evidence.

BOUNDARY is a self-hosted local CLI. v0.1.0 runs one deterministic, uncredentialed
passive scan against operator-supplied targets. Use it only on systems you own
or are explicitly authorized to test.

## What v0.1.0 does

- **Scope Engine** — HTTP/HTTPS only; exact-origin allowlisting; explicit
  `PUBLIC` / `LOCAL_LAB` address policy; DNS and address validation; redirect
  admission.
- **Controlled HTTP Transport** — httpcore with DNS/IP pinning; TLS SNI uses
  the real hostname; `retries=0`; bounded response bodies; optional timeouts;
  redirect revalidation. Persistent connection reuse is not implemented.
- **Bounded Discovery** — uncredentialed `GET` only, limited by `max_pages`
  and `max_depth`. HTML extraction covers `a[href]`, `form[action]`,
  `script[src]` and `link[href]`.
- **Passive checks** — HSTS; `X-Content-Type-Options: nosniff`; enforced CSP;
  frame protection; cookie `Secure`; `SameSite=None` without `Secure`.
- **Evidence** — status, requested and final targets, body length, and body
  SHA-256. Response bodies and headers are not retained.
- **Authorization primitives** — explicit `Identity`; origin-bound
  `Authorization` / `Cookie` credentials; GET `request_as`; deterministic
  equivalent/distinct response projections as `AuthorizationObservation`.
  Library API only; not invoked by `boundary scan`.
- **Scan orchestration** — one uncredentialed workflow from scoped seed to
  `ScanResult`.
- **Reporting** — `text`, JSON, and SARIF 2.1.0, with whole-query redaction.

v0.1.0 does not scan for SQL injection, XSS, CSRF, IDOR/BOLA, CORS, cache
policy, information disclosure, or active TLS issues. It does not integrate
with GitHub Code Scanning.

## Safety model

BOUNDARY is intended only for systems the operator owns or is explicitly
authorized to test.

v0.1.0 does not implement active or mutating testing.

`boundary scan`:

- is uncredentialed;
- performs GET-based bounded discovery and passive analysis;
- cannot enable an active profile through the CLI or the environment.

Scope:

- matches exact Origin only (`scheme` + `host` + `port`);
- does not match wildcards, suffixes, or parent domains;
- requires an explicit `PUBLIC` or `LOCAL_LAB` address policy.

Credentials:

- allowlisted to `Authorization` and `Cookie`;
- bound to one origin;
- available only through library APIs;
- not accepted by `boundary scan`.

`AuthorizationObservation` records `equivalent_projection` or
`distinct_projection`. Those are observations, not vulnerability verdicts.

## Installation

Install from this repository. Python `>=3.13,<3.14` and [uv](https://docs.astral.sh/uv/)
are required. v0.1.0 is not published to PyPI.

```text
uv sync
```

The CLI entry point is:

```text
uv run boundary
```

## Quick start

BOUNDARY has no hidden scan-budget defaults. These options are required:

- `--allow-origin`
- `--address-policy`
- `--max-pages`
- `--max-depth`
- `--max-redirects`
- `--max-body-bytes`

Timeout flags (`--connect-timeout`, `--read-timeout`, `--write-timeout`,
`--pool-timeout`) are optional. If omitted, BOUNDARY imposes no timeout for
that dimension.

`--allow-origin` may be repeated for every origin the scan is allowed to
follow.

**PUBLIC documentation example.** `example.invalid` is documentation-only and
is not expected to resolve or run:

```text
uv run boundary scan https://app.example.invalid/ \
  --allow-origin https://app.example.invalid \
  --address-policy public \
  --max-pages 5 \
  --max-depth 1 \
  --max-redirects 5 \
  --max-body-bytes 65536
```

**LOCAL_LAB example.** Use `LOCAL_LAB` only for operator-owned or authorized
lab targets:

```text
uv run boundary scan http://127.0.0.1:8080/ \
  --allow-origin http://127.0.0.1:8080 \
  --address-policy local_lab \
  --max-pages 5 \
  --max-depth 1 \
  --max-redirects 5 \
  --max-body-bytes 65536
```

## Output

The default format is `--format text`. Example:

```text
3 findings
```

JSON:

```text
uv run boundary scan ... --format json
```

SARIF:

```text
uv run boundary scan ... --format sarif
```

SARIF output targets OASIS SARIF 2.1.0. GitHub upload and Code Scanning
integration are not implemented. BOUNDARY does not fabricate repository
source paths.

## Reporting privacy

Any non-empty query is replaced in full. For example:

```text
https://example.test/reset?token=secret
```

is exported as:

```text
https://example.test/reset?REDACTED
```

Path segments are preserved and are not redacted. `body_sha256` is a digest,
not a confidentiality mechanism. Finding fingerprints and `evidence_id` are
not exported in v0.1.0 reports.

This is query redaction, not universal secret removal.

## Architecture

```text
Target
→ Scope
→ Controlled Transport
→ Discovery
→ Passive Analysis
→ Evidence
→ ScanResult
→ Safe Reporting
→ text / JSON / SARIF
```

Scope decides where a request may go. Transport is the only network execution
path. Deterministic modules produce observations and evidence. Reporting
exports only an explicit safe projection of those facts.

## Current limitations

- no active or mutating tests
- `boundary scan` is uncredentialed
- authorization primitives are library-only
- no browser or JavaScript execution
- no form submission
- no SQLi / XSS / CSRF / IDOR verdict engine
- no persistence, database, or dashboard
- no GitHub Code Scanning upload integration
- optional timeouts have no numeric defaults
- `LOCAL_LAB` includes link-local IPv4 ranges and must only be used
  deliberately
- persistent connection reuse is not implemented
- path tokens are not redacted in reports

## Development

```text
uv run ruff format --check .
uv run ruff check .
uv run mypy
uv run pytest
```

The v0.1.0 release checkpoint recorded 1518 passing tests on Python 3.13.14.
