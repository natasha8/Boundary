# Changelog

## 0.1.0 - 2026-08-19

### Added

- Deterministic Scope Engine with exact-origin allowlisting and
  PUBLIC / LOCAL_LAB address policy.
- Controlled HTTP transport with DNS/IP pinning, redirect revalidation,
  response-size limits, and optional timeouts.
- Bounded uncredentialed GET discovery.
- Passive header and cookie checks for HSTS, nosniff, enforced CSP,
  frame protection, cookie Secure, and SameSite=None without Secure.
- Deterministic evidence projections with status, targets, body length,
  and SHA-256.
- Authorization primitives for explicit identity-pair GET comparison.
  These remain library APIs and are not executed by boundary scan.
- Scan orchestration and CLI boundary scan.
- Text, JSON, and SARIF 2.1.0 report formats with fail-closed query redaction.

### Security

- Active and mutating testing are not implemented.
- Credentials are origin-bound and restricted to Authorization and Cookie.
- boundary scan does not accept credentials.
- Authorization observations are equivalent/distinct response projections,
  not vulnerability verdicts.
- Reports replace the complete query with REDACTED.
- Path tokens are not redacted and body_sha256 is not a confidentiality
  mechanism.
- PUBLIC rejects the remediated special-use IPv6 destination ranges.
- Non-ASCII URL path/query input is rejected before Transport.

### Deferred / Known limitations

- No dashboard, accounts, database, browser automation, or AI findings.
- No active injection, form submission, or mutating HTTP methods.
- No GitHub Code Scanning upload/file-path integration.
- boundary scan is uncredentialed.
- Timeout flags are optional and have no numeric defaults.
- LOCAL_LAB deliberately admits configured lab/link-local ranges and must only
  be used for authorized environments.
- Persistent connection reuse is not implemented.
