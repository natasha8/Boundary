# BOUNDARY Product Brief

## Purpose

BOUNDARY is a self-hosted Web and API security scanner focused on controlled
attack-surface discovery, authorization testing and reproducible evidence.

It is intended for systems owned by the operator or tested with explicit
authorization.

## Problem

Many automated scanners produce large numbers of findings without enough
evidence to distinguish confirmed vulnerabilities from weak signals.

BOUNDARY will prioritize:

- strict target scope enforcement;
- deterministic checks;
- reproducible evidence;
- explicit confidence levels;
- low-noise reporting;
- authorization and object-access testing.

## Product principles

1. Safety before scanning.
2. Evidence before severity.
3. Deterministic validation before AI explanation.
4. Minimal dependencies.
5. Local and self-hosted by default.
6. Active testing disabled by default.
7. No claim of complete vulnerability coverage.

## First technical release

The first release will provide:

- a command-line interface;
- target and scope configuration;
- URL and redirect validation;
- controlled asynchronous HTTP requests;
- passive HTTP security checks;
- structured findings;
- redacted request and response evidence;
- JSON report output;
- deterministic local integration tests.

## Explicitly excluded from the first release

The first release will not include:

- a web dashboard;
- user accounts;
- a database;
- Redis or distributed workers;
- AI-generated findings;
- autonomous exploitation;
- browser automation;
- active injection testing;
- external target scanning in automated tests.

## Initial passive checks

The first passive rules may cover:

- security headers;
- cookie security attributes;
- cache policy;
- information disclosure;
- CORS response configuration;
- insecure redirects.

These rules will be added only after the scope and HTTP transport layers are
tested and stable.

## Definition of a confirmed finding

A finding may be marked as confirmed only when:

- the detection rule is deterministic;
- the triggering evidence is stored after redaction;
- the result is reproducible;
- the rule explains why the observed behavior is unsafe;
- the finding includes remediation guidance.

Signals that do not meet these requirements must be marked as informational or
requiring manual review.
