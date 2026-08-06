# ADR 0001: Begin as a modular monolith

- Status: Accepted
- Date: 2026-08-07

## Context

BOUNDARY requires several security capabilities, but its initial domain model
and operational requirements are not yet stable.

Splitting the project into services or independent packages now would create
deployment, versioning and communication complexity without proven benefits.

## Decision

BOUNDARY will begin as one Python application organized into cohesive internal
modules.

The initial application will contain:

- scope validation;
- HTTP transport;
- passive rules;
- evidence handling;
- reporting;
- CLI entry point.

Modules may be extracted only when they have an independent lifecycle,
dependency boundary or execution requirement.

## Consequences

Positive:

- fewer moving parts;
- simpler local development;
- easier refactoring;
- one test environment;
- no premature network boundaries.

Negative:

- module boundaries must be enforced through code review;
- later extraction may require deliberate migration work.
