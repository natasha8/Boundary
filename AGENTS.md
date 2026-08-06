# BOUNDARY Agent Instructions

## Mission

BOUNDARY is a self-hosted Web and API security scanner focused on:

- controlled attack-surface discovery;
- authorization testing;
- reproducible evidence;
- deterministic finding validation.

## Engineering principles

- Implement only the current approved task.
- Prefer the smallest complete solution.
- Do not add abstractions without a concrete use case.
- Do not add dependencies without explaining their purpose.
- Keep framework code separate from domain logic.
- Use explicit types and structured errors.
- Preserve backward compatibility unless a change is explicitly approved.
- Update tests and documentation when behavior changes.

## Security rules

- Never scan public or third-party targets during development or testing.
- Never send active payloads unless explicitly enabled by an approved scan profile.
- Never follow redirects outside the approved scope.
- Never log or persist passwords, tokens, cookies, API keys or authorization headers.
- Never execute destructive Git, Docker, database or filesystem commands.
- Never disable security controls to make a test pass.

## Workflow

Before modifying code:

1. Read the relevant documentation and project rules.
2. Inspect the existing implementation and tests.
3. State assumptions and affected components.
4. Propose the smallest implementation plan.
5. Define success, failure and boundary test cases.

After modifying code:

1. Run formatting, linting, type checking and relevant tests.
2. Review the diff for unnecessary code.
3. Report changed files, commands executed and remaining risks.

## Definition of done

A task is complete only when:

- acceptance criteria are satisfied;
- success and failure paths are tested;
- relevant security boundaries are tested;
- checks pass without skipped or weakened tests;
- no secrets or sensitive evidence are exposed;
- documentation matches the implementation.
