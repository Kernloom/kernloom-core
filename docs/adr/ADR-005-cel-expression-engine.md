# ADR-005: CEL Is the v1 Expression Engine

## Status

Accepted.

## Decision

Kernloom uses CEL for conditions, guardrails, risk recipes, validation checks and simulation expectations.

## Consequences

Policy authors do not write CEL directly in normal KNI intents; Forge resolves controlled authoring values to canonical expressions.

