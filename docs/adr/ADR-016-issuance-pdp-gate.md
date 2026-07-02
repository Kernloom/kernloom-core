# ADR-016: Issuance PDP Is a Gate

## Status

Accepted.

## Decision

The Issuance PDP decides whether issuance is allowed. Issuer/Signer creates the artifact only after allow.

## Consequences

Access proofs may be JWS/JWT only when a consuming PEP requires token-style proof.

