# Security Policy

QCosmos is a reference implementation for post-quantum migration. Treat it as
audit-ready prototype code until your chain has completed an independent review.

## Supported Primitives

- ML-DSA-65 and ML-DSA-87 for post-quantum signatures.
- ML-KEM-768 and ML-KEM-1024 for key encapsulation.
- secp256k1 ECDSA for the classical Cosmos migration leg.

## Required Deployment Rule

During migration, high-value paths must require both classical and
post-quantum verification:

```text
classic_valid && pq_valid
```

Never treat a registered PQ key as a replacement for the original account key
until the chain has explicitly migrated its account model.
