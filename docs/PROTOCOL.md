# QCosmos Protocol Specification

## 1. Domains

All signatures are domain separated.

| Domain | Purpose |
| --- | --- |
| `qcosmos/pq-key-binding/v1` | Register or rotate an account PQ key |
| `qcosmos/pq-key-revocation/v1` | Revoke an account PQ key |
| `qcosmos/hybrid-tx/v1` | Sign an application transaction envelope |
| `qcosmos/validator-attestation/v1` | Sign a validator PQ finality attestation |
| `qcosmos/ibc-hybrid-update/v1` | Bind a PQ certificate to an IBC header update |

## 2. Account Registry

Each account can bind one active post-quantum key.

```text
address -> {
  algorithm,
  pqPublicKey,
  version,
  status,
  notBeforeHeight,
  registeredAtHeight,
  rotatedAtHeight?
}
```

Registration requires:

```text
secp256k1_signature(binding_sign_bytes, account_classic_key)
ML-DSA_signature(binding_sign_bytes, pq_private_key)
```

Rotation requires the same signatures plus a valid signature from the currently
active PQ key unless the chain performs governance recovery.

## 3. Hybrid Transactions

A hybrid transaction envelope contains:

```text
body
classicPublicKey
classicSignature
pqKeyVersion
pqAlgorithm
pqSignature
```

Verification succeeds only when:

```text
address(classicPublicKey) == body.accountAddress
classicSignature verifies over body
registry has active PQ key for body.accountAddress
registry.version == envelope.pqKeyVersion
registry.algorithm == envelope.pqAlgorithm
pqSignature verifies over body
```

## 4. Validator PQ Finality Certificate

The chain builds a canonical header commitment:

```text
chainId
height
round
blockId
appHash
validatorsHash
nextValidatorsHash
timeUnixMs
```

Validators sign the canonical commitment with their registered validator PQ key.
The certificate is valid if unique valid signers exceed the configured voting
power threshold, normally more than two thirds of total power.

## 5. IBC Hybrid Update

The normal ICS-07 CometBFT verification remains required. QCosmos adds a second
condition:

```text
valid_cometbft_header && valid_pq_finality_certificate
```

The PQ certificate must bind to the same height, app hash, validator-set hash,
and next-validator-set hash used by the IBC header.
