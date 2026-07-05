# Cosmos Integration Guide

## SDK Module Layout

Recommended module names:

- `x/pqregistry`
- `x/pqauth`
- `x/pqfinality`

## x/pqregistry

Stores account PQ key state. Message handlers should map directly to the
reference functions in `src/registry.js`:

- `MsgRegisterPQKey`
- `MsgRotatePQKey`
- `MsgRevokePQKey`

The module should expose gRPC queries for:

- active key by account address
- key history by account address
- algorithm policy

## x/pqauth

The AnteHandler should run after normal transaction decoding and before message
execution:

```text
normal signature verification
load PQ registry entry
verify QCosmos hybrid envelope
charge gas based on signature size and algorithm
continue to message execution
```

## x/pqfinality

For CometBFT chains that cannot immediately change consensus signatures, start
with an application-side finality overlay:

1. Validators register validator PQ keys.
2. Validators publish PQ attestations through vote extensions or an agreed
   sidecar.
3. The chain verifies threshold certificates and stores accepted PQ finality
   roots.

## IBC

Do not remove normal IBC verification. A hybrid client should first perform
standard ICS-07 verification, then verify a QCosmos PQ finality certificate for
the same header fields.

## Governance Rollout

Suggested chain parameters:

- `allowed_algorithms`: `mldsa65`, `mldsa87`
- `mandatory_account_classes`: governance module accounts, community pool,
  IBC relayers, validator operator accounts
- `min_validator_certificate_power`: `2/3`
- `activation_height`
- `legacy_grace_period`
