# QCosmos Protocol

Open-source post-quantum migration primitives for Cosmos SDK chains, appchains,
and Cosmos-aligned Layer 1 networks.

QCosmos is a reference protocol package for helping Cosmos projects move from
classical-only authentication toward hybrid post-quantum security. The core
migration rule is intentionally conservative:

```text
accept = valid_classic_signature AND valid_pq_signature AND active_registry_key
```

The project does not try to invent new cryptography. It uses standardized
post-quantum primitives through `@noble/post-quantum`, including ML-DSA,
ML-KEM, and SLH-DSA, and keeps existing Cosmos-style secp256k1 authentication
active during migration.

## Current Status

This repository is currently a **reference SDK, CLI, protobuf contract set, and
conformance test suite**.

It is suitable for:

- protocol review
- local development
- integration planning
- testnet prototyping
- Go/Cosmos SDK module porting
- conformance testing for independent implementations

It is **not yet a drop-in Cosmos SDK module** and should not be described as
mainnet-ready chain protection by itself.

## What Is Already Built

- Cosmos-style address derivation from secp256k1 public keys.
- ML-DSA-65 and ML-DSA-87 signing and verification.
- SLH-DSA backup signature support.
- ML-KEM-768 and ML-KEM-1024 encapsulation wrappers.
- Hybrid account key registry.
- PQ key registration, rotation, and revocation flows.
- Hybrid transaction envelope signing and verification.
- Validator PQ finality certificates with voting-power threshold checks.
- IBC-oriented hybrid update overlay for CometBFT header binding.
- Chain rollout policy helpers.
- CLI: `qcosmos`.
- Protobuf contracts for Cosmos module ports.
- Deterministic conformance vectors.
- Unit, integration, and conformance tests.
- CI workflow.
- Dockerfile.
- npm release artifact.

## What Is Not Built Yet

The next production phase is Cosmos-native implementation work:

- `x/pqregistry` as a real Cosmos SDK Go module.
- `x/pqauth` AnteHandler integration.
- `x/pqfinality` keeper/store/query/message service.
- Validator vote-extension or sidecar integration.
- Native hybrid IBC light client implementation.
- CometBFT runtime integration.
- Gas and block-size benchmarking.
- Chain-specific governance proposal and parameter activation.
- Validator key management and operational runbooks.
- Independent cryptography and consensus audit.

## Repository Layout

```text
src/
  address.js        Cosmos-style address helpers
  classic.js        secp256k1 signing and verification
  pqc.js            ML-DSA, SLH-DSA, ML-KEM wrappers
  registry.js       PQ key registry state machine
  tx.js             Hybrid transaction envelope verification
  attestation.js    Validator PQ finality certificates
  ibc.js            IBC hybrid overlay checks
  policy.js         Chain rollout policy helpers

proto/qcosmos/
  pqregistry/       Registry message and genesis contracts
  pqauth/           Hybrid transaction envelope contracts
  pqfinality/       Validator certificate contracts
  pqibc/            Hybrid IBC update contracts
  pqpolicy/         Chain policy contracts

testdata/
  qcosmos-vectors-v1.json

docs/
  PROTOCOL.md
  COSMOS_INTEGRATION.md
  GO_LIVE.md
  GOVERNANCE_PROPOSAL_TEMPLATE.md
```

## Quick Start

Requirements:

- Node.js `>=22`
- npm

Install and verify:

```bash
npm install
npm run vectors
npm run ci
npm run release:check
```

Generate a PQ key:

```bash
npm exec qcosmos -- keygen --algo mldsa65
```

List supported algorithms:

```bash
npm exec qcosmos -- algorithms
```

Run the end-to-end demo:

```bash
node examples/end-to-end.js
```

## Test Status

Latest local verification completed:

- `npm run ci`: passed
- `npm run release:check`: passed
- `npm audit --omit=dev`: 0 vulnerabilities
- tests: 12/12 passed
- protobuf contracts validated: 6
- end-to-end demo: hybrid tx, finality certificate, and IBC overlay verified

Release artifact:

```text
qcosmos-protocol-0.1.0.tgz
```

Regenerate and inspect the artifact with:

```bash
npm pack
sha256sum qcosmos-protocol-0.1.0.tgz
```

## How Cosmos Projects Can Use This

For a Cosmos SDK chain, the intended path is:

1. Review the protocol and threat model in `docs/PROTOCOL.md`.
2. Generate Go types from `proto/qcosmos/**`.
3. Port the reference state machines from `src/**` into Cosmos SDK modules.
4. Use `testdata/qcosmos-vectors-v1.json` as mandatory conformance tests.
5. Add an AnteHandler path that requires hybrid signatures for selected account
   classes.
6. Add validator PQ key registration and finality certificate verification.
7. Add a hybrid IBC client or wrapper that requires both normal CometBFT
   verification and a PQ certificate for the same header.
8. Benchmark gas, verification time, block-size impact, relayer behavior, and
   validator operational load.
9. Run a public testnet.
10. Complete independent security audit before mainnet activation.

Recommended initial mandatory account classes:

- governance module accounts
- community pool / treasury accounts
- validator operator accounts
- IBC relayer accounts
- bridge or cross-chain security accounts

## Suggested Cosmos Modules

- `x/pqregistry`: stores account and validator PQ keys, rotations, revocations,
  and key status.
- `x/pqauth`: verifies hybrid transaction envelopes in the AnteHandler path.
- `x/pqfinality`: verifies validator PQ finality certificates and stores accepted
  finality commitments.
- `x/pqibc` or `07-cometbft-hybrid`: verifies IBC client updates with both
  CometBFT and PQ finality evidence.
- `x/pqpolicy`: stores activation height, allowed algorithms, mandatory account
  classes, and certificate threshold parameters.

## Migration Roadmap

Recommended rollout for large Cosmos projects:

1. Optional PQ key registration for users and operators.
2. Mandatory hybrid signatures for governance, treasury, validator operator, and
   IBC relayer accounts.
3. Validator PQ finality certificates on testnet.
4. IBC hybrid client testing between two controlled testnets.
5. Wider validator onboarding and recovery drills.
6. Mainnet governance proposal with conservative parameters.
7. Gradual expansion to more account classes.
8. Native CometBFT PQ validator support after ecosystem coordination.

## Security Notes

- Do not start with PQ-only authentication.
- Keep classical signatures required during migration.
- Treat PQ finality certificates as an overlay until CometBFT supports native PQ
  validator signatures.
- Do not activate on mainnet without independent audit.
- Do not assume IBC is protected unless the counterparty verification path also
  validates the PQ finality certificate.

## Release And Go-Live Docs

- Go-live guide: `docs/GO_LIVE.md`
- Governance template: `docs/GOVERNANCE_PROPOSAL_TEMPLATE.md`
- Cosmos integration notes: `docs/COSMOS_INTEGRATION.md`
- Protocol spec: `docs/PROTOCOL.md`

## Donation

This work is intended as a contribution toward helping the Cosmos ecosystem
prepare for post-quantum migration. Donations are welcome and will support
continued development, testing, documentation, and Cosmos-native module work.

```text
EVM:     0x3475178e253561fdd3037c0d6eefb67a0af4c50a
Bitcoin: bc1pkqeu0zv9wsn8w68s4t5pl58y8l626fnhhdt8sxr0erstglhv0ntsr3fgpq
ATOM:    cosmos1pp3nnvd3pcxlxxfze672j2hj6ua9gstrasl305
```

## License

MIT. See `LICENSE`.
