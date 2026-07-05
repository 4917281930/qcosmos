# Go-Live Guide

This repository is release-ready as a reference SDK, CLI, protobuf contract set,
and conformance suite. A public Cosmos mainnet launch still requires a specific
chain repository, validators, governance process, and independent audit.

## Release Readiness

Run:

```bash
npm ci
npm run vectors
npm run release:check
```

Expected checks:

- JavaScript syntax/import validation.
- Protobuf contract parse validation.
- Unit and conformance tests.
- End-to-end demo.
- npm package dry-run.

## Package Go-Live

For an npm release:

```bash
npm version patch
npm publish --access public
```

For a container release:

```bash
docker build -t qcosmos-protocol:0.1.0 .
docker run --rm qcosmos-protocol:0.1.0 algorithms
```

## Cosmos Testnet Go-Live

1. Generate Go types from `proto/qcosmos/**`.
2. Port the reference logic into chain modules:
   - `x/pqregistry`
   - `x/pqauth`
   - `x/pqfinality`
   - `x/pqibc` or a hybrid ICS-07 client wrapper
3. Import `testdata/qcosmos-vectors-v1.json` into Go tests and verify:
   - registry sign bytes
   - hybrid tx sign bytes
   - validator attestation sign bytes
   - finality certificate threshold logic
   - IBC header/certificate binding
4. Enable testnet params:
   - `activation_height`
   - `allowed_signature_algorithms`
   - `mandatory_account_classes`
   - `min_validator_certificate_power`
5. Require PQ for governance, treasury, validator operator, and IBC relayer
   accounts first.
6. Run load tests for block size, gas, signature verification latency, and
   relayer behavior.
7. Audit before mainnet.

## Mainnet Boundary

Do not claim mainnet post-quantum protection until these are complete:

- The target chain has merged native modules or equivalent wrappers.
- Governance has activated chain params.
- Validators have registered PQ validator keys.
- IBC counterparties have upgraded to a compatible hybrid client.
- Independent cryptography and consensus audits have passed.
