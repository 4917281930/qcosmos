# Governance Proposal Template

## Title

Enable QCosmos hybrid post-quantum authentication on `<chain-id>`.

## Summary

This proposal activates QCosmos hybrid authentication for selected high-value
account classes and starts the chain migration from classical-only signatures
to classical-plus-post-quantum verification.

## Proposed Parameters

```json
{
  "activation_height": "0",
  "legacy_grace_period": "0",
  "allowed_signature_algorithms": ["mldsa65", "mldsa87"],
  "preferred_signature_algorithm": "mldsa87",
  "mandatory_account_classes": [
    "governance",
    "treasury",
    "ibc-relayer",
    "validator-operator"
  ],
  "min_validator_certificate_power": {
    "numerator": "2",
    "denominator": "3"
  }
}
```

## Scope

- Enable `x/pqregistry` for account PQ key registration, rotation, and
  revocation.
- Enable `x/pqauth` for hybrid transaction verification.
- Enable `x/pqfinality` for validator PQ finality certificates.
- Prepare IBC counterparties for `x/pqibc` or compatible hybrid ICS-07
  verification.

## Risk Controls

- Classical signatures remain required during migration.
- PQ-only authentication is not enabled by this proposal.
- Initial enforcement is limited to high-value account classes.
- Validators must test key custody and recovery before production activation.

## Rollback

If unexpected verification failures occur, governance may set
`mandatory_account_classes` to an empty list while keeping `x/pqregistry`
available for voluntary registration. Existing classical transaction paths stay
unchanged unless the chain separately disables them.
