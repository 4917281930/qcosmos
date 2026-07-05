import { DOMAINS, domainSignBytes, validationResult } from './canonical.js';
import { hashValidatorSet, verifyFinalityCertificate } from './attestation.js';

export function ibcHybridUpdateSignBytes(update) {
  return domainSignBytes(DOMAINS.ibcHybridUpdate, {
    trustedConsensusState: update.trustedConsensusState,
    header: update.header
  });
}

export function verifyHybridIbcUpdate(update, options = {}) {
  const errors = [];
  const {
    trustedConsensusState,
    header,
    trustedValidators,
    validatorSet,
    certificate
  } = update;

  if (!trustedConsensusState) errors.push('missing trusted consensus state');
  if (!header) errors.push('missing IBC header');
  if (!Array.isArray(trustedValidators)) errors.push('missing trusted validators');
  if (!Array.isArray(validatorSet)) errors.push('missing validator set');
  if (!certificate) errors.push('missing PQ finality certificate');
  if (errors.length > 0) return validationResult(errors);

  const trustedHash = hashValidatorSet(trustedValidators);
  if (trustedConsensusState.nextValidatorsHash !== trustedHash) {
    errors.push('trusted validator set hash does not match trusted consensus state');
  }

  const validatorsHash = hashValidatorSet(validatorSet);
  if (header.validatorsHash !== validatorsHash) {
    errors.push('header validatorsHash does not match validator set');
  }

  for (const field of ['chainId', 'height', 'appHash', 'validatorsHash', 'nextValidatorsHash']) {
    if (String(certificate.header?.[field]) !== String(header[field])) {
      errors.push(`PQ certificate header ${field} does not match IBC header`);
    }
  }

  const certResult = verifyFinalityCertificate(certificate, validatorSet, options);
  if (!certResult.ok) {
    errors.push(...certResult.errors.map((error) => `PQ certificate: ${error}`));
  }

  return validationResult(errors, {
    certificate: certResult
  });
}
