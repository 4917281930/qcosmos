import {
  DOMAINS,
  canonicalBytes,
  domainSignBytes,
  sha256Hex,
  validationResult
} from './canonical.js';
import { normalizeAlgorithm, signPq, verifyPq } from './pqc.js';

export function normalizeValidator(validator) {
  return {
    address: validator.address,
    power: String(validator.power),
    pqAlgorithm: normalizeAlgorithm(validator.pqAlgorithm),
    pqPublicKey: validator.pqPublicKey
  };
}

export function normalizeValidatorSet(validators) {
  return validators.map(normalizeValidator).sort((a, b) => a.address.localeCompare(b.address));
}

export function hashValidatorSet(validators) {
  return sha256Hex(canonicalBytes(normalizeValidatorSet(validators)));
}

export function createHeaderCommitment({
  chainId,
  height,
  round = 0,
  blockId,
  appHash,
  validatorsHash,
  nextValidatorsHash,
  timeUnixMs
}) {
  return {
    chainId,
    height: String(height),
    round: String(round),
    blockId,
    appHash,
    validatorsHash,
    nextValidatorsHash,
    timeUnixMs: String(timeUnixMs)
  };
}

export function validatorAttestationSignBytes(header) {
  return domainSignBytes(DOMAINS.validatorAttestation, header);
}

export function signValidatorAttestation({ header, validator, pqSecretKey }) {
  const normalized = normalizeValidator(validator);
  const bytes = validatorAttestationSignBytes(header);
  return {
    address: normalized.address,
    pqAlgorithm: normalized.pqAlgorithm,
    pqPublicKey: normalized.pqPublicKey,
    signature: signPq(normalized.pqAlgorithm, bytes, pqSecretKey)
  };
}

export function verifyValidatorAttestation(attestation, header, validator) {
  const normalized = normalizeValidator(validator);
  if (attestation.address !== normalized.address) return false;
  if (normalizeAlgorithm(attestation.pqAlgorithm) !== normalized.pqAlgorithm) return false;
  if (attestation.pqPublicKey !== normalized.pqPublicKey) return false;
  return verifyPq(
    normalized.pqAlgorithm,
    attestation.signature,
    validatorAttestationSignBytes(header),
    normalized.pqPublicKey
  );
}

export function createFinalityCertificate({ header, attestations }) {
  return {
    protocol: 'qcosmos-pq-finality',
    version: 1,
    header,
    attestations
  };
}

export function verifyFinalityCertificate(certificate, validators, options = {}) {
  const thresholdNumerator = BigInt(options.thresholdNumerator ?? 2);
  const thresholdDenominator = BigInt(options.thresholdDenominator ?? 3);
  const errors = [];
  const validatorMap = new Map(normalizeValidatorSet(validators).map((v) => [v.address, v]));
  const seen = new Set();
  let signedPower = 0n;
  let totalPower = 0n;

  for (const validator of validatorMap.values()) {
    totalPower += BigInt(validator.power);
  }
  if (totalPower <= 0n) errors.push('validator set has zero total power');

  if (!certificate?.header) errors.push('missing certificate header');
  if (!Array.isArray(certificate?.attestations)) errors.push('missing certificate attestations');
  if (errors.length > 0) {
    return validationResult(errors, { signedPower: '0', totalPower: totalPower.toString() });
  }

  for (const attestation of certificate.attestations) {
    if (seen.has(attestation.address)) {
      errors.push(`duplicate attestation from ${attestation.address}`);
      continue;
    }
    seen.add(attestation.address);
    const validator = validatorMap.get(attestation.address);
    if (!validator) {
      errors.push(`attestation from unknown validator ${attestation.address}`);
      continue;
    }
    if (!verifyValidatorAttestation(attestation, certificate.header, validator)) {
      errors.push(`invalid attestation from ${attestation.address}`);
      continue;
    }
    signedPower += BigInt(validator.power);
  }

  const hasThreshold = signedPower * thresholdDenominator > totalPower * thresholdNumerator;
  if (!hasThreshold) {
    errors.push('signed validator power does not exceed threshold');
  }

  return validationResult(errors, {
    signedPower: signedPower.toString(),
    totalPower: totalPower.toString(),
    threshold: `${thresholdNumerator}/${thresholdDenominator}`
  });
}
