import { normalizeAlgorithm } from './pqc.js';
import { verifyHybridTx } from './tx.js';

export const DEFAULT_CHAIN_POLICY = Object.freeze({
  activationHeight: 0,
  legacyGracePeriod: 0,
  allowedSignatureAlgorithms: ['mldsa65', 'mldsa87'],
  preferredSignatureAlgorithm: 'mldsa87',
  mandatoryAccountClasses: [
    'governance',
    'treasury',
    'ibc-relayer',
    'validator-operator'
  ],
  minValidatorCertificatePower: {
    numerator: 2,
    denominator: 3
  }
});

export function normalizeChainPolicy(policy = {}) {
  return {
    ...DEFAULT_CHAIN_POLICY,
    ...policy,
    allowedSignatureAlgorithms: (
      policy.allowedSignatureAlgorithms ?? DEFAULT_CHAIN_POLICY.allowedSignatureAlgorithms
    ).map(normalizeAlgorithm),
    preferredSignatureAlgorithm: normalizeAlgorithm(
      policy.preferredSignatureAlgorithm ?? DEFAULT_CHAIN_POLICY.preferredSignatureAlgorithm
    ),
    mandatoryAccountClasses: [
      ...(policy.mandatoryAccountClasses ?? DEFAULT_CHAIN_POLICY.mandatoryAccountClasses)
    ],
    minValidatorCertificatePower: {
      ...DEFAULT_CHAIN_POLICY.minValidatorCertificatePower,
      ...(policy.minValidatorCertificatePower ?? {})
    }
  };
}

export function isPqActiveAtHeight(height, policy = {}) {
  const normalized = normalizeChainPolicy(policy);
  return Number(height) >= Number(normalized.activationHeight);
}

export function isLegacyGraceActiveAtHeight(height, policy = {}) {
  const normalized = normalizeChainPolicy(policy);
  const start = Number(normalized.activationHeight);
  const end = start + Number(normalized.legacyGracePeriod);
  return Number(height) >= start && Number(height) <= end;
}

export function isAlgorithmAllowed(algorithm, policy = {}) {
  const normalized = normalizeChainPolicy(policy);
  return normalized.allowedSignatureAlgorithms.includes(normalizeAlgorithm(algorithm));
}

export function isHybridRequiredForAccount(accountClass = 'default', height = 0, policy = {}) {
  const normalized = normalizeChainPolicy(policy);
  if (!isPqActiveAtHeight(height, normalized)) return false;
  return normalized.mandatoryAccountClasses.includes(accountClass);
}

export function verifyTxAgainstPolicy(envelope, registry, {
  accountClass = 'default',
  height = 0,
  policy = {}
} = {}) {
  const normalized = normalizeChainPolicy(policy);
  const required = isHybridRequiredForAccount(accountClass, height, normalized);
  const hasPqAuth = Boolean(envelope?.auth?.pqSignature);

  if (!required && !hasPqAuth) {
    return {
      ok: true,
      skipped: true,
      required: false,
      errors: []
    };
  }

  const result = verifyHybridTx(envelope, registry, { height });
  const errors = [...result.errors];
  if (hasPqAuth && !isAlgorithmAllowed(envelope.auth.pqAlgorithm, normalized)) {
    errors.push('PQ algorithm is not allowed by chain policy');
  }

  return {
    ...result,
    ok: errors.length === 0,
    errors,
    skipped: false,
    required
  };
}
