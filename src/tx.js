import { DOMAINS, domainSignBytes, validationResult } from './canonical.js';
import { classicPublicKeyFromSecret, signClassic, verifyClassic } from './classic.js';
import { addressFromClassicPublicKey } from './address.js';
import { normalizeAlgorithm, pqPublicKeyFromSecret, signPq, verifyPq } from './pqc.js';

export function createTxBody({
  chainId,
  accountAddress,
  sequence,
  messages,
  fee = { amount: [], gasLimit: '0' },
  memo = '',
  timeoutHeight = 0,
  extensionOptions = {}
}) {
  return {
    chainId,
    accountAddress,
    sequence: String(sequence),
    messages,
    fee,
    memo,
    timeoutHeight: String(timeoutHeight),
    extensionOptions
  };
}

export function txSignBytes(body) {
  return domainSignBytes(DOMAINS.hybridTx, body);
}

export function signHybridTx({
  body,
  classicSecretKey,
  pqSecretKey,
  pqAlgorithm = 'mldsa65',
  pqKeyVersion = 1,
  prefix = 'cosmos'
}) {
  const classicPublicKey = classicPublicKeyFromSecret(classicSecretKey);
  const expectedAddress = addressFromClassicPublicKey(classicPublicKey, prefix);
  if (body.accountAddress !== expectedAddress) {
    throw new Error('transaction body accountAddress does not match classic key');
  }
  const canonicalAlgorithm = normalizeAlgorithm(pqAlgorithm);
  const bytes = txSignBytes(body);
  return {
    body,
    auth: {
      classicAlgorithm: 'secp256k1',
      classicPublicKey,
      classicSignature: signClassic(bytes, classicSecretKey),
      pqAlgorithm: canonicalAlgorithm,
      pqPublicKey: pqPublicKeyFromSecret(canonicalAlgorithm, pqSecretKey),
      pqKeyVersion,
      pqSignature: signPq(canonicalAlgorithm, bytes, pqSecretKey)
    }
  };
}

export function verifyHybridTx(envelope, registry, options = {}) {
  const errors = [];
  const height = options.height ?? null;
  const prefix = options.prefix ?? envelope.body?.accountAddress?.split('1')[0] ?? 'cosmos';
  const auth = envelope.auth ?? {};
  const body = envelope.body;

  if (!body) errors.push('missing transaction body');
  if (!auth.classicPublicKey) errors.push('missing classic public key');
  if (!auth.classicSignature) errors.push('missing classic signature');
  if (!auth.pqSignature) errors.push('missing PQ signature');

  if (errors.length > 0) return validationResult(errors);

  const expectedAddress = addressFromClassicPublicKey(auth.classicPublicKey, prefix);
  if (expectedAddress !== body.accountAddress) {
    errors.push('classic public key does not match transaction account address');
  }

  const bytes = txSignBytes(body);
  if (!verifyClassic(auth.classicSignature, bytes, auth.classicPublicKey)) {
    errors.push('invalid classic transaction signature');
  }

  const entry = typeof registry.getActive === 'function'
    ? registry.getActive(body.accountAddress, height)
    : registry[body.accountAddress];

  if (!entry) {
    errors.push('no active PQ registry entry for account');
  } else {
    const algo = normalizeAlgorithm(auth.pqAlgorithm);
    if (entry.pqAlgorithm !== algo) errors.push('PQ algorithm does not match registry');
    if (entry.pqKeyVersion !== auth.pqKeyVersion) errors.push('PQ key version does not match registry');
    if (entry.pqPublicKey !== auth.pqPublicKey) errors.push('PQ public key does not match registry');
    if (!verifyPq(entry.pqAlgorithm, auth.pqSignature, bytes, entry.pqPublicKey)) {
      errors.push('invalid PQ transaction signature');
    }
  }

  return validationResult(errors);
}

export function assertValidHybridTx(envelope, registry, options = {}) {
  const result = verifyHybridTx(envelope, registry, options);
  if (!result.ok) {
    const err = new Error(`invalid hybrid transaction: ${result.errors.join('; ')}`);
    err.result = result;
    throw err;
  }
  return true;
}
