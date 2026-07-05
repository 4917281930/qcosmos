import {
  DOMAINS,
  domainSignBytes,
  validationResult
} from './canonical.js';
import { randomUUID } from 'node:crypto';
import {
  classicPublicKeyFromSecret,
  signClassic,
  verifyClassic
} from './classic.js';
import { addressFromClassicPublicKey } from './address.js';
import {
  generatePqKeyPair,
  normalizeAlgorithm,
  pqPublicKeyFromSecret,
  signPq,
  verifyPq
} from './pqc.js';

export const REGISTRY_MESSAGE_TYPES = Object.freeze({
  register: 'qcosmos/MsgRegisterPQKey',
  rotate: 'qcosmos/MsgRotatePQKey',
  revoke: 'qcosmos/MsgRevokePQKey'
});

export function keyBindingPayload(message) {
  return {
    type: message.type,
    chainId: message.chainId,
    address: message.address,
    classicAlgorithm: 'secp256k1',
    classicPublicKey: message.classicPublicKey,
    pqAlgorithm: normalizeAlgorithm(message.pqAlgorithm),
    pqPublicKey: message.pqPublicKey,
    pqKeyVersion: message.pqKeyVersion,
    nonce: message.nonce,
    notBeforeHeight: message.notBeforeHeight ?? 0,
    expiresAtHeight: message.expiresAtHeight ?? null,
    metadata: message.metadata ?? {}
  };
}

export function keyBindingSignBytes(message) {
  return domainSignBytes(DOMAINS.keyBinding, keyBindingPayload(message));
}

export function revocationPayload(message) {
  return {
    type: message.type,
    chainId: message.chainId,
    address: message.address,
    classicAlgorithm: 'secp256k1',
    classicPublicKey: message.classicPublicKey,
    pqKeyVersion: message.pqKeyVersion,
    nonce: message.nonce,
    reason: message.reason ?? ''
  };
}

export function revocationSignBytes(message) {
  return domainSignBytes(DOMAINS.keyRevocation, revocationPayload(message));
}

export function createRegisterKeyMessage({
  chainId,
  classicSecretKey,
  pqSecretKey,
  pqAlgorithm = 'mldsa65',
  pqKeyVersion = 1,
  prefix = 'cosmos',
  nonce = randomUUID(),
  notBeforeHeight = 0,
  expiresAtHeight = null,
  metadata = {}
}) {
  const classicPublicKey = classicPublicKeyFromSecret(classicSecretKey);
  const address = addressFromClassicPublicKey(classicPublicKey, prefix);
  const canonicalAlgorithm = normalizeAlgorithm(pqAlgorithm);
  const pqPublicKey = pqPublicKeyFromSecret(canonicalAlgorithm, pqSecretKey);
  const unsigned = {
    type: REGISTRY_MESSAGE_TYPES.register,
    chainId,
    address,
    classicPublicKey,
    pqAlgorithm: canonicalAlgorithm,
    pqPublicKey,
    pqKeyVersion,
    nonce,
    notBeforeHeight,
    expiresAtHeight,
    metadata
  };
  const bytes = keyBindingSignBytes(unsigned);
  return {
    ...unsigned,
    signatures: {
      classic: signClassic(bytes, classicSecretKey),
      pq: signPq(canonicalAlgorithm, bytes, pqSecretKey)
    }
  };
}

export function createRotateKeyMessage({
  chainId,
  classicSecretKey,
  currentPqSecretKey,
  currentPqAlgorithm,
  nextPqSecretKey,
  nextPqAlgorithm = 'mldsa65',
  pqKeyVersion,
  prefix = 'cosmos',
  nonce = randomUUID(),
  notBeforeHeight = 0,
  expiresAtHeight = null,
  metadata = {}
}) {
  const classicPublicKey = classicPublicKeyFromSecret(classicSecretKey);
  const address = addressFromClassicPublicKey(classicPublicKey, prefix);
  const canonicalAlgorithm = normalizeAlgorithm(nextPqAlgorithm);
  const currentAlgorithm = normalizeAlgorithm(currentPqAlgorithm);
  const pqPublicKey = pqPublicKeyFromSecret(canonicalAlgorithm, nextPqSecretKey);
  const unsigned = {
    type: REGISTRY_MESSAGE_TYPES.rotate,
    chainId,
    address,
    classicPublicKey,
    pqAlgorithm: canonicalAlgorithm,
    pqPublicKey,
    pqKeyVersion,
    nonce,
    notBeforeHeight,
    expiresAtHeight,
    metadata
  };
  const bytes = keyBindingSignBytes(unsigned);
  return {
    ...unsigned,
    signatures: {
      classic: signClassic(bytes, classicSecretKey),
      pq: signPq(canonicalAlgorithm, bytes, nextPqSecretKey),
      previousPq: signPq(currentAlgorithm, bytes, currentPqSecretKey)
    }
  };
}

export function createRevokeKeyMessage({
  chainId,
  classicSecretKey,
  currentPqSecretKey,
  currentPqAlgorithm,
  pqKeyVersion,
  prefix = 'cosmos',
  nonce = randomUUID(),
  reason = ''
}) {
  const classicPublicKey = classicPublicKeyFromSecret(classicSecretKey);
  const address = addressFromClassicPublicKey(classicPublicKey, prefix);
  const canonicalAlgorithm = normalizeAlgorithm(currentPqAlgorithm);
  const unsigned = {
    type: REGISTRY_MESSAGE_TYPES.revoke,
    chainId,
    address,
    classicPublicKey,
    pqKeyVersion,
    nonce,
    reason
  };
  const bytes = revocationSignBytes(unsigned);
  return {
    ...unsigned,
    signatures: {
      classic: signClassic(bytes, classicSecretKey),
      pq: signPq(canonicalAlgorithm, bytes, currentPqSecretKey)
    }
  };
}

export function createFreshRegisterKeyMessage({
  chainId,
  classicSecretKey,
  pqAlgorithm = 'mldsa65',
  pqKeyVersion = 1,
  prefix = 'cosmos',
  nonce,
  notBeforeHeight,
  expiresAtHeight,
  metadata
}) {
  const pq = generatePqKeyPair(pqAlgorithm);
  return {
    message: createRegisterKeyMessage({
      chainId,
      classicSecretKey,
      pqSecretKey: pq.secretKey,
      pqAlgorithm: pq.algorithm,
      pqKeyVersion,
      prefix,
      nonce,
      notBeforeHeight,
      expiresAtHeight,
      metadata
    }),
    pq
  };
}

export function verifyRegistryMessage(message, currentEntry = null, options = {}) {
  const errors = [];
  const prefix = options.prefix ?? message.address?.split('1')[0] ?? 'cosmos';

  if (!Object.values(REGISTRY_MESSAGE_TYPES).includes(message.type)) {
    errors.push('unsupported registry message type');
    return validationResult(errors);
  }
  if (!message.signatures) errors.push('missing signatures');

  let expectedAddress = '';
  try {
    expectedAddress = addressFromClassicPublicKey(message.classicPublicKey, prefix);
    if (expectedAddress !== message.address) errors.push('classic public key does not match address');
  } catch {
    errors.push('invalid classic public key or address');
  }

  if (message.type === REGISTRY_MESSAGE_TYPES.revoke) {
    const bytes = revocationSignBytes(message);
    if (!verifyClassic(message.signatures?.classic ?? '', bytes, message.classicPublicKey)) {
      errors.push('invalid classic revocation signature');
    }
    if (!currentEntry || currentEntry.status !== 'active') {
      errors.push('no active registry entry to revoke');
    } else {
      if (currentEntry.pqKeyVersion !== message.pqKeyVersion) {
        errors.push('revocation key version does not match active entry');
      }
      if (!verifyPq(currentEntry.pqAlgorithm, message.signatures?.pq ?? '', bytes, currentEntry.pqPublicKey)) {
        errors.push('invalid current PQ revocation signature');
      }
    }
    return validationResult(errors);
  }

  const bytes = keyBindingSignBytes(message);
  const pqAlgorithm = normalizeAlgorithm(message.pqAlgorithm);

  if (!verifyClassic(message.signatures?.classic ?? '', bytes, message.classicPublicKey)) {
    errors.push('invalid classic key-binding signature');
  }
  if (!verifyPq(pqAlgorithm, message.signatures?.pq ?? '', bytes, message.pqPublicKey)) {
    errors.push('invalid new PQ key-binding signature');
  }

  if (message.type === REGISTRY_MESSAGE_TYPES.register) {
    if (currentEntry && currentEntry.status === 'active') {
      errors.push('active registry entry already exists; use rotation');
    }
    if (message.pqKeyVersion !== 1) {
      errors.push('initial PQ key version must be 1');
    }
  }

  if (message.type === REGISTRY_MESSAGE_TYPES.rotate) {
    if (!currentEntry || currentEntry.status !== 'active') {
      errors.push('no active registry entry to rotate');
    } else {
      if (message.pqKeyVersion <= currentEntry.pqKeyVersion) {
        errors.push('rotation key version must increase');
      }
      if (!verifyPq(
        currentEntry.pqAlgorithm,
        message.signatures?.previousPq ?? '',
        bytes,
        currentEntry.pqPublicKey
      )) {
        errors.push('invalid previous PQ rotation signature');
      }
    }
  }

  return validationResult(errors);
}

export class PqRegistry {
  constructor(entries = {}) {
    this.entries = new Map();
    for (const [address, entry] of Object.entries(entries)) {
      this.entries.set(address, { ...entry });
    }
  }

  get(address) {
    return this.entries.get(address) ?? null;
  }

  getActive(address, height = null) {
    const entry = this.get(address);
    if (!entry || entry.status !== 'active') return null;
    if (height !== null && height < entry.notBeforeHeight) return null;
    if (height !== null && entry.expiresAtHeight !== null && height > entry.expiresAtHeight) return null;
    return entry;
  }

  apply(message, height = 0, options = {}) {
    const current = this.get(message.address);
    const result = verifyRegistryMessage(message, current, options);
    if (!result.ok) {
      const err = new Error(`invalid registry message: ${result.errors.join('; ')}`);
      err.result = result;
      throw err;
    }

    if (message.type === REGISTRY_MESSAGE_TYPES.revoke) {
      this.entries.set(message.address, {
        ...current,
        status: 'revoked',
        revokedAtHeight: height,
        revocationReason: message.reason ?? ''
      });
      return this.get(message.address);
    }

    const entry = {
      address: message.address,
      classicAlgorithm: 'secp256k1',
      classicPublicKey: message.classicPublicKey,
      pqAlgorithm: normalizeAlgorithm(message.pqAlgorithm),
      pqPublicKey: message.pqPublicKey,
      pqKeyVersion: message.pqKeyVersion,
      status: 'active',
      notBeforeHeight: message.notBeforeHeight ?? 0,
      expiresAtHeight: message.expiresAtHeight ?? null,
      registeredAtHeight: current?.registeredAtHeight ?? height,
      rotatedAtHeight: message.type === REGISTRY_MESSAGE_TYPES.rotate ? height : null,
      metadata: message.metadata ?? {}
    };
    this.entries.set(message.address, entry);
    return entry;
  }

  toJSON() {
    return Object.fromEntries(this.entries.entries());
  }

  static fromJSON(value) {
    return new PqRegistry(value ?? {});
  }
}
