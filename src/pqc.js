import { ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { ml_kem768, ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import {
  slh_dsa_sha2_128s,
  slh_dsa_sha2_192s,
  slh_dsa_sha2_256s
} from '@noble/post-quantum/slh-dsa.js';
import { bytesToHex, hexToBytes } from './canonical.js';

const SIGNATURE_ALGORITHMS = Object.freeze({
  mldsa65: {
    canonical: 'mldsa65',
    standardName: 'ML-DSA-65',
    type: 'signature',
    nist: 'FIPS 204',
    level: 3,
    implementation: ml_dsa65
  },
  mldsa87: {
    canonical: 'mldsa87',
    standardName: 'ML-DSA-87',
    type: 'signature',
    nist: 'FIPS 204',
    level: 5,
    implementation: ml_dsa87
  },
  slhdsa128s: {
    canonical: 'slhdsa128s',
    standardName: 'SLH-DSA-SHA2-128s',
    type: 'signature',
    nist: 'FIPS 205',
    level: 1,
    implementation: slh_dsa_sha2_128s
  },
  slhdsa192s: {
    canonical: 'slhdsa192s',
    standardName: 'SLH-DSA-SHA2-192s',
    type: 'signature',
    nist: 'FIPS 205',
    level: 3,
    implementation: slh_dsa_sha2_192s
  },
  slhdsa256s: {
    canonical: 'slhdsa256s',
    standardName: 'SLH-DSA-SHA2-256s',
    type: 'signature',
    nist: 'FIPS 205',
    level: 5,
    implementation: slh_dsa_sha2_256s
  }
});

const KEM_ALGORITHMS = Object.freeze({
  mlkem768: {
    canonical: 'mlkem768',
    standardName: 'ML-KEM-768',
    type: 'kem',
    nist: 'FIPS 203',
    level: 3,
    implementation: ml_kem768
  },
  mlkem1024: {
    canonical: 'mlkem1024',
    standardName: 'ML-KEM-1024',
    type: 'kem',
    nist: 'FIPS 203',
    level: 5,
    implementation: ml_kem1024
  }
});

export function normalizeAlgorithm(algorithm) {
  if (typeof algorithm !== 'string') {
    throw new TypeError('algorithm must be a string');
  }
  return algorithm.toLowerCase().replace(/[^a-z0-9]/g, '');
}

export function getSignatureAlgorithm(algorithm) {
  const normalized = normalizeAlgorithm(algorithm);
  const entry = SIGNATURE_ALGORITHMS[normalized];
  if (!entry) throw new Error(`unsupported PQ signature algorithm: ${algorithm}`);
  return entry;
}

export function getKemAlgorithm(algorithm) {
  const normalized = normalizeAlgorithm(algorithm);
  const entry = KEM_ALGORITHMS[normalized];
  if (!entry) throw new Error(`unsupported PQ KEM algorithm: ${algorithm}`);
  return entry;
}

export function listPqAlgorithms() {
  return {
    signatures: Object.values(SIGNATURE_ALGORITHMS).map(describeAlgorithm),
    kems: Object.values(KEM_ALGORITHMS).map(describeAlgorithm)
  };
}

export function describeAlgorithm(entry) {
  return {
    algorithm: entry.canonical,
    standardName: entry.standardName,
    type: entry.type,
    nist: entry.nist,
    level: entry.level,
    lengths: { ...entry.implementation.lengths }
  };
}

export function generatePqKeyPair(algorithm = 'mldsa65', seedHex = null) {
  const entry = getSignatureAlgorithm(algorithm);
  const keys = entry.implementation.keygen(seedHex ? hexToBytes(seedHex) : undefined);
  return {
    algorithm: entry.canonical,
    publicKey: bytesToHex(keys.publicKey),
    secretKey: bytesToHex(keys.secretKey)
  };
}

export function pqPublicKeyFromSecret(algorithm, secretKeyHex) {
  const entry = getSignatureAlgorithm(algorithm);
  return bytesToHex(entry.implementation.getPublicKey(hexToBytes(secretKeyHex)));
}

export function signPq(algorithm, message, secretKeyHex, options = {}) {
  const entry = getSignatureAlgorithm(algorithm);
  return bytesToHex(entry.implementation.sign(message, hexToBytes(secretKeyHex), options));
}

export function verifyPq(algorithm, signatureHex, message, publicKeyHex, options = {}) {
  try {
    const entry = getSignatureAlgorithm(algorithm);
    return entry.implementation.verify(
      hexToBytes(signatureHex),
      message,
      hexToBytes(publicKeyHex),
      options
    );
  } catch {
    return false;
  }
}

export function generateKemKeyPair(algorithm = 'mlkem768', seedHex = null) {
  const entry = getKemAlgorithm(algorithm);
  const keys = entry.implementation.keygen(seedHex ? hexToBytes(seedHex) : undefined);
  return {
    algorithm: entry.canonical,
    publicKey: bytesToHex(keys.publicKey),
    secretKey: bytesToHex(keys.secretKey)
  };
}

export function encapsulateKem(algorithm, publicKeyHex) {
  const entry = getKemAlgorithm(algorithm);
  const result = entry.implementation.encapsulate(hexToBytes(publicKeyHex));
  return {
    algorithm: entry.canonical,
    cipherText: bytesToHex(result.cipherText),
    sharedSecret: bytesToHex(result.sharedSecret)
  };
}

export function decapsulateKem(algorithm, cipherTextHex, secretKeyHex) {
  const entry = getKemAlgorithm(algorithm);
  return bytesToHex(
    entry.implementation.decapsulate(hexToBytes(cipherTextHex), hexToBytes(secretKeyHex))
  );
}
