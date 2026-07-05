import * as secp from '@noble/secp256k1';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 as nobleSha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes } from './canonical.js';

secp.hashes.sha256 = nobleSha256;
secp.hashes.hmacSha256 = (key, message) => hmac(nobleSha256, key, message);

export const CLASSIC_ALGORITHM = 'secp256k1';

export function generateClassicKeyPair(secretKeyHex = null) {
  const secretKey = secretKeyHex ? hexToBytes(secretKeyHex) : secp.utils.randomSecretKey();
  const publicKey = secp.getPublicKey(secretKey, true);
  return {
    algorithm: CLASSIC_ALGORITHM,
    secretKey: bytesToHex(secretKey),
    publicKey: bytesToHex(publicKey)
  };
}

export function classicPublicKeyFromSecret(secretKeyHex) {
  return bytesToHex(secp.getPublicKey(hexToBytes(secretKeyHex), true));
}

export function signClassic(message, secretKeyHex, options = {}) {
  const extraEntropy = Object.hasOwn(options, 'extraEntropy') ? options.extraEntropy : true;
  return bytesToHex(
    secp.sign(message, hexToBytes(secretKeyHex), {
      format: 'compact',
      lowS: true,
      extraEntropy
    })
  );
}

export function verifyClassic(signatureHex, message, publicKeyHex) {
  try {
    return secp.verify(
      hexToBytes(signatureHex),
      message,
      hexToBytes(publicKeyHex),
      { format: 'compact', lowS: true }
    );
  } catch {
    return false;
  }
}

export function isValidClassicPublicKey(publicKeyHex) {
  try {
    return secp.utils.isValidPublicKey(hexToBytes(publicKeyHex), true);
  } catch {
    return false;
  }
}

export function isValidClassicSecretKey(secretKeyHex) {
  try {
    return secp.utils.isValidSecretKey(hexToBytes(secretKeyHex));
  } catch {
    return false;
  }
}
