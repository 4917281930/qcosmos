import { bech32 } from 'bech32';
import { bytesToHex, hash160, hexToBytes } from './canonical.js';

export function addressBytesFromClassicPublicKey(classicPublicKeyHex) {
  return hash160(hexToBytes(classicPublicKeyHex));
}

export function addressFromClassicPublicKey(classicPublicKeyHex, prefix = 'cosmos') {
  const words = bech32.toWords(addressBytesFromClassicPublicKey(classicPublicKeyHex));
  return bech32.encode(prefix, words);
}

export function decodeAddress(address) {
  const decoded = bech32.decode(address);
  const bytes = new Uint8Array(bech32.fromWords(decoded.words));
  if (bytes.length !== 20) {
    throw new TypeError('Cosmos account addresses must decode to 20 bytes');
  }
  return {
    prefix: decoded.prefix,
    bytes,
    hex: bytesToHex(bytes)
  };
}

export function assertAddressMatchesPublicKey(address, classicPublicKeyHex) {
  const { prefix } = decodeAddress(address);
  const expected = addressFromClassicPublicKey(classicPublicKeyHex, prefix);
  if (expected !== address) {
    throw new Error('classic public key does not derive the supplied address');
  }
  return true;
}
