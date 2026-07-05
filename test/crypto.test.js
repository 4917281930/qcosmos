import test from 'node:test';
import assert from 'node:assert/strict';
import {
  addressFromClassicPublicKey,
  decapsulateKem,
  encapsulateKem,
  generateClassicKeyPair,
  generateKemKeyPair,
  generatePqKeyPair,
  signClassic,
  signPq,
  utf8ToBytes,
  verifyClassic,
  verifyPq
} from '../src/index.js';

test('classic secp256k1 signing and Cosmos address derivation work', () => {
  const key = generateClassicKeyPair();
  const message = utf8ToBytes('qcosmos');
  const signature = signClassic(message, key.secretKey);

  assert.equal(verifyClassic(signature, message, key.publicKey), true);
  assert.match(addressFromClassicPublicKey(key.publicKey, 'cosmos'), /^cosmos1/);
});

test('ML-DSA signing verifies and rejects modified messages', () => {
  const key = generatePqKeyPair('mldsa65');
  const message = utf8ToBytes('header commitment');
  const signature = signPq(key.algorithm, message, key.secretKey);

  assert.equal(verifyPq(key.algorithm, signature, message, key.publicKey), true);
  assert.equal(verifyPq(key.algorithm, signature, utf8ToBytes('tampered'), key.publicKey), false);
});

test('ML-KEM encapsulation and decapsulation derive the same shared secret', () => {
  const key = generateKemKeyPair('mlkem768');
  const encrypted = encapsulateKem(key.algorithm, key.publicKey);
  const sharedSecret = decapsulateKem(key.algorithm, encrypted.cipherText, key.secretKey);

  assert.equal(sharedSecret, encrypted.sharedSecret);
});
