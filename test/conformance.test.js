import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  bytesToHex,
  keyBindingSignBytes,
  PqRegistry,
  sha256Hex,
  txSignBytes,
  validatorAttestationSignBytes,
  verifyFinalityCertificate,
  verifyHybridIbcUpdate,
  verifyHybridTx,
  verifyRegistryMessage
} from '../src/index.js';

const vector = JSON.parse(readFileSync('testdata/qcosmos-vectors-v1.json', 'utf8'));

test('conformance vector registry message verifies and sign bytes are stable', () => {
  const message = vector.registry.registerMessage;
  const signBytes = keyBindingSignBytes(message);

  assert.equal(bytesToHex(signBytes), vector.registry.registerSignBytesHex);
  assert.equal(sha256Hex(signBytes), vector.registry.registerSignBytesSha256);
  assert.equal(verifyRegistryMessage(message).ok, true);
});

test('conformance vector hybrid transaction verifies', () => {
  const registry = new PqRegistry();
  registry.apply(vector.registry.registerMessage, 1);
  const signBytes = txSignBytes(vector.tx.envelope.body);

  assert.equal(bytesToHex(signBytes), vector.tx.signBytesHex);
  assert.equal(sha256Hex(signBytes), vector.tx.signBytesSha256);
  assert.equal(verifyHybridTx(vector.tx.envelope, registry).ok, true);
});

test('conformance vector finality certificate and IBC overlay verify', () => {
  const signBytes = validatorAttestationSignBytes(vector.finality.header);

  assert.equal(bytesToHex(signBytes), vector.finality.attestationSignBytesHex);
  assert.equal(sha256Hex(signBytes), vector.finality.attestationSignBytesSha256);
  assert.equal(
    verifyFinalityCertificate(vector.finality.certificate, vector.finality.validators).ok,
    true
  );
  assert.equal(verifyHybridIbcUpdate(vector.ibc.update).ok, true);
});
