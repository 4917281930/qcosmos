import test from 'node:test';
import assert from 'node:assert/strict';
import {
  addressFromClassicPublicKey,
  createRegisterKeyMessage,
  createRevokeKeyMessage,
  createRotateKeyMessage,
  createTxBody,
  generateClassicKeyPair,
  generatePqKeyPair,
  PqRegistry,
  signHybridTx,
  verifyHybridTx,
  verifyRegistryMessage
} from '../src/index.js';

test('registry accepts registration, rotation, and revocation messages', () => {
  const classic = generateClassicKeyPair();
  const pq1 = generatePqKeyPair('mldsa65');
  const registry = new PqRegistry();

  const register = createRegisterKeyMessage({
    chainId: 'qcosmos-test-1',
    classicSecretKey: classic.secretKey,
    pqSecretKey: pq1.secretKey,
    pqAlgorithm: pq1.algorithm
  });

  assert.equal(verifyRegistryMessage(register).ok, true);
  const entry1 = registry.apply(register, 10);
  assert.equal(entry1.pqKeyVersion, 1);

  const pq2 = generatePqKeyPair('mldsa87');
  const rotate = createRotateKeyMessage({
    chainId: 'qcosmos-test-1',
    classicSecretKey: classic.secretKey,
    currentPqSecretKey: pq1.secretKey,
    currentPqAlgorithm: pq1.algorithm,
    nextPqSecretKey: pq2.secretKey,
    nextPqAlgorithm: pq2.algorithm,
    pqKeyVersion: 2
  });

  assert.equal(verifyRegistryMessage(rotate, registry.get(register.address)).ok, true);
  const entry2 = registry.apply(rotate, 20);
  assert.equal(entry2.pqAlgorithm, 'mldsa87');
  assert.equal(entry2.pqKeyVersion, 2);

  const revoke = createRevokeKeyMessage({
    chainId: 'qcosmos-test-1',
    classicSecretKey: classic.secretKey,
    currentPqSecretKey: pq2.secretKey,
    currentPqAlgorithm: pq2.algorithm,
    pqKeyVersion: 2,
    reason: 'operator rotation'
  });

  assert.equal(verifyRegistryMessage(revoke, registry.get(register.address)).ok, true);
  const revoked = registry.apply(revoke, 30);
  assert.equal(revoked.status, 'revoked');
});

test('hybrid transactions require both classic and active PQ signatures', () => {
  const classic = generateClassicKeyPair();
  const pq = generatePqKeyPair('mldsa65');
  const address = addressFromClassicPublicKey(classic.publicKey, 'cosmos');
  const registry = new PqRegistry();
  registry.apply(createRegisterKeyMessage({
    chainId: 'qcosmos-test-1',
    classicSecretKey: classic.secretKey,
    pqSecretKey: pq.secretKey,
    pqAlgorithm: pq.algorithm
  }), 1);

  const body = createTxBody({
    chainId: 'qcosmos-test-1',
    accountAddress: address,
    sequence: 7,
    messages: [
      {
        typeUrl: '/cosmos.bank.v1beta1.MsgSend',
        value: {
          fromAddress: address,
          toAddress: 'cosmos1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqp8r7p4',
          amount: [{ denom: 'uatom', amount: '1' }]
        }
      }
    ],
    fee: { amount: [{ denom: 'uatom', amount: '200' }], gasLimit: '80000' }
  });
  const envelope = signHybridTx({
    body,
    classicSecretKey: classic.secretKey,
    pqSecretKey: pq.secretKey,
    pqAlgorithm: pq.algorithm,
    pqKeyVersion: 1
  });

  assert.equal(verifyHybridTx(envelope, registry).ok, true);

  const tampered = structuredClone(envelope);
  tampered.body.messages[0].value.amount[0].amount = '100';
  const result = verifyHybridTx(tampered, registry);
  assert.equal(result.ok, false);
  assert.match(result.errors.join('\n'), /signature/);
});
