import test from 'node:test';
import assert from 'node:assert/strict';
import {
  addressFromClassicPublicKey,
  createFinalityCertificate,
  createHeaderCommitment,
  generateClassicKeyPair,
  generatePqKeyPair,
  hashValidatorSet,
  signValidatorAttestation,
  verifyFinalityCertificate,
  verifyHybridIbcUpdate
} from '../src/index.js';

function makeValidator(power) {
  const classic = generateClassicKeyPair();
  const pq = generatePqKeyPair('mldsa65');
  return {
    secretKey: pq.secretKey,
    validator: {
      address: addressFromClassicPublicKey(classic.publicKey, 'cosmosvalcons'),
      power,
      pqAlgorithm: pq.algorithm,
      pqPublicKey: pq.publicKey
    }
  };
}

test('validator PQ finality certificate requires more than two thirds power', () => {
  const validatorsWithSecrets = [makeValidator(40), makeValidator(35), makeValidator(25)];
  const validators = validatorsWithSecrets.map((item) => item.validator);
  const validatorsHash = hashValidatorSet(validators);
  const nextValidatorsHash = hashValidatorSet(validators);
  const header = createHeaderCommitment({
    chainId: 'qcosmos-test-1',
    height: 100,
    round: 0,
    blockId: 'A'.repeat(64),
    appHash: 'B'.repeat(64),
    validatorsHash,
    nextValidatorsHash,
    timeUnixMs: 1783267200000
  });

  const attestations = validatorsWithSecrets.slice(0, 2).map((item) =>
    signValidatorAttestation({
      header,
      validator: item.validator,
      pqSecretKey: item.secretKey
    })
  );
  const certificate = createFinalityCertificate({ header, attestations });
  const result = verifyFinalityCertificate(certificate, validators);

  assert.equal(result.ok, true);
  assert.equal(result.signedPower, '75');

  const weak = createFinalityCertificate({ header, attestations: attestations.slice(0, 1) });
  assert.equal(verifyFinalityCertificate(weak, validators).ok, false);
});

test('IBC hybrid update binds PQ certificate to the submitted header', () => {
  const validatorsWithSecrets = [makeValidator(50), makeValidator(30), makeValidator(20)];
  const validators = validatorsWithSecrets.map((item) => item.validator);
  const validatorsHash = hashValidatorSet(validators);
  const header = createHeaderCommitment({
    chainId: 'counterparty-1',
    height: 123,
    blockId: 'C'.repeat(64),
    appHash: 'D'.repeat(64),
    validatorsHash,
    nextValidatorsHash: validatorsHash,
    timeUnixMs: 1783267200000
  });
  const certificate = createFinalityCertificate({
    header,
    attestations: validatorsWithSecrets.slice(0, 2).map((item) =>
      signValidatorAttestation({
        header,
        validator: item.validator,
        pqSecretKey: item.secretKey
      })
    )
  });

  const result = verifyHybridIbcUpdate({
    trustedConsensusState: {
      timestampUnixMs: '1783267190000',
      appHash: '0'.repeat(64),
      nextValidatorsHash: validatorsHash
    },
    header,
    trustedValidators: validators,
    validatorSet: validators,
    certificate
  });

  assert.equal(result.ok, true);

  const mismatched = structuredClone(certificate);
  mismatched.header.appHash = 'E'.repeat(64);
  assert.equal(verifyHybridIbcUpdate({
    trustedConsensusState: {
      timestampUnixMs: '1783267190000',
      appHash: '0'.repeat(64),
      nextValidatorsHash: validatorsHash
    },
    header,
    trustedValidators: validators,
    validatorSet: validators,
    certificate: mismatched
  }).ok, false);
});
