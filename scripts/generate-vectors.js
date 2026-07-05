import { mkdirSync, writeFileSync } from 'node:fs';
import {
  bytesToHex,
  createFinalityCertificate,
  createHeaderCommitment,
  createTxBody,
  DOMAINS,
  generateClassicKeyPair,
  generatePqKeyPair,
  hashValidatorSet,
  keyBindingSignBytes,
  PqRegistry,
  REGISTRY_MESSAGE_TYPES,
  revocationSignBytes,
  sha256Hex,
  signClassic,
  signPq,
  txSignBytes,
  validatorAttestationSignBytes,
  verifyFinalityCertificate,
  verifyHybridIbcUpdate,
  verifyHybridTx,
  verifyRegistryMessage
} from '../src/index.js';
import { addressFromClassicPublicKey } from '../src/address.js';

const chainId = 'qcosmos-vector-1';
const classicSecret = '0000000000000000000000000000000000000000000000000000000000000001';
const classic = generateClassicKeyPair(classicSecret);
const pq = generatePqKeyPair('mldsa65', '11'.repeat(32));
const address = addressFromClassicPublicKey(classic.publicKey, 'cosmos');

const registerUnsigned = {
  type: REGISTRY_MESSAGE_TYPES.register,
  chainId,
  address,
  classicPublicKey: classic.publicKey,
  pqAlgorithm: pq.algorithm,
  pqPublicKey: pq.publicKey,
  pqKeyVersion: 1,
  nonce: 'vector-register-0001',
  notBeforeHeight: 1,
  expiresAtHeight: null,
  metadata: {
    accountClass: 'treasury',
    vector: 'true'
  }
};
const registerSignBytes = keyBindingSignBytes(registerUnsigned);
const registerMessage = {
  ...registerUnsigned,
  signatures: {
    classic: signClassic(registerSignBytes, classic.secretKey, { extraEntropy: false }),
    pq: signPq(pq.algorithm, registerSignBytes, pq.secretKey, { extraEntropy: false })
  }
};

const registry = new PqRegistry();
registry.apply(registerMessage, 1);

const txBody = createTxBody({
  chainId,
  accountAddress: address,
  sequence: 1,
  messages: [{
    typeUrl: '/cosmos.bank.v1beta1.MsgSend',
    value: {
      fromAddress: address,
      toAddress: 'cosmos1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqp8r7p4',
      amount: [{ denom: 'uatom', amount: '42' }]
    }
  }],
  fee: {
    amount: [{ denom: 'uatom', amount: '250' }],
    gasLimit: '90000'
  },
  memo: 'qcosmos deterministic vector'
});
const txBytes = txSignBytes(txBody);
const txEnvelope = {
  body: txBody,
  auth: {
    classicAlgorithm: 'secp256k1',
    classicPublicKey: classic.publicKey,
    classicSignature: signClassic(txBytes, classic.secretKey, { extraEntropy: false }),
    pqAlgorithm: pq.algorithm,
    pqPublicKey: pq.publicKey,
    pqKeyVersion: 1,
    pqSignature: signPq(pq.algorithm, txBytes, pq.secretKey, { extraEntropy: false })
  }
};

function validator(index, power) {
  const classicKey = generateClassicKeyPair(index.toString(16).padStart(64, '0'));
  const pqKey = generatePqKeyPair('mldsa65', (0x20 + index).toString(16).padStart(2, '0').repeat(32));
  return {
    secretKey: pqKey.secretKey,
    validator: {
      address: addressFromClassicPublicKey(classicKey.publicKey, 'cosmosvalcons'),
      power,
      pqAlgorithm: pqKey.algorithm,
      pqPublicKey: pqKey.publicKey
    }
  };
}

const validatorsWithSecrets = [validator(2, 40), validator(3, 35), validator(4, 25)];
const validators = validatorsWithSecrets.map((item) => item.validator);
const validatorsHash = hashValidatorSet(validators);
const header = createHeaderCommitment({
  chainId,
  height: 200,
  round: 0,
  blockId: '1'.repeat(64),
  appHash: '2'.repeat(64),
  validatorsHash,
  nextValidatorsHash: validatorsHash,
  timeUnixMs: 1783267200000
});
const attestationBytes = validatorAttestationSignBytes(header);
const certificate = createFinalityCertificate({
  header,
  attestations: validatorsWithSecrets.slice(0, 2).map((item) => ({
    address: item.validator.address,
    pqAlgorithm: item.validator.pqAlgorithm,
    pqPublicKey: item.validator.pqPublicKey,
    signature: signPq(
      item.validator.pqAlgorithm,
      attestationBytes,
      item.secretKey,
      { extraEntropy: false }
    )
  }))
});

const ibcUpdate = {
  trustedConsensusState: {
    timestampUnixMs: '1783267199000',
    appHash: '0'.repeat(64),
    nextValidatorsHash: validatorsHash
  },
  header,
  trustedValidators: validators,
  validatorSet: validators,
  certificate
};

const vector = {
  name: 'qcosmos-v1-deterministic',
  generatedBy: 'scripts/generate-vectors.js',
  domains: DOMAINS,
  account: {
    classic,
    pq,
    address
  },
  registry: {
    registerSignBytesHex: bytesToHex(registerSignBytes),
    registerSignBytesSha256: sha256Hex(registerSignBytes),
    registerMessage,
    registerVerification: verifyRegistryMessage(registerMessage)
  },
  tx: {
    signBytesHex: bytesToHex(txBytes),
    signBytesSha256: sha256Hex(txBytes),
    envelope: txEnvelope,
    verification: verifyHybridTx(txEnvelope, registry)
  },
  finality: {
    validators,
    validatorSetHash: validatorsHash,
    header,
    attestationSignBytesHex: bytesToHex(attestationBytes),
    attestationSignBytesSha256: sha256Hex(attestationBytes),
    certificate,
    verification: verifyFinalityCertificate(certificate, validators)
  },
  ibc: {
    update: ibcUpdate,
    verification: verifyHybridIbcUpdate(ibcUpdate)
  },
  unused: {
    revocationDomainSignBytesSha256: sha256Hex(revocationSignBytes({
      type: REGISTRY_MESSAGE_TYPES.revoke,
      chainId,
      address,
      classicPublicKey: classic.publicKey,
      pqKeyVersion: 1,
      nonce: 'vector-revoke-0001',
      reason: 'vector'
    }))
  }
};

mkdirSync('testdata', { recursive: true });
writeFileSync('testdata/qcosmos-vectors-v1.json', `${JSON.stringify(vector, null, 2)}\n`);
console.log('Wrote testdata/qcosmos-vectors-v1.json');
