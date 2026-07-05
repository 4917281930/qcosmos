import {
  addressFromClassicPublicKey,
  createFinalityCertificate,
  createHeaderCommitment,
  createRegisterKeyMessage,
  createTxBody,
  generateClassicKeyPair,
  generatePqKeyPair,
  hashValidatorSet,
  PqRegistry,
  signHybridTx,
  signValidatorAttestation,
  verifyFinalityCertificate,
  verifyHybridIbcUpdate,
  verifyTxAgainstPolicy
} from '../src/index.js';

const chainId = 'qcosmos-demo-1';

const accountClassic = generateClassicKeyPair();
const accountPq = generatePqKeyPair('mldsa65');
const accountAddress = addressFromClassicPublicKey(accountClassic.publicKey, 'cosmos');
const registry = new PqRegistry();

registry.apply(createRegisterKeyMessage({
  chainId,
  classicSecretKey: accountClassic.secretKey,
  pqSecretKey: accountPq.secretKey,
  pqAlgorithm: accountPq.algorithm
}), 1);

const tx = signHybridTx({
  body: createTxBody({
    chainId,
    accountAddress,
    sequence: 1,
    messages: [{
      typeUrl: '/cosmos.bank.v1beta1.MsgSend',
      value: {
        fromAddress: accountAddress,
        toAddress: 'cosmos1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqp8r7p4',
        amount: [{ denom: 'uatom', amount: '1000' }]
      }
    }]
  }),
  classicSecretKey: accountClassic.secretKey,
  pqSecretKey: accountPq.secretKey,
  pqAlgorithm: accountPq.algorithm
});

const txResult = verifyTxAgainstPolicy(tx, registry, {
  accountClass: 'treasury',
  height: 100,
  policy: { activationHeight: 1 }
});

function validator(power) {
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

const validatorsWithSecrets = [validator(40), validator(35), validator(25)];
const validators = validatorsWithSecrets.map((item) => item.validator);
const validatorsHash = hashValidatorSet(validators);
const header = createHeaderCommitment({
  chainId,
  height: 200,
  blockId: '1'.repeat(64),
  appHash: '2'.repeat(64),
  validatorsHash,
  nextValidatorsHash: validatorsHash,
  timeUnixMs: Date.now()
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
const certificateResult = verifyFinalityCertificate(certificate, validators);
const ibcResult = verifyHybridIbcUpdate({
  trustedConsensusState: {
    timestampUnixMs: String(Date.now() - 1000),
    appHash: '0'.repeat(64),
    nextValidatorsHash: validatorsHash
  },
  header,
  trustedValidators: validators,
  validatorSet: validators,
  certificate
});

console.log(JSON.stringify({
  accountAddress,
  txVerified: txResult.ok,
  certificateVerified: certificateResult.ok,
  ibcOverlayVerified: ibcResult.ok
}, null, 2));
