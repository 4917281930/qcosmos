import test from 'node:test';
import assert from 'node:assert/strict';
import {
  isAlgorithmAllowed,
  isHybridRequiredForAccount,
  normalizeChainPolicy,
  verifyTxAgainstPolicy
} from '../src/index.js';

test('chain policy normalizes algorithms and account classes', () => {
  const policy = normalizeChainPolicy({
    allowedSignatureAlgorithms: ['ML-DSA-65'],
    activationHeight: 50
  });

  assert.deepEqual(policy.allowedSignatureAlgorithms, ['mldsa65']);
  assert.equal(isAlgorithmAllowed('ml-dsa-65', policy), true);
  assert.equal(isAlgorithmAllowed('mldsa87', policy), false);
  assert.equal(isHybridRequiredForAccount('treasury', 49, policy), false);
  assert.equal(isHybridRequiredForAccount('treasury', 50, policy), true);
});

test('policy can skip optional legacy accounts before they opt in', () => {
  const result = verifyTxAgainstPolicy({ body: {} }, {}, {
    accountClass: 'default',
    height: 10,
    policy: { activationHeight: 1 }
  });

  assert.equal(result.ok, true);
  assert.equal(result.skipped, true);
  assert.equal(result.required, false);
});
