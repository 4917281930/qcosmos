import { createHash, timingSafeEqual } from 'node:crypto';

export const textEncoder = new TextEncoder();
export const textDecoder = new TextDecoder();

export const DOMAINS = Object.freeze({
  keyBinding: 'qcosmos/pq-key-binding/v1',
  keyRevocation: 'qcosmos/pq-key-revocation/v1',
  hybridTx: 'qcosmos/hybrid-tx/v1',
  validatorAttestation: 'qcosmos/validator-attestation/v1',
  ibcHybridUpdate: 'qcosmos/ibc-hybrid-update/v1'
});

export function utf8ToBytes(value) {
  return textEncoder.encode(value);
}

export function bytesToUtf8(bytes) {
  return textDecoder.decode(bytes);
}

export function bytesToHex(bytes) {
  assertBytes(bytes, 'bytes');
  return Buffer.from(bytes).toString('hex');
}

export function hexToBytes(hex) {
  if (typeof hex !== 'string') {
    throw new TypeError('hex must be a string');
  }
  const normalized = hex.startsWith('0x') ? hex.slice(2) : hex;
  if (normalized.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(normalized)) {
    throw new TypeError('invalid hex string');
  }
  return new Uint8Array(Buffer.from(normalized, 'hex'));
}

export function bytesToBase64(bytes) {
  assertBytes(bytes, 'bytes');
  return Buffer.from(bytes).toString('base64');
}

export function base64ToBytes(base64) {
  if (typeof base64 !== 'string') {
    throw new TypeError('base64 must be a string');
  }
  return new Uint8Array(Buffer.from(base64, 'base64'));
}

export function concatBytes(...arrays) {
  const total = arrays.reduce((sum, item) => {
    assertBytes(item, 'concat segment');
    return sum + item.length;
  }, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const item of arrays) {
    out.set(item, offset);
    offset += item.length;
  }
  return out;
}

export function sha256(bytes) {
  assertBytes(bytes, 'sha256 input');
  return new Uint8Array(createHash('sha256').update(bytes).digest());
}

export function sha256Hex(bytes) {
  return bytesToHex(sha256(bytes));
}

export function ripemd160(bytes) {
  assertBytes(bytes, 'ripemd160 input');
  return new Uint8Array(createHash('ripemd160').update(bytes).digest());
}

export function hash160(bytes) {
  return ripemd160(sha256(bytes));
}

export function equalBytes(a, b) {
  assertBytes(a, 'left bytes');
  assertBytes(b, 'right bytes');
  if (a.length !== b.length) return false;
  return timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

export function canonicalize(value) {
  if (value === null) return null;
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value instanceof Uint8Array) {
    throw new TypeError('Uint8Array cannot be canonicalized directly; encode as hex first');
  }
  if (typeof value === 'bigint') return value.toString();
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new TypeError('non-finite numbers are not canonical');
    if (Object.is(value, -0)) return 0;
    return value;
  }
  if (typeof value === 'string' || typeof value === 'boolean') return value;
  if (typeof value === 'undefined') {
    throw new TypeError('undefined is not canonical JSON');
  }
  if (typeof value === 'object') {
    const out = {};
    for (const key of Object.keys(value).sort()) {
      const child = value[key];
      if (typeof child === 'undefined') continue;
      out[key] = canonicalize(child);
    }
    return out;
  }
  throw new TypeError(`unsupported canonical JSON type: ${typeof value}`);
}

export function canonicalJson(value) {
  return JSON.stringify(canonicalize(value));
}

export function canonicalBytes(value) {
  return utf8ToBytes(canonicalJson(value));
}

export function domainSignBytes(domain, payload) {
  if (typeof domain !== 'string' || domain.length === 0) {
    throw new TypeError('domain must be a non-empty string');
  }
  return utf8ToBytes(`${domain}\n${canonicalJson(payload)}`);
}

export function omitUndefined(value) {
  return canonicalize(value);
}

export function assertBytes(value, name = 'value') {
  if (!(value instanceof Uint8Array)) {
    throw new TypeError(`${name} must be Uint8Array`);
  }
}

export function assertHex(value, name = 'hex') {
  if (typeof value !== 'string' || value.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(value)) {
    throw new TypeError(`${name} must be even-length hex`);
  }
}

export function validationResult(errors, extra = {}) {
  return {
    ok: errors.length === 0,
    errors,
    ...extra
  };
}
