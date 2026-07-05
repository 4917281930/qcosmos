#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import {
  addressFromClassicPublicKey,
  decapsulateKem,
  encapsulateKem,
  generateClassicKeyPair,
  generateKemKeyPair,
  generatePqKeyPair,
  listPqAlgorithms,
  PqRegistry,
  verifyFinalityCertificate,
  verifyHybridTx
} from '../src/index.js';

function parseArgs(argv) {
  const [command, ...rest] = argv;
  const flags = {};
  for (let i = 0; i < rest.length; i += 1) {
    const item = rest[i];
    if (!item.startsWith('--')) {
      flags._ = flags._ ?? [];
      flags._.push(item);
      continue;
    }
    const key = item.slice(2);
    const next = rest[i + 1];
    if (!next || next.startsWith('--')) {
      flags[key] = true;
    } else {
      flags[key] = next;
      i += 1;
    }
  }
  return { command, flags };
}

function readJson(path) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

function printJson(value) {
  process.stdout.write(`${JSON.stringify(value, null, 2)}\n`);
}

function usage() {
  process.stdout.write(`qcosmos commands:
  algorithms
  keygen --algo classic|mldsa65|mldsa87|slhdsa128s|mlkem768|mlkem1024 [--prefix cosmos]
  address --classic-pub <hex> [--prefix cosmos]
  kem-encapsulate --algo mlkem768|mlkem1024 --public-key <hex>
  kem-decapsulate --algo mlkem768|mlkem1024 --cipher-text <hex> --secret-key <hex>
  verify-tx --registry registry.json --tx envelope.json [--height n]
  verify-cert --validators validators.json --cert certificate.json
`);
}

const { command, flags } = parseArgs(process.argv.slice(2));

try {
  switch (command) {
    case 'algorithms':
      printJson(listPqAlgorithms());
      break;
    case 'keygen': {
      const algo = flags.algo ?? 'mldsa65';
      if (algo === 'classic' || algo === 'secp256k1') {
        const key = generateClassicKeyPair();
        printJson({
          ...key,
          address: addressFromClassicPublicKey(key.publicKey, flags.prefix ?? 'cosmos')
        });
      } else if (algo.startsWith('mlkem')) {
        printJson(generateKemKeyPair(algo));
      } else {
        printJson(generatePqKeyPair(algo));
      }
      break;
    }
    case 'address':
      if (!flags['classic-pub']) throw new Error('missing --classic-pub');
      printJson({
        prefix: flags.prefix ?? 'cosmos',
        address: addressFromClassicPublicKey(flags['classic-pub'], flags.prefix ?? 'cosmos')
      });
      break;
    case 'kem-encapsulate':
      if (!flags.algo || !flags['public-key']) {
        throw new Error('missing --algo or --public-key');
      }
      printJson(encapsulateKem(flags.algo, flags['public-key']));
      break;
    case 'kem-decapsulate':
      if (!flags.algo || !flags['cipher-text'] || !flags['secret-key']) {
        throw new Error('missing --algo, --cipher-text, or --secret-key');
      }
      printJson({
        algorithm: flags.algo,
        sharedSecret: decapsulateKem(flags.algo, flags['cipher-text'], flags['secret-key'])
      });
      break;
    case 'verify-tx': {
      if (!flags.registry || !flags.tx) throw new Error('missing --registry or --tx');
      const registry = PqRegistry.fromJSON(readJson(flags.registry));
      const tx = readJson(flags.tx);
      const result = verifyHybridTx(tx, registry, {
        height: flags.height === undefined ? null : Number(flags.height)
      });
      printJson(result);
      process.exitCode = result.ok ? 0 : 2;
      break;
    }
    case 'verify-cert': {
      if (!flags.validators || !flags.cert) throw new Error('missing --validators or --cert');
      const result = verifyFinalityCertificate(readJson(flags.cert), readJson(flags.validators));
      printJson(result);
      process.exitCode = result.ok ? 0 : 2;
      break;
    }
    default:
      usage();
      process.exitCode = command ? 1 : 0;
  }
} catch (error) {
  process.stderr.write(`${error.message}\n`);
  process.exitCode = 1;
}
