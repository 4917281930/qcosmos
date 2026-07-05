import { readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import protobuf from 'protobufjs';

const files = [];

function walk(dir) {
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    const stat = statSync(path);
    if (stat.isDirectory()) walk(path);
    else if (path.endsWith('.proto')) files.push(path);
  }
}

walk('proto');

for (const file of files) {
  const root = new protobuf.Root();
  await root.load(file, { keepCase: true });
  root.resolveAll();
}

console.log(`Validated ${files.length} protobuf contracts`);
