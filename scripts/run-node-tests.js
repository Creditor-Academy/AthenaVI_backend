'use strict';

/**
 * Collect test files from the listed directories and run them with `node --test`.
 * Avoids relying on `node --test` glob support (Node 21+); works on Node 20.
 */
const { spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');

const TEST_DIRS = [
  ['src/modules/presentation/test', /\.test\.js$/],
  ['packages/athena-contracts/test', /\.test\.mjs$/],
];

const files = [...process.argv.slice(2)];
for (const [dir, pattern] of TEST_DIRS) {
  const abs = path.join(root, dir);
  for (const name of fs.readdirSync(abs).sort()) {
    if (pattern.test(name)) files.push(path.join(dir, name));
  }
}

const result = spawnSync(process.execPath, ['--test', ...files], { cwd: root, stdio: 'inherit' });
process.exit(result.status ?? 1);
