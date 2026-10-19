'use strict';

/**
 * Copy packages/athena-contracts from this repo into ../AthenaVI/packages/athena-contracts
 * when both repos are checked out side by side. Run after editing the canonical package.
 */
const fs = require('fs');
const path = require('path');

const src = path.join(__dirname, '../packages/athena-contracts');
const dest = path.join(__dirname, '../../AthenaVI/packages/athena-contracts');

function copyRecursive(from, to) {
  fs.mkdirSync(to, { recursive: true });
  for (const name of fs.readdirSync(from)) {
    if (name === 'node_modules') continue;
    const fromPath = path.join(from, name);
    const toPath = path.join(to, name);
    if (fs.statSync(fromPath).isDirectory()) {
      copyRecursive(fromPath, toPath);
    } else {
      fs.copyFileSync(fromPath, toPath);
    }
  }
}

if (!fs.existsSync(src)) {
  console.error('Missing source:', src);
  process.exit(1);
}

if (!fs.existsSync(path.join(__dirname, '../../AthenaVI'))) {
  console.error(
    'AthenaVI repo not found next to backend. Clone both repos side by side or copy packages/athena-contracts manually.'
  );
  process.exit(1);
}

copyRecursive(src, dest);
console.log('Synced athena-contracts → AthenaVI/packages/athena-contracts');
