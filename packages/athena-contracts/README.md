# @athena/contracts

Shared layout content contract, normalization, slot text, and repair helpers used by **AthenaVI_backend** and **AthenaVI**.

- **Canonical copy:** this folder in the backend repo.
- **Frontend:** `AthenaVI/packages/athena-contracts` (same contents; keep in sync).

After changing files here, from the backend repo run:

```bash
npm run sync:athena-contracts
```

Then commit the package in **both** repos (or your team’s chosen sync process).

Tests: `npm run test:content-contract-parity` and `npm run test:content-repair` in the backend repo.
