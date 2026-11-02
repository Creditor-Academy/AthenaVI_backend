const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const SRC = path.resolve(__dirname, '../..');

function stub(relPath, exports) {
  const file = require.resolve(path.join(SRC, relPath));
  require.cache[file] = { id: file, filename: file, loaded: true, exports };
}

const store = new Map();
stub('shared/config/redis.js', {
  redisClient: {
    async get(key) {
      return store.has(key) ? String(store.get(key)) : null;
    },
    async incr(key) {
      const next = (store.get(key) || 0) + 1;
      store.set(key, next);
      return next;
    },
    async ttl(key) {
      return store.has(key) ? 3600 : -2;
    },
    async expire() {},
  },
});

const { assertContextCreateAllowed, getContextHourState, MAX } = require('./imageGen.contextRateLimit.service');

test('context-create limit is per user, across workspaces, and not shared with teammates', async () => {
  for (let i = 0; i < MAX; i += 1) {
    // eslint-disable-next-line no-await-in-loop
    await assertContextCreateAllowed('user-a', i % 2 ? 'ws-1' : 'ws-2');
  }

  await assert.rejects(assertContextCreateAllowed('user-a', 'ws-3'), (err) => {
    assert.equal(err.statusCode, 429);
    assert.equal(err.limit, MAX);
    return true;
  });

  const teammate = await assertContextCreateAllowed('user-b', 'ws-1');
  assert.equal(teammate.used, 1);
  assert.equal(teammate.remaining, MAX - 1);

  const exhausted = await getContextHourState('user-a');
  assert.equal(exhausted.used, MAX);
  assert.equal(exhausted.remaining, 0);
  assert.ok(![...store.keys()].some((key) => key.includes(':workspace:')));
});
