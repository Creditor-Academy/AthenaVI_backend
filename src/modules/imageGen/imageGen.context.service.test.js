const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const SRC = path.resolve(__dirname, '../..');

function stub(relPath, exports) {
  const file = require.resolve(path.join(SRC, relPath));
  require.cache[file] = { id: file, filename: file, loaded: true, exports };
}

const RATE_LIMIT = { limit: 20, used: 1, remaining: 19 };

stub('shared/services/ai/moderation.service.js', { async moderateText() {} });
stub('modules/s3/s3.service.js', {
  async uploadFileToKey() {},
  async getObjectBuffer() {
    return Buffer.from('asset');
  },
  async deleteFile() {},
  async getPresignedGetUrl(key) {
    return `https://signed.example/${key}`;
  },
});
stub('modules/asset/asset.dao.js', { async findAssetById() { return null; } });
stub('modules/imageGen/imageGen.contextRateLimit.service.js', {
  async assertContextCreateAllowed() {
    return RATE_LIMIT;
  },
  async getContextHourState() {
    return RATE_LIMIT;
  },
});
stub('modules/imageGen/imageGen.contextParse.service.js', {
  async parseContextFile(file) {
    return {
      name: file.originalname,
      mimeType: file.mimetype,
      role: 'reference_image',
      extractedText: null,
      imageSummary: 'A red logo',
      truncated: false,
      excerpt: null,
    };
  },
  excerpt: (text) => String(text || ''),
});
stub('modules/imageGen/imageGen.context.dao.js', {
  async createContextWithFiles({ context, files }) {
    return { ...context, createdAt: new Date(), files };
  },
});

const contextService = require('./imageGen.context.service');

test('createContext returns a resolved context with id and preview URLs', async () => {
  const result = await contextService.createContext({
    userId: 'user-1',
    workspace: { id: 'ws-1', type: 'PRIVATE', members: [] },
    files: [{ originalname: 'logo.png', mimetype: 'image/png', buffer: Buffer.from('png') }],
    body: {},
  });

  assert.equal(typeof result.context?.then, 'undefined');
  assert.ok(result.context.id);
  assert.equal(result.context.status, 'READY');
  assert.equal(result.context.previews.images.length, 1);
  assert.match(result.context.previews.images[0].url, /^https:\/\/signed\.example\//);
  assert.deepEqual(result.rateLimit, RATE_LIMIT);
});
