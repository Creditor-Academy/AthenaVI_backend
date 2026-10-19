const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const sharp = require('sharp');

const SRC = path.resolve(__dirname, '../..');

function stub(relPath, exports) {
  const file = require.resolve(path.join(SRC, relPath));
  require.cache[file] = { id: file, filename: file, loaded: true, exports };
}

const db = { generations: new Map(), threads: new Map(), messages: [], charges: [], assets: new Map() };
const calls = { chat: [], generate: [], edit: [] };
let nextSpec = null;

function specFor(user) {
  if (nextSpec) return nextSpec;
  return {
    headline: 'Launch your AI course in one weekend with Athena studio',
    supportingText: 'Avatars, voiceovers, and templates in a single place for busy teams',
    cta: 'Start your free trial today',
    visualSubject: 'Instructor beside a glowing laptop',
    composition: user.includes('Current SocialPostSpec') ? 'patched layout' : 'subject right, text left',
  };
}

async function png(width, height) {
  return sharp({
    create: { width, height, channels: 3, background: { r: 200, g: 30, b: 30 } },
  })
    .png()
    .toBuffer();
}

function aspectDims(aspectRatio, size) {
  if (aspectRatio) {
    const [w, h] = aspectRatio.split(':').map(Number);
    return [Math.round(1024 * (w / h)), 1024];
  }
  return size.split('x').map(Number);
}

stub('shared/services/ai/index.js', {
  DEFAULT_SLIDE_MODEL: 'test-model',
  async chatJson({ system, user }) {
    calls.chat.push({ system, user });
    if (String(system).includes('editMode') || String(user).startsWith('Instruction:')) {
      return { data: { editMode: 'spec' } };
    }
    return { data: specFor(user), usage: null };
  },
  async generateForModel({ model, prompt, size, aspectRatio }) {
    calls.generate.push({ model: model.id, prompt, size, aspectRatio });
    const [w, h] = aspectDims(aspectRatio, size);
    return { buffer: await png(w, h), revised_prompt: null };
  },
  async editForModel({ model, imageBuffer, instruction, size, aspectRatio }) {
    const meta = await sharp(imageBuffer).metadata();
    calls.edit.push({ model: model.id, instruction, size, aspectRatio, input: [meta.width, meta.height] });
    const [w, h] = aspectDims(aspectRatio, size);
    return { buffer: await sharp(imageBuffer).resize(w, h, { fit: 'fill' }).png().toBuffer() };
  },
});
stub('shared/services/ai/moderation.service.js', { async moderateText() {} });
stub('shared/config/prismaClient.js', {
  folder: { async findFirst() { return { id: 'folder-1' }; } },
  imageGeneration: {
    async update({ where, data }) {
      Object.assign(db.generations.get(where.id), data);
    },
  },
});
stub('modules/s3/s3.service.js', {
  async getObjectBuffer(key) { return db.assets.get(key); },
  async streamObjectToResponse() {},
});
stub('modules/asset/asset.service.js', {
  async persistWorkspaceAsset({ buffer, name, stockMetadata }) {
    const key = `key-${db.assets.size + 1}`;
    db.assets.set(key, buffer);
    return { id: `asset-${db.assets.size}`, key, url: `https://cdn/${key}`, name, stockMetadata };
  },
});
stub('modules/project/project.dao.js', {
  async findFolderById(id) { return { id, workspaceId: 'ws-1' }; },
});
stub('modules/imageGen/imageGenCredit.service.js', {
  async assertAfford() {},
  async chargeFlat(args) {
    db.charges.push(args);
    return { pricing: { athenaCredits: args.amountAc } };
  },
});
stub('modules/imageGen/imageGenRateLimit.service.js', {
  async assertGenerateAllowed() {},
  async assertRegenerateAllowed() {},
});
stub('modules/imageGen/imageGen.context.service.js', {
  async resolveForGenerate() { return { referenceImageBuffers: [], enrichmentBlock: '' }; },
  appendContextBlock: (p) => p,
  withReferenceImageIndexHints: (p) => p,
  async pinIfNeeded() {},
});
stub('modules/imageGen/imageGen.dao.js', {
  async createGeneration(row) {
    db.generations.set(row.id, { ...row, createdAt: new Date() });
    return { ...row };
  },
  async findById(id) { return db.generations.get(id) || null; },
  async setThreadId(id, threadId) {
    const row = db.generations.get(id);
    if (row) row.threadId = threadId;
  },
  async listGenerations({ mode }) {
    return [...db.generations.values()].filter((g) => !mode || g.mode === mode);
  },
});
function threadView(id) {
  const t = db.threads.get(id);
  if (!t) return null;
  return { ...t, headGeneration: db.generations.get(t.headGenerationId) || null, messages: [] };
}
stub('modules/imageGen/imageGen.thread.dao.js', {
  async createThread(data) {
    const id = `thread-${db.threads.size + 1}`;
    db.threads.set(id, { id, ...data });
    return { id, ...data };
  },
  async findById(id) { return threadView(id); },
  async findByRootGenerationId(rootId) {
    const t = [...db.threads.values()].find((x) => x.rootGenerationId === rootId);
    return t ? threadView(t.id) : null;
  },
  async updateThread(id, data) {
    Object.assign(db.threads.get(id), data);
    return threadView(id);
  },
});
stub('modules/imageGen/imageGen.message.dao.js', {
  async createMessages(rows) { db.messages.push(...rows); },
  async listUserMessages() { return []; },
});

const service = require('./imageGen.service');

const workspace = { id: 'ws-1', type: 'PRIVATE' };
const userId = 'user-1';

async function exportSize(generation) {
  const meta = await sharp(db.assets.get(generation.s3Key)).metadata();
  return [meta.width, meta.height];
}

test('social generate: exact pixels, clamped copy, social charge, serialized platform', async () => {
  const result = await service.generate({
    userId,
    workspace,
    body: {
      mode: 'social',
      folderId: 'folder-1',
      formatId: 'youtube-thumbnail',
      prompt: 'Thumbnail for a course launch video',
    },
  });

  const g = result.generation;
  assert.equal(g.mode, 'social');
  assert.equal(g.modelId, 'gemini-3-pro-image');
  assert.equal(g.platform, 'youtube');
  assert.deepEqual(await exportSize(db.generations.get(g.id)), [1280, 720]);
  assert.ok(g.socialSpec.headline.length <= 40);
  assert.equal(g.socialSpec.supportingText, '');
  assert.equal(g.socialSpec.cta, '');
  assert.ok(g.request.warnings.length >= 1);
  assert.equal(result.thread.platform, 'youtube');
  assert.equal(result.thread.head.platform, 'youtube');

  const charge = db.charges.at(-1);
  assert.equal(charge.feature, 'image_gen_social');
  assert.equal(charge.amountAc, 12);
  assert.equal(charge.metadata.platform, 'youtube');
  assert.equal(calls.generate.at(-1).aspectRatio, '16:9');
});

test('every destination exports at exact pixels on both providers', async () => {
  const ids = [
    'youtube-thumbnail',
    'instagram-post',
    'facebook-post',
    'facebook-cover',
    'youtube-banner',
    'twitter-post',
    'linkedin-banner',
  ];
  const { FORMAT_BY_ID } = require('./catalogs/formats');
  for (const modelId of ['gemini-3-pro-image', 'gpt-image-1-hd']) {
    for (const formatId of ids) {
      const { generation } = await service.generate({
        userId,
        workspace,
        body: { mode: 'social', folderId: 'folder-1', formatId, modelId, prompt: 'Launch post' },
      });
      const f = FORMAT_BY_ID[formatId];
      assert.deepEqual(
        await exportSize(db.generations.get(generation.id)),
        [f.width, f.height],
        `${modelId} ${formatId}`
      );
    }
  }
});

test('image and infographic defaults moved to HD OpenAI and Gemini Pro', async () => {
  const image = await service.generate({
    userId,
    workspace,
    body: { mode: 'image', folderId: 'folder-1', prompt: 'A lake at dawn' },
  });
  assert.equal(image.generation.modelId, 'gpt-image-1-hd');
  assert.equal(image.generation.formatId, 'square');
});

test('social regenerate keeps destination, reuses spec, rejects destination change', async () => {
  const { generation: parent } = await service.generate({
    userId,
    workspace,
    body: { mode: 'social', folderId: 'folder-1', formatId: 'linkedin-banner', prompt: 'Banner' },
  });
  const chatsBefore = calls.chat.length;

  const re = await service.regenerate({
    userId,
    workspace,
    generationId: parent.id,
    body: { modelId: 'gpt-image-1-hd' },
  });
  assert.equal(calls.chat.length, chatsBefore, 'model-only regenerate must not call the spec LLM');
  assert.equal(re.generation.formatId, 'linkedin-banner');
  assert.deepEqual(re.generation.socialSpec, parent.socialSpec);
  assert.equal(re.thread.id, db.generations.get(parent.id).threadId);

  await service.regenerate({
    userId,
    workspace,
    generationId: parent.id,
    body: { prompt: 'A different banner idea' },
  });
  assert.equal(calls.chat.length, chatsBefore + 1, 'new prompt rebuilds the spec');

  await assert.rejects(
    service.regenerate({ userId, workspace, generationId: parent.id, body: { formatId: 'twitter-post' } }),
    (err) => err.statusCode === 400 && /locked/i.test(err.message)
  );
  await assert.rejects(
    service.regenerate({ userId, workspace, generationId: parent.id, body: { mode: 'image' } }),
    (err) => err.statusCode === 400
  );
});

test('social chat: copy edits patch the spec, visual edits pixel-edit at the same size', async () => {
  const { generation: parent, thread } = await service.generate({
    userId,
    workspace,
    body: { mode: 'social', folderId: 'folder-1', formatId: 'facebook-cover', prompt: 'Cover' },
  });

  const specHop = await service.sendThreadMessage({
    userId,
    workspace,
    threadId: thread.id,
    content: 'Change the headline to "Go live today"',
  });
  assert.equal(specHop.generation.mode, 'social');
  assert.equal(specHop.generation.formatId, 'facebook-cover');
  assert.equal(specHop.generation.request.pixelEdited, undefined);
  assert.equal(specHop.generation.socialSpec.composition, 'patched layout');
  assert.equal(db.charges.at(-1).feature, 'image_gen_social');

  const pixelHop = await service.sendThreadMessage({
    userId,
    workspace,
    threadId: thread.id,
    content: 'make the background darker',
  });
  const edit = calls.edit.at(-1);
  assert.equal(pixelHop.generation.request.pixelEdited, true);
  assert.deepEqual(pixelHop.generation.socialSpec, specHop.generation.socialSpec);
  assert.deepEqual(await exportSize(db.generations.get(pixelHop.generation.id)), [851, 315]);
  assert.equal(db.charges.at(-1).feature, 'image_gen_social');
  assert.equal(db.charges.at(-1).amountAc, 12);

  const [inW, inH] = edit.input;
  const [outW, outH] = aspectDims(edit.aspectRatio, edit.size);
  assert.ok(
    Math.abs(inW / inH - outW / outH) < 0.02,
    `pixel-edit source ${inW}x${inH} must match the provider canvas ${outW}x${outH}`
  );
  assert.match(edit.instruction, /text/i, 'pixel edit must protect the on-image copy');

  assert.equal(db.threads.get(thread.id).formatId, 'facebook-cover');
  assert.notEqual(parent.id, pixelHop.generation.id);
});

test('padToAspect + cover crop round-trips the original banner pixels', async () => {
  const { padToAspect, cropToFormat } = require('./socialCrop.service');
  const left = await png(792, 396);
  const banner = await sharp({
    create: { width: 1584, height: 396, channels: 3, background: { r: 20, g: 40, b: 220 } },
  })
    .composite([{ input: left, left: 0, top: 0 }])
    .png()
    .toBuffer();

  const padded = await padToAspect(banner, 1.5);
  const meta = await sharp(padded).metadata();
  assert.ok(Math.abs(meta.width / meta.height - 1.5) < 0.01);

  const back = await cropToFormat(padded, { width: 1584, height: 396 });
  const original = await sharp(banner).removeAlpha().raw().toBuffer();
  const restored = await sharp(back.buffer).removeAlpha().raw().toBuffer();
  assert.equal(restored.length, original.length);
  let maxDiff = 0;
  for (let i = 0; i < original.length; i += 997) {
    maxDiff = Math.max(maxDiff, Math.abs(original[i] - restored[i]));
  }
  assert.ok(maxDiff <= 8, `restored banner drifted by ${maxDiff}`);
});

test('listGenerations filters social and estimate prices social', async () => {
  const list = await service.listGenerations({ userId, workspace, query: { mode: 'social' } });
  const rows = list.generations || list.items || list;
  assert.ok(Array.isArray(rows) && rows.length > 0);
  assert.ok(rows.every((g) => g.mode === 'social'));

  const estimate = service.creditEstimate({ mode: 'social', modelId: 'gemini-3.1-flash-image' });
  assert.equal(estimate.breakdown.feature, 'image_gen_social');
  assert.equal(estimate.athenaCredits, 8);
});
