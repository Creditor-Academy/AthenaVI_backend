const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const sharp = require('sharp');
const { PDFDocument } = require('pdf-lib');

const SRC = path.resolve(__dirname, '../..');

function stub(relPath, exports) {
  const file = require.resolve(path.join(SRC, relPath));
  require.cache[file] = { id: file, filename: file, loaded: true, exports };
}

const db = { generations: new Map(), threads: new Map(), messages: [], charges: [], objects: new Map() };
const calls = { chat: [], generate: [], edit: [] };

function specFor(user) {
  return {
    headline: 'Athena Learning Summit 2026',
    subheadline: 'Two days of hands-on AI teaching workshops',
    details: ['14-15 November 2026', 'Bengaluru International Centre', 'athenavi.com/summit'],
    cta: 'Register today',
    visualSubject: 'Abstract geometric shapes suggesting connected learners',
    composition: user.includes('Current PrintSpec') ? 'patched layout' : 'headline top third',
  };
}

async function png(width, height) {
  return sharp({
    create: { width, height, channels: 3, background: { r: 30, g: 90, b: 200 } },
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
  async generateForModel({ model, prompt, size, aspectRatio, imageSize }) {
    calls.generate.push({ model: model.id, prompt, size, aspectRatio, imageSize });
    const [w, h] = aspectDims(aspectRatio, size);
    return { buffer: await png(w, h), revised_prompt: null };
  },
  async editForModel({ model, imageBuffer, instruction, size, aspectRatio, imageSize }) {
    const meta = await sharp(imageBuffer).metadata();
    calls.edit.push({
      model: model.id,
      instruction,
      size,
      aspectRatio,
      imageSize,
      input: [meta.width, meta.height],
    });
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
  async getObjectBuffer(key) {
    if (!db.objects.has(key)) throw new Error(`missing object ${key}`);
    return db.objects.get(key);
  },
  async uploadFileToKey(buffer, key) {
    db.objects.set(key, buffer);
    return key;
  },
  async streamObjectToResponse() {},
});
stub('modules/asset/asset.service.js', {
  async persistWorkspaceAsset({ buffer, name, stockMetadata }) {
    const key = `asset-key-${db.objects.size + 1}`;
    db.objects.set(key, buffer);
    return { id: `asset-${db.objects.size}`, key, url: `https://cdn/${key}`, name, stockMetadata };
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
const { buildDownloadPayload } = require('./imageGenExport.service');
const { FORMAT_BY_ID, PRINT_FORMAT_IDS, bleedCanvasFor } = require('./catalogs/formats');

const workspace = { id: 'ws-1', type: 'PRIVATE' };
const userId = 'user-1';

async function meta(key) {
  return sharp(db.objects.get(key)).metadata();
}

function generatePrintable(formatId, extra = {}) {
  return service.generate({
    userId,
    workspace,
    body: { mode: 'printable', folderId: 'folder-1', formatId, prompt: 'Summit poster', ...extra },
  });
}

function download(generationId, format, bleed = false) {
  const row = db.generations.get(generationId);
  return buildDownloadPayload({
    s3Key: row.s3Key,
    format,
    filenameBase: 'summit',
    generation: row,
    bleed,
  });
}

test('printable generate: trim asset at DPI, bleed master stored, printable charge', async () => {
  const { generation: g, thread } = await generatePrintable('poster-a4-portrait');

  assert.equal(g.mode, 'printable');
  assert.equal(g.modelId, 'gemini-3-pro-image');
  assert.equal(g.platform, null);
  assert.equal(g.printSpec.headline, 'Athena Learning Summit 2026');
  assert.equal(g.printSpec.kind, 'poster');

  const trim = await meta(g.s3Key);
  assert.deepEqual([trim.width, trim.height], [2480, 3508]);
  assert.equal(trim.density, 300);

  const row = db.generations.get(g.id);
  const bleed = await meta(row.request.print.bleedKey);
  assert.deepEqual([bleed.width, bleed.height], [2550, 3578]);
  assert.equal(bleed.density, 300);
  assert.match(row.request.print.bleedKey, new RegExp(`print-bleed/${g.id}\\.png$`));

  assert.equal(g.print.bleedAvailable, true);
  assert.equal(g.print.bleedKey, undefined, 'bleed key must not leak to clients');
  assert.equal(g.print.dpi, 300);
  assert.equal(g.print.widthMm, 210);
  assert.equal(thread.formatId, 'poster-a4-portrait');

  const charge = db.charges.at(-1);
  assert.equal(charge.feature, 'image_gen_printable');
  assert.equal(charge.amountAc, 12);
  assert.deepEqual(charge.metadata.print, { formatId: 'poster-a4-portrait', dpi: 300 });

  const call = calls.generate.at(-1);
  assert.equal(call.aspectRatio, '3:4');
  assert.equal(call.imageSize, '2K');
  assert.match(call.prompt, /PRINTED TEXT/);
});

test('every print size exports exact trim and bleed pixels on both providers', async () => {
  for (const modelId of ['gemini-3-pro-image', 'gpt-image-1-hd']) {
    for (const formatId of PRINT_FORMAT_IDS) {
      const { generation } = await generatePrintable(formatId, { modelId });
      const f = FORMAT_BY_ID[formatId];
      const canvas = bleedCanvasFor(f);
      const row = db.generations.get(generation.id);
      const trim = await meta(row.s3Key);
      const bleed = await meta(row.request.print.bleedKey);
      assert.deepEqual([trim.width, trim.height], [f.width, f.height], `${modelId} ${formatId} trim`);
      assert.deepEqual([bleed.width, bleed.height], [canvas.width, canvas.height], `${modelId} ${formatId} bleed`);
      assert.equal(trim.density, f.dpi, `${modelId} ${formatId} dpi`);
    }
  }
  const openai = calls.generate.filter((c) => c.model === 'gpt-image-1-hd');
  assert.ok(openai.every((c) => c.imageSize === undefined), 'OpenAI calls get no imageSize');
});

test('business card copy is clamped to the card limits', async () => {
  const { generation } = await generatePrintable('business-card');
  assert.equal(generation.printSpec.cta, '');
  assert.ok(generation.printSpec.details.length <= 4);
  assert.ok(generation.request.warnings.some((w) => /call to action/i.test(w)));
});

test('printable regenerate keeps the size, reuses the spec, rejects a size change', async () => {
  const { generation: parent } = await generatePrintable('poster-a3-landscape');
  const chatsBefore = calls.chat.length;

  const re = await service.regenerate({
    userId,
    workspace,
    generationId: parent.id,
    body: { modelId: 'gpt-image-1-hd' },
  });
  assert.equal(calls.chat.length, chatsBefore, 'model-only regenerate must not call the spec LLM');
  assert.equal(re.generation.formatId, 'poster-a3-landscape');
  assert.deepEqual(re.generation.printSpec, parent.printSpec);
  assert.ok(re.generation.print.bleedAvailable);

  await assert.rejects(
    service.regenerate({ userId, workspace, generationId: parent.id, body: { formatId: 'poster-a2-landscape' } }),
    (err) => err.statusCode === 400 && /locked to one size/i.test(err.message)
  );
});

test('printable chat: spec patch re-renders, pixel edit runs on the bleed master', async () => {
  const { generation: parent, thread } = await generatePrintable('invitation-a6-portrait');

  const specHop = await service.sendThreadMessage({
    userId,
    workspace,
    threadId: thread.id,
    content: 'Change the date to 16 November 2026',
  });
  assert.equal(specHop.generation.mode, 'printable');
  assert.equal(specHop.generation.formatId, 'invitation-a6-portrait');
  assert.equal(specHop.generation.printSpec.composition, 'patched layout');
  assert.equal(db.charges.at(-1).feature, 'image_gen_printable');

  const specRow = db.generations.get(specHop.generation.id);
  const pixelHop = await service.sendThreadMessage({
    userId,
    workspace,
    threadId: thread.id,
    content: 'make the background darker',
  });
  const edit = calls.edit.at(-1);
  const pixelRow = db.generations.get(pixelHop.generation.id);

  assert.equal(pixelHop.generation.request.pixelEdited, true);
  assert.deepEqual(pixelHop.generation.printSpec, specHop.generation.printSpec);
  assert.equal(edit.imageSize, '2K');
  assert.match(edit.instruction, /printed word/);

  const [inW, inH] = edit.input;
  const [outW, outH] = aspectDims(edit.aspectRatio, edit.size);
  assert.ok(
    Math.abs(inW / inH - outW / outH) < 0.02,
    `pixel-edit source ${inW}x${inH} must match the provider canvas ${outW}x${outH}`
  );
  const bleedMaster = await meta(specRow.request.print.bleedKey);
  assert.ok(Math.max(inW, inH) >= Math.max(bleedMaster.width, bleedMaster.height), 'source is the bleed master');

  const trim = await meta(pixelRow.s3Key);
  const bleed = await meta(pixelRow.request.print.bleedKey);
  assert.deepEqual([trim.width, trim.height], [1240, 1748]);
  assert.deepEqual([bleed.width, bleed.height], [1310, 1818]);
  assert.notEqual(pixelRow.request.print.bleedKey, specRow.request.print.bleedKey);
  assert.equal(db.threads.get(thread.id).formatId, 'invitation-a6-portrait');
  assert.notEqual(parent.id, pixelHop.generation.id);
});

test('print downloads: physical PDF, bleed PDF with boxes, DPI on JPG', async () => {
  const { generation } = await generatePrintable('poster-a4-portrait');

  const pdf = await download(generation.id, 'pdf');
  const doc = await PDFDocument.load(pdf.buffer);
  const page = doc.getPage(0);
  const { width, height } = page.getSize();
  assert.ok(Math.abs(width - 595.28) < 0.05, `A4 width ${width}`);
  assert.ok(Math.abs(height - 841.89) < 0.05, `A4 height ${height}`);

  const bleedPdf = await download(generation.id, 'pdf', true);
  assert.match(bleedPdf.filename, /_bleed\.pdf$/);
  const bleedPage = (await PDFDocument.load(bleedPdf.buffer)).getPage(0);
  const size = bleedPage.getSize();
  const bleedPt = (35 / 300) * 72;
  const marginPt = (10 / 25.4) * 72;
  assert.ok(Math.abs(size.width - (595.28 + 2 * bleedPt + 2 * marginPt)) < 0.1);
  const trimBox = bleedPage.getTrimBox();
  assert.ok(Math.abs(trimBox.width - 595.28) < 0.05);
  assert.ok(Math.abs(trimBox.x - (marginPt + bleedPt)) < 0.05);
  const bleedBox = bleedPage.getBleedBox();
  assert.ok(Math.abs(bleedBox.width - (595.28 + 2 * bleedPt)) < 0.05);

  const jpg = await download(generation.id, 'jpg');
  assert.equal((await sharp(jpg.buffer).metadata()).density, 300);

  await assert.rejects(download(generation.id, 'png', true), (err) => err.statusCode === 400);
});

test('bleed download is rejected for non-printable generations; image PDF unchanged', async () => {
  const { generation } = await service.generate({
    userId,
    workspace,
    body: { mode: 'image', folderId: 'folder-1', formatId: 'landscape', prompt: 'A lake at dawn' },
  });
  await assert.rejects(download(generation.id, 'pdf', true), (err) => err.statusCode === 400);

  const row = db.generations.get(generation.id);
  const pdf = await download(generation.id, 'pdf');
  const { width, height } = (await PDFDocument.load(pdf.buffer)).getPage(0).getSize();
  assert.deepEqual([Math.round(width), Math.round(height)], [row.exportWidth, row.exportHeight]);
});

test('printable without formatId is rejected; list and estimate see printable', async () => {
  await assert.rejects(
    service.generate({
      userId,
      workspace,
      body: { mode: 'printable', folderId: 'folder-1', prompt: 'Poster' },
    }),
    (err) => err.statusCode === 400 && /formatId/.test(err.message)
  );

  const list = await service.listGenerations({ userId, workspace, query: { mode: 'printable' } });
  const rows = list.generations || list.items || list;
  assert.ok(rows.length > 0 && rows.every((g) => g.mode === 'printable'));

  const estimate = service.creditEstimate({ mode: 'printable', modelId: 'gemini-3-pro-image' });
  assert.equal(estimate.breakdown.feature, 'image_gen_printable');
});
