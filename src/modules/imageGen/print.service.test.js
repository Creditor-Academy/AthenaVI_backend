const test = require('node:test');
const assert = require('node:assert/strict');

const {
  FORMAT_BY_ID,
  PRINT_FORMAT_IDS,
  listFormats,
  isFormatForMode,
  defaultFormatIdForMode,
  openaiSizeForFormat,
  geminiImageConfigForFormat,
  bleedCanvasFor,
  mmToPx,
} = require('./catalogs/formats');
const { modelCatalog, defaultModelIdForMode, estimateCredits } = require('./catalogs/models');
const { generateSchema, downloadSchema } = require('../validations/imageGen.validations');
const { validatePrintSpec } = require('../validations/printSpec.validations');
const { clampCopy, buildRenderPrompt, buildPixelEditInstruction } = require('./print.service');
const { printGeometry } = require('./prompts/printRender.prompt');
const { classifyEditHeuristic } = require('./prompts/printChat.prompt');
const { IMAGE_GEN_FEATURE, getPrintableAc } = require('../../shared/config/imageGenCreditPricing');

const generateBody = generateSchema.extract('body');

const EXPECTED = {
  'poster-a4-portrait': { trim: [2480, 3508], bleed: [2550, 3578], dpi: 300 },
  'poster-a4-landscape': { trim: [3508, 2480], bleed: [3578, 2550], dpi: 300 },
  'poster-a3-portrait': { trim: [1754, 2480], bleed: [1790, 2516], dpi: 150 },
  'poster-a3-landscape': { trim: [2480, 1754], bleed: [2516, 1790], dpi: 150 },
  'poster-a2-portrait': { trim: [2480, 3508], bleed: [2516, 3544], dpi: 150 },
  'poster-a2-landscape': { trim: [3508, 2480], bleed: [3544, 2516], dpi: 150 },
  'business-card': { trim: [1050, 600], bleed: [1126, 676], dpi: 300 },
  'invitation-a6-portrait': { trim: [1240, 1748], bleed: [1310, 1818], dpi: 300 },
};

function sampleSpec(overrides = {}) {
  return {
    headline: 'Athena Learning Summit 2026',
    subheadline: 'Two days of hands-on AI teaching workshops',
    details: ['14-15 November 2026', 'Bengaluru International Centre', 'athenavi.com/summit'],
    cta: 'Register today',
    visualSubject: 'Abstract geometric shapes suggesting connected learners',
    composition: 'headline top third, details bottom band',
    ...overrides,
  };
}

test('print catalog: eight sizes with exact trim and bleed pixels', () => {
  assert.deepEqual([...PRINT_FORMAT_IDS].sort(), Object.keys(EXPECTED).sort());
  for (const [id, want] of Object.entries(EXPECTED)) {
    const f = FORMAT_BY_ID[id];
    assert.equal(f.category, 'print', id);
    assert.deepEqual(f.modes, ['printable'], id);
    assert.equal(f.dpi, want.dpi, id);
    assert.deepEqual([f.width, f.height], want.trim, id);
    const canvas = bleedCanvasFor(f);
    assert.deepEqual([canvas.width, canvas.height], want.bleed, id);
    assert.equal(canvas.width - f.width, canvas.offsetX * 2, `${id} bleed is symmetric`);
    assert.ok(isFormatForMode(f, 'printable'));
    assert.ok(!isFormatForMode(f, 'social'));
  }
  assert.equal(mmToPx(210, 300), 2480);
  assert.equal(defaultFormatIdForMode('printable'), null);
});

test('print formats expose physical info in the catalog', () => {
  const card = listFormats().find((f) => f.id === 'business-card');
  assert.equal(card.print.kind, 'business_card');
  assert.equal(card.print.widthIn, 3.5);
  assert.equal(card.print.heightIn, 2);
  assert.equal(card.print.dpi, 300);
  assert.equal(card.print.bleedWidth, 1126);

  const a3 = listFormats().find((f) => f.id === 'poster-a3-landscape');
  assert.equal(a3.print.widthMm, 420);
  assert.equal(a3.print.heightMm, 297);
  assert.equal(a3.print.orientation, 'landscape');
  assert.equal(a3.platform, null);
});

test('provider sizing picks the nearest aspect and 2K Gemini for print', () => {
  const gemini = { provider: 'gemini', maxImageSize: '4K' };
  assert.equal(geminiImageConfigForFormat(FORMAT_BY_ID['poster-a4-portrait'], gemini).aspectRatio, '3:4');
  assert.equal(geminiImageConfigForFormat(FORMAT_BY_ID['poster-a2-landscape'], gemini).aspectRatio, '4:3');
  assert.equal(geminiImageConfigForFormat(FORMAT_BY_ID['business-card'], gemini).aspectRatio, '16:9');
  assert.equal(geminiImageConfigForFormat(FORMAT_BY_ID['invitation-a6-portrait'], gemini).imageSize, '2K');
  assert.equal(openaiSizeForFormat(FORMAT_BY_ID['poster-a4-portrait'], 'gpt-image-1'), '1024x1536');
  assert.equal(openaiSizeForFormat(FORMAT_BY_ID['business-card'], 'gpt-image-1'), '1536x1024');
});

test('printable defaults match social: Gemini Pro, no recommended badge', () => {
  assert.equal(defaultModelIdForMode('printable'), 'gemini-3-pro-image');
  const catalog = modelCatalog('printable');
  const defaults = catalog.defaults || catalog.modeDefault || catalog;
  const serialized = JSON.stringify(defaults);
  assert.match(serialized, /gemini-3-pro-image/);
  assert.equal(IMAGE_GEN_FEATURE.PRINTABLE, 'image_gen_printable');
  assert.equal(getPrintableAc('gemini-3-pro-image'), 12);
  const estimate = estimateCredits({ modelId: 'gemini-3-pro-image', mode: 'printable', isTweak: false });
  assert.equal(estimate.breakdown.feature, 'image_gen_printable');
  assert.equal(estimate.athenaCredits, 12);
});

test('generate validation: printable requires a print formatId', () => {
  const base = { folderId: '00000000-0000-4000-8000-000000000001', prompt: 'Summit poster' };
  assert.ok(generateBody.validate({ ...base, mode: 'printable' }).error);
  assert.ok(generateBody.validate({ ...base, mode: 'printable', formatId: 'instagram-post' }).error);
  assert.ok(generateBody.validate({ ...base, mode: 'social', formatId: 'business-card' }).error);
  assert.equal(
    generateBody.validate({ ...base, mode: 'printable', formatId: 'poster-a3-portrait' }).error,
    undefined
  );

  const query = downloadSchema.extract('query');
  assert.equal(query.validate({ format: 'pdf', bleed: 'true' }).error, undefined);
  assert.ok(query.validate({ format: 'pdf', bleed: 'yes' }).error);
});

test('PrintSpec schema requires headline and visual subject', () => {
  assert.equal(validatePrintSpec(sampleSpec()).error, undefined);
  assert.ok(validatePrintSpec(sampleSpec({ headline: '' })).error);
  assert.ok(validatePrintSpec(sampleSpec({ visualSubject: undefined })).error);
  assert.ok(validatePrintSpec(sampleSpec({ details: new Array(9).fill('x') })).error);
});

test('clampCopy fits a business card: no CTA, four detail lines, short lines', () => {
  const card = FORMAT_BY_ID['business-card'];
  const { spec, warnings } = clampCopy(
    sampleSpec({
      headline: 'Priya Raman',
      subheadline: 'Head of Learning',
      details: [
        '+91 98450 12345',
        'priya@athenavi.com',
        'athenavi.com',
        'Level 4, Prestige Tech Park, Outer Ring Road, Marathahalli, Bengaluru',
        'extra line',
      ],
    }),
    card
  );
  assert.equal(spec.cta, '');
  assert.equal(spec.details.length, 4);
  assert.ok(spec.details.every((line) => line.length <= card.textLimits.detailLine));
  assert.equal(spec.formatId, 'business-card');
  assert.equal(spec.kind, 'business_card');
  assert.ok(warnings.length >= 3);
});

test('render prompt: flat artwork, bleed geometry, exact copy', () => {
  const format = FORMAT_BY_ID['poster-a4-portrait'];
  const spec = clampCopy(sampleSpec(), format).spec;
  const prompt = buildRenderPrompt({ spec, format, sizing: { size: '1024x1536' } });
  assert.match(prompt, /2550x3578 px at 300 DPI/);
  assert.match(prompt, /NOT a photo or mockup/);
  assert.match(prompt, /crop marks/);
  assert.match(prompt, /Headline \(exact\): "Athena Learning Summit 2026"/);
  assert.match(prompt, /Detail line 3 \(exact\): "athenavi.com\/summit"/);
  assert.match(prompt, /Call to action \(exact\)|CTA \(exact\)/);
});

test('print geometry scales trim and safe boxes to the provider canvas', () => {
  const card = FORMAT_BY_ID['business-card'];
  const onBleed = printGeometry(card);
  const onOpenAi = printGeometry(card, 1.5);
  assert.equal(onBleed.trim.height, 89);
  assert.ok(onOpenAi.trim.height < onBleed.trim.height, '3:2 canvas loses height to the crop');
  assert.ok(onOpenAi.safe.width < onOpenAi.trim.width);
  assert.ok(onOpenAi.safe.height < onOpenAi.trim.height);
});

test('pixel edit instruction protects printed text and blurred padding', () => {
  const text = buildPixelEditInstruction({ instruction: 'make the background navy', spec: sampleSpec() });
  assert.match(text, /make the background navy/);
  assert.match(text, /printed word/);
  assert.match(text, /Athena Learning Summit 2026/);
  assert.match(text, /blurred outer border/);
});

test('edit heuristic routes copy edits to spec and visual edits to pixel', () => {
  assert.equal(classifyEditHeuristic('Change the date to 16 November'), 'spec');
  assert.equal(classifyEditHeuristic('update the phone number'), 'spec');
  assert.equal(classifyEditHeuristic('make the background darker'), 'pixel');
});
