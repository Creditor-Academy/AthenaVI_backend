const test = require('node:test');
const assert = require('node:assert/strict');

const {
  FORMAT_BY_ID,
  SOCIAL_FORMAT_IDS,
  listFormats,
  isFormatForMode,
  defaultFormatIdForMode,
  openaiSizeForFormat,
  geminiImageConfigForFormat,
} = require('./catalogs/formats');
const {
  modelCatalog,
  defaultModelIdForMode,
  estimateCredits,
  resolveModel,
} = require('./catalogs/models');
const { generateSchema } = require('../validations/imageGen.validations');
const { validateSocialSpec } = require('../validations/socialSpec.validations');
const { clampCopy, providerAspectFor } = require('./social.service');
const { buildSocialRenderPrompt, visibleRegion } = require('./prompts/socialRender.prompt');
const { classifyEditHeuristic } = require('./prompts/socialChat.prompt');
const { IMAGE_GEN_FEATURE, getSocialAc } = require('../../shared/config/imageGenCreditPricing');

const generateBody = generateSchema.extract('body');

const EXPECTED_SIZES = {
  'youtube-thumbnail': [1280, 720],
  'instagram-post': [1080, 1350],
  'facebook-post': [940, 788],
  'facebook-cover': [851, 315],
  'youtube-banner': [2560, 1440],
  'twitter-post': [1600, 900],
  'linkedin-banner': [1584, 396],
};

function sampleSpec(overrides = {}) {
  return {
    headline: 'Launch your course in a weekend',
    supportingText: 'Templates, avatars, and voiceovers in one studio',
    cta: 'Start free',
    visualSubject: 'Confident instructor beside a glowing laptop',
    ...overrides,
  };
}

test('social catalog has the seven destinations at exact pixel sizes', () => {
  assert.deepEqual([...SOCIAL_FORMAT_IDS].sort(), Object.keys(EXPECTED_SIZES).sort());
  for (const [id, [width, height]] of Object.entries(EXPECTED_SIZES)) {
    const format = FORMAT_BY_ID[id];
    assert.equal(format.width, width, `${id} width`);
    assert.equal(format.height, height, `${id} height`);
    assert.equal(format.category, 'social');
    assert.ok(format.platform, `${id} platform`);
    assert.deepEqual(format.modes, ['social']);
    assert.ok(openaiSizeForFormat(format, 'gpt-image-1'));
    assert.ok(geminiImageConfigForFormat(format).aspectRatio);
  }
});

test('formats are scoped by mode', () => {
  assert.equal(isFormatForMode(FORMAT_BY_ID['youtube-thumbnail'], 'social'), true);
  assert.equal(isFormatForMode(FORMAT_BY_ID['youtube-thumbnail'], 'image'), false);
  assert.equal(isFormatForMode(FORMAT_BY_ID.square, 'social'), false);
  assert.equal(isFormatForMode(FORMAT_BY_ID.square, 'infographic'), true);
  assert.equal(defaultFormatIdForMode('image'), 'square');
  assert.equal(defaultFormatIdForMode('infographic'), 'landscape');
  assert.equal(defaultFormatIdForMode('social'), null);
  const listed = listFormats().find((f) => f.id === 'instagram-post');
  assert.equal(listed.platform, 'instagram');
  assert.deepEqual(listed.modes, ['social']);
});

test('generate validation requires a social format for social mode', () => {
  const base = {
    prompt: 'Promote our new AI course',
    folderId: '00000000-0000-4000-8000-000000000000',
  };

  assert.ok(generateBody.validate({ ...base, mode: 'social' }).error);
  assert.ok(generateBody.validate({ ...base, mode: 'social', formatId: 'square' }).error);
  assert.ok(generateBody.validate({ ...base, mode: 'image', formatId: 'youtube-banner' }).error);
  assert.ok(generateBody.validate({ ...base, mode: 'social', formatId: 'tiktok-post' }).error);

  const ok = generateBody.validate({ ...base, mode: 'social', formatId: 'youtube-thumbnail' });
  assert.equal(ok.error, undefined);
  assert.equal(generateBody.validate({ ...base, mode: 'infographic' }).error, undefined);
});

test('social spec validation requires headline and visual subject', () => {
  assert.equal(validateSocialSpec(sampleSpec()).error, undefined);
  assert.ok(validateSocialSpec(sampleSpec({ headline: '' })).error);
  assert.ok(validateSocialSpec(sampleSpec({ visualSubject: undefined })).error);
  assert.ok(validateSocialSpec(sampleSpec({ palette: ['red'] })).error);
});

test('clampCopy enforces per-destination limits and stamps destination', () => {
  const thumb = FORMAT_BY_ID['youtube-thumbnail'];
  const long = 'Build a complete online course with AI avatars in a single weekend';
  const { spec, warnings } = clampCopy(sampleSpec({ headline: long }), thumb);

  assert.ok(spec.headline.length <= thumb.textLimits.headline);
  assert.ok(long.startsWith(spec.headline));
  assert.equal(spec.supportingText, '');
  assert.equal(spec.cta, '');
  assert.equal(spec.formatId, 'youtube-thumbnail');
  assert.equal(spec.platform, thumb.platform);
  assert.equal(warnings.length, 3);

  const insta = clampCopy(sampleSpec(), FORMAT_BY_ID['instagram-post']);
  assert.equal(insta.warnings.length, 0);
  assert.equal(insta.spec.cta, 'Start free');
});

test('render prompt includes exact copy, safe area, and crop band', () => {
  const banner = FORMAT_BY_ID['youtube-banner'];
  const prompt = buildSocialRenderPrompt({
    spec: clampCopy(sampleSpec(), banner).spec,
    format: banner,
    providerAspect: 16 / 9,
  });
  assert.match(prompt, /2560x1440/);
  assert.match(prompt, /60% of the final width and 29% of the final height/);
  assert.match(prompt, /Headline \(exact\): "Launch your course in a weekend"/);
  assert.doesNotMatch(prompt, /cropped to a centered/);

  const linkedin = FORMAT_BY_ID['linkedin-banner'];
  const aspect = providerAspectFor({ size: '1536x1024' });
  const region = visibleRegion(linkedin, aspect);
  assert.deepEqual(region, { axis: 'height', percent: 38 });
  const cropped = buildSocialRenderPrompt({
    spec: clampCopy(sampleSpec(), linkedin).spec,
    format: linkedin,
    providerAspect: aspect,
  });
  assert.match(cropped, /middle 38% of the canvas height/);

  assert.equal(visibleRegion(FORMAT_BY_ID['instagram-post'], 4 / 5), null);
});

test('edit heuristic routes copy changes to spec and look changes to pixel', () => {
  assert.equal(classifyEditHeuristic('change the headline to "Go live today"'), 'spec');
  assert.equal(classifyEditHeuristic('make the background darker'), 'pixel');
});

test('model picker exposes two providers with three models each and mode defaults', () => {
  const catalog = modelCatalog();
  assert.deepEqual(
    catalog.providers.map((p) => p.id),
    ['openai', 'gemini']
  );
  for (const provider of catalog.providers) {
    assert.equal(provider.modelIds.length, 3, provider.id);
    assert.ok(provider.modelIds.includes(provider.defaultModelId));
  }
  assert.equal(defaultModelIdForMode('image'), 'gpt-image-1-hd');
  assert.equal(defaultModelIdForMode('infographic'), 'gemini-3-pro-image');
  assert.equal(defaultModelIdForMode('social'), 'gemini-3-pro-image');
  assert.equal(defaultModelIdForMode('social', 'dall-e-3'), 'dall-e-3');
  assert.equal(catalog.defaults.image.recommendedProvider, 'openai');
  assert.equal(resolveModel('gpt-image-1-hd').recommended, true);
});

test('social credits use the flat social feature with model fallback and env override', () => {
  const prev = process.env.IMAGE_GEN_SOCIAL_AC;
  try {
    delete process.env.IMAGE_GEN_SOCIAL_AC;
    assert.equal(getSocialAc('gemini-3-pro-image'), 12);
    assert.equal(getSocialAc('gemini-3.1-flash-lite-image'), 4);

    const estimate = estimateCredits({ modelId: 'gemini-3-pro-image', mode: 'social' });
    assert.equal(estimate.breakdown.feature, IMAGE_GEN_FEATURE.SOCIAL);
    assert.equal(estimate.athenaCredits, 12);

    process.env.IMAGE_GEN_SOCIAL_AC = '20';
    assert.equal(getSocialAc('gemini-3.1-flash-lite-image'), 20);
  } finally {
    if (prev === undefined) delete process.env.IMAGE_GEN_SOCIAL_AC;
    else process.env.IMAGE_GEN_SOCIAL_AC = prev;
  }
});
