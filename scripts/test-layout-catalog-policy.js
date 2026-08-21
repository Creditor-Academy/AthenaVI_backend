/**
 * Unit checks for blueprint layout catalog policy.
 * Run: node scripts/test-layout-catalog-policy.js
 */
const assert = require('assert');
const path = require('path');

const seed = require('../src/modules/presentation/templates/seed-layouts.json');
const policy = require('../src/modules/presentation/layoutCatalogPolicy');

const templates = seed.map((t) => ({
  id: t.schema?.layout_id || t.variant,
  name: t.name,
  contentType: t.contentType,
  variant: t.variant,
  schema: t.schema,
}));

function ids(metas) {
  return new Set(metas.map((m) => m.layoutId));
}

const para = templates.find((t) => /three_para|two_para/.test(t.schema?.layout_id || ''));
assert.ok(para, 'seed has a multi-para layout');
const paraMeta = policy.deriveLayoutMeta(para);
assert.ok(
  !paraMeta.densityFit.includes('concise') || policy.PARA_DENSE_RE.test(paraMeta.layoutId),
  'multi-para is dense'
);

const concise = policy.filterLayoutTemplates(templates, { density: 'concise', imageType: 'ai' });
assert.ok(
  ![...ids(concise)].some((id) => policy.PARA_DENSE_RE.test(id)),
  'concise density bans two/three/four para'
);

const none = policy.filterLayoutTemplates(templates, { density: 'balanced', imageType: 'none' });
assert.ok(
  none.every((m) => m.imageSlotCount === 0),
  'imageType=none excludes image slots'
);

const watercolor = policy.filterLayoutTemplates(templates, {
  density: 'balanced',
  imageType: 'ai',
  imageStyle: 'watercolor',
});
const waterIds = [...ids(watercolor)];
assert.ok(
  waterIds.some((id) => policy.GALLERY_RE.test(id) || /four_images|para_three_images|grid_bento/.test(id)),
  'watercolor prefers gallery layouts in the pool'
);

const infographic = policy.filterLayoutTemplates(templates, {
  density: 'balanced',
  imageType: 'ai',
  imageStyle: 'infographic',
});
assert.ok(
  infographic.some((m) => m.imageStyleFamilies.includes('infographic') || m.contentType === 'diagram'),
  'infographic style keeps diagram/infographic families'
);

const packSkip = policy.filterLayoutTemplates(templates, {
  density: 'balanced',
  imageType: 'ai',
  allowCharts: false,
  allowDevices: false,
});
assert.ok(packSkip.every((m) => !m.hasChart), 'pack chart skip removes chart layouts');
assert.ok(packSkip.every((m) => !m.hasDevice), 'pack device skip removes device layouts');

assert.ok(policy.promptLooksQuantitative('Q3 revenue growth and KPI charts'));
assert.ok(!policy.promptLooksQuantitative('A history of tea ceremonies'));

const digest = policy.buildLayoutDigest(concise);
const unknown = policy.coerceOutlineLayouts(
  [
    {
      order: 1,
      title: 'Hello',
      summary: 'Open',
      suggestedContentType: 'title',
      layoutId: 'not_a_real_layout_v9',
    },
  ],
  concise,
  { slideCount: 1 }
);
assert.ok(unknown[0].layoutId, 'unknown layoutId is replaced');
assert.ok(unknown[0].layoutId !== 'not_a_real_layout_v9', 'stripped unknown id');
assert.ok(
  digest.some((row) => row.layoutId === unknown[0].layoutId) ||
    concise.some((m) => m.layoutId === unknown[0].layoutId),
  'replacement is from the filtered catalog'
);

const padded = policy.enforceSlideCount([{ order: 1, title: 'A', summary: 's' }], 5);
assert.strictEqual(padded.length, 5, 'slideCount is honored by padding');
assert.strictEqual(padded[4].suggestedContentType, 'closing');

const dark = policy.appearanceFromPalette({ bg: '#0F1115' });
const light = policy.appearanceFromPalette({ bg: '#FFFFFF' });
assert.strictEqual(dark, 'dark');
assert.strictEqual(light, 'light');

const families = policy.familiesForImageStyle('watercolor', 'Suggested');
assert.ok(families.includes('gallery'));

const largeImage = templates.find((t) => (t.schema?.layout_id || t.variant) === 'large_image_v1');
assert.ok(largeImage, 'seed has large_image_v1');
const largeMeta = policy.deriveLayoutMeta(largeImage);
assert.ok(largeMeta.captionOnly || !largeMeta.hasHeadingSlot, 'large_image is caption-only / no heading');

const cinematic = policy.filterLayoutTemplates(templates, {
  density: 'balanced',
  imageType: 'ai',
  imageStyle: 'cinematic',
});
const coercedHero = policy.coerceOutlineLayouts(
  [
    {
      order: 1,
      title: 'MIST & MUG',
      subtitle: 'Coffee above the ordinary.',
      summary: 'Cover',
      suggestedContentType: 'image+text',
      layoutId: 'large_image_v1',
    },
  ],
  cinematic,
  { slideCount: 1, imageType: 'ai' }
);
assert.ok(coercedHero[0].layoutId !== 'large_image_v1', 'slide 1 cannot stay caption-only');
assert.strictEqual(coercedHero[0].suggestedContentType, 'title');
const heroMeta = cinematic.find((m) => m.layoutId === coercedHero[0].layoutId);
assert.ok(heroMeta && heroMeta.hasHeadingSlot, 'slide 1 layout has a heading slot');
assert.ok(/title_fullbleed|title_hero|title_/.test(coercedHero[0].layoutId), 'slide 1 uses a title_* layout');

const noVisuals = policy.filterLayoutTemplates(templates, {
  density: 'balanced',
  imageType: 'none',
});
const coercedPlain = policy.coerceOutlineLayouts(
  [{ order: 1, title: 'Hello', summary: 'Open', layoutId: 'large_image_v1' }],
  noVisuals,
  { slideCount: 1, imageType: 'none' }
);
assert.ok(coercedPlain[0].layoutId, 'text-only slide 1 still gets a title layout');
const plainMeta = noVisuals.find((m) => m.layoutId === coercedPlain[0].layoutId);
assert.ok(!plainMeta || plainMeta.imageSlotCount === 0, 'visuals off prefers no image slots');

const named = policy.namedPromptPalette(
  'warm sand, espresso brown, cream, misty grey, muted forest green'
);
assert.ok(named && named.bg && named.text, 'named hospitality colors bias the palette');
assert.ok(named.text.toLowerCase() !== '#64748b', 'espresso text is not grey');

console.log('layoutCatalogPolicy tests passed', {
  seed: templates.length,
  concise: concise.length,
  none: none.length,
  watercolor: watercolor.length,
  infographic: infographic.length,
  packSkip: packSkip.length,
});
