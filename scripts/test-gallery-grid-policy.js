/**
 * Gallery grid policy regression tests.
 * Run: node scripts/test-gallery-grid-policy.js
 */
const assert = require('assert');
const {
  looksLikeImageLedGallery,
  preferredPureGalleryLayoutId,
  galleryProfileOverrides,
  galleryAdjacentExcludeIds,
  isTextImageGridLayout,
  resolvePureGallerySlidePolicy,
} = require('../src/modules/presentation/galleryGridPolicy.util');
const { ARCHETYPES } = require('../src/modules/presentation/slideArrangementPlan.service');

// Harbor Light-style spaces gallery
const spaces = {
  title: 'Spaces',
  summary: 'Rooms, lobby, spa, and infinity pool',
  beats: ['Ocean-view suite', 'Lobby lounge', 'Spa', 'Infinity pool'],
  visual: 'Four distinct hotel interior and exterior photos',
  contentType: 'grid',
  imageStylePhrase: 'cinematic environmental scene photography',
};
assert.strictEqual(looksLikeImageLedGallery(spaces), true, 'spaces slide is image-led gallery');

// Outline often classifies gallery slides as image+text — still pure gallery
const spacesImageText = { ...spaces, contentType: 'image+text', suggestedContentType: 'image+text' };
assert.strictEqual(
  looksLikeImageLedGallery(spacesImageText),
  true,
  'image+text gallery slide still image-led'
);
const imageTextPolicy = resolvePureGallerySlidePolicy({
  layoutContentType: 'image+text',
  content: spacesImageText,
  outlineSlide: { title: spacesImageText.title, beats: spacesImageText.beats, visual: spacesImageText.visual },
  ctx: { imageStylePhrase: spacesImageText.imageStylePhrase },
});
assert.ok(imageTextPolicy, 'image+text gallery resolves policy');
assert.strictEqual(imageTextPolicy.layoutContentType, 'grid');
assert.strictEqual(imageTextPolicy.preferredLayoutId, 'grid_bento_four_v1');
assert.ok(imageTextPolicy.excludeLayoutIds.includes('grid_text_image_cards_v1'));

assert.strictEqual(
  preferredPureGalleryLayoutId(4),
  'grid_bento_four_v1',
  '4-up gallery prefers bento four'
);

const overrides = galleryProfileOverrides(spaces);
assert.ok(overrides, 'gallery overrides returned');
assert.strictEqual(overrides.imageCount, 4, 'gallery imageCount is 4');
assert.strictEqual(overrides.body, '', 'gallery body suppressed for capacity');

// Feature copy grid should stay text-capable
const featureGrid = {
  title: 'Why choose us',
  summary:
    'Our platform delivers end-to-end automation with detailed feature breakdowns for finance teams who need audit trails and compliance controls across every workflow step.',
  contentType: 'grid',
};
assert.strictEqual(looksLikeImageLedGallery(featureGrid), false, 'feature copy is not pure gallery');

// Standard text+image slide — must keep text slots even with cinematic deck style
const productSlide = {
  title: 'How We Help',
  summary:
    'We partner with teams to transform their workflow through guided onboarding, dedicated support, and measurable outcomes over the first 90 days.',
  bullets: [
    { title: 'Onboarding', body: 'Structured 30-day rollout with dedicated success manager and training.' },
    { title: 'Support', body: '24/7 priority support with SLA-backed response times for enterprise teams.' },
    { title: 'Outcomes', body: 'Quarterly business reviews with ROI tracking and adoption benchmarks.' },
  ],
  contentType: 'image+text',
  suggestedContentType: 'image+text',
  visual: 'Product screenshot with team collaboration',
  imageStylePhrase: 'cinematic environmental scene photography',
};
assert.strictEqual(
  looksLikeImageLedGallery(productSlide),
  false,
  'text+image product slide stays text-capable'
);
assert.strictEqual(
  resolvePureGallerySlidePolicy({
    layoutContentType: 'image+text',
    content: productSlide,
    outlineSlide: productSlide,
    ctx: { imageStylePhrase: productSlide.imageStylePhrase },
  }),
  null,
  'text+image product slide does not resolve pure gallery policy'
);

// Arrangement prefs lead with pure bento (rotation may pick any unused pref)
const generalGrid = ARCHETYPES.general.preferredLayouts.grid;
assert.strictEqual(generalGrid[0], 'grid_bento_four_v1', 'general grid prefs start with bento four');
assert.ok(generalGrid.includes('grid_six_images_v1'), 'six-image bento in prefs');

// Adjacent diversity excludes text+image twins
const exclude = galleryAdjacentExcludeIds('grid_text_image_cards_v1');
assert.ok(exclude.includes('grid_text_image_cards_v1'), 'excludes prior text+image grid');
assert.ok(isTextImageGridLayout('grid_three_images_text_v1'), 'detects text+image grid');

console.log('ok: gallery grid policy', {
  spacesLayout: preferredPureGalleryLayoutId(4),
  generalFirst: generalGrid[0],
  excludeCount: exclude.length,
});
