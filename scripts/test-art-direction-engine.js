const assert = require('assert');

const { resolveThemeTokens, contrastRatioCss } = require('../src/modules/presentation/theme.service');
const { resolveSemanticTheme } = require('../src/modules/presentation/artDirection/semanticTheme');
const { resolveTextColor } = require('../src/modules/presentation/artDirection/resolveTextColor');
const { planDeckVisualRhythm } = require('../src/modules/presentation/artDirection/deckVisualRhythm');
const { planDeckImageDistribution } = require('../src/modules/presentation/artDirection/imageDistribution');
const { buildSlideDesignPlan } = require('../src/modules/presentation/artDirection/buildSlideDesignPlan');

function approxGte(value, min, msg) {
  assert.ok(value != null, msg || 'value should not be null');
  assert.ok(value >= min, msg || `expected ${value} >= ${min}`);
}

// 1) semantic theme + resolveTextColor should return token-based colors and roles.
{
  const themeTokens = resolveThemeTokens({ themeId: 'clean_light' });
  const theme = resolveSemanticTheme(themeTokens);
  assert.ok(theme?.colors?.heading, 'theme should include semantic heading color');

  const heading = resolveTextColor({
    theme,
    textRole: 'heading',
    backgroundMode: 'light',
    backgroundHex: '#FFFFFF',
  });
  assert.strictEqual(heading.colorRole, 'text', 'heading should map to element colorRole "text"');
  approxGte(contrastRatioCss(heading.color, '#FFFFFF'), 4.5, 'heading should have readable contrast');

  const body = resolveTextColor({
    theme,
    textRole: 'body',
    backgroundMode: 'light',
    backgroundHex: '#FFFFFF',
  });
  assert.strictEqual(body.colorRole, 'muted', 'body should map to element colorRole "muted"');
  approxGte(contrastRatioCss(body.color, '#FFFFFF'), 4.5, 'body should have readable contrast');
}

// 2) rgba contrast math should not crash (and should yield a number).
{
  const ratio = contrastRatioCss('rgba(255,255,255,0.85)', '#FFFFFF');
  assert.ok(ratio == null || typeof ratio === 'number', 'ratio should parse (may be low)');
}

// 3) deck rhythm and image strategy schedule are deterministic.
{
  const rhythm = planDeckVisualRhythm({ slideCount: 10 });
  assert.strictEqual(rhythm.length, 10, 'should produce one rhythm entry per slide');
  assert.strictEqual(rhythm[0].imageUsage, 'required', 'cover should be image-required');
  assert.strictEqual(rhythm[9].imageUsage, 'preferred', 'closing should be preferred');

  const stratByOrder = planDeckImageDistribution({ visualRhythm: rhythm });
  assert.deepStrictEqual(Object.keys(stratByOrder).map(Number).sort((a, b) => a - b), [1,2,3,4,5,6,7,8,9,10], 'should create usage entries for orders 1..N');
}

// 4) cover slide plan should select image backgroundStyle.
{
  const ctx = { visualRhythm: [{ role: 'hero', imageUsage: 'required' }], themeTokens: {} };
  const plan = buildSlideDesignPlan({ ctx, slide: { order: 1 }, outlineSlide: {} });
  assert.strictEqual(plan.visualRole, 'cover', 'hero rhythm role should map to visualRole cover');
  assert.strictEqual(plan.designTokens.backgroundStyle, 'image', 'cover should use image backgroundStyle');
}

// 5) sticky brand + light appearance on visual role uses solid background.
{
  const { resolveStickyBrandColors } = require('../src/modules/presentation/artDirection/semanticTheme');
  const { designTokensForVisualRole } = require('../src/modules/presentation/artDirection/visualTreatment');
  const tokens = resolveThemeTokens({ themeId: 'clean_light' });
  const brand = resolveStickyBrandColors(tokens);
  assert.strictEqual(brand.appearance, 'light');
  assert.ok(brand.primary && brand.secondary, 'sticky brand must expose primary and secondary');
  const visual = designTokensForVisualRole({ visualRole: 'visual', appearance: 'light' });
  assert.strictEqual(visual.backgroundStyle, 'solid');
}

console.log('ok: art-direction engine deterministic checks');

