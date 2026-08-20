const assert = require('assert');

const catalog = require('../src/modules/presentation/themes/catalog.json');
const themeService = require('../src/modules/presentation/theme.service');
const { resolveStickyBrandColors } = require('../src/modules/presentation/artDirection/semanticTheme');
const { designTokensForVisualRole } = require('../src/modules/presentation/artDirection/visualTreatment');
const { validateSlide } = require('../src/modules/presentation/layoutQa.service');
const { textForSlot, layoutSlotsToElements } = require('../src/modules/presentation/layoutToElements');

function approxLum(hex) {
  return themeService.relativeLuminance(hex);
}

// 1) Catalog has 20 themes: 10 light + 10 dark, each with primary/secondary.
{
  assert.strictEqual(catalog.length, 20, `expected 20 catalog themes, got ${catalog.length}`);
  const light = catalog.filter((t) => t.themeTokens?.appearance === 'light');
  const dark = catalog.filter((t) => t.themeTokens?.appearance === 'dark');
  assert.strictEqual(light.length, 10, `expected 10 light themes, got ${light.length}`);
  assert.strictEqual(dark.length, 10, `expected 10 dark themes, got ${dark.length}`);

  for (const theme of catalog) {
    const p = theme.themeTokens?.palette || {};
    assert.ok(p.primary, `${theme.id} missing primary`);
    assert.ok(p.secondary, `${theme.id} missing secondary`);
    assert.ok(p.bg, `${theme.id} missing bg`);
    const appearance = theme.themeTokens.appearance;
    const lum = approxLum(p.bg);
    if (appearance === 'light') {
      assert.ok(lum >= 0.35, `${theme.id} light bg luminance ${lum} should be >= 0.35`);
    } else {
      assert.ok(lum < 0.35, `${theme.id} dark bg luminance ${lum} should be < 0.35`);
    }
  }
}

// 2) enforceAppearancePalette clamps mismatched bg.
{
  const badLight = themeService.enforceAppearancePalette({
    appearance: 'light',
    palette: {
      bg: '#0B1220',
      surface: '#121A2B',
      text: '#0F172A',
      primary: '#2563EB',
      secondary: '#0EA5E9',
    },
  });
  assert.ok(
    themeService.relativeLuminance(badLight.palette.bg) >= 0.35,
    'light appearance must not keep dark bg'
  );

  const badDark = themeService.enforceAppearancePalette({
    appearance: 'dark',
    palette: {
      bg: '#FFFFFF',
      surface: '#F8FAFC',
      text: '#F8FAFC',
      primary: '#3B82F6',
      secondary: '#22D3EE',
    },
  });
  assert.ok(
    themeService.relativeLuminance(badDark.palette.bg) < 0.35,
    'dark appearance must not keep light bg'
  );
}

// 3) Sticky brand colors + light visual treatment defaults to solid (not dark gradient).
{
  const tokens = themeService.resolveThemeTokens({ themeId: 'sky_day' });
  const brand = resolveStickyBrandColors(tokens);
  assert.strictEqual(brand.appearance, 'light');
  assert.strictEqual(brand.primary, tokens.palette.primary);
  assert.strictEqual(brand.secondary, tokens.palette.secondary);

  const visual = designTokensForVisualRole({ visualRole: 'visual', appearance: 'light' });
  assert.strictEqual(visual.backgroundStyle, 'solid', 'light visual role must use solid bg');
}

// 4) Gallery QA flags repeated slide title as labels.
{
  const layoutSchema = {
    layout_id: 'four_images_text_v1',
    slots: [
      { id: 'HEADING', role: 'heading' },
      { id: 'IMAGE_1', role: 'image' },
      { id: 'IMAGE_1_LABEL', role: 'caption' },
      { id: 'IMAGE_2', role: 'image' },
      { id: 'IMAGE_2_LABEL', role: 'caption' },
      { id: 'IMAGE_3', role: 'image' },
      { id: 'IMAGE_3_LABEL', role: 'caption' },
      { id: 'IMAGE_4', role: 'image' },
      { id: 'IMAGE_4_LABEL', role: 'caption' },
    ],
  };
  const qa = validateSlide({
    content: {
      title: 'Azure Cliff Residence',
      columns: [
        { title: 'Azure Cliff Residence', body: 'Ocean views and terraces' },
        { title: 'Azure Cliff Residence', body: 'Private wellness suites' },
        { title: 'Azure Cliff Residence', body: 'Concierge dining' },
        { title: 'Azure Cliff Residence', body: 'Infinity pool decks' },
      ],
    },
    layoutSchema,
  });
  const rules = (qa.issues || []).map((i) => i.rule);
  assert.ok(
    rules.includes('gallery_label_matches_slide_title') || rules.includes('distinct_gallery_labels'),
    `expected gallery label QA issues, got ${JSON.stringify(rules)}`
  );
}

// 5) textForSlot dedupes gallery labels and column titles.
{
  const content = {
    title: 'Azure Cliff Residence',
    columns: [
      { title: 'Azure Cliff Residence', body: 'Ocean views and cliffside terraces' },
      { title: 'Azure Cliff Residence', body: 'Private wellness and spa suites' },
      { title: 'Azure Cliff Residence', body: 'Concierge dining experiences' },
      { title: 'Azure Cliff Residence', body: 'Infinity pool evening decks' },
    ],
  };
  const labels = [1, 2, 3, 4].map((n) => textForSlot(`IMAGE_${n}_LABEL`, content));
  const unique = new Set(labels.map((l) => String(l).toLowerCase()));
  assert.strictEqual(unique.size, 4, `labels must be distinct, got ${JSON.stringify(labels)}`);
  for (const label of labels) {
    assert.notStrictEqual(
      String(label).toLowerCase(),
      'azure cliff residence',
      'label must not equal slide title'
    );
  }
}

// 6) Compiling a 4-image gallery preserves all slot URLs (no compile-time wipe).
{
  const layoutSchema = {
    layout_id: 'four_images_text_v1',
    slots: [
      { id: 'HEADING', role: 'heading', region: 'cols 1-12, rows 1-2', layer: 10 },
      { id: 'IMAGE_1', role: 'image', region: 'cols 1-3, rows 3-6', layer: 2, fit: 'cover' },
      { id: 'IMAGE_1_LABEL', role: 'caption', region: 'cols 1-3, rows 6-7', layer: 10 },
      { id: 'IMAGE_2', role: 'image', region: 'cols 4-6, rows 3-6', layer: 2, fit: 'cover' },
      { id: 'IMAGE_2_LABEL', role: 'caption', region: 'cols 4-6, rows 6-7', layer: 10 },
      { id: 'IMAGE_3', role: 'image', region: 'cols 7-9, rows 3-6', layer: 2, fit: 'cover' },
      { id: 'IMAGE_3_LABEL', role: 'caption', region: 'cols 7-9, rows 6-7', layer: 10 },
      { id: 'IMAGE_4', role: 'image', region: 'cols 10-12, rows 3-6', layer: 2, fit: 'cover' },
      { id: 'IMAGE_4_LABEL', role: 'caption', region: 'cols 10-12, rows 6-7', layer: 10 },
    ],
  };
  const urls = {
    IMAGE_1: 'https://cdn.example/a.jpg',
    IMAGE_2: 'https://cdn.example/b.jpg',
    IMAGE_3: 'https://cdn.example/c.jpg',
    IMAGE_4: 'https://cdn.example/d.jpg',
  };
  const content = {
    title: 'Gallery',
    columns: [
      { title: 'View A', body: 'Detail A' },
      { title: 'View B', body: 'Detail B' },
      { title: 'View C', body: 'Detail C' },
      { title: 'View D', body: 'Detail D' },
    ],
    slotImageUrls: urls,
  };
  const themeTokens = themeService.resolveThemeTokens({ themeId: 'clean_light' });
  const doc = layoutSlotsToElements(
    layoutSchema,
    content,
    null,
    { width: 1920, height: 1080 },
    { themeTokens }
  );
  const imageEls = (doc.elements || []).filter((e) => e.type === 'image');
  assert.strictEqual(imageEls.length, 4, `expected 4 image elements, got ${imageEls.length}`);
  const compiledUrls = imageEls.map((e) => e.content?.url).filter(Boolean);
  assert.strictEqual(compiledUrls.length, 4, `expected 4 URLs preserved, got ${JSON.stringify(compiledUrls)}`);
  assert.deepStrictEqual(new Set(compiledUrls).size, 4, 'compiled URLs must remain distinct');
}

console.log('ok: palette + gallery + heading fixes');
