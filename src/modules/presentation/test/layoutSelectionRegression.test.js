'use strict';

const assert = require('assert');
const crypto = require('crypto');
const { readFileSync } = require('fs');
const path = require('path');
const { test } = require('node:test');

const { toDeckLayout } = require('../deckLayout/toDeckLayout');
const { rankLayouts } = require('../deckLayout/rankLayouts');
const {
  pickLayoutForGeneratedSlide,
  applyLayoutExclusions,
} = require('../deckLayout/pickLayoutForGeneratedSlide');
const { pickSafeLayoutFallback } = require('../deckLayout/layoutSafeFallback');
const { toSlideContentProfile } = require('../deckLayout/toSlideContentProfile');
const {
  shouldReusePreselectedLayout,
  contentFitsLayoutContract,
} = require('../deckLayout/preselectedLayoutReuse');
const { splitPrimaryAndWidenedTemplates } = require('../deckLayout/resolveLayoutCandidates');
const { validateSlide } = require('../layoutQa.service');
const {
  normalizeContentForLayout,
  collectRawArrayOverflowErrors,
  contentFitsLayoutGroups,
  validateContentForLayoutSoft,
} = require('@athena/contracts/contentContract.js');
const { textForSlot } = require('@athena/contracts/slotText.js');

function qaHasUnresolvedOverflow(issues) {
  return (issues || []).some(
    (i) =>
      i.requiresLayoutRetry === true ||
      (String(i.code || '') === 'ARRAY_OVERFLOW' && i.repairable === false)
  );
}

const seedPath = path.join(__dirname, '../templates/seed-layouts.json');
const seedLayouts = JSON.parse(readFileSync(seedPath, 'utf8'));

function seedTemplate(layoutId) {
  const entry = seedLayouts.find(
    (row) => String(row?.schema?.layout_id || row?.variant || '') === layoutId
  );
  assert.ok(entry, `missing seed for ${layoutId}`);
  return entry;
}

function hashPayload(parts) {
  return crypto.createHash('sha256').update(JSON.stringify(parts)).digest('hex');
}

test('preselected image+text is not reused for comparison statistics content', () => {
  const imageText = seedTemplate('section_with_image_v1');
  const content = {
    title: 'Cloud vs on-prem',
    body: 'Side-by-side metrics',
    stats: [
      { value: '99.9%', label: 'Cloud uptime' },
      { value: '97%', label: 'On-prem uptime' },
    ],
    comparison: {
      rows: [
        {
          leftTitle: 'Cloud',
          leftBody: 'Elastic scale',
          rightTitle: 'On-prem',
          rightBody: 'Fixed capacity',
        },
      ],
    },
  };
  const outlineSlide = { title: content.title, suggestedContentType: 'image+text' };
  const ok = shouldReusePreselectedLayout({
    content,
    outlineSlide,
    template: imageText,
    policy: { layoutContentType: 'image+text' },
    slideOrder: 2,
    wizardDensity: null,
    galleryBlocksReuse: false,
  });
  assert.equal(ok, false);
});

test('compatible preselected image+text is reused for matching title and body', () => {
  const imageText = seedTemplate('section_with_image_v1');
  const content = {
    title: 'Product overview',
    body: 'One concise paragraph that fits a split image layout.',
  };
  const outlineSlide = { title: content.title, suggestedContentType: 'image+text' };
  const ok = shouldReusePreselectedLayout({
    content,
    outlineSlide,
    template: imageText,
    policy: { layoutContentType: 'image+text' },
    slideOrder: 2,
    wizardDensity: null,
    galleryBlocksReuse: false,
  });
  assert.equal(ok, true);
});

test('comparison content selects a comparison layout when one exists in the pool', async () => {
  const comparisonTpl = seedTemplate('comparison_side_by_side_v1');
  const quoteTpl = seedTemplate('quote_portrait_v1');
  const content = {
    title: 'Build vs buy',
    left: { title: 'Build', bullets: ['Control', 'Cost'] },
    right: { title: 'Buy', bullets: ['Speed', 'Support'] },
    comparison: {
      rows: [
        {
          leftTitle: 'Time to market',
          leftBody: 'Slower initial delivery',
          rightTitle: 'Time to market',
          rightBody: 'Faster launch',
        },
      ],
    },
  };
  const prevAi = process.env.PPT_LAYOUT_AI_ENABLED;
  process.env.PPT_LAYOUT_AI_ENABLED = 'false';
  try {
    const { layoutId } = await pickLayoutForGeneratedSlide({
      content,
      templates: [quoteTpl, comparisonTpl],
      primaryLayoutContentType: 'bullet_list',
      phase: 'final',
      outlineSlide: { title: content.title, suggestedContentType: 'comparison' },
      slide: { order: 3 },
      ctx: {},
      totalSlides: 5,
    });
    assert.ok(/comparison/i.test(String(layoutId)), `expected comparison layout, got ${layoutId}`);
  } finally {
    if (prevAi == null) delete process.env.PPT_LAYOUT_AI_ENABLED;
    else process.env.PPT_LAYOUT_AI_ENABLED = prevAi;
  }
});

test('widened pool is used when primary candidates are all hard-rejected', () => {
  const profile = toSlideContentProfile({
    title: 'Cloud vs on-prem',
    suggestedContentType: 'comparison',
    comparison: { rows: [{ leftTitle: 'A', rightTitle: 'B' }] },
  });
  const bullet = toDeckLayout(seedTemplate('bullet_list_dense_v1'));
  const comparison = toDeckLayout(seedTemplate('comparison_side_by_side_v1'));
  const ranked = rankLayouts(profile, [bullet], {
    topN: 3,
    widenedLayouts: [comparison],
  });
  assert.equal(ranked.length, 1);
  assert.equal(ranked[0].layoutId, comparison.id);
  assert.ok(
    (ranked[0].warnings || []).some((w) => /widened/i.test(w)),
    'expected widened-pool warning'
  );
});

test('no arbitrary layout when every candidate fails compatibility', () => {
  const profile = toSlideContentProfile({
    title: 'Revenue chart',
    suggestedContentType: 'chart',
    hasChart: true,
    chart: { labels: ['Q1'], series: [{ data: [1] }] },
  });
  const bullet = toDeckLayout(seedTemplate('bullet_list_dense_v1'));
  const ranked = rankLayouts(profile, [bullet], { topN: 5, widenedLayouts: [] });
  assert.equal(ranked.length, 0);
});

test('contract validation rejects array overflow for selected layout', () => {
  const twoCardSchema = seedTemplate('two_cards_image_text_v1').schema;
  const content = {
    title: 'Too many cards',
    columns: [
      { title: 'One', body: 'A' },
      { title: 'Two', body: 'B' },
      { title: 'Three', body: 'C' },
      { title: 'Four', body: 'D' },
      { title: 'Five', body: 'E' },
    ],
  };
  assert.equal(contentFitsLayoutContract(content, twoCardSchema), false);
  const qa = validateSlide({
    content,
    layoutSchema: twoCardSchema,
    includeContract: true,
    contractPhase: 'generated',
  });
  const overflow = qa.issues.filter((i) => i.code === 'ARRAY_OVERFLOW');
  assert.ok(overflow.length >= 1, 'expected ARRAY_OVERFLOW issue');
  assert.equal(overflow[0].repairable, false);
  assert.equal(overflow[0].requiresLayoutRetry, true);
  assert.ok(overflow[0].actual > overflow[0].max);
});

test('raw overflow detected before normalize would conceal excess columns', () => {
  const twoCardSchema = seedTemplate('two_cards_image_text_v1').schema;
  const content = {
    title: 'Cards',
    columns: [
      { title: '1', body: 'a' },
      { title: '2', body: 'b' },
      { title: '3', body: 'c' },
      { title: '4', body: 'd' },
      { title: '5', body: 'e' },
    ],
  };
  const rawErrors = collectRawArrayOverflowErrors(content, twoCardSchema);
  assert.ok(rawErrors.some((e) => e.path === 'columns'));
  const soft = validateContentForLayoutSoft(content, twoCardSchema);
  assert.ok(soft.errors.some((e) => e.code === 'ARRAY_OVERFLOW'));
  const normalized = normalizeContentForLayout(content, twoCardSchema);
  assert.equal(normalized.columns.length, 2);
});

test('exact maximum column count remains valid', () => {
  const twoCardSchema = seedTemplate('two_cards_image_text_v1').schema;
  const content = {
    title: 'Two cards',
    columns: [
      { title: 'Alpha', body: 'First' },
      { title: 'Beta', body: 'Second' },
    ],
  };
  assert.equal(contentFitsLayoutGroups(content, twoCardSchema), true);
  const qa = validateSlide({
    content,
    layoutSchema: twoCardSchema,
    includeContract: true,
    contractPhase: 'generated',
  });
  assert.equal(
    qa.issues.filter((i) => i.code === 'ARRAY_OVERFLOW').length,
    0
  );
});

test('qaHasUnresolvedOverflow flags non-repairable overflow for controlled failure', () => {
  const issues = [
    {
      code: 'ARRAY_OVERFLOW',
      path: 'columns',
      repairable: false,
      requiresLayoutRetry: true,
      actual: 5,
      max: 2,
    },
  ];
  assert.equal(qaHasUnresolvedOverflow(issues), true);
  assert.equal(
    qaHasUnresolvedOverflow([{ code: 'MISSING_TITLE', repairable: true }]),
    false
  );
});

test('layout change re-normalizes content to the new layout contract', () => {
  const twoCardSchema = seedTemplate('two_cards_image_text_v1').schema;
  const content = {
    title: 'Vendor comparison',
    columns: [
      { title: 'Alpha', body: 'First' },
      { title: 'Beta', body: 'Second' },
      { title: 'Gamma', body: 'Third' },
      { title: 'Delta', body: 'Fourth' },
    ],
  };
  assert.equal(contentFitsLayoutContract(content, twoCardSchema), false);
  const normalized = normalizeContentForLayout(content, twoCardSchema);
  assert.equal(contentFitsLayoutContract(normalized, twoCardSchema), true);
  const qa = validateSlide({
    content: normalized,
    layoutSchema: twoCardSchema,
    includeContract: true,
    contractPhase: 'generated',
  });
  const overflow = qa.issues.filter((i) => i.code === 'ARRAY_OVERFLOW');
  assert.equal(overflow.length, 0, `unexpected overflow after normalize: ${JSON.stringify(overflow)}`);
});

test('content job hash includes layout id so layout change can invalidate duplicate skip', () => {
  const base = [
    'CONTENT',
    'slide-1',
    'v2.1',
    'balanced',
    'Title',
    'Summary',
    'bullet_list',
    '',
    '[]',
    '',
    '',
    '',
    'section_with_image_v1',
  ];
  const other = base.slice();
  other[other.length - 1] = 'comparison_side_by_side_v1';
  assert.notEqual(hashPayload(base), hashPayload(other));
});

test('splitPrimaryAndWidenedTemplates separates catalog types', () => {
  const bullet = seedTemplate('bullet_list_dense_v1');
  const comparison = seedTemplate('comparison_side_by_side_v1');
  const { primaryTemplates, widenedTemplates } = splitPrimaryAndWidenedTemplates(
    [bullet, comparison],
    'bullet_list'
  );
  assert.equal(primaryTemplates.length, 1);
  assert.equal(widenedTemplates.length, 1);
  assert.equal(primaryTemplates[0].variant, 'bullet_list_dense_v1');
  assert.equal(widenedTemplates[0].variant, 'comparison_side_by_side_v1');
});

test('excluded compatible layout is never selected', async () => {
  const comparisonTpl = seedTemplate('comparison_side_by_side_v1');
  const content = { title: 'A vs B', suggestedContentType: 'comparison' };
  const prevAi = process.env.PPT_LAYOUT_AI_ENABLED;
  process.env.PPT_LAYOUT_AI_ENABLED = 'false';
  try {
    const { layoutId } = await pickLayoutForGeneratedSlide({
      content,
      templates: [comparisonTpl],
      excludeLayoutIds: ['comparison_side_by_side_v1'],
      phase: 'final',
      outlineSlide: { title: content.title, suggestedContentType: 'comparison' },
      slide: { order: 2 },
      ctx: {},
      totalSlides: 4,
    });
    assert.equal(layoutId, null);
  } finally {
    if (prevAi == null) delete process.env.PPT_LAYOUT_AI_ENABLED;
    else process.env.PPT_LAYOUT_AI_ENABLED = prevAi;
  }
});

test('applyLayoutExclusions marks exhausted pool without restoring excluded templates', () => {
  const comparisonTpl = seedTemplate('comparison_side_by_side_v1');
  const { allowed, exhausted } = applyLayoutExclusions(
    [comparisonTpl],
    ['comparison_side_by_side_v1']
  );
  assert.equal(allowed.length, 0);
  assert.equal(exhausted, true);
});

test('safe fallback skips excluded compatible layouts', () => {
  const profile = toSlideContentProfile({
    title: 'Build vs buy',
    suggestedContentType: 'comparison',
  });
  const comparison = toDeckLayout(seedTemplate('comparison_side_by_side_v1'));
  const safe = pickSafeLayoutFallback(profile, [comparison], {
    excludeLayoutIds: [comparison.id],
  });
  assert.equal(safe, null);
});

test('textForSlot maps POINT_, CELL_, and comparison ROW slots from structured content', () => {
  const content = {
    title: 'Strategy',
    columns: [
      { title: 'Vision', body: 'North star' },
      { title: 'Execution', body: 'Ship weekly' },
    ],
    table: {
      headers: ['Metric', 'Q1', 'Q2'],
      rows: [
        ['Revenue', '$1M', '$2M'],
        ['Users', '10k', '20k'],
      ],
    },
    comparison: {
      rows: [
        {
          leftTitle: 'Cloud',
          leftBody: 'Elastic',
          rightTitle: 'On-prem',
          rightBody: 'Fixed',
        },
      ],
    },
  };
  assert.equal(textForSlot('POINT_1_TITLE', content), 'Vision');
  assert.equal(textForSlot('POINT_2_DESC', content), 'Ship weekly');
  assert.equal(textForSlot('CELL_1_1', content), 'Metric');
  assert.equal(textForSlot('CELL_1_2', content), 'Q1');
  assert.equal(textForSlot('CELL_2_1', content), 'Users');
  assert.equal(textForSlot('ROW_1_LEFT_TITLE', content), 'Cloud');
  assert.equal(textForSlot('ROW_1_RIGHT_BODY', content), 'Fixed');
});

test('textForSlot maps subheadline intro and numbered headings', () => {
  const content = {
    title: 'Main headline',
    subtitle: 'Tagline here',
    intro: 'Opening paragraph.',
  };
  assert.equal(textForSlot('SUBHEADLINE', content), 'Tagline here');
  assert.equal(textForSlot('INTRO', content), 'Opening paragraph.');
  assert.equal(textForSlot('HEADING_1', content), 'Main headline');
});

test('layout retry pick excludes previously rejected layout id', async () => {
  const side = seedTemplate('comparison_side_by_side_v1');
  const pros = seedTemplate('comparison_pros_cons_v1');
  const content = {
    title: 'Option tradeoffs',
    left: { title: 'Build' },
    right: { title: 'Buy' },
    comparison: {
      rows: [{ leftTitle: 'Cost', rightTitle: 'Speed' }],
    },
  };
  const prevAi = process.env.PPT_LAYOUT_AI_ENABLED;
  process.env.PPT_LAYOUT_AI_ENABLED = 'false';
  try {
    const first = await pickLayoutForGeneratedSlide({
      content,
      templates: [side, pros],
      preferredLayoutId: 'comparison_side_by_side_v1',
      primaryLayoutContentType: 'comparison',
      phase: 'final',
      outlineSlide: { title: content.title, suggestedContentType: 'comparison' },
      slide: { order: 2 },
      ctx: {},
      totalSlides: 4,
    });
    assert.equal(first.layoutId, 'comparison_side_by_side_v1');
    const second = await pickLayoutForGeneratedSlide({
      content,
      templates: [side, pros],
      excludeLayoutIds: ['comparison_side_by_side_v1'],
      primaryLayoutContentType: 'comparison',
      phase: 'final',
      outlineSlide: { title: content.title, suggestedContentType: 'comparison' },
      slide: { order: 2 },
      ctx: {},
      totalSlides: 4,
    });
    assert.ok(second.layoutId);
    assert.notEqual(second.layoutId, first.layoutId);
  } finally {
    if (prevAi == null) delete process.env.PPT_LAYOUT_AI_ENABLED;
    else process.env.PPT_LAYOUT_AI_ENABLED = prevAi;
  }
});
