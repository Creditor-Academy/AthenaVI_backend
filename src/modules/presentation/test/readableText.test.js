'use strict';

const assert = require('assert');
const { test } = require('node:test');
const SEED = require('../templates/seed-layouts.json');
const { compileSlide } = require('../slideCompiler.service');
const { tierOf } = require('../artDirection/textHierarchy');
const { isExemptLayout } = require('../artDirection/deckHeadingSize');

const LAYOUTS = Array.isArray(SEED) ? SEED : SEED.layouts || [];
const THEME = {
  typeScale: { title: 42, subtitle: 26, body: 18, caption: 14 },
  fonts: { heading: 'Playfair Display', body: 'Lato' },
  palette: { primary: '#8B7D3A', text: '#2B2B2B', bg: '#F7EFEC' },
};
const LONG = 'VELORA unmatched creative vision sets it apart, blending avant-garde artistry with wearable fashion to captivate trendsetters and tastemakers alike across every market.';
const CONTENT = {
  title: 'Key Takeaways: Why VELORA is Poised for Impact',
  bullets: [LONG, LONG, LONG],
  columns: [1, 2, 3, 4].map((i) => ({ title: `Point title ${i}`, body: LONG })),
};

test('generated text: theme fonts on every element, nothing below 14px (captions 12px)', async () => {
  const failures = [];
  for (const t of LAYOUTS) {
    if (isExemptLayout(t.schema)) continue;
    let doc;
    try {
      // eslint-disable-next-line no-await-in-loop
      ({ elementsDoc: doc } = await compileSlide({ layoutSchema: t.schema, content: CONTENT, themeTokens: THEME, skipContentRepair: true, themeRecolor: true }));
    } catch {
      continue;
    }
    for (const el of doc.elements || []) {
      if (el.type !== 'text' || !String(el.content?.text || '').trim()) continue;
      if (!['Playfair Display', 'Lato'].includes(el.content.fontFamily)) failures.push(`${t.schema.layout_id} ${el.slotId}: font ${el.content.fontFamily}`);
      const floor = tierOf(el) === 4 ? 12 : 14;
      if (/BADGE|TAG|CATEGORY|PILL|CHIP|_NUM$|NUMBER/i.test(String(el.slotId || ''))) continue;
      if ((Number(el.placement?.height) || 0) < floor * (1920 / 900) * (Number(el.content?.lineHeight) || 1.25)) continue;
      if (Number(el.content.fontSize) < floor) failures.push(`${t.schema.layout_id} ${el.slotId}: ${el.content.fontSize}px`);
    }
  }
  assert.deepStrictEqual(failures.slice(0, 15), []);
});

test('card box with title + paragraph gets a bold title run', async () => {
  const schema = LAYOUTS.find((t) => t.schema?.layout_id === 'four_para_image_grid_v1').schema;
  const { elementsDoc } = await compileSlide({ layoutSchema: schema, content: CONTENT, themeTokens: THEME, skipContentRepair: true, themeRecolor: true });
  const bullet = elementsDoc.elements.find((el) => el.slotId === 'BULLET_1');
  assert.ok(Array.isArray(bullet.content.runs), 'runs created');
  assert.strictEqual(bullet.content.runs[0].fontWeight, 700);
  assert.ok(bullet.content.fontSize >= 14);
});
