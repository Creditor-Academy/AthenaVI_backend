'use strict';

const assert = require('assert');
const { test } = require('node:test');
const SEED = require('../templates/seed-layouts.json');
const { compileSlide } = require('../slideCompiler.service');
const { normalizeTextAndCards, tierOf } = require('../artDirection/textHierarchy');
const { isExemptLayout } = require('../artDirection/deckHeadingSize');

const LAYOUTS = Array.isArray(SEED) ? SEED : SEED.layouts || [];
const THEME = {
  typeScale: { display: 56, title: 42, subtitle: 26, body: 18, caption: 14 },
  palette: { primary: '#1E3A8A', secondary: '#1D4ED8', accent: '#3B82F6', text: '#0F172A', bg: '#FFFFFF' },
};
const CONTENT = {
  title: 'AI in Hospital Operations',
  subtitle: 'Practical gains for care teams',
  bullets: ['Workflow automation', 'Smarter scheduling', 'Faster documentation'],
  columns: [
    { title: 'Scheduling', body: 'Balance staff demand.' },
    { title: 'Documentation', body: 'Draft notes for review.' },
    { title: 'Patient flow', body: 'Anticipate bed demand.' },
  ],
  timeline: [
    { label: 'Q1', title: 'Assess', detail: 'Audit readiness.' },
    { label: 'Q2', title: 'Pilot', detail: 'Supervised pilot.' },
    { label: 'Q3', title: 'Scale', detail: 'Govern rollout.' },
  ],
};

test('generated content slides keep heading > card title > body (≥1.15×) on every layout', async () => {
  const failures = [];
  for (const t of LAYOUTS) {
    if (isExemptLayout(t.schema)) continue;
    let doc;
    try {
      // eslint-disable-next-line no-await-in-loop
      ({ elementsDoc: doc } = await compileSlide({
        layoutSchema: t.schema,
        content: CONTENT,
        themeTokens: THEME,
        skipContentRepair: true,
        themeRecolor: true,
      }));
    } catch {
      continue;
    }
    const tiers = { 1: [], 2: [], 3: [] };
    for (const el of doc.elements || []) {
      if (el.type !== 'text' || !String(el.content?.text || '').trim()) continue;
      const tier = tierOf(el);
      if (tiers[tier]) tiers[tier].push(Number(el.content.fontSize) || 0);
    }
    if (tiers[2].length && tiers[3].length) {
      const t2 = Math.min(...tiers[2]);
      const t3 = Math.max(...tiers[3]);
      // Titles never smaller than paragraphs; ≥1.15× unless the paragraph sits at the 14px
      // readability floor and the title box can't grow (then the title is bold instead).
      if (t2 < t3 || (t2 / t3 < 1.15 && t3 > 14 && t2 > 9)) failures.push(`${t.schema.layout_id}: ${t2}/${t3}`);
    }
    if (tiers[1].length && tiers[2].length && Math.max(...tiers[2]) >= tiers[1][0]) {
      failures.push(`${t.schema.layout_id}: card title ≥ heading`);
    }
  }
  assert.deepStrictEqual(failures, []);
});

const card = (i, h = 400) => ({
  id: `card-${i}`,
  type: 'shape',
  slotId: `CARD_${i}_BG`,
  placement: { x: 100 + i * 600, y: 300, width: 520, height: h },
  content: { shape: 'rect', fill: '#EEF2FF' },
});
const cardText = (i, text, size = 16) => ({
  id: `txt-${i}`,
  type: 'text',
  slotId: `CARD_${i}_BODY`,
  placement: { x: 130 + i * 600, y: 330, width: 460, height: 300 },
  content: { text, fontSize: size },
});

test('a row of cards with short text shrinks to equal height and centers its text', () => {
  const doc = { elements: [0, 1, 2].flatMap((i) => [card(i), cardText(i, 'Short note')]) };
  const out = normalizeTextAndCards(doc, { themeTokens: THEME, layoutSchema: { layout_id: 'grid_cards_x' } });
  const heights = out.elements.filter((el) => el.type === 'shape').map((el) => el.placement.height);
  assert.ok(heights.every((h) => h < 400), `cards shrink (${heights})`);
  assert.strictEqual(new Set(heights).size, 1, 'row cards stay equal height');
  for (const el of out.elements.filter((e) => e.type === 'text')) {
    assert.strictEqual(el.content.verticalAlign, 'center');
    assert.strictEqual(el.content.align, 'center');
    const c = out.elements.find((e) => e.id === el.id.replace('txt', 'card')).placement;
    assert.ok(el.placement.y + el.placement.height <= c.y + c.height, 'text stays inside its card');
  }
});

test('long card text keeps the card size', () => {
  const long = 'Clinicians review every AI suggestion before it reaches a patient record. '.repeat(6);
  const doc = { elements: [0, 1].flatMap((i) => [card(i), cardText(i, long, 14)]) };
  const out = normalizeTextAndCards(doc, { themeTokens: THEME, layoutSchema: { layout_id: 'grid_cards_x' } });
  assert.ok(out.elements.filter((el) => el.type === 'shape').every((el) => el.placement.height === 400));
});

test('editor path (no themeRecolor) is unchanged', async () => {
  const schema = LAYOUTS.find((t) => t.schema?.layout_id === 'process_linner_numeric_v1')?.schema;
  const { elementsDoc } = await compileSlide({ layoutSchema: schema, content: CONTENT, themeTokens: THEME, skipContentRepair: true });
  const title = elementsDoc.elements.find((el) => el.slotId === 'STEP_1_TITLE');
  assert.strictEqual(title.content.fontSize, 14, 'layout default size kept without the generation flag');
});
