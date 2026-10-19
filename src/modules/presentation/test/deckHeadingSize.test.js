'use strict';

const assert = require('assert');
const { test } = require('node:test');
const SEED = require('../templates/seed-layouts.json');
const { compileSlide } = require('../slideCompiler.service');
const {
  harmonizeDeckHeadings,
  resolveDeckHeadingPx,
  findMainHeading,
  isExemptLayout,
  MIN_DECK_HEADING_PX,
} = require('../artDirection/deckHeadingSize');

const LAYOUTS = Array.isArray(SEED) ? SEED : SEED.layouts || [];
const schemaFor = (id) => LAYOUTS.find((t) => t.schema?.layout_id === id)?.schema;
const THEME = { typeScale: { display: 56, title: 42, subtitle: 26, body: 18 }, palette: { text: '#0F172A', primary: '#1E3A8A' } };

const CONTENT = {
  title: 'AI in Hospital Operations',
  bullets: ['Workflow automation', 'Smarter scheduling', 'Faster documentation'],
  columns: [
    { title: 'Scheduling', body: 'Balance demand across teams.' },
    { title: 'Documentation', body: 'Draft notes for clinician review.' },
    { title: 'Patient flow', body: 'Anticipate bed demand.' },
  ],
  timeline: [
    { label: 'Q1', title: 'Assess', detail: 'Audit readiness.' },
    { label: 'Q2', title: 'Pilot', detail: 'Supervised pilot.' },
    { label: 'Q3', title: 'Scale', detail: 'Govern rollout.' },
  ],
};

const CONTENT_LAYOUTS = [
  'bullet_list_two_column_v1',
  'diagram_process_steps_v1',
  'timeline_milestones_v1',
  'process_linner_horti_v1',
  'three_cards_image_text_v1',
];

test('content slides get the theme heading size and are marked deckHeading', async () => {
  for (const layoutId of CONTENT_LAYOUTS) {
    const schema = schemaFor(layoutId);
    if (!schema || isExemptLayout(schema)) continue;
    // eslint-disable-next-line no-await-in-loop
    const { elementsDoc } = await compileSlide({ layoutSchema: schema, content: CONTENT, themeTokens: THEME, skipContentRepair: true });
    const heading = findMainHeading(elementsDoc.elements || []);
    assert.ok(heading, `${layoutId}: has a main heading`);
    assert.strictEqual(heading.content.deckHeading, true, `${layoutId}: marked deckHeading`);
    assert.ok(heading.content.fontSize <= 42 && heading.content.fontSize >= 19, `${layoutId}: size ${heading.content.fontSize}`);
  }
});

test('cover slides keep their display size', async () => {
  const schema = schemaFor('title_fullbleed_v1');
  assert.ok(isExemptLayout(schema));
  const { elementsDoc } = await compileSlide({ layoutSchema: schema, content: CONTENT, themeTokens: THEME, skipContentRepair: true });
  assert.ok(!(elementsDoc.elements || []).some((el) => el?.content?.deckHeading));
});

const slideWith = (id, size) => ({
  id,
  elements: { elements: [{ id: `${id}-h`, type: 'text', slotId: 'HEADING', content: { text: 'T', fontSize: size, deckHeading: true } }] },
});

test('harmonizeDeckHeadings shrinks every heading to the smallest fitted size', () => {
  const { headingPx, updates } = harmonizeDeckHeadings([slideWith('a', 42), slideWith('b', 34), slideWith('c', 42)]);
  assert.strictEqual(headingPx, 34);
  assert.deepStrictEqual(updates.map((u) => u.slideId).sort(), ['a', 'c']);
  for (const u of updates) assert.strictEqual(u.elements.elements[0].content.fontSize, 34);
});

test('one cramped slide cannot drag the deck below the floor', () => {
  const { headingPx, updates } = harmonizeDeckHeadings([slideWith('a', 42), slideWith('b', 19)]);
  assert.strictEqual(headingPx, MIN_DECK_HEADING_PX);
  assert.deepStrictEqual(updates.map((u) => u.slideId), ['a']);
});

test('a harmonized deck size wins over the theme title for later recompiles', () => {
  assert.strictEqual(resolveDeckHeadingPx({ typeScale: { title: 44, deckHeading: 32 } }), 32);
  assert.strictEqual(resolveDeckHeadingPx({ typeScale: { title: 44 } }), 44);
  assert.strictEqual(resolveDeckHeadingPx(null), 42);
});
