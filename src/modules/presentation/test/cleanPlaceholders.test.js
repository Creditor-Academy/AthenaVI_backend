'use strict';

const assert = require('assert');
const { test } = require('node:test');
const SEED = require('../templates/seed-layouts.json');
const { compileSlide } = require('../slideCompiler.service');
const { isCatalogPlaceholderText } = require('../catalogPlaceholder');
const { cleanPlaceholders } = require('../artDirection/cleanPlaceholders');

const LAYOUTS = Array.isArray(SEED) ? SEED : SEED.layouts || [];
const THEME = { typeScale: { title: 42, subtitle: 26, body: 18 }, palette: { primary: '#1E3A8A', text: '#0F172A' } };
const CONTENT = {
  title: 'AI in Hospital Operations',
  bullets: ['Workflow automation', 'Smarter scheduling', 'Faster documentation'],
  columns: [
    { title: 'Scheduling', body: 'Balance staff demand.' },
    { title: 'Documentation', body: 'Draft notes for review.' },
  ],
};
const MAIN = new Set(['HEADING', 'TITLE', 'MAIN_TITLE', 'HEADLINE']);
const textOf = (el) => String(el?.content?.text || (el?.content?.runs || []).map((r) => r.text || '').join('') || '').trim();

test('generated slides contain no placeholder copy and no stray empty text boxes', async () => {
  const failures = [];
  for (const t of LAYOUTS) {
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
    const required = new Set((t.schema.slots || []).filter((s) => s.required === true).map((s) => String(s.id).toUpperCase()));
    for (const el of doc.elements || []) {
      if (el.type !== 'text' && el.type !== 'textbox') continue;
      const text = textOf(el);
      const sid = String(el.slotId || '').toUpperCase();
      if (text && isCatalogPlaceholderText(text)) failures.push(`${t.schema.layout_id}: placeholder "${text}"`);
      if (!text && !MAIN.has(sid) && !required.has(sid)) failures.push(`${t.schema.layout_id}: empty ${sid}`);
    }
  }
  assert.deepStrictEqual(failures.slice(0, 15), []);
});

test('cleanPlaceholders blanks placeholder copy, drops empty boxes, keeps the heading', () => {
  const doc = {
    elements: [
      { type: 'text', slotId: 'HEADING', content: { text: '' } },
      { type: 'text', slotId: 'ROW_1_LABEL', content: { text: 'Add Text Here' } },
      { type: 'text', slotId: 'BODY', content: { text: 'Double-click to edit' } },
      { type: 'text', slotId: 'CARD_1_BODY', content: { text: 'Real copy' } },
      { type: 'shape', slotId: 'CARD_1_BG', content: {} },
    ],
  };
  const out = cleanPlaceholders(doc, { layoutSchema: { slots: [] } });
  assert.deepStrictEqual(out.elements.map((el) => el.slotId), ['HEADING', 'CARD_1_BODY', 'CARD_1_BG']);
});

const { collapseEmptyCards } = require('../artDirection/cleanPlaceholders');

function cardRow(texts, { svg = false } = {}) {
  const els = [];
  texts.forEach((text, i) => {
    const x = 100 + i * 440;
    els.push(
      svg
        ? { id: `bg${i}`, type: 'graphic', slotId: `CARD_${i + 1}_BG`, placement: { x, y: 300, width: 400, height: 300 }, content: { svg: '<svg viewBox="0 0 1 1"/>' } }
        : { id: `bg${i}`, type: 'shape', slotId: `CARD_${i + 1}_BG`, placement: { x, y: 300, width: 400, height: 300 }, content: { shape: 'rect' } },
      { id: `ic${i}`, type: 'graphic', slotId: `CARD_${i + 1}_ICON`, placement: { x: x + 20, y: 320, width: 60, height: 60 }, content: {} },
      { id: `tx${i}`, type: 'text', slotId: `CARD_${i + 1}_BODY`, placement: { x: x + 20, y: 400, width: 360, height: 150 }, content: { text } }
    );
  });
  return els;
}

test('empty cards are removed with their contents and the rest re-flow across the row', () => {
  const out = collapseEmptyCards(cardRow(['Scheduling', 'Docs', '', '']), { layoutSchema: { layout_id: 'grid_cards_x' } });
  assert.ok(!out.some((el) => /^(bg|ic|tx)[23]$/.test(el.id)), 'cards 3–4 and their icons removed');
  const bgs = out.filter((el) => el.slotId?.endsWith('_BG')).map((el) => el.placement);
  assert.strictEqual(bgs.length, 2);
  assert.strictEqual(bgs[0].x, 100, 'row starts where it did');
  assert.strictEqual(bgs[1].x + bgs[1].width, 100 + 3 * 440 + 400, 'row ends where it did');
  assert.strictEqual(bgs[0].width, bgs[1].width, 'equal widths');
  assert.strictEqual(bgs[1].x - (bgs[0].x + bgs[0].width), 40, 'original gap kept');
  for (const i of [0, 1]) {
    const bg = out.find((el) => el.id === `bg${i}`).placement;
    const tx = out.find((el) => el.id === `tx${i}`).placement;
    assert.ok(tx.x >= bg.x && tx.x + tx.width <= bg.x + bg.width, 'text stays inside its card');
  }
});

test('non-stretchable SVG cards keep their width and are centred', () => {
  const out = collapseEmptyCards(cardRow(['One', '', ''], { svg: true }), { layoutSchema: { layout_id: 'grid_cards_x' } });
  const bg = out.find((el) => el.id === 'bg0').placement;
  assert.strictEqual(bg.width, 400);
  assert.strictEqual(bg.x, Math.round(100 + (2 * 440 + 400 - 400) / 2));
});

test('a row with every card empty is left alone; connected diagrams are skipped', () => {
  const allEmpty = cardRow(['', '']);
  assert.strictEqual(collapseEmptyCards(allEmpty, { layoutSchema: { layout_id: 'grid_cards_x' } }), allEmpty);
  const funnel = cardRow(['A', '']);
  assert.strictEqual(collapseEmptyCards(funnel, { layoutSchema: { layout_id: 'diagram_funnel_v1' } }), funnel);
});

test('editor path (no generation flag) is unchanged', async () => {
  const schema = LAYOUTS.find((t) => t.schema?.layout_id === 'table_with_description_v1')?.schema;
  const { elementsDoc } = await compileSlide({ layoutSchema: schema, content: CONTENT, themeTokens: THEME, skipContentRepair: true });
  assert.ok((elementsDoc.elements || []).some((el) => el.type === 'text' && !textOf(el)), 'empty slots kept for editing');
});
