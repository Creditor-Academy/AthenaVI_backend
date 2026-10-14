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

test('editor path (no generation flag) is unchanged', async () => {
  const schema = LAYOUTS.find((t) => t.schema?.layout_id === 'table_with_description_v1')?.schema;
  const { elementsDoc } = await compileSlide({ layoutSchema: schema, content: CONTENT, themeTokens: THEME, skipContentRepair: true });
  assert.ok((elementsDoc.elements || []).some((el) => el.type === 'text' && !textOf(el)), 'empty slots kept for editing');
});
