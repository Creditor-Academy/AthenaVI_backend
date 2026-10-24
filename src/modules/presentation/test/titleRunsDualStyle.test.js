'use strict';

const assert = require('assert');
const { test } = require('node:test');
const { buildRichTitleContent, deriveTitleRunsFallback } = require('../layoutToElements');

const themeTokens = {
  fonts: { heading: 'Playfair Display', body: 'Inter' },
};

test('buildRichTitleContent resolves fontRole to theme font families', () => {
  const content = {
    title: 'Lead phrase. Accent punch.',
    titleRuns: [
      { text: 'Lead phrase. ', colorRole: 'text', fontRole: 'heading' },
      { text: 'Accent punch.', colorRole: 'accent', fontWeight: 700, fontRole: 'heading' },
    ],
  };
  const rich = buildRichTitleContent(content, false, null, themeTokens);
  assert.ok(rich);
  assert.equal(rich.runs.length, 2);
  assert.equal(rich.runs[0].fontFamily, 'Playfair Display');
  assert.equal(rich.runs[1].fontFamily, 'Playfair Display');
  assert.equal(rich.runs[0].colorRole, 'text');
  assert.equal(rich.runs[1].colorRole, 'accent');
});

test('buildRichTitleContent keeps fontRole when theme fonts missing', () => {
  const content = {
    title: 'Hello world.',
    titleRuns: [
      { text: 'Hello ', colorRole: 'text', fontRole: 'body' },
      { text: 'world.', colorRole: 'accent', fontRole: 'heading', fontWeight: 700 },
    ],
  };
  const rich = buildRichTitleContent(content, false, null, null);
  assert.equal(rich.runs[0].fontRole, 'body');
  assert.equal(rich.runs[1].fontRole, 'heading');
  assert.ok(!rich.runs[0].fontFamily);
});

test('deriveTitleRunsFallback emits dual-font roles for multi-sentence titles', () => {
  const runs = deriveTitleRunsFallback(
    { title: 'First sentence. Middle thought. Final punch.' },
    false
  );
  assert.equal(runs.length, 3);
  assert.equal(runs[0].fontRole, 'heading');
  assert.equal(runs[1].fontRole, 'body');
  assert.equal(runs[1].italic, true);
  assert.equal(runs[2].fontRole, 'heading');
  assert.equal(runs[2].colorRole, 'accent');
});
