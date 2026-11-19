'use strict';

// Phase 7.3: the CI gate on export fidelity scores (scripts/presentation-eval/fidelity-gate.js).

const assert = require('assert');
const { test } = require('node:test');
const { checkFidelity } = require('../../../../scripts/presentation-eval/fidelity-gate');

function deck(pdf, pptx, slides, errors = []) {
  return { pdf: { mean: pdf }, pptx: pptx == null ? null : { mean: pptx }, slides, errors };
}
const slides = (pdf, pptx) => [
  { n: 1, id: 's1', layoutId: 'title', pdf: pdf[0], pptx: pptx[0] },
  { n: 2, id: 's2', layoutId: 'chart', pdf: pdf[1], pptx: pptx[1] },
];
const baseline = { decks: { a: deck(0.99, 0.9, slides([0.99, 0.99], [0.95, 0.85])) } };

test('the same scores (or better) pass', () => {
  assert.deepEqual(checkFidelity(baseline, baseline), []);
  assert.deepEqual(checkFidelity({ decks: { a: deck(0.995, 0.93, slides([0.995, 0.99], [0.97, 0.9])) } }, baseline), []);
});

test('small noise passes: PDF slide within 0.02, PPTX deck within 0.01 and slide within 0.03', () => {
  const now = { decks: { a: deck(0.985, 0.891, slides([0.975, 0.99], [0.925, 0.85])) } };
  assert.deepEqual(checkFidelity(now, baseline), []);
});

test('drops fail, each named with its slide', () => {
  const now = { decks: { a: deck(0.975, 0.87, slides([0.95, 0.99], [0.95, 0.8])) } };
  const problems = checkFidelity(now, baseline);
  assert.equal(problems.length, 4, problems.join('\n'));
  assert.match(problems.join('\n'), /PDF average 0\.975 is below the target 0\.980/);
  assert.match(problems.join('\n'), /PPTX average 0\.870, was 0\.900/);
  assert.match(problems.join('\n'), /a slide 1 \(title\): PDF 0\.950, was 0\.990/);
  assert.match(problems.join('\n'), /a slide 2 \(chart\): PPTX 0\.800, was 0\.850/);
});

test('a deck that errored or was not measured fails; a new deck needs only the PDF target', () => {
  assert.deepEqual(checkFidelity({ decks: {} }, baseline), ['a: not measured (it is in the baseline)']);
  const errored = { decks: { a: deck(0.99, 0.9, slides([0.99, 0.99], [0.95, 0.85]), ['PPTX: LibreOffice crashed']) } };
  assert.deepEqual(checkFidelity(errored, baseline), ['a: PPTX: LibreOffice crashed']);
  const added = { decks: { ...baseline.decks, b: deck(0.99, 0.5, []) } };
  assert.deepEqual(checkFidelity(added, baseline), []);
});
