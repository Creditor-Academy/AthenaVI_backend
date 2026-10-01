const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { fitFontSize, fitTextElementsToBoxes, estimateLineCount } = require('./textFit.util');

const textEl = (overrides = {}) => ({
  type: 'text',
  placement: { x: 160, y: 216, width: 800, height: 324, rotation: 0 },
  content: { text: 'War Through Ordinary Eyes.', fontSize: 56, fontWeight: 800, lineHeight: 1.15 },
  ...overrides,
});

describe('estimateLineCount', () => {
  it('wraps greedily and honours explicit newlines', () => {
    assert.equal(estimateLineCount('aaaa bbbb cccc', 9), 2);
    assert.equal(estimateLineCount('a\nb\nc', 40), 3);
  });
  it('breaks a single over-long word by character', () => {
    assert.equal(estimateLineCount('abcdefghij', 4), 3);
  });
});

describe('fitFontSize', () => {
  it('shrinks text that would overflow its box', () => {
    const el = textEl({
      content: {
        text: 'War Through Ordinary Eyes. Stories of conflict, seen from the ground and beyond.',
        fontSize: 56,
        lineHeight: 1.15,
      },
    });
    const size = fitFontSize(el.content, el.placement, 1920);
    assert.ok(size != null && size < 56);
    assert.ok(size >= Math.round(56 * 0.45));
  });
  it('leaves text that already fits alone', () => {
    const el = textEl({ content: { text: 'Hi', fontSize: 24 } });
    assert.equal(fitFontSize(el.content, el.placement, 1920), null);
  });
  it('never grows font size and ignores empty text', () => {
    assert.equal(fitFontSize({ text: '', fontSize: 40 }, { width: 500, height: 100 }, 1920), null);
  });
});

describe('fitTextElementsToBoxes', () => {
  it('returns the same doc when nothing changes', () => {
    const doc = { elements: [textEl({ content: { text: 'Hi', fontSize: 24 } })] };
    assert.equal(fitTextElementsToBoxes(doc, { width: 1920, height: 1080 }), doc);
  });
  it('pulls text boxes hanging off the slide back inside', () => {
    const doc = {
      elements: [textEl({ placement: { x: -31, y: 579, width: 330, height: 50, rotation: 0 }, content: { text: 'Hi', fontSize: 12 } })],
    };
    const out = fitTextElementsToBoxes(doc, { width: 1920, height: 1080 });
    assert.equal(out.elements[0].placement.x, 0);
  });
  it('only touches text elements', () => {
    const img = { type: 'image', placement: { x: -50, y: 0, width: 100, height: 100 }, content: {} };
    const doc = { elements: [img] };
    assert.equal(fitTextElementsToBoxes(doc, { width: 1920, height: 1080 }), doc);
  });
});
