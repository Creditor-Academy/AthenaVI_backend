const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { toPublicSlide } = require('./deckRender.service');

describe('toPublicSlide speakerNotes', () => {
  const slide = {
    id: 's1',
    order: 0,
    status: 'READY',
    title: 'Intro',
    speakerNotes: 'Say hello',
    elements: { version: 1, elements: [] },
  };

  it('omits speakerNotes by default (guest / public builder)', () => {
    const out = toPublicSlide(slide);
    assert.equal('speakerNotes' in out, false);
  });

  it('omits speakerNotes when includeNotes is false', () => {
    const out = toPublicSlide(slide, { includeNotes: false });
    assert.equal('speakerNotes' in out, false);
  });

  it('includes speakerNotes when includeNotes is true (member preview)', () => {
    const out = toPublicSlide(slide, { includeNotes: true });
    assert.equal(out.speakerNotes, 'Say hello');
  });

  it('defaults missing notes to empty string when includeNotes is true', () => {
    const out = toPublicSlide({ ...slide, speakerNotes: undefined }, { includeNotes: true });
    assert.equal(out.speakerNotes, '');
  });
});
