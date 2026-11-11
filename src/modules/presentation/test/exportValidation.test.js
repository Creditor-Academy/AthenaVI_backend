'use strict';

const assert = require('assert');
const { test } = require('node:test');
const { exportDeckSchema } = require('../../validations/presentation.validations');

const params = { workspaceId: '3f1c2b4e-1111-4a2b-8c3d-123456789abc', presentationId: 'deck-1' };
const check = (body) => exportDeckSchema.validate({ params, body }).error?.message || null;

test('export accepts whole-deck requests with slideId missing, null, or empty', () => {
  for (const format of ['PPTX', 'PDF', 'PNG', 'JPEG']) {
    assert.strictEqual(check({ format }), null, `${format} without slideId`);
    assert.strictEqual(check({ format, slideId: null }), null, `${format} with slideId null`);
    assert.strictEqual(check({ format, slideId: '' }), null, `${format} with empty slideId`);
  }
});

test('export accepts a single-slide request and still rejects bad input', () => {
  assert.strictEqual(check({ format: 'PDF', slideId: 'slide-7' }), null);
  assert.ok(check({ format: 'DOCX' }), 'unknown format rejected');
  assert.ok(check({ slideId: 'slide-7' }), 'format is required');
});

test('PPTX can be made for PowerPoint or Google Slides', () => {
  assert.strictEqual(check({ format: 'PPTX', pptxTarget: 'powerpoint' }), null);
  assert.strictEqual(check({ format: 'PPTX', pptxTarget: 'google-slides' }), null);
  assert.ok(check({ format: 'PPTX', pptxTarget: 'keynote' }), 'unknown target rejected');
});

test('any set of slides: at least one, no repeats, at most a full deck', () => {
  assert.strictEqual(check({ format: 'PDF', slideIds: ['s1', 's3'] }), null);
  assert.ok(check({ format: 'PDF', slideIds: [] }), 'empty list rejected');
  assert.ok(check({ format: 'PDF', slideIds: ['s1', 's1'] }), 'repeats rejected');
  assert.ok(check({ format: 'PDF', slideIds: Array.from({ length: 41 }, (_, i) => `s${i}`) }), 'more than a deck rejected');
});

test('image options: size 1–3×, JPEG quality 60–100, transparency on/off', () => {
  assert.strictEqual(check({ format: 'PNG', scale: 2, transparent: true }), null);
  assert.strictEqual(check({ format: 'JPEG', scale: 3, quality: 75 }), null);
  assert.ok(check({ format: 'PNG', scale: 4 }), 'scale 4 rejected');
  assert.ok(check({ format: 'JPEG', quality: 59 }), 'quality below 60 rejected');
  assert.ok(check({ format: 'JPEG', quality: 101 }), 'quality above 100 rejected');
});

test('browser image charge: PNG / JPEG, a slide list and a uuid download id', () => {
  const { browserExportSchema } = require('../../validations/presentation.validations');
  const charge = (body) => browserExportSchema.validate({ params, body }).error?.message || null;
  const downloadId = '3f1c2b4e-1111-4a2b-8c3d-123456789abc';
  assert.strictEqual(charge({ format: 'PNG', slideIds: ['s1'], downloadId }), null);
  assert.ok(charge({ format: 'PDF', slideIds: ['s1'], downloadId }), 'PDF is a server export');
  assert.ok(charge({ format: 'PNG', slideIds: [], downloadId }), 'no slides rejected');
  assert.ok(charge({ format: 'PNG', slideIds: ['s1'], downloadId: 'abc' }), 'download id must be a uuid');
});
