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
