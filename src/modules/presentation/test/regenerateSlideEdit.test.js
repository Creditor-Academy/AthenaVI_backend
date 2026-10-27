'use strict';

const assert = require('assert');
const { test } = require('node:test');
const { buildUser } = require('../prompts/slideContent.prompt');
const { regenerateSlideSchema } = require('../../validations/presentation.validations');

const EXISTING = {
  title: 'AI in Hospital Operations',
  bullets: ['Workflow automation', 'Smarter scheduling'],
  imageRef: { s3Key: 'secret/key.png' },
};

test('edit instruction embeds current slide content and instruction', () => {
  const out = buildUser({
    title: 'AI in Hospital Operations',
    editInstruction: 'Make the content on this slide shorter.',
    existingContent: EXISTING,
  });
  assert.match(out, /EDIT MODE/);
  assert.match(out, /<current_slide>[\s\S]*Smarter scheduling[\s\S]*<\/current_slide>/);
  assert.match(out, /<edit_instruction>\nMake the content on this slide shorter\.\n<\/edit_instruction>/);
  // Only content fields go to the model, not storage refs.
  assert.doesNotMatch(out, /secret\/key\.png/);
});

test('no edit section for fresh regenerate', () => {
  const out = buildUser({ title: 'AI in Hospital Operations' });
  assert.doesNotMatch(out, /EDIT MODE|<current_slide>/);
});

test('regenerate schema keeps the action id', () => {
  const { error, value } = regenerateSlideSchema.validate(
    {
      params: {},
      body: { target: 'full', prompt: 'Improve the writing on this slide.', action: 'improve-writing' },
    },
    { stripUnknown: true, allowUnknown: false }
  );
  assert.ok(!error || error.details.every((d) => d.path[0] === 'params'));
  assert.equal(value.body.action, 'improve-writing');
});
