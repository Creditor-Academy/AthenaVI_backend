'use strict';

const assert = require('assert');
const { test } = require('node:test');
const { candidateContentTypes } = require('../deckLayout/resolveLayoutCandidates');

test('candidateContentTypes adds comparison when profile.hasComparison despite bullet_list primary', () => {
  const types = candidateContentTypes(
    { hasComparison: true, contentStructure: 'comparison', bulletCount: 4 },
    { suggestedContentType: 'bullet_list' },
    'bullet_list'
  );
  assert.ok(types.includes('comparison'));
  assert.ok(types.includes('bullet_list'));
});

test('candidateContentTypes adds chart pool for table structure', () => {
  const types = candidateContentTypes(
    { hasTable: true },
    { suggestedContentType: 'bullet_list' },
    'bullet_list'
  );
  assert.ok(types.includes('chart'));
});
