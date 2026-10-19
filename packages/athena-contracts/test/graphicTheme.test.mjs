#!/usr/bin/env node
import assert from 'node:assert/strict';
import test from 'node:test';
import {
  resolvePaletteRole,
  resolvePaletteSequenceIndex,
  resolveGraphicDisplayColor,
  isThemedColorMode,
  THEME_PALETTE_SEQUENCE,
} from '../graphicTheme.js';

test('resolvePaletteRole prefers brand colorRoles over palette', () => {
  const color = resolvePaletteRole(
    { primary: '#111111', accent: '#222222' },
    { accent: '#AABBCC' },
    'accent',
    '#000'
  );
  assert.equal(color, '#AABBCC');
});

test('resolvePaletteSequenceIndex cycles through THEME_PALETTE_SEQUENCE', () => {
  assert.equal(THEME_PALETTE_SEQUENCE[0], 'primary');
  assert.equal(
    resolvePaletteSequenceIndex({ primary: '#P1', accent: '#A1' }, null, 0),
    '#P1'
  );
  assert.equal(
    resolvePaletteSequenceIndex({ primary: '#P1', accent: '#A1' }, null, 1),
    '#A1'
  );
});

test('resolveGraphicDisplayColor ignores stale hex fill when fillColorRole set', () => {
  const color = resolveGraphicDisplayColor(
    { fill: '#2EC4D6', fillColorRole: 'accent', colorMode: 'themed' },
    { accent: '#FF00AA' }
  );
  assert.equal(color, '#FF00AA');
});

test('resolveGraphicDisplayColor uses sequenceIndex for sequenced mode', () => {
  const color = resolveGraphicDisplayColor(
    { sequenceIndex: 2, colorMode: 'sequenced', fill: '#OLD' },
    { secondary: '#SEC' }
  );
  assert.equal(color, '#SEC');
});

test('isThemedColorMode covers themed recolorable and sequenced', () => {
  assert.equal(isThemedColorMode('themed'), true);
  assert.equal(isThemedColorMode('recolorable'), true);
  assert.equal(isThemedColorMode('sequenced'), true);
  assert.equal(isThemedColorMode('fixed'), false);
  assert.equal(isThemedColorMode('preserve'), false);
});
