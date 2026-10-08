'use strict';

const assert = require('assert');
const { test } = require('node:test');
const themeService = require('../theme.service');
const {
  buildThemeTokensFromRoles,
  scoreCatalogTheme,
} = require('../presentationVibePalette.suggest.service');

test('buildThemeTokensFromRoles passes contrast after enforce', () => {
  const themeTokens = buildThemeTokensFromRoles({
    background: '#FFFBF5',
    primary: '#F4847B',
    secondary: '#F5C542',
    accent: '#F5A66E',
    text: '#3A1F14',
    appearance: 'light',
    name: 'Sunrise Test',
  });
  assert.ok(themeTokens.palette);
  themeService.assertContrast(themeTokens.palette);
  assert.equal(themeTokens.wizardColorThemeId, 'prompt_suggested');
});

test('buildThemeTokensFromRoles fixes low-contrast text on dark bg', () => {
  const themeTokens = buildThemeTokensFromRoles({
    background: '#0B1220',
    primary: '#3B82F6',
    secondary: '#22D3EE',
    accent: '#60A5FA',
    text: '#0B1220',
    appearance: 'dark',
    name: 'Midnight',
  });
  themeService.assertContrast(themeTokens.palette);
  assert.equal(themeTokens.appearance, 'dark');
});

test('scoreCatalogTheme prefers nature keywords', () => {
  const theme = scoreCatalogTheme(
    'organic farm fresh produce sustainability',
    'Friendly',
    'Customers',
    'Inform'
  );
  assert.ok(theme);
  const vibe = String(theme.vibe || '').toLowerCase();
  assert.ok(vibe.includes('nature') || vibe.includes('organic') || vibe.includes('fresh'));
});
