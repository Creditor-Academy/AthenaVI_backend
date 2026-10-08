'use strict';

const assert = require('assert');
const { test } = require('node:test');
const themeService = require('../theme.service');
const {
  buildThemeTokensFromRoles,
  scoreCatalogTheme,
  harmonizeSuggestedPalette,
  hexToHsl,
} = require('../presentationVibePalette.suggest.service');

function hueDistance(a, b) {
  const diff = Math.abs(a - b);
  return Math.min(diff, 360 - diff);
}

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

test('harmonizeSuggestedPalette pulls accent/secondary into primary hue family', () => {
  const out = harmonizeSuggestedPalette({
    background: '#FFFBF5',
    primary: '#FF1493',
    secondary: '#FFFF00',
    accent: '#00FF00',
    text: '#1A1A1A',
    appearance: 'light',
    name: 'Rainbow',
  });
  const pH = hexToHsl(out.primary).h;
  const sH = hexToHsl(out.secondary).h;
  const aH = hexToHsl(out.accent).h;
  assert.ok(hueDistance(pH, sH) < 30, `secondary hue ${sH} vs primary ${pH}`);
  assert.ok(hueDistance(pH, aH) < 50, `accent hue ${aH} vs primary ${pH}`);
  const themeTokens = buildThemeTokensFromRoles({
    background: out.background,
    primary: out.primary,
    secondary: out.secondary,
    accent: out.accent,
    text: out.text,
    appearance: out.appearance,
    name: out.name,
  });
  themeService.assertContrast(themeTokens.palette);
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
