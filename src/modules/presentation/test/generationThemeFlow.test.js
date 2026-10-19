'use strict';

const assert = require('assert');
const { test } = require('node:test');
const { resolveFlowToGenerateCtx } = require('../generationFlow.service');
const { assertEffectiveWizardTheme } = require('../deckGeneration.service');

test('resolveFlowToGenerateCtx builds catalog colorTreatment for deep-space', () => {
  const ctx = resolveFlowToGenerateCtx({
    version: 1,
    selections: {
      themeMode: 'palette',
      colorTheme: 'deep-space',
      imageStyle: 'photo',
    },
  });
  assert.ok(ctx.themeTokens?.colorTreatment);
  assert.match(ctx.themeTokens.colorTreatment, /space|navy|primary/i);
  assert.equal(ctx.themeTokens.wizardColorThemeId, 'deep-space');
});

test('resolveFlowToGenerateCtx uses customThemeTokens for prompt-suggested', () => {
  const ctx = resolveFlowToGenerateCtx({
    version: 1,
    selections: {
      themeMode: 'palette',
      colorTheme: 'prompt-suggested',
      customThemeTokens: {
        palette: {
          bg: '#0A0A0C',
          primary: '#1E3A5F',
          secondary: '#C0C5CC',
          accent: '#8A94A0',
          text: '#F8FAFC',
          muted: '#C0C5CC',
        },
        colorTreatment: 'custom navy; primary #1E3A5F, accent #8A94A0',
        wizardColorThemeId: 'prompt_suggested',
        appearance: 'dark',
      },
    },
  });
  assert.equal(ctx.themeTokens?.wizardColorThemeId, 'prompt_suggested');
  assert.match(ctx.themeTokens?.colorTreatment || '', /navy|1E3A5F/i);
});

test('assertEffectiveWizardTheme replaces stale prompt_suggested deck tokens', () => {
  const flowCtx = {
    generationFlow: {
      selections: {
        colorTheme: 'deep-space',
        imageStyle: 'photo',
      },
    },
    themeTokens: {
      wizardColorThemeId: 'prompt_suggested',
      colorTreatment: 'custom; primary #FF1493, accent #00FF00',
      palette: { primary: '#FF1493', accent: '#00FF00', bg: '#FFFFFF', text: '#111' },
    },
  };
  const deck = {
    themeTokens: {
      wizardColorThemeId: 'prompt_suggested',
      colorTreatment: 'custom; primary #FF1493, accent #00FF00',
    },
    outline: { sourcePrompt: 'Gen Z app pitch' },
  };
  assertEffectiveWizardTheme(flowCtx, deck);
  assert.equal(flowCtx.themeTokens.wizardColorThemeId, 'deep-space');
  assert.ok(!String(flowCtx.themeTokens.colorTreatment).includes('#FF1493'));
  assert.match(flowCtx.themeTokens.colorTreatment, /space|navy|primary/i);
});
