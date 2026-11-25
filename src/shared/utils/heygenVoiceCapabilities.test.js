'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const { validateVideoVoiceSettings } = require('./heygenVoiceCapabilities');

/** Same shape as GET /v3/videos/voice-capabilities (`data.capabilities`). */
const CAPABILITIES = [
  {
    language: 'en',
    locale: 'en-US',
    engines: [
      { engine: 'mockingbird', models: [] },
      { engine: 'heygen_voice', models: ['heygen-voice-1'] },
    ],
  },
  {
    language: 'af',
    locale: null,
    engines: [
      { engine: 'elevenlabs', models: ['eleven_v3', 'eleven_v4'] },
      { engine: 'fish', models: ['s2.1-pro', 's2-pro'] },
      { engine: 'starfish', models: [] },
    ],
  },
  {
    language: 'en',
    locale: null,
    engines: [
      { engine: 'elevenlabs', models: ['eleven_multilingual_v2', 'eleven_v3', 'eleven_v4'] },
      { engine: 'heygen_voice', models: ['heygen-voice-1'] },
      { engine: 'cartesia', models: ['sonic-3.6'] },
    ],
  },
];

describe('validateVideoVoiceSettings: nothing to check', () => {
  it('passes when voice_settings is absent or has no locale and no engine_settings', () => {
    assert.deepEqual(validateVideoVoiceSettings(CAPABILITIES, undefined), { ok: true });
    assert.deepEqual(validateVideoVoiceSettings(CAPABILITIES, { speed: 1 }), { ok: true });
    assert.deepEqual(validateVideoVoiceSettings(CAPABILITIES, { locale: '  ' }), { ok: true });
  });

  it('passes the server default engine on Original Accent', () => {
    assert.deepEqual(
      validateVideoVoiceSettings(CAPABILITIES, { engine_settings: { engine_type: 'heygen_voice' } }),
      { ok: true }
    );
  });
});

describe('validateVideoVoiceSettings: locale', () => {
  it('accepts a locale the list offers, with the default engine', () => {
    assert.deepEqual(validateVideoVoiceSettings(CAPABILITIES, { locale: 'en-US' }), { ok: true });
  });

  it('rejects a locale HeyGen does not offer for video voices', () => {
    const result = validateVideoVoiceSettings(CAPABILITIES, { locale: 'xx-YY' });
    assert.equal(result.ok, false);
    assert.match(result.message, /"xx-YY" is not offered/);
  });
});

describe('validateVideoVoiceSettings: engine for the accent', () => {
  it('rejects an engine that the locale does not offer, and lists the offered ones', () => {
    const result = validateVideoVoiceSettings(CAPABILITIES, {
      locale: 'en-US',
      engine_settings: { engine_type: 'elevenlabs', model: 'eleven_v3' },
    });
    assert.equal(result.ok, false);
    assert.match(result.message, /Engine "elevenlabs" is not offered for locale "en-US"/);
    assert.match(result.message, /mockingbird, heygen_voice/);
  });

  it('accepts an engine the locale offers', () => {
    assert.deepEqual(
      validateVideoVoiceSettings(CAPABILITIES, {
        locale: 'en-US',
        engine_settings: { engine_type: 'mockingbird' },
      }),
      { ok: true }
    );
  });

  it('checks Original Accent (locale null) separately from regional locales', () => {
    assert.deepEqual(
      validateVideoVoiceSettings(CAPABILITIES, { engine_settings: { engine_type: 'cartesia' } }),
      { ok: true }
    );
    const result = validateVideoVoiceSettings(CAPABILITIES, {
      engine_settings: { engine_type: 'mockingbird' },
    });
    assert.equal(result.ok, false);
    assert.match(result.message, /Original Accent/);
  });
});

describe('validateVideoVoiceSettings: model', () => {
  it('accepts a model the engine lists for that accent', () => {
    assert.deepEqual(
      validateVideoVoiceSettings(CAPABILITIES, {
        engine_settings: { engine_type: 'elevenlabs', model: 'eleven_v4' },
      }),
      { ok: true }
    );
  });

  it('rejects a model that is not in the list', () => {
    const result = validateVideoVoiceSettings(CAPABILITIES, {
      engine_settings: { engine_type: 'elevenlabs', model: 'eleven_turbo_v2_5' },
    });
    assert.equal(result.ok, false);
    assert.match(result.message, /Model "eleven_turbo_v2_5" is not offered/);
  });

  it('rejects a model for an engine that takes none', () => {
    const result = validateVideoVoiceSettings(CAPABILITIES, {
      engine_settings: { engine_type: 'starfish', model: 'x' },
    });
    assert.equal(result.ok, false);
    assert.match(result.message, /takes no model/);
  });
});

describe('validateVideoVoiceSettings: engine_settings shape', () => {
  it('requires engine_type when engine_settings is sent', () => {
    const result = validateVideoVoiceSettings(CAPABILITIES, {
      engine_settings: { model: 'heygen-voice-1' },
    });
    assert.equal(result.ok, false);
    assert.match(result.message, /engine_type is required/);
  });
});
