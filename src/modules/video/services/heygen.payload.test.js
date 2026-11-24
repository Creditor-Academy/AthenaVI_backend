'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const { buildHeyGenVideoPayload } = require('./heygen.service');

const BASE_BODY = {
  avatarId: 'look_123',
  avatarEngine: 'avatar_iv',
  avatarType: 'photo_avatar',
  title: 'Scene 1',
  resolution: '1080p',
  aspectRatio: '16:9',
  backgroundColor: '#008000',
  voiceId: 'voice_1',
  script: 'Hello.',
  outputFormat: 'mp4',
};

describe('buildHeyGenVideoPayload voice settings', () => {
  it('names the engine but leaves the model out by default', () => {
    const payload = buildHeyGenVideoPayload(BASE_BODY);
    assert.deepEqual(payload.voice_settings.engine_settings, { engine_type: 'heygen_voice' });
    assert.equal('model' in payload.voice_settings.engine_settings, false);
  });

  it('passes caller engine_settings through unchanged', () => {
    const engine_settings = { engine_type: 'elevenlabs', model: 'eleven_v3' };
    const payload = buildHeyGenVideoPayload({
      ...BASE_BODY,
      voiceSettings: { engine_settings },
    });
    assert.deepEqual(payload.voice_settings.engine_settings, engine_settings);
  });

  it('clamps speed to HeyGen 0.5–1.5 and volume to at most 1', () => {
    const fast = buildHeyGenVideoPayload({ ...BASE_BODY, voiceSettings: { speed: 2, volume: 1.5 } });
    assert.equal(fast.voice_settings.speed, 1.5);
    assert.equal(fast.voice_settings.volume, 1);

    const slow = buildHeyGenVideoPayload({ ...BASE_BODY, voiceSettings: { speed: 0.2 } });
    assert.equal(slow.voice_settings.speed, 0.5);
  });
});

describe('buildHeyGenVideoPayload Avatar 6', () => {
  it('renders Avatar 6 at 1080p when 720p is requested', () => {
    const payload = buildHeyGenVideoPayload({
      ...BASE_BODY,
      avatarEngine: 'heygen-avatar-6-turbo',
      resolution: '720p',
    });
    assert.equal(payload.resolution, '1080p');
    assert.deepEqual(payload.engine, { type: 'heygen-avatar-6-turbo' });
  });

  it('keeps 720p for Avatar IV', () => {
    const payload = buildHeyGenVideoPayload({ ...BASE_BODY, resolution: '720p' });
    assert.equal(payload.resolution, '720p');
  });

  it('sends motion_expressiveness inside the engine for Avatar 6 only', () => {
    const six = buildHeyGenVideoPayload({
      ...BASE_BODY,
      avatarEngine: 'heygen-avatar-6',
      motionExpressiveness: 'less',
    });
    assert.deepEqual(six.engine, { type: 'heygen-avatar-6', motion_expressiveness: 'less' });

    const iv = buildHeyGenVideoPayload({ ...BASE_BODY, motionExpressiveness: 'less' });
    assert.deepEqual(iv.engine, { type: 'avatar_iv' });
  });
});
