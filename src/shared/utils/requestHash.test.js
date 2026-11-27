'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

const { generateHeygenRequestHash } = require('./requestHash');

const base = {
  workspaceId: 'ws-1',
  projectId: 'proj-1',
  sceneId: 'scene-1',
  avatarId: 'look-1',
  voiceId: 'voice-1',
  script: 'Hello There',
  outputFormat: 'mp4',
};

/** The hash exactly as it was computed before motionExpressiveness existed. */
function legacyHash(engine) {
  return crypto
    .createHash('sha256')
    .update(
      JSON.stringify({
        workspaceId: 'ws-1',
        projectId: 'proj-1',
        sceneId: 'scene-1',
        avatarId: 'look-1',
        voiceId: 'voice-1',
        script: 'hello there',
        avatarEngine: engine,
        outputFormat: 'mp4',
      })
    )
    .digest('hex');
}

describe('generateHeygenRequestHash', () => {
  it('keeps the exact pre-existing hash when motionExpressiveness is not used', () => {
    for (const engine of ['avatar_iv', 'avatar_v', 'avatar_iii', 'heygen-avatar-6', 'heygen-avatar-6-turbo']) {
      assert.equal(
        generateHeygenRequestHash({ ...base, avatarEngine: engine }),
        legacyHash(engine),
        engine
      );
    }
  });

  it('keeps the pre-existing hash for motionExpressiveness "default"', () => {
    assert.equal(
      generateHeygenRequestHash({
        ...base,
        avatarEngine: 'heygen-avatar-6',
        motionExpressiveness: 'default',
      }),
      legacyHash('heygen-avatar-6')
    );
  });

  it('gives Avatar 6 "less" motion its own hash so it is not served the default-motion video', () => {
    for (const engine of ['heygen-avatar-6', 'heygen-avatar-6-turbo']) {
      const less = generateHeygenRequestHash({ ...base, avatarEngine: engine, motionExpressiveness: 'less' });
      assert.notEqual(less, legacyHash(engine), engine);
      assert.equal(
        less,
        generateHeygenRequestHash({ ...base, avatarEngine: engine, motionExpressiveness: ' LESS ' }),
        'value is normalized'
      );
    }
  });

  it('ignores motionExpressiveness on engines that do not use it', () => {
    for (const engine of ['avatar_iv', 'avatar_v', 'avatar_iii']) {
      assert.equal(
        generateHeygenRequestHash({ ...base, avatarEngine: engine, motionExpressiveness: 'less' }),
        legacyHash(engine),
        engine
      );
    }
  });
});
