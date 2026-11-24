'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const { rehydrateHeygenAvatarsInProjectData } = require('./projectHeygenRehydrate');
const { rehydrateSpeechInProjectData } = require('./projectSpeechRehydrate');
const {
  generateHeygenRequestHash,
  generateSpeechRequestHash,
} = require('../../shared/utils/requestHash');

const WORKSPACE = 'ws-1';
const PROJECT = 'proj-1';
const SCENE = 'scene-1';

function heygenRow(overrides = {}) {
  return {
    id: 'row-1',
    sceneId: SCENE,
    status: 'completed',
    s3Key: 'some/key.mp4',
    createdAt: '2026-11-24T10:00:00.000Z',
    requestHash: null,
    ...overrides,
  };
}

function speechRow(overrides = {}) {
  return {
    id: 'sp-1',
    sceneId: SCENE,
    status: 'completed',
    s3Key: 'some/key.mp3',
    createdAt: '2026-11-24T10:00:00.000Z',
    requestHash: null,
    ...overrides,
  };
}

function heygenScene(extra = {}) {
  return {
    sceneId: SCENE,
    presenter: { avatarId: 'look-1', voiceId: 'voice-1', script: 'Hello there' },
    elements: [],
    ...extra,
  };
}

function speechScene(extra = {}) {
  return {
    sceneId: SCENE,
    presenter: { voiceId: 'voice-1', script: 'Hello there' },
    elements: [{ id: 'a1', type: 'audio', content: {} }],
    ...extra,
  };
}

function run(scene, rows) {
  return rehydrateHeygenAvatarsInProjectData({
    workspaceId: WORKSPACE,
    projectId: PROJECT,
    data: { scenes: [scene] },
    heygenRows: rows,
  });
}

function runSpeech(scene, rows) {
  return rehydrateSpeechInProjectData({
    workspaceId: WORKSPACE,
    projectId: PROJECT,
    data: { scenes: [scene] },
    speechRows: rows,
  });
}

describe('project load never attaches a failed video row without a file', () => {
  it('does not restore an avatar element from a failed row', () => {
    const result = run(heygenScene(), [heygenRow({ status: 'failed', s3Key: null })]);
    assert.equal(result.changed, false);
    assert.equal(result.data.scenes[0].elements.length, 0);
  });

  it('does not attach a failed row matched by request hash', () => {
    const requestHash = generateHeygenRequestHash({
      workspaceId: WORKSPACE,
      projectId: PROJECT,
      sceneId: SCENE,
      avatarId: 'look-1',
      voiceId: 'voice-1',
      script: 'Hello there',
    });
    const scene = heygenScene({
      elements: [{ id: 'el-1', type: 'video', role: 'avatar', content: { provider: 'heygen' } }],
    });
    const result = run(scene, [heygenRow({ status: 'failed', s3Key: null, requestHash })]);
    assert.equal(result.changed, false);
    assert.equal(result.data.scenes[0].elements[0].content.heygenVideoId, undefined);
  });

  it('prefers a completed row over a newer failed row', () => {
    const result = run(heygenScene(), [
      heygenRow({ id: 'row-done', createdAt: '2026-11-24T09:00:00.000Z' }),
      heygenRow({ id: 'row-failed', status: 'failed', s3Key: null, createdAt: '2026-11-24T11:00:00.000Z' }),
    ]);
    assert.equal(result.changed, true);
    assert.equal(result.data.scenes[0].elements[0].content.heygenVideoId, 'row-done');
  });

  it('leaves a scene that already references a failed row alone (retry reuses that row)', () => {
    const scene = heygenScene({
      generation: { heygenVideoId: 'row-failed' },
      elements: [
        {
          id: 'el-1',
          type: 'video',
          role: 'avatar',
          content: { provider: 'heygen', heygenVideoId: 'row-failed' },
        },
      ],
    });
    const result = run(scene, [heygenRow({ id: 'row-failed', status: 'failed', s3Key: null })]);
    assert.equal(result.changed, false);
    assert.equal(result.data.scenes[0].elements[0].content.heygenVideoId, 'row-failed');
  });

  it('still attaches a video that is in progress', () => {
    const result = run(heygenScene(), [heygenRow({ id: 'row-live', status: 'processing', s3Key: null })]);
    assert.equal(result.changed, true);
    assert.equal(result.data.scenes[0].elements[0].content.heygenVideoId, 'row-live');
  });
});

describe('project load never attaches a failed narration row without audio', () => {
  it('does not attach a failed row picked by scene', () => {
    const result = runSpeech(speechScene(), [speechRow({ status: 'failed', s3Key: null })]);
    assert.equal(result.changed, false);
    assert.equal(result.data.scenes[0].generation, undefined);
    assert.equal(result.data.scenes[0].elements[0].content.speechGenerationId, undefined);
  });

  it('does not attach a failed row matched by request hash', () => {
    const requestHash = generateSpeechRequestHash({
      workspaceId: WORKSPACE,
      projectId: PROJECT,
      sceneId: SCENE,
      voiceId: 'voice-1',
      script: 'Hello there',
    });
    const result = runSpeech(speechScene(), [speechRow({ status: 'failed', s3Key: null, requestHash })]);
    assert.equal(result.changed, false);
  });

  it('prefers a completed row over a newer failed row', () => {
    const result = runSpeech(speechScene(), [
      speechRow({ id: 'sp-done', createdAt: '2026-11-24T09:00:00.000Z' }),
      speechRow({ id: 'sp-failed', status: 'failed', s3Key: null, createdAt: '2026-11-24T11:00:00.000Z' }),
    ]);
    assert.equal(result.changed, true);
    assert.equal(result.data.scenes[0].generation.speechGenerationId, 'sp-done');
    assert.equal(result.data.scenes[0].elements[0].content.speechGenerationId, 'sp-done');
  });

  it('leaves a scene that already references a failed row alone (retry reuses that row)', () => {
    const scene = speechScene({
      generation: { speechGenerationId: 'sp-failed' },
      presenter: { voiceId: 'voice-1', script: 'Hello there', speechGenerationId: 'sp-failed' },
    });
    const result = runSpeech(scene, [speechRow({ id: 'sp-failed', status: 'failed', s3Key: null })]);
    assert.equal(result.changed, false);
    assert.equal(result.data.scenes[0].generation.speechGenerationId, 'sp-failed');
  });

  it('still attaches a narration that is in progress', () => {
    const result = runSpeech(speechScene(), [speechRow({ id: 'sp-live', status: 'processing', s3Key: null })]);
    assert.equal(result.changed, true);
    assert.equal(result.data.scenes[0].generation.speechGenerationId, 'sp-live');
  });
});
