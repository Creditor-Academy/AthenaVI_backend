const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  sceneKey,
  isSceneAssignmentUnchanged,
  buildSceneAssignmentMetadata,
} = require('./sceneAssignment');
const { setSceneAssigneeSchema } = require('../validations/project.validations');
const {
  getCategoryForType,
  getPreferenceKeyForType,
  getTypesForCategory,
  CATEGORIES,
} = require('../inbox/inbox.notificationTypes');

const WS = '11111111-1111-1111-1111-111111111111';
const PROJECT = '22222222-2222-2222-2222-222222222222';
const USER = '33333333-3333-3333-3333-333333333333';
const SCENE = 'scene_abc123def456';

describe('sceneKey', () => {
  it('prefers sceneId over id', () => {
    assert.equal(sceneKey({ sceneId: 'a', id: 'b' }), 'a');
  });

  it('falls back to id when sceneId is missing (client-created scenes carry both anyway)', () => {
    assert.equal(sceneKey({ id: 'b' }), 'b');
  });

  it('returns null for a scene with neither key', () => {
    assert.equal(sceneKey({}), null);
    assert.equal(sceneKey(null), null);
  });
});

describe('isSceneAssignmentUnchanged', () => {
  it('treats null and undefined as equivalent', () => {
    assert.equal(isSceneAssignmentUnchanged({ assignedToId: null }, null), true);
    assert.equal(isSceneAssignmentUnchanged({}, null), true);
  });

  it('detects same assignee', () => {
    assert.equal(isSceneAssignmentUnchanged({ assignedToId: 'a' }, 'a'), true);
  });

  it('detects change', () => {
    assert.equal(isSceneAssignmentUnchanged({ assignedToId: 'a' }, 'b'), false);
    assert.equal(isSceneAssignmentUnchanged({ assignedToId: 'a' }, null), false);
  });
});

describe('buildSceneAssignmentMetadata', () => {
  it('builds a deep link scoped to the scene', () => {
    const meta = buildSceneAssignmentMetadata({
      scene: { sceneId: SCENE, order: 1, name: 'Intro' },
      project: { id: PROJECT, workspaceId: WS, name: 'Launch video' },
      workspace: { id: WS, name: 'Acme' },
      actor: { id: USER, name: 'Alex' },
      frontendUrl: 'https://app.example',
    });
    assert.equal(meta.sceneId, SCENE);
    assert.equal(meta.sceneOrder, 2);
    assert.equal(meta.projectId, PROJECT);
    assert.equal(
      meta.actionUrl,
      `https://app.example/workspaces/${WS}/projects/${PROJECT}?scene=${SCENE}`
    );
  });

  it('omits actionUrl when workspace/project ids are missing', () => {
    const meta = buildSceneAssignmentMetadata({ scene: { sceneId: SCENE } });
    assert.equal(meta.actionUrl, undefined);
  });
});

describe('setSceneAssigneeSchema', () => {
  const opts = { abortEarly: false, stripUnknown: true, convert: true };

  it('allows null to unassign', () => {
    const { error, value } = setSceneAssigneeSchema.validate(
      {
        params: { workspaceId: WS, projectId: PROJECT, sceneId: SCENE },
        body: { assigneeId: null },
      },
      opts
    );
    assert.equal(error, undefined);
    assert.equal(value.body.assigneeId, null);
  });

  it('accepts a uuid assigneeId', () => {
    const { error } = setSceneAssigneeSchema.validate(
      {
        params: { workspaceId: WS, projectId: PROJECT, sceneId: SCENE },
        body: { assigneeId: USER },
      },
      opts
    );
    assert.equal(error, undefined);
  });

  it('rejects a non-uuid assigneeId', () => {
    const { error } = setSceneAssigneeSchema.validate(
      {
        params: { workspaceId: WS, projectId: PROJECT, sceneId: SCENE },
        body: { assigneeId: 'not-a-uuid' },
      },
      opts
    );
    assert.ok(error);
  });

  it('accepts non-uuid sceneId (client-generated, not a uuid)', () => {
    const { error } = setSceneAssigneeSchema.validate(
      {
        params: { workspaceId: WS, projectId: PROJECT, sceneId: SCENE },
        body: { assigneeId: null },
      },
      opts
    );
    assert.equal(error, undefined);
  });
});

describe('scene assignment notification wiring', () => {
  it('maps SCENE_ASSIGNED/SCENE_UNASSIGNED to collaboration + workspaceTeamAlerts', () => {
    assert.equal(getCategoryForType('SCENE_ASSIGNED'), CATEGORIES.COLLABORATION);
    assert.equal(getCategoryForType('SCENE_UNASSIGNED'), CATEGORIES.COLLABORATION);
    assert.equal(getPreferenceKeyForType('SCENE_ASSIGNED'), 'workspaceTeamAlerts');
    assert.equal(getPreferenceKeyForType('SCENE_UNASSIGNED'), 'workspaceTeamAlerts');
    const collab = getTypesForCategory(CATEGORIES.COLLABORATION);
    assert.ok(collab.includes('SCENE_ASSIGNED'));
    assert.ok(collab.includes('SCENE_UNASSIGNED'));
  });
});
