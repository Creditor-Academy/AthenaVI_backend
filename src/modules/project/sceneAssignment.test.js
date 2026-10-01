const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  sceneKey,
  isSceneAssignmentUnchanged,
  preserveSceneAssignments,
  clearUserFromSceneAssignments,
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

describe('preserveSceneAssignments', () => {
  const stored = [
    { id: 's1', sceneId: 's1', assignedToId: USER, assignedById: WS, assignedAt: '2026-01-01T00:00:00.000Z' },
    { id: 's2', sceneId: 's2' },
  ];

  it('re-applies the stored assignment and ignores stale client values', () => {
    const [out] = preserveSceneAssignments(
      [{ id: 's1', sceneId: 's1', name: 'Intro', assignedToId: 'stale', assignee: { id: 'stale' }, assignedBy: { id: 'x' } }],
      stored
    );
    assert.equal(out.assignedToId, USER);
    assert.equal(out.assignedById, WS);
    assert.equal(out.assignedAt, '2026-01-01T00:00:00.000Z');
    assert.equal(out.name, 'Intro');
    assert.equal('assignee' in out, false);
    assert.equal('assignedBy' in out, false);
  });

  it('does not let a client assign or keep an assignment the server does not hold', () => {
    const [out] = preserveSceneAssignments(
      [{ id: 's2', sceneId: 's2', assignedToId: USER, assignee: { id: USER } }],
      stored
    );
    assert.equal('assignedToId' in out, false);
    assert.equal('assignee' in out, false);
  });

  it('leaves new scenes unassigned and tolerates missing inputs', () => {
    assert.deepEqual(preserveSceneAssignments([{ id: 'new' }], stored), [{ id: 'new' }]);
    assert.deepEqual(preserveSceneAssignments([{ id: 'new' }], undefined), [{ id: 'new' }]);
    assert.equal(preserveSceneAssignments(undefined, stored), undefined);
  });
});

describe('clearUserFromSceneAssignments', () => {
  const OTHER = '44444444-4444-4444-4444-444444444444';

  it('clears assignee scenes fully and assigner-only scenes partially', () => {
    const scenes = [
      { id: 'a', assignedToId: USER, assignedById: OTHER, assignedAt: 't' },
      { id: 'b', assignedToId: OTHER, assignedById: USER, assignedAt: 't' },
      { id: 'c' },
    ];
    const { scenes: out, changed } = clearUserFromSceneAssignments(scenes, USER);
    assert.equal(changed, true);
    assert.deepEqual(out[0], { id: 'a', assignedToId: null, assignedById: null, assignedAt: null });
    assert.deepEqual(out[1], { id: 'b', assignedToId: OTHER, assignedById: null, assignedAt: 't' });
    assert.deepEqual(out[2], { id: 'c' });
  });

  it('reports no change when the user is not referenced', () => {
    const scenes = [{ id: 'a', assignedToId: OTHER, assignedById: OTHER }];
    const result = clearUserFromSceneAssignments(scenes, USER);
    assert.equal(result.changed, false);
    assert.equal(result.scenes, scenes);
  });
});
