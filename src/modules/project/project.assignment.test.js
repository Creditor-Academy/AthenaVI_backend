const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const Joi = require('joi');
const {
  buildAssignmentWhere,
  isAssignmentUnchanged,
  assignmentListQueryJoi,
  withAssignmentOxor,
  buildProjectAssignmentMetadata,
} = require('./project.assignment');
const {
  listProjectsSchema,
  setProjectAssigneeSchema,
} = require('../validations/project.validations');
const { listPresentationsSchema } = require('../validations/presentation.validations');
const { listWorkspaceLibrarySchema } = require('../validations/workspace.validations');
const {
  getCategoryForType,
  getPreferenceKeyForType,
  getTypesForCategory,
  buildActionUrl,
  CATEGORIES,
} = require('../inbox/inbox.notificationTypes');

const WS = '11111111-1111-1111-1111-111111111111';
const PROJECT = '22222222-2222-2222-2222-222222222222';
const USER = '33333333-3333-3333-3333-333333333333';

describe('buildAssignmentWhere', () => {
  it('returns assignedToId for assignedTo=me', () => {
    assert.deepEqual(buildAssignmentWhere({ assignedTo: 'me' }, 'user-1'), {
      assignedToId: 'user-1',
    });
  });

  it('does not match all rows when assignedTo=me has no userId', () => {
    assert.deepEqual(buildAssignmentWhere({ assignedTo: 'me' }), {
      assignedToId: { in: [] },
    });
  });

  it('returns assignedToId for assigneeId', () => {
    assert.deepEqual(buildAssignmentWhere({ assigneeId: 'user-2' }, 'user-1'), {
      assignedToId: 'user-2',
    });
  });

  it('returns null assignedToId for unassigned=true', () => {
    assert.deepEqual(buildAssignmentWhere({ unassigned: true }, 'user-1'), {
      assignedToId: null,
    });
  });

  it('returns empty object when no filter', () => {
    assert.deepEqual(buildAssignmentWhere({}, 'user-1'), {});
  });
});

describe('isAssignmentUnchanged', () => {
  it('treats null and undefined as equivalent', () => {
    assert.equal(isAssignmentUnchanged({ assignedToId: null }, null), true);
    assert.equal(isAssignmentUnchanged({}, null), true);
  });

  it('detects same assignee', () => {
    assert.equal(isAssignmentUnchanged({ assignedToId: 'a' }, 'a'), true);
  });

  it('detects change', () => {
    assert.equal(isAssignmentUnchanged({ assignedToId: 'a' }, 'b'), false);
    assert.equal(isAssignmentUnchanged({ assignedToId: 'a' }, null), false);
  });
});

describe('assignment list query Joi oxor', () => {
  const schema = withAssignmentOxor(
    Joi.object({
      folderId: Joi.string().uuid().optional(),
      ...assignmentListQueryJoi(Joi),
    }),
    Joi
  );

  it('accepts a single filter', () => {
    const { error } = schema.validate({ assignedTo: 'me' });
    assert.equal(error, undefined);
  });

  it('rejects combining assignedTo and unassigned', () => {
    const { error } = schema.validate({ assignedTo: 'me', unassigned: true });
    assert.ok(error);
  });

  it('rejects combining assigneeId and assignedTo', () => {
    const { error } = schema.validate({
      assignedTo: 'me',
      assigneeId: '11111111-1111-1111-1111-111111111111',
    });
    assert.ok(error);
  });

  it('accepts empty query', () => {
    const { error } = schema.validate({});
    assert.equal(error, undefined);
  });
});

describe('HTTP schema smoke (express query convert)', () => {
  const opts = { abortEarly: false, stripUnknown: true, convert: true };

  it('listProjectsSchema coerces unassigned=true query string', () => {
    const { error, value } = listProjectsSchema.validate(
      {
        params: { workspaceId: WS },
        query: { unassigned: 'true', type: 'VIDEO' },
      },
      opts
    );
    assert.equal(error, undefined);
    assert.equal(value.query.unassigned, true);
    assert.equal(value.query.type, 'VIDEO');
  });

  it('listProjectsSchema oxor rejects assignedTo + unassigned', () => {
    const { error } = listProjectsSchema.validate(
      {
        params: { workspaceId: WS },
        query: { assignedTo: 'me', unassigned: 'true' },
      },
      opts
    );
    assert.ok(error);
  });

  it('listPresentationsSchema accepts assignedTo=me', () => {
    const { error, value } = listPresentationsSchema.validate(
      {
        params: { workspaceId: WS },
        query: { assignedTo: 'me' },
      },
      opts
    );
    assert.equal(error, undefined);
    assert.equal(value.query.assignedTo, 'me');
  });

  it('library schema accepts category=image with assignedTo (ignored by image list)', () => {
    const { error } = listWorkspaceLibrarySchema.validate(
      {
        params: { workspaceId: WS },
        query: { category: 'image', assignedTo: 'me' },
      },
      opts
    );
    assert.equal(error, undefined);
  });

  it('setProjectAssigneeSchema allows null unassign', () => {
    const { error, value } = setProjectAssigneeSchema.validate(
      {
        params: { workspaceId: WS, projectId: PROJECT },
        body: { assigneeId: null },
      },
      opts
    );
    assert.equal(error, undefined);
    assert.equal(value.body.assigneeId, null);
  });

  it('setProjectAssigneeSchema requires uuid assigneeId', () => {
    const { error } = setProjectAssigneeSchema.validate(
      {
        params: { workspaceId: WS, projectId: PROJECT },
        body: { assigneeId: 'not-a-uuid' },
      },
      opts
    );
    assert.ok(error);
  });
});

describe('assignment inbox metadata smoke', () => {
  it('VIDEO omits presentation actionUrl so generic builder can use /projects/:id', () => {
    const prev = process.env.FRONTEND_URL;
    process.env.FRONTEND_URL = 'https://app.example';
    try {
      const meta = buildProjectAssignmentMetadata({
        project: {
          id: PROJECT,
          workspaceId: WS,
          name: 'Q1 Training',
          type: 'VIDEO',
        },
        workspace: { id: WS, name: 'Acme' },
        actor: { id: USER, name: 'Alex' },
        frontendUrl: 'https://app.example',
      });
      assert.equal(meta.actionUrl, undefined);
      assert.equal(meta.projectType, 'VIDEO');
      const url = buildActionUrl(meta);
      assert.equal(url, `https://app.example/workspaces/${WS}/projects/${PROJECT}`);
    } finally {
      process.env.FRONTEND_URL = prev;
    }
  });

  it('PRESENTATION sets /presentations/:id actionUrl', () => {
    const meta = buildProjectAssignmentMetadata({
      project: {
        id: PROJECT,
        workspaceId: WS,
        name: 'Pitch',
        type: 'PRESENTATION',
      },
      workspace: { id: WS, name: 'Acme' },
      actor: { id: USER, name: 'Alex' },
      frontendUrl: 'https://app.example',
    });
    assert.equal(
      meta.actionUrl,
      `https://app.example/workspaces/${WS}/presentations/${PROJECT}`
    );
    assert.equal(meta.presentationId, PROJECT);
  });

  it('maps assignment types to collaboration + workspaceTeamAlerts', () => {
    assert.equal(getCategoryForType('PROJECT_ASSIGNED'), CATEGORIES.COLLABORATION);
    assert.equal(getCategoryForType('PROJECT_UNASSIGNED'), CATEGORIES.COLLABORATION);
    assert.equal(getPreferenceKeyForType('PROJECT_ASSIGNED'), 'workspaceTeamAlerts');
    const collab = getTypesForCategory(CATEGORIES.COLLABORATION);
    assert.ok(collab.includes('PROJECT_ASSIGNED'));
    assert.ok(collab.includes('PROJECT_UNASSIGNED'));
  });
});
