const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  isSlideAssignmentUnchanged,
  buildSlideAssignmentMetadata,
} = require('./slideAssignment');
const { setSlideAssigneeSchema } = require('../validations/presentation.validations');
const {
  getCategoryForType,
  getPreferenceKeyForType,
  getTypesForCategory,
  CATEGORIES,
} = require('../inbox/inbox.notificationTypes');

const WS = '11111111-1111-1111-1111-111111111111';
const PRESENTATION = 'cabc123456789012345678901';
const SLIDE = 'cdef123456789012345678901';
const USER = '33333333-3333-3333-3333-333333333333';

describe('isSlideAssignmentUnchanged', () => {
  it('treats null and undefined as equivalent', () => {
    assert.equal(isSlideAssignmentUnchanged({ assignedToId: null }, null), true);
    assert.equal(isSlideAssignmentUnchanged({}, null), true);
  });

  it('detects same assignee', () => {
    assert.equal(isSlideAssignmentUnchanged({ assignedToId: 'a' }, 'a'), true);
  });

  it('detects change', () => {
    assert.equal(isSlideAssignmentUnchanged({ assignedToId: 'a' }, 'b'), false);
    assert.equal(isSlideAssignmentUnchanged({ assignedToId: 'a' }, null), false);
  });
});

describe('buildSlideAssignmentMetadata', () => {
  it('builds a deep link scoped to the slide', () => {
    const meta = buildSlideAssignmentMetadata({
      slide: { id: SLIDE, order: 2 },
      project: { id: PRESENTATION, workspaceId: WS, name: 'Pitch' },
      workspace: { id: WS, name: 'Acme' },
      actor: { id: USER, name: 'Alex' },
      frontendUrl: 'https://app.example',
    });
    assert.equal(meta.slideId, SLIDE);
    assert.equal(meta.slideOrder, 3);
    assert.equal(meta.presentationId, PRESENTATION);
    assert.equal(
      meta.actionUrl,
      `https://app.example/workspaces/${WS}/presentations/${PRESENTATION}?slide=${SLIDE}`
    );
  });

  it('omits actionUrl when workspace/presentation ids are missing', () => {
    const meta = buildSlideAssignmentMetadata({ slide: { id: SLIDE } });
    assert.equal(meta.actionUrl, undefined);
  });
});

describe('setSlideAssigneeSchema', () => {
  const opts = { abortEarly: false, stripUnknown: true, convert: true };

  it('allows null to unassign', () => {
    const { error, value } = setSlideAssigneeSchema.validate(
      {
        params: { workspaceId: WS, presentationId: PRESENTATION, slideId: SLIDE },
        body: { assigneeId: null },
      },
      opts
    );
    assert.equal(error, undefined);
    assert.equal(value.body.assigneeId, null);
  });

  it('accepts a uuid assigneeId', () => {
    const { error } = setSlideAssigneeSchema.validate(
      {
        params: { workspaceId: WS, presentationId: PRESENTATION, slideId: SLIDE },
        body: { assigneeId: USER },
      },
      opts
    );
    assert.equal(error, undefined);
  });

  it('rejects a non-uuid assigneeId', () => {
    const { error } = setSlideAssigneeSchema.validate(
      {
        params: { workspaceId: WS, presentationId: PRESENTATION, slideId: SLIDE },
        body: { assigneeId: 'not-a-uuid' },
      },
      opts
    );
    assert.ok(error);
  });

  it('requires assigneeId to be present (use null, not omitted, to unassign)', () => {
    const { error } = setSlideAssigneeSchema.validate(
      {
        params: { workspaceId: WS, presentationId: PRESENTATION, slideId: SLIDE },
        body: {},
      },
      opts
    );
    assert.ok(error);
  });

  it('accepts non-uuid presentationId/slideId (cuid, not uuid)', () => {
    const { error } = setSlideAssigneeSchema.validate(
      {
        params: { workspaceId: WS, presentationId: PRESENTATION, slideId: SLIDE },
        body: { assigneeId: null },
      },
      opts
    );
    assert.equal(error, undefined);
  });
});

describe('slide assignment notification wiring', () => {
  it('maps SLIDE_ASSIGNED/SLIDE_UNASSIGNED to collaboration + workspaceTeamAlerts', () => {
    assert.equal(getCategoryForType('SLIDE_ASSIGNED'), CATEGORIES.COLLABORATION);
    assert.equal(getCategoryForType('SLIDE_UNASSIGNED'), CATEGORIES.COLLABORATION);
    assert.equal(getPreferenceKeyForType('SLIDE_ASSIGNED'), 'workspaceTeamAlerts');
    assert.equal(getPreferenceKeyForType('SLIDE_UNASSIGNED'), 'workspaceTeamAlerts');
    const collab = getTypesForCategory(CATEGORIES.COLLABORATION);
    assert.ok(collab.includes('SLIDE_ASSIGNED'));
    assert.ok(collab.includes('SLIDE_UNASSIGNED'));
  });
});
