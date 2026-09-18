/**
 * Shared assignment helpers for presentation slides.
 * Same workflow-only model as project.assignment.js, scoped to one Slide row
 * instead of a whole Project — a slide's assignee never changes who can open
 * or edit the deck.
 */
const { attachUsers } = require('../../shared/utils/attachUsers');

const SLIDE_USER_FIELD_MAP = [
  { sourceField: 'assignedToId', targetField: 'assignee' },
  { sourceField: 'assignedById', targetField: 'assignedBy' },
];

/**
 * Hydrate `assignee`/`assignedBy` { id, name, email } onto enriched slide(s).
 * @param {object[]} slides
 * @returns {Promise<object[]>}
 */
async function attachSlideAssignees(slides) {
  return attachUsers(slides, SLIDE_USER_FIELD_MAP);
}

/**
 * True when the desired assignee matches the slide's current assignee.
 * @param {{ assignedToId?: string | null }} slide
 * @param {string | null} nextAssigneeId
 */
function isSlideAssignmentUnchanged(slide, nextAssigneeId) {
  const current = slide?.assignedToId ?? null;
  const next = nextAssigneeId ?? null;
  return current === next;
}

/**
 * Inbox metadata + deep link for slide assignment notifications.
 * @param {{ slide: object, project: object, workspace?: object, actor?: object, frontendUrl?: string }} args
 */
function buildSlideAssignmentMetadata({ slide, project, workspace, actor, frontendUrl } = {}) {
  const base = frontendUrl ?? process.env.FRONTEND_URL ?? '';
  const workspaceId = project?.workspaceId || workspace?.id;
  const presentationId = project?.id;
  const metadata = {
    workspaceId,
    workspaceName: workspace?.name || null,
    presentationId,
    projectId: presentationId,
    projectType: 'PRESENTATION',
    projectName: project?.name || 'Untitled',
    slideId: slide?.id,
    slideOrder: slide?.order != null ? slide.order + 1 : null,
    assignedByUserId: actor?.id || null,
    assignedByName: actor?.name || 'Someone',
  };

  if (workspaceId && presentationId && slide?.id) {
    metadata.actionUrl = `${base}/workspaces/${workspaceId}/presentations/${presentationId}?slide=${slide.id}`;
  }

  return metadata;
}

module.exports = {
  attachSlideAssignees,
  isSlideAssignmentUnchanged,
  buildSlideAssignmentMetadata,
};
