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

/**
 * Which inbox events fire after a slide assignee change.
 * Self-assign / no-op changes notify nobody.
 */
function slideAssignmentNotifications({ actorId, previousAssigneeId, nextAssigneeId } = {}) {
  const actor = actorId || null;
  const previous = previousAssigneeId || null;
  const next = nextAssigneeId || null;
  const events = [];
  if (next && next !== actor) {
    events.push({ type: 'SLIDE_ASSIGNED', userId: next });
  }
  if (previous && previous !== next && previous !== actor) {
    events.push({ type: 'SLIDE_UNASSIGNED', userId: previous, reassignedToId: next });
  }
  return events;
}

function fireSlideAssignmentNotifications(inbox, ctx) {
  const events = slideAssignmentNotifications({
    actorId: ctx?.actor?.id,
    previousAssigneeId: ctx?.previousAssigneeId,
    nextAssigneeId: ctx?.nextAssigneeId,
  });
  const jobs = events.map((event) => {
    const job =
      event.type === 'SLIDE_ASSIGNED'
        ? inbox.notifySlideAssigned(ctx)
        : inbox.notifySlideUnassigned({
            ...ctx,
            unassignedUserId: event.userId,
            reassignedToId: event.reassignedToId,
          });
    return Promise.resolve(job).catch((error) =>
      console.error(
        event.type === 'SLIDE_ASSIGNED'
          ? 'Slide assigned notification failed:'
          : 'Slide unassigned notification failed:',
        error
      )
    );
  });
  return { events, jobs };
}

module.exports = {
  attachSlideAssignees,
  isSlideAssignmentUnchanged,
  buildSlideAssignmentMetadata,
  slideAssignmentNotifications,
  fireSlideAssignmentNotifications,
};
