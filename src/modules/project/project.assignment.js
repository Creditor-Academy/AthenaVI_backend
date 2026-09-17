/**
 * Shared assignment query helpers for Project list endpoints.
 * Assignment is workflow metadata on Project (VIDEO + PRESENTATION), not ACL.
 */

/**
 * Build a Prisma `where` fragment from validated list query params.
 * @param {{ assignedTo?: string, assigneeId?: string, unassigned?: boolean }} query
 * @param {string} [userId] required when assignedTo === 'me'
 * @returns {Record<string, unknown>}
 */
function buildAssignmentWhere(query = {}, userId) {
  if (query.assignedTo === 'me') {
    // Prisma ignores `{ assignedToId: undefined }` (would return every row).
    if (!userId) {
      return { assignedToId: { in: [] } };
    }
    return { assignedToId: userId };
  }
  if (query.assigneeId) {
    return { assignedToId: query.assigneeId };
  }
  if (query.unassigned === true) {
    return { assignedToId: null };
  }
  return {};
}

/**
 * Inbox metadata + deep link. PRESENTATION must not use the video editor path.
 * @param {{ project: object, workspace?: object, actor?: object, frontendUrl?: string }} args
 */
function buildProjectAssignmentMetadata({ project, workspace, actor, frontendUrl } = {}) {
  const base = frontendUrl ?? process.env.FRONTEND_URL ?? '';
  const workspaceId = project?.workspaceId || workspace?.id;
  const projectId = project?.id;
  const projectType = project?.type || 'VIDEO';
  const metadata = {
    workspaceId,
    workspaceName: workspace?.name || null,
    projectId,
    projectName: project?.name || 'Untitled',
    projectType,
    assignedByUserId: actor?.id || null,
    assignedByName: actor?.name || 'Someone',
  };

  if (projectType === 'PRESENTATION' && workspaceId && projectId) {
    metadata.presentationId = projectId;
    metadata.actionUrl = `${base}/workspaces/${workspaceId}/presentations/${projectId}`;
  }

  return metadata;
}

/**
 * Joi fragment for mutually exclusive assignment filters.
 * Reuse in project / presentation / library list schemas.
 */
function assignmentListQueryJoi(Joi) {
  return {
    assignedTo: Joi.string().valid('me').optional(),
    assigneeId: Joi.string().uuid().optional(),
    unassigned: Joi.boolean().optional(),
  };
}

/**
 * Apply oxor on assignment keys after the object is built.
 * @param {import('joi').ObjectSchema} querySchema
 * @param {typeof import('joi')} Joi
 */
function withAssignmentOxor(querySchema, Joi) {
  return querySchema.oxor('assignedTo', 'assigneeId', 'unassigned');
}

/**
 * True when the desired assignee matches the project's current assignee.
 * @param {{ assignedToId?: string | null }} project
 * @param {string | null} nextAssigneeId
 */
function isAssignmentUnchanged(project, nextAssigneeId) {
  const current = project?.assignedToId ?? null;
  const next = nextAssigneeId ?? null;
  return current === next;
}

module.exports = {
  buildAssignmentWhere,
  assignmentListQueryJoi,
  withAssignmentOxor,
  isAssignmentUnchanged,
  buildProjectAssignmentMetadata,
};
