/**
 * Shared assignment helpers for VIDEO project scenes.
 * Same workflow-only model as project.assignment.js / presentation/slideAssignment.js,
 * but scenes are NOT a normalized DB row — they're objects inside Project.data.scenes[]
 * (a JSON column), keyed by `sceneId` (older/template-appended scenes) or `id` (scenes
 * created client-side always carry both, kept in sync). All helpers here operate on
 * plain scene objects, not Prisma rows.
 */
const { attachUsers } = require('../../shared/utils/attachUsers');

const SCENE_USER_FIELD_MAP = [
  { sourceField: 'assignedToId', targetField: 'assignee' },
  { sourceField: 'assignedById', targetField: 'assignedBy' },
];

/** The stable id of a scene, whichever key it was stored under. */
function sceneKey(scene) {
  return scene?.sceneId || scene?.id || null;
}

/**
 * Hydrate `assignee`/`assignedBy` { id, name, email } onto scene objects.
 * @param {object[]} scenes
 * @returns {Promise<object[]>}
 */
async function attachSceneAssignees(scenes) {
  return attachUsers(Array.isArray(scenes) ? scenes : [], SCENE_USER_FIELD_MAP);
}

/**
 * True when the desired assignee matches the scene's current assignee.
 * @param {{ assignedToId?: string | null }} scene
 * @param {string | null} nextAssigneeId
 */
function isSceneAssignmentUnchanged(scene, nextAssigneeId) {
  const current = scene?.assignedToId ?? null;
  const next = nextAssigneeId ?? null;
  return current === next;
}

/**
 * Inbox metadata + deep link for scene assignment notifications.
 * @param {{ scene: object, project: object, workspace?: object, actor?: object, frontendUrl?: string }} args
 */
function buildSceneAssignmentMetadata({ scene, project, workspace, actor, frontendUrl } = {}) {
  const base = frontendUrl ?? process.env.FRONTEND_URL ?? '';
  const workspaceId = project?.workspaceId || workspace?.id;
  const projectId = project?.id;
  const sceneId = sceneKey(scene);
  const metadata = {
    workspaceId,
    workspaceName: workspace?.name || null,
    projectId,
    projectName: project?.name || 'Untitled',
    projectType: 'VIDEO',
    sceneId,
    sceneName: scene?.name || null,
    sceneOrder: scene?.order != null ? scene.order + 1 : null,
    assignedByUserId: actor?.id || null,
    assignedByName: actor?.name || 'Someone',
  };

  if (workspaceId && projectId && sceneId) {
    metadata.actionUrl = `${base}/workspaces/${workspaceId}/projects/${projectId}?scene=${sceneId}`;
  }

  return metadata;
}

module.exports = {
  sceneKey,
  attachSceneAssignees,
  isSceneAssignmentUnchanged,
  buildSceneAssignmentMetadata,
};
