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
 * Assignment is server-owned: only PATCH .../scenes/:sceneId/assignee may change it.
 * Editor autosaves replace Project.data wholesale with client scenes, which never carry a
 * fresh assignedToId (the client only holds the hydrated `assignee` object), so a naive
 * save would revert or drop an assignment. Re-apply the stored assignment by scene key and
 * strip client-sent assignment fields (including the hydrated assignee/assignedBy objects).
 * @param {object[]} incomingScenes scenes from the client save payload
 * @param {object[]} existingScenes scenes currently stored on the project
 * @returns {object[]}
 */
function preserveSceneAssignments(incomingScenes, existingScenes) {
  if (!Array.isArray(incomingScenes)) return incomingScenes;
  const stored = new Map();
  for (const scene of Array.isArray(existingScenes) ? existingScenes : []) {
    const key = sceneKey(scene);
    if (key && scene.assignedToId) stored.set(key, scene);
  }
  return incomingScenes.map((scene) => {
    if (!scene || typeof scene !== 'object') return scene;
    const {
      assignee: _assignee,
      assignedBy: _assignedBy,
      assignedToId: _assignedToId,
      assignedById: _assignedById,
      assignedAt: _assignedAt,
      ...rest
    } = scene;
    const prev = stored.get(sceneKey(scene));
    if (!prev) return rest;
    return {
      ...rest,
      assignedToId: prev.assignedToId,
      assignedById: prev.assignedById ?? null,
      assignedAt: prev.assignedAt ?? null,
    };
  });
}

/**
 * Clear a departed member from scene assignment fields (mirrors
 * project.dao.clearAssignmentsForUser for the DB-backed project/slide assignees).
 * - assignee: clear assignedToId + assignedById + assignedAt
 * - only assignedBy: clear assignedById
 * @param {object[]} scenes
 * @param {string} userId
 * @returns {{ scenes: object[], changed: boolean }}
 */
function clearUserFromSceneAssignments(scenes, userId) {
  if (!Array.isArray(scenes) || !userId) return { scenes, changed: false };
  let changed = false;
  const next = scenes.map((scene) => {
    if (!scene || typeof scene !== 'object') return scene;
    if (scene.assignedToId === userId) {
      changed = true;
      return { ...scene, assignedToId: null, assignedById: null, assignedAt: null };
    }
    if (scene.assignedById === userId) {
      changed = true;
      return { ...scene, assignedById: null };
    }
    return scene;
  });
  return { scenes: changed ? next : scenes, changed };
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
  preserveSceneAssignments,
  clearUserFromSceneAssignments,
  buildSceneAssignmentMetadata,
};
