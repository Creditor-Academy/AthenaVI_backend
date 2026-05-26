const { generateHeygenRequestHash } = require('../../shared/utils/requestHash');

function scoreHeygenRow(row) {
  if (row.status === 'completed' && row.s3Key) return 4;
  if (row.status === 'completed') return 3;
  if (row.s3Key) return 2;
  return 1;
}

function pickBestHeygenRow(rows) {
  if (!rows?.length) return null;
  return [...rows].sort((a, b) => {
    const diff = scoreHeygenRow(b) - scoreHeygenRow(a);
    if (diff !== 0) return diff;
    return new Date(b.createdAt) - new Date(a.createdAt);
  })[0];
}

function indexHeygenRows(heygenRows) {
  const byHash = new Map();
  const bySceneId = new Map();
  const validIds = new Set();

  for (const row of heygenRows || []) {
    validIds.add(row.id);
    if (row.requestHash) {
      byHash.set(row.requestHash, row);
    }
    const sceneId = String(row.sceneId || '').trim();
    if (!sceneId) continue;
    if (!bySceneId.has(sceneId)) {
      bySceneId.set(sceneId, []);
    }
    bySceneId.get(sceneId).push(row);
  }

  return { byHash, bySceneId, validIds };
}

function resolveHeygenRowForAvatarElement({
  workspaceId,
  projectId,
  sceneId,
  content,
  byHash,
  bySceneId,
  validIds,
}) {
  const existingId = content?.heygenVideoId ? String(content.heygenVideoId).trim() : '';
  if (existingId && validIds.has(existingId)) {
    return { heygenVideoId: existingId, changed: false };
  }

  const fromHash = tryResolveByRequestHash({
    workspaceId,
    projectId,
    sceneId,
    content,
    byHash,
  });
  if (fromHash) {
    return { heygenVideoId: fromHash.id, changed: true };
  }

  const sceneRows = bySceneId.get(sceneId) || [];
  const best = pickBestHeygenRow(sceneRows);
  if (best) {
    return { heygenVideoId: best.id, changed: true };
  }

  if (existingId) {
    return { heygenVideoId: undefined, changed: true };
  }

  return { heygenVideoId: undefined, changed: false };
}

function tryResolveByRequestHash({ workspaceId, projectId, sceneId, content, byHash }) {
  const avatarId = content?.avatarId;
  const voiceId = content?.voiceId;
  const script = content?.script;

  if (!avatarId || !voiceId || script == null || String(script).trim() === '') {
    return null;
  }

  try {
    const requestHash = generateHeygenRequestHash({
      workspaceId,
      projectId,
      sceneId,
      avatarId,
      voiceId,
      script,
    });
    return byHash.get(requestHash) || null;
  } catch {
    return null;
  }
}

function buildRestoredAvatarElement({ scene, heygenRow }) {
  const sceneId = String(scene.sceneId).trim();
  const durationInFrames = Number(scene.durationInFrames) > 0 ? Number(scene.durationInFrames) : 150;

  return {
    id: `avatar_restored_${heygenRow.id.replace(/-/g, '').slice(0, 12)}`,
    type: 'avatar',
    layer: 10,
    startFrame: 0,
    durationInFrames,
    placement: {
      x: 0,
      y: 0,
      width: 520,
      height: 820,
      rotation: 0,
      scale: 1,
      opacity: 1,
    },
    content: {
      provider: 'heygen',
      sceneId,
      heygenVideoId: heygenRow.id,
      avatarId: '',
      voiceId: '',
      script: '',
    },
    animations: [],
  };
}

/**
 * Attach missing or stale `content.heygenVideoId` on avatar elements from persisted HeygenResponse rows.
 * Restores a placeholder avatar element when a scene clip exists but the editor payload dropped the element.
 * @returns {{ data: object, changed: boolean }}
 */
function rehydrateHeygenAvatarsInProjectData({ workspaceId, projectId, data, heygenRows }) {
  if (!data || !Array.isArray(data.scenes) || !heygenRows?.length) {
    return { data, changed: false };
  }

  const { byHash, bySceneId, validIds } = indexHeygenRows(heygenRows);
  let changed = false;

  const scenes = data.scenes.map((scene) => {
    const sceneId = String(scene?.sceneId || '').trim();
    if (!sceneId || !Array.isArray(scene.elements)) {
      return scene;
    }

    const hasAvatarElement = scene.elements.some((element) => element?.type === 'avatar');
    const sceneRows = bySceneId.get(sceneId) || [];
    const bestRow = pickBestHeygenRow(sceneRows);

    let elements = scene.elements.map((element) => {
      if (element?.type !== 'avatar') {
        return element;
      }

      const content = element.content && typeof element.content === 'object' ? element.content : {};
      const resolved = resolveHeygenRowForAvatarElement({
        workspaceId,
        projectId,
        sceneId,
        content,
        byHash,
        bySceneId,
        validIds,
      });

      if (!resolved.changed) {
        return element;
      }

      changed = true;
      const nextContent = { ...content };
      if (resolved.heygenVideoId) {
        nextContent.heygenVideoId = resolved.heygenVideoId;
        if (!nextContent.provider) {
          nextContent.provider = 'heygen';
        }
      } else {
        delete nextContent.heygenVideoId;
      }

      return { ...element, content: nextContent };
    });

    if (!hasAvatarElement && bestRow) {
      changed = true;
      elements = [...elements, buildRestoredAvatarElement({ scene, heygenRow: bestRow })];
    }

    return { ...scene, elements };
  });

  if (!changed) {
    return { data, changed: false };
  }

  return { data: { ...data, scenes }, changed: true };
}

module.exports = {
  rehydrateHeygenAvatarsInProjectData,
  pickBestHeygenRow,
};
