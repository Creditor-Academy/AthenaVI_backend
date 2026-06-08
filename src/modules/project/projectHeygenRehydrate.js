const { generateHeygenRequestHash } = require('../../shared/utils/requestHash');
const { getEffectiveHeygenFields, isHeygenAvatarElement } = require('./projectEditorNormalize');

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
  scene,
  content,
  byHash,
  bySceneId,
  validIds,
}) {
  const effective = getEffectiveHeygenFields(scene, content);
  const existingId = effective.heygenVideoId || '';
  if (existingId && validIds.has(existingId)) {
    return { heygenVideoId: existingId, changed: false, effective };
  }

  const fromHash = tryResolveByRequestHash({
    workspaceId,
    projectId,
    sceneId,
    effective,
    byHash,
  });
  if (fromHash) {
    return { heygenVideoId: fromHash.id, changed: true, effective };
  }

  const sceneRows = bySceneId.get(sceneId) || [];
  const best = pickBestHeygenRow(sceneRows);
  if (best) {
    return { heygenVideoId: best.id, changed: true, effective };
  }

  if (existingId) {
    return { heygenVideoId: undefined, changed: true, effective };
  }

  return { heygenVideoId: undefined, changed: false, effective };
}

function tryResolveByRequestHash({ workspaceId, projectId, sceneId, effective, byHash }) {
  const { avatarId, voiceId, script, avatarEngine } = effective;

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
      avatarEngine,
    });
    return byHash.get(requestHash) || null;
  } catch {
    return null;
  }
}

function applyHeygenFieldsToSceneAndElement(scene, element, heygenVideoId, effective) {
  const nextContent = {
    ...(element.content && typeof element.content === 'object' ? element.content : {}),
    provider: 'heygen',
    sceneId: String(scene.sceneId).trim(),
  };

  if (heygenVideoId) {
    nextContent.heygenVideoId = heygenVideoId;
  } else {
    delete nextContent.heygenVideoId;
  }

  if (effective.avatarId) nextContent.avatarId = effective.avatarId;
  if (effective.voiceId) nextContent.voiceId = effective.voiceId;
  if (effective.script != null && String(effective.script).trim() !== '') {
    nextContent.script = effective.script;
  }
  if (effective.avatarType) nextContent.avatarType = effective.avatarType;

  const presenter = {
    ...(scene.presenter && typeof scene.presenter === 'object' ? scene.presenter : {}),
  };
  if (effective.avatarId) presenter.avatarId = effective.avatarId;
  if (effective.voiceId) presenter.voiceId = effective.voiceId;
  if (effective.script != null) presenter.script = effective.script;
  if (effective.avatarType) presenter.avatarType = effective.avatarType;

  const generation = {
    ...(scene.generation && typeof scene.generation === 'object' ? scene.generation : {}),
  };
  if (heygenVideoId) {
    generation.heygenVideoId = heygenVideoId;
    if (!generation.status) generation.status = 'completed';
  } else {
    delete generation.heygenVideoId;
  }

  return {
    scene: { ...scene, presenter, generation },
    element: { ...element, content: nextContent },
  };
}

function buildRestoredAvatarElement({ scene, heygenRow, effective }) {
  const sceneId = String(scene.sceneId).trim();
  const durationInFrames = Number(scene.durationInFrames) > 0 ? Number(scene.durationInFrames) : 150;

  const base = {
    id: `avatar_restored_${heygenRow.id.replace(/-/g, '').slice(0, 12)}`,
    type: 'video',
    role: 'avatar',
    layer: 10,
    visible: true,
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
      avatarId: effective.avatarId || '',
      voiceId: effective.voiceId || '',
      script: effective.script != null ? String(effective.script) : '',
    },
    animations: [],
  };

  const { scene: nextScene, element } = applyHeygenFieldsToSceneAndElement(
    scene,
    base,
    heygenRow.id,
    {
      ...effective,
      heygenVideoId: heygenRow.id,
      script: effective.script ?? '',
    }
  );

  return { scene: nextScene, element };
}

/**
 * Attach missing or stale heygenVideoId on avatar elements from heygen_responses.
 * Reads scene.presenter / scene.generation and element.content.
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

    const hasAvatarElement = scene.elements.some((element) => isHeygenAvatarElement(element));
    const sceneRows = bySceneId.get(sceneId) || [];
    const bestRow = pickBestHeygenRow(sceneRows);

    let nextScene = scene;
    let elements = scene.elements.map((element) => {
      if (!isHeygenAvatarElement(element)) {
        return element;
      }

      const content = element.content && typeof element.content === 'object' ? element.content : {};
      const resolved = resolveHeygenRowForAvatarElement({
        workspaceId,
        projectId,
        sceneId,
        scene: nextScene,
        content,
        byHash,
        bySceneId,
        validIds,
      });

      if (!resolved.changed) {
        return element;
      }

      changed = true;
      const applied = applyHeygenFieldsToSceneAndElement(
        nextScene,
        element,
        resolved.heygenVideoId,
        resolved.effective
      );
      nextScene = applied.scene;
      return applied.element;
    });

    if (!hasAvatarElement && bestRow) {
      changed = true;
      const effective = getEffectiveHeygenFields(nextScene, {});
      const restored = buildRestoredAvatarElement({
        scene: nextScene,
        heygenRow: bestRow,
        effective,
      });
      nextScene = restored.scene;
      elements = [...elements, restored.element];
    }

    return { ...nextScene, elements };
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
