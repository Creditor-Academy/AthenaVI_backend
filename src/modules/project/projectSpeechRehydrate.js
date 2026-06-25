const { generateSpeechRequestHash } = require('../../shared/utils/requestHash');
const { extractAssetId } = require('../../shared/utils/projectAssetIds');

function getEffectiveSpeechFields(scene, content = {}) {
  const presenter = scene?.presenter && typeof scene.presenter === 'object' ? scene.presenter : {};
  const generation = scene?.generation && typeof scene.generation === 'object' ? scene.generation : {};
  const c = content && typeof content === 'object' ? content : {};

  return {
    voiceId: (c.voiceId ?? presenter.voiceId ?? generation.voiceId ?? '').toString().trim() || null,
    script: c.script ?? presenter.script ?? generation.script ?? null,
    speechGenerationId:
      (c.speechGenerationId ?? presenter.speechGenerationId ?? generation.speechGenerationId ?? '')
        .toString()
        .trim() || null,
    inputType: c.inputType ?? presenter.inputType ?? generation.inputType ?? 'text',
    speed:
      c.speed != null
        ? Number(c.speed)
        : presenter.speed != null
          ? Number(presenter.speed)
          : generation.speed != null
            ? Number(generation.speed)
            : 1,
    locale: c.locale ?? presenter.locale ?? generation.locale ?? null,
  };
}

function scoreSpeechRow(row) {
  if (row.status === 'completed' && row.s3Key) return 4;
  if (row.status === 'completed') return 3;
  if (row.s3Key) return 2;
  return 1;
}

function pickBestSpeechRow(rows) {
  if (!rows?.length) return null;
  return [...rows].sort((a, b) => {
    const diff = scoreSpeechRow(b) - scoreSpeechRow(a);
    if (diff !== 0) return diff;
    return new Date(b.createdAt) - new Date(a.createdAt);
  })[0];
}

function indexSpeechRows(speechRows) {
  const byHash = new Map();
  const bySceneId = new Map();
  const validIds = new Set();

  for (const row of speechRows || []) {
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

function tryResolveByRequestHash({ workspaceId, projectId, sceneId, effective, byHash }) {
  const { voiceId, script, speed, inputType, locale } = effective;

  if (!voiceId || script == null || String(script).trim() === '') {
    return null;
  }

  try {
    const requestHash = generateSpeechRequestHash({
      workspaceId,
      projectId,
      sceneId,
      voiceId,
      script,
      speed,
      inputType,
      locale,
    });
    return byHash.get(requestHash) || null;
  } catch {
    return null;
  }
}

function resolveSpeechRowForScene({
  workspaceId,
  projectId,
  sceneId,
  scene,
  byHash,
  bySceneId,
  validIds,
}) {
  const effective = getEffectiveSpeechFields(scene, {});
  const existingId = effective.speechGenerationId || '';
  if (existingId && validIds.has(existingId)) {
    return { speechGenerationId: existingId, changed: false, effective };
  }

  const fromHash = tryResolveByRequestHash({
    workspaceId,
    projectId,
    sceneId,
    effective,
    byHash,
  });
  if (fromHash) {
    return { speechGenerationId: fromHash.id, changed: true, effective };
  }

  const sceneRows = bySceneId.get(sceneId) || [];
  const best = pickBestSpeechRow(sceneRows);
  if (best) {
    return { speechGenerationId: best.id, changed: true, effective };
  }

  if (existingId) {
    return { speechGenerationId: undefined, changed: true, effective };
  }

  return { speechGenerationId: undefined, changed: false, effective };
}

function applySpeechFieldsToScene(scene, speechGenerationId, effective) {
  const presenter = {
    ...(scene.presenter && typeof scene.presenter === 'object' ? scene.presenter : {}),
  };
  if (effective.voiceId) presenter.voiceId = effective.voiceId;
  if (effective.script != null) presenter.script = effective.script;
  if (effective.inputType) presenter.inputType = effective.inputType;
  if (effective.speed != null) presenter.speed = effective.speed;
  if (effective.locale) presenter.locale = effective.locale;

  const generation = {
    ...(scene.generation && typeof scene.generation === 'object' ? scene.generation : {}),
  };
  if (effective.voiceId) generation.voiceId = effective.voiceId;
  if (effective.script != null) generation.script = effective.script;
  if (speechGenerationId) {
    generation.speechGenerationId = speechGenerationId;
    if (!generation.status) generation.status = 'completed';
  } else {
    delete generation.speechGenerationId;
  }

  if (speechGenerationId) {
    presenter.speechGenerationId = speechGenerationId;
  } else {
    delete presenter.speechGenerationId;
  }

  return { ...scene, presenter, generation };
}

function applySpeechToAudioElement(element, speechGenerationId, effective) {
  if (element?.type !== 'audio') {
    return element;
  }

  const content = element.content && typeof element.content === 'object' ? element.content : {};
  const nextContent = { ...content };
  if (speechGenerationId) {
    nextContent.speechGenerationId = speechGenerationId;
  } else {
    delete nextContent.speechGenerationId;
  }
  if (effective.voiceId) nextContent.voiceId = effective.voiceId;
  if (effective.script != null) nextContent.script = effective.script;

  return { ...element, content: nextContent };
}

/**
 * Attach missing or stale speechGenerationId on scenes from speech_generations.
 */
function rehydrateSpeechInProjectData({ workspaceId, projectId, data, speechRows }) {
  if (!data || !Array.isArray(data.scenes) || !speechRows?.length) {
    return { data, changed: false };
  }

  const { byHash, bySceneId, validIds } = indexSpeechRows(speechRows);
  let changed = false;

  const scenes = data.scenes.map((scene) => {
    const sceneId = String(scene?.sceneId || '').trim();
    if (!sceneId || !Array.isArray(scene.elements)) {
      return scene;
    }

    const resolved = resolveSpeechRowForScene({
      workspaceId,
      projectId,
      sceneId,
      scene,
      byHash,
      bySceneId,
      validIds,
    });

    if (!resolved.changed) {
      return scene;
    }

    changed = true;
    let nextScene = applySpeechFieldsToScene(scene, resolved.speechGenerationId, resolved.effective);
    const elements = scene.elements.map((element) => {
      const content = element.content && typeof element.content === 'object' ? element.content : {};
      const elementSpeechId = content.speechGenerationId;
      const hasUploadedAsset = Boolean(extractAssetId(content));
      if (
        element.type === 'audio' &&
        (elementSpeechId || resolved.speechGenerationId) &&
        !(hasUploadedAsset && !elementSpeechId)
      ) {
        const idToApply =
          elementSpeechId && validIds.has(elementSpeechId)
            ? elementSpeechId
            : resolved.speechGenerationId;
        return applySpeechToAudioElement(element, idToApply, resolved.effective);
      }
      return element;
    });

    return { ...nextScene, elements };
  });

  if (!changed) {
    return { data, changed: false };
  }

  return { data: { ...data, scenes }, changed: true };
}

module.exports = {
  rehydrateSpeechInProjectData,
  getEffectiveSpeechFields,
  pickBestSpeechRow,
};
