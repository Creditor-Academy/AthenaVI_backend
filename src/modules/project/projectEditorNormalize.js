/**
 * Normalizes V2 editor payloads (clips, timing, style, scene presenter/generation)
 * for persistence and Remotion render (expects startFrame, placement, content.*).
 */

function normalizePlacement(placement) {
  const p = placement && typeof placement === 'object' ? placement : {};
  return {
    x: Number(p.x) || 0,
    y: Number(p.y) || 0,
    width: Number(p.width) > 0 ? Number(p.width) : 100,
    height: Number(p.height) > 0 ? Number(p.height) : 100,
    rotation: Number(p.rotation) || 0,
    scale: Number(p.scale) > 0 ? Number(p.scale) : 1,
    opacity: p.opacity != null ? Number(p.opacity) : 1,
  };
}

function normalizeTransition(transition) {
  if (!transition || typeof transition !== 'object') {
    return transition;
  }
  if (transition.in || transition.out) {
    return transition;
  }
  if (transition.type) {
    return {
      in: {
        type: transition.type,
        durationInFrames: Number(transition.durationInFrames) || 0,
        ...(transition.easing && { easing: transition.easing }),
        ...(transition.direction != null && { direction: transition.direction }),
      },
    };
  }
  return transition;
}

function mergeContentForRender(element) {
  const content = { ...(element.content && typeof element.content === 'object' ? element.content : {}) };
  const style = element.style && typeof element.style === 'object' ? element.style : {};
  const filters = element.filters && typeof element.filters === 'object' ? element.filters : {};

  if (element.type === 'text') {
    if (content.text == null && typeof element.text === 'string') {
      content.text = element.text;
    }
    Object.assign(content, style);
  }

  if (element.type === 'image' || element.type === 'video' || element.type === 'avatar') {
    if (style.objectFit && content.fit == null) {
      content.fit = style.objectFit;
    }
    if (Object.keys(filters).length > 0) {
      content.filters = { ...(content.filters || {}), ...filters };
    }
    if (style.borderRadius != null && content.borderRadius == null) {
      content.borderRadius = style.borderRadius;
    }
  }

  if (element.type === 'shape') {
    if (style.backgroundColor && content.fill == null) {
      content.fill = style.backgroundColor;
    }
    if (style.borderRadius != null && content.borderRadius == null) {
      content.borderRadius = style.borderRadius;
    }
    Object.assign(content, style);
  }

  if (element.type === 'audio' && element.audio && typeof element.audio === 'object') {
    content.audio = { ...(content.audio || {}), ...element.audio };
  }

  return content;
}

function normalizeElement(element) {
  if (!element || typeof element !== 'object') {
    return element;
  }

  const timing = element.timing && typeof element.timing === 'object' ? element.timing : {};
  const startFrame =
    element.startFrame != null ? Number(element.startFrame) : Number(timing.startFrame);
  const durationInFrames =
    element.durationInFrames != null
      ? Number(element.durationInFrames)
      : Number(timing.durationInFrames);

  return {
    ...element,
    startFrame: Number.isFinite(startFrame) ? startFrame : 0,
    durationInFrames: Number.isFinite(durationInFrames) && durationInFrames >= 1 ? durationInFrames : 1,
    placement: normalizePlacement(element.placement),
    content: mergeContentForRender(element),
    animations: Array.isArray(element.animations) ? element.animations : [],
  };
}

function normalizeScene(scene) {
  if (!scene || typeof scene !== 'object') {
    return scene;
  }

  const rawElements = Array.isArray(scene.elements)
    ? scene.elements
    : Array.isArray(scene.clips)
      ? scene.clips
      : [];

  const { clips: _clips, ...rest } = scene;

  return {
    ...rest,
    elements: rawElements.map(normalizeElement),
    transition: normalizeTransition(scene.transition),
  };
}

/**
 * @param {object|null|undefined} projectState
 * @returns {object}
 */
function normalizeEditorProjectData(projectState) {
  if (!projectState || typeof projectState !== 'object') {
    return projectState;
  }

  if (!Array.isArray(projectState.scenes)) {
    return projectState;
  }

  return {
    ...projectState,
    scenes: projectState.scenes.map(normalizeScene),
  };
}

/**
 * HeyGen fields may live on scene.presenter / scene.generation or avatar content.
 */
function getEffectiveHeygenFields(scene, content) {
  const presenter = scene?.presenter && typeof scene.presenter === 'object' ? scene.presenter : {};
  const generation = scene?.generation && typeof scene.generation === 'object' ? scene.generation : {};
  const c = content && typeof content === 'object' ? content : {};

  const heygenVideoIdRaw = c.heygenVideoId ?? generation.heygenVideoId ?? null;
  const heygenVideoId =
    heygenVideoIdRaw != null && String(heygenVideoIdRaw).trim() !== ''
      ? String(heygenVideoIdRaw).trim()
      : null;

  return {
    avatarId: (c.avatarId ?? presenter.avatarId ?? '').toString().trim() || null,
    voiceId: (c.voiceId ?? presenter.voiceId ?? '').toString().trim() || null,
    script: c.script ?? presenter.script ?? null,
    heygenVideoId,
    avatarType: c.avatarType ?? presenter.avatarType ?? null,
  };
}

module.exports = {
  normalizeEditorProjectData,
  normalizeScene,
  normalizeElement,
  getEffectiveHeygenFields,
};
