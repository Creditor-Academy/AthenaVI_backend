/**
 * Normalizes V2 editor payloads (clips, timing, style, scene presenter/generation)
 * for persistence and Remotion render (expects startFrame, placement, content.*).
 */

/** Typography keys mirrored in both `style` and `content` for text round-trip. */
const TEXT_TYPOGRAPHY_KEYS = [
  'fontFamily',
  'fontSize',
  'fontWeight',
  'fontStyle',
  'textTransform',
  'color',
  'backgroundColor',
  'textAlign',
  'lineHeight',
  'letterSpacing',
  'padding',
  'textDecoration',
  'textDecorationLine',
  'textDecorationColor',
  'textDecorationStyle',
  'textShadow',
  'boxShadow',
  'whiteSpace',
  'wordBreak',
  'headingLevel',
  'htmlTag',
  'tag',
  'underline',
  'bold',
  'italic',
  'variant',
];

const HEADING_TAGS = new Set(['h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'p']);

function inferHeadingTag(element, style, content) {
  const candidates = [
    style.htmlTag,
    style.tag,
    style.headingLevel,
    content.htmlTag,
    content.tag,
    content.headingLevel,
    element.role,
    element.headingLevel,
  ];
  for (const raw of candidates) {
    if (raw == null || String(raw).trim() === '') continue;
    const v = String(raw).trim().toLowerCase();
    if (HEADING_TAGS.has(v)) return v;
    const headingMatch = v.match(/^heading[-_]?([1-6])$/);
    if (headingMatch) return `h${headingMatch[1]}`;
  }
  return null;
}

function applyTextTypographyShortcuts(style, content) {
  const nextStyle = { ...style };
  const nextContent = { ...content };

  if (nextStyle.underline === true && !nextStyle.textDecoration && !nextContent.textDecoration) {
    nextStyle.textDecoration = 'underline';
    nextContent.textDecoration = 'underline';
  }
  if (nextStyle.bold === true && nextStyle.fontWeight == null && nextContent.fontWeight == null) {
    nextStyle.fontWeight = '700';
    nextContent.fontWeight = '700';
  }
  if (nextStyle.italic === true && !nextStyle.fontStyle && !nextContent.fontStyle) {
    nextStyle.fontStyle = 'italic';
    nextContent.fontStyle = 'italic';
  }

  return { style: nextStyle, content: nextContent };
}

/**
 * Keep typography in both `style` and `content` so clients reading either field reload correctly.
 */
function syncTextTypography(element) {
  if (element.type !== 'text' && element.type !== 'subtitle') {
    return element;
  }

  let content =
    element.content && typeof element.content === 'object'
      ? { ...element.content }
      : typeof element.content === 'string'
        ? { text: element.content }
        : {};

  if (content.text == null && typeof element.text === 'string') {
    content.text = element.text;
  }

  let style = element.style && typeof element.style === 'object' ? { ...element.style } : {};

  for (const key of TEXT_TYPOGRAPHY_KEYS) {
    if (style[key] != null && content[key] == null) {
      content[key] = style[key];
    } else if (content[key] != null && style[key] == null) {
      style[key] = content[key];
    }
  }

  const headingTag = inferHeadingTag(element, style, content);
  if (headingTag) {
    style.htmlTag = headingTag;
    style.tag = headingTag;
    content.htmlTag = headingTag;
    content.tag = headingTag;
  }

  ({ style, content } = applyTextTypographyShortcuts(style, content));

  return { ...element, content, style };
}

function clampOpacity(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) {
    return 1;
  }
  return Math.min(Math.max(n, 0), 1);
}

function normalizePlacement(placement) {
  const p = placement && typeof placement === 'object' ? placement : {};
  return {
    x: Number(p.x) || 0,
    y: Number(p.y) || 0,
    width: Number(p.width) > 0 ? Number(p.width) : 100,
    height: Number(p.height) > 0 ? Number(p.height) : 100,
    rotation: Number(p.rotation) || 0,
    scale: Number(p.scale) > 0 ? Number(p.scale) : 1,
    opacity: p.opacity != null ? clampOpacity(p.opacity) : 1,
  };
}

function resolvePlacementWithOpacity(element) {
  const rawPlacement = element.placement && typeof element.placement === 'object' ? element.placement : {};
  const style = element.style && typeof element.style === 'object' ? element.style : {};
  const content = element.content && typeof element.content === 'object' ? element.content : {};
  const placement = normalizePlacement(rawPlacement);

  if (rawPlacement.opacity != null) {
    return placement;
  }
  if (style.opacity != null) {
    return { ...placement, opacity: clampOpacity(style.opacity) };
  }
  if (content.opacity != null) {
    return { ...placement, opacity: clampOpacity(content.opacity) };
  }

  return placement;
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

  if (element.type === 'text' || element.type === 'subtitle') {
    if (content.text == null && typeof element.text === 'string') {
      content.text = element.text;
    }
    Object.assign(content, style);
  }

  if (element.type === 'image' || element.type === 'video' || element.type === 'avatar') {
    if (style.objectFit && content.fit == null) {
      content.fit = style.objectFit;
    }
    if (style.shape && content.shape == null) {
      content.shape = style.shape;
    }
    if (style.flipHorizontal != null && content.flipHorizontal == null) {
      content.flipHorizontal = style.flipHorizontal;
    }
    if (style.flipVertical != null && content.flipVertical == null) {
      content.flipVertical = style.flipVertical;
    }
    if (style.opacity != null && content.opacity == null) {
      content.opacity = style.opacity;
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
    if (style.shape && content.shape == null) {
      content.shape = style.shape;
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

  const synced = syncTextTypography(element);
  const timing = synced.timing && typeof synced.timing === 'object' ? synced.timing : {};
  const startFrame =
    synced.startFrame != null ? Number(synced.startFrame) : Number(timing.startFrame);
  const durationInFrames =
    synced.durationInFrames != null
      ? Number(synced.durationInFrames)
      : Number(timing.durationInFrames);

  const withContent = {
    ...synced,
    startFrame: Number.isFinite(startFrame) ? startFrame : 0,
    durationInFrames:
      Number.isFinite(durationInFrames) && durationInFrames >= 1 ? durationInFrames : 1,
    placement: resolvePlacementWithOpacity(synced),
    content: mergeContentForRender(synced),
    animations: Array.isArray(synced.animations) ? synced.animations : [],
  };

  return syncTextTypography(withContent);
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
  syncTextTypography,
  getEffectiveHeygenFields,
  TEXT_TYPOGRAPHY_KEYS,
};
