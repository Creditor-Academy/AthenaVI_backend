/**
 * Which slide elements PowerPoint (and Google Slides) can show natively, and which must be
 * exported as a picture cut from the editor renderer so they look the way they do in the
 * editor instead of turning into a plain rectangle or disappearing.
 *
 * Native (editable): text (with shadow / outline / glow / highlight / gradient), plain and
 * clip-path polygon shapes, gradients, dashed borders, photos, charts, tables. Pictures keep
 * their exact place and layer.
 *
 * `target`: 'powerpoint' (default) or 'google-slides'. Google Slides can't show gradient
 * fills, glow or hollow text, so for it those become pictures too.
 */

const { parsePolygonClipPath } = require('./pptxShapes');

const TARGETS = new Set(['powerpoint', 'google-slides']);
function normalizeTarget(target) {
  const t = String(target || '').toLowerCase();
  return TARGETS.has(t) ? t : 'powerpoint';
}

/** Shape kinds pptxgenjs draws with the same outline as the editor (no clip-path polygon). */
const NATIVE_SHAPE_KINDS = new Set([
  'rect',
  'rectangle',
  'square',
  'rounded-rect',
  'round-corner-rect',
  'pill',
  'circle',
  'ellipse',
  'oval',
  'line',
  'line-h',
  'line-v',
]);

/** Element effects PowerPoint has a native form for: a shadow, or a glow. */
const NATIVE_EFFECTS = new Set(['shadow', 'lift', 'glow', 'neon', 'echo']);
/** Text effects with a native form (shadow, outline, glow, highlight); the rest are pictures. */
const NATIVE_TEXT_EFFECTS = new Set(['shadow', 'lift', 'outline', 'hollow', 'neon', 'background']);

function isGradientFill(fill) {
  return Boolean(
    fill &&
      typeof fill === 'object' &&
      (fill.type === 'gradient' || fill.kind === 'radial' || Array.isArray(fill.stops))
  );
}

function effectType(content) {
  const fx = content?.effect;
  return fx && typeof fx === 'object' && fx.type && fx.type !== 'none' ? String(fx.type) : null;
}

function hasNonNativeEffect(content) {
  const type = effectType(content);
  return Boolean(type && !NATIVE_EFFECTS.has(type));
}

function maskType(mask) {
  const type = mask && typeof mask === 'object' ? mask.type : mask;
  return type && type !== 'none' ? String(type) : null;
}

function isCurvedText(c = {}) {
  return (
    c.shapeEffect === 'curve' ||
    c.shapeEffect === 'circle' ||
    c.textShape === 'curve' ||
    c.textShape === 'circle' ||
    (c.curveAmount != null && Number(c.curveAmount) !== 0)
  );
}

/**
 * Why an element should be a picture in PPTX, or null when it can be native.
 * @returns {string|null}
 */
function rasterReason(el, { target = 'powerpoint' } = {}) {
  if (!el || typeof el !== 'object') return null;
  const c = el.content || {};
  const slides = normalizeTarget(target) === 'google-slides';
  switch (el.type) {
    case 'text':
    case 'textbox':
      if (isCurvedText(c)) return 'curved text';
      if (c.textEffect && c.textEffect !== 'none' && !NATIVE_TEXT_EFFECTS.has(c.textEffect)) {
        return `text effect ${c.textEffect}`;
      }
      if (slides && (c.textEffect === 'hollow' || c.textEffect === 'neon')) return `text effect ${c.textEffect}`;
      if (slides && (isGradientFill(c.fill) || isGradientFill(c.color))) return 'gradient text';
      return null;
    case 'shape': {
      const kind = String(c.shape || 'rect').toLowerCase();
      if (c.deviceFrame || kind === 'device-frame') return 'device frame';
      if (c.clipPath && !parsePolygonClipPath(c.clipPath)) return `shape ${kind}`;
      if (!c.clipPath && !NATIVE_SHAPE_KINDS.has(kind)) return `shape ${kind}`;
      if (c.clipPath && c.borderStyle && c.borderStyle !== 'solid') return `${c.borderStyle} border`;
      if (c.borderStyle && !['solid', 'dashed', 'dotted'].includes(c.borderStyle)) return `${c.borderStyle} border`;
      if (slides && isGradientFill(c.fill)) return 'gradient fill';
      if (c.boxShadow || c.shadow) return 'shadow';
      if (c.screenUrl || c.url || c.src) return 'image in shape';
      if (hasNonNativeEffect(c)) return `effect ${effectType(c)}`;
      return null;
    }
    case 'image':
      // An empty image slot: the editor draws a placeholder picture, not a grey box.
      if (!(c.url || c.src || c.s3Key)) return 'image placeholder';
      // Stored as { type: 'circle' | 'oval' | 'hexagon' | 'blob' | 'fade' } (older decks: a string).
      if (maskType(c.imageMask)) return 'image mask';
      if (c.clipPath) return 'clipped image';
      if (c.filter || c.cssFilter) return 'image filter';
      if (c.edgeFade) return 'edge fade';
      if (Number(c.borderRadius) > 0) return 'rounded corners';
      if (c.deviceFrame) return 'device frame';
      if (hasNonNativeEffect(c)) return `effect ${effectType(c)}`;
      return null;
    case 'icon':
    case 'graphic':
      // Already pictures in PPTX; the editor's tinting and sizing are matched exactly.
      return 'icon / graphic';
    case 'embed':
    case 'link':
      return 'embed';
    default:
      return null;
  }
}

/** Stage px of room around an element for shadows / glows painted past its box. */
function captureMargin(el) {
  const c = el?.content || {};
  if (effectType(c) || c.textEffect || c.boxShadow || c.shadow) return 40;
  return 2;
}

/**
 * The slide's background must be a picture: an image (always), or a gradient for Google
 * Slides (PowerPoint gets a native gradient background).
 */
function needsBackgroundPicture(slide, { target = 'powerpoint' } = {}) {
  const doc = slide?.elements || {};
  if (doc.backgroundImage || slide?.backgroundImage || doc.backgroundFromElement) return true;
  if (normalizeTarget(target) !== 'google-slides') return false;
  const fill = doc.backgroundFill || slide?.backgroundFill;
  if (isGradientFill(fill)) return true;
  const start = doc.backgroundGradientStart || slide?.backgroundGradientStart;
  const end = doc.backgroundGradientEnd || slide?.backgroundGradientEnd;
  return Boolean(start && end);
}

/**
 * What to capture for each slide. Charts are always captured too, but only used if the native
 * chart can't be built (`fallbackOnly`).
 * @returns {Array<{ slideId: string, background: boolean,
 *   elements: Array<{ id: string, reason: string, margin: number, fallbackOnly?: boolean }> }>}
 */
function pptxRasterPlan(slides = [], { target = 'powerpoint' } = {}) {
  return slides.map((slide) => {
    const elements = [];
    for (const el of slide?.elements?.elements || []) {
      if (!el?.id || el.type === 'group') continue;
      if (el.type === 'chart') {
        elements.push({ id: el.id, reason: 'chart (used only if the native chart fails)', margin: 2, fallbackOnly: true });
        continue;
      }
      const reason = rasterReason(el, { target });
      if (reason) elements.push({ id: el.id, reason, margin: captureMargin(el) });
    }
    return { slideId: slide.id, background: needsBackgroundPicture(slide, { target }), elements };
  });
}

module.exports = {
  NATIVE_SHAPE_KINDS,
  NATIVE_TEXT_EFFECTS,
  normalizeTarget,
  isGradientFill,
  rasterReason,
  captureMargin,
  needsBackgroundPicture,
  pptxRasterPlan,
};
