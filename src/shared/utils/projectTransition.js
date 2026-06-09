const { TRANSITION_TYPES } = require('../constants/videoEditor');

const TRANSITION_TYPE_ALIASES = {
  none: 'cut',
  'no-transition': 'cut',
  notransition: 'cut',
  crossfade: 'fade',
  crossFade: 'fade',
  fadein: 'fade',
  fadeIn: 'fade',
  fadeout: 'fade',
  fadeOut: 'fade',
  dissolve: 'dissolve',
  slideleft: 'slide-left',
  'slide left': 'slide-left',
  slideLeft: 'slide-left',
  slideright: 'slide-right',
  'slide right': 'slide-right',
  slideRight: 'slide-right',
  slideup: 'slide-up',
  'slide up': 'slide-up',
  slideUp: 'slide-up',
  slidedown: 'slide-down',
  'slide down': 'slide-down',
  slideDown: 'slide-down',
  wipeleft: 'wipe-left',
  wipeLeft: 'wipe-left',
  wiperight: 'wipe-right',
  wipeRight: 'wipe-right',
  zoomin: 'zoom-in',
  zoomIn: 'zoom-in',
  zoomout: 'zoom-out',
  zoomOut: 'zoom-out',
  'circle wipe in': 'circle-wipe-in',
  circlewipein: 'circle-wipe-in',
  circleWipeIn: 'circle-wipe-in',
  'circle wipe out': 'circle-wipe-out',
  circlewipeout: 'circle-wipe-out',
  circleWipeOut: 'circle-wipe-out',
  'colour wipe left': 'colour-wipe-left',
  'color wipe left': 'colour-wipe-left',
  colourwipeleft: 'colour-wipe-left',
  colorwipeleft: 'colour-wipe-left',
  colourWipeLeft: 'colour-wipe-left',
  colorWipeLeft: 'colour-wipe-left',
  'colour wipe right': 'colour-wipe-right',
  'color wipe right': 'colour-wipe-right',
  colourwiperight: 'colour-wipe-right',
  colorwiperight: 'colour-wipe-right',
  colourWipeRight: 'colour-wipe-right',
  colorWipeRight: 'colour-wipe-right',
  'colour wipe up': 'colour-wipe-up',
  'color wipe up': 'colour-wipe-up',
  colourwipeup: 'colour-wipe-up',
  colorwipeup: 'colour-wipe-up',
  colourWipeUp: 'colour-wipe-up',
  colorWipeUp: 'colour-wipe-up',
  'colour wipe down': 'colour-wipe-down',
  'color wipe down': 'colour-wipe-down',
  colourwipedown: 'colour-wipe-down',
  colorwipedown: 'colour-wipe-down',
  colourWipeDown: 'colour-wipe-down',
  colorWipeDown: 'colour-wipe-down',
  'line wipe left': 'line-wipe-left',
  linewipeleft: 'line-wipe-left',
  lineWipeLeft: 'line-wipe-left',
  'line wipe right': 'line-wipe-right',
  linewiperight: 'line-wipe-right',
  lineWipeRight: 'line-wipe-right',
  'line wipe up': 'line-wipe-up',
  linewipeup: 'line-wipe-up',
  lineWipeUp: 'line-wipe-up',
  'line wipe down': 'line-wipe-down',
  linewipedown: 'line-wipe-down',
  lineWipeDown: 'line-wipe-down',
  'match & move': 'match-move',
  'match and move': 'match-move',
  matchandmove: 'match-move',
  matchMove: 'match-move',
  'flow left': 'flow-left',
  flowleft: 'flow-left',
  flowLeft: 'flow-left',
  'flow right': 'flow-right',
  flowright: 'flow-right',
  flowRight: 'flow-right',
  'flow up': 'flow-up',
  flowup: 'flow-up',
  flowUp: 'flow-up',
  'flow down': 'flow-down',
  flowdown: 'flow-down',
  flowDown: 'flow-down',
  'stack left': 'stack-left',
  stackleft: 'stack-left',
  stackLeft: 'stack-left',
  'stack right': 'stack-right',
  stackright: 'stack-right',
  stackRight: 'stack-right',
  'stack up': 'stack-up',
  stackup: 'stack-up',
  stackUp: 'stack-up',
  'stack down': 'stack-down',
  stackdown: 'stack-down',
  stackDown: 'stack-down',
  chop: 'chop',
};

function toKebabTransitionId(raw) {
  return String(raw)
    .trim()
    .replace(/\s*&\s*/g, '-')
    .replace(/_/g, '-')
    .replace(/([a-z0-9])([A-Z])/g, '$1-$2')
    .replace(/\s+/g, '-')
    .toLowerCase();
}

function normalizeTransitionType(raw) {
  if (raw == null || String(raw).trim() === '') return 'cut';
  const s = String(raw).trim();
  if (TRANSITION_TYPES.includes(s)) return s;
  if (TRANSITION_TYPE_ALIASES[s]) return TRANSITION_TYPE_ALIASES[s];
  const lower = s.toLowerCase();
  if (TRANSITION_TYPES.includes(lower)) return lower;
  if (TRANSITION_TYPE_ALIASES[lower]) return TRANSITION_TYPE_ALIASES[lower];
  const kebab = toKebabTransitionId(s);
  if (TRANSITION_TYPES.includes(kebab)) return kebab;
  const colorKebab = kebab.replace(/^color-wipe-/, 'colour-wipe-');
  if (TRANSITION_TYPES.includes(colorKebab)) return colorKebab;
  return null;
}

function normalizeTransitionStep(step) {
  if (!step || typeof step !== 'object' || Array.isArray(step)) return null;
  const type = normalizeTransitionType(step.type);
  if (!type) return null;
  return {
    ...step,
    type,
    durationInFrames: Math.max(0, Math.trunc(Number(step.durationInFrames) || 0)),
  };
}

/**
 * Coerce editor transition payloads before Joi / persistence.
 * @returns {object|undefined} normalized transition, or undefined to omit
 * @returns {null} invalid — caller should fail validation
 */
function normalizeTransitionPayload(transition) {
  if (transition == null) return undefined;
  if (typeof transition !== 'object' || Array.isArray(transition)) return null;

  if (transition.in || transition.out) {
    const next = { ...transition };
    if (transition.in) {
      const inStep = normalizeTransitionStep(transition.in);
      if (!inStep) return null;
      next.in = inStep;
    }
    if (transition.out) {
      const outStep = normalizeTransitionStep(transition.out);
      if (!outStep) return null;
      next.out = outStep;
    }
    if (!next.in && !next.out) return undefined;
    return next;
  }

  if (transition.type != null) {
    const type = normalizeTransitionType(transition.type);
    if (!type) return null;
    return {
      ...transition,
      type,
      durationInFrames: Math.max(0, Math.trunc(Number(transition.durationInFrames) || 0)),
    };
  }

  if (Object.keys(transition).length === 0) return undefined;
  return null;
}

module.exports = {
  normalizeTransitionType,
  normalizeTransitionPayload,
  TRANSITION_TYPE_ALIASES,
  toKebabTransitionId,
};
