const { TRANSITION_TYPES } = require('../constants/videoEditor');

const TRANSITION_TYPE_ALIASES = {
  none: 'cut',
  'no-transition': 'cut',
  notransition: 'cut',
  crossfade: 'fade',
  crossFade: 'fade',
  dissolve: 'fade',
  fadein: 'fade',
  fadeIn: 'fade',
  fadeout: 'fade',
  fadeOut: 'fade',
  slideleft: 'slide-left',
  slideLeft: 'slide-left',
  slideright: 'slide-right',
  slideRight: 'slide-right',
  slideup: 'slide-up',
  slideUp: 'slide-up',
  slidedown: 'slide-down',
  slideDown: 'slide-down',
  wipeleft: 'wipe-left',
  wipeLeft: 'wipe-left',
  wiperight: 'wipe-right',
  wipeRight: 'wipe-right',
  zoomin: 'zoom-in',
  zoomIn: 'zoom-in',
  zoomout: 'zoom-out',
  zoomOut: 'zoom-out',
};

function normalizeTransitionType(raw) {
  if (raw == null || String(raw).trim() === '') return 'cut';
  const s = String(raw).trim();
  if (TRANSITION_TYPES.includes(s)) return s;
  if (TRANSITION_TYPE_ALIASES[s]) return TRANSITION_TYPE_ALIASES[s];
  const lower = s.toLowerCase();
  if (TRANSITION_TYPES.includes(lower)) return lower;
  if (TRANSITION_TYPE_ALIASES[lower]) return TRANSITION_TYPE_ALIASES[lower];
  const kebab = s
    .replace(/_/g, '-')
    .replace(/([a-z0-9])([A-Z])/g, '$1-$2')
    .toLowerCase();
  if (TRANSITION_TYPES.includes(kebab)) return kebab;
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
};
