function clamp(value, min = 0, max = 1) {
  return Math.min(Math.max(value, min), max);
}

function coerceAnimationsList(animations) {
  if (Array.isArray(animations)) {
    return animations.filter((item) => item && typeof item === 'object');
  }

  if (!animations || typeof animations !== 'object') {
    return [];
  }

  if (animations.in || animations.out) {
    const list = [];
    if (animations.in && typeof animations.in === 'object') {
      list.push({
        ...animations.in,
        type: animations.in.type || 'fade-in',
      });
    }
    if (animations.out && typeof animations.out === 'object') {
      list.push({
        ...animations.out,
        type: animations.out.type || 'fade-out',
      });
    }
    return list;
  }

  return Object.values(animations).filter((item) => item && typeof item === 'object');
}

function resolveAnimationStartFrame(animation, elementStartFrame = 0, elementDuration) {
  let startFrame = Number(animation.startFrame || 0);
  const duration = Number.isFinite(elementDuration) ? elementDuration : null;

  if (elementStartFrame > 0 && startFrame >= elementStartFrame) {
    const withinElement =
      duration == null || startFrame <= elementStartFrame + duration;
    if (withinElement) {
      startFrame -= elementStartFrame;
    }
  }

  return Math.max(0, startFrame);
}

function normalizeAnimationTimings(animations, elementStartFrame = 0, elementDuration) {
  return coerceAnimationsList(animations).map((animation) => ({
    ...animation,
    startFrame: resolveAnimationStartFrame(animation, elementStartFrame, elementDuration),
  }));
}

function normalizeTimedEffectStartFrame(effect, elementStartFrame = 0, elementDuration) {
  if (!effect || typeof effect !== 'object' || effect.startFrame == null) {
    return effect;
  }

  const startFrame = resolveAnimationStartFrame(
    {
      startFrame: effect.startFrame,
      durationInFrames: effect.durationInFrames,
    },
    elementStartFrame,
    elementDuration
  );

  return {
    ...effect,
    startFrame,
  };
}

module.exports = {
  clamp,
  coerceAnimationsList,
  resolveAnimationStartFrame,
  normalizeAnimationTimings,
  normalizeTimedEffectStartFrame,
};
