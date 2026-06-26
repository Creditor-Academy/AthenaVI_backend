const { Easing } = require('remotion');
const {
  clamp,
  coerceAnimationsList,
  resolveAnimationStartFrame,
  normalizeAnimationTimings,
  normalizeTimedEffectStartFrame,
} = require('../../../../shared/utils/animationTiming');

function normalizeEasingKey(easing) {
  return String(easing || 'linear')
    .trim()
    .replace(/([a-z])([A-Z])/g, '$1-$2')
    .toLowerCase();
}

function applyEasing(progress, easing) {
  const key = normalizeEasingKey(easing);
  if (!key || key === 'linear') {
    return progress;
  }

  const easingMap = {
    linear: (value) => value,
    ease: Easing.inOut(Easing.ease),
    'ease-in': Easing.in(Easing.ease),
    easein: Easing.in(Easing.ease),
    'ease-out': Easing.out(Easing.ease),
    easeout: Easing.out(Easing.ease),
    'ease-in-out': Easing.inOut(Easing.ease),
    easeinout: Easing.inOut(Easing.ease),
    'ease-in-quad': Easing.in(Easing.quad),
    easeinquad: Easing.in(Easing.quad),
    'ease-out-quad': Easing.out(Easing.quad),
    easeoutquad: Easing.out(Easing.quad),
    'ease-in-out-quad': Easing.inOut(Easing.quad),
    easeinoutquad: Easing.inOut(Easing.quad),
    'ease-in-cubic': Easing.in(Easing.cubic),
    easeincubic: Easing.in(Easing.cubic),
    'ease-out-cubic': Easing.out(Easing.cubic),
    easeoutcubic: Easing.out(Easing.cubic),
    'ease-in-out-cubic': Easing.inOut(Easing.cubic),
    easeinoutcubic: Easing.inOut(Easing.cubic),
  };

  const easingFn = easingMap[key];
  if (typeof easingFn === 'function') {
    return clamp(easingFn(progress));
  }

  return progress;
}

function getAnimationProgress(frame, animation, elementStartFrame = 0, elementDuration) {
  const startFrame = resolveAnimationStartFrame(animation, elementStartFrame, elementDuration);
  const durationInFrames = Math.max(Number(animation.durationInFrames || 0), 1);
  const localFrame = frame - startFrame;

  if (localFrame <= 0) {
    return 0;
  }

  const linearProgress = clamp(localFrame / durationInFrames);
  return applyEasing(linearProgress, animation.easing);
}

module.exports = {
  clamp,
  coerceAnimationsList,
  resolveAnimationStartFrame,
  applyEasing,
  getAnimationProgress,
  normalizeAnimationTimings,
  normalizeTimedEffectStartFrame,
};
