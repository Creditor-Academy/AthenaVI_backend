const { interpolate } = require('remotion');

function getDuration(transition) {
  return Number(transition?.durationInFrames || 0);
}

function getOverlapDuration(previousScene, nextScene) {
  return Math.max(getDuration(previousScene?.transition?.out), getDuration(nextScene?.transition?.in));
}

function buildSceneTimings(scenes) {
  const timings = [];
  let cursor = 0;

  scenes.forEach((scene, index) => {
    if (index > 0) {
      cursor -= getOverlapDuration(scenes[index - 1], scene);
    }

    timings.push({
      ...scene,
      startFrame: cursor,
    });

    cursor += Number(scene.durationInFrames || 0);
  });

  return {
    scenes: timings,
    durationInFrames: Math.max(cursor, 1),
  };
}

function applyTransitionStyle(target, transition, progress, phase) {
  if (!transition || transition.type === 'cut') {
    return target;
  }

  const clamped = Math.min(Math.max(progress, 0), 1);
  const direction = phase === 'in' ? 1 - clamped : clamped;

  switch (transition.type) {
    case 'fade':
      target.opacity *= phase === 'in' ? clamped : 1 - clamped;
      break;
    case 'slide-left':
      target.translateX += interpolate(direction, [0, 1], [-target.width, 0]);
      break;
    case 'slide-right':
      target.translateX += interpolate(direction, [0, 1], [target.width, 0]);
      break;
    case 'slide-up':
      target.translateY += interpolate(direction, [0, 1], [-target.height, 0]);
      break;
    case 'slide-down':
      target.translateY += interpolate(direction, [0, 1], [target.height, 0]);
      break;
    case 'wipe-left': {
      const value = phase === 'in' ? clamped : 1 - clamped;
      target.clipPath = `inset(0 ${(1 - value) * 100}% 0 0)`;
      break;
    }
    case 'wipe-right': {
      const value = phase === 'in' ? clamped : 1 - clamped;
      target.clipPath = `inset(0 0 0 ${(1 - value) * 100}%)`;
      break;
    }
    case 'zoom-in':
      target.scale *= phase === 'in'
        ? interpolate(clamped, [0, 1], [1.08, 1])
        : interpolate(clamped, [0, 1], [1, 0.92]);
      break;
    case 'zoom-out':
      target.scale *= phase === 'in'
        ? interpolate(clamped, [0, 1], [0.92, 1])
        : interpolate(clamped, [0, 1], [1, 1.08]);
      break;
    default:
      break;
  }

  return target;
}

function getSceneTransitionStyle({ frame, scene, width, height }) {
  const target = {
    opacity: 1,
    scale: 1,
    translateX: 0,
    translateY: 0,
    clipPath: undefined,
    width,
    height,
  };

  const enter = scene.transition?.in;
  const enterDuration = getDuration(enter);
  if (enter && enterDuration > 0 && frame <= enterDuration) {
    applyTransitionStyle(target, enter, frame / enterDuration, 'in');
  }

  const exit = scene.transition?.out;
  const exitDuration = getDuration(exit);
  const exitStart = Number(scene.durationInFrames || 0) - exitDuration;
  if (exit && exitDuration > 0 && frame >= exitStart) {
    applyTransitionStyle(target, exit, (frame - exitStart) / exitDuration, 'out');
  }

  return {
    opacity: target.opacity,
    clipPath: target.clipPath,
    transform: `translate(${target.translateX}px, ${target.translateY}px) scale(${target.scale})`,
  };
}

module.exports = {
  buildSceneTimings,
  getSceneTransitionStyle,
};
