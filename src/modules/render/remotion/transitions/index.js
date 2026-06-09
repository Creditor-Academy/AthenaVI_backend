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

function createTransitionTarget(width, height) {
  return {
    opacity: 1,
    scale: 1,
    translateX: 0,
    translateY: 0,
    clipPath: undefined,
    filter: undefined,
    wipeColor: undefined,
    width,
    height,
  };
}

function applyInsetWipe(target, value, edge) {
  const hidden = (1 - value) * 100;
  switch (edge) {
    case 'left':
      target.clipPath = `inset(0 ${hidden}% 0 0)`;
      break;
    case 'right':
      target.clipPath = `inset(0 0 0 ${hidden}%)`;
      break;
    case 'up':
      target.clipPath = `inset(${hidden}% 0 0 0)`;
      break;
    case 'down':
      target.clipPath = `inset(0 0 ${hidden}% 0)`;
      break;
    default:
      break;
  }
}

function applyLineWipe(target, value, edge) {
  const pct = value * 100;
  switch (edge) {
    case 'left':
      target.clipPath = `polygon(0 0, ${pct}% 0, ${pct}% 100%, 0 100%)`;
      break;
    case 'right':
      target.clipPath = `polygon(${100 - pct}% 0, 100% 0, 100% 100%, ${100 - pct}% 100%)`;
      break;
    case 'up':
      target.clipPath = `polygon(0 0, 100% 0, 100% ${pct}%, 0 ${pct}%)`;
      break;
    case 'down':
      target.clipPath = `polygon(0 ${100 - pct}%, 100% ${100 - pct}%, 100% 100%, 0 100%)`;
      break;
    default:
      break;
  }
}

function applyColourWipe(target, transition, value, edge) {
  applyInsetWipe(target, value, edge);
  target.wipeColor = transition.color || transition.wipeColor || '#ffffff';
}

function applyFlow(target, direction, directionValue, clamped, phase) {
  const blurMax = 10;
  const blurAmount = phase === 'in' ? (1 - clamped) * blurMax : clamped * blurMax;
  target.filter = blurAmount > 0.1 ? `blur(${blurAmount}px)` : undefined;

  switch (direction) {
    case 'left':
      target.translateX += interpolate(directionValue, [0, 1], [-target.width * 0.6, 0]);
      break;
    case 'right':
      target.translateX += interpolate(directionValue, [0, 1], [target.width * 0.6, 0]);
      break;
    case 'up':
      target.translateY += interpolate(directionValue, [0, 1], [-target.height * 0.6, 0]);
      break;
    case 'down':
      target.translateY += interpolate(directionValue, [0, 1], [target.height * 0.6, 0]);
      break;
    default:
      break;
  }
}

function applyStack(target, direction, directionValue) {
  const offset = 0.18;
  switch (direction) {
    case 'left':
      target.translateX += interpolate(directionValue, [0, 1], [-target.width * offset, 0]);
      break;
    case 'right':
      target.translateX += interpolate(directionValue, [0, 1], [target.width * offset, 0]);
      break;
    case 'up':
      target.translateY += interpolate(directionValue, [0, 1], [-target.height * offset, 0]);
      break;
    case 'down':
      target.translateY += interpolate(directionValue, [0, 1], [target.height * offset, 0]);
      break;
    default:
      break;
  }
  target.scale *= interpolate(directionValue, [0, 1], [0.9, 1]);
}

function applyTransitionStyle(target, transition, progress, phase) {
  if (!transition || transition.type === 'cut') {
    return target;
  }

  const clamped = Math.min(Math.max(progress, 0), 1);
  const direction = phase === 'in' ? 1 - clamped : clamped;
  const reveal = phase === 'in' ? clamped : 1 - clamped;

  switch (transition.type) {
    case 'fade':
    case 'dissolve':
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
    case 'wipe-left':
      applyInsetWipe(target, reveal, 'left');
      break;
    case 'wipe-right':
      applyInsetWipe(target, reveal, 'right');
      break;
    case 'circle-wipe-in':
      target.clipPath = `circle(${reveal * 150}% at 50% 50%)`;
      break;
    case 'circle-wipe-out':
      target.clipPath = `circle(${(1 - reveal) * 150}% at 50% 50%)`;
      break;
    case 'colour-wipe-left':
      applyColourWipe(target, transition, reveal, 'left');
      break;
    case 'colour-wipe-right':
      applyColourWipe(target, transition, reveal, 'right');
      break;
    case 'colour-wipe-up':
      applyColourWipe(target, transition, reveal, 'up');
      break;
    case 'colour-wipe-down':
      applyColourWipe(target, transition, reveal, 'down');
      break;
    case 'line-wipe-left':
      applyLineWipe(target, reveal, 'left');
      break;
    case 'line-wipe-right':
      applyLineWipe(target, reveal, 'right');
      break;
    case 'line-wipe-up':
      applyLineWipe(target, reveal, 'up');
      break;
    case 'line-wipe-down':
      applyLineWipe(target, reveal, 'down');
      break;
    case 'match-move':
      if (phase === 'in') {
        target.scale *= interpolate(clamped, [0, 1], [1.12, 1]);
        target.translateX += interpolate(clamped, [0, 1], [-target.width * 0.04, 0]);
        target.translateY += interpolate(clamped, [0, 1], [-target.height * 0.04, 0]);
      } else {
        target.scale *= interpolate(clamped, [0, 1], [1, 1.12]);
        target.translateX += interpolate(clamped, [0, 1], [0, target.width * 0.04]);
        target.translateY += interpolate(clamped, [0, 1], [0, target.height * 0.04]);
      }
      break;
    case 'flow-left':
      applyFlow(target, 'left', direction, clamped, phase);
      break;
    case 'flow-right':
      applyFlow(target, 'right', direction, clamped, phase);
      break;
    case 'flow-up':
      applyFlow(target, 'up', direction, clamped, phase);
      break;
    case 'flow-down':
      applyFlow(target, 'down', direction, clamped, phase);
      break;
    case 'stack-left':
      applyStack(target, 'left', direction);
      break;
    case 'stack-right':
      applyStack(target, 'right', direction);
      break;
    case 'stack-up':
      applyStack(target, 'up', direction);
      break;
    case 'stack-down':
      applyStack(target, 'down', direction);
      break;
    case 'chop': {
      const split = reveal * 50;
      target.clipPath = `inset(${50 - split}% 0 ${50 - split}% 0)`;
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
  const target = createTransitionTarget(width, height);

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
    filter: target.filter,
    wipeColor: target.wipeColor,
    transform: `translate(${target.translateX}px, ${target.translateY}px) scale(${target.scale})`,
  };
}

module.exports = {
  buildSceneTimings,
  getSceneTransitionStyle,
  applyTransitionStyle,
};
