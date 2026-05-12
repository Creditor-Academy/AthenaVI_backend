const { interpolate, spring } = require('remotion');

function clamp(value, min = 0, max = 1) {
  return Math.min(Math.max(value, min), max);
}

function getAnimationProgress(frame, animation) {
  const startFrame = Number(animation.startFrame || 0);
  const durationInFrames = Math.max(Number(animation.durationInFrames || 0), 1);
  const localFrame = frame - startFrame;

  if (localFrame <= 0) {
    return 0;
  }

  return clamp(localFrame / durationInFrames);
}

function buildAnimatedStyle({ frame, fps, placement, animations = [] }) {
  const baseScale = placement.scale ?? 1;
  const baseRotation = placement.rotation ?? 0;
  const baseOpacity = placement.opacity ?? 1;

  let translateX = 0;
  let translateY = 0;
  let opacity = baseOpacity;
  let scale = baseScale;
  let rotation = baseRotation;

  for (const animation of animations) {
    const progress = getAnimationProgress(frame, animation);
    const distance = Number(animation.distance ?? 80);
    const degrees = Number(animation.degrees ?? 20);

    switch (animation.type) {
      case 'fade-in':
        opacity *= interpolate(progress, [0, 1], [0, 1], {
          extrapolateLeft: 'clamp',
          extrapolateRight: 'clamp',
        });
        break;
      case 'fade-out':
        opacity *= interpolate(progress, [0, 1], [1, 0], {
          extrapolateLeft: 'clamp',
          extrapolateRight: 'clamp',
        });
        break;
      case 'slide-up':
        translateY += interpolate(progress, [0, 1], [distance, 0], {
          extrapolateLeft: 'clamp',
          extrapolateRight: 'clamp',
        });
        break;
      case 'slide-down':
        translateY += interpolate(progress, [0, 1], [-distance, 0], {
          extrapolateLeft: 'clamp',
          extrapolateRight: 'clamp',
        });
        break;
      case 'slide-left':
        translateX += interpolate(progress, [0, 1], [distance, 0], {
          extrapolateLeft: 'clamp',
          extrapolateRight: 'clamp',
        });
        break;
      case 'slide-right':
        translateX += interpolate(progress, [0, 1], [-distance, 0], {
          extrapolateLeft: 'clamp',
          extrapolateRight: 'clamp',
        });
        break;
      case 'zoom-in':
      case 'scale-in':
        scale *= interpolate(
          progress,
          [0, 1],
          [Number(animation.fromScale ?? 0.8), Number(animation.toScale ?? 1)],
          {
            extrapolateLeft: 'clamp',
            extrapolateRight: 'clamp',
          }
        );
        break;
      case 'zoom-out':
      case 'scale-out':
        scale *= interpolate(
          progress,
          [0, 1],
          [Number(animation.fromScale ?? 1.1), Number(animation.toScale ?? 1)],
          {
            extrapolateLeft: 'clamp',
            extrapolateRight: 'clamp',
          }
        );
        break;
      case 'rotate-in':
        rotation += interpolate(progress, [0, 1], [degrees, 0], {
          extrapolateLeft: 'clamp',
          extrapolateRight: 'clamp',
        });
        break;
      case 'rotate-out':
        rotation += interpolate(progress, [0, 1], [0, degrees], {
          extrapolateLeft: 'clamp',
          extrapolateRight: 'clamp',
        });
        break;
      case 'bounce': {
        const value = spring({
          fps,
          frame: Math.max(frame - Number(animation.startFrame || 0), 0),
          config: {
            damping: 10,
            stiffness: 120,
            mass: 0.5,
          },
          durationInFrames: Math.max(Number(animation.durationInFrames || 0), 1),
        });
        translateY -= value * Number(animation.amplitude ?? 24);
        break;
      }
      case 'pulse': {
        const cycles = Number(animation.cycles ?? 2);
        scale *= 1 + Math.sin(progress * Math.PI * cycles) * Number(animation.intensity ?? 0.08);
        break;
      }
      default:
        break;
    }
  }

  return {
    position: 'absolute',
    left: placement.x,
    top: placement.y,
    width: placement.width,
    height: placement.height,
    opacity,
    transform: `translate(${translateX}px, ${translateY}px) scale(${scale}) rotate(${rotation}deg)`,
    transformOrigin: 'center center',
  };
}

function resolveAnimatedText({ frame, text, animations = [] }) {
  const typewriter = animations.find((animation) => animation.type === 'typewriter');

  if (!typewriter || typeof text !== 'string') {
    return text;
  }

  const progress = getAnimationProgress(frame, typewriter);
  const visibleChars = Math.max(Math.floor(text.length * progress), 0);
  return text.slice(0, visibleChars);
}

module.exports = {
  buildAnimatedStyle,
  resolveAnimatedText,
};
