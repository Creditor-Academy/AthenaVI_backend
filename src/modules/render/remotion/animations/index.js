const { interpolate, spring } = require('remotion');
const {
  coerceAnimationsList,
  getAnimationProgress,
  resolveAnimationStartFrame,
} = require('./timing');

function buildAnimatedStyle({
  frame,
  fps,
  placement,
  animations = [],
  elementStartFrame = 0,
  elementDuration,
  flipHorizontal = false,
  flipVertical = false,
}) {
  const baseScale = placement.scale ?? 1;
  const baseRotation = placement.rotation ?? 0;
  const baseOpacity = placement.opacity ?? 1;

  let translateX = 0;
  let translateY = 0;
  let opacity = baseOpacity;
  let scale = baseScale;
  let rotation = baseRotation;

  const duration =
    elementDuration != null
      ? elementDuration
      : Number.isFinite(Number(placement?.durationInFrames))
        ? Number(placement.durationInFrames)
        : undefined;

  for (const animation of coerceAnimationsList(animations)) {
    const progress = getAnimationProgress(frame, animation, elementStartFrame, duration);
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
        const bounceStart = resolveAnimationStartFrame(
          animation,
          elementStartFrame,
          duration
        );
        const value = spring({
          fps,
          frame: Math.max(frame - bounceStart, 0),
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

  const flipX = flipHorizontal ? -1 : 1;
  const flipY = flipVertical ? -1 : 1;
  const flipPart = flipX !== 1 || flipY !== 1 ? ` scale(${flipX}, ${flipY})` : '';

  return {
    position: 'absolute',
    left: placement.x,
    top: placement.y,
    width: placement.width,
    height: placement.height,
    opacity,
    transform: `translate(${translateX}px, ${translateY}px) rotate(${rotation}deg) scale(${scale})${flipPart}`,
    transformOrigin: 'center center',
  };
}

function resolveAnimatedText({
  frame,
  text,
  animations = [],
  elementStartFrame = 0,
  elementDuration,
}) {
  const typewriter = coerceAnimationsList(animations).find(
    (animation) => animation.type === 'typewriter'
  );

  if (!typewriter || typeof text !== 'string') {
    return text;
  }

  const progress = getAnimationProgress(frame, typewriter, elementStartFrame, elementDuration);
  const visibleChars = Math.max(Math.floor(text.length * progress), 0);
  return text.slice(0, visibleChars);
}

module.exports = {
  buildAnimatedStyle,
  resolveAnimatedText,
};
