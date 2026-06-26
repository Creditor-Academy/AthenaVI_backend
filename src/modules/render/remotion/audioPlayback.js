const { interpolate } = require('remotion');
const {
  collectAudioSettings,
  normalizeAudioSettings,
  AUDIO_PLAYBACK_RATE_MIN,
  AUDIO_PLAYBACK_RATE_MAX,
} = require('../../../shared/utils/audioSettings');
const {
  clamp,
  coerceAnimationsList,
  getAnimationProgress,
  normalizeTimedEffectStartFrame,
} = require('./animations/timing');

function applyFadeIn(volume, frame, fadeIn, elementStartFrame = 0, elementDuration) {
  if (!fadeIn || typeof fadeIn !== 'object') {
    return volume;
  }

  const durationInFrames = Math.max(Number(fadeIn.durationInFrames) || 0, 0);
  if (durationInFrames <= 0) {
    return volume;
  }

  const normalizedFade = normalizeTimedEffectStartFrame(
    fadeIn,
    elementStartFrame,
    elementDuration
  );
  const progress = getAnimationProgress(
    frame,
    {
      startFrame: normalizedFade.startFrame || 0,
      durationInFrames,
      easing: normalizedFade.easing,
    },
    elementStartFrame,
    elementDuration
  );
  return volume * progress;
}

function applyFadeOut(volume, frame, fadeOut, durationInFrames, elementStartFrame = 0) {
  if (!fadeOut || typeof fadeOut !== 'object') {
    return volume;
  }

  const fadeDuration = Math.max(Number(fadeOut.durationInFrames) || 0, 0);
  if (fadeDuration <= 0) {
    return volume;
  }

  const normalizedFade = normalizeTimedEffectStartFrame(
    {
      ...fadeOut,
      startFrame:
        fadeOut.startFrame != null
          ? fadeOut.startFrame
          : Math.max(durationInFrames - fadeDuration, 0),
    },
    elementStartFrame,
    durationInFrames
  );
  const progress = getAnimationProgress(
    frame,
    {
      startFrame: normalizedFade.startFrame,
      durationInFrames: fadeDuration,
      easing: normalizedFade.easing,
    },
    elementStartFrame,
    durationInFrames
  );

  return volume * (1 - progress);
}

function applyAnimationFades(volume, frame, animations, elementStartFrame = 0, elementDuration) {
  let nextVolume = volume;
  for (const animation of coerceAnimationsList(animations)) {
    const progress = getAnimationProgress(frame, animation, elementStartFrame, elementDuration);

    if (animation.type === 'fade-in') {
      nextVolume *= interpolate(progress, [0, 1], [0, 1], {
        extrapolateLeft: 'clamp',
        extrapolateRight: 'clamp',
      });
    }

    if (animation.type === 'fade-out') {
      nextVolume *= interpolate(progress, [0, 1], [1, 0], {
        extrapolateLeft: 'clamp',
        extrapolateRight: 'clamp',
      });
    }
  }

  return nextVolume;
}

function resolveAudioVolume({ frame, element, settings: presetSettings }) {
  const durationInFrames = Math.max(Number(element?.durationInFrames) || 1, 1);
  const elementStartFrame = Number(element?.startFrame) || 0;
  const settings = presetSettings || normalizeAudioSettings(collectAudioSettings(element));

  let volume = settings.volume != null ? Number(settings.volume) : 1;
  if (!Number.isFinite(volume)) {
    volume = 1;
  }
  volume = clamp(volume, 0, 1);

  volume = applyFadeIn(volume, frame, settings.fadeIn, elementStartFrame, durationInFrames);
  volume = applyFadeOut(
    volume,
    frame,
    settings.fadeOut,
    durationInFrames,
    elementStartFrame
  );
  volume = applyAnimationFades(
    volume,
    frame,
    element?.animations,
    elementStartFrame,
    durationInFrames
  );

  return clamp(volume, 0, 1);
}

/**
 * Remotion <Audio /> props derived from element audio settings.
 * Pan / reverse / normalize are persisted for editor preview; not applied at export yet.
 */
function resolveAudioPlaybackProps({ frame, element }) {
  const settings = normalizeAudioSettings(collectAudioSettings(element));
  const volume = resolveAudioVolume({ frame, element, settings });
  const muted = settings.muted === true;

  let playbackRate = settings.playbackRate != null ? Number(settings.playbackRate) : 1;
  if (!Number.isFinite(playbackRate) || playbackRate <= 0) {
    playbackRate = 1;
  }
  playbackRate = clamp(playbackRate, AUDIO_PLAYBACK_RATE_MIN, AUDIO_PLAYBACK_RATE_MAX);

  const trim = settings.trim && typeof settings.trim === 'object' ? settings.trim : {};
  const trimBeforeRaw = settings.trimBefore ?? trim.startFrame ?? settings.trimStartFrame;
  const trimAfterRaw = settings.trimAfter ?? trim.endFrame ?? settings.trimEndFrame;

  const trimBefore =
    trimBeforeRaw != null && Number.isFinite(Number(trimBeforeRaw)) && Number(trimBeforeRaw) > 0
      ? Math.trunc(Number(trimBeforeRaw))
      : undefined;
  const trimAfter =
    trimAfterRaw != null && Number.isFinite(Number(trimAfterRaw)) && Number(trimAfterRaw) > 0
      ? Math.trunc(Number(trimAfterRaw))
      : undefined;

  return {
    volume: muted ? 0 : volume,
    playbackRate,
    loop: settings.loop === true,
    muted,
    trimBefore,
    trimAfter,
  };
}

module.exports = {
  resolveAudioPlaybackProps,
  resolveAudioVolume,
  collectAudioSettings,
};
