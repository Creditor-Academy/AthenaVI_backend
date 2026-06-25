/** Typical NLE playback speed range (0.25× – 4×). */
const AUDIO_PLAYBACK_RATE_MIN = 0.25;
const AUDIO_PLAYBACK_RATE_MAX = 4;

/** Keys mirrored between `element.audio` and `content.audio` on save/GET. */
const AUDIO_SETTINGS_KEYS = [
  'volume',
  'fadeIn',
  'fadeOut',
  'playbackRate',
  'playbackSpeed',
  'pitch',
  'pitchSemitones',
  'preservePitch',
  'muted',
  'loop',
  'pan',
  'trim',
  'trimStartFrame',
  'trimEndFrame',
  'trimBefore',
  'trimAfter',
  'reverse',
  'normalize',
];

const DEFAULT_AUDIO_SETTINGS = {
  volume: 1,
  playbackRate: 1,
  preservePitch: true,
  muted: false,
  loop: false,
  pan: 0,
  reverse: false,
  normalize: false,
};

function clampNumber(value, min, max) {
  const n = Number(value);
  if (!Number.isFinite(n)) {
    return min;
  }
  return Math.min(Math.max(n, min), max);
}

function collectAudioSettings(element) {
  const content = element?.content && typeof element.content === 'object' ? element.content : {};
  const contentAudio = content.audio && typeof content.audio === 'object' ? content.audio : {};
  const topAudio = element?.audio && typeof element.audio === 'object' ? element.audio : {};

  return {
    ...contentAudio,
    ...topAudio,
    ...(content.volume != null && topAudio.volume == null ? { volume: content.volume } : {}),
  };
}

/**
 * Canonicalize aliases (playbackSpeed → playbackRate, trim* → trim object).
 * @param {object} raw
 * @returns {object}
 */
function normalizeAudioSettings(raw = {}) {
  if (!raw || typeof raw !== 'object') {
    return {};
  }

  const settings = { ...raw };

  if (settings.playbackSpeed != null && settings.playbackRate == null) {
    settings.playbackRate = Number(settings.playbackSpeed);
  }
  if (settings.pitch != null && settings.pitchSemitones == null) {
    const pitch = Number(settings.pitch);
    if (Number.isFinite(pitch) && pitch > 0) {
      settings.pitchSemitones = Math.round(Math.log2(pitch) * 12);
    }
  }

  const trim = settings.trim && typeof settings.trim === 'object' ? { ...settings.trim } : {};

  if (settings.trimStartFrame != null && trim.startFrame == null) {
    trim.startFrame = Number(settings.trimStartFrame);
  }
  if (settings.trimEndFrame != null && trim.endFrame == null) {
    trim.endFrame = Number(settings.trimEndFrame);
  }
  if (settings.trimBefore != null && trim.startFrame == null) {
    trim.startFrame = Number(settings.trimBefore);
  }
  if (settings.trimAfter != null && trim.endFrame == null) {
    trim.endFrame = Number(settings.trimAfter);
  }

  if (trim.startFrame != null || trim.endFrame != null) {
    settings.trim = trim;
    if (trim.startFrame != null) {
      settings.trimBefore = trim.startFrame;
    }
    if (trim.endFrame != null) {
      settings.trimAfter = trim.endFrame;
    }
  }

  if (settings.playbackRate != null) {
    settings.playbackRate = clampNumber(
      settings.playbackRate,
      AUDIO_PLAYBACK_RATE_MIN,
      AUDIO_PLAYBACK_RATE_MAX
    );
  }
  if (settings.playbackSpeed != null) {
    settings.playbackSpeed = clampNumber(
      settings.playbackSpeed,
      AUDIO_PLAYBACK_RATE_MIN,
      AUDIO_PLAYBACK_RATE_MAX
    );
  }
  if (settings.volume != null) {
    settings.volume = clampNumber(settings.volume, 0, 1);
  }
  if (settings.pan != null) {
    settings.pan = clampNumber(settings.pan, -1, 1);
  }
  if (settings.pitchSemitones != null) {
    settings.pitchSemitones = clampNumber(settings.pitchSemitones, -24, 24);
  }

  return settings;
}

function mergeAudioSettings(contentAudio = {}, topAudio = {}, content = {}) {
  const merged = { ...contentAudio, ...topAudio };
  for (const key of AUDIO_SETTINGS_KEYS) {
    if (topAudio[key] != null) {
      merged[key] = topAudio[key];
    } else if (contentAudio[key] != null) {
      merged[key] = contentAudio[key];
    }
  }
  if (content.volume != null && merged.volume == null) {
    merged.volume = content.volume;
  }
  return normalizeAudioSettings(merged);
}

module.exports = {
  AUDIO_PLAYBACK_RATE_MIN,
  AUDIO_PLAYBACK_RATE_MAX,
  AUDIO_SETTINGS_KEYS,
  DEFAULT_AUDIO_SETTINGS,
  collectAudioSettings,
  normalizeAudioSettings,
  mergeAudioSettings,
};
