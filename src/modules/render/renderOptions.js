const X264_PRESETS = [
  'ultrafast',
  'superfast',
  'veryfast',
  'faster',
  'fast',
  'medium',
  'slow',
  'slower',
  'veryslow',
  'placebo',
];

const CHROMIUM_GL_RENDERERS = ['swangle', 'angle', 'egl', 'swiftshader', 'vulkan', 'angle-egl'];

function readTrimmed(env, key) {
  const value = env[key];
  if (value == null) {
    return '';
  }
  return String(value).trim();
}

/**
 * Extra `renderMedia` options from env. Unset or invalid values are omitted so Remotion keeps its defaults.
 */
function buildRemotionRenderOptions(env = process.env) {
  const options = {};

  const concurrencyRaw = readTrimmed(env, 'REMOTION_CONCURRENCY');
  if (/^\d+$/.test(concurrencyRaw)) {
    const concurrency = Number(concurrencyRaw);
    if (concurrency >= 1) {
      options.concurrency = concurrency;
    }
  }

  const preset = readTrimmed(env, 'REMOTION_X264_PRESET').toLowerCase();
  if (X264_PRESETS.includes(preset)) {
    options.x264Preset = preset;
  }

  const gl = readTrimmed(env, 'REMOTION_CHROMIUM_GL').toLowerCase();
  if (CHROMIUM_GL_RENDERERS.includes(gl)) {
    options.chromiumOptions = { gl };
  }

  return options;
}

module.exports = {
  buildRemotionRenderOptions,
};
