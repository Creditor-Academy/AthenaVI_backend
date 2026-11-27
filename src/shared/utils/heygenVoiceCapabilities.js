'use strict';

/** HeyGen Voice is the engine HeyGen uses when voice_settings.engine_settings is omitted. */
const DEFAULT_ENGINE_TYPE = 'heygen_voice';

function normalizeLocale(value) {
  if (value == null) return null;
  const s = String(value).trim();
  return s === '' ? null : s;
}

/**
 * Checks voice_settings.locale and engine_settings against GET /v3/videos/voice-capabilities.
 *
 * HeyGen reads the language from the script, which we do not detect, so this checks the accent
 * (locale), the engine offered for that accent, and the model offered by that engine. Voice
 * ownership and setup (e.g. professional clones ignoring model) are still decided by HeyGen.
 *
 * Nothing is checked unless the caller sent a locale or engine_settings: the server default
 * (heygen_voice, no model) is always valid.
 *
 * @param {Array<{ language: string, locale: string|null, engines: Array<{ engine: string, models: string[] }> }>} capabilities
 * @param {object|null|undefined} voiceSettings
 * @returns {{ ok: true } | { ok: false, message: string }}
 */
function validateVideoVoiceSettings(capabilities, voiceSettings) {
  if (!voiceSettings || typeof voiceSettings !== 'object') return { ok: true };

  const engineSettings = voiceSettings.engine_settings;
  const hasEngineSettings = engineSettings != null && typeof engineSettings === 'object';
  const locale = normalizeLocale(voiceSettings.locale);
  if (!hasEngineSettings && !locale) return { ok: true };

  if (hasEngineSettings && !normalizeLocale(engineSettings.engine_type)) {
    return { ok: false, message: 'voice_settings.engine_settings.engine_type is required' };
  }

  const engineType = hasEngineSettings
    ? String(engineSettings.engine_type).trim()
    : DEFAULT_ENGINE_TYPE;
  const requestedModel = hasEngineSettings ? normalizeLocale(engineSettings.model) : null;
  const accent = locale ? `locale "${locale}"` : 'Original Accent (no locale)';

  const rows = (Array.isArray(capabilities) ? capabilities : []).filter(
    (row) => normalizeLocale(row?.locale) === locale
  );

  if (rows.length === 0) {
    return {
      ok: false,
      message: `${accent} is not offered for video voices. Use a locale from GET /v3/videos/voice-capabilities or omit voice_settings.locale.`,
    };
  }

  const engineRows = rows.flatMap((row) =>
    (row.engines || []).filter((entry) => entry.engine === engineType)
  );
  if (engineRows.length === 0) {
    const offered = [...new Set(rows.flatMap((row) => (row.engines || []).map((e) => e.engine)))];
    return {
      ok: false,
      message: `Engine "${engineType}" is not offered for ${accent}. Offered engines: ${offered.join(', ')}.`,
    };
  }

  if (requestedModel) {
    const allowedModels = [...new Set(engineRows.flatMap((entry) => entry.models || []))];
    if (allowedModels.length === 0) {
      return {
        ok: false,
        message: `Engine "${engineType}" takes no model for ${accent}. Remove voice_settings.engine_settings.model.`,
      };
    }
    if (!allowedModels.includes(requestedModel)) {
      return {
        ok: false,
        message: `Model "${requestedModel}" is not offered for engine "${engineType}" with ${accent}. Offered models: ${allowedModels.join(', ')}.`,
      };
    }
  }

  return { ok: true };
}

module.exports = {
  DEFAULT_ENGINE_TYPE,
  validateVideoVoiceSettings,
};
