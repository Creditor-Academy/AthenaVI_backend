/** HeyGen TTS (POST /v3/voices/speech) uses the Starfish engine only. */

function normalizeVoiceEngineToken(value) {
  return String(value || '')
    .trim()
    .toLowerCase()
    .replace(/^voiceprovider\./, '');
}

function extractVoiceSpeechEngines(voiceBody) {
  if (!voiceBody || typeof voiceBody !== 'object' || Array.isArray(voiceBody)) {
    return [];
  }

  const engines = new Set();

  function add(value) {
    if (value == null) return;
    if (Array.isArray(value)) {
      value.forEach(add);
      return;
    }
    const normalized = normalizeVoiceEngineToken(value);
    if (normalized) engines.add(normalized);
  }

  add(voiceBody.supported_engines ?? voiceBody.supportedEngines);
  add(voiceBody.engines);
  add(voiceBody.voice_provider ?? voiceBody.voiceProvider);
  add(voiceBody.provider);

  return [...engines];
}

/**
 * Whether custom text can be synthesized via POST /v3/voices/speech (Starfish TTS).
 * Cloned/private voices are typically video-only; public catalog voices default to true
 * when HeyGen omits engine metadata.
 */
function voiceSupportsStarfishSpeech(voiceBody) {
  const engines = extractVoiceSpeechEngines(voiceBody);
  if (engines.length > 0) {
    return engines.includes('starfish');
  }

  const type = String(voiceBody?.type || '').toLowerCase();
  if (type === 'private') {
    return false;
  }

  return true;
}

function enrichVoiceWithSpeechHints(voice) {
  if (!voice || typeof voice !== 'object' || Array.isArray(voice)) {
    return voice;
  }

  const supportsSpeechPreview = voiceSupportsStarfishSpeech(voice);
  const previewAudioUrl =
    voice.preview_audio_url ?? voice.previewAudioUrl ?? voice.preview_audio ?? null;

  return {
    ...voice,
    supportsSpeechPreview,
    supports_starfish_tts: supportsSpeechPreview,
    ...(previewAudioUrl ? { previewAudioUrl: String(previewAudioUrl) } : {}),
  };
}

const VOICE_LIST_ARRAY_KEYS = [
  'voices',
  'voice_list',
  'items',
  'results',
  'data',
];

function enrichVoicesListBodyWithSpeechHints(body) {
  if (!body || typeof body !== 'object') return body;

  const hasEnvelope = 'data' in body && body.data != null && typeof body.data === 'object';
  const target = hasEnvelope ? body.data : body;

  function enrichItem(item) {
    if (!item || typeof item !== 'object' || Array.isArray(item)) return item;
    return enrichVoiceWithSpeechHints(item);
  }

  if (Array.isArray(target)) {
    const next = target.map(enrichItem);
    return hasEnvelope ? { ...body, data: next } : next;
  }

  for (const key of VOICE_LIST_ARRAY_KEYS) {
    if (!Array.isArray(target[key])) continue;
    const nextTarget = { ...target, [key]: target[key].map(enrichItem) };
    return hasEnvelope ? { ...body, data: nextTarget } : nextTarget;
  }

  return body;
}

function isHeygenStarfishSpeechUnsupportedError(message) {
  const msg = String(message || '').toLowerCase();
  return msg.includes('starfish') && msg.includes('not supported');
}

module.exports = {
  normalizeVoiceEngineToken,
  extractVoiceSpeechEngines,
  voiceSupportsStarfishSpeech,
  enrichVoiceWithSpeechHints,
  enrichVoicesListBodyWithSpeechHints,
  isHeygenStarfishSpeechUnsupportedError,
};
