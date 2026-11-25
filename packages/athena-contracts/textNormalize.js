'use strict';

const UNICODE_CONTROL_RE = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F\u200B-\u200D\uFEFF]/g;
const BIDI_RE = /[\u202A-\u202E\u2066-\u2069]/g;

function stripUnicodeControls(text) {
  if (text == null || typeof text !== 'string') return text;
  return String(text).normalize('NFC').replace(BIDI_RE, '').replace(UNICODE_CONTROL_RE, '');
}

function sanitizeLineBreaks(text) {
  if (text == null || typeof text !== 'string') return text;
  return String(text)
    .replace(/\r\n/g, '\n')
    .replace(/\r/g, '\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

function normalizeStringValue(text) {
  if (text == null || typeof text !== 'string') return text;
  return sanitizeLineBreaks(stripUnicodeControls(text));
}

function truncateWords(text, maxWords) {
  if (!text || typeof text !== 'string') return text;
  const cleaned = normalizeStringValue(text);
  const words = cleaned.split(/\s+/).filter(Boolean);
  if (maxWords == null || maxWords <= 0 || words.length <= maxWords) return cleaned;
  return words.slice(0, maxWords).join(' ') + '...';
}

function truncateChars(text, maxChars) {
  if (!text || typeof text !== 'string') return text;
  const cleaned = normalizeStringValue(text);
  if (maxChars == null || maxChars <= 0 || cleaned.length <= maxChars) return cleaned;
  if (maxChars <= 3) return cleaned.substring(0, maxChars);
  return cleaned.substring(0, maxChars - 3) + '...';
}

function truncateLines(text, maxLines) {
  if (!text || typeof text !== 'string') return text;
  const cleaned = normalizeStringValue(text);
  if (maxLines == null || maxLines <= 0) return cleaned;
  const lines = cleaned.split('\n');
  if (lines.length <= maxLines) return cleaned;
  const joined = lines.slice(0, maxLines).join('\n');
  if (joined.endsWith('...')) return joined;
  return joined + '...';
}

/**
 * @param {string} text
 * @param {{ maxLines?: number, maxWords?: number, maxChars?: number } | null} limits
 */
function clampSlotText(text, limits) {
  if (text == null) return '';
  let out = normalizeStringValue(String(text));
  if (!limits || typeof limits !== 'object') return out;
  if (limits.maxLines != null && limits.maxLines > 0) {
    out = truncateLines(out, limits.maxLines);
  }
  if (limits.maxWords != null && limits.maxWords > 0) {
    out = truncateWords(out, limits.maxWords);
  }
  if (limits.maxChars != null && limits.maxChars > 0) {
    out = truncateChars(out, limits.maxChars);
  }
  return out;
}

function walkNormalizeStrings(value) {
  if (value == null) return value;
  if (typeof value === 'string') return normalizeStringValue(value);
  if (Array.isArray(value)) return value.map(walkNormalizeStrings);
  if (typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      out[k] = walkNormalizeStrings(v);
    }
    return out;
  }
  return value;
}

module.exports = {
  stripUnicodeControls,
  sanitizeLineBreaks,
  normalizeStringValue,
  truncateWords,
  truncateChars,
  truncateLines,
  clampSlotText,
  walkNormalizeStrings,
};
