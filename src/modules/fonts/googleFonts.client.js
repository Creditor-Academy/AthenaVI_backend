const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');
const logger = require('../../shared/utils/logger');

const WEBFONTS_URL = 'https://www.googleapis.com/webfonts/v1/webfonts';

function isConfigured() {
  const key = process.env.GOOGLE_FONTS_API_KEY;
  return Boolean(key && String(key).trim());
}

function getApiKey() {
  const key = process.env.GOOGLE_FONTS_API_KEY;
  if (!key || !String(key).trim()) {
    throw new AppError(messages.FONTS_API_NOT_CONFIGURED, 503);
  }
  return String(key).trim();
}

/**
 * Fetch the full Google Fonts directory (sorted by popularity).
 * Returns normalized entries: { family, category, variants, subsets }.
 */
async function fetchWebfonts({ sort = 'popularity' } = {}) {
  const url = `${WEBFONTS_URL}?key=${encodeURIComponent(getApiKey())}&sort=${encodeURIComponent(sort)}`;
  let res;
  try {
    res = await fetch(url, { method: 'GET' });
  } catch (err) {
    logger.warn('Google Fonts API network error', { error: err.message });
    throw new AppError(messages.FONTS_PROVIDER_REQUEST_FAILED, 502);
  }

  let body = null;
  try {
    body = await res.json();
  } catch {
    body = null;
  }

  if (!res.ok) {
    const msg = body?.error?.message || res.statusText || messages.FONTS_PROVIDER_REQUEST_FAILED;
    const status = res.status === 429 ? 429 : res.status >= 400 && res.status < 600 ? res.status : 502;
    throw new AppError(msg, status);
  }

  const items = Array.isArray(body?.items) ? body.items : [];
  return items.map((item) => ({
    family: String(item.family || '').trim(),
    category: String(item.category || 'sans-serif').trim(),
    variants: Array.isArray(item.variants) ? item.variants.map(String) : ['regular'],
    subsets: Array.isArray(item.subsets) ? item.subsets.map(String) : ['latin'],
  })).filter((f) => f.family);
}

module.exports = {
  isConfigured,
  fetchWebfonts,
};
