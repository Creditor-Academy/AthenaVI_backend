/**
 * SVGL API client — brand logos only (https://api.svgl.app).
 * Free / no auth; cache responses to respect rate limits. Fail-soft always.
 */

const SVGL_BASE = 'https://api.svgl.app';
const CACHE_TTL_MS = 12 * 60 * 1000;
const FETCH_TIMEOUT_MS = 6000;

/** @type {Map<string, { expires: number, value: any }>} */
const cache = new Map();

function cacheGet(key) {
  const hit = cache.get(key);
  if (!hit) return undefined;
  if (Date.now() > hit.expires) {
    cache.delete(key);
    return undefined;
  }
  return hit.value;
}

function cacheSet(key, value) {
  cache.set(key, { expires: Date.now() + CACHE_TTL_MS, value });
}

async function fetchJson(url) {
  const cached = cacheGet(url);
  if (cached !== undefined) return cached;

  let res;
  try {
    res = await fetch(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    });
  } catch {
    return null;
  }
  if (!res.ok) return null;
  let data;
  try {
    data = await res.json();
  } catch {
    return null;
  }
  cacheSet(url, data);
  return data;
}

/**
 * @param {string} query
 * @returns {Promise<Array<object>>}
 */
async function searchByTitle(query) {
  const q = String(query || '').trim();
  if (q.length < 2) return [];
  const url = `${SVGL_BASE}?search=${encodeURIComponent(q)}`;
  const data = await fetchJson(url);
  return Array.isArray(data) ? data : [];
}

/**
 * Resolve logo URL for light/dark appearance.
 * @param {object} entry
 * @param {'light'|'dark'|string} appearance
 */
function resolveRouteUrl(entry, appearance = 'light') {
  if (!entry) return '';
  const route = entry.route;
  if (!route) return '';
  if (typeof route === 'string') return route;
  if (typeof route === 'object') {
    const preferDark = String(appearance || '').toLowerCase() === 'dark';
    if (preferDark && route.dark) return route.dark;
    if (route.light) return route.light;
    if (route.dark) return route.dark;
  }
  return '';
}

function normalizeBrandKey(text) {
  return String(text || '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '')
    .trim();
}

/**
 * Extract a short brand-like candidate from bullet/column title text.
 */
function extractBrandCandidate(text) {
  let raw = String(text || '').trim();
  if (!raw) return '';
  raw = raw.replace(/^\*+\s*/, '').replace(/\*+$/, '');
  raw = raw.replace(/^\d+[\.)]\s*/, '');
  // Prefer title before colon / em dash (not hyphen — brands like GPT-4 keep hyphen)
  const split = raw.split(/\s*[:：—–]\s*/);
  if (split[0] && split[0].trim().length >= 2) {
    raw = split[0].trim();
  }
  const words = raw.split(/\s+/).filter(Boolean).slice(0, 4);
  return words.join(' ').trim();
}

/**
 * High-confidence match only — avoid random logos on generic copy.
 */
function isConfidentBrandMatch(candidate, entryTitle) {
  const a = normalizeBrandKey(candidate);
  const b = normalizeBrandKey(entryTitle);
  if (!a || !b || a.length < 2 || b.length < 2) return false;
  if (a === b) return true;
  if (a.includes(b) && b.length >= 3) return true;
  if (b.includes(a) && a.length >= 3) return true;
  return false;
}

/**
 * Find a confident SVGL brand logo for point text, or null.
 */
async function findBrandGraphic(pointText, { appearance = 'light', usedIds = new Set() } = {}) {
  const candidate = extractBrandCandidate(pointText);
  if (!candidate || candidate.length < 2) return null;

  const results = await searchByTitle(candidate);
  if (!results.length) return null;

  const hit = results.find((entry) => {
    if (!entry?.title) return false;
    const id = `svgl:${entry.id}`;
    if (usedIds.has(id)) return false;
    return isConfidentBrandMatch(candidate, entry.title);
  });
  if (!hit) return null;

  const fileUrl = resolveRouteUrl(hit, appearance);
  if (!fileUrl) return null;

  return {
    id: `svgl:${hit.id}`,
    name: hit.title,
    fileUrl,
    previewUrl: fileUrl,
    colorMode: 'fixed',
    source: 'svgl',
    brandUrl: hit.brandUrl || hit.url || undefined,
  };
}

function clearCacheForTests() {
  cache.clear();
}

module.exports = {
  searchByTitle,
  resolveRouteUrl,
  extractBrandCandidate,
  isConfidentBrandMatch,
  findBrandGraphic,
  clearCacheForTests,
  SVGL_BASE,
};
