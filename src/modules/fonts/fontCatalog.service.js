const path = require('path');
const fs = require('fs');
const logger = require('../../shared/utils/logger');
const { redisClient } = require('../../shared/config/redis');
const { FEATURED_FAMILIES } = require('../../shared/fonts/fontPairings');
const googleFontsClient = require('./googleFonts.client');

const CACHE_KEY = 'fonts:catalog:v1';
const CACHE_TTL_SEC = 24 * 60 * 60;
const SNAPSHOT_PATH = path.join(__dirname, 'catalog', 'googleFonts.snapshot.json');

const featuredSet = new Set(FEATURED_FAMILIES.map((f) => f.toLowerCase()));

let memorySnapshot = null;

function loadSnapshot() {
  if (memorySnapshot) return memorySnapshot;
  const raw = fs.readFileSync(SNAPSHOT_PATH, 'utf8');
  const parsed = JSON.parse(raw);
  const fonts = Array.isArray(parsed.fonts) ? parsed.fonts : [];
  memorySnapshot = fonts.map(normalizeEntry);
  return memorySnapshot;
}

function normalizeEntry(entry) {
  const family = String(entry.family || '').trim();
  return {
    family,
    category: String(entry.category || 'sans-serif').trim(),
    variants: Array.isArray(entry.variants) ? entry.variants.map(String) : ['regular'],
    subsets: Array.isArray(entry.subsets) ? entry.subsets.map(String) : ['latin'],
    featured: entry.featured === true || featuredSet.has(family.toLowerCase()),
  };
}

function mergeCatalog(snapshotFonts, liveFonts) {
  const byFamily = new Map();
  for (const font of snapshotFonts) {
    if (!font.family) continue;
    byFamily.set(font.family.toLowerCase(), font);
  }
  for (const live of liveFonts || []) {
    if (!live.family) continue;
    const key = live.family.toLowerCase();
    const existing = byFamily.get(key);
    byFamily.set(key, {
      family: live.family,
      category: live.category || existing?.category || 'sans-serif',
      variants: live.variants?.length ? live.variants : existing?.variants || ['regular'],
      subsets: live.subsets?.length ? live.subsets : existing?.subsets || ['latin'],
      featured: featuredSet.has(key) || existing?.featured === true,
    });
  }
  return [...byFamily.values()].sort((a, b) => a.family.localeCompare(b.family));
}

async function readCache() {
  try {
    if (!redisClient.isOpen) return null;
    const raw = await redisClient.get(CACHE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed?.fonts)) return null;
    return parsed.fonts.map(normalizeEntry);
  } catch (err) {
    logger.warn('Font catalog Redis read failed', { error: err.message });
    return null;
  }
}

async function writeCache(fonts) {
  try {
    if (!redisClient.isOpen) return;
    await redisClient.setEx(
      CACHE_KEY,
      CACHE_TTL_SEC,
      JSON.stringify({ fonts, cachedAt: new Date().toISOString() })
    );
  } catch (err) {
    logger.warn('Font catalog Redis write failed', { error: err.message });
  }
}

/**
 * Resolve the full catalog: Redis → live merge → snapshot.
 * Never throws — always returns at least the vendored snapshot.
 */
async function getCatalogFonts() {
  const cached = await readCache();
  if (cached?.length) return cached;

  const snapshot = loadSnapshot();
  let fonts = snapshot;

  if (googleFontsClient.isConfigured()) {
    try {
      const live = await googleFontsClient.fetchWebfonts({ sort: 'popularity' });
      fonts = mergeCatalog(snapshot, live);
    } catch (err) {
      logger.warn('Google Fonts live fetch failed; using snapshot', { error: err.message });
      fonts = snapshot;
    }
  }

  await writeCache(fonts);
  return fonts;
}

module.exports = {
  getCatalogFonts,
  loadSnapshot,
  CACHE_KEY,
  CACHE_TTL_SEC,
};
