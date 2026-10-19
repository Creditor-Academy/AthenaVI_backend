/**
 * Regenerate src/modules/fonts/catalog/googleFonts.snapshot.json from the live
 * Google Fonts API. Requires GOOGLE_FONTS_API_KEY.
 *
 * Usage:
 *   node scripts/refresh-font-catalog.js
 *   dotenv -e .env.development -- node scripts/refresh-font-catalog.js
 */

const path = require('path');
const fs = require('fs');
const { FEATURED_FAMILIES, PAIRING_FAMILIES } = require('../src/shared/fonts/fontPairings');

const OUT_PATH = path.join(
  __dirname,
  '..',
  'src',
  'modules',
  'fonts',
  'catalog',
  'googleFonts.snapshot.json'
);

const featuredSet = new Set(FEATURED_FAMILIES.map((f) => f.toLowerCase()));
const pairingSet = new Set(PAIRING_FAMILIES.map((f) => f.toLowerCase()));

async function main() {
  const key = process.env.GOOGLE_FONTS_API_KEY;
  if (!key || !String(key).trim()) {
    console.error('GOOGLE_FONTS_API_KEY is required to refresh the snapshot.');
    process.exit(1);
  }

  const url = `https://www.googleapis.com/webfonts/v1/webfonts?key=${encodeURIComponent(
    String(key).trim()
  )}&sort=popularity`;
  const res = await fetch(url);
  if (!res.ok) {
    const text = await res.text();
    console.error('Google Fonts API failed:', res.status, text.slice(0, 400));
    process.exit(1);
  }

  const body = await res.json();
  const items = Array.isArray(body.items) ? body.items : [];

  // Keep top 400 by popularity, always include pairing + featured families.
  const top = items.slice(0, 400);
  const byFamily = new Map();
  for (const item of top) {
    const family = String(item.family || '').trim();
    if (!family) continue;
    byFamily.set(family.toLowerCase(), {
      family,
      category: String(item.category || 'sans-serif'),
      variants: Array.isArray(item.variants) ? item.variants : ['regular'],
      subsets: Array.isArray(item.subsets) ? item.subsets : ['latin'],
      featured: featuredSet.has(family.toLowerCase()),
    });
  }

  for (const item of items) {
    const family = String(item.family || '').trim();
    if (!family) continue;
    const keyLower = family.toLowerCase();
    if (!featuredSet.has(keyLower) && !pairingSet.has(keyLower)) continue;
    if (byFamily.has(keyLower)) {
      byFamily.get(keyLower).featured = true;
      continue;
    }
    byFamily.set(keyLower, {
      family,
      category: String(item.category || 'sans-serif'),
      variants: Array.isArray(item.variants) ? item.variants : ['regular'],
      subsets: Array.isArray(item.subsets) ? item.subsets : ['latin'],
      featured: true,
    });
  }

  const fonts = [...byFamily.values()];
  const payload = {
    version: 1,
    generatedAt: new Date().toISOString(),
    source: 'google-webfonts-api',
    fonts,
  };

  fs.mkdirSync(path.dirname(OUT_PATH), { recursive: true });
  fs.writeFileSync(OUT_PATH, JSON.stringify(payload, null, 2));
  console.log(
    `Wrote ${fonts.length} fonts (${fonts.filter((f) => f.featured).length} featured) → ${OUT_PATH}`
  );
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
