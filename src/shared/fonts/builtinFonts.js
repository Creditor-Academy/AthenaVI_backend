/**
 * Built-in / system fonts always offered alongside the Google Fonts catalog.
 * Keep in sync with AthenaVI frontend `src/utils/legacyFonts.js`.
 */

const SYSTEM_FONT_FAMILIES = new Set([
  'arial',
  'helvetica',
  'georgia',
  'times new roman',
  'courier new',
  'monospace',
  'system-ui',
  'sans-serif',
  'serif',
  'cursive',
  'fantasy',
]);

const BUILTIN_FONT_ENTRIES = [
  { family: 'Inter', category: 'sans-serif', featured: true },
  { family: 'Arial', category: 'system', featured: true },
  { family: 'Helvetica', category: 'system', featured: true },
  { family: 'Georgia', category: 'system', featured: true },
  { family: 'Times New Roman', category: 'system', featured: true },
  { family: 'Courier New', category: 'system', featured: true },
  { family: 'Montserrat', category: 'sans-serif', featured: true },
  { family: 'Roboto', category: 'sans-serif', featured: true },
  { family: 'Open Sans', category: 'sans-serif', featured: true },
  { family: 'Poppins', category: 'sans-serif', featured: true },
  { family: 'Lato', category: 'sans-serif', featured: true },
  { family: 'Playfair Display', category: 'serif', featured: true },
  { family: 'Outfit', category: 'sans-serif', featured: true },
  { family: 'Space Grotesk', category: 'sans-serif', featured: true },
  { family: 'monospace', category: 'system', featured: true },
];

function isSystemFontFamily(family) {
  return SYSTEM_FONT_FAMILIES.has(
    String(family || '')
      .trim()
      .replace(/^["']|["']$/g, '')
      .toLowerCase()
  );
}

function builtinFontEntries() {
  return BUILTIN_FONT_ENTRIES.map((entry) => ({
    family: entry.family,
    category: entry.category,
    variants: ['300', 'regular', '500', '600', '700'],
    subsets: ['latin'],
    featured: true,
    source: isSystemFontFamily(entry.family) ? 'system' : 'builtin',
  }));
}

/**
 * Prepend built-in fonts, then Google catalog; Google wins on family conflict.
 */
function mergeBuiltinFonts(catalogFonts = []) {
  const map = new Map();
  for (const font of builtinFontEntries()) {
    map.set(font.family.toLowerCase(), font);
  }
  for (const font of catalogFonts || []) {
    const family = font?.family;
    if (!family) continue;
    const key = family.toLowerCase();
    const existing = map.get(key);
    map.set(key, {
      ...(existing || {}),
      ...font,
      family,
      featured: Boolean(font.featured || existing?.featured),
      source: existing?.source || font.source || 'google',
    });
  }

  const builtinKeys = new Set(BUILTIN_FONT_ENTRIES.map((f) => f.family.toLowerCase()));
  const ordered = [];
  for (const entry of BUILTIN_FONT_ENTRIES) {
    const font = map.get(entry.family.toLowerCase());
    if (font) ordered.push(font);
  }
  for (const font of catalogFonts || []) {
    const key = String(font?.family || '').toLowerCase();
    if (!key || builtinKeys.has(key)) continue;
    ordered.push(map.get(key) || font);
  }
  return ordered;
}

module.exports = {
  SYSTEM_FONT_FAMILIES,
  BUILTIN_FONT_ENTRIES,
  isSystemFontFamily,
  builtinFontEntries,
  mergeBuiltinFonts,
};
