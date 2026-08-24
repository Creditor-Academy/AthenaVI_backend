const { getCatalogFonts } = require('./fontCatalog.service');
const { FONT_PAIRING_CATALOG } = require('../../shared/fonts/fontPairings');
const { googleFontsHref } = require('../../shared/fonts/googleFontsCss');
const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');

function parseBoolean(value) {
  if (value === true || value === false) return value;
  if (value == null || value === '') return undefined;
  const s = String(value).trim().toLowerCase();
  if (s === 'true' || s === '1' || s === 'yes') return true;
  if (s === 'false' || s === '0' || s === 'no') return false;
  return undefined;
}

function parseFamiliesParam(families) {
  if (Array.isArray(families)) {
    return families.map((f) => String(f || '').trim()).filter(Boolean);
  }
  if (typeof families !== 'string') return [];
  return families
    .split(',')
    .map((f) => f.trim())
    .filter(Boolean);
}

async function getCatalog({ q, category, subset, featured, limit } = {}) {
  const all = await getCatalogFonts();
  const query = String(q || '').trim().toLowerCase();
  const categoryFilter = String(category || '').trim().toLowerCase();
  const subsetFilter = String(subset || '').trim().toLowerCase();
  const featuredOnly = parseBoolean(featured);
  const max = Math.min(Math.max(Number(limit) || 200, 1), 500);

  let fonts = all;
  if (featuredOnly === true) {
    fonts = fonts.filter((f) => f.featured);
  }
  if (categoryFilter) {
    fonts = fonts.filter((f) => String(f.category).toLowerCase() === categoryFilter);
  }
  if (subsetFilter) {
    fonts = fonts.filter((f) =>
      (f.subsets || []).some((s) => String(s).toLowerCase() === subsetFilter)
    );
  }
  if (query) {
    fonts = fonts.filter((f) => f.family.toLowerCase().includes(query));
  }

  fonts = fonts.slice(0, max).map((f) => ({
    family: f.family,
    category: f.category,
    variants: f.variants,
    subsets: f.subsets,
    featured: Boolean(f.featured),
    cssUrl: googleFontsHref(f.family),
  }));

  return {
    fonts,
    pairings: FONT_PAIRING_CATALOG.map((p) => ({
      id: p.id,
      heading: p.heading,
      subheading: p.subheading,
      body: p.body,
      moods: p.moods || [],
      useCases: p.useCases || [],
    })),
    total: fonts.length,
  };
}

function buildCssHref({ families } = {}) {
  const list = parseFamiliesParam(families);
  if (!list.length) {
    throw new AppError(messages.FONT_FAMILIES_REQUIRED, 400);
  }
  const href = googleFontsHref(list);
  if (!href) {
    throw new AppError(messages.FONT_FAMILIES_REQUIRED, 400);
  }
  return { href, families: list };
}

module.exports = {
  getCatalog,
  buildCssHref,
};
