'use strict';

/**
 * Generation-time theme recolor for diagram chrome (SVG cards, icons, bordered cards, badges).
 *
 * ~76 diagram compilers bake their own accent palettes into inline SVG (rainbow timelines, blue
 * agenda columns, …). On first generation we map every saturated accent on the slide onto the
 * theme's color family (in order of appearance), and light tints of those accents onto matching
 * tints of the mapped theme color. Neutrals (white, greys, near-black), charts and images are left
 * alone. Applied only when a slide is generated — later editor recompiles keep user colors.
 */
const { processStepColors } = require('../diagrams/processThemeColors');

const HEX_RE = /#([0-9a-fA-F]{6}|[0-9a-fA-F]{3})(?![0-9a-zA-Z_-])/g;
const SKIP_TYPES = new Set(['chart', 'image', 'table', 'embed']);

function normHex(value) {
  const raw = String(value || '').trim().replace(/^#/, '');
  if (/^[0-9a-fA-F]{3}$/.test(raw)) return `#${raw.split('').map((c) => c + c).join('')}`.toLowerCase();
  if (/^[0-9a-fA-F]{6}$/.test(raw)) return `#${raw}`.toLowerCase();
  return null;
}

function hexToHsl(hex) {
  const h = normHex(hex);
  if (!h) return null;
  const r = parseInt(h.slice(1, 3), 16) / 255;
  const g = parseInt(h.slice(3, 5), 16) / 255;
  const b = parseInt(h.slice(5, 7), 16) / 255;
  const max = Math.max(r, g, b);
  const min = Math.min(r, g, b);
  const l = (max + min) / 2;
  if (max === min) return { h: 0, s: 0, l };
  const d = max - min;
  const s = l > 0.5 ? d / (2 - max - min) : d / (max + min);
  let hue;
  if (max === r) hue = (g - b) / d + (g < b ? 6 : 0);
  else if (max === g) hue = (b - r) / d + 2;
  else hue = (r - g) / d + 4;
  return { h: hue * 60, s, l };
}

function mixHex(hex, toward, amount) {
  const a = normHex(hex);
  const b = normHex(toward);
  if (!a || !b) return hex;
  const t = Math.max(0, Math.min(1, Number(amount) || 0));
  const ch = (i) =>
    Math.round(parseInt(a.slice(i, i + 2), 16) + (parseInt(b.slice(i, i + 2), 16) - parseInt(a.slice(i, i + 2), 16)) * t)
      .toString(16)
      .padStart(2, '0');
  return `#${ch(1)}${ch(3)}${ch(5)}`.toUpperCase();
}

/** accent: saturated mid-tone · tint: light pastel of an accent · neutral: everything else. */
function classify(hex) {
  const hsl = hexToHsl(hex);
  if (!hsl || hsl.s < 0.2) return 'neutral';
  if (hsl.l > 0.97 || hsl.l < 0.12) return 'neutral';
  if (hsl.l > 0.78) return 'tint';
  return 'accent';
}

const hueDistance = (a, b) => {
  const d = Math.abs(a - b) % 360;
  return d > 180 ? 360 - d : d;
};

function collectHexes(value, out) {
  if (typeof value === 'string') {
    const direct = normHex(value);
    if (direct && /^#?[0-9a-fA-F]{3,6}$/.test(value.trim())) {
      out.push(direct);
      return;
    }
    for (const m of value.matchAll(HEX_RE)) out.push(normHex(m[0]));
  }
}

function colorFieldsOf(el) {
  const c = el?.content || {};
  return [c.svg, c.fill, c.color, c.stroke, c.borderColor, c.background];
}

/**
 * @param {{ elements?: object[] }} doc compiled elements doc
 * @param {object} themeTokens deck theme tokens (palette, brand chart colors)
 */
function recolorDiagramToTheme(doc, themeTokens) {
  if (!doc || !Array.isArray(doc.elements)) return doc;
  const palette = themeTokens?.palette || themeTokens || {};
  if (!palette || typeof palette !== 'object' || !normHex(palette.primary)) return doc;

  const themeSet = new Set(
    [palette.primary, palette.secondary, palette.accent, ...(processStepColors(palette, 8) || [])]
      .map(normHex)
      .filter(Boolean)
  );

  // 1. Accents in order of first appearance (decorative elements only).
  const found = [];
  for (const el of doc.elements) {
    if (!el || SKIP_TYPES.has(el.type)) continue;
    for (const field of colorFieldsOf(el)) collectHexes(field, found);
  }
  const accents = [];
  for (const hex of found) {
    if (!hex || themeSet.has(hex) || classify(hex) !== 'accent' || accents.includes(hex)) continue;
    accents.push(hex);
  }
  const tints = [...new Set(found.filter((hex) => hex && !themeSet.has(hex) && classify(hex) === 'tint'))];
  if (!accents.length && !tints.length) return doc;

  // 2. Build the mapping: accent i → theme family i; tint → same lightness of nearest-hue mapped accent.
  const family = processStepColors(palette, Math.max(accents.length, 1));
  const map = new Map(accents.map((hex, i) => [hex, family[i % family.length]]));
  const primary = normHex(palette.primary);
  for (const tint of tints) {
    const tHsl = hexToHsl(tint);
    let base = primary;
    let best = 50; // only borrow an accent's mapping when hues are close
    for (const accent of accents) {
      const d = hueDistance(hexToHsl(accent).h, tHsl.h);
      if (d < best) {
        best = d;
        base = map.get(accent);
      }
    }
    const baseL = hexToHsl(base)?.l ?? 0.5;
    const amount = baseL >= 1 ? 0 : (tHsl.l - baseL) / (1 - baseL);
    map.set(tint, mixHex(base, '#ffffff', Math.max(0, Math.min(0.95, amount))));
  }

  const swap = (value) => {
    if (typeof value !== 'string') return value;
    const direct = normHex(value);
    if (direct && /^#?[0-9a-fA-F]{3,6}$/.test(value.trim())) return map.get(direct) || value;
    return value.replace(HEX_RE, (m) => map.get(normHex(m)) || m);
  };

  // 3. Apply to decorative graphics/shapes/icons and accent-colored text (e.g. step titles).
  let changed = false;
  const elements = doc.elements.map((el) => {
    if (!el || SKIP_TYPES.has(el.type) || !el.content) return el;
    const c = el.content;
    let next = null;
    for (const key of ['svg', 'fill', 'color', 'stroke', 'borderColor', 'background']) {
      if (c[key] == null) continue;
      if (el.type === 'text' && key !== 'color' && key !== 'fill') continue;
      const swapped = swap(c[key]);
      if (swapped !== c[key]) {
        next = next || { ...c };
        next[key] = swapped;
      }
    }
    if (!next) return el;
    changed = true;
    return { ...el, content: next };
  });
  return changed ? { ...doc, elements } : doc;
}

module.exports = {
  recolorDiagramToTheme,
  classifyThemeColor: classify,
};
