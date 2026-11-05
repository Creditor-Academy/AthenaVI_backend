/**
 * Element effects (shadow, glow, outline…) for exports. Mirrors the editor's
 * src/utils/elementEffects.js: stored on `content.effect` as `{ type, ...settings }`, sizes in
 * editor-stage px (900 wide).
 *  - PDF: the same CSS `filter` the editor draws.
 *  - PPTX: PowerPoint's shape/picture shadow, for the effects it can show (shadow, lift, glow,
 *    neon, echo). Outline, glitch and blur have no PowerPoint equivalent and are left out.
 */

const DEFAULTS = {
  shadow: { offset: 8, angle: 45, blur: 12, color: '#000000', transparency: 60 },
  lift: { intensity: 50 },
  glow: { size: 14, color: '#FACC15' },
  outline: { thickness: 3, color: '#111827' },
  echo: { offset: 6, color: '#6366F1' },
  neon: { intensity: 70, color: '#EC4899' },
  glitch: { offset: 4 },
  blur: { amount: 4 },
};

const RANGES = {
  offset: [0, 40],
  angle: [0, 360],
  blur: [0, 40],
  transparency: [0, 100],
  intensity: [0, 100],
  size: [1, 40],
  thickness: [1, 12],
  amount: [1, 20],
};

function clamp(value, [min, max], fallback) {
  const n = Number(value);
  return Number.isFinite(n) ? Math.min(max, Math.max(min, n)) : fallback;
}

function normalizeElementEffect(effect) {
  if (!effect || typeof effect !== 'object') return null;
  const type = String(effect.type || '').toLowerCase();
  const defaults = DEFAULTS[type];
  if (!defaults) return null;
  const out = { type };
  for (const [key, fallback] of Object.entries(defaults)) {
    if (key === 'color') {
      out.color = typeof effect.color === 'string' && effect.color.trim() ? effect.color.trim() : fallback;
    } else {
      out[key] = clamp(effect[key], RANGES[key], fallback);
    }
  }
  return out;
}

/** Hex `#rrggbb` for a stored colour (hex, rgb(), or a palette key), or the fallback. */
function toHex(color, palette = {}, fallback = '#000000') {
  let raw = String(color || '').trim();
  if (palette && typeof palette[raw] === 'string') raw = palette[raw];
  const short = /^#([0-9a-f]{3})$/i.exec(raw);
  if (short) return `#${short[1].replace(/./g, (c) => c + c)}`.toUpperCase();
  if (/^#[0-9a-f]{6}$/i.test(raw)) return raw.toUpperCase();
  const rgb = /^rgba?\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)/i.exec(raw);
  if (rgb) {
    return `#${rgb
      .slice(1, 4)
      .map((v) => Math.min(255, Number(v)).toString(16).padStart(2, '0'))
      .join('')}`.toUpperCase();
  }
  return fallback;
}

function rgba(hex, alpha) {
  const h = hex.slice(1);
  const r = parseInt(h.slice(0, 2), 16);
  const g = parseInt(h.slice(2, 4), 16);
  const b = parseInt(h.slice(4, 6), 16);
  return alpha >= 1 ? hex : `rgba(${r}, ${g}, ${b}, ${Number(alpha.toFixed(3))})`;
}

const px = (n) => `${Math.round(n * 100) / 100}px`;
const drop = (x, y, blur, color) => `drop-shadow(${px(x)} ${px(y)} ${px(blur)} ${color})`;

/** CSS `filter` value for the element's effect (stage px × `scale`), or ''. */
function elementEffectCssFilter(content, { palette = {}, scale = 1 } = {}) {
  const fx = normalizeElementEffect(content?.effect);
  if (!fx) return '';
  const k = Number(scale) > 0 ? Number(scale) : 1;
  const color = (alpha = 1) => rgba(toHex(fx.color, palette, toHex(DEFAULTS[fx.type].color)), alpha);
  switch (fx.type) {
    case 'shadow': {
      const rad = (fx.angle * Math.PI) / 180;
      return drop(Math.cos(rad) * fx.offset * k, Math.sin(rad) * fx.offset * k, fx.blur * k, color(1 - fx.transparency / 100));
    }
    case 'lift': {
      const i = fx.intensity / 100;
      const b1 = (4 + i * 8) * k;
      const b2 = (10 + i * 22) * k;
      return [
        drop(0, b1 / 2, b1, `rgba(0, 0, 0, ${(0.18 + i * 0.3).toFixed(2)})`),
        drop(0, b2 / 2, b2, `rgba(0, 0, 0, ${(0.08 + i * 0.22).toFixed(2)})`),
      ].join(' ');
    }
    case 'glow':
      return [drop(0, 0, fx.size * k, color()), drop(0, 0, (fx.size / 2) * k, color())].join(' ');
    case 'outline': {
      const t = fx.thickness * k;
      const c = color();
      return [drop(t, 0, 0, c), drop(-t, 0, 0, c), drop(0, t, 0, c), drop(0, -t, 0, c)].join(' ');
    }
    case 'echo': {
      const o = fx.offset * k;
      const c = color(0.55);
      return [drop(o, o, 0, c), drop(o, o, 0, c), drop(o, o, 0, c)].join(' ');
    }
    case 'neon': {
      const i = fx.intensity / 100;
      const c = color();
      return [drop(0, 0, (2 + i * 3) * k, c), drop(0, 0, (6 + i * 8) * k, c), drop(0, 0, (12 + i * 18) * k, c)].join(' ');
    }
    case 'glitch': {
      const o = fx.offset * k;
      return [drop(-o, 0, 0, 'rgba(0, 255, 255, 0.85)'), drop(o, o / 2, 0, 'rgba(255, 0, 255, 0.85)')].join(' ');
    }
    case 'blur':
      return `blur(${px(fx.amount * k)})`;
    default:
      return '';
  }
}

/**
 * pptxgenjs `shadow` option for the element's effect, or undefined.
 * @param {number} ptPerStagePx points per editor-stage px (slide width in pt / 900)
 */
function elementEffectPptxShadow(content, { palette = {}, ptPerStagePx = 0.8 } = {}) {
  const fx = normalizeElementEffect(content?.effect);
  if (!fx) return undefined;
  const pt = (n) => Math.round(n * ptPerStagePx * 10) / 10;
  const hex = (fallback) => toHex(fx.color, palette, fallback).slice(1);
  switch (fx.type) {
    case 'shadow':
      return {
        type: 'outer',
        color: hex('#000000'),
        opacity: Math.max(0, Math.min(1, 1 - fx.transparency / 100)),
        blur: pt(fx.blur),
        offset: pt(fx.offset),
        angle: Math.round(fx.angle) % 360,
      };
    case 'lift': {
      const i = fx.intensity / 100;
      return { type: 'outer', color: '000000', opacity: 0.2 + i * 0.3, blur: pt(10 + i * 22), offset: pt(4 + i * 8), angle: 90 };
    }
    case 'glow':
      return { type: 'outer', color: hex('#FACC15'), opacity: 0.9, blur: pt(fx.size * 1.5), offset: 0, angle: 0 };
    case 'neon':
      return { type: 'outer', color: hex('#EC4899'), opacity: 0.95, blur: pt(12 + (fx.intensity / 100) * 18), offset: 0, angle: 0 };
    case 'echo':
      return { type: 'outer', color: hex('#6366F1'), opacity: 0.55, blur: 0, offset: pt(fx.offset * 1.4), angle: 45 };
    default:
      return undefined;
  }
}

module.exports = { normalizeElementEffect, elementEffectCssFilter, elementEffectPptxShadow };
