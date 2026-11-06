/**
 * Any CSS colour the editor stores → a colour PowerPoint accepts.
 *
 * pptxgenjs only takes 6-digit hex and silently paints anything else BLACK: #RRGGBBAA,
 * #RGB(A), rgb()/rgba() (comma or space syntax, %), hsl(), and names like "white" all came out
 * black in exports. This parses all of them into { hex: 'RRGGBB', alpha: 0–1 }.
 */

const NAMED = {
  black: '000000', white: 'FFFFFF', red: 'FF0000', green: '008000', blue: '0000FF', yellow: 'FFFF00',
  orange: 'FFA500', purple: '800080', pink: 'FFC0CB', gray: '808080', grey: '808080', silver: 'C0C0C0',
  navy: '000080', teal: '008080', maroon: '800000', olive: '808000', lime: '00FF00', aqua: '00FFFF',
  cyan: '00FFFF', magenta: 'FF00FF', fuchsia: 'FF00FF', gold: 'FFD700', indigo: '4B0082', violet: 'EE82EE',
  brown: 'A52A2A', beige: 'F5F5DC', coral: 'FF7F50', crimson: 'DC143C', salmon: 'FA8072', tomato: 'FF6347',
  khaki: 'F0E68C', lavender: 'E6E6FA', ivory: 'FFFFF0', tan: 'D2B48C', turquoise: '40E0D0',
  slategray: '708090', slategrey: '708090', darkgray: 'A9A9A9', darkgrey: 'A9A9A9', lightgray: 'D3D3D3',
  lightgrey: 'D3D3D3', whitesmoke: 'F5F5F5', gainsboro: 'DCDCDC', dimgray: '696969', dimgrey: '696969',
};

const to2 = (n) => Math.max(0, Math.min(255, Math.round(n))).toString(16).padStart(2, '0').toUpperCase();

function channel(v) {
  const s = String(v).trim();
  return s.endsWith('%') ? (parseFloat(s) / 100) * 255 : parseFloat(s);
}

function alphaOf(v) {
  if (v == null || v === '') return 1;
  const s = String(v).trim();
  const a = s.endsWith('%') ? parseFloat(s) / 100 : parseFloat(s);
  return Number.isFinite(a) ? Math.max(0, Math.min(1, a)) : 1;
}

function hslToRgb(h, s, l) {
  const hue = ((((Number(h) || 0) % 360) + 360) % 360) / 360;
  const sat = Math.max(0, Math.min(1, s));
  const lig = Math.max(0, Math.min(1, l));
  if (sat === 0) return [lig * 255, lig * 255, lig * 255];
  const q = lig < 0.5 ? lig * (1 + sat) : lig + sat - lig * sat;
  const p = 2 * lig - q;
  const f = (t) => {
    let x = t;
    if (x < 0) x += 1;
    if (x > 1) x -= 1;
    if (x < 1 / 6) return p + (q - p) * 6 * x;
    if (x < 1 / 2) return q;
    if (x < 2 / 3) return p + (q - p) * (2 / 3 - x) * 6;
    return p;
  };
  return [f(hue + 1 / 3) * 255, f(hue) * 255, f(hue - 1 / 3) * 255];
}

/**
 * @returns {{ hex: string, alpha: number } | null}  hex without '#'; null if not a colour
 */
function parseColor(value) {
  if (value == null) return null;
  const raw = String(value).trim();
  if (!raw) return null;
  const lower = raw.toLowerCase();
  if (lower === 'transparent' || lower === 'none') return { hex: '000000', alpha: 0 };
  if (NAMED[lower]) return { hex: NAMED[lower], alpha: 1 };

  const hex = /^#?([0-9a-f]{3,4}|[0-9a-f]{6}|[0-9a-f]{8})$/i.exec(raw);
  if (hex) {
    let h = hex[1];
    if (h.length <= 4) h = h.split('').map((c) => c + c).join('');
    return { hex: h.slice(0, 6).toUpperCase(), alpha: h.length === 8 ? parseInt(h.slice(6, 8), 16) / 255 : 1 };
  }

  const rgb = /^rgba?\(\s*([^,\s/]+)[\s,]+([^,\s/]+)[\s,]+([^,\s/)]+)\s*(?:[,/]\s*([^)\s]+))?\s*\)$/i.exec(raw);
  if (rgb) {
    const [r, g, b] = [rgb[1], rgb[2], rgb[3]].map(channel);
    if ([r, g, b].some((n) => !Number.isFinite(n))) return null;
    return { hex: `${to2(r)}${to2(g)}${to2(b)}`, alpha: alphaOf(rgb[4]) };
  }

  const hsl = /^hsla?\(\s*([^,\s/]+?)(?:deg)?[\s,]+([^,\s/]+)%[\s,]+([^,\s/)]+)%\s*(?:[,/]\s*([^)\s]+))?\s*\)$/i.exec(raw);
  if (hsl) {
    const [r, g, b] = hslToRgb(parseFloat(hsl[1]), parseFloat(hsl[2]) / 100, parseFloat(hsl[3]) / 100);
    return { hex: `${to2(r)}${to2(g)}${to2(b)}`, alpha: alphaOf(hsl[4]) };
  }

  // A gradient used as a colour: its first colour.
  const inGradient = /(#[0-9a-f]{3,8}\b|rgba?\([^)]*\)|hsla?\([^)]*\))/i.exec(raw);
  if (/gradient\(/i.test(raw) && inGradient) return parseColor(inGradient[1]);
  return null;
}

/** 6-digit hex (no '#') for a colour, or `fallback` (also run through the parser). */
function hex6(value, fallback = '111111') {
  const parsed = parseColor(value);
  if (parsed) return parsed.hex;
  const fb = parseColor(fallback);
  return fb ? fb.hex : '111111';
}

module.exports = { parseColor, hex6 };
