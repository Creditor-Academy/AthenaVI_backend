/**
 * Shared fill helpers for PPT canvas persist + PNG/PDF/PPTX export.
 * Accepts hex strings, color roles, or { type: 'solid'|'gradient', kind, angle, stops }.
 */

function hexNoHash(value, fallback = '111111') {
  const raw = String(value || fallback).trim();
  return raw.replace(/^#/, '') || fallback.replace(/^#/, '');
}

function resolveToken(value, palette, fallback) {
  if (value == null || value === '') return fallback;
  if (typeof value === 'object') {
    return resolveToken(value.color || value.colorRole, palette, fallback);
  }
  const key = String(value).trim();
  if (palette && palette[key]) return palette[key];
  if (key.startsWith('#') || key.startsWith('rgb') || key.startsWith('hsl') || key.includes('gradient')) {
    return key;
  }
  return key;
}

function stopList(fill, palette, fallback) {
  const stops = Array.isArray(fill?.stops) ? fill.stops : [];
  if (stops.length) {
    return stops.map((stop, i, all) => {
      const color = resolveToken(stop?.color || stop?.colorRole || stop, palette, fallback);
      const at = stop?.at != null ? Number(stop.at) : stop?.position != null ? Number(stop.position) : null;
      const pct =
        at == null
          ? all.length <= 1
            ? 0
            : Math.round((i / (all.length - 1)) * 100)
          : Math.round(Number(at) <= 1 ? Number(at) * 100 : Number(at));
      return { color, pct };
    });
  }
  const start = resolveToken(fill?.from || fill?.start, palette, fallback);
  const end = resolveToken(fill?.to || fill?.end, palette, fallback);
  return [
    { color: start, pct: 0 },
    { color: end, pct: 100 },
  ];
}

function cssFromFill(fill, palette = {}, fallback = '#111111') {
  if (fill == null || fill === '') return fallback;
  if (typeof fill === 'string') return resolveToken(fill, palette, fallback);
  if (fill.type === 'gradient' || fill.kind === 'radial' || Array.isArray(fill.stops)) {
    const stops = stopList(fill, palette, fallback);
    const parts = stops.map((s) => `${s.color} ${s.pct}%`);
    if (fill.kind === 'radial' || fill.gradientKind === 'radial') {
      return `radial-gradient(circle at center, ${parts.join(', ')})`;
    }
    const angle = fill.angle != null ? Number(fill.angle) : 135;
    const direction = fill.direction || `${Number.isFinite(angle) ? angle : 135}deg`;
    return `linear-gradient(${direction}, ${parts.join(', ')})`;
  }
  return resolveToken(fill.color || fill.colorRole, palette, fallback);
}

function firstHexFromFill(fill, palette = {}, fallback = '111111') {
  if (fill == null || fill === '') return hexNoHash(fallback);
  if (typeof fill === 'object' && (fill.type === 'gradient' || Array.isArray(fill.stops))) {
    const stops = stopList(fill, palette, fallback);
    return hexNoHash(stops[0]?.color || fallback, fallback);
  }
  return hexNoHash(resolveToken(fill, palette, fallback), fallback);
}

function slideBackgroundCss(slide, palette = {}) {
  const doc = slide?.elements && typeof slide.elements === 'object' ? slide.elements : {};
  if (slide?.backgroundImage || doc.backgroundImage) {
    const url = slide.backgroundImage || doc.backgroundImage;
    const fit = slide.backgroundImageFit || doc.backgroundImageFit || 'cover';
    const color = doc.backgroundColor || slide.backgroundColor || palette.bg || '#ffffff';
    return `${color} url(${url}) center / ${fit === 'fill' ? '100% 100%' : fit} no-repeat`;
  }
  const fill = doc.backgroundFill || slide.backgroundFill;
  if (fill && typeof fill === 'object') return cssFromFill(fill, palette, palette.bg || '#ffffff');
  const start = doc.backgroundGradientStart || slide.backgroundGradientStart;
  const end = doc.backgroundGradientEnd || slide.backgroundGradientEnd;
  if (start && end) {
    return cssFromFill(
      {
        type: 'gradient',
        kind: doc.backgroundGradientKind || slide.backgroundGradientKind || 'linear',
        angle: doc.backgroundGradientAngle ?? slide.backgroundGradientAngle ?? 135,
        stops: Array.isArray(doc.backgroundGradientStops)
          ? doc.backgroundGradientStops
          : [
              { color: start, at: 0 },
              { color: end, at: 1 },
            ],
      },
      palette,
      palette.bg || '#ffffff'
    );
  }
  return doc.backgroundColor || slide.backgroundColor || palette.bg || '#ffffff';
}

function textPaintCss(fill, palette, fallback) {
  const css = cssFromFill(fill, palette, fallback);
  if (css && String(css).includes('gradient')) {
    return `background-image:${css};-webkit-background-clip:text;background-clip:text;color:transparent;-webkit-text-fill-color:transparent`;
  }
  return `color:${css}`;
}

const CANVAS_BACKGROUND_KEYS = [
  'backgroundColor',
  'backgroundImage',
  'backgroundImageFit',
  'backgroundImageElementId',
  'backgroundGradientStart',
  'backgroundGradientEnd',
  'backgroundGradientAngle',
  'backgroundGradientKind',
  'backgroundGradientStops',
  'backgroundFill',
];

module.exports = {
  cssFromFill,
  firstHexFromFill,
  slideBackgroundCss,
  textPaintCss,
  CANVAS_BACKGROUND_KEYS,
  hexNoHash,
};
