/**
 * Editor shapes and picture masks as native PowerPoint geometry, so they stay editable objects
 * (recolour, resize, outline, re-crop) instead of pictures:
 *   - library shapes cut with a CSS clip-path polygon (triangles, stars, arrows, callouts…);
 *   - shapes drawn as a box with CSS border-radius (semicircle, arch, quarter circle, cloud,
 *     speech bubbles, stadium, ring…), including elliptical corners (`50% / 60% 40%`);
 *   - picture masks: clip-path polygon / ellipse / circle (oval, arch, hexagon, blob masks) and
 *     rounded corners.
 *
 * A path is a list of segments in fractions (0–1) of the shape's box:
 *   { move: [x, y] } · { line: [x, y] } · { cubic: [x1, y1, x2, y2, x, y] } · { close: true }
 * It becomes pptxgenjs custGeom points (shapes) or <a:custGeom> XML (pictures, via a patch).
 */

/** Control-point distance for a quarter ellipse drawn with one cubic Bézier. */
const KAPPA = 0.5522847498;

/**
 * `polygon(50% 0%, 100% 100%, 0% 100%)` → [{ x: 0.5, y: 0 }, …] in 0–1 of the box.
 * Only percentages are supported; anything else (px, calc, other clip-path functions) → null.
 */
function parsePolygonClipPath(clipPath) {
  const m = /^\s*polygon\(\s*(?:(?:nonzero|evenodd)\s*,\s*)?([^)]*)\)\s*$/i.exec(String(clipPath || ''));
  if (!m) return null;
  const points = [];
  for (const pair of m[1].split(',')) {
    const parts = pair.trim().split(/\s+/);
    if (parts.length !== 2) return null;
    const [x, y] = parts.map((v) => (/^-?[\d.]+%$/.test(v) ? parseFloat(v) / 100 : NaN));
    if (!Number.isFinite(x) || !Number.isFinite(y)) return null;
    points.push({ x, y });
  }
  return points.length >= 3 ? points : null;
}

/** pptxgenjs custGeom points (inches inside the shape box) for a polygon. */
function custGeomPoints(polygon, box) {
  return [
    ...polygon.map((p, i) => ({ x: p.x * box.w, y: p.y * box.h, ...(i === 0 ? { moveTo: true } : {}) })),
    { close: true },
  ];
}

/** CSS border style → pptxgenjs dashType. */
function dashTypeFor(borderStyle) {
  const style = String(borderStyle || '').toLowerCase();
  if (style === 'dashed') return 'dash';
  if (style === 'dotted') return 'sysDot';
  return null;
}

/**
 * The radii a browser actually uses for a box `w` × `h`: when adjacent corners ask for more
 * than the side, every radius shrinks by the same factor (CSS Backgrounds 3, §5.5).
 * @param {Array<[number, number]>} radii  [horizontal, vertical] for TL, TR, BR, BL
 */
function clampRadii(radii, w, h) {
  const r = (radii || []).slice(0, 4).map((c) => [Math.max(0, Number(c?.[0]) || 0), Math.max(0, Number(c?.[1]) || 0)]);
  while (r.length < 4) r.push([0, 0]);
  const [tl, tr, br, bl] = r;
  const ratios = [w / (tl[0] + tr[0]), w / (bl[0] + br[0]), h / (tl[1] + bl[1]), h / (tr[1] + br[1])].filter(Number.isFinite);
  const f = Math.min(1, ...ratios);
  return r.map(([x, y]) => [x * f, y * f]);
}

/** True when every corner is square (a plain rectangle needs no custom geometry). */
function isSquareBox(radii) {
  return !(radii || []).some((c) => (Number(c?.[0]) || 0) > 0.01 || (Number(c?.[1]) || 0) > 0.01);
}

/**
 * Path of a box `w` × `h` with corner radii (same unit as w / h), inset by `inset` on every side
 * (a border drawn inside the box, as CSS does). Fractions of the box.
 */
function roundedBoxPath(radii, w, h, { inset = 0 } = {}) {
  if (!(w > 0 && h > 0)) return null;
  const [tl, tr, br, bl] = clampRadii(radii, w, h).map(([x, y]) => [Math.max(0, x - inset), Math.max(0, y - inset)]);
  const L = inset;
  const T = inset;
  const R = w - inset;
  const B = h - inset;
  const P = (x, y) => [x / w, y / h];
  const curve = (c1, c2, to) => ({ cubic: [...P(...c1), ...P(...c2), ...P(...to)] });
  const segs = [{ move: P(L + tl[0], T) }, { line: P(R - tr[0], T) }];
  if (tr[0] || tr[1]) segs.push(curve([R - tr[0] + KAPPA * tr[0], T], [R, T + tr[1] - KAPPA * tr[1]], [R, T + tr[1]]));
  segs.push({ line: P(R, B - br[1]) });
  if (br[0] || br[1]) segs.push(curve([R, B - br[1] + KAPPA * br[1]], [R - br[0] + KAPPA * br[0], B], [R - br[0], B]));
  segs.push({ line: P(L + bl[0], B) });
  if (bl[0] || bl[1]) segs.push(curve([L + bl[0] - KAPPA * bl[0], B], [L, B - bl[1] + KAPPA * bl[1]], [L, B - bl[1]]));
  segs.push({ line: P(L, T + tl[1]) });
  if (tl[0] || tl[1]) segs.push(curve([L, T + tl[1] - KAPPA * tl[1]], [L + tl[0] - KAPPA * tl[0], T], [L + tl[0], T]));
  segs.push({ close: true });
  return segs;
}

/** A CSS length in a clip-path: `40%` of `ref`, `12px`, or a position keyword. */
function cssLength(value, ref) {
  const v = String(value || '').trim();
  if (/^-?[\d.]+%$/.test(v)) return (parseFloat(v) / 100) * ref;
  if (/^-?[\d.]+(px)?$/.test(v)) return parseFloat(v);
  if (v === 'center') return ref / 2;
  if (v === 'left' || v === 'top') return 0;
  if (v === 'right' || v === 'bottom') return ref;
  return NaN;
}

/** Keep the part of a polygon inside the box [0, w] × [0, h] (Sutherland–Hodgman). */
function clipToBox(points, w, h) {
  const inside = [(p) => p.x >= 0, (p) => p.x <= w, (p) => p.y >= 0, (p) => p.y <= h];
  const cross = [
    (a, b) => ({ x: 0, y: a.y + ((b.y - a.y) * (0 - a.x)) / (b.x - a.x) }),
    (a, b) => ({ x: w, y: a.y + ((b.y - a.y) * (w - a.x)) / (b.x - a.x) }),
    (a, b) => ({ x: a.x + ((b.x - a.x) * (0 - a.y)) / (b.y - a.y), y: 0 }),
    (a, b) => ({ x: a.x + ((b.x - a.x) * (h - a.y)) / (b.y - a.y), y: h }),
  ];
  let out = points;
  for (let e = 0; e < 4 && out.length; e += 1) {
    const input = out;
    out = [];
    for (let i = 0; i < input.length; i += 1) {
      const cur = input[i];
      const prev = input[(i + input.length - 1) % input.length];
      if (inside[e](cur)) {
        if (!inside[e](prev)) out.push(cross[e](prev, cur));
        out.push(cur);
      } else if (inside[e](prev)) {
        out.push(cross[e](prev, cur));
      }
    }
  }
  return out;
}

/**
 * A CSS clip-path on a box `w` × `h` as a polygon in fractions of the box, clipped to the box:
 * polygon(), ellipse(rx ry at x y) and circle(r at x y). Curves become 180-point outlines.
 * Returns null for anything else (inset, path, url…).
 */
function clipPathToPolygon(clipPath, w = 1, h = 1) {
  const raw = String(clipPath || '').trim();
  const poly = parsePolygonClipPath(raw);
  if (poly) {
    const clipped = clipToBox(poly.map((p) => ({ x: p.x * w, y: p.y * h })), w, h);
    return clipped.length >= 3 ? clipped.map((p) => ({ x: p.x / w, y: p.y / h })) : null;
  }
  const m = /^(ellipse|circle)\(\s*([^)]*?)\s*\)$/i.exec(raw);
  if (!m || !(w > 0 && h > 0)) return null;
  const [sizePart, atPart = 'center center'] = m[2].split(/\s*\bat\b\s*/i);
  const sizes = sizePart.trim() ? sizePart.trim().split(/\s+/) : [];
  const at = atPart.trim().split(/\s+/);
  const cx = cssLength(at[0], w);
  const cy = cssLength(at[1] ?? 'center', h);
  let rx;
  let ry;
  if (m[1].toLowerCase() === 'circle') {
    rx = cssLength(sizes[0] ?? '50%', Math.hypot(w, h) / Math.SQRT2);
    ry = rx;
  } else {
    rx = cssLength(sizes[0] ?? '50%', w);
    ry = cssLength(sizes[1] ?? '50%', h);
  }
  if (![cx, cy, rx, ry].every(Number.isFinite) || rx <= 0 || ry <= 0) return null;
  const n = 180;
  const outline = Array.from({ length: n }, (_, i) => {
    const t = (i / n) * Math.PI * 2;
    return { x: cx + rx * Math.cos(t), y: cy + ry * Math.sin(t) };
  });
  const clipped = clipToBox(outline, w, h);
  return clipped.length >= 3 ? clipped.map((p) => ({ x: p.x / w, y: p.y / h })) : null;
}

/** A polygon (fractions) as path segments. */
function polygonPath(points) {
  if (!points || points.length < 3) return null;
  return [{ move: [points[0].x, points[0].y] }, ...points.slice(1).map((p) => ({ line: [p.x, p.y] })), { close: true }];
}

/** Path segments → pptxgenjs custGeom points, in inches inside a box `box.w` × `box.h`. */
function pathToCustGeomPoints(segments, box) {
  const X = (v) => v * box.w;
  const Y = (v) => v * box.h;
  return segments.map((s) => {
    if (s.move) return { x: X(s.move[0]), y: Y(s.move[1]), moveTo: true };
    if (s.line) return { x: X(s.line[0]), y: Y(s.line[1]) };
    if (s.cubic) {
      const [x1, y1, x2, y2, x, y] = s.cubic;
      return { x: X(x), y: Y(y), curve: { type: 'cubic', x1: X(x1), y1: Y(y1), x2: X(x2), y2: Y(y2) } };
    }
    return { close: true };
  });
}

/**
 * Path segments → <a:custGeom> XML. The path's own coordinate space (100000 × 100000) scales to
 * whatever box the shape or picture has, so no sizes are needed.
 */
function pathToCustGeomXml(segments) {
  const S = 100000;
  const pt = (x, y) => `<a:pt x="${Math.round(x * S)}" y="${Math.round(y * S)}"/>`;
  const body = segments
    .map((s) => {
      if (s.move) return `<a:moveTo>${pt(...s.move)}</a:moveTo>`;
      if (s.line) return `<a:lnTo>${pt(...s.line)}</a:lnTo>`;
      if (s.cubic) {
        const [x1, y1, x2, y2, x, y] = s.cubic;
        return `<a:cubicBezTo>${pt(x1, y1)}${pt(x2, y2)}${pt(x, y)}</a:cubicBezTo>`;
      }
      return '<a:close/>';
    })
    .join('');
  return `<a:custGeom><a:avLst/><a:gdLst/><a:ahLst/><a:cxnLst/><a:rect l="l" t="t" r="r" b="b"/><a:pathLst><a:path w="${S}" h="${S}">${body}</a:path></a:pathLst></a:custGeom>`;
}

module.exports = {
  parsePolygonClipPath,
  custGeomPoints,
  dashTypeFor,
  clampRadii,
  isSquareBox,
  roundedBoxPath,
  clipPathToPolygon,
  polygonPath,
  pathToCustGeomPoints,
  pathToCustGeomXml,
};
