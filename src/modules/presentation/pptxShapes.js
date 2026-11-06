/**
 * Library shapes drawn with a CSS clip-path polygon (triangles, stars, arrows, callouts…) as
 * native PowerPoint custom geometry, so they stay editable shapes (recolour, resize, outline)
 * instead of pictures.
 */

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

module.exports = { parsePolygonClipPath, custGeomPoints, dashTypeFor };
