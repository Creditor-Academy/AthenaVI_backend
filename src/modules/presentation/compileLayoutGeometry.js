/**
 * Authoritative layout geometry compiler (backend CJS mirror of frontend).
 */
const { CANVAS_WIDTH, CANVAS_HEIGHT } = require('./presentation.constants');

const DEFAULT_CANVAS = { width: CANVAS_WIDTH, height: CANVAS_HEIGHT };

function parseRegion(region) {
  if (!region) return null;
  const colMatch = String(region).match(/cols?\s+(\d+)[-–](\d+)/i);
  const rowMatch = String(region).match(/rows?\s+(\d+)[-–](\d+)/i);
  if (!colMatch || !rowMatch) return null;
  return {
    c1: parseInt(colMatch[1], 10),
    c2: parseInt(colMatch[2], 10),
    r1: parseInt(rowMatch[1], 10),
    r2: parseInt(rowMatch[2], 10),
  };
}

function getGridDims(slots = []) {
  let maxR = 10;
  let maxC = 12;
  for (const slot of slots) {
    const reg = parseRegion(slot.region);
    if (!reg) continue;
    maxR = Math.max(maxR, reg.r2);
    maxC = Math.max(maxC, reg.c2);
  }
  return { COLS: Math.max(12, maxC), ROWS: Math.max(10, maxR) };
}

function resolveSlotPaddingPx(slot, grid, canvas) {
  const p = slot?.padding;
  if (p == null) return { left: 0, right: 0, top: 0, bottom: 0 };

  const width = canvas?.width || DEFAULT_CANVAS.width;
  const height = canvas?.height || DEFAULT_CANVAS.height;
  const COLS = grid?.COLS || 12;
  const ROWS = grid?.ROWS || 10;
  const colW = width / COLS;
  const rowH = height / ROWS;

  if (typeof p === 'number') {
    const v = Number(p) || 0;
    const isGrid = v > 0 && v < 5;
    const px = isGrid ? { x: v * colW, y: v * rowH } : { x: v, y: v };
    return { left: px.x, right: px.x, top: px.y, bottom: px.y };
  }

  return {
    left: Number(p.left) || 0,
    right: Number(p.right) || 0,
    top: Number(p.top) || 0,
    bottom: Number(p.bottom) || 0,
  };
}

function gridRegionToPlacement(reg, grid, canvas, paddingPx = null) {
  const width = canvas?.width || DEFAULT_CANVAS.width;
  const height = canvas?.height || DEFAULT_CANVAS.height;
  const COLS = grid?.COLS || 12;
  const ROWS = grid?.ROWS || 10;
  const colW = width / COLS;
  const rowH = height / ROWS;
  const pad = paddingPx || { left: 0, right: 0, top: 0, bottom: 0 };
  const rawW = (reg.c2 - reg.c1 + 1) * colW;
  const rawH = (reg.r2 - reg.r1 + 1) * rowH;

  return {
    x: Math.round((reg.c1 - 1) * colW + pad.left),
    y: Math.round((reg.r1 - 1) * rowH + pad.top),
    width: Math.max(1, Math.round(rawW - pad.left - pad.right)),
    height: Math.max(1, Math.round(rawH - pad.top - pad.bottom)),
    rotation: 0,
    opacity: 1,
  };
}

function applySlotGeometryTransform(slot, placement) {
  const id = String(slot?.id || '');
  const transform = slot?.geometryTransform;

  if (transform === 'metricSquare' || /^METRIC_IMAGE_/i.test(id)) {
    const size = Math.max(48, Math.round(Math.min(placement.width || 0, placement.height || 0)));
    return {
      ...placement,
      x: Math.round((placement.x || 0) + ((placement.width || size) - size) / 2),
      y: Math.round((placement.y || 0) + ((placement.height || size) - size) / 2),
      width: size,
      height: size,
    };
  }

  return placement;
}

function compileLayoutGeometry(schema, canvas = DEFAULT_CANVAS) {
  const slots = Array.isArray(schema?.slots) ? schema.slots : [];
  const grid = getGridDims(slots);
  const map = new Map();

  for (const slot of slots) {
    if (!slot?.id || !slot?.region) continue;
    const reg = parseRegion(slot.region);
    if (!reg) continue;
    const paddingPx = resolveSlotPaddingPx(slot, grid, canvas);
    const base = gridRegionToPlacement(reg, grid, canvas, paddingPx);
    const compiled = applySlotGeometryTransform(slot, base);
    map.set(slot.id, { layout: { ...base }, compiled, base });
  }

  return map;
}

function getSlotPlacement(geometryMap, slotId, slot = null) {
  const entry = geometryMap.get(slotId);
  if (!entry) return null;
  if (slot) return applySlotGeometryTransform(slot, entry.base);
  return entry.compiled;
}

module.exports = {
  DEFAULT_CANVAS,
  parseRegion,
  getGridDims,
  compileLayoutGeometry,
  getSlotPlacement,
  gridRegionToPlacement,
  resolveSlotPaddingPx,
  applySlotGeometryTransform,
};
