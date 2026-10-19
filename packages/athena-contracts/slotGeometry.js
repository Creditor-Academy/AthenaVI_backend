'use strict';

const DEFAULT_CANVAS = { width: 1920, height: 1080 };

function parseRegion(region) {
  if (!region) return null;
  const str = String(region);
  const colMatch = str.match(/cols?\s+(\d+)[-–](\d+)/i);
  const rowMatch = str.match(/rows?\s+(\d+)[-–](\d+)/i);
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
    const reg = parseRegion(slot?.region);
    if (!reg) continue;
    maxR = Math.max(maxR, reg.r2);
    maxC = Math.max(maxC, reg.c2);
  }
  return { COLS: Math.max(12, maxC), ROWS: Math.max(10, maxR) };
}

function gridRegionToPlacement(reg, grid, canvas = DEFAULT_CANVAS) {
  const COLS = grid?.COLS || 12;
  const ROWS = grid?.ROWS || 10;
  const w = canvas.width || DEFAULT_CANVAS.width;
  const h = canvas.height || DEFAULT_CANVAS.height;
  const colW = w / COLS;
  const rowH = h / ROWS;
  return {
    x: Math.round((reg.c1 - 1) * colW),
    y: Math.round((reg.r1 - 1) * rowH),
    width: Math.round((reg.c2 - reg.c1 + 1) * colW),
    height: Math.round((reg.r2 - reg.r1 + 1) * rowH),
  };
}

function slotEnvelope(slot, canvas = DEFAULT_CANVAS) {
  const reg = parseRegion(slot?.region);
  if (!reg) return null;
  const grid = getGridDims([slot]);
  return gridRegionToPlacement(reg, grid, canvas);
}

module.exports = {
  DEFAULT_CANVAS,
  parseRegion,
  getGridDims,
  gridRegionToPlacement,
  slotEnvelope,
};
