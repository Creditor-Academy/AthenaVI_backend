'use strict';

/** Horizontal inset for text boxes (~5% of 1920). Images are not affected. */
const SLIDE_TEXT_SAFE_INSET_X = 96;
/** Vertical inset for text boxes (~5% of 1080). */
const SLIDE_TEXT_SAFE_INSET_Y = 54;

function slideTextSafeRect(canvasW = 1920, canvasH = 1080) {
  const w = Math.max(320, Number(canvasW) || 1920);
  const h = Math.max(240, Number(canvasH) || 1080);
  const insetX = Math.min(SLIDE_TEXT_SAFE_INSET_X, Math.floor(w * 0.12));
  const insetY = Math.min(SLIDE_TEXT_SAFE_INSET_Y, Math.floor(h * 0.12));
  return {
    x: insetX,
    y: insetY,
    width: Math.max(80, w - insetX * 2),
    height: Math.max(80, h - insetY * 2),
  };
}

function clampPlacementToSafeRect(placement, safe) {
  if (!placement || !safe) return placement;
  let x = Number(placement.x) || 0;
  let y = Number(placement.y) || 0;
  let width = Math.max(1, Number(placement.width) || 1);
  let height = Math.max(1, Number(placement.height) || 1);
  const safeRight = safe.x + safe.width;
  const safeBottom = safe.y + safe.height;

  if (x < safe.x) {
    width -= safe.x - x;
    x = safe.x;
  }
  if (y < safe.y) {
    height -= safe.y - y;
    y = safe.y;
  }
  if (x + width > safeRight) {
    width = safeRight - x;
  }
  if (y + height > safeBottom) {
    height = safeBottom - y;
  }

  width = Math.max(1, Math.round(width));
  height = Math.max(1, Math.round(height));

  return {
    ...placement,
    x: Math.round(x),
    y: Math.round(y),
    width,
    height,
  };
}

function placementInsideSafeRect(placement, safe, tolerance = 2) {
  if (!placement || !safe) return true;
  const x = Number(placement.x) || 0;
  const y = Number(placement.y) || 0;
  const w = Number(placement.width) || 0;
  const h = Number(placement.height) || 0;
  return (
    x >= safe.x - tolerance &&
    y >= safe.y - tolerance &&
    x + w <= safe.x + safe.width + tolerance &&
    y + h <= safe.y + safe.height + tolerance
  );
}

module.exports = {
  SLIDE_TEXT_SAFE_INSET_X,
  SLIDE_TEXT_SAFE_INSET_Y,
  slideTextSafeRect,
  clampPlacementToSafeRect,
  placementInsideSafeRect,
};
