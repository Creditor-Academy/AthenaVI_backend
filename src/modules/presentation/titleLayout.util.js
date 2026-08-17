/**
 * Title slide layout pools — rotate variants instead of one fixed hero template.
 */

const { simpleDeckHash } = require('./slideArrangementPlan.service');

/** Image-forward title layouts (shaped hero, fade, full bleed). */
const TITLE_IMAGE_LAYOUTS = [
  'title_hero_left_blob_v1',
  'title_hero_right_oval_v1',
  'title_hero_left_fade_v1',
  'title_hero_right_fade_v1',
  'title_fullbleed_v1',
  'title_image_logo_v1',
];

/** Text-only title layouts when visuals are off or unavailable. */
const TITLE_TEXT_LAYOUTS = [
  'title_centered_v1',
  'title_minimal_v1',
  'title_statement_v1',
  'headline_centered_v1',
  'title_with_logo_v1',
];

function resolveTitlePreferredLayoutId(ctx, preferVisuals = true, usedLayoutIds = null) {
  const pool = preferVisuals ? TITLE_IMAGE_LAYOUTS : TITLE_TEXT_LAYOUTS;
  const used = usedLayoutIds && typeof usedLayoutIds.has === 'function' ? usedLayoutIds : null;
  const unused = used ? pool.filter((id) => !used.has(String(id))) : pool;
  const candidates = unused.length ? unused : pool;
  const seed = simpleDeckHash(ctx || {});
  const idx = seed % candidates.length;
  return candidates[idx];
}

module.exports = {
  TITLE_IMAGE_LAYOUTS,
  TITLE_TEXT_LAYOUTS,
  resolveTitlePreferredLayoutId,
};
