'use strict';

const { toDeckLayout } = require('./toDeckLayout');
const { evaluateLayoutCompatibility } = require('./layoutCompatibility');
const { pickSafeLayoutFallback } = require('./layoutSafeFallback');

/**
 * Text layouts that can host any slide content (heading + bullet block). Last resort so a
 * slide never fails for lack of a layout; content normalizers reshape cards/columns into bullets.
 */
const UNIVERSAL_TEXT_LAYOUT_IDS = ['bullet_list_dense_v1', 'text_only_centered_v1', 'bullet_list_two_column_v1'];

function templateId(template) {
  return String(template?.schema?.layout_id || template?.variant || template?.id || '').trim();
}

/** Count hard-reject reasons across a pool — used to explain empty candidate pools in logs. */
function summarizeHardRejects(profile, templates) {
  const counts = {};
  for (const template of Array.isArray(templates) ? templates : []) {
    const layout = toDeckLayout(template);
    if (!layout?.id) continue;
    const result = evaluateLayoutCompatibility(profile, layout);
    if (result.status !== 'hardReject') continue;
    const reason = result.reasons?.[0] || 'unknown';
    counts[reason] = (counts[reason] || 0) + 1;
  }
  return counts;
}

function pickFromPool(profile, templates, excludeLayoutIds) {
  const pool = (Array.isArray(templates) ? templates : []).filter((t) => templateId(t));
  if (!pool.length) return null;
  const deckLayouts = pool.map((t) => toDeckLayout(t)).filter((l) => l?.id);
  const safe = pickSafeLayoutFallback(profile, deckLayouts, { excludeLayoutIds: excludeLayoutIds || [] });
  if (!safe?.id) return null;
  const template = pool.find((t) => templateId(t) === safe.id);
  return template ? { layoutId: safe.id, template } : null;
}

/**
 * Guarantee a layout for a generated slide when the narrowed candidate pool had none.
 *
 * Ladder: full catalog within the pack whitelist → full catalog ignoring the whitelist →
 * full catalog without adjacency/repeat exclusions → universal text layout. Never returns null
 * while the catalog contains any universal layout.
 *
 * @param {object} args
 * @param {object} args.profile SlideContentProfile
 * @param {(whitelist: string[]|null) => Promise<object[]>} args.loadAllTemplates
 * @param {(templates: object[]) => object[]} [args.filterForOrder] slide-order rules (title/closing)
 * @param {string[]|null} [args.layoutIdWhitelist]
 * @param {string[]|null} [args.excludeLayoutIds] soft exclusions (adjacent/repeat bans)
 * @param {string[]|null} [args.hardExcludeLayoutIds] never relaxed (e.g. layout just rejected for overflow)
 */
async function ensureCompatibleLayout({
  profile,
  loadAllTemplates,
  filterForOrder = (templates) => templates,
  layoutIdWhitelist = null,
  excludeLayoutIds = null,
  hardExcludeLayoutIds = null,
  slideNumber = null,
  logger = null,
}) {
  const hardExclude = (hardExcludeLayoutIds || []).map(String);
  const softExclude = [...new Set([...(excludeLayoutIds || []).map(String), ...hardExclude])];
  const hasWhitelist = Array.isArray(layoutIdWhitelist) && layoutIdWhitelist.length > 0;

  const prepare = (templates) => {
    const ordered = filterForOrder(templates || []);
    // Slide-order filters must not empty the pool entirely.
    return ordered.length ? ordered : templates || [];
  };

  const steps = [];
  if (hasWhitelist) steps.push({ source: 'catalog_whitelist', whitelist: layoutIdWhitelist, exclude: softExclude });
  steps.push({ source: 'catalog', whitelist: null, exclude: softExclude });
  steps.push({ source: 'catalog_relaxed', whitelist: null, exclude: hardExclude });

  let fullCatalog = null;
  for (const step of steps) {
    // eslint-disable-next-line no-await-in-loop
    const raw = await loadAllTemplates(step.whitelist);
    if (!step.whitelist) fullCatalog = raw;
    const hit = pickFromPool(profile, prepare(raw), step.exclude);
    if (hit) {
      if (step.source !== 'catalog_whitelist' && hasWhitelist) {
        logger?.warn?.('presentation_layout_whitelist_bypassed', {
          slideNumber,
          selectedLayoutId: hit.layoutId,
          whitelistSize: layoutIdWhitelist.length,
        });
      }
      return { ...hit, source: step.source };
    }
  }

  // Unfiltered catalog: slide-order rules (e.g. closing-only pools) must not block the last resort.
  const catalog = fullCatalog || (await loadAllTemplates(null)) || [];
  for (const id of UNIVERSAL_TEXT_LAYOUT_IDS) {
    const template = catalog.find((t) => templateId(t) === id && !hardExclude.includes(id));
    if (template) {
      logger?.warn?.('presentation_layout_universal_fallback', {
        slideNumber,
        selectedLayoutId: id,
        hardRejects: summarizeHardRejects(profile, catalog),
      });
      return { layoutId: id, template, source: 'universal_fallback' };
    }
  }
  return null;
}

module.exports = {
  UNIVERSAL_TEXT_LAYOUT_IDS,
  ensureCompatibleLayout,
  summarizeHardRejects,
};
