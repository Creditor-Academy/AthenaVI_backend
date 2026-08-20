const MAIN_TITLE_SLOT_RE = /^(main_title|title|headline|heading)$/;

function isLikelyCoverLayout(layoutSchema) {
  const layoutId = String(layoutSchema?.layout_id || layoutSchema?.layoutId || '').toLowerCase();
  return (
    layoutId.startsWith('title_') ||
    layoutId.includes('fullbleed') ||
    layoutId.includes('hero') ||
    layoutId.includes('statement_top') ||
    layoutId.includes('statement_bottom')
  );
}

/**
 * Map existing slot roles/ids into semantic typography roles.
 * We do not change the renderer geometry; we only control which typeScale bucket to use.
 */
function inferTypographyRole({ slot = {}, layoutSchema = {} } = {}) {
  const slotRole = String(slot?.role || '').toLowerCase();
  const slotId = String(slot?.id || '').toLowerCase();

  const mainTitle = MAIN_TITLE_SLOT_RE.test(slotId) || (slotRole === 'heading' && MAIN_TITLE_SLOT_RE.test(slotId));
  const cover = isLikelyCoverLayout(layoutSchema);

  if (slotRole === 'heading') {
    if (mainTitle && cover) return 'heroTitle';
    if (mainTitle) return 'title';
    return 'title';
  }

  if (slotRole === 'subheading') return 'subtitle';
  if (slotRole === 'caption' || slotRole === 'eyebrow' || slotRole === 'attribution') return 'caption';
  if (slotRole === 'stat' || slotRole === 'stat_label') return 'metric';
  if (slotRole === 'quote') return 'sectionTitle';

  // Default: body-ish
  return 'body';
}

module.exports = {
  inferTypographyRole,
};

