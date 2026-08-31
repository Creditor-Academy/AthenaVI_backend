/**
 * Prefer pure image-only grid layouts (bento) for gallery / photo-heavy slides.
 */

const PURE_IMAGE_GRID_LAYOUTS = [
  'grid_bento_four_v1',
  'grid_bento_three_v1',
  'grid_six_images_v1',
];

const TEXT_IMAGE_GRID_LAYOUTS = new Set([
  'grid_text_image_cards_v1',
  'grid_three_images_text_v1',
  'grid_images_text_cards_v1',
  'four_images_text_v1',
]);

function textHay(parts = []) {
  return parts
    .flatMap((p) => (Array.isArray(p) ? p : [p]))
    .map((v) => {
      if (v == null) return '';
      if (typeof v === 'string') return v;
      if (typeof v === 'object') {
        return [v.title, v.label, v.detail, v.body, v.text, v.name].filter(Boolean).join(' ');
      }
      return String(v);
    })
    .join(' ')
    .toLowerCase();
}

function beatCount({ beats, bullets, columns } = {}) {
  const from = (list) => (Array.isArray(list) ? list.filter(Boolean).length : 0);
  return Math.max(from(beats), from(bullets), from(columns), 0);
}

/** Slide needs readable body / bullets — keep text+image layouts. */
function hasSubstantialCopy({ summary, body, bullets, columns, beats } = {}) {
  const summaryLen = String(summary || body || '').trim().length;
  if (summaryLen > 160) return true;

  const lists = [bullets, columns, beats].filter(Array.isArray);
  for (const list of lists) {
    const items = list.filter(Boolean);
    if (!items.length) continue;
    let totalLen = 0;
    for (const item of items) {
      if (typeof item === 'string') totalLen += item.trim().length;
      else if (item && typeof item === 'object') {
        totalLen += String(
          item.body || item.detail || item.text || item.description || item.label || item.title || ''
        ).trim().length;
      }
    }
    const avgLen = totalLen / items.length;
    if (items.length >= 2 && avgLen > 48) return true;
    if (summaryLen > 90 && items.length >= 2 && avgLen > 28) return true;
  }
  return false;
}

function strongGalleryOnlyCue(hay, visual = '') {
  const combined = `${hay} ${String(visual || '')}`.toLowerCase();
  return /images? only|photo-led|mostly images|minimal copy|pure gallery|image-only|no copy|bento|multi-?image grid|distinct photos?|four photos?|photo cards?|gallery grid/i.test(
    combined
  );
}

function photoLedVisualDirection(visual = '', visualIntent = null) {
  const v = String(visual || '').toLowerCase();
  if (
    /photo|gallery|multi-?image|bento|portfolio|showcase|distinct photos?|image-led|mostly images|scenic|cinematic still/i.test(
      v
    )
  ) {
    return true;
  }
  return (
    Array.isArray(visualIntent) &&
    visualIntent.some((item) =>
      /photo|gallery|multi-?image|bento|showcase|image-led|scenic/i.test(String(item))
    )
  );
}

function isTextImageGridLayout(layoutId) {
  return TEXT_IMAGE_GRID_LAYOUTS.has(String(layoutId || '').trim());
}

function isPureImageGridLayoutId(layoutId) {
  return PURE_IMAGE_GRID_LAYOUTS.includes(String(layoutId || '').trim());
}

function galleryTextImageExcludeIds() {
  return [...TEXT_IMAGE_GRID_LAYOUTS];
}

/**
 * Slide is image-led gallery: multi-photo beats / visual direction, not feature copy.
 */
function looksLikeImageLedGallery({
  title,
  summary,
  beats,
  bullets,
  columns,
  visual,
  intent,
  contentType,
  suggestedContentType,
  arrangementHint,
  imageStylePhrase,
  visualIntent,
  wizardBrief,
} = {}) {
  const ct = String(
    contentType || suggestedContentType || arrangementHint || ''
  ).toLowerCase();
  const hay = textHay([
    title,
    summary,
    beats,
    bullets,
    visual,
    intent,
    visualIntent,
    wizardBrief,
  ]);
  const summaryLen = String(summary || '').trim().length;
  const nBeats = beatCount({ beats, bullets, columns });
  const substantialCopy = hasSubstantialCopy({ summary, body: summary, bullets, columns, beats });

  // Feature / copy-heavy grids need text slots
  if (
    /feature|benefit|capability|why (us|choose)|how it helps|describe this|key point|solution|overview|problem|approach/i.test(
      hay
    ) &&
    (summaryLen > 100 || substantialCopy)
  ) {
    return false;
  }
  if (/metric|kpi|stat|chart|data table|comparison table/i.test(hay)) {
    return false;
  }

  const photoStyle = /photo|scene|cinematic|still-life|gallery|visual|image-led|image heavy/i.test(
    String(imageStylePhrase || '')
  );
  const galleryCue =
    /gallery|bento|multi-image|photo cards?|spaces|rooms|moments|portfolio|showcase|local moments|stay packages|visual brand|images only|photo-led|distinct photos?|four photos?|mostly images|minimal copy|image-led cards?|photo-heavy/i.test(
      hay
    );
  const visualBeat =
    photoLedVisualDirection(visual, visualIntent) ||
    (nBeats >= 2 &&
      nBeats <= 6 &&
      summaryLen <= 100 &&
      !substantialCopy &&
      /photo|gallery|portfolio|showcase|distinct photos?|multi-?image|bento|room|pool|spa|terrace|coast|landscape|space|sunset/i.test(
        hay
      ));

  const gridish = ct === 'grid' || ct === 'image+text' || String(arrangementHint || '').toLowerCase() === 'grid';
  if (!gridish && !(photoStyle && (galleryCue || visualBeat))) return false;

  // Genuine text+image slides: keep text slots unless explicitly image-only gallery
  if (ct === 'image+text') {
    const strongGallery = galleryCue || visualBeat || strongGalleryOnlyCue(hay, visual);
    if (!strongGallery) return false;
    if (substantialCopy && !strongGalleryOnlyCue(hay, visual)) return false;
  }

  // Long explanatory copy on grid slides is not a pure photo gallery
  if (ct === 'grid' && substantialCopy && !strongGalleryOnlyCue(hay, visual) && !galleryCue) {
    return false;
  }

  return galleryCue || (photoStyle && visualBeat) || visualBeat;
}

/**
 * When true: coerce to grid pool + force pure bento layout.
 */
function resolvePureGallerySlidePolicy({
  layoutContentType,
  content,
  outlineSlide,
  ctx,
  usedLayoutIds,
} = {}) {
  const signals = {
    title: content?.title || outlineSlide?.title,
    summary: content?.summary || content?.body || outlineSlide?.summary,
    beats: outlineSlide?.beats || content?.beats,
    bullets: content?.bullets,
    columns: content?.columns,
    visual: outlineSlide?.visual,
    intent: outlineSlide?.intent || outlineSlide?.purpose || content?.intent,
    contentType: layoutContentType,
    suggestedContentType: outlineSlide?.suggestedContentType,
    arrangementHint: outlineSlide?.arrangementHint,
    imageStylePhrase: ctx?.imageStylePhrase || ctx?.themeTokens?.imageStyle || '',
    visualIntent: outlineSlide?.visualIntent || outlineSlide?.visual_intent,
    wizardBrief: ctx?.wizardBrief || ctx?.sourceText || ctx?.outline?.sourcePrompt || '',
  };
  if (!looksLikeImageLedGallery(signals)) return null;
  const n = beatCount(signals);
  return {
    layoutContentType: 'grid',
    preferredLayoutId: preferredPureGalleryLayoutId(n, usedLayoutIds),
    excludeLayoutIds: galleryTextImageExcludeIds(),
    profileOverrides: galleryProfileOverrides(signals),
  };
}

function preferredPureGalleryLayoutId(beatCountHint = 0, usedLayoutIds = null) {
  const used =
    usedLayoutIds && typeof usedLayoutIds.has === 'function' ? usedLayoutIds : new Set();
  const n = Number(beatCountHint) || 0;
  let prefs = PURE_IMAGE_GRID_LAYOUTS;
  if (n === 3) prefs = ['grid_bento_three_v1', 'grid_bento_four_v1', 'grid_six_images_v1'];
  else if (n >= 5) prefs = ['grid_six_images_v1', 'grid_bento_four_v1', 'grid_bento_three_v1'];
  else if (n === 4) prefs = ['grid_bento_four_v1', 'grid_six_images_v1', 'grid_bento_three_v1'];

  const unused = prefs.filter((id) => !used.has(String(id)));
  return (unused.length ? unused : prefs)[0] || 'grid_bento_four_v1';
}

/**
 * Profile overrides so pure bento layouts are not capacity-penalized by outline summary.
 */
function galleryProfileOverrides(signals = {}) {
  if (!looksLikeImageLedGallery(signals)) return null;
  const n = beatCount(signals);
  const imageCount = n >= 5 ? 6 : n === 3 ? 3 : 4;
  return {
    imageCount,
    body: '',
    summary: '',
    bullets: [],
    columns: [],
  };
}

/** Exclude text+image grids when the previous slide already used one. */
function galleryAdjacentExcludeIds(previousLayoutId) {
  const prev = String(previousLayoutId || '').trim();
  if (!isTextImageGridLayout(prev)) return [];
  return [...TEXT_IMAGE_GRID_LAYOUTS];
}

module.exports = {
  PURE_IMAGE_GRID_LAYOUTS,
  TEXT_IMAGE_GRID_LAYOUTS,
  isTextImageGridLayout,
  isPureImageGridLayoutId,
  looksLikeImageLedGallery,
  hasSubstantialCopy,
  preferredPureGalleryLayoutId,
  galleryProfileOverrides,
  beatCount,
  galleryAdjacentExcludeIds,
  galleryTextImageExcludeIds,
  resolvePureGallerySlidePolicy,
};
