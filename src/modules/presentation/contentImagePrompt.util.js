'use strict';

const { isMediaImageSlot } = require('./layoutToElements');
const {
  isDeviceScreenSlotId,
  deviceUiScreenshotDirective,
  deviceScreenUiKind,
} = require('./diagrams/deviceChrome.util');

const SINGLE_SUBJECT_NEGATIVES =
  'no triptych, no multi-panel, no split image, no collage, no diptych, no grid, no multiple cups, no comparison sheet, no split frame';

const CHART_PHOTO_NEGATIVES =
  'no charts, no graphs, no bar charts, no line charts, no pie charts, no dashboards, no axes, no data visualizations, no spreadsheet screens';

const TEXT_NEGATIVES =
  'no text, no words, no letters, no captions, no typography, no watermarks, no logos, no UI chrome, no posters with headlines';
function shortVisualPhrase(text, maxWords = 8) {
  const raw = String(text || '').trim();
  if (!raw) return '';
  const beforeBreak = raw.split(/[:â€”â€“|]/)[0].trim();
  const source = beforeBreak && beforeBreak.split(/\s+/).filter(Boolean).length >= 2 ? beforeBreak : raw;
  const words = source.split(/\s+/).filter(Boolean);
  if (!words.length) return '';
  return words.slice(0, Math.max(2, maxWords)).join(' ');
}

function slideCopyCorpus(content = {}) {
  const parts = [];
  const push = (v) => {
    const s = String(v || '').trim();
    if (s) parts.push(s);
  };
  push(content.body);
  push(content.summary);
  push(content.subtitle);
  push(content.left_body);
  push(content.right_body);
  for (const col of content.columns || content.cards || content.features || content.items || []) {
    if (typeof col === 'string') push(col);
    else if (col && typeof col === 'object') {
      push(col.body);
      push(col.text);
      push(col.description);
    }
  }
  for (const b of content.bullets || []) {
    if (typeof b === 'string') push(b);
    else if (b && typeof b === 'object') push(b.text || b.body || b.description);
  }
  return parts;
}

/** True when an image prompt reuses a long phrase from slide body copy. */
function imagePromptEchoesCopy(prompt, content = {}) {
  const p = String(prompt || '')
    .toLowerCase()
    .replace(/\s+/g, ' ')
    .trim();
  if (p.length < 36) return false;
  const bodies = slideCopyCorpus(content);
  for (const body of bodies) {
    const normalized = String(body).toLowerCase().replace(/\s+/g, ' ').trim();
    if (normalized.length < 28) continue;
    const words = normalized.split(/\s+/).filter(Boolean);
    if (words.length < 6) continue;
    for (let i = 0; i <= words.length - 6; i += 1) {
      const ngram = words.slice(i, i + 6).join(' ');
      if (p.includes(ngram)) return true;
    }
  }
  return false;
}

function appendImageNegatives(prompt, { isDevice = false, hasChart = false } = {}) {
  let next = String(prompt || '').trim();
  if (!next) return next;
  const lower = next.toLowerCase();
  if (!isDevice && !lower.includes('no text')) {
    next = `${next}. ${TEXT_NEGATIVES}`;
  }
  if (!lower.includes('no collage') && !lower.includes('no triptych')) {
    next = `${next}. ${SINGLE_SUBJECT_NEGATIVES}`;
  }
  if (hasChart && !lower.includes('no charts')) {
    next = `${next}. ${CHART_PHOTO_NEGATIVES}`;
  }
  return next;
}

function withDeviceUiDirective(prompt, slotId, layoutId = '') {
  const base = String(prompt || '').trim();
  if (!isDeviceScreenSlotId(slotId)) return base;
  const directive = deviceUiScreenshotDirective(slotId, layoutId);
  const lower = base.toLowerCase();
  const kind = deviceScreenUiKind(slotId, layoutId);
  const already =
    (kind === 'website' && /website|web[- ]?app|browser|desktop ui/.test(lower)) ||
    (kind === 'mobile_app' && /mobile app|phone app|app ui|ios|android/.test(lower)) ||
    (kind === 'watch_app' && /watch|wearable/.test(lower));
  if (already && /no (phone|laptop|tablet|device|bezel|hardware)/.test(lower)) return base;
  return `${base}. ${directive}`;
}

function columnEntryAt(content = {}, index) {
  const list = content.columns || content.cards || content.features || content.items || [];
  const col = Array.isArray(list) ? list[index] : null;
  return col && typeof col === 'object' ? col : null;
}

/** Short visual noun phrase only â€” never paste paragraph body into image prompts. */
function columnSubjectFromEntry(col) {
  if (!col || typeof col !== 'object') return null;
  const title = String(col.title ?? col.heading ?? col.label ?? '').trim();
  if (title) return shortVisualPhrase(title, 8);
  const body = String(col.body ?? col.text ?? col.description ?? '').trim();
  if (body) return shortVisualPhrase(body, 8);
  return null;
}

function numberedImageSlotIndex(slotId) {
  const id = String(slotId || '');
  let m = id.match(/^COL_(\d+)_IMAGE$/i);
  if (m) return Number(m[1]) - 1;
  m = id.match(/^METRIC_IMAGE_(\d+)$/i);
  if (m) return Number(m[1]) - 1;
  m = id.match(/^(?:GRID_)?IMAGE_(\d+)$/i);
  if (m) return Number(m[1]) - 1;
  m = id.match(/^POINT_IMAGE$/i);
  if (m) return 0;
  return null;
}

function layoutHasChartSlot(layoutSchema) {
  const slots = Array.isArray(layoutSchema?.slots) ? layoutSchema.slots : [];
  return slots.some((s) => String(s.role || '').toLowerCase() === 'chart');
}

function overallThemeSubject(content = {}, opts = {}) {
  const visual = String(content.visual || '').trim();
  if (visual) return shortVisualPhrase(visual, 12);

  const title = String(content.title || '').trim();
  if (title) return shortVisualPhrase(title, 10);

  const summary = String(content.summary || content.subtitle || content.body || '').trim();
  if (summary) return shortVisualPhrase(summary, 10);

  const deckSummary = String(
    opts.deckNarrative || opts.sourceText || content.deckSummary || content.overallSummary || ''
  ).trim();
  if (deckSummary) return shortVisualPhrase(deckSummary, 12);

  return null;
}

function resolveImagePromptAlias(slotId, imagePrompts = {}) {
  const id = String(slotId || '');
  const direct =
    imagePrompts[id] ||
    imagePrompts[id.toUpperCase()] ||
    imagePrompts[id.toLowerCase()] ||
    null;
  if (direct) return String(direct).trim();

  // LLM often keys IMAGE_n while layout uses COL_n_IMAGE
  const colMatch = id.match(/^COL_(\d+)_IMAGE$/i);
  if (colMatch) {
    const n = colMatch[1];
    const alt =
      imagePrompts[`IMAGE_${n}`] ||
      imagePrompts[`image_${n}`] ||
      imagePrompts[`IMAGE_${n}`.toLowerCase()];
    if (alt) return String(alt).trim();
  }
  const imageMatch = id.match(/^IMAGE_(\d+)$/i);
  if (imageMatch) {
    const n = imageMatch[1];
    const alt =
      imagePrompts[`COL_${n}_IMAGE`] ||
      imagePrompts[`col_${n}_image`] ||
      imagePrompts[`COL_${n}_IMAGE`.toLowerCase()];
    if (alt) return String(alt).trim();
  }
  return null;
}

function deriveSlotImagePromptBase(slotId, content = {}, layoutSchema = null, opts = {}) {
  const id = String(slotId || '');
  const imagePrompts =
    content?.imagePrompts && typeof content.imagePrompts === 'object' ? content.imagePrompts : {};
  const direct = resolveImagePromptAlias(id, imagePrompts);
  if (direct) return direct;

  const numberedIdx = numberedImageSlotIndex(id);
  if (numberedIdx != null && !/^POINT_IMAGE$/i.test(id)) {
    const fromCol = columnSubjectFromEntry(columnEntryAt(content, numberedIdx));
    if (fromCol) return fromCol;
  }

  if (/^POINT_IMAGE$/i.test(id)) {
    const pointTitle = String(
      content.pointHeading ||
        content.columns?.[0]?.title ||
        content.cards?.[0]?.title ||
        ''
    ).trim();
    if (pointTitle) return shortVisualPhrase(pointTitle, 8);
    const pointBody = String(
      content.pointBody || content.columns?.[0]?.body || content.cards?.[0]?.body || content.summary || ''
    ).trim();
    if (pointBody) return shortVisualPhrase(pointBody, 8);
  }

  const deviceMatch = id.match(/^DEVICE_IMAGE_(\d+)$/i);
  if (deviceMatch) {
    const idx = Number(deviceMatch[1]) - 1;
    const col = columnEntryAt(content, idx);
    const label = col ? String(col.title ?? col.heading ?? col.label ?? '').trim() : '';
    const base = shortVisualPhrase(label || String(content.title || '').trim(), 8);
    const layoutId = String(layoutSchema?.layout_id || '');
    const kind = deviceScreenUiKind(id, layoutId);
    const uiLabel = kind === 'website' ? 'website UI screenshot' : 'mobile app UI screenshot';
    if (base) return `${base} â€” ${uiLabel}`;
  }

  if (/^(PHONE_IMAGE|WATCH_IMAGE)$/i.test(id)) {
    const base = shortVisualPhrase(String(content.title || '').trim(), 8);
    if (base) return `${base} â€” mobile app UI screenshot`;
  }
  if (/^(TABLET_IMAGE|LAPTOP_IMAGE)$/i.test(id)) {
    const base = shortVisualPhrase(String(content.title || '').trim(), 8);
    if (base) return `${base} â€” website UI screenshot`;
  }

  if (/^(HERO_IMAGE|BACKGROUND_IMAGE)$/i.test(id)) {
    const theme = overallThemeSubject(content, opts);
    if (theme) return theme;
  }

  if (content.title) {
    const slots = Array.isArray(layoutSchema?.slots) ? layoutSchema.slots : [];
    const imageSlots = slots.filter((s) => isMediaImageSlot(s.id, s.role, s));
    if (imageSlots.length > 1) {
      const slotIndex = imageSlots.findIndex((s) => String(s.id) === id);
      if (slotIndex >= 0) {
        const fromCol = columnSubjectFromEntry(columnEntryAt(content, slotIndex));
        if (fromCol) return fromCol;
        return `${content.title} â€” visual ${slotIndex + 1} of ${imageSlots.length}`;
      }
    }
  }

  return overallThemeSubject(content, opts);
}

function buildSlotImagePrompt(slotId, content = {}, layoutSchema = null, opts = {}) {
  const id = String(slotId || '');
  const isDevice = isDeviceScreenSlotId(id);
  const layoutId = String(layoutSchema?.layout_id || '').trim();
  const imagePrompts =
    content?.imagePrompts && typeof content.imagePrompts === 'object' ? content.imagePrompts : {};
  const llmPrompt = resolveImagePromptAlias(id, imagePrompts);
  let subject = '';

  if (llmPrompt && !imagePromptEchoesCopy(llmPrompt, content)) {
    // Keep concrete visual briefs from the content model.
    subject = String(llmPrompt).trim();
  } else {
    const numberedIdx = numberedImageSlotIndex(id);
    if (numberedIdx != null && !/^POINT_IMAGE$/i.test(id)) {
      subject = columnSubjectFromEntry(columnEntryAt(content, numberedIdx)) || '';
    }
    if (!subject) {
      subject = deriveSlotImagePromptBase(id, content, layoutSchema, opts) || '';
    }
    if (subject && imagePromptEchoesCopy(subject, content)) {
      const fromCol =
        numberedIdx != null ? columnSubjectFromEntry(columnEntryAt(content, numberedIdx)) : null;
      subject =
        fromCol ||
        overallThemeSubject(content, opts) ||
        shortVisualPhrase(content?.title || 'Slide topic', 8);
    }
  }

  if (!subject) {
    subject =
      overallThemeSubject(content, opts) ||
      shortVisualPhrase(content?.title || 'Slide topic', 8);
  }

  const slots = Array.isArray(layoutSchema?.slots) ? layoutSchema.slots : [];
  const imageSlots = slots.filter((s) => isMediaImageSlot(s.id, s.role, s));
  const slotIndex = Math.max(0, imageSlots.findIndex((s) => String(s.id) === id));
  const hasChart = layoutHasChartSlot(layoutSchema);
  const isHero = /^(HERO_IMAGE|BACKGROUND_IMAGE)$/i.test(id);
  const uiKind = deviceScreenUiKind(id, layoutId);

  const assembled = [
    isDevice
      ? `${id}${layoutId ? ` of ${layoutId}` : ''}: ${
          uiKind === 'website'
            ? 'flat website UI screenshot'
            : uiKind === 'watch_app'
              ? 'flat watch app UI screenshot'
              : 'flat mobile app UI screenshot'
        }`
      : isHero
        ? `${id}${layoutId ? ` of ${layoutId}` : ''}: establishing photograph matching the deck theme`
        : `${id}${layoutId ? ` of ${layoutId}` : ''}: isolated single subject photograph`,
    /four_images|grid_.*images|three_cards_image|grid_images_text/i.test(layoutId)
      ? 'Gallery slot â€” ONE distinct visual metaphor of this cardâ€™s topic (not the cardâ€™s wording)'
      : null,
    hasChart && !isHero
      ? 'Slide already has a rendered chart â€” photograph a related real-world subject, not a chart graphic'
      : null,
    isDevice
      ? `UI screen content: ${subject}`
      : `Single photograph, ONE subject only, no collage: ${subject}`,
    `(variation ${slotIndex + 1})`,
  ]
    .filter(Boolean)
    .join('. ');

  return appendImageNegatives(withDeviceUiDirective(assembled, id, layoutId), {
    isDevice,
    hasChart,
  });
}

function deriveSlotImagePrompt(slotId, content = {}, layoutSchema = null, opts = {}) {
  return buildSlotImagePrompt(slotId, content, layoutSchema, opts);
}

/** Author/LLM-supplied visual brief on the slide content, if any. */
function resolveAuthorImagePrompt(content = {}) {
  if (!content || typeof content !== 'object') return '';
  const candidates = [
    content.imagePrompt,
    content.image_prompt,
    content.visual,
    content.visualPrompt,
    content.visual_prompt,
    content.authorImagePrompt,
    content.imageBrief && content.imageBrief.subject,
    content.brief && content.brief.subject,
  ];
  for (const value of candidates) {
    const text = String(value || '').trim();
    if (text) return text;
  }
  return '';
}

function titleWordsFromBody(body, fallback) {
  const words = String(body || '')
    .trim()
    .split(/\s+/)
    .filter(Boolean);
  if (words.length >= 2) return words.slice(0, 4).join(' ');
  return fallback;
}

module.exports = {
  shortVisualPhrase,
  slideCopyCorpus,
  imagePromptEchoesCopy,
  appendImageNegatives,
  withDeviceUiDirective,
  layoutHasChartSlot,
  resolveImagePromptAlias,
  buildSlotImagePrompt,
  deriveSlotImagePrompt,
  resolveAuthorImagePrompt,
  titleWordsFromBody,
};
