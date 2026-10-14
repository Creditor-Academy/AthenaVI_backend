'use strict';

/**
 * One heading size for every content slide in a deck.
 *
 * Layout seeds and ~115 diagram compilers each hardcode their own heading size (16–72px), so
 * headings jumped in size slide to slide. This sets the main heading of every non-cover slide to
 * the theme's title size. When the box is too small, it grows downward into free space; otherwise
 * fitTextElementsToBoxes shrinks only as much as needed (never overlapping other content).
 * Mirrored in AthenaVI/src/utils/deckHeadingSize.js.
 */
const { isLikelyCoverLayout } = require('./typographyRoles');
const { FONT_REF_WIDTH, estimateLineCount } = require('../textFit.util');

const MAIN_HEADING_SLOTS = ['HEADING', 'TITLE', 'MAIN_TITLE', 'HEADLINE'];
/** Display-style slides keep their own large heading. */
const EXEMPT_CONTENT_TYPES = new Set(['title', 'section_divider', 'closing']);

/** A single cramped layout must not shrink every heading in the deck below this. */
const MIN_DECK_HEADING_PX = 24;

function resolveDeckHeadingPx(themeTokens) {
  const scale = themeTokens?.typeScale || {};
  // Size harmonized after generation (see harmonizeDeckHeadings) wins for later recompiles.
  const deckHeading = Number(scale.deckHeading);
  if (deckHeading > 0) return Math.round(deckHeading);
  const title = Number(scale.title);
  if (title > 0) return Math.round(title);
  const display = Number(scale.display);
  if (display > 0) return Math.round(display * 0.75);
  return 42;
}

function isExemptLayout(layoutSchema) {
  const contentType = String(layoutSchema?.content_type || layoutSchema?.contentType || '').toLowerCase();
  const layoutId = String(layoutSchema?.layout_id || '').toLowerCase();
  return (
    isLikelyCoverLayout(layoutSchema) ||
    EXEMPT_CONTENT_TYPES.has(contentType) ||
    /^(section_|closing_|thank_you)/.test(layoutId)
  );
}

function plainText(content) {
  if (typeof content?.text === 'string') return content.text;
  if (Array.isArray(content?.runs)) return content.runs.map((r) => String(r?.text || '')).join('');
  return '';
}

/** The slide's main heading: HEADING/TITLE/MAIN_TITLE/HEADLINE, else CHART_HEADING when it is the only title. */
function findMainHeading(elements) {
  const texts = elements.filter((el) => el && (el.type === 'text' || el.type === 'textbox'));
  const bySlot = (ids) => texts.find((el) => ids.includes(String(el.slotId || '').toUpperCase()));
  return bySlot(MAIN_HEADING_SLOTS) || bySlot(['CHART_HEADING']) || null;
}

/** Canvas-px height the text needs at `fontSize` (font sizes are editor-stage px). */
function requiredHeight(content, width, fontSize, canvasWidth) {
  const px = fontSize * (Math.max(canvasWidth, 320) / FONT_REF_WIDTH);
  const pad = Number(content?.padding) || 0;
  const lineHeight = Number(content?.lineHeight) > 0 ? Number(content.lineHeight) : 1.2;
  const charsPerLine = Math.max(1, (width - pad * 2) / (px * 0.54));
  return Math.ceil(estimateLineCount(plainText(content).trim(), charsPerLine) * px * lineHeight + pad * 2);
}

const rect = (p) => ({ x: Number(p?.x) || 0, y: Number(p?.y) || 0, w: Number(p?.width) || 0, h: Number(p?.height) || 0 });
const overlaps = (a, b) => a.x < b.x + b.w && b.x < a.x + a.w && a.y < b.y + b.h && b.y < a.y + a.h;
const contains = (outer, inner) =>
  outer.x <= inner.x && outer.y <= inner.y && outer.x + outer.w >= inner.x + inner.w && outer.y + outer.h >= inner.y + inner.h;

/** Grow the heading box downward when the space below is free (cards/backgrounds behind it are ignored). */
function growIntoFreeSpace(heading, elements, neededH, canvasHeight) {
  const box = rect(heading.placement);
  if (neededH <= box.h) return heading;
  const grown = { ...box, h: Math.min(neededH, canvasHeight - box.y) };
  const blocked = elements.some((el) => {
    if (!el || el === heading || el.id === heading.id) return false;
    const r = rect(el.placement);
    if (!(r.w > 0 && r.h > 0)) return false;
    if (contains(r, box)) return false; // panel / background behind the heading
    return overlaps(grown, r);
  });
  if (blocked || grown.h <= box.h) return heading;
  return { ...heading, placement: { ...heading.placement, height: Math.round(grown.h) } };
}

/**
 * @param {{ elements?: object[] }} doc compiled elements doc
 * @param {{ themeTokens?: object, layoutSchema?: object, canvas?: { width?: number, height?: number } }} opts
 */
function applyDeckHeadingSize(doc, { themeTokens = null, layoutSchema = null, canvas = {} } = {}) {
  if (!doc || !Array.isArray(doc.elements) || isExemptLayout(layoutSchema)) return doc;
  const heading = findMainHeading(doc.elements);
  if (!heading || !plainText(heading.content).trim()) return doc;

  const targetPx = resolveDeckHeadingPx(themeTokens);
  const canvasWidth = Number(canvas.width) || Number(doc.canvas?.width) || 1920;
  const canvasHeight = Number(canvas.height) || Number(doc.canvas?.height) || 1080;

  let next = {
    ...heading,
    content: {
      ...heading.content,
      fontSize: targetPx,
      deckHeading: true,
      ...(Array.isArray(heading.content?.runs)
        ? { runs: heading.content.runs.map((r) => (r && r.fontSize ? { ...r, fontSize: targetPx } : r)) }
        : {}),
    },
  };
  const width = Number(next.placement?.width) || 0;
  if (width > 0) {
    next = growIntoFreeSpace(next, doc.elements, requiredHeight(next.content, width, targetPx, canvasWidth), canvasHeight);
  }
  return { ...doc, elements: doc.elements.map((el) => (el === heading ? next : el)) };
}

const withFontSize = (el, size) => ({
  ...el,
  content: {
    ...el.content,
    fontSize: size,
    ...(Array.isArray(el.content?.runs)
      ? { runs: el.content.runs.map((r) => (r && r.fontSize ? { ...r, fontSize: size } : r)) }
      : {}),
  },
});

/**
 * Deck-level pass after all slides compiled: per-slide fitting may have shrunk some headings, so
 * bring every heading down to the smallest fitted size (never below MIN_DECK_HEADING_PX). Only
 * shrinks, so it can never cause overflow.
 * @param {{ id: string, elements?: { elements?: object[] } }[]} slides
 * @returns {{ headingPx: number|null, updates: { slideId: string, elements: object }[] }}
 */
function harmonizeDeckHeadings(slides, { floor = MIN_DECK_HEADING_PX } = {}) {
  const headings = [];
  for (const slide of Array.isArray(slides) ? slides : []) {
    const els = slide?.elements?.elements;
    if (!Array.isArray(els)) continue;
    const heading = els.find((el) => el?.content?.deckHeading === true);
    const size = Number(heading?.content?.fontSize);
    if (heading && size > 0) headings.push({ slide, heading, size });
  }
  if (!headings.length) return { headingPx: null, updates: [] };

  const headingPx = Math.max(floor, Math.min(...headings.map((h) => h.size)));
  const updates = headings
    .filter((h) => h.size > headingPx)
    .map(({ slide, heading }) => ({
      slideId: slide.id,
      elements: {
        ...slide.elements,
        elements: slide.elements.elements.map((el) => (el === heading ? withFontSize(el, headingPx) : el)),
      },
    }));
  return { headingPx, updates };
}

/** Floors so one cramped slide can't shrink every card title / paragraph / caption in the deck. */
const DECK_TIER_FLOORS = { 2: 18, 3: 14, 4: 12 };

/**
 * Deck-level pass for card titles (tier 2), paragraphs (tier 3) and captions (tier 4), tagged by
 * textHierarchy (content.deckTier). Each tier gets one size across the deck — the smallest fitted
 * size, not below its floor; tiers keep their ratios (body ≤ title÷1.2, caption ≤ body÷1.1).
 * Only shrinks, so it can never cause overflow.
 * @returns {{ tiers: { t2?: number, t3?: number, t4?: number }, updates: { slideId: string, elements: object }[] }}
 */
function harmonizeDeckTiers(slides) {
  const list = (Array.isArray(slides) ? slides : []).filter((s) => Array.isArray(s?.elements?.elements));
  const minOf = (tier) => {
    const sizes = [];
    for (const s of list) {
      for (const el of s.elements.elements) {
        if (el?.content?.deckTier === tier && Number(el.content.fontSize) > 0) sizes.push(Number(el.content.fontSize));
      }
    }
    return sizes.length ? Math.min(...sizes) : null;
  };
  const target = {};
  for (const tier of [2, 3, 4]) {
    const min = minOf(tier);
    if (min != null) target[tier] = Math.max(DECK_TIER_FLOORS[tier], min);
  }
  if (target[2] && target[3]) target[3] = Math.min(target[3], Math.floor(target[2] / 1.2));
  if (target[3] && target[4]) target[4] = Math.min(target[4], Math.floor(target[3] / 1.1));
  if (!Object.keys(target).length) return { tiers: {}, updates: [] };

  const updates = [];
  for (const s of list) {
    let changed = false;
    const elements = s.elements.elements.map((el) => {
      const t = target[el?.content?.deckTier];
      if (!t || !(Number(el.content.fontSize) > t)) return el;
      changed = true;
      return withFontSize(el, t);
    });
    if (changed) updates.push({ slideId: s.id, elements: { ...s.elements, elements } });
  }
  return { tiers: { t2: target[2], t3: target[3], t4: target[4] }, updates };
}

module.exports = {
  DECK_TIER_FLOORS,
  harmonizeDeckTiers,
  MIN_DECK_HEADING_PX,
  resolveDeckHeadingPx,
  applyDeckHeadingSize,
  harmonizeDeckHeadings,
  findMainHeading,
  isExemptLayout,
};
