'use strict';

/**
 * Generation-time typography + card pass.
 *
 * Diagram compilers hardcode 12–16px for card titles, body and captions alike, so slides had no
 * visible hierarchy, and cards kept fixed heights with short text stuck top-left. This pass:
 *  1. enforces a type ramp (heading > card title/subheading > body > caption) from the theme,
 *     only raising sizes as far as the text box allows;
 *  2. shrinks rows of cards to fit their content (equal height per row, top edge kept);
 *  3. centers short text inside its card.
 * Runs only on AI generation (same flag as theme recolor) — editor recompiles keep user edits.
 */
const { FONT_REF_WIDTH, estimateLineCount, fitFontSize } = require('../textFit.util');
const { isExemptLayout } = require('./deckHeadingSize');

const CHAR_EM = 0.54;
const MIN_PX = 9;
const TIER2_ID_RE = /_(TITLE|HEADING|HEADER|NAME|LABEL)$/i;
const NO_RESIZE_LAYOUT_RE = /funnel|pyramid|cycle|venn|process_|timeline_|ribbon|hex|roadmap/i;
const SKIP_ROLE_RE = /^(stat|metric|quote|cta)$/i;

const isText = (el) => el && (el.type === 'text' || el.type === 'textbox');
const textOf = (el) => {
  const c = el?.content || {};
  if (typeof c.text === 'string') return c.text.trim();
  if (Array.isArray(c.runs)) return c.runs.map((r) => r?.text || '').join('').trim();
  return '';
};
const rect = (el) => {
  const p = el?.placement || {};
  return { x: Number(p.x) || 0, y: Number(p.y) || 0, w: Number(p.width) || 0, h: Number(p.height) || 0 };
};
const contains = (o, i, tol = 2) =>
  o.x - tol <= i.x && o.y - tol <= i.y && o.x + o.w + tol >= i.x + i.w && o.y + o.h + tol >= i.y + i.h;

function tierOf(el) {
  if (el.content?.deckHeading) return 1;
  const role = String(el.role || '').toLowerCase();
  const sid = String(el.slotId || '');
  if (SKIP_ROLE_RE.test(role) || /^(stat|metric|quote|cta)/i.test(sid)) return 0;
  if (/caption|eyebrow|attribution|footnote/.test(role)) return 4;
  if (role === 'heading' || role === 'subheading' || TIER2_ID_RE.test(sid)) return 2;
  return 3;
}

/** Canvas-px height text needs in its box width at `size` (editor-stage px). */
function neededHeight(el, size, canvasW) {
  const box = rect(el);
  const px = size * (canvasW / FONT_REF_WIDTH);
  const lineHeight = Number(el.content?.lineHeight) > 0 ? Number(el.content.lineHeight) : 1.25;
  const pad = (Number(el.content?.padding) || 0) * 2;
  const perLine = Math.max(1, (box.w - pad) / (px * CHAR_EM));
  return estimateLineCount(textOf(el), perLine) * px * lineHeight + pad;
}

/** Same check the final fitTextElementsToBoxes pass uses, so it never shrinks what we set. */
const fits = (el, size, canvasW) =>
  fitFontSize({ ...el.content, fontSize: size }, el.placement, canvasW) == null;

/**
 * Largest size ≤ desired that fits the box. Sizing to fit here (not only growing) means the final
 * fitTextElementsToBoxes pass has nothing left to shrink, so tier sizes stay uniform.
 */
function fittedSize(el, desired, canvasW) {
  let size = Math.max(MIN_PX, Math.round(desired));
  while (size > MIN_PX && !fits(el, size, canvasW)) size -= 1;
  return size;
}

const setSize = (el, size) => ({
  ...el,
  content: {
    ...el.content,
    fontSize: size,
    ...(Array.isArray(el.content?.runs)
      ? { runs: el.content.runs.map((r) => (r && r.fontSize ? { ...r, fontSize: size } : r)) }
      : {}),
  },
});

function applyTypeRamp(elements, themeTokens, canvasW) {
  const ts = themeTokens?.typeScale || {};
  const body = Number(ts.body) > 0 ? Number(ts.body) : 18;
  const headingEl = elements.find((el) => isText(el) && el.content?.deckHeading);
  // Cap against the size the heading will actually render at after the final fit pass.
  const heading = headingEl
    ? fittedSize(headingEl, Number(headingEl.content?.fontSize) || Number(ts.title) || 42, canvasW)
    : Number(ts.title) || 42;

  const byTier = { 2: [], 3: [], 4: [] };
  elements.forEach((el, i) => {
    if (!isText(el) || !textOf(el)) return;
    const t = tierOf(el);
    if (byTier[t]) byTier[t].push(i);
  });
  const out = elements.slice();
  const cur = (i) => Number(out[i].content?.fontSize) || body;

  // Tier 2: ≥ body×1.3, ≤ heading÷1.3; all tier-2 texts share the smallest fitted size.
  let t2 = null;
  if (byTier[2].length) {
    const hi = Math.floor(heading / 1.3);
    const sizes = byTier[2].map((i) => fittedSize(out[i], Math.min(hi, Math.max(cur(i), body * 1.3)), canvasW));
    t2 = Math.min(...sizes);
    byTier[2].forEach((i) => { out[i] = setSize(out[i], t2); });
  }
  // Tier 3: ≥ body×0.85, ≤ tier2÷1.2.
  let t3 = null;
  if (byTier[3].length) {
    const cap = t2 ? Math.floor(t2 / 1.2) : Infinity;
    const sizes = byTier[3].map((i) => fittedSize(out[i], Math.min(cap, Math.max(cur(i), body * 0.85)), canvasW));
    t3 = Math.max(MIN_PX, Math.min(cap, Math.min(...sizes)));
    byTier[3].forEach((i) => { out[i] = setSize(out[i], t3); });
  }
  // Tier 4: ≤ body÷1.15 and below tier 3.
  if (byTier[4].length) {
    const cap = Math.floor(Math.min(body / 1.15, t3 ? t3 / 1.1 : Infinity));
    byTier[4].forEach((i) => { if (cur(i) > cap) out[i] = setSize(out[i], Math.max(MIN_PX, cap)); });
  }
  return out;
}

function findCards(elements, canvas) {
  const canvasArea = canvas.width * canvas.height;
  const texts = elements.map((el, i) => ({ el, i })).filter(({ el }) => isText(el) && textOf(el) && !el.content?.deckHeading);
  const candidates = elements
    .map((el, i) => ({ el, i, r: rect(el) }))
    .filter(({ el, r }) => (el?.type === 'shape' || el?.type === 'graphic') && r.w >= 80 && r.h >= 60 && r.w * r.h < canvasArea * 0.85);
  const owner = new Map();
  for (const t of texts) {
    const tr = rect(t.el);
    let best = null;
    for (const c of candidates) {
      if (!contains(c.r, tr)) continue;
      if (!best || c.r.w * c.r.h < best.r.w * best.r.h) best = c;
    }
    if (best) {
      if (!owner.has(best.i)) owner.set(best.i, []);
      owner.get(best.i).push(t.i);
    }
  }
  return candidates
    .filter((c) => owner.has(c.i) && owner.get(c.i).length <= 6)
    .map((c) => ({ ...c, textIdx: owner.get(c.i) }));
}

function isResizable(card, elements) {
  const { el, r } = card;
  if (el.type === 'shape') {
    const kind = String(el.content?.shape || 'rect').toLowerCase();
    if (!/^(rect|rounded-rect|roundrect)$/.test(kind)) return false;
  } else if (!/preserveAspectRatio="none"/.test(String(el.content?.svg || ''))) {
    return false;
  }
  const bottom = r.y + r.h;
  // Connectors/badges sitting on the card's bottom edge would float after shrinking.
  return !elements.some((other, i) => {
    if (i === card.i || isText(other)) return false;
    const o = rect(other);
    if (contains(r, o)) return false;
    const horiz = o.x < r.x + r.w && r.x < o.x + o.w;
    return horiz && o.y < bottom + 4 && o.y + o.h > bottom - 4 && !contains(o, r);
  });
}

function fitCardsAndCenter(elements, layoutSchema, canvas) {
  const cards = findCards(elements, canvas);
  if (!cards.length) return elements;
  const out = elements.slice();
  const canResize = !NO_RESIZE_LAYOUT_RE.test(String(layoutSchema?.layout_id || ''));

  const blockOf = (card) => {
    const tops = card.textIdx.map((i) => rect(out[i]).y);
    const bottoms = card.textIdx.map((i) => {
      const r = rect(out[i]);
      return r.y + Math.min(r.h, neededHeight(out[i], Number(out[i].content?.fontSize) || 16, canvas.width));
    });
    return { top: Math.min(...tops), bottom: Math.max(...bottoms) };
  };
  const hasOtherChildren = (card) =>
    out.some((el, i) => i !== card.i && !isText(el) && contains(card.r, rect(el)) && rect(el).w * rect(el).h > 0);

  // Rows: cards sharing a top edge and similar height.
  const rows = [];
  for (const card of cards) {
    const row = rows.find((rw) => Math.abs(rw[0].r.y - card.r.y) <= 10 && Math.abs(rw[0].r.h - card.r.h) <= rw[0].r.h * 0.15);
    if (row) row.push(card);
    else rows.push([card]);
  }

  for (const row of rows) {
    const needs = row.map((card) => {
      const b = blockOf(card);
      const inset = Math.max(24, b.top - card.r.y);
      return b.bottom - card.r.y + inset;
    });
    const target = Math.ceil(Math.max(...needs));
    const shrink =
      canResize &&
      target < row[0].r.h * 0.8 &&
      row.every((card) => isResizable(card, out)) &&
      row.every((card) => !out.some((el, i) => i !== card.i && !isText(el) && contains(card.r, rect(el)) && rect(el).y + rect(el).h > card.r.y + target));

    for (const card of row) {
      const newH = shrink ? target : card.r.h;
      if (shrink) {
        out[card.i] = { ...out[card.i], placement: { ...out[card.i].placement, height: newH } };
        for (const ti of card.textIdx) {
          const r = rect(out[ti]);
          const maxH = card.r.y + newH - r.y - 8;
          if (r.h > maxH && maxH > 0) out[ti] = { ...out[ti], placement: { ...out[ti].placement, height: Math.round(maxH) } };
        }
      }
      // Center short text: the block uses < 50% of the card.
      const b = blockOf(card);
      if ((b.bottom - b.top) / newH >= 0.5) continue;
      if (card.textIdx.length === 1 && !hasOtherChildren(card)) {
        const ti = card.textIdx[0];
        const inset = Math.max(16, Math.min(32, newH * 0.12));
        out[ti] = {
          ...out[ti],
          placement: { ...out[ti].placement, y: Math.round(card.r.y + inset), height: Math.round(newH - inset * 2) },
          content: { ...out[ti].content, verticalAlign: 'center' },
        };
      } else if (!hasOtherChildren(card)) {
        const shift = Math.round(card.r.y + newH / 2 - (b.top + b.bottom) / 2);
        if (shift > 0) {
          for (const ti of card.textIdx) {
            out[ti] = { ...out[ti], placement: { ...out[ti].placement, y: rect(out[ti]).y + shift } };
          }
        }
      } else {
        for (const ti of card.textIdx) out[ti] = { ...out[ti], content: { ...out[ti].content, verticalAlign: 'center' } };
      }
    }

    // Horizontal centering only when every card in the row holds short, single-line text.
    const short = row.every((card) =>
      card.textIdx.every((ti) => {
        const words = textOf(out[ti]).split(/\s+/).filter(Boolean).length;
        const size = Number(out[ti].content?.fontSize) || 16;
        return words <= 6 && neededHeight(out[ti], size, canvas.width) <= size * (canvas.width / FONT_REF_WIDTH) * 1.6;
      })
    );
    if (short && row.length > 1) {
      for (const card of row) {
        for (const ti of card.textIdx) out[ti] = { ...out[ti], content: { ...out[ti].content, align: 'center' } };
      }
    }
  }
  return out;
}

/**
 * @param {{ elements?: object[] }} doc
 * @param {{ themeTokens?: object, layoutSchema?: object, canvas?: { width?: number, height?: number } }} opts
 */
function normalizeTextAndCards(doc, { themeTokens = null, layoutSchema = null, canvas = {} } = {}) {
  if (!doc || !Array.isArray(doc.elements) || isExemptLayout(layoutSchema)) return doc;
  const size = {
    width: Number(canvas.width) || Number(doc.canvas?.width) || 1920,
    height: Number(canvas.height) || Number(doc.canvas?.height) || 1080,
  };
  let elements = applyTypeRamp(doc.elements, themeTokens, size.width);
  elements = fitCardsAndCenter(elements, layoutSchema, size);
  return { ...doc, elements };
}

module.exports = { normalizeTextAndCards, tierOf };
