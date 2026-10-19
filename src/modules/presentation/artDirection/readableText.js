'use strict';

/**
 * Generation-time readability pass (runs after the type ramp, before the final fit):
 *  - one font family per role from the theme (overrides hardcoded Inter/Georgia in diagrams);
 *  - "Title\nParagraph" in a single card box → bold title run + muted paragraph run;
 *  - nothing below 14px (captions 12px): text that can't fit at the floor is trimmed
 *    (trailing sentences first, then words + "…") instead of shrinking to 9px.
 */
const { fitFontSize } = require('../textFit.util');
const { tierOf } = require('./textHierarchy');
const { isExemptLayout } = require('./deckHeadingSize');

const BODY_FLOOR = 14;
const CAPTION_FLOOR = 12;
/** Single boxes that hold a card's title + paragraph (no separate title slot). */
const BADGE_SLOT_RE = /BADGE|TAG|CATEGORY|PILL|CHIP|_NUM$|NUMBER/i;
const COMBINED_CARD_SLOT_RE = /^(BULLET|BODY|ITEM|POINT|PARA|COL|CARD)_\d+$/i;

const isText = (el) => el && (el.type === 'text' || el.type === 'textbox');
const textOf = (el) => {
  const c = el?.content || {};
  if (Array.isArray(c.runs) && c.runs.length) return c.runs.map((r) => r?.text || '').join('');
  return typeof c.text === 'string' ? c.text : '';
};
const fitsAt = (el, size, canvasW) => fitFontSize({ ...el.content, fontSize: size }, el.placement, canvasW) == null;

function themeFontFor(el, fonts) {
  const tier = tierOf(el);
  if (tier === 1 || /^(title|heading|headline|stat_value)$/i.test(String(el.role || ''))) return fonts.heading || fonts.body;
  if (tier === 2) return fonts.subheading || fonts.heading || fonts.body;
  return fonts.body || fonts.subheading || fonts.heading;
}

/** Trim text until it fits its box at `size`: drop trailing sentences, then words (+ "…"). */
function trimToFit(el, size, canvasW) {
  const full = textOf(el).trim();
  const lines = full.split('\n');
  // Keep a short first line as the card title; a long first line is just content (e.g. bullets).
  const hasTitle = lines.length > 1 && lines[0].trim().split(/\s+/).length <= 7;
  const head = hasTitle ? `${lines[0]}\n` : '';
  let body = hasTitle ? lines.slice(1).join(' ') : full.replace(/\n+/g, ' ');
  const withText = (t) => ({ ...el, content: { ...el.content, text: `${head}${t}`.trim(), runs: null } });

  let sentences = body.match(/[^.!?]+[.!?]+(\s|$)|[^.!?]+$/g) || [body];
  while (sentences.length > 1 && !fitsAt(withText(sentences.join('').trim()), size, canvasW)) sentences.pop();
  body = sentences.join('').trim();
  if (fitsAt(withText(body), size, canvasW)) return withText(body);

  const words = body.split(/\s+/);
  while (words.length > 1 && !fitsAt(withText(`${words.join(' ')}…`), size, canvasW)) words.pop();
  return withText(`${words.join(' ').replace(/[,.;:]$/, '')}…`);
}

/** "Card title\nParagraph" → bold title run + muted paragraph run (hierarchy inside one box). */
function titleBodyRuns(el) {
  if (!COMBINED_CARD_SLOT_RE.test(String(el.slotId || '')) || Array.isArray(el.content?.runs)) return el;
  const text = String(el.content?.text || '');
  const nl = text.indexOf('\n');
  if (nl <= 0) return el;
  const title = text.slice(0, nl).trim();
  const body = text.slice(nl + 1).trim();
  if (!title || !body || title.split(/\s+/).length > 7) return el;
  return {
    ...el,
    content: {
      ...el.content,
      runs: [
        { text: title, fontWeight: 700, colorRole: 'text' },
        { text: '\n', colorRole: 'muted' },
        { text: body, colorRole: 'muted' },
      ],
    },
  };
}

/**
 * @param {{ elements?: object[] }} doc
 * @param {{ themeTokens?: object, layoutSchema?: object, canvas?: { width?: number } }} opts
 */
function enforceReadableText(doc, { themeTokens = null, layoutSchema = null, canvas = {} } = {}) {
  if (!doc || !Array.isArray(doc.elements)) return doc;
  const canvasW = Number(canvas.width) || Number(doc.canvas?.width) || 1920;
  const fonts = themeTokens?.fonts || {};
  const exempt = isExemptLayout(layoutSchema);

  const elements = doc.elements.map((el) => {
    if (!isText(el) || !textOf(el).trim()) return el;
    let next = el;
    const family = themeFontFor(el, fonts);
    if (family) next = { ...next, content: { ...next.content, fontFamily: family } };
    if (exempt || next.content?.deckHeading) return next;

    const floor = tierOf(next) === 4 ? CAPTION_FLOOR : BODY_FLOOR;
    // Pill badges / tags and boxes too short for one line at the floor are designed small — keep.
    if (BADGE_SLOT_RE.test(String(next.slotId || ''))) return titleBodyRuns(next);
    const oneLine = floor * (canvasW / 900) * (Number(next.content?.lineHeight) || 1.25);
    if ((Number(next.placement?.height) || 0) < oneLine) return titleBodyRuns(next);
    if (!(Number(next.content?.fontSize) >= floor)) {
      next = { ...next, content: { ...next.content, fontSize: floor } };
    }
    if (!fitsAt(next, Number(next.content.fontSize), canvasW)) {
      // Prefer the largest size ≥ floor that fits; otherwise trim the copy at the floor.
      let size = Number(next.content.fontSize);
      while (size > floor && !fitsAt(next, size, canvasW)) size -= 1;
      next = { ...next, content: { ...next.content, fontSize: size } };
      if (!fitsAt(next, size, canvasW)) next = trimToFit(next, size, canvasW);
    }
    return titleBodyRuns(next);
  });

  // Floors can lift paragraphs up to card-title size — keep card titles ≥1.2× the paragraphs.
  if (!exempt) {
    const bodySizes = elements
      .filter((el) => isText(el) && textOf(el).trim() && tierOf(el) === 3)
      .map((el) => Number(el.content.fontSize) || 0);
    const minTitle = bodySizes.length ? Math.ceil(Math.max(...bodySizes) * 1.2) : 0;
    for (let i = 0; i < elements.length; i += 1) {
      const el = elements[i];
      if (!minTitle || !isText(el) || !textOf(el).trim() || tierOf(el) !== 2) continue;
      if (BADGE_SLOT_RE.test(String(el.slotId || '')) || Number(el.content.fontSize) >= minTitle) continue;
      let lifted = { ...el, content: { ...el.content, fontSize: minTitle } };
      if (!fitsAt(lifted, minTitle, canvasW)) lifted = trimToFit(lifted, minTitle, canvasW);
      if (!fitsAt(lifted, minTitle, canvasW)) {
        // Title box too small even for one word at that size: largest size that fits.
        let size = minTitle;
        while (size > Number(el.content.fontSize) && !fitsAt(lifted, size, canvasW)) size -= 1;
        lifted = { ...lifted, content: { ...lifted.content, fontSize: size } };
      }
      elements[i] = lifted;
    }
    // Title boxes too small to grow: readability wins (paragraphs stay ≥14px); those titles are
    // still bold, so the hierarchy reads by weight.
    for (let i = 0; i < elements.length; i += 1) {
      const el = elements[i];
      if (isText(el) && tierOf(el) === 2 && textOf(el).trim() && !(Number(el.content.fontWeight) >= 700)) {
        elements[i] = { ...el, content: { ...el.content, fontWeight: 700 } };
      }
    }
  }
  return { ...doc, elements };
}

module.exports = { enforceReadableText, BODY_FLOOR, CAPTION_FLOOR };
