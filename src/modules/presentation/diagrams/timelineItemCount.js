'use strict';

/**
 * Timeline layouts draw a fixed number of cards (4–6). When the slide has fewer real entries,
 * drop the extra cards and any sample copy the diagram compiler injected into empty slots.
 * Mirrored in AthenaVI/src/utils/timelineItemCount.js.
 */
const { isCatalogPlaceholderText } = require('../catalogPlaceholder');

/** Per-card slot ids: text slots (milestone_N_*, step_N_*) and diagram chrome (TLM_4, TLM_4N, TLPS_BOX_4, IMAGE_4). */
const TEXT_INDEX_RE = /^(?:milestone|step)_(\d+)(?:_|$)/i;
const CHROME_INDEX_RES = [/^TL[A-Z]*_(\d+)[A-Z]?$/i, /^TLPS_(?:BOX|CIRCLE)_(\d+)$/i, /^IMAGE_(\d+)$/i];

function isTimelineLayoutId(layoutId) {
  return /^timeline_/i.test(String(layoutId || ''));
}

function timelineItemIndex(slotId) {
  const sid = String(slotId || '');
  const m = sid.match(TEXT_INDEX_RE) || CHROME_INDEX_RES.map((re) => sid.match(re)).find(Boolean);
  return m ? Number(m[1]) : null;
}

function elementText(el) {
  const c = el?.content || {};
  if (typeof c.text === 'string' && c.text.trim()) return c.text.trim();
  if (Array.isArray(c.runs)) return c.runs.map((r) => r?.text || '').join('').trim();
  return '';
}

const listOf = (docOrElements) =>
  Array.isArray(docOrElements) ? docOrElements : Array.isArray(docOrElements?.elements) ? docOrElements.elements : [];

/** Snapshot of generated text per timeline text slot, taken before the diagram compiler runs. */
function snapshotTimelineText(docOrElements) {
  const textBySlot = new Map();
  for (const el of listOf(docOrElements)) {
    if (el?.type !== 'text' && el?.type !== 'textbox') continue;
    if (!TEXT_INDEX_RE.test(String(el.slotId || ''))) continue;
    const text = elementText(el);
    textBySlot.set(String(el.slotId), text && !isCatalogPlaceholderText(text) ? text : '');
  }
  return textBySlot;
}

/** Number of leading cards that carry real generated text (0 = no content, e.g. catalog preview). */
function countTimelineItems(textBySlot) {
  const filled = new Set();
  for (const [slotId, text] of textBySlot) {
    if (text) filled.add(timelineItemIndex(slotId));
  }
  let n = 0;
  while (filled.has(n + 1)) n += 1;
  return n || (filled.size ? Math.max(...filled) : 0);
}

const isNumbering = (text) => /^\d{1,2}$/.test(String(text || '').trim());

/**
 * Drop cards beyond `itemCount` and clear sample copy the compiler injected into slots that were
 * empty before compile (keeps simple 01/02 numbering). No-op when itemCount is 0 (previews).
 */
function pruneTimelineToItemCount(docOrElements, textBySlot, itemCount) {
  if (!itemCount) return docOrElements;
  const pruned = listOf(docOrElements)
    .filter((el) => {
      const idx = timelineItemIndex(el?.slotId);
      return idx == null || idx <= itemCount;
    })
    .map((el) => {
      const sid = String(el?.slotId || '');
      if (!textBySlot.has(sid) || textBySlot.get(sid)) return el;
      const injected = elementText(el);
      if (!injected || isNumbering(injected)) return el;
      return { ...el, content: { ...el.content, text: '', runs: null } };
    });
  return Array.isArray(docOrElements) ? pruned : { ...docOrElements, elements: pruned };
}

module.exports = {
  isTimelineLayoutId,
  timelineItemIndex,
  snapshotTimelineText,
  countTimelineItems,
  pruneTimelineToItemCount,
};
