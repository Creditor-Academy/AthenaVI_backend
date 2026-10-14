'use strict';

/**
 * Generation-time cleanup: no placeholder copy ("Double-click to edit", "Add text here", catalog
 * sample text) and no leftover empty text boxes on generated slides. Empty boxes are where the
 * editor draws its "Double-click to edit" hint, so removing them keeps generated slides clean.
 * The main heading and schema-required slots are kept so the user can still type into them.
 */
const { isCatalogPlaceholderText, isLayoutEngineDefaultText } = require('../catalogPlaceholder');

const MAIN_HEADING_SLOTS = new Set(['HEADING', 'TITLE', 'MAIN_TITLE', 'HEADLINE']);

const isText = (el) => el && (el.type === 'text' || el.type === 'textbox');

function textOf(el) {
  const c = el?.content || {};
  if (typeof c.text === 'string' && c.text.trim()) return c.text.trim();
  if (Array.isArray(c.runs)) return c.runs.map((r) => r?.text || '').join('').trim();
  return '';
}

const rect = (el) => {
  const p = el?.placement || {};
  return { x: Number(p.x) || 0, y: Number(p.y) || 0, w: Number(p.width) || 0, h: Number(p.height) || 0 };
};
const contains = (o, i, tol = 2) =>
  o.x - tol <= i.x && o.y - tol <= i.y && o.x + o.w + tol >= i.x + i.w && o.y + o.h + tol >= i.y + i.h;
const isRealText = (el) => {
  const t = textOf(el);
  return Boolean(t) && !isCatalogPlaceholderText(t) && !isLayoutEngineDefaultText(t);
};
/** Slot ids that number a repeated card: CARD_3_TITLE, COL_2_BODY, STEP_4_ICON, IMAGE_3 … */
const CARD_INDEX_RE = /^(CARD|COL|COLUMN|STEP|POINT|ITEM|FEATURE|BULLET|IMAGE|ICON|STAT|METRIC|PLAN|MEMBER)_(\d+)(?:_|$)/i;

const canStretch = (el) =>
  el.type === 'shape' || /preserveAspectRatio="none"/.test(String(el.content?.svg || ''));

/**
 * Cards whose text is all empty are removed with everything inside them; the remaining cards in
 * the row are re-flowed across the row's original span (equal widths, original gap).
 */
function collapseEmptyCards(elements, { layoutSchema = null, canvas = {} } = {}) {
  const { NO_RESIZE_LAYOUT_RE } = require('./textHierarchy');
  if (NO_RESIZE_LAYOUT_RE.test(String(layoutSchema?.layout_id || ''))) return elements;
  const canvasArea = (Number(canvas.width) || 1920) * (Number(canvas.height) || 1080);

  // Cards = elements sharing a slot index (CARD_3_TITLE, CARD_3_BODY, IMAGE_3, CARD_3_BG …),
  // plus any element visually inside that group's background (unnamed shapes/icons).
  const groups = new Map();
  elements.forEach((el, i) => {
    const m = String(el?.slotId || '').match(CARD_INDEX_RE);
    if (!m) return;
    const key = `${m[1].toUpperCase()}#${m[2]}`;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(i);
  });
  // IMAGE_n / ICON_n belong to the card family with the same index (CARD_n / COL_n …).
  for (const [key, idx] of [...groups]) {
    const [family, n] = key.split('#');
    if (family !== 'IMAGE' && family !== 'ICON') continue;
    const owner = [...groups.keys()].find((k) => k.endsWith(`#${n}`) && !/^(IMAGE|ICON)#/.test(k));
    if (owner) {
      groups.get(owner).push(...idx);
      groups.delete(key);
    }
  }
  const bbox = (idx) => {
    const rs = idx.map((i) => rect(elements[i])).filter((r) => r.w > 0 && r.h > 0);
    const x = Math.min(...rs.map((r) => r.x));
    const y = Math.min(...rs.map((r) => r.y));
    return { x, y, w: Math.max(...rs.map((r) => r.x + r.w)) - x, h: Math.max(...rs.map((r) => r.y + r.h)) - y };
  };
  const cards = [];
  for (const idx of groups.values()) {
    const texts = idx.filter((i) => isText(elements[i]));
    if (!texts.length) continue;
    const r = bbox(idx);
    if (!(r.w > 0) || r.w * r.h >= canvasArea * 0.85) continue;
    // Unnamed elements fully inside the card's box (e.g. a background shape or icon) go with it.
    const extra = elements
      .map((el, i) => i)
      .filter((i) => !idx.includes(i) && !elements[i]?.slotId && contains(r, rect(elements[i])));
    const all = [...idx, ...extra];
    cards.push({ idx: all, r: bbox(all), empty: texts.every((i) => !isRealText(elements[i])) });
  }

  // Rows: same top edge (±10px) and similar height (±15%).
  const rows = [];
  for (const card of cards) {
    const row = rows.find((rw) => Math.abs(rw[0].r.y - card.r.y) <= 10 && Math.abs(rw[0].r.h - card.r.h) <= rw[0].r.h * 0.15);
    if (row) row.push(card);
    else rows.push([card]);
  }

  const remove = new Set();
  const moved = new Map(); // element index → new placement
  for (const row of rows) {
    const empties = row.filter((c) => c.empty);
    const kept = row.filter((c) => !c.empty).sort((a, b) => a.r.x - b.r.x);
    if (!empties.length || !kept.length) continue;

    for (const card of empties) card.idx.forEach((i) => remove.add(i));

    const all = row.slice().sort((a, b) => a.r.x - b.r.x);
    const spanStart = all[0].r.x;
    const spanEnd = all[all.length - 1].r.x + all[all.length - 1].r.w;
    const gap = all.length > 1 ? Math.max(0, all[1].r.x - (all[0].r.x + all[0].r.w)) : 0;
    // Only a card's background graphic decides stretching; small icons/images just move.
    const isBackdrop = (card, i) => {
      const r = rect(elements[i]);
      return r.w * r.h >= card.r.w * card.r.h * 0.5;
    };
    const stretch = kept.every((c) =>
      c.idx.every((i) => elements[i].type !== 'graphic' || !isBackdrop(c, i) || canStretch(elements[i]))
    );
    const newW = stretch ? (spanEnd - spanStart - gap * (kept.length - 1)) / kept.length : null;
    const groupW = stretch ? null : kept.reduce((s, c) => s + c.r.w, 0) + gap * (kept.length - 1);
    let cursor = stretch ? spanStart : spanStart + (spanEnd - spanStart - groupW) / 2;

    const proposal = new Map();
    const newBoxes = [];
    for (const card of kept) {
      const w = stretch ? newW : card.r.w;
      const scale = w / card.r.w;
      const dx = cursor;
      const mapX = (x) => Math.round(dx + (x - card.r.x) * scale);
      newBoxes.push({ x: dx, y: card.r.y, w, h: card.r.h });
      for (const i of card.idx) {
        if (remove.has(i)) continue;
        const r = rect(elements[i]);
        const fixedWidth = ['graphic', 'image', 'icon'].includes(elements[i].type) && !isBackdrop(card, i);
        if (fixedWidth) {
          // Icons/images keep their size; their centre follows the card.
          proposal.set(i, { x: Math.round(mapX(r.x + r.w / 2) - r.w / 2) });
        } else {
          proposal.set(i, { x: mapX(r.x), width: Math.round(r.w * (stretch ? scale : 1)) });
        }
      }
      cursor += w + gap;
    }
    // Staggered/zigzag layouts: re-flowing would collide with cards in other rows → keep positions.
    const others = cards.filter((c) => !row.includes(c) && !c.empty);
    const collides = newBoxes.some((b) =>
      others.some((o) => b.x < o.r.x + o.r.w - 2 && o.r.x < b.x + b.w - 2 && b.y < o.r.y + o.r.h - 2 && o.r.y < b.y + b.h - 2)
    );
    if (!collides) proposal.forEach((v, k) => moved.set(k, v));
  }
  if (!remove.size) return elements;
  return elements
    .map((el, i) => (moved.has(i) ? { ...el, placement: { ...el.placement, ...moved.get(i) } } : el))
    .filter((_, i) => !remove.has(i));
}

/**
 * @param {{ elements?: object[] }} doc
 * @param {{ layoutSchema?: object, canvas?: object }} opts
 */
function cleanPlaceholders(doc, { layoutSchema = null, canvas = {} } = {}) {
  if (!doc || !Array.isArray(doc.elements)) return doc;
  const collapsed = collapseEmptyCards(doc.elements, { layoutSchema, canvas });
  if (collapsed !== doc.elements) doc = { ...doc, elements: collapsed };
  const required = new Set(
    (Array.isArray(layoutSchema?.slots) ? layoutSchema.slots : [])
      .filter((s) => s?.required === true)
      .map((s) => String(s.id || '').toUpperCase())
  );
  const keep = (el) => {
    const sid = String(el.slotId || '').toUpperCase();
    return MAIN_HEADING_SLOTS.has(sid) || required.has(sid);
  };

  let changed = false;
  const elements = [];
  for (const el of doc.elements) {
    if (!isText(el)) {
      elements.push(el);
      continue;
    }
    let text = textOf(el);
    let next = el;
    if (text && (isCatalogPlaceholderText(text) || isLayoutEngineDefaultText(text))) {
      next = { ...el, content: { ...el.content, text: '', runs: null } };
      text = '';
      changed = true;
    }
    if (!text && !keep(next)) {
      changed = true;
      continue; // drop leftover empty box
    }
    elements.push(next);
  }
  return changed ? { ...doc, elements } : doc;
}

module.exports = { cleanPlaceholders, collapseEmptyCards };
