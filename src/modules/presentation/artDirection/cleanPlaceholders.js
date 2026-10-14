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

/**
 * @param {{ elements?: object[] }} doc
 * @param {{ layoutSchema?: object }} opts
 */
function cleanPlaceholders(doc, { layoutSchema = null } = {}) {
  if (!doc || !Array.isArray(doc.elements)) return doc;
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

module.exports = { cleanPlaceholders };
