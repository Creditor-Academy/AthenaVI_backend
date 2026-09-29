'use strict';

const { runContentPreShape } = require('./contentPreShape.util');
const { titleWordsFromBody } = require('./contentImagePrompt.util');
function layoutNeedsGalleryLabels(slots) {
  return slots.some((slot) => /^IMAGE_\d+_LABEL$/i.test(String(slot.id || '')));
}

function cloneContent(content) {
  if (!content || typeof content !== 'object') return {};
  return JSON.parse(JSON.stringify(content));
}

function dedupeColumnTitles(content, layoutSchema) {
  const next = cloneContent(content);
  const cols = next.columns || next.cards || next.features;
  if (!Array.isArray(cols) || cols.length < 2) return next;
  const slideTitle = String(next.title || '').trim().toLowerCase();
  const seen = new Set();
  const key = Array.isArray(next.columns) ? 'columns' : Array.isArray(next.cards) ? 'cards' : 'features';
  next[key] = cols.map((col, index) => {
    const copy = col && typeof col === 'object' ? { ...col } : { title: '', body: String(col || '') };
    let title = String(copy.title ?? copy.heading ?? copy.label ?? '').trim();
    const body = String(copy.body ?? copy.text ?? '').trim();
    const titleLower = title.toLowerCase();
    if (!title || titleLower === slideTitle || seen.has(titleLower)) {
      const fromBody = titleWordsFromBody(body, '');
      const fromBodyLower = String(fromBody || '').trim().toLowerCase();
      title =
        fromBody && fromBodyLower !== slideTitle && !seen.has(fromBodyLower)
          ? fromBody
          : `Aspect ${index + 1}`;
      copy.title = title;
      if (copy.heading != null) copy.heading = title;
      if (copy.label != null) copy.label = title;
    }
    seen.add(String(copy.title ?? title).trim().toLowerCase());
    return copy;
  });
  if (key !== 'columns') next.columns = next[key];
  return next;
}

function applyHeuristicRepairs(content, layoutSchema, issues = []) {
  const repairs = [];
  let next = cloneContent(content);
  const issueList = Array.isArray(issues) ? issues : [];

  if (issueList.some((i) => i.repairable || i.rule === 'required_structured')) {
    const before = JSON.stringify(next).length;
    next = runContentPreShape(next, layoutSchema);
    repairs.push({ path: '*', action: 'pre_shape', before: before, after: JSON.stringify(next).length });
  }

  const slots = Array.isArray(layoutSchema?.slots) ? layoutSchema.slots : [];
  if (
    issueList.some(
      (i) =>
        i.rule === 'distinct_gallery_labels' ||
        i.rule === 'gallery_label_matches_slide_title' ||
        i.rule === 'distinct_titles' ||
        i.rule === 'column_title_matches_slide_title'
    ) ||
    layoutNeedsGalleryLabels(slots)
  ) {
    next = dedupeColumnTitles(next, layoutSchema);
    repairs.push({ path: 'columns', action: 'dedupe_titles' });
  }

  return { content: next, repairs };
}

module.exports = {
  applyHeuristicRepairs,
  dedupeColumnTitles,
};
