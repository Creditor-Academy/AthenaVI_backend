'use strict';

const { isProblemNarrativeSlide } = require('../narrativeContentTypeGuard');

function layoutIdFromTemplate(template) {
  return String(template?.schema?.layout_id || template?.variant || template?.id || '').trim();
}

function isChartLayoutId(layoutId) {
  const id = String(layoutId || '').toLowerCase();
  return id.startsWith('chart_') || /^chart\d/.test(id);
}

function filterTemplatesForProblemIntent(templates, { outlineSlide = {}, layoutLocked = false } = {}) {
  const list = Array.isArray(templates) ? templates.filter(Boolean) : [];
  if (layoutLocked || !list.length) return list;
  if (!isProblemNarrativeSlide(outlineSlide)) return list;
  if (String(outlineSlide?.suggestedContentType || '').toLowerCase() === 'chart') return list;

  const filtered = list.filter((t) => !isChartLayoutId(layoutIdFromTemplate(t)));
  return filtered.length ? filtered : list;
}

function scoreProblemLayoutPreference(layout, slideOrOutline = {}) {
  const outlineSlide = {
    purpose: slideOrOutline.purpose,
    narrativeRole: slideOrOutline.narrativeRole || slideOrOutline.narrative_role,
    suggestedContentType: slideOrOutline.suggestedContentType,
  };
  if (!isProblemNarrativeSlide(outlineSlide)) return 0;
  if (String(outlineSlide?.suggestedContentType || '').toLowerCase() === 'chart') return 0;
  const id = String(layout?.id || '').toLowerCase();
  const category = String(layout?.category || '').toLowerCase();
  if (isChartLayoutId(id) || category === 'chart' || category === 'data') return -12;
  if (/problem|bullet|split.*bullet|two_para|image/.test(id)) return 4;
  return 0;
}

module.exports = {
  filterTemplatesForProblemIntent,
  scoreProblemLayoutPreference,
  isChartLayoutId,
};
