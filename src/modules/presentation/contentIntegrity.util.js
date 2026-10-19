'use strict';

const {
  textForSlot,
  chartForSlot,
  chartSlotAllowsSampleData,
  isSyntheticRepairFingerprint,
  isChartElementSlot,
} = require('@athena/contracts/slotText.js');
const { isCatalogPlaceholderText, isLayoutEngineDefaultText } = require('./catalogPlaceholder');
const { isChartDonutContextTextSlot } = require('./diagrams/chartDonutContext');
const { collectRawArrayOverflowErrors } = require('@athena/contracts/contentContract.js');

const SAMPLE_CHART_VALUES = new Set([42, 58, 51, 67, 28, 36, 44, 39, 55, 48, 62, 71]);

function elementText(el) {
  const c = el?.content || {};
  if (typeof c.text === 'string' && c.text.trim()) return c.text.trim();
  if (Array.isArray(c.runs) && c.runs.length) {
    return c.runs.map((r) => r.text || '').join('').trim();
  }
  return '';
}

function collectTextFromElementsDoc(elementsDoc) {
  const texts = [];
  for (const el of elementsDoc?.elements || []) {
    if (el.type === 'text' || el.type === 'textbox') {
      const t = elementText(el);
      if (t) texts.push(t);
    }
    if (el.type === 'chart') {
      const labels = el.content?.labels || [];
      for (const label of labels) {
        const s = String(label || '').trim();
        if (s) texts.push(s);
      }
    }
  }
  return texts;
}

function chartElementHasSampleFingerprint(el) {
  const labels = (el.content?.labels || []).map((l) => String(l || '').trim());
  if (!labels.length) return false;
  const hasQuarterLabels = labels.some((l) => /^Q[1-4]$/i.test(l));
  if (!hasQuarterLabels) return false;
  let values = el.content?.values;
  if (!Array.isArray(values) || !values.length) {
    const series = el.content?.series;
    if (Array.isArray(series) && series[0]?.values) values = series[0].values;
  }
  if (!Array.isArray(values)) return false;
  const nums = values.map(Number).filter((n) => !Number.isNaN(n));
  return nums.some((n) => SAMPLE_CHART_VALUES.has(n));
}

function slotIsRequired(slot) {
  if (slot.required === false) return false;
  const role = String(slot.role || '').toLowerCase();
  if (role === 'decoration' || role === 'accent') return false;
  return true;
}

function scanCompiledContentIntegrity(elementsDoc, layoutSchema, content, options = {}) {
  const issues = [];
  const warnings = [];
  const rawSource = options.rawContent != null ? options.rawContent : content;

  for (const err of collectRawArrayOverflowErrors(rawSource, layoutSchema)) {
    issues.push({
      ...err,
      source: 'integrity',
      repairable: false,
      requiresLayoutRetry: true,
      phase: 'compiled',
    });
  }

  const texts = collectTextFromElementsDoc(elementsDoc);
  for (const text of texts) {
    if (isCatalogPlaceholderText(text) || isLayoutEngineDefaultText(text)) {
      issues.push({
        code: 'CATALOG_PLACEHOLDER',
        path: 'elements',
        rule: 'catalog_placeholder_survived',
        repairable: false,
        phase: 'compiled',
      });
      break;
    }
    if (isSyntheticRepairFingerprint(text)) {
      issues.push({
        code: 'SYNTHETIC_REPAIR_TEXT',
        path: 'elements',
        rule: 'synthetic_fingerprint',
        repairable: false,
        phase: 'compiled',
      });
      break;
    }
  }

  const slots = Array.isArray(layoutSchema?.slots) ? layoutSchema.slots : [];
  for (const slot of slots) {
    if (!slot?.id || !slotIsRequired(slot)) continue;
    const role = String(slot.role || '').toLowerCase();
    if (role === 'chart' || isChartElementSlot(slot.id, role)) continue;
    if (role !== 'heading' && role !== 'title' && role !== 'body' && role !== 'subheading') {
      continue;
    }
    const mapped = String(textForSlot(slot.id, content, layoutSchema) || '').trim();
    const el = (elementsDoc?.elements || []).find(
      (item) => String(item.slotId || '').toUpperCase() === String(slot.id).toUpperCase()
    );
    const compiled = el ? elementText(el) : '';
    if (!mapped && !compiled) continue;
    if (compiled && (isCatalogPlaceholderText(compiled) || isLayoutEngineDefaultText(compiled))) {
      issues.push({
        code: 'CATALOG_PLACEHOLDER',
        path: slot.id,
        rule: 'catalog_placeholder_survived',
        repairable: false,
        phase: 'compiled',
      });
    }
  }

  for (const el of elementsDoc?.elements || []) {
    const slotId = String(el.slotId || '').toUpperCase();
    if (!slotId || !isChartDonutContextTextSlot(slotId)) continue;
    const compiled = elementText(el);
    if (compiled && (isCatalogPlaceholderText(compiled) || isLayoutEngineDefaultText(compiled))) {
      issues.push({
        code: 'CATALOG_PLACEHOLDER',
        path: slotId,
        rule: 'layout_engine_default_survived',
        repairable: false,
        phase: 'compiled',
      });
    }
  }

  const chartSlots = slots.filter(
    (s) => isChartElementSlot(s.id, s.role) && /^CHART_\d+$/i.test(String(s.id || ''))
  );
  if (chartSlots.length > 0) {
    for (const slot of chartSlots) {
      const data = chartForSlot(slot.id, content);
      const labels = data?.labels;
      const series = data?.series;
      const hasData =
        (Array.isArray(labels) && labels.filter(Boolean).length >= 2) ||
        (Array.isArray(series) &&
          series.some(
            (s) => Array.isArray(s?.values) && s.values.filter((v) => v != null && v !== '').length >= 2
          ));
      if (!hasData && !chartSlotAllowsSampleData(content, slot.id)) {
        const rendered = (elementsDoc?.elements || []).some(
          (el) =>
            el.type === 'chart' &&
            String(el.slotId || '').toUpperCase() === String(slot.id).toUpperCase()
        );
        if (!rendered) {
          issues.push({
            code: 'MISSING_CHART_SLOT',
            path: slot.id,
            rule: 'missing_chart_slot',
            repairable: false,
            requiresLayoutRetry: true,
            phase: 'compiled',
          });
        }
      }
    }
  }

  for (const el of elementsDoc?.elements || []) {
    if (el.type !== 'chart') continue;
    if (chartSlotAllowsSampleData(content, el.slotId)) continue;
    if (chartElementHasSampleFingerprint(el)) {
      issues.push({
        code: 'SAMPLE_CHART_DATA',
        path: el.slotId || 'chart',
        rule: 'fabricated_sample_chart',
        repairable: false,
        phase: 'compiled',
      });
    }
  }

  const blocking = issues.some(
    (i) => i.repairable === false || i.requiresLayoutRetry === true
  );
  return { issues, warnings, blocking };
}

function reconcileCompiledTextWithContent(elementsDoc, layoutSchema, content) {
  if (!elementsDoc?.elements?.length || !layoutSchema?.slots?.length) return elementsDoc;
  const elements = elementsDoc.elements.map((el) => {
    if (el.type !== 'text' && el.type !== 'textbox') return el;
    const slotId = String(el.slotId || el.id || '').trim();
    if (!slotId) return el;
    const current = elementText(el);
    const mapped = String(textForSlot(slotId, content, layoutSchema) || '').trim();
    const mappedAlt = String(
      textForSlot(slotId.toLowerCase(), content, layoutSchema) || ''
    ).trim();
    const replacement = mapped || mappedAlt;
    if (replacement && !isCatalogPlaceholderText(replacement)) {
      if (
        !current ||
        isCatalogPlaceholderText(current) ||
        isSyntheticRepairFingerprint(current)
      ) {
        return { ...el, content: { ...(el.content || {}), text: replacement } };
      }
      return el;
    }
    if (isCatalogPlaceholderText(current) || isSyntheticRepairFingerprint(current)) {
      return { ...el, content: { ...(el.content || {}), text: '' } };
    }
    return el;
  });
  return { ...elementsDoc, elements };
}

module.exports = {
  collectTextFromElementsDoc,
  scanCompiledContentIntegrity,
  reconcileCompiledTextWithContent,
};
