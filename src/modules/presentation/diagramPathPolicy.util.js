/**
 * Path B vs process/diagram layouts — ownership rules.
 * Linear templatable flows → diagram_template + process layouts.
 * Path B → irregular/untemplatable composite diagrams only.
 */

const PROCESS_LAYOUT_PREFS_3 = [
  'process_linner_horti_v1',
  'process_linner_numeric_v1',
  'process_linear_horizontal_v2',
];

const PROCESS_LAYOUT_PREFS_4 = [
  'diagram_process_steps_v1',
  'process_linner_horti_four_v1',
  'process_linear_four_cards_v1',
];

/** True 5-milestone process/journey layouts (timeline family in catalog). */
const PROCESS_LAYOUT_PREFS_5 = [
  'timeline_vertical_v1',
  'timeline_vertical_cards_v1',
];

/** @deprecated use preferredProcessLayoutId — kept for callers expecting a flat list */
const PROCESS_LAYOUT_PREFS = [
  ...PROCESS_LAYOUT_PREFS_4,
  ...PROCESS_LAYOUT_PREFS_3,
  ...PROCESS_LAYOUT_PREFS_5,
];

function textHay(parts = []) {
  return parts
    .flatMap((p) => (Array.isArray(p) ? p : [p]))
    .map((v) => {
      if (v == null) return '';
      if (typeof v === 'string') return v;
      if (typeof v === 'object') {
        return [v.title, v.label, v.detail, v.body, v.text, v.name].filter(Boolean).join(' ');
      }
      return String(v);
    })
    .join(' ')
    .toLowerCase();
}

function countProcessSteps({ beats, bullets, columns, steps, panels } = {}) {
  const fromList = (list) => (Array.isArray(list) ? list.filter(Boolean).length : 0);
  return Math.max(
    fromList(beats),
    fromList(bullets),
    fromList(columns),
    fromList(steps),
    fromList(panels),
    0
  );
}

function looksLikePathBTopology({ title, summary, beats, bullets, visual, intent } = {}) {
  const hay = textHay([title, summary, beats, bullets, visual, intent]);
  return /architecture|erd\b|entity.?relation|system (map|diagram)|branching|cross-?link|schema map|multi-panel (diagram|infographic)|untemplatable|bespoke diagram/.test(
    hay
  );
}

/**
 * Normal N-step how-it-works / workflow that fits process layouts.
 */
function looksLikeLinearProcessSlide({
  title,
  summary,
  beats,
  bullets,
  columns,
  visual,
  intent,
  contentType,
} = {}) {
  if (looksLikeDeviceFramesSlide({ title, summary, beats, bullets, visual, intent, contentType })) {
    return false;
  }
  if (looksLikePathBTopology({ title, summary, beats, bullets, visual, intent })) {
    return false;
  }
  const hay = textHay([title, summary, beats, bullets, columns, visual, intent, contentType]);
  const stepCount = countProcessSteps({ beats, bullets, columns });
  const processCue =
    /how (it|we|this) works|workflow|process steps?|pipeline|step[-\s]?by[-\s]?step|numbered steps?|phases?|stages?|five simple steps|from .+ to .+/.test(
      hay
    ) ||
    (/\b(upload|extract|validate|ingest|transform|load)\b/.test(hay) &&
      /\b(upload|extract|validate|post|sync|store)\b/.test(hay));

  if (processCue && stepCount >= 2 && stepCount <= 6) return true;
  if (processCue && stepCount === 0) return true; // title/summary alone often enough pre-content
  if (stepCount >= 3 && stepCount <= 6 && /(→|->|then\b|next\b)/.test(hay)) return true;
  if (String(contentType || '').toLowerCase() === 'diagram' && stepCount >= 2 && stepCount <= 6) {
    return !/swot|funnel|matrix|venn|pyramid|cycle/.test(hay);
  }
  return false;
}

/** App / product UI mockup slides — must use device_frames, never diagram process. */
function looksLikeDeviceFramesSlide({
  title,
  summary,
  beats,
  bullets,
  visual,
  intent,
  contentType,
  purpose,
} = {}) {
  const ct = String(contentType || '').toLowerCase();
  if (ct === 'device_frames') return true;
  const hay = textHay([title, summary, beats, bullets, visual, intent, purpose, contentType]);
  if (
    /device.?frame|product ui|app (ui|screen|mockup)|mobile app|phone mockup|tablet mockup|laptop mockup|in your pocket|see .+ in action|screenshot|ui mockup|web.?app ui|built-in cook timer|browse personalized/.test(
      hay
    )
  ) {
    // Prefer device when UI/product cues dominate over pure process wording alone.
    if (!/how (it|we|this) works|five simple steps|step[-\s]?by[-\s]?step pipeline/.test(hay)) {
      return true;
    }
    // Mixed copy: still device if mockup/app UI is explicit.
    if (/device|mockup|screenshot|app that|phone|tablet|laptop|in your pocket/.test(hay)) {
      return true;
    }
  }
  const purposeHay = String(purpose || intent || '').toLowerCase();
  if (/product.?ui|device|app.?mockup|mockups?/.test(purposeHay)) return true;
  return false;
}

function hasUsablePathBSpec(spec) {
  if (!spec || typeof spec !== 'object') return false;
  const panels = Array.isArray(spec.panels) ? spec.panels : [];
  if (!panels.length) return false;
  return panels.some((panel) => {
    if (!panel || typeof panel !== 'object') return false;
    const title = String(panel.title || '').trim();
    const content = String(panel.content || '').trim();
    const steps = Array.isArray(panel.steps)
      ? panel.steps.filter(Boolean)
      : String(panel.steps || '').trim()
        ? [panel.steps]
        : [];
    const boxes = Array.isArray(panel.boxes)
      ? panel.boxes.filter(Boolean)
      : String(panel.boxes || '').trim()
        ? [panel.boxes]
        : [];
    return Boolean(title || content || steps.length || boxes.length);
  });
}

function preferredProcessLayoutId(stepCount = 0, usedLayoutIds = null) {
  const used =
    usedLayoutIds && typeof usedLayoutIds.has === 'function' ? usedLayoutIds : new Set();
  const n = Number(stepCount) || 0;
  // Match layout slot count to beats: 3 / 4 / 5+ (5 uses timeline vertical with 5 milestones).
  let prefs;
  if (n === 2 || n === 3) {
    prefs = PROCESS_LAYOUT_PREFS_3;
  } else if (n === 4) {
    prefs = PROCESS_LAYOUT_PREFS_4;
  } else if (n >= 5) {
    prefs = [...PROCESS_LAYOUT_PREFS_5, ...PROCESS_LAYOUT_PREFS_4];
  } else {
    // Unknown count (pre-content): prefer 3-step, then 4/5 — never force 4 when beats say 3.
    prefs = [...PROCESS_LAYOUT_PREFS_3, ...PROCESS_LAYOUT_PREFS_4, ...PROCESS_LAYOUT_PREFS_5];
  }
  const unused = prefs.filter((id) => !used.has(String(id)));
  return (unused.length ? unused : prefs)[0] || PROCESS_LAYOUT_PREFS_3[0];
}

/**
 * After classify: coerce linear process → diagram_template;
 * Path B without usable pathBSpec → diagram_template.
 * Never overwrite device_frames / product UI slides.
 */
function resolveDiagramVisualPolicy({
  visualNeed,
  contentType,
  content = null,
  outlineSlide = null,
} = {}) {
  let need = String(visualNeed || '').toLowerCase();
  let type = String(contentType || '').toLowerCase();

  const signals = {
    title: content?.title || outlineSlide?.title,
    summary: content?.summary || content?.body || outlineSlide?.summary,
    beats: outlineSlide?.beats || content?.beats,
    bullets: content?.bullets,
    columns: content?.columns,
    visual: outlineSlide?.visual,
    intent: outlineSlide?.intent || outlineSlide?.purpose || content?.intent,
    purpose: outlineSlide?.purpose || content?.purpose,
    contentType: type,
  };

  if (looksLikeDeviceFramesSlide(signals) || type === 'device_frames') {
    return { visualNeed: need === 'path_b' ? 'photo' : need || 'photo', contentType: 'device_frames' };
  }

  if (need === 'path_b' && !hasUsablePathBSpec(content?.pathBSpec)) {
    need = 'diagram_template';
    type = looksLikeLinearProcessSlide(signals) || !['diagram', 'timeline'].includes(type)
      ? 'diagram'
      : type;
  }

  if (
    need !== 'path_b' &&
    looksLikeLinearProcessSlide(signals) &&
    !looksLikePathBTopology(signals)
  ) {
    const steps = countProcessSteps(signals);
    need = 'diagram_template';
    // 5+ step journeys use timeline layouts (5 milestones) — keep type timeline so pool matches.
    type = steps >= 5 ? 'timeline' : 'diagram';
  }

  return { visualNeed: need || visualNeed, contentType: type || contentType };
}

module.exports = {
  PROCESS_LAYOUT_PREFS,
  PROCESS_LAYOUT_PREFS_3,
  PROCESS_LAYOUT_PREFS_4,
  PROCESS_LAYOUT_PREFS_5,
  countProcessSteps,
  looksLikePathBTopology,
  looksLikeLinearProcessSlide,
  looksLikeDeviceFramesSlide,
  hasUsablePathBSpec,
  preferredProcessLayoutId,
  resolveDiagramVisualPolicy,
};
