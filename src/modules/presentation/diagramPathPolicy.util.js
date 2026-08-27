/**
 * Path B vs process/diagram layouts — ownership rules.
 * Linear templatable flows → diagram_template + process layouts.
 * Path B → irregular/untemplatable composite diagrams only.
 */

const PROCESS_LAYOUT_PREFS = [
  'diagram_process_steps_v1',
  'diagram_cycle_v1',
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
  if (looksLikePathBTopology({ title, summary, beats, bullets, visual, intent })) {
    return false;
  }
  const hay = textHay([title, summary, beats, bullets, columns, visual, intent, contentType]);
  const stepCount = countProcessSteps({ beats, bullets, columns });
  const processCue =
    /how (it|we|this) works|workflow|process steps?|pipeline|step[-\s]?by[-\s]?step|numbered steps?|phases?|stages?/.test(
      hay
    ) ||
    (/\b(upload|extract|validate|ingest|transform|load)\b/.test(hay) &&
      /\b(upload|extract|validate|post|sync|store)\b/.test(hay));

  if (processCue && stepCount >= 2 && stepCount <= 5) return true;
  if (processCue && stepCount === 0) return true; // title/summary alone often enough pre-content
  if (stepCount >= 3 && stepCount <= 5 && /(→|->|then\b|next\b)/.test(hay)) return true;
  if (String(contentType || '').toLowerCase() === 'diagram' && stepCount >= 2 && stepCount <= 5) {
    return !/swot|funnel|matrix|venn|pyramid|cycle/.test(hay);
  }
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
  // Prefer linear process-steps; cycle only as rare alternate when already used.
  const prefs =
    Number(stepCount) === 4
      ? ['diagram_process_steps_v1', 'diagram_cycle_v1']
      : ['diagram_process_steps_v1', 'diagram_cycle_v1'];
  const unused = prefs.filter((id) => !used.has(String(id)));
  return (unused.length ? unused : prefs)[0] || 'diagram_process_steps_v1';
}

/**
 * After classify: coerce linear process → diagram_template;
 * Path B without usable pathBSpec → diagram_template.
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
    contentType: type,
  };

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
    need = 'diagram_template';
    type = 'diagram';
  }

  return { visualNeed: need || visualNeed, contentType: type || contentType };
}

module.exports = {
  PROCESS_LAYOUT_PREFS,
  countProcessSteps,
  looksLikePathBTopology,
  looksLikeLinearProcessSlide,
  hasUsablePathBSpec,
  preferredProcessLayoutId,
  resolveDiagramVisualPolicy,
};
