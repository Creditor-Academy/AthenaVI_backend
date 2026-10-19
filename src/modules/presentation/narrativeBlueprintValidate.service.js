const { PPT_NARRATIVE_SLIDE_COUNTS } = require('./presentation.constants');
const {
  normalizeRole,
  isBookendRole,
  SYNTHESIS_ROLE_POOL,
  contentSlideOrdersForAgenda,
} = require('./narrativeSlideBlueprints');

const SYNTHESIS_AVOID_TYPES = new Set(['chart', 'diagram', 'timeline']);

function assertAllowedSlideCount(slideCount) {
  const n = Number(slideCount);
  if (!PPT_NARRATIVE_SLIDE_COUNTS.includes(n)) {
    return `slideCount must be one of ${PPT_NARRATIVE_SLIDE_COUNTS.join(', ')} (got ${slideCount})`;
  }
  return null;
}

function slideByOrder(slides) {
  const map = new Map();
  for (let i = 0; i < slides.length; i += 1) {
    const s = slides[i];
    const order = Number(s.order) > 0 ? Number(s.order) : i + 1;
    map.set(order, s);
  }
  return map;
}

/**
 * @returns {{ ok: boolean, errors: string[], warnings: string[] }}
 */
function validateNarrativeBlueprint(outline, { packMode = false, strict = true } = {}) {
  const errors = [];
  const warnings = [];
  const slideCount = Number(outline?.slideCount) || 0;
  const slides = Array.isArray(outline?.slides) ? outline.slides : [];

  if (!packMode) {
    const countErr = assertAllowedSlideCount(slideCount);
    if (countErr) errors.push(countErr);
  }

  if (slides.length !== slideCount && slideCount > 0) {
    errors.push(`slides.length (${slides.length}) must equal slideCount (${slideCount})`);
  }

  if (packMode) {
    return { ok: errors.length === 0, errors, warnings };
  }

  const n = slideCount || slides.length;
  const byOrder = slideByOrder(slides);

  const s1 = byOrder.get(1);
  const ct1 = String(s1?.suggestedContentType || '').toLowerCase();
  if (!s1 || ct1 !== 'title') {
    errors.push('Slide 1 must use suggestedContentType title');
  }
  if (normalizeRole(s1?.narrativeRole) !== 'hero_title') {
    errors.push('Slide 1 narrativeRole must be hero_title');
  }

  const s2 = byOrder.get(2);
  const ct2 = String(s2?.suggestedContentType || '').toLowerCase();
  const locked2 = Boolean(s2?.layoutLocked);
  if (!s2 || (!locked2 && ct2 !== 'agenda')) {
    errors.push('Slide 2 must use suggestedContentType agenda (unless layout locked)');
  }
  if (locked2 && ct2 !== 'agenda') {
    errors.push('Slide 2 cannot lock a non-agenda layout');
  }
  if (normalizeRole(s2?.narrativeRole) !== 'agenda_overview') {
    errors.push('Slide 2 narrativeRole must be agenda_overview');
  }

  const sn = byOrder.get(n);
  const ctn = String(sn?.suggestedContentType || '').toLowerCase();
  if (!sn || ctn !== 'closing') {
    errors.push(`Slide ${n} must use suggestedContentType closing`);
  }
  if (normalizeRole(sn?.narrativeRole) !== 'summary_cta') {
    errors.push(`Slide ${n} narrativeRole must be summary_cta`);
  }

  if (n >= 6) {
    const syn = byOrder.get(n - 1);
    const synCt = String(syn?.suggestedContentType || '').toLowerCase();
    const synRole = normalizeRole(syn?.narrativeRole);
    if (['title', 'agenda', 'closing'].includes(synCt)) {
      errors.push(`Slide ${n - 1} must not use bookend content types (synthesis slide)`);
    }
    if (synRole && isBookendRole(synRole)) {
      errors.push(`Slide ${n - 1} must not use bookend narrativeRole`);
    }
    if (
      !syn?.layoutLocked &&
      SYNTHESIS_AVOID_TYPES.has(synCt) &&
      !(synRole && SYNTHESIS_ROLE_POOL.includes(synRole))
    ) {
      errors.push(
        `Slide ${n - 1} synthesis slide should not default to chart/diagram/timeline (use bullet_list, stat, image+text, quote)`
      );
    }
  }

  for (const [order, slide] of byOrder.entries()) {
    if (order <= 2 || order >= n) continue;
    if (n >= 6 && order === n - 1) continue;
    const role = normalizeRole(slide?.narrativeRole);
    if (role && isBookendRole(role)) {
      errors.push(`Slide ${order} must not use bookend narrativeRole ${role} in the middle`);
    }
  }

  const middleRoles = [];
  for (const [order, slide] of byOrder.entries()) {
    if (order <= 2 || order >= n) continue;
    if (n >= 6 && order === n - 1) continue;
    const role = normalizeRole(slide?.narrativeRole);
    if (role) middleRoles.push(role);
  }
  if (n > 5) {
    const counts = new Map();
    for (const r of middleRoles) {
      counts.set(r, (counts.get(r) || 0) + 1);
    }
    for (const [role, count] of counts.entries()) {
      if (count > 2) {
        errors.push(`Middle narrativeRole "${role}" appears ${count} times (max 2)`);
      }
    }
  }

  const agendaBeats = Array.isArray(s2?.beats) ? s2.beats.filter(Boolean).map(String) : [];
  const contentOrders = contentSlideOrdersForAgenda(n);
  const contentTitles = contentOrders
    .map((o) => String(byOrder.get(o)?.title || '').trim())
    .filter(Boolean);
  if (contentTitles.length >= 2 && agendaBeats.length > 0) {
    const overlap = contentTitles.filter((t) =>
      agendaBeats.some((b) => b.trim().toLowerCase() === t.toLowerCase())
    ).length;
    const minCover = Math.min(2, contentTitles.length);
    if (overlap < minCover) {
      warnings.push('Agenda beats should reflect content slide titles');
      if (strict) {
        errors.push(
          `Agenda beats must include at least ${minCover} content slide title(s); overlap=${overlap}`
        );
      }
    }
  }

  return { ok: errors.length === 0, errors, warnings };
}

function assertNarrativeBlueprint(outline, options = {}) {
  const result = validateNarrativeBlueprint(outline, { ...options, strict: true });
  if (!result.ok) {
    const err = new Error(result.errors.join('; '));
    err.code = 'NARRATIVE_BLUEPRINT_INVALID';
    err.details = result;
    throw err;
  }
  return result;
}

module.exports = {
  assertAllowedSlideCount,
  validateNarrativeBlueprint,
  assertNarrativeBlueprint,
};
