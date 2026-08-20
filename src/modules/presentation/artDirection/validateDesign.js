/**
 * Design validation + repair hooks.
 * Deterministic post-compile fixes for contrast-adjacent issues and text overlap.
 */

function textElements(doc) {
  return (Array.isArray(doc?.elements) ? doc.elements : []).filter(
    (el) => el.type === 'text' || el.type === 'textbox'
  );
}

function placementOverlapRatio(a, b) {
  const ax = a?.x ?? 0;
  const ay = a?.y ?? 0;
  const aw = a?.width ?? 0;
  const ah = a?.height ?? 0;
  const bx = b?.x ?? 0;
  const by = b?.y ?? 0;
  const bw = b?.width ?? 0;
  const bh = b?.height ?? 0;
  const overlapW = Math.max(0, Math.min(ax + aw, bx + bw) - Math.max(ax, bx));
  const overlapH = Math.max(0, Math.min(ay + ah, by + bh) - Math.max(ay, by));
  const minArea = Math.min(Math.max(1, aw * ah), Math.max(1, bw * bh));
  return (overlapW * overlapH) / minArea;
}

function findOverlappingPairs(elements) {
  const pairs = [];
  for (let i = 0; i < elements.length; i += 1) {
    for (let j = i + 1; j < elements.length; j += 1) {
      const ratio = placementOverlapRatio(elements[i].placement, elements[j].placement);
      if (ratio > 0.15) pairs.push([elements[i], elements[j], ratio]);
    }
  }
  return pairs;
}

function validateDesign(doc) {
  if (!doc?.elements || !Array.isArray(doc.elements)) {
    return { ok: true, issues: [] };
  }
  const issues = [];
  const pairs = findOverlappingPairs(textElements(doc));
  if (pairs.length) {
    issues.push({
      rule: 'text_overlap',
      count: pairs.length,
      repairable: true,
    });
  }
  return { ok: issues.length === 0, issues };
}

function shrinkTextElement(el, factor = 0.88) {
  if (!el?.content) return;
  const size = Number(el.content.fontSize);
  if (!Number.isFinite(size) || size <= 12) return;
  const next = Math.max(12, Math.round(size * factor));
  el.content.fontSize = next;
  if (Array.isArray(el.content.runs)) {
    el.content.runs = el.content.runs.map((run) =>
      run.fontSize != null
        ? { ...run, fontSize: Math.max(12, Math.round(Number(run.fontSize) * factor)) }
        : run
    );
  }
}

function nudgeDown(el, pixels = 12) {
  if (!el?.placement) return;
  el.placement = {
    ...el.placement,
    y: (el.placement.y ?? 0) + pixels,
  };
}

/**
 * Repair overlapping text by shrinking the lower / body-like element first,
 * then nudging it down if still overlapping. Caps at a few passes.
 */
function repairElementsDoc(doc) {
  if (!doc?.elements || !Array.isArray(doc.elements)) return doc;

  const next = {
    ...doc,
    elements: doc.elements.map((el) => ({
      ...el,
      content: el.content ? { ...el.content } : el.content,
      placement: el.placement ? { ...el.placement } : el.placement,
    })),
  };

  for (let pass = 0; pass < 4; pass += 1) {
    const texts = textElements(next);
    const pairs = findOverlappingPairs(texts);
    if (!pairs.length) break;

    for (const [a, b] of pairs) {
      const aRole = String(a.role || a.slotId || '').toLowerCase();
      const bRole = String(b.role || b.slotId || '').toLowerCase();
      const aIsHeading = /title|heading|headline/.test(aRole);
      const bIsHeading = /title|heading|headline/.test(bRole);
      // Prefer shrinking the non-heading / lower element.
      let victim = a;
      if (aIsHeading && !bIsHeading) victim = b;
      else if (bIsHeading && !aIsHeading) victim = a;
      else if ((a.placement?.y ?? 0) <= (b.placement?.y ?? 0)) victim = b;

      shrinkTextElement(victim, 0.9);
      if (pass >= 1) nudgeDown(victim, 10 + pass * 4);

      // Truncate very long overflow text as a last resort.
      if (pass >= 2 && typeof victim.content?.text === 'string') {
        const maxChars = Math.max(
          40,
          Math.floor(((victim.placement?.width || 200) * (victim.placement?.height || 40)) / 40)
        );
        if (victim.content.text.length > maxChars) {
          victim.content.text = `${victim.content.text.slice(0, maxChars - 1).trim()}…`;
          if (Array.isArray(victim.content.runs)) {
            victim.content.runs = [{ text: victim.content.text }];
          }
        }
      }
    }
  }

  return next;
}

module.exports = {
  validateDesign,
  repairElementsDoc,
};
