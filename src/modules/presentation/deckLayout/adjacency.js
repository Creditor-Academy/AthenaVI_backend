'use strict';

/**
 * Slides (sorted by order) whose layout repeats the previous slide's layout.
 * Locked slides are never reported (the user chose that layout explicitly).
 * @param {{ id: string, order: number, layoutId?: string|null, layoutLocked?: boolean }[]} slides
 * @returns {{ index: number, slide: object, prevLayoutId: string, nextLayoutId: string|null }[]}
 */
function findAdjacentDuplicates(slides) {
  const sorted = (Array.isArray(slides) ? slides : [])
    .filter((s) => s && s.layoutId)
    .sort((a, b) => Number(a.order) - Number(b.order));
  const dups = [];
  for (let i = 1; i < sorted.length; i += 1) {
    const prev = sorted[i - 1];
    const cur = sorted[i];
    if (Number(cur.order) !== Number(prev.order) + 1) continue;
    if (String(cur.layoutId) !== String(prev.layoutId) || cur.layoutLocked) continue;
    dups.push({
      index: i,
      slide: cur,
      prevLayoutId: String(prev.layoutId),
      nextLayoutId: sorted[i + 1] ? String(sorted[i + 1].layoutId) : null,
    });
  }
  return dups;
}

module.exports = { findAdjacentDuplicates };
