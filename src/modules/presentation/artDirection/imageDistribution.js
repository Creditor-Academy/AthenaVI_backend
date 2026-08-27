function applyDeckImageStrategyToVisualNeed({ currentVisualNeed, usage, preferVisuals }) {
  const need = String(currentVisualNeed || '').toLowerCase();
  const allowVisuals = preferVisuals !== false;

  // Do not override specialized visuals; those have their own deterministic paths.
  if (['chart', 'icon', 'diagram_template', 'path_b'].includes(need)) return currentVisualNeed;

  if (!allowVisuals && usage !== 'none') return 'none';

  if (usage === 'none') return 'none';

  // For required/preferred we set to photo if the pipeline would otherwise skip.
  if (usage === 'required') return 'photo';
  if (usage === 'preferred') return need && need !== 'none' ? currentVisualNeed : 'photo';

  // Optional: keep the existing classification.
  if (usage === 'optional') return currentVisualNeed;

  return currentVisualNeed;
}

function planDeckImageDistribution({ visualRhythm = [] }) {
  const byOrder = {};
  for (const entry of visualRhythm) {
    if (!entry?.slideNumber) continue;
    byOrder[Number(entry.slideNumber)] = { usage: entry.imageUsage, role: entry.role };
  }
  return byOrder;
}

module.exports = {
  planDeckImageDistribution,
  applyDeckImageStrategyToVisualNeed,
};

