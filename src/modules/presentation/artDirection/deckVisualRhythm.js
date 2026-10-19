/**
 * Simple deterministic visual rhythm + image usage schedule.
 * This module does NOT force images; it only sets intent levels that
 * influence `visualNeed` before the existing image brief pipeline runs.
 */
function planDeckVisualRhythm({ slideCount }) {
  const n = Math.max(1, Number(slideCount) || 1);
  const visualRhythm = [];

  for (let i = 0; i < n; i++) {
    const order = i + 1;
    let role = 'text';

    if (order === 1) role = 'hero';
    else if (order === n) role = 'closing';
    else if (i % 3 === 1) role = 'visual';
    else if (i % 3 === 2) role = 'balanced';
    else role = 'text';

    visualRhythm.push({
      slideNumber: order,
      role,
      imageUsage:
        order === 1
          ? 'required'
          : order === n
            ? 'preferred'
            : i % 3 === 0
              ? 'none'
              : i % 3 === 1
                ? 'preferred'
                : 'optional',
    });
  }

  return visualRhythm;
}

module.exports = {
  planDeckVisualRhythm,
};

