const DEFAULT_MIN_INTERVAL_MS = 2000;

function clampRatio(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) {
    return 0;
  }
  return Math.min(1, Math.max(0, n));
}

function mapRange(ratio, from, to) {
  return Math.round(from + (to - from) * clampRatio(ratio));
}

function remotionProgressRatio(event) {
  if (!event || typeof event !== 'object') {
    return 0;
  }
  if (typeof event.progress === 'number') {
    return clampRatio(event.progress);
  }
  return 0;
}

/**
 * Throttles DB writes so Remotion frame callbacks do not hammer Postgres.
 * Never reports 100 — that is reserved for completed / failed.
 */
function createProgressReporter({ persist, minIntervalMs = DEFAULT_MIN_INTERVAL_MS } = {}) {
  if (typeof persist !== 'function') {
    throw new Error('createProgressReporter requires persist(progress)');
  }

  let lastSentAt = 0;
  let lastProgress = -1;
  let writing = Promise.resolve();

  function report(progress) {
    const next = Math.max(0, Math.min(99, Math.round(Number(progress) || 0)));
    if (next <= lastProgress) {
      return writing;
    }
    const now = Date.now();
    if (now - lastSentAt < minIntervalMs && next < 99) {
      return writing;
    }
    lastSentAt = now;
    lastProgress = next;
    writing = writing
      .then(() => persist(next))
      .catch((error) => {
        console.error('Failed to persist render progress:', error);
      });
    return writing;
  }

  return { report, lastProgress: () => lastProgress };
}

module.exports = {
  clampRatio,
  mapRange,
  remotionProgressRatio,
  createProgressReporter,
};
