/**
 * Export metrics for this server: every finished export of the last hour (outcome, format,
 * slides, duration, failure reason), summarised for GET /health/export, and an alert when the
 * failure rate passes PPT_EXPORT_ALERT_FAILURE_RATE (default 5%).
 *
 * The alert is an error log line, `presentation_export_failure_rate_high`, at most once per
 * PPT_EXPORT_ALERT_COOLDOWN_MS (default 15 min), and only once PPT_EXPORT_ALERT_MIN_EXPORTS
 * exports (default 20) finished in the hour, so one failure out of two doesn't page anyone. With
 * PPT_EXPORT_ALERT_WEBHOOK_URL set it is also posted there as `{ text }` (Slack-compatible).
 *
 * Numbers are per server. The `presentation_export_finished` log line (one per export) carries
 * the same fields, for totals across servers in the log platform.
 */

const logger = require('../../shared/utils/logger');

const WINDOW_MS = 60 * 60 * 1000;
const MAX_EVENTS = 10_000;

const envNumber = (name, fallback) => (Number(process.env[name]) > 0 ? Number(process.env[name]) : fallback);

/** Finished exports, oldest first: { at, outcome, format, durationMs, reason }. */
let events = [];
let lastAlertAt = 0;

function prune(now) {
  const from = now - WINDOW_MS;
  let drop = 0;
  while (drop < events.length && events[drop].at < from) drop += 1;
  if (drop) events = events.slice(drop);
  if (events.length > MAX_EVENTS) events = events.slice(events.length - MAX_EVENTS);
}

function percentile(sorted, p) {
  if (!sorted.length) return null;
  const at = Math.min(sorted.length - 1, Math.max(0, Math.ceil((p / 100) * sorted.length) - 1));
  return sorted[at];
}

/** Summary of the last hour. Cancelled exports are counted but are not failures. */
function snapshot(now = Date.now()) {
  prune(now);
  const byFormat = {};
  const reasons = new Map();
  let ready = 0;
  let failed = 0;
  let cancelled = 0;
  for (const e of events) {
    const f = (byFormat[e.format] = byFormat[e.format] || { ready: 0, failed: 0, cancelled: 0, durations: [] });
    if (e.outcome === 'READY') {
      ready += 1;
      f.ready += 1;
      if (Number.isFinite(e.durationMs)) f.durations.push(e.durationMs);
    } else if (e.outcome === 'FAILED') {
      failed += 1;
      f.failed += 1;
      reasons.set(e.reason || 'unknown', (reasons.get(e.reason || 'unknown') || 0) + 1);
    } else if (e.outcome === 'CANCELLED') {
      cancelled += 1;
      f.cancelled += 1;
    }
  }
  const finished = ready + failed;
  for (const f of Object.values(byFormat)) {
    const sorted = f.durations.sort((a, b) => a - b);
    f.p50Ms = percentile(sorted, 50);
    f.p95Ms = percentile(sorted, 95);
    delete f.durations;
  }
  return {
    windowMinutes: WINDOW_MS / 60_000,
    total: events.length,
    ready,
    failed,
    cancelled,
    failureRate: finished ? Number((failed / finished).toFixed(4)) : 0,
    byFormat,
    topReasons: [...reasons]
      .map(([reason, count]) => ({ reason, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5),
  };
}

function postWebhook(text) {
  const url = String(process.env.PPT_EXPORT_ALERT_WEBHOOK_URL || '').trim();
  if (!url || typeof fetch !== 'function') return;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 5_000);
  timer.unref?.();
  fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ text }),
    signal: controller.signal,
  })
    .catch((err) => logger.warn('presentation_export_alert_webhook_failed', { error: String(err?.message || err) }))
    .finally(() => clearTimeout(timer));
}

function checkAlert(now) {
  const threshold = envNumber('PPT_EXPORT_ALERT_FAILURE_RATE', 0.05);
  const minExports = envNumber('PPT_EXPORT_ALERT_MIN_EXPORTS', 20);
  const cooldownMs = envNumber('PPT_EXPORT_ALERT_COOLDOWN_MS', 15 * 60 * 1000);
  const s = snapshot(now);
  if (s.ready + s.failed < minExports || s.failureRate <= threshold) return null;
  if (lastAlertAt && now - lastAlertAt < cooldownMs) return null;
  lastAlertAt = now;
  const alert = {
    failureRate: s.failureRate,
    threshold,
    failed: s.failed,
    finished: s.ready + s.failed,
    windowMinutes: s.windowMinutes,
    topReasons: s.topReasons,
  };
  logger.error('presentation_export_failure_rate_high', alert);
  postWebhook(
    `Presentation exports: ${(s.failureRate * 100).toFixed(1)}% failed in the last hour ` +
      `(${s.failed} of ${s.ready + s.failed}, alert above ${(threshold * 100).toFixed(0)}%). ` +
      `Top reason: ${s.topReasons[0]?.reason || 'unknown'}`
  );
  return alert;
}

/**
 * Record a finished export. `outcome` is READY / FAILED / CANCELLED. Returns the alert raised
 * by this export, if any.
 */
function recordExport({ outcome, format, durationMs = null, reason = null } = {}, now = Date.now()) {
  events.push({
    at: now,
    outcome: String(outcome || '').toUpperCase(),
    format: String(format || 'unknown').toUpperCase(),
    durationMs: Number.isFinite(durationMs) ? durationMs : null,
    reason: reason ? String(reason).slice(0, 200) : null,
  });
  prune(now);
  return outcome === 'FAILED' ? checkAlert(now) : null;
}

/** Tests: forget everything. */
function reset() {
  events = [];
  lastAlertAt = 0;
}

module.exports = { recordExport, snapshot, reset };
