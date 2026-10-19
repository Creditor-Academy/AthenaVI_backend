'use strict';

const crypto = require('crypto');
const logger = require('../../shared/utils/logger');
const presentationDao = require('./presentation.dao');

const REPAIR_CAP = 50;
const ISSUE_CAP = 30;

function auditMode() {
  const raw = String(process.env.PPT_CONTENT_REPAIR_AUDIT || 'log').trim().toLowerCase();
  if (raw === 'off' || raw === 'false' || raw === 'none') return 'off';
  if (raw === 'job' || raw === 'db' || raw === 'jobs') return 'job';
  if (raw === 'both' || raw === 'all') return 'both';
  return 'log';
}

function capAuditPayload(audit) {
  if (!audit || typeof audit !== 'object') return {};
  return {
    warnings: Array.isArray(audit.warnings) ? audit.warnings.slice(0, 20) : [],
    repairs: Array.isArray(audit.repairs) ? audit.repairs.slice(0, REPAIR_CAP) : [],
    issues: Array.isArray(audit.issues) ? audit.issues.slice(0, ISSUE_CAP) : [],
    passes: audit.passes,
    durationMs: audit.durationMs,
    skipped: audit.skipped,
    emptySlotFallback: audit.emptySlotFallback,
  };
}

function auditStatus(audit) {
  if (audit?.emptySlotFallback || (audit?.repairs && audit.repairs.length > 0)) return 'REPAIRED';
  if (audit?.issues && audit.issues.length > 0) return 'WARN';
  return 'OK';
}

function shouldLogStatus(status) {
  if (process.env.PPT_CONTENT_REPAIR_LOG === 'verbose') return true;
  return status !== 'OK';
}

function requestHashForRepair({ slideId, phase, layoutId }) {
  const hourBucket = Math.floor(Date.now() / 3_600_000);
  return crypto
    .createHash('sha256')
    .update(`CONTENT_REPAIR|${slideId}|${phase}|${layoutId || ''}|${hourBucket}`)
    .digest('hex');
}

/**
 * Record repair/QA audit without a new Prisma model:
 * - log (default): structured winston → combined.log
 * - job: reuse slide_generation_jobs (jobType CONTENT_REPAIR, payload in usage)
 * - both: log + job
 *
 * Set PPT_CONTENT_REPAIR_AUDIT=off to disable entirely.
 */
async function recordContentRepairAudit({
  slideId,
  deckId,
  layoutId,
  phase,
  audit,
}) {
  const mode = auditMode();
  if (mode === 'off' || !slideId) return;

  const status = auditStatus(audit);
  const capped = capAuditPayload(audit);
  const payload = {
    slideId,
    deckId: deckId || null,
    layoutId: layoutId || null,
    phase: phase || 'PRE_COMPILE',
    status,
    repairCount: capped.repairs?.length || 0,
    issueCount: capped.issues?.length || 0,
    durationMs: capped.durationMs ?? null,
  };

  if ((mode === 'log' || mode === 'both') && shouldLogStatus(status)) {
    logger.info?.('presentation_content_repair_audit', {
      ...payload,
      audit: capped,
    });
  }

  if (mode === 'job' || mode === 'both') {
    try {
      await presentationDao.recordContentRepairJob({
        slideId,
        phase: phase || 'PRE_COMPILE',
        layoutId: layoutId || null,
        status,
        usage: { ...capped, ...payload },
        latencyMs: capped.durationMs ?? null,
        requestHash: requestHashForRepair({ slideId, phase, layoutId }),
      });
    } catch (err) {
      logger.warn?.('presentation_content_repair_job_failed', {
        slideId,
        phase,
        error: err.message,
      });
    }
  }
}

module.exports = {
  recordContentRepairAudit,
  auditMode,
  capAuditPayload,
};
