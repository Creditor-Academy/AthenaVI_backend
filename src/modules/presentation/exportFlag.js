/**
 * PPT_EXPORT_V2: who gets the new presentation export pipeline.
 *
 * V2 is everything built in Phases 3–6 of docs/PPT_EXPORT_PRODUCTION_PLAN.md (frontend repo):
 *   - PDF and images drawn by the editor's own renderer (the export-render page);
 *   - PPTX built from what that renderer drew (measured text, pictures for what PowerPoint can't
 *     draw) with the deck's fonts embedded;
 *   - the job queue (BullMQ), with progress across servers.
 * Without V2 an export runs as before: the server's HTML renderer for PDF and images, a PPTX
 * built from the stored deck alone (no measuring, fonts by name), in the process that took the
 * request.
 *
 *   PPT_EXPORT_V2=on        everyone (the default)
 *   PPT_EXPORT_V2=internal  only the workspaces / people listed below
 *   PPT_EXPORT_V2=off       nobody
 *
 *   PPT_EXPORT_V2_WORKSPACES     comma-separated workspace ids
 *   PPT_EXPORT_V2_EMAIL_DOMAINS  comma-separated email domains of the person exporting
 *
 * The choice is made once, when the export is requested, and travels with the job, so a job
 * keeps its pipeline even if the setting changes while it waits.
 */

const MODES = new Set(['on', 'internal', 'off']);

function list(value) {
  return String(value || '')
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
}

/** 'on' | 'internal' | 'off'. Unknown values count as 'on' (today's behaviour). */
function exportV2Mode(env = process.env) {
  const raw = String(env.PPT_EXPORT_V2 ?? '').trim().toLowerCase();
  if (['1', 'true', 'yes', 'all'].includes(raw)) return 'on';
  if (['0', 'false', 'no', 'none'].includes(raw)) return 'off';
  return MODES.has(raw) ? raw : 'on';
}

/** The allowlists for 'internal'. */
function exportV2Allowlist(env = process.env) {
  return {
    workspaces: list(env.PPT_EXPORT_V2_WORKSPACES),
    emailDomains: list(env.PPT_EXPORT_V2_EMAIL_DOMAINS).map((d) => d.replace(/^@/, '')),
  };
}

function emailDomain(email) {
  const at = String(email || '').lastIndexOf('@');
  return at > 0 ? String(email).slice(at + 1).trim().toLowerCase() : '';
}

/**
 * Whether this export uses V2. `findUserEmail(userId)` is called only when the mode is
 * 'internal' and the workspace isn't listed (it may hit the database).
 */
async function useExportV2({ workspaceId, userId, findUserEmail } = {}, env = process.env) {
  const mode = exportV2Mode(env);
  if (mode === 'on') return true;
  if (mode === 'off') return false;
  const { workspaces, emailDomains } = exportV2Allowlist(env);
  if (workspaceId && workspaces.includes(String(workspaceId).toLowerCase())) return true;
  if (!emailDomains.length || !userId || typeof findUserEmail !== 'function') return false;
  try {
    return emailDomains.includes(emailDomain(await findUserEmail(userId)));
  } catch {
    return false;
  }
}

/** For GET /health/export: how the flag is set (no ids or domains, only counts). */
function exportV2Status(env = process.env) {
  const { workspaces, emailDomains } = exportV2Allowlist(env);
  return { mode: exportV2Mode(env), workspaces: workspaces.length, emailDomains: emailDomains.length };
}

module.exports = { exportV2Mode, exportV2Allowlist, useExportV2, exportV2Status, emailDomain };
