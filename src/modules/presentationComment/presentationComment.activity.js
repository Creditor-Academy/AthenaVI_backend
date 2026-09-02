const { redisClient } = require('../../shared/config/redis');

/**
 * Last-write marker for a presentation's comment thread, so the public preview page can
 * refetch comments off the presence heartbeat instead of polling the comment list.
 *
 * Lives here rather than in presentationShare so the share service can read it without
 * requiring the comment service (which would close an import cycle).
 */
const commentsVersionKey = (projectId) => `ppt:share:comments:${projectId}`;

/** Best-effort: a failed cache write must never fail the comment mutation. */
async function touchComments(projectId) {
  if (!projectId) return;
  try {
    await redisClient.set(commentsVersionKey(projectId), new Date().toISOString());
  } catch {
    // the client falls back to its own refetch cadence
  }
}

/** @returns {Promise<string|null>} ISO timestamp of the last comment write, or null. */
async function getCommentsUpdatedAt(projectId) {
  if (!projectId) return null;
  try {
    return (await redisClient.get(commentsVersionKey(projectId))) || null;
  } catch {
    return null;
  }
}

module.exports = {
  commentsVersionKey,
  touchComments,
  getCommentsUpdatedAt,
};
