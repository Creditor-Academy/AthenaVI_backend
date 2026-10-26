const logger = require('../utils/logger');
const messages = require('../utils/messages');
const renderDao = require('../../modules/render/render.dao');

/** Renders run in this process's memory queue, so anything still active from a previous process is dead. */
async function recoverInterruptedRenders(before = new Date()) {
  try {
    const result = await renderDao.failInterruptedRenders({
      before,
      error: messages.PROJECT_RENDER_INTERRUPTED,
    });
    if (result.renders > 0) {
      logger.warn('Marked interrupted renders as failed', result);
    }
    return result;
  } catch (error) {
    logger.error('Interrupted render recovery failed', { error: error.message });
    return null;
  }
}

module.exports = {
  recoverInterruptedRenders,
};
