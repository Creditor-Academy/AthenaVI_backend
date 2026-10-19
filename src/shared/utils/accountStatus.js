const AppError = require('./AppError');
const messages = require('./messages');

function isUserPaused(user) {
  return Boolean(user && user.pausedAt);
}

/** Throws 403 when an admin has paused this user's service. */
function assertAccountActive(user) {
  if (isUserPaused(user)) {
    throw new AppError(messages.ACCOUNT_PAUSED, 403);
  }
}

module.exports = { isUserPaused, assertAccountActive };
