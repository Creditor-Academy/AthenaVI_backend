const { errorResponse } = require("../shared/utils/apiResponse");
const messages = require("../shared/utils/messages");
const logger = require("../shared/utils/logger");

module.exports = (err, req, res, next) => {
  logger.error(err.stack || err);

  const statusCode = err.statusCode || 500;

  // If it's a known / operational error, expose its message
  if (err.isOperational) {
    return errorResponse(req, res, statusCode, err.message);
  }

  // Otherwise, hide internal details
  return errorResponse(
    req,
    res,
    500,
    messages.INTERNAL_SERVER_ERROR
  );
};
