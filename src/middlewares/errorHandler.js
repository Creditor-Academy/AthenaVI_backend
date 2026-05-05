const multer = require('multer');
const { errorResponse } = require('../shared/utils/apiResponse');
const messages = require('../shared/utils/messages');
const logger = require('../shared/utils/logger');

module.exports = (err, req, res, next) => {
  logger.error(err.stack || err);

  if (err instanceof multer.MulterError) {
    const msg =
      err.code === 'LIMIT_FILE_SIZE'
        ? 'File too large (max 32 MB for HeyGen avatar upload)'
        : err.message || 'Upload error';
    return errorResponse(req, res, 400, msg, [msg]);
  }

  const statusCode = err.statusCode || 500;

  if (err.isOperational) {
    return errorResponse(req, res, statusCode, err.message, err.errors);
  }

  return errorResponse(req, res, 500, messages.INTERNAL_SERVER_ERROR);
};
