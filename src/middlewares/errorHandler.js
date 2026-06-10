const multer = require('multer');
const { errorResponse } = require('../shared/utils/apiResponse');
const messages = require('../shared/utils/messages');
const logger = require('../shared/utils/logger');

module.exports = (err, req, res, next) => {
  logger.error(err.stack || err);

  /** express.json / body-parser: payload larger than `limit` */
  if (
    err.status === 413 ||
    err.type === 'entity.too.large' ||
    (typeof err.message === 'string' && err.message.toLowerCase().includes('too large'))
  ) {
    const hint =
      'JSON body exceeds server limit (voice clone base64 is large). Set JSON_BODY_LIMIT (e.g. JSON_BODY_LIMIT=32mb) or send clone audio as type url / asset_id instead of base64.';
    return errorResponse(req, res, 413, hint, [hint]);
  }

  /** Malformed JSON from express.json */
  if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
    const msg = 'Invalid JSON in request body';
    return errorResponse(req, res, 400, msg, [msg]);
  }

  if (err instanceof multer.MulterError) {
    const msg =
      err.code === 'LIMIT_FILE_SIZE'
        ? 'File too large (max 32 MB for HeyGen avatar upload)'
        : err.message || 'Upload error';
    return errorResponse(req, res, 400, msg, [msg]);
  }

  const statusCode = Number(err.statusCode || err.status) || 500;

  /** AppError, or body-parser / http-errors client errors (e.g. 413 payload too large) */
  const exposeClientError =
    err.isOperational === true ||
    (err.expose === true && statusCode >= 400 && statusCode < 500);

  if (exposeClientError) {
    const errors =
      Array.isArray(err.errors) && err.errors.length > 0
        ? err.errors
        : [err.message || messages.INTERNAL_SERVER_ERROR];

    if (statusCode === 429 && Number(err.retryAfterSec) > 0) {
      res.set('Retry-After', String(Math.ceil(err.retryAfterSec)));
    }

    return errorResponse(
      req,
      res,
      statusCode,
      err.message || messages.INTERNAL_SERVER_ERROR,
      errors
    );
  }

  return errorResponse(req, res, 500, messages.INTERNAL_SERVER_ERROR);
};
