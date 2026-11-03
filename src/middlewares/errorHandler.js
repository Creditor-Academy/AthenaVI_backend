const multer = require('multer');
const { errorResponse } = require('../shared/utils/apiResponse');
const messages = require('../shared/utils/messages');
const logger = require('../shared/utils/logger');

module.exports = (err, req, res, next) => {
  const statusCode = Number(err.statusCode || err.status) || 500;
  const isOperational = err.isOperational === true;
  if (isOperational && statusCode >= 400 && statusCode < 500) {
    if (statusCode >= 500) {
      logger.error(err.stack || err);
    } else if (statusCode === 401 || statusCode === 403 || statusCode === 503) {
      // Expected client auth failures / dependency unavailable — avoid flooding combined.log
    } else {
      logger.warn(err.message || err);
    }
  } else {
    logger.error(err.stack || err);
  }

  /** express.json / body-parser: payload larger than `limit` */
  if (
    // A file over an upload limit is a MulterError whose message is also "File too large";
    // it gets its own per-route message below, not this JSON-body hint.
    !(err instanceof multer.MulterError) &&
    (err.status === 413 ||
      err.type === 'entity.too.large' ||
      (typeof err.message === 'string' && err.message.toLowerCase().includes('too large')))
  ) {
    const hint =
      'JSON body exceeds server limit (voice clone base64 is large). Use multipart POST /api/heygen/voices/clone with field file, or POST /api/heygen/voices/upload then JSON with audio.type url. Optional: JSON_BODY_LIMIT=32mb.';
    return errorResponse(req, res, 413, hint, [hint]);
  }

  /** Malformed JSON from express.json */
  if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
    const msg = 'Invalid JSON in request body';
    return errorResponse(req, res, 400, msg, [msg]);
  }

  if (err instanceof multer.MulterError) {
    const url = String(req.originalUrl || '');
    const isLargeAvatarUpload = url.includes('/avatars/upload');
    const isVoiceUpload = url.includes('/voices/upload');
    const isVoiceCloneMultipart = url.includes('/voices/clone');
    const isAvatarCreateMultipart =
      url.endsWith('/avatars') || url.match(/\/avatars$/);
    const isLibraryUpload = /\/assets\/[^/]+\/upload/.test(url);
    const isProfileImage = url.includes('/upload/profile-image');
    const isHeygen = url.includes('/heygen/');
    const msg =
      err.code === 'LIMIT_FILE_SIZE'
        ? isLibraryUpload
          ? 'File too large (max 1 GB)'
          : isLargeAvatarUpload
          ? 'File too large (max 900 MB for HeyGen avatar file upload)'
          : isVoiceUpload || isVoiceCloneMultipart
            ? 'File too large (max 100 MB for HeyGen voice clone upload)'
            : isAvatarCreateMultipart
              ? 'File too large (max 900 MB for HeyGen avatar create multipart)'
              : isProfileImage
                ? 'File too large (max 2 MB for a profile photo)'
                : isHeygen
                  ? 'File too large (max 32 MB for HeyGen avatar upload)'
                  : 'File too large (max 50 MB)'
        : err.message || 'Upload error';
    return errorResponse(req, res, 400, msg, [msg]);
  }

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

    const rateLimitData =
      statusCode === 429 && (err.resetAt || Number(err.retryAfterSec) > 0)
        ? {
            retryAfterSec: Number(err.retryAfterSec) || 0,
            resetAt: err.resetAt || null,
            remaining: err.remaining != null ? Number(err.remaining) : 0,
            limit: err.limit != null ? Number(err.limit) : undefined,
          }
        : undefined;

    return errorResponse(
      req,
      res,
      statusCode,
      err.message || messages.INTERNAL_SERVER_ERROR,
      errors,
      rateLimitData
    );
  }

  return errorResponse(req, res, 500, messages.INTERNAL_SERVER_ERROR);
};
