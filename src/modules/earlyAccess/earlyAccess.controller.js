const asyncHandler = require('../../shared/utils/asyncHandler');
const { getClientIp } = require('../../shared/utils/getClientIp');
const messages = require('../../shared/utils/messages');
const AppError = require('../../shared/utils/AppError');
const EarlyAccessHttpError = require('./earlyAccess.errors');
const { earlyAccessSuccess, earlyAccessError } = require('./earlyAccess.response');
const { validateEarlyAccessBody } = require('../validations/earlyAccess.validations');
const earlyAccessService = require('./earlyAccess.service');

function handleEarlyAccessFailure(res, err) {
  if (err instanceof EarlyAccessHttpError) {
    if (Number(err.retryAfterSec) > 0) {
      res.set('Retry-After', String(Math.ceil(err.retryAfterSec)));
    }

    return earlyAccessError(res, err.statusCode, {
      error: err.error,
      message: err.message,
      fields: err.fields,
    });
  }

  if (err instanceof AppError && err.message === messages.STORAGE_UPGRADE_NOTIFICATION_NOT_CONFIGURED) {
    return earlyAccessError(res, 500, {
      error: 'INTERNAL_ERROR',
      message: messages.EARLY_ACCESS_INTERNAL_ERROR,
    });
  }

  console.error('Early access unexpected error:', err);
  return earlyAccessError(res, 500, {
    error: 'INTERNAL_ERROR',
    message: messages.EARLY_ACCESS_INTERNAL_ERROR,
  });
}

const submitEarlyAccessRequest = asyncHandler(async (req, res) => {
  const validation = validateEarlyAccessBody(req.body);

  if (!validation.valid) {
    return earlyAccessError(res, 400, {
      error: 'VALIDATION_ERROR',
      message: messages.EARLY_ACCESS_VALIDATION,
      fields: validation.fields,
    });
  }

  try {
    const { requestId } = await earlyAccessService.submitEarlyAccessRequest(
      validation.value,
      getClientIp(req)
    );

    return earlyAccessSuccess(res, 201, {
      message: messages.EARLY_ACCESS_RECEIVED,
      requestId,
    });
  } catch (err) {
    return handleEarlyAccessFailure(res, err);
  }
});

module.exports = {
  submitEarlyAccessRequest,
};
