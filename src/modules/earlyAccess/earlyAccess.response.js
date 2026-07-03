function earlyAccessSuccess(res, statusCode, { message, requestId }) {
  return res.status(statusCode).json({
    success: true,
    message,
    requestId,
  });
}

function earlyAccessError(res, statusCode, { error, message, fields }) {
  const body = {
    success: false,
    error,
    message,
  };

  if (fields && Object.keys(fields).length > 0) {
    body.fields = fields;
  }

  return res.status(statusCode).json(body);
}

module.exports = {
  earlyAccessSuccess,
  earlyAccessError,
};
