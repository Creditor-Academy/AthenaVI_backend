const { jsonSafeDeep } = require('./byteSize');

exports.successResponse = (req, res, data, statusCode, message) => {
  return res.status(statusCode).json({
    success: true,
    message,
    data: jsonSafeDeep(data),
  });
};

exports.errorResponse = (req, res, statusCode, message, errors = [], data) => {
  const body = {
    success: false,
    message,
    errors,
  };
  if (data && typeof data === 'object') {
    body.data = jsonSafeDeep(data);
  }
  return res.status(statusCode).json(body);
};
