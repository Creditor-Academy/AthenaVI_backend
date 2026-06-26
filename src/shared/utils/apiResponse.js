const { jsonSafeDeep } = require('./byteSize');

exports.successResponse = (req, res, data, statusCode, message) => {
  return res.status(statusCode).json({
    success: true,
    message,
    data: jsonSafeDeep(data),
  });
};

exports.errorResponse = (req, res, statusCode, message, errors = []) => {
  return res.status(statusCode).json({
    success: false,
    message,
    errors,
  });
};
