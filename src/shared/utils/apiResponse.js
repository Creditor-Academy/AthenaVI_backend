exports.successResponse = (req, res, data, statusCode, message) => {
  return res.status(statusCode).json({
    success: true,
    message,
    data,
  });
};

exports.errorResponse = (req, res, statusCode, message) => {
  return res.status(statusCode).json({
    success: false,
    message,
  });
};