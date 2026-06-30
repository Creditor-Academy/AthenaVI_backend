class EarlyAccessHttpError extends Error {
  constructor({ statusCode, error, message, fields, retryAfterSec }) {
    super(message);
    this.statusCode = statusCode;
    this.error = error;
    this.fields = fields;
    this.retryAfterSec = retryAfterSec;
  }
}

module.exports = EarlyAccessHttpError;
