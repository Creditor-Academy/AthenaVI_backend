class AppError extends Error {
  constructor(message, statusCode = 500) {
    super();

    this.statusCode = statusCode;
    this.isOperational = true;

    if (Array.isArray(message)) {
      this.message = 'Validation error';
      this.errors = message;
    } else {
      this.message = message;
      this.errors = [message];
    }

    Error.captureStackTrace(this, this.constructor);
  }
}

module.exports = AppError;
