const AppError = require('../shared/utils/AppError');

const validate = (schema) => (req, res, next) => {
  const { error, value } = schema.validate(
    {
      body: req.body,
      params: req.params,
      query: req.query,
    },
    {
      abortEarly: false, // return all errors
      stripUnknown: true, // remove extra fields
      convert: false, // disable type coercion
    }
  );

  if (error) {
    const errors = error.details.map((err) =>
      err.message.replace('"body.', '"')
    );

    throw new AppError(errors, 400);
  }

  req.body = value.body;
  req.params = value.params;
  req.query = value.query;

  next();
};

module.exports = validate;
