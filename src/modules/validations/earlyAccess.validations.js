const Joi = require('joi');

const optionalTrimmedString = (max) =>
  Joi.string()
    .trim()
    .max(max)
    .allow('')
    .empty('')
    .optional()
    .default(null);

const earlyAccessRequestBodySchema = Joi.object({
  body: Joi.object({
    name: Joi.string().trim().max(100).required(),
    email: Joi.string().trim().email().max(254).required(),
    company: optionalTrimmedString(150),
    role: optionalTrimmedString(100),
    useCase: optionalTrimmedString(100),
    message: optionalTrimmedString(1000),
  }).required(),
});

const FIELD_LABELS = {
  'body.name': 'name',
  'body.email': 'email',
  'body.company': 'company',
  'body.role': 'role',
  'body.useCase': 'useCase',
  'body.message': 'message',
};

const FIELD_MESSAGES = {
  'any.required': 'Required',
  'string.empty': 'Required',
  'string.email': 'Must be a valid email address',
  'string.max': 'Too long',
};

function mapJoiDetailsToFields(details) {
  const fields = {};

  for (const detail of details) {
    const fieldKey = FIELD_LABELS[detail.path.join('.')] || detail.path[detail.path.length - 1];
    const message =
      FIELD_MESSAGES[detail.type] ||
      (detail.type === 'string.email' ? 'Must be a valid email address' : detail.message);

    if (!fields[fieldKey]) {
      fields[fieldKey] = message;
    }
  }

  return fields;
}

function validateEarlyAccessBody(body) {
  const { error, value } = earlyAccessRequestBodySchema.validate(
    { body },
    {
      abortEarly: false,
      stripUnknown: true,
      convert: true,
    }
  );

  if (error) {
    return {
      valid: false,
      fields: mapJoiDetailsToFields(error.details),
    };
  }

  return {
    valid: true,
    value: value.body,
  };
}

module.exports = {
  earlyAccessRequestBodySchema,
  validateEarlyAccessBody,
};
