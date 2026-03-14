const Joi = require('joi');

const updateUserProfileValidation = Joi.object({
  body: Joi.object({
    name: Joi.string().min(2).max(100),
    phoneNumber: Joi.string()
      .pattern(/^\+?[0-9()\-]* ?[0-9()\-]*$/)
      .min(8)
      .max(20)
      .messages({
        'string.pattern.base':
          'Phone number can contain digits, +, -, (), and only one space. Example: +1(310)1234567 or +1(310) 1234567',
        'string.min': 'Phone number must be at least 8 characters long',
        'string.max': 'Phone number cannot exceed 20 characters',
        'string.base': 'Phone number must be a string',
      }),
  })
    .min(1)
    .unknown(false)
    .required(),
});



module.exports = {
  updateUserProfileValidation,
};
