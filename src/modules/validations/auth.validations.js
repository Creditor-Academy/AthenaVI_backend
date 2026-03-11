const Joi = require('joi');
const { token } = require('morgan');

const onlyEmailValidation = Joi.object({
  body: Joi.object({
    email: Joi.string().email().required(),
  }),
});

const verifyAndRegisterSchema = Joi.object({
  body: Joi.object({
    name: Joi.string().min(2).max(50).required(),
    email: Joi.string().email().required(),
    password: Joi.string().min(6).required(),
    otp: Joi.number().integer().min(100000).max(999999).required(),
  }),
});

const loginSchema = Joi.object({
  body: Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().required(),
  }),
});

const resetPasswordSchema = Joi.object({
  body: Joi.object({
    token: Joi.string().required(),
    newPassword: Joi.string().min(6).required(),
  }),
});


const googleCallbackSchema = Joi.object({
  query: Joi.object({
    code: Joi.string().required(),
    state: Joi.string().required(),
  }),
}); 



module.exports = {
  onlyEmailValidation,
  verifyAndRegisterSchema,
  loginSchema,
  resetPasswordSchema,
  googleCallbackSchema
};
