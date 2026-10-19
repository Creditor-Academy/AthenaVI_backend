const Joi = require('joi');

const catalogSchema = Joi.object({
  query: Joi.object({
    q: Joi.string().trim().min(1).max(100).optional(),
    category: Joi.string()
      .trim()
      .valid('sans-serif', 'serif', 'display', 'handwriting', 'monospace')
      .optional(),
    subset: Joi.string().trim().min(1).max(64).optional(),
    featured: Joi.alternatives()
      .try(Joi.boolean(), Joi.string().valid('true', 'false', '1', '0', 'yes', 'no'))
      .optional(),
    limit: Joi.number().integer().min(1).max(500).default(200),
  }),
});

const cssSchema = Joi.object({
  query: Joi.object({
    families: Joi.alternatives()
      .try(
        Joi.string().trim().min(1).max(2000),
        Joi.array().items(Joi.string().trim().min(1).max(128)).min(1).max(40)
      )
      .required(),
  }),
});

module.exports = {
  catalogSchema,
  cssSchema,
};
