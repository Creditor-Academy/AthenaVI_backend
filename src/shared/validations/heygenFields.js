const Joi = require('joi');
const {
  HEYGEN_AVATAR_ENGINE_VALUES,
  DEFAULT_HEYGEN_AVATAR_ENGINE,
} = require('../constants/heygen');

/**
 * HeyGen looks often return `supported_api_engines: []`. Clients may mirror that
 * as `avatarEngine: ""`. Treat missing/empty as the default engine.
 */
function avatarEngineField({ optional = false, withDefault = true } = {}) {
  let schema = Joi.string()
    .trim()
    .empty('')
    .valid(...HEYGEN_AVATAR_ENGINE_VALUES);

  if (withDefault) {
    schema = schema.default(DEFAULT_HEYGEN_AVATAR_ENGINE);
  }
  if (optional) {
    schema = schema.optional();
  }
  return schema;
}

module.exports = {
  avatarEngineField,
};
