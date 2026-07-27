const OpenAI = require('openai');
const AppError = require('../../utils/AppError');

/** @type {import('openai').default | null} */
let client = null;

/**
 * Lazy OpenAI client from OPENAI_API_KEY.
 * @returns {import('openai').default}
 */
function getOpenAI() {
  if (client) return client;

  const apiKey = process.env.OPENAI_API_KEY && String(process.env.OPENAI_API_KEY).trim();
  if (!apiKey) {
    throw new AppError('OpenAI is not configured (missing OPENAI_API_KEY)', 503);
  }

  client = new OpenAI({ apiKey });
  return client;
}

module.exports = {
  getOpenAI,
};
