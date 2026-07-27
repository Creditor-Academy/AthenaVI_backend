const AppError = require('../../utils/AppError');
const { getOpenAI } = require('./openai.client');

/**
 * Moderate text via OpenAI Moderations. Requires a configured client.
 * @param {string} text
 * @returns {Promise<{ flagged: false, categories: object, category_scores: object }>}
 */
async function moderateText(text) {
  const openai = getOpenAI();
  const input = text == null ? '' : String(text);

  const result = await openai.moderations.create({ input });
  const row = result?.results?.[0];

  if (!row) {
    throw new AppError('Moderation check failed', 502);
  }

  if (row.flagged) {
    throw new AppError('Content failed safety moderation', 400);
  }

  return {
    flagged: false,
    categories: row.categories || {},
    category_scores: row.category_scores || {},
  };
}

module.exports = {
  moderateText,
};
