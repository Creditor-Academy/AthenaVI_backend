const { GoogleGenAI } = require('@google/genai');
const AppError = require('../../utils/AppError');

/** @type {import('@google/genai').GoogleGenAI | null} */
let client = null;

/**
 * Lazy Gemini client from GEMINI_API_KEY.
 * @returns {import('@google/genai').GoogleGenAI}
 */
function getGemini() {
  if (client) return client;

  const apiKey =
    (process.env.GEMINI_API_KEY && String(process.env.GEMINI_API_KEY).trim()) ||
    (process.env.GOOGLE_API_KEY && String(process.env.GOOGLE_API_KEY).trim());
  if (!apiKey) {
    throw new AppError('Gemini is not configured (missing GEMINI_API_KEY)', 503);
  }

  client = new GoogleGenAI({ apiKey });
  return client;
}

function isGeminiConfigured() {
  return Boolean(
    (process.env.GEMINI_API_KEY && String(process.env.GEMINI_API_KEY).trim()) ||
      (process.env.GOOGLE_API_KEY && String(process.env.GOOGLE_API_KEY).trim())
  );
}

module.exports = {
  getGemini,
  isGeminiConfigured,
};
