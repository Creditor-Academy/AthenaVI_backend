const AppError = require('../../utils/AppError');
const { getOpenAI } = require('./openai.client');

const DEFAULT_OUTLINE_MODEL = process.env.PPT_OUTLINE_MODEL || 'gpt-4.1';
const DEFAULT_SLIDE_MODEL = process.env.PPT_SLIDE_MODEL || 'gpt-4.1-mini';

/**
 * Chat completion that must return a JSON object.
 * @param {{ system: string, user: string, model?: string, schemaHint?: string|object, temperature?: number }} opts
 * @returns {Promise<{ data: object, usage: { prompt_tokens: number, completion_tokens: number }, model: string, latencyMs: number }>}
 */
async function chatJson({ system, user, model, schemaHint, temperature = 0.4 } = {}) {
  const openai = getOpenAI();
  const resolvedModel = model || DEFAULT_SLIDE_MODEL;

  let systemContent = system == null ? '' : String(system);
  if (schemaHint != null) {
    const hint =
      typeof schemaHint === 'string' ? schemaHint : JSON.stringify(schemaHint, null, 2);
    systemContent = `${systemContent}\n\nJSON schema / shape hint:\n${hint}`.trim();
  }

  const started = Date.now();
  let completion;
  try {
    completion = await openai.chat.completions.create({
      model: resolvedModel,
      temperature,
      response_format: { type: 'json_object' },
      messages: [
        { role: 'system', content: systemContent },
        { role: 'user', content: user == null ? '' : String(user) },
      ],
    });
  } catch (err) {
    const msg = err?.message || 'OpenAI chat completion failed';
    const status = err?.status >= 400 && err?.status < 600 ? err.status : 502;
    throw new AppError(msg, status);
  }

  const latencyMs = Date.now() - started;
  const raw = completion?.choices?.[0]?.message?.content;
  if (!raw || typeof raw !== 'string') {
    throw new AppError('OpenAI returned empty JSON content', 502);
  }

  let data;
  try {
    data = JSON.parse(raw);
  } catch {
    throw new AppError('OpenAI returned invalid JSON', 502);
  }

  const usage = {
    prompt_tokens: completion?.usage?.prompt_tokens ?? 0,
    completion_tokens: completion?.usage?.completion_tokens ?? 0,
  };

  return {
    data,
    usage,
    model: completion?.model || resolvedModel,
    latencyMs,
  };
}

module.exports = {
  chatJson,
  DEFAULT_OUTLINE_MODEL,
  DEFAULT_SLIDE_MODEL,
};
