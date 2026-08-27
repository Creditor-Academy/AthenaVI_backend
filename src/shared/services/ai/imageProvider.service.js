const openaiImage = require('./image.service');
const geminiImage = require('./geminiImage.service');

/**
 * Provider-agnostic image calls for Image Gen catalog models.
 * Both providers return the same shape: { b64, buffer, revised_prompt, usage, latencyMs, model }.
 *
 * Callers pass `size` (OpenAI WxH string) and `aspectRatio` (Gemini ratio) so this
 * module stays free of the imageGen catalog.
 */

function isGemini(model) {
  return (model && model.provider) === 'gemini';
}

async function generateForModel({
  model,
  prompt,
  size,
  aspectRatio,
  referenceBuffers = [],
} = {}) {
  const useRefs = Array.isArray(referenceBuffers) && referenceBuffers.length > 0;

  if (isGemini(model)) {
    const opts = {
      prompt,
      model: model.providerModel,
      aspectRatio,
      maxImageSize: model.maxImageSize,
    };
    return useRefs
      ? geminiImage.generateImageWithReferences({ ...opts, referenceBuffers })
      : geminiImage.generateImage(opts);
  }

  const opts = {
    prompt,
    model: model.providerModel,
    quality: model.quality,
    size,
  };
  return useRefs
    ? openaiImage.generateImageWithReferences({ ...opts, referenceBuffers })
    : openaiImage.generateImage(opts);
}

async function editForModel({ model, imageBuffer, instruction, size, aspectRatio } = {}) {
  if (isGemini(model)) {
    return geminiImage.editImage({
      imageBuffer,
      instruction,
      model: model.providerModel,
      aspectRatio,
      maxImageSize: model.maxImageSize,
    });
  }

  // OpenAI edits always run on gpt-image-1 (dall-e has no edit endpoint).
  return openaiImage.editImage({
    imageBuffer,
    instruction,
    model: 'gpt-image-1',
    quality: model?.quality === 'high' ? 'high' : 'medium',
    size,
  });
}

module.exports = {
  generateForModel,
  editForModel,
};
