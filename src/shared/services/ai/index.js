const { getOpenAI } = require('./openai.client');
const { moderateText } = require('./moderation.service');
const {
  chatJson,
  DEFAULT_OUTLINE_MODEL,
  DEFAULT_SLIDE_MODEL,
} = require('./llm.service');
const { generateImage, editImage, generateImageWithReferences, DEFAULT_IMAGE_MODEL } = require('./image.service');
const { checkImageRelevance, summarizeReferenceImage } = require('./vision.service');

module.exports = {
  getOpenAI,
  moderateText,
  chatJson,
  DEFAULT_OUTLINE_MODEL,
  DEFAULT_SLIDE_MODEL,
  generateImage,
  editImage,
  generateImageWithReferences,
  DEFAULT_IMAGE_MODEL,
  checkImageRelevance,
  summarizeReferenceImage,
};
