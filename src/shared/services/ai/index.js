const { getOpenAI } = require('./openai.client');
const { moderateText } = require('./moderation.service');
const {
  chatJson,
  DEFAULT_OUTLINE_MODEL,
  DEFAULT_SLIDE_MODEL,
} = require('./llm.service');
const { generateImage, DEFAULT_IMAGE_MODEL } = require('./image.service');
const { checkImageRelevance } = require('./vision.service');

module.exports = {
  getOpenAI,
  moderateText,
  chatJson,
  DEFAULT_OUTLINE_MODEL,
  DEFAULT_SLIDE_MODEL,
  generateImage,
  DEFAULT_IMAGE_MODEL,
  checkImageRelevance,
};
