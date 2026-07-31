const outlinePrompt = require('./outline.prompt');
const slideContentPrompt = require('./slideContent.prompt');
const classifyPrompt = require('./classify.prompt');
const imageBriefPrompt = require('./imageBrief.prompt');
const pathBPrompt = require('./pathB.prompt');
const visionRelevancePrompt = require('./visionRelevance.prompt');

const PROMPT_BUNDLE_VERSION = 'v1.3';

function getOutlinePrompt() {
  return outlinePrompt;
}

function getSlideContentPrompt() {
  return slideContentPrompt;
}

function getClassifyPrompt() {
  return classifyPrompt;
}

function getImageBriefPrompt() {
  return imageBriefPrompt;
}

function getPathBPrompt() {
  return pathBPrompt;
}

function getVisionRelevancePrompt() {
  return visionRelevancePrompt;
}

module.exports = {
  PROMPT_BUNDLE_VERSION,
  getOutlinePrompt,
  getSlideContentPrompt,
  getClassifyPrompt,
  getImageBriefPrompt,
  getPathBPrompt,
  getVisionRelevancePrompt,
  // Direct access for convenience
  outlinePrompt,
  slideContentPrompt,
  classifyPrompt,
  imageBriefPrompt,
  pathBPrompt,
  visionRelevancePrompt,
};
