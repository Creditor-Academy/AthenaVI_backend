/** AI outline / full-deck generate hard max */
const AI_SLIDE_MAX = 20;
/** Manual add / duplicate deck total hard max */
const DECK_SLIDE_MAX = 40;
/** Max freeform elements on one slide */
const MAX_ELEMENTS_PER_SLIDE = 50;
/** Default canvas for 16:9 freeform editor */
const CANVAS_WIDTH = 1920;
const CANVAS_HEIGHT = 1080;
/** pptxgenjs 16:9 layout inches */
const PPTX_WIDTH_IN = 13.333;
const PPTX_HEIGHT_IN = 7.5;

const ELEMENT_TYPES = ['text', 'image', 'shape', 'icon', 'chart', 'table'];

const ASPECT_CANVAS = {
  '16:9': { width: 1920, height: 1080, pptxWidthIn: 13.333, pptxHeightIn: 7.5 },
  '4:3': { width: 1600, height: 1200, pptxWidthIn: 10, pptxHeightIn: 7.5 },
  '9:16': { width: 1080, height: 1920, pptxWidthIn: 7.5, pptxHeightIn: 13.333 },
};

function resolveAspectCanvas(aspectRatio) {
  return ASPECT_CANVAS[String(aspectRatio || '16:9')] || ASPECT_CANVAS['16:9'];
}

module.exports = {
  AI_SLIDE_MAX,
  DECK_SLIDE_MAX,
  MAX_ELEMENTS_PER_SLIDE,
  CANVAS_WIDTH,
  CANVAS_HEIGHT,
  PPTX_WIDTH_IN,
  PPTX_HEIGHT_IN,
  ELEMENT_TYPES,
  ASPECT_CANVAS,
  resolveAspectCanvas,
};
