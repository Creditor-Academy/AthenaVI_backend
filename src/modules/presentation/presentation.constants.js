/** AI outline / full-deck generate hard max */
const AI_SLIDE_MAX = 20;
/** Allowed AI narrative deck lengths (title + agenda + middle + closing [+ synthesis when N≥6]) */
const PPT_NARRATIVE_SLIDE_COUNTS = Object.freeze([5, 8, 10, 12, 20]);

function clampNarrativeSlideCount(count) {
  const n = Number(count);
  if (PPT_NARRATIVE_SLIDE_COUNTS.includes(n)) return n;
  const target = Number.isFinite(n) && n > 0 ? n : 12;
  let best = PPT_NARRATIVE_SLIDE_COUNTS[0];
  let dist = Math.abs(best - target);
  for (const c of PPT_NARRATIVE_SLIDE_COUNTS) {
    const d = Math.abs(c - target);
    if (d < dist) {
      dist = d;
      best = c;
    }
  }
  return best;
}
/** Manual add / duplicate deck total hard max */
const DECK_SLIDE_MAX = 40;
/** Max freeform elements on one slide */
const MAX_ELEMENTS_PER_SLIDE = 60;
/** Default canvas for 16:9 freeform editor */
const CANVAS_WIDTH = 1920;
const CANVAS_HEIGHT = 1080;
/** pptxgenjs 16:9 layout inches */
const PPTX_WIDTH_IN = 13.333;
const PPTX_HEIGHT_IN = 7.5;

/** PPT canvas element types (FE contract) */
const ELEMENT_TYPES = [
  'text',
  'textbox',
  'image',
  'shape',
  'icon',
  'chart',
  'table',
  'embed',
  'graphic',
  'group',
];

/** PPT supports 16:9 and 4:3 only (native pixel canvases). */
const PPT_ASPECT_RATIOS = ['16:9', '4:3'];

const ASPECT_CANVAS = {
  '16:9': { width: 1920, height: 1080, pptxWidthIn: 13.333, pptxHeightIn: 7.5 },
  '4:3': { width: 1600, height: 1200, pptxWidthIn: 10, pptxHeightIn: 7.5 },
};

/** Shape kinds accepted from FE; export maps unknown → rect */
const SHAPE_KINDS = [
  'rect',
  'rounded-rect',
  'circle',
  'ellipse',
  'pill',
  'triangle',
  'diamond',
  'star',
  'line',
  'plus',
  'arrow-right',
  'arrow-left',
  'arrow-up',
  'arrow-down',
  'flow-process',
  'flow-decision',
];

function resolveAspectCanvas(aspectRatio) {
  const key = String(aspectRatio || '16:9').trim();
  return ASPECT_CANVAS[key] || ASPECT_CANVAS['16:9'];
}

const {
  SLIDE_TEXT_SAFE_INSET_X,
  SLIDE_TEXT_SAFE_INSET_Y,
  slideTextSafeRect,
} = require('./slideTextSafeArea');

module.exports = {
  AI_SLIDE_MAX,
  PPT_NARRATIVE_SLIDE_COUNTS,
  clampNarrativeSlideCount,
  DECK_SLIDE_MAX,
  MAX_ELEMENTS_PER_SLIDE,
  CANVAS_WIDTH,
  CANVAS_HEIGHT,
  SLIDE_TEXT_SAFE_INSET_X,
  SLIDE_TEXT_SAFE_INSET_Y,
  slideTextSafeRect,
  PPTX_WIDTH_IN,
  PPTX_HEIGHT_IN,
  ELEMENT_TYPES,
  PPT_ASPECT_RATIOS,
  ASPECT_CANVAS,
  SHAPE_KINDS,
  resolveAspectCanvas,
};
