const ELEMENT_TYPES = [
  'avatar',
  'text',
  'image',
  'video',
  'audio',
  'shape',
  'subtitle',
];

const TRANSITION_TYPES = [
  'cut',
  'fade',
  'dissolve',
  'slide-left',
  'slide-right',
  'slide-up',
  'slide-down',
  'wipe-left',
  'wipe-right',
  'zoom-in',
  'zoom-out',
  'circle-wipe-in',
  'circle-wipe-out',
  'colour-wipe-left',
  'colour-wipe-right',
  'colour-wipe-up',
  'colour-wipe-down',
  'line-wipe-left',
  'line-wipe-right',
  'line-wipe-up',
  'line-wipe-down',
  'match-move',
  'flow-left',
  'flow-right',
  'flow-up',
  'flow-down',
  'stack-left',
  'stack-right',
  'stack-up',
  'stack-down',
  'chop',
];

const ANIMATION_TYPES = [
  'fade-in',
  'fade-out',
  'slide-up',
  'slide-down',
  'slide-left',
  'slide-right',
  'zoom-in',
  'zoom-out',
  'scale-in',
  'scale-out',
  'rotate-in',
  'rotate-out',
  'typewriter',
  'bounce',
  'pulse',
];

const PROJECT_STATUSES = ['draft', 'rendering', 'completed', 'failed'];
const RENDER_STATUSES = ['queued', 'processing', 'completed', 'failed'];

const DEFAULT_VIDEO_SETTINGS = {
  width: 1920,
  height: 1080,
  fps: 30,
  backgroundColor: '#000000',
};

/** Matches Create Video wizard canvas presets (step 1). */
const CANVAS_ASPECT_RATIOS = ['16:9', '9:16', '1:1', '4:5', 'custom'];

const CANVAS_PRESETS = {
  '16:9': { width: 1920, height: 1080 },
  '9:16': { width: 1080, height: 1920 },
  '1:1': { width: 1080, height: 1080 },
  '4:5': { width: 1080, height: 1350 },
};

module.exports = {
  ELEMENT_TYPES,
  TRANSITION_TYPES,
  ANIMATION_TYPES,
  PROJECT_STATUSES,
  RENDER_STATUSES,
  DEFAULT_VIDEO_SETTINGS,
  CANVAS_ASPECT_RATIOS,
  CANVAS_PRESETS,
};
