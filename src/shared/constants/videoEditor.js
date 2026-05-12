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
  'slide-left',
  'slide-right',
  'slide-up',
  'slide-down',
  'wipe-left',
  'wipe-right',
  'zoom-in',
  'zoom-out',
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

module.exports = {
  ELEMENT_TYPES,
  TRANSITION_TYPES,
  ANIMATION_TYPES,
  PROJECT_STATUSES,
  RENDER_STATUSES,
  DEFAULT_VIDEO_SETTINGS,
};
