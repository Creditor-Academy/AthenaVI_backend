import cjs from '../textNormalize.js';

export const {
  stripUnicodeControls,
  sanitizeLineBreaks,
  normalizeStringValue,
  truncateWords,
  truncateChars,
  truncateLines,
  clampSlotText,
  walkNormalizeStrings,
} = cjs;

export default cjs;
