import cjs from '../contentContract.js';

export const {
  CHARS_PER_WORD,
  WORDS_PER_LINE,
  deriveContentContract,
  normalizeContentForLayout,
  validateContentForLayout,
  validateContentForLayoutSoft,
  repairContentForLayout,
  repairContentForLayoutDetailed,
  clampRepeatingGroups,
  assertContentForLayout,
} = cjs;

export default cjs;
