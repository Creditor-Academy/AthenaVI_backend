import cjs from '../contentContract.js';

export const CHARS_PER_WORD = cjs.CHARS_PER_WORD;
export const WORDS_PER_LINE = cjs.WORDS_PER_LINE;
export const deriveContentContract = cjs.deriveContentContract;
export const normalizeContentForLayout = cjs.normalizeContentForLayout;
export const collectRawArrayOverflowErrors = cjs.collectRawArrayOverflowErrors;
export const collectPostNormalizeContractErrors = cjs.collectPostNormalizeContractErrors;
export const contentFitsLayoutGroups = cjs.contentFitsLayoutGroups;
export const validateContentForLayout = cjs.validateContentForLayout;
export const validateContentForLayoutSoft = cjs.validateContentForLayoutSoft;
export const repairContentForLayout = cjs.repairContentForLayout;
export const repairContentForLayoutDetailed = cjs.repairContentForLayoutDetailed;
export const clampRepeatingGroups = cjs.clampRepeatingGroups;
export const assertContentForLayout = cjs.assertContentForLayout;

export default cjs;
