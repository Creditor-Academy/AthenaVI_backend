const MAX_FILENAME_BASE_LENGTH = 50;
const MAX_SIGNIFICANT_WORDS = 8;

const STOP_WORDS = new Set([
  'a',
  'an',
  'the',
  'of',
  'and',
  'or',
  'for',
  'to',
  'in',
  'on',
  'with',
  'at',
  'by',
  'from',
  'is',
  'it',
  'as',
  'into',
]);

const WINDOWS_RESERVED = new Set([
  'con',
  'prn',
  'aux',
  'nul',
  'com1',
  'com2',
  'com3',
  'com4',
  'com5',
  'com6',
  'com7',
  'com8',
  'com9',
  'lpt1',
  'lpt2',
  'lpt3',
  'lpt4',
  'lpt5',
  'lpt6',
  'lpt7',
  'lpt8',
  'lpt9',
]);

function withPngExtension(name) {
  const trimmed = String(name || '').trim();
  if (!trimmed) return 'athena-image.png';
  return /\.png$/i.test(trimmed) ? trimmed : `${trimmed}.png`;
}

function slugifyPromptText(text) {
  const raw = String(text || '').trim();
  if (!raw) return '';

  const ascii = raw
    .normalize('NFKD')
    .replace(/\p{M}/gu, '')
    .toLowerCase();

  const words = ascii
    .split(/[^a-z0-9]+/)
    .filter((word) => word && !STOP_WORDS.has(word))
    .slice(0, MAX_SIGNIFICANT_WORDS);

  let base = words.join('-').replace(/-+/g, '-').replace(/^-|-$/g, '');
  if (base.length > MAX_FILENAME_BASE_LENGTH) {
    base = base.slice(0, MAX_FILENAME_BASE_LENGTH).replace(/-+$/g, '');
    const lastHyphen = base.lastIndexOf('-');
    if (lastHyphen >= 12) {
      base = base.slice(0, lastHyphen);
    }
  }

  if (WINDOWS_RESERVED.has(base)) {
    return `athena-${base}`;
  }

  return base;
}

function collectPromptSources({ prompt, instruction } = {}) {
  return [prompt, instruction].filter((value) => value && String(value).trim());
}

/**
 * Display filename for AI Image Studio assets and downloads.
 * Does not affect S3 keys (those stay UUID-based).
 */
function generateDescriptiveFilename({ prompt, mode, instruction } = {}) {
  const fallback = `athena-${mode || 'image'}.png`;

  for (const source of collectPromptSources({ prompt, instruction })) {
    const slug = slugifyPromptText(source);
    if (slug) {
      return `${slug}.png`;
    }
  }

  return fallback;
}

function resolveAssetFilename({ name, prompt, mode, instruction } = {}) {
  if (name && String(name).trim()) {
    return withPngExtension(name);
  }
  return generateDescriptiveFilename({
    prompt,
    mode,
    instruction,
  });
}

module.exports = {
  generateDescriptiveFilename,
  resolveAssetFilename,
  slugifyPromptText,
  withPngExtension,
};
