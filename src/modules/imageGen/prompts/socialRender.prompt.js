const { composeRulesForMode } = require('../catalogs/formats');

/** Aspects within this relative difference crop too little to mention. */
const CROP_TOLERANCE = 0.03;

function parseAspect(value) {
  const match = String(value || '').match(/^\s*(\d+(?:\.\d+)?)\s*[:x]\s*(\d+(?:\.\d+)?)\s*$/i);
  if (!match) return null;
  const w = Number(match[1]);
  const h = Number(match[2]);
  return w > 0 && h > 0 ? w / h : null;
}

/**
 * Portion of the rendered canvas that survives the centered cover crop
 * to the destination size, as whole percentages.
 */
function visibleRegion(format, providerAspect) {
  if (!format || !providerAspect) return null;
  const target = format.width / format.height;
  const diff = Math.abs(target - providerAspect) / providerAspect;
  if (diff <= CROP_TOLERANCE) return null;
  if (target > providerAspect) {
    return { axis: 'height', percent: Math.round((providerAspect / target) * 100) };
  }
  return { axis: 'width', percent: Math.round((target / providerAspect) * 100) };
}

function cropInstruction(region) {
  if (!region) return null;
  if (region.axis === 'height') {
    return `The finished image is cropped to a centered horizontal band covering only the middle ${region.percent}% of the canvas height. Put every word, logo, and face inside that band; the top and bottom outside it must contain only background.`;
  }
  return `The finished image is cropped to a centered vertical column covering only the middle ${region.percent}% of the canvas width. Put every word, logo, and face inside that column; the sides outside it must contain only background.`;
}

function safeAreaInstruction(format) {
  if (!format || !format.safeArea) return null;
  const w = Math.round((format.safeArea.width / format.width) * 100);
  const h = Math.round((format.safeArea.height / format.height) * 100);
  return `Hard safe area: all text and logos inside a centered box ${w}% of the final width and ${h}% of the final height.`;
}

function buildCopyBlock(spec) {
  const lines = [`Headline (exact): "${spec.headline}"`];
  if (spec.supportingText) lines.push(`Supporting line (exact): "${spec.supportingText}"`);
  if (spec.cta) lines.push(`Call to action (exact): "${spec.cta}"`);
  return lines.join('\n');
}

/**
 * Build the image-model prompt from a validated SocialPostSpec.
 * @param {{ spec: object, format: object, providerAspect?: number|null, hasReferences?: boolean }} args
 */
function buildSocialRenderPrompt({
  spec,
  format,
  providerAspect = null,
  hasReferences = false,
} = {}) {
  const { composeRules, safeZone } = composeRulesForMode(format, 'social');

  const parts = [
    `Create a finished ${format.name} graphic for ${format.platform}.`,
    'Render the exact on-image text below, correctly spelled. Do not add, remove, or alter any words or numbers, and add no other text.',
    '',
    `Final size: ${format.width}x${format.height} px (${format.aspectRatio}).`,
    '',
    'Composition rules:',
    ...composeRules.map((r) => `- ${r}`),
  ];

  if (safeZone) parts.push(`Safe zone: ${safeZone}`);
  const safeArea = safeAreaInstruction(format);
  if (safeArea) parts.push(safeArea);
  const crop = cropInstruction(visibleRegion(format, providerAspect));
  if (crop) parts.push(crop);

  parts.push('', `Visual subject: ${spec.visualSubject}`);
  if (spec.composition) parts.push(`Layout: ${spec.composition}`);

  if (spec.visualStyle && String(spec.visualStyle).trim()) {
    parts.push(`Visual style (follow this appearance guidance): ${String(spec.visualStyle).trim()}`);
  } else {
    parts.push('Visual style: none specified — make a clean, modern, eye-catching default.');
  }

  if (Array.isArray(spec.palette) && spec.palette.length) {
    parts.push(`Color palette (hard constraint): ${spec.palette.join(', ')}`);
  }

  parts.push('', '=== ON-IMAGE TEXT (exact) ===', buildCopyBlock(spec), '=== END TEXT ===');

  if (hasReferences) {
    parts.push(
      '',
      'Reference images: use them as brand, logo, product, or style cues. Do not copy their text.'
    );
  }

  return parts.join('\n');
}

module.exports = {
  buildSocialRenderPrompt,
  buildCopyBlock,
  parseAspect,
  visibleRegion,
};
