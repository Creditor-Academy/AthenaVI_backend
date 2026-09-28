const { composeRulesForMode, bleedCanvasFor } = require('../catalogs/formats');
const { describeSize } = require('./printSpec.prompt');

function percent(fraction) {
  return Math.round(fraction * 100);
}

/**
 * Trim and safe boxes as centred percentages of the canvas the model renders.
 * The bleed canvas is centre-cropped out of the provider canvas, so both boxes are
 * scaled by the part of the provider canvas that survives that crop.
 */
function printGeometry(format, providerAspect = null) {
  const canvas = bleedCanvasFor(format);
  const bleedAspect = canvas.width / canvas.height;
  let keepW = 1;
  let keepH = 1;
  if (providerAspect) {
    if (bleedAspect > providerAspect) keepH = providerAspect / bleedAspect;
    else keepW = bleedAspect / providerAspect;
  }
  return {
    canvas,
    trim: {
      width: percent((format.width / canvas.width) * keepW),
      height: percent((format.height / canvas.height) * keepH),
    },
    safe: {
      width: percent(((format.width - canvas.safePx * 2) / canvas.width) * keepW),
      height: percent(((format.height - canvas.safePx * 2) / canvas.height) * keepH),
    },
  };
}

function buildPrintCopyBlock(spec) {
  const lines = [`Headline (exact): "${spec.headline}"`];
  if (spec.subheadline) lines.push(`Subheadline (exact): "${spec.subheadline}"`);
  (spec.details || []).forEach((line, i) => {
    lines.push(`Detail line ${i + 1} (exact): "${line}"`);
  });
  if (spec.cta) lines.push(`Call to action (exact): "${spec.cta}"`);
  return lines.join('\n');
}

/**
 * Build the image-model prompt from a validated PrintSpec.
 * @param {{ spec: object, format: object, providerAspect?: number|null, hasReferences?: boolean }} args
 */
function buildPrintRenderPrompt({
  spec,
  format,
  providerAspect = null,
  hasReferences = false,
} = {}) {
  const { composeRules, safeZone } = composeRulesForMode(format, 'printable');
  const geometry = printGeometry(format, providerAspect);

  const parts = [
    `Create the flat print artwork for a ${describeSize(format)}.`,
    'Render the exact printed text below, correctly spelled. Do not add, remove, or alter any words, names, numbers, emails, or addresses, and add no other text.',
    '',
    `Final print file: ${geometry.canvas.width}x${geometry.canvas.height} px at ${format.dpi} DPI, including bleed.`,
    '',
    'Composition rules:',
    ...composeRules.map((r) => `- ${r}`),
    '',
    `Trim: the finished piece is the centered box covering ${geometry.trim.width}% of the canvas width and ${geometry.trim.height}% of its height. Everything outside that box is trimmed off, so fill it with background only.`,
    `Safe area: every word and logo must sit inside the centered box covering ${geometry.safe.width}% of the width and ${geometry.safe.height}% of the height.`,
  ];

  if (safeZone) parts.push(`Safe margin: ${safeZone}`);

  parts.push('', `Artwork: ${spec.visualSubject}`);
  if (spec.composition) parts.push(`Layout: ${spec.composition}`);

  if (spec.visualStyle && String(spec.visualStyle).trim()) {
    parts.push(`Visual style (follow this appearance guidance): ${String(spec.visualStyle).trim()}`);
  } else {
    parts.push('Visual style: none specified — make a clean, professional, print-appropriate design.');
  }

  if (Array.isArray(spec.palette) && spec.palette.length) {
    parts.push(`Color palette (hard constraint): ${spec.palette.join(', ')}`);
  }

  parts.push('', '=== PRINTED TEXT (exact) ===', buildPrintCopyBlock(spec), '=== END TEXT ===');

  if (hasReferences) {
    parts.push(
      '',
      'Reference images: use them as brand, logo, product, or style cues. Do not copy their text.'
    );
  }

  return parts.join('\n');
}

module.exports = {
  buildPrintRenderPrompt,
  buildPrintCopyBlock,
  printGeometry,
};
