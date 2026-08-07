const { styleSuffix } = require('../catalogs/styles');

function aspectLabel(format) {
  if (!format?.width || !format?.height) return null;
  const w = format.width;
  const h = format.height;
  const g = gcd(w, h);
  return `${Math.round(w / g)}:${Math.round(h / g)}`;
}

function gcd(a, b) {
  let x = Math.abs(a);
  let y = Math.abs(b);
  while (y) {
    const t = y;
    y = x % y;
    x = t;
  }
  return x || 1;
}

/**
 * Build a social creative prompt with format-aware composition + typography rules.
 * Emphasizes safe zones so post-resize does not clip or misalign text.
 */
function buildSocialPrompt({
  prompt,
  styleId,
  format,
  headline,
  subheadline,
  brandPalette,
} = {}) {
  const parts = [];
  const ratio = aspectLabel(format);

  if (format) {
    parts.push(
      [
        `Create a polished ${format.name} social media graphic.`,
        `Final canvas: exactly ${format.width}x${format.height} pixels${ratio ? ` (${ratio} aspect ratio)` : ''}.`,
        'Compose the FULL design for this exact aspect ratio as if designing on the final canvas.',
        'Do not design for a different aspect and hope it crops later.',
      ].join(' ')
    );

    if (format.safeZone) {
      parts.push(`Safe zone / platform UI: ${format.safeZone}`);
    }
  }

  parts.push(
    [
      'Typography rules (critical):',
      '- All headline and body text must be fully visible, sharp, and perfectly aligned (no tilted/warped letters).',
      '- Keep ALL text inside a centered safe area with at least 10% margin from every edge.',
      '- Never place text, logos, or CTAs near edges, corners, or where platform UI may overlap.',
      '- No cropped, cut-off, overflowing, overlapping, or unreadable text.',
      '- Prefer short headlines; large high-contrast letters with clear spacing.',
      '- Text must sit on a clean area (solid or soft gradient) so it stays legible.',
    ].join('\n')
  );

  if (headline) {
    parts.push(
      `Primary headline (exact wording, fully on-canvas, centered or left-aligned consistently): "${String(headline).trim()}".`
    );
  }
  if (subheadline) {
    parts.push(
      `Supporting subheadline (exact wording, fully on-canvas, aligned under the headline): "${String(subheadline).trim()}".`
    );
  }

  if (Array.isArray(brandPalette) && brandPalette.length) {
    parts.push(`Brand colors: ${brandPalette.join(', ')}. Use them consistently for accents and text contrast.`);
  }

  if (prompt) {
    parts.push(`Creative brief: ${String(prompt).trim()}`);
  }

  const suffix = styleSuffix(styleId);
  if (suffix) {
    parts.push(suffix);
  }

  parts.push(
    'High-quality marketing creative, professional layout, balanced composition, production-ready for social upload.'
  );

  return parts.filter(Boolean).join('\n\n');
}

module.exports = {
  buildSocialPrompt,
  aspectLabel,
};
