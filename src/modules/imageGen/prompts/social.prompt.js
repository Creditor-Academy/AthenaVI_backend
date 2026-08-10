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

function isBannerOrCover(format) {
  const id = format?.id || '';
  return /banner|cover|header/i.test(id);
}

/**
 * Per-format composition block from catalog composeRules (fallback to safeZone).
 */
function formatCompositionBlock(format) {
  if (!format) return null;
  const rules = Array.isArray(format.composeRules) ? format.composeRules.filter(Boolean) : [];
  if (rules.length) {
    return [`Composition rules for ${format.name} (${format.width}×${format.height}):`, ...rules.map((r) => `- ${r}`)].join(
      '\n'
    );
  }
  if (format.safeZone) {
    return `Platform safe zone: ${format.safeZone}`;
  }
  return null;
}

/**
 * Build a social creative prompt with per-format composition + typography rules.
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
  const bannerLike = isBannerOrCover(format);

  if (format) {
    parts.push(
      [
        `Create a polished ${format.name} social media graphic.`,
        `Final canvas: exactly ${format.width}x${format.height} pixels${ratio ? ` (${ratio} aspect ratio)` : ''}.`,
        'Compose as one continuous full-bleed artwork for this exact size.',
      ].join(' ')
    );

    const composition = formatCompositionBlock(format);
    if (composition) {
      parts.push(composition);
    }

    // Keep a short safeZone reminder for FE-aligned copy (composeRules already include detail)
    if (format.safeZone && Array.isArray(format.composeRules) && format.composeRules.length) {
      parts.push(`Safe zone summary: ${format.safeZone}`);
    }
  }

  parts.push(
    [
      'Typography rules (critical):',
      '- All headline and body text must be fully visible, sharp, and perfectly aligned (no tilted/warped letters).',
      '- Keep text inside the format safe zone — never cut off by edges or platform UI.',
      '- No cropped, overflowing, overlapping, or unreadable text.',
      '- Prefer short headlines; large high-contrast modern type with clear spacing.',
      '- Text may use a soft local contrast treatment (subtle scrim/glow) — NOT a large separate solid panel or side bars.',
    ].join('\n')
  );

  if (headline) {
    const placement = bannerLike
      ? 'Place around center-right (not extreme left); fully on-canvas'
      : 'Fully on-canvas within safe margins';
    parts.push(`Primary headline (${placement}): "${String(headline).trim()}".`);
  }
  if (subheadline) {
    parts.push(
      `Supporting subheadline (exact wording, fully on-canvas under the headline): "${String(subheadline).trim()}".`
    );
  }

  if (Array.isArray(brandPalette) && brandPalette.length) {
    parts.push(
      `Brand colors: ${brandPalette.join(', ')}. Use as accents and lighting — never as empty solid filler panels.`
    );
  }

  if (prompt) {
    parts.push(`Creative brief: ${String(prompt).trim()}`);
  }

  const suffix = styleSuffix(styleId);
  if (suffix) {
    parts.push(suffix);
  }

  parts.push(
    bannerLike
      ? 'Premium panoramic social banner/cover: full-bleed, edge-to-edge, no blank panels, production-ready.'
      : 'High-quality marketing creative, full-bleed, professional layout, production-ready for social upload.'
  );

  return parts.filter(Boolean).join('\n\n');
}

module.exports = {
  buildSocialPrompt,
  aspectLabel,
  formatCompositionBlock,
  isBannerOrCover,
};
