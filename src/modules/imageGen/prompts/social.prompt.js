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

function insetBandHint(format) {
  const insets = format?.overlayInsets;
  if (!insets || typeof insets !== 'object') {
    return 'Keep the focal subject in the center of the frame so cover-crop does not clip faces.';
  }
  const leftPct = Math.round((Number(insets.left) || 0) * 100);
  const rightPct = Math.round((Number(insets.right) || 0) * 100);
  const topPct = Math.round((Number(insets.top) || 0) * 100);
  const bottomPct = Math.round((Number(insets.bottom) || 0) * 100);
  return `Keep the focal subject (faces, product, hero) inside the crop-safe band: ≥${topPct}% from top, ≥${bottomPct}% from bottom, ≥${leftPct}% from left, ≥${rightPct}% from right.`;
}

function overlayTypographyBlock(format) {
  return [
    'Typography / lettering (critical — overlay mode):',
    '- Do NOT render any letters, numbers, captions, watermarks, fake UI, logos-as-text, or labels.',
    '- Do not paint words from the brief, headline, subheadline, or any attached context.',
    '- Leave a quiet region matching the overlay insets for later typesetting.',
    `- ${insetBandHint(format)}`,
  ].join('\n');
}

function bakedTypographyBlock(format, { headline, subheadline, bannerLike }) {
  const parts = [
    'Typography rules (critical — baked mode):',
    '- Render the quoted headline as VERY LARGE high-contrast type. Short copy only.',
    '- All headline and body text must be fully visible, sharp, and perfectly aligned (no tilted/warped letters).',
    '- Keep text inside the format safe zone — never cut off by edges or platform UI.',
    '- No cropped, overflowing, overlapping, or unreadable text.',
    `- ${insetBandHint(format)}`,
    '- Text may use a soft local contrast treatment (subtle scrim/glow) — NOT a large separate solid panel or side bars.',
  ];
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
  return parts.join('\n');
}

/**
 * Build a social creative prompt.
 * textMode overlay (default): no letters in the model; Sharp typesets later.
 * textMode baked: quote headline/subheadline as huge type (YouTube-style).
 */
function buildSocialPrompt({
  prompt,
  styleId,
  format,
  headline,
  subheadline,
  brandPalette,
  textMode = 'overlay',
} = {}) {
  const parts = [];
  const ratio = aspectLabel(format);
  const bannerLike = isBannerOrCover(format);
  const overlay = textMode !== 'baked';

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

    if (format.safeZone && Array.isArray(format.composeRules) && format.composeRules.length) {
      parts.push(`Safe zone summary: ${format.safeZone}`);
    }
  }

  if (overlay) {
    parts.push(overlayTypographyBlock(format));
  } else {
    parts.push(bakedTypographyBlock(format, { headline, subheadline, bannerLike }));
  }

  if (Array.isArray(brandPalette) && brandPalette.length) {
    parts.push(
      `Brand colors: ${brandPalette.join(', ')}. Use as accents and lighting — never as empty solid filler panels.`
    );
  }

  if (prompt && String(prompt).trim()) {
    if (overlay) {
      parts.push(
        `Creative brief (visual scene only — do not typeset any words from this brief): ${String(prompt).trim()}`
      );
    } else {
      parts.push(`Creative brief: ${String(prompt).trim()}`);
    }
  } else if (overlay) {
    parts.push(
      'No creative brief: produce a premium full-bleed photographic or illustrated brand background matching the style.'
    );
  }

  const suffix = styleSuffix(styleId);
  if (suffix) {
    parts.push(suffix);
  }

  parts.push(
    overlay
      ? bannerLike
        ? 'Premium panoramic social banner/cover: full-bleed, edge-to-edge, ZERO letters, production-ready background.'
        : 'High-quality marketing background, full-bleed, ZERO letters or numbers, production-ready for overlay typesetting.'
      : bannerLike
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
