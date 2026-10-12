const { inferTypographyRole } = require('./typographyRoles');

/**
 * Deck-wide heading sizes: theme typeScale first, seed slot fontSize as ceiling only.
 */
function resolveHeadingTypography({
  slot,
  layoutSchema,
  themeTokens,
  placement,
  canvasWidth,
  canvasFontSizeForTextSlot,
  resolveTypeScaleFontSize,
  styleForSlotFallback,
}) {
  const ty = slot?.typography || {};
  const role = String(slot?.role || '').toLowerCase();
  const slotId = slot?.id || '';
  const scale = themeTokens?.typeScale || {};
  const typographyRole = inferTypographyRole({ slot, layoutSchema });
  const fallback = styleForSlotFallback ? styleForSlotFallback(slotId, layoutSchema) : {};

  let fontSize = null;
  const semanticSize =
    typographyRole === 'heroTitle'
      ? scale.display
      : typographyRole === 'title' || typographyRole === 'sectionTitle'
        ? scale.title
        : typographyRole === 'cardTitle'
          ? scale.subtitle ?? (scale.body != null ? Math.round(Number(scale.body) * 1.35) : null)
          : typographyRole === 'subtitle'
            ? scale.subtitle
            : typographyRole === 'body'
              ? scale.body
              : typographyRole === 'caption' || typographyRole === 'eyebrow' || typographyRole === 'label'
                ? scale.caption
                : typographyRole === 'metric'
                  ? scale.stat ?? scale.display
                  : null;

  if (semanticSize != null && Number(semanticSize) > 0) {
    fontSize = Number(semanticSize);
  } else if (resolveTypeScaleFontSize) {
    fontSize = resolveTypeScaleFontSize(role, scale, slotId);
  }

  if (
    fontSize == null &&
    role === 'heading' &&
    scale.display != null &&
    typographyRole !== 'cardTitle' &&
    !/^(card|col|row|feature|bullet|item)_\d+_/i.test(String(slotId || ''))
  ) {
    fontSize = Number(scale.display);
  }

  if (fontSize == null && placement && canvasFontSizeForTextSlot) {
    fontSize = canvasFontSizeForTextSlot(slot, placement, canvasWidth);
  }
  if (fontSize == null) fontSize = fallback.fontSize;

  const seedCeiling = ty.fontSize != null ? Number(ty.fontSize) : null;
  if (seedCeiling != null && Number.isFinite(seedCeiling) && seedCeiling > 0) {
    if (fontSize == null) fontSize = seedCeiling;
    else if (typographyRole === 'heroTitle' || typographyRole === 'title' || typographyRole === 'sectionTitle') {
      fontSize = Math.min(fontSize, seedCeiling);
    }
  }

  const fontWeight =
    ty.fontWeight != null
      ? Number(ty.fontWeight)
      : fallback.bold
        ? 700
        : typographyRole === 'heroTitle' || typographyRole === 'title'
          ? 700
          : 400;

  return {
    fontSize,
    fontWeight,
    bold: fontWeight >= 600,
    typographyRole,
  };
}

module.exports = {
  resolveHeadingTypography,
};
