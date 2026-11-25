/** Ordered roles for multi-accent layout chrome (columns, steps, pricing tiers). */
export const THEME_PALETTE_SEQUENCE = Object.freeze([
  'primary',
  'accent',
  'secondary',
  'chart1',
  'chart2',
  'chart3',
  'muted',
]);

function normalizePalette(palette) {
  if (!palette || typeof palette !== 'object') return {};
  if (palette.palette && typeof palette.palette === 'object') return palette.palette;
  return palette;
}

function normalizeColorRoles(colorRoles) {
  if (!colorRoles || typeof colorRoles !== 'object') return {};
  return colorRoles;
}

export function resolvePaletteRole(palette, colorRoles, role, fallback = null) {
  const pal = normalizePalette(palette);
  const roles = normalizeColorRoles(colorRoles);
  const key = String(role || '').trim();
  if (!key) return fallback;
  if (roles[key] != null && String(roles[key]).trim()) return String(roles[key]).trim();
  if (pal[key] != null) {
    const hit = pal[key];
    if (typeof hit === 'string' && hit.trim()) return hit.trim();
    if (hit && typeof hit === 'object' && hit.color) return String(hit.color).trim();
  }
  return fallback;
}

export function resolvePaletteSequenceIndex(palette, colorRoles, index, fallback = '#6366F1') {
  const i = Math.max(0, Number(index) || 0);
  const role = THEME_PALETTE_SEQUENCE[i % THEME_PALETTE_SEQUENCE.length];
  return resolvePaletteRole(palette, colorRoles, role, fallback);
}

export function isThemedColorMode(colorMode) {
  const mode = String(colorMode || '').toLowerCase();
  return mode === 'recolorable' || mode === 'themed' || mode === 'sequenced';
}

export function graphicContentFromTheme({
  svg,
  colorMode = 'themed',
  fillColorRole = null,
  sequenceIndex = null,
  fill = null,
  alt = '',
  colorRoles = null,
} = {}) {
  const content = {
    svg,
    colorMode: sequenceIndex != null && sequenceIndex >= 0 ? 'sequenced' : colorMode,
    alt: alt || '',
  };
  if (fillColorRole) content.fillColorRole = fillColorRole;
  if (sequenceIndex != null && sequenceIndex >= 0) content.sequenceIndex = Number(sequenceIndex);
  if (colorRoles && typeof colorRoles === 'object') content.colorRoles = colorRoles;
  if (fill != null && !isThemedColorMode(content.colorMode)) content.fill = fill;
  return content;
}

export function resolveGraphicDisplayColor(content = {}, palette = {}, colorRoles = null) {
  const roles = colorRoles || content.colorRoles || null;
  const mode = String(content.colorMode || '').toLowerCase();
  const themed = isThemedColorMode(mode);

  if (content.fillColorRole) {
    return resolvePaletteRole(palette, roles, content.fillColorRole, null);
  }
  if (content.fill && typeof content.fill === 'object' && content.fill.colorRole) {
    return resolvePaletteRole(palette, roles, content.fill.colorRole, null);
  }
  if (content.sequenceIndex != null && content.sequenceIndex >= 0) {
    return resolvePaletteSequenceIndex(palette, roles, content.sequenceIndex, null);
  }
  if (!themed && typeof content.fill === 'string' && content.fill.trim()) {
    return content.fill.trim();
  }
  if (content.colorOverrides?.primary) return String(content.colorOverrides.primary).trim();
  return (
    resolvePaletteRole(palette, roles, 'accent', null) ||
    resolvePaletteRole(palette, roles, 'primary', null) ||
    '#6366F1'
  );
}

const graphicTheme = {
  THEME_PALETTE_SEQUENCE,
  resolvePaletteRole,
  resolvePaletteSequenceIndex,
  graphicContentFromTheme,
  resolveGraphicDisplayColor,
  isThemedColorMode,
};

export default graphicTheme;
