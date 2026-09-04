/**
 * Agenda infographic SVG hub — routes to per-family modules (diagram-style).
 * Family implementations: agendaMinimalSvg, agendaNumberedSvg, agendaColumnsSvg,
 * agendaTimelineSvg, agendaTwoColumnSvg, agendaThreeColumn.
 */

const { horizontalTimelineInlineSvg } = require('../timelineProcessSvg');
const {
  AGENDA_GEOM,
  AGENDA_ICON_KEYS,
  AGENDA_LAYOUT_META,
  agendaArrowInlineSvg,
  agendaBadgeInlineSvg,
  agendaDividerInlineSvg,
  agendaGraphicFrame,
  agendaIconInlineSvg,
  agendaSpineInlineSvg,
  iconPath,
  isAgendaInfographicLayout,
  isAgendaHeroLayout,
  isAgendaMinimalLayout,
  isAgendaNumberedLayout,
  isAgendaThreeColumnLayout,
  isAgendaTimelineLayout,
  isAgendaTwoColumnLayout,
  resolveAgendaMeta,
  scaleBox,
} = require('./agendaSharedSvg');
const { agendaMinimalChromeSpecs, agendaMinimalOverlayPlacements } = require('./agendaMinimalSvg');
const { agendaNumberedChromeSpecs, agendaNumberedOverlayPlacements } = require('./agendaNumberedSvg');
const { agendaColumnsChromeSpecs, agendaColumnsOverlayPlacements } = require('./agendaColumnsSvg');
const { agendaTimelineChromeSpecs, agendaTimelineOverlayPlacements } = require('./agendaTimelineSvg');
const { agendaTwoColumnChromeSpecs, agendaTwoColumnOverlayPlacements } = require('./agendaTwoColumnSvg');
const {
  agendaThreeColumnPreviewSvg,
  isAgendaThreeColumnColouredLayout,
  specToThreeColumnContent,
} = require('./agendaThreeColumn');
const {
  agendaThreeCardsPreviewSvg,
  isAgendaThreeCardsLayout,
  specToThreeCardsContent,
} = require('./agendaThreeCards');
const { agendaNumberedBlocksPreviewSvg } = require('./agendaNumberedBlocks');
const { agendaNumberedTimelinePreviewSvg } = require('./agendaNumberedTimeline');

function agendaChromeSpecs(family, variant, itemCount = 4) {
  switch (family) {
    case 'minimal':
      return agendaMinimalChromeSpecs(variant, itemCount)
    case 'numbered':
      return agendaNumberedChromeSpecs(variant, itemCount)
    case 'hero':
    case 'three_col':
      return agendaColumnsChromeSpecs(family, variant)
    case 'timeline':
      return agendaTimelineChromeSpecs(variant, itemCount)
    case 'two_col':
      return agendaTwoColumnChromeSpecs(variant)
    default:
      return agendaMinimalChromeSpecs('default', itemCount)
  }
}

function agendaOverlayPlacements(gx, gy, gw, gh, family, variant, opts = {}) {
  switch (family) {
    case 'minimal':
      return agendaMinimalOverlayPlacements(gx, gy, gw, gh, variant, opts)
    case 'numbered':
      return agendaNumberedOverlayPlacements(gx, gy, gw, gh, variant, opts)
    case 'hero':
    case 'three_col':
      return agendaColumnsOverlayPlacements(gx, gy, gw, gh, family, variant)
    case 'timeline':
      return agendaTimelineOverlayPlacements(gx, gy, gw, gh, variant, opts)
    case 'two_col':
      return agendaTwoColumnOverlayPlacements(gx, gy, gw, gh)
    default:
      return agendaMinimalOverlayPlacements(gx, gy, gw, gh, variant, opts)
  }
}

function buildAgendaDiagramSvg(family, variant, colors, opts = {}) {
  const specs = agendaChromeSpecs(family, variant, opts.itemCount)
  const parts = []
  const accent = colors.accent || '#6366f1'
  const muted = colors.muted || '#94a3b8'
  const soft = colors.soft || 'rgba(99,102,241,0.12)'

  for (const spec of specs) {
    const cx = spec.x + spec.w / 2
    const cy = spec.y + spec.h / 2
    if (spec.kind === 'shape') {
      parts.push(`<rect x="${spec.x}" y="${spec.y}" width="${spec.w}" height="${spec.h}" rx="${spec.borderRadius || 12}" fill="${soft}" stroke="${accent}" stroke-width="1.5" opacity="0.85"/>`)
    } else if (spec.badge) {
      parts.push(`<circle cx="${cx}" cy="${cy}" r="${spec.w / 2}" fill="${accent}"/><text x="${cx}" y="${cy + 5}" text-anchor="middle" fill="#fff" font-size="12" font-weight="800" font-family="system-ui,sans-serif">${spec.badge}</text>`)
    } else if (spec.spine) {
      parts.push(`<rect x="${spec.x}" y="${spec.y}" width="${spec.w}" height="${spec.h}" rx="1.5" fill="${spec.spine === 'v' ? accent : muted}" opacity="0.5"/>`)
    } else if (spec.divider) {
      parts.push(`<rect x="${spec.x}" y="${spec.y + spec.h / 2 - 0.5}" width="${spec.w}" height="1" fill="${muted}" opacity="0.35"/>`)
    } else if (spec.arrow) {
      parts.push(`<path d="M ${spec.x} ${cy} H ${spec.x + spec.w - 10} M ${spec.x + spec.w - 18} ${cy - 5} L ${spec.x + spec.w - 8} ${cy} L ${spec.x + spec.w - 18} ${cy + 5}" fill="none" stroke="${accent}" stroke-width="2.5" stroke-linecap="round" opacity="0.6"/>`)
    } else if (spec.timeline) {
      const inner = horizontalTimelineInlineSvg(spec.timeline, { accent, spine: muted, showChevrons: true })
      const match = inner.match(/<svg[^>]*>([\s\S]*)<\/svg>/i)
      if (match) parts.push(`<g transform="translate(${spec.x},${spec.y}) scale(${spec.w / 1000})">${match[1]}</g>`)
    } else if (spec.iconIndex != null) {
      const key = AGENDA_ICON_KEYS[spec.iconIndex % AGENDA_ICON_KEYS.length]
      const r = spec.w / 2
      parts.push(`<circle cx="${cx}" cy="${cy}" r="${r}" fill="${soft}" stroke="${accent}" stroke-width="2"/>`)
      parts.push(`<path d="${iconPath(key, cx, cy, r)}" fill="none" stroke="${accent}" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/>`)
    }
  }
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${AGENDA_GEOM.viewW} ${AGENDA_GEOM.viewH}">${parts.join('')}</svg>`
}

function agendaDiagramInlineSvg(family, variant, colors = {}, opts = {}) {
  return buildAgendaDiagramSvg(family, variant, colors, opts).replace(/<svg\b([^>]*)>/i, (match, attrs) => {
    let next = attrs
    if (!/\bwidth\s*=/i.test(next)) next += ' width="100%"'
    if (!/\bheight\s*=/i.test(next)) next += ' height="100%"'
    if (!/\bpreserveAspectRatio\s*=/i.test(next)) next += ' preserveAspectRatio="xMidYMid meet"'
    return `<svg${next}>`
  })
}

function agendaPreviewSvg(family, variant, colors = {}, opts = {}) {
  if (family === 'numbered' && (variant === 'path' || variant === 'timeline')) {
    return agendaNumberedTimelinePreviewSvg()
  }
  if (family === 'numbered' && variant !== 'cards') {
    return agendaNumberedBlocksPreviewSvg(colors)
  }
  if (family === 'three_col' && variant === 'cards') {
    return agendaThreeCardsPreviewSvg(colors)
  }
  if (family === 'three_col' && variant !== 'panels' && variant !== 'step') {
    return agendaThreeColumnPreviewSvg(colors)
  }
  return agendaDiagramInlineSvg(family, variant, {
    accent: colors.accent || '#6366f1',
    muted: colors.muted || '#94a3b8',
    soft: colors.soft || 'rgba(99,102,241,0.12)',
  }, opts)
}

function agendaPreviewSvgFromSchema(schema, colors = {}) {
  const { family, variant } = resolveAgendaMeta(schema)
  const itemCount = schema?.preview?.agendaItems?.length || schema?.preview?.milestones?.length || 4
  return agendaPreviewSvg(family, variant, colors, { itemCount })
}

function specToGraphicContent(spec, accent, soft) {
  if (spec.badge) return { svg: agendaBadgeInlineSvg(spec.badge), colorMode: 'recolorable', fill: accent }
  if (spec.spine) return { svg: agendaSpineInlineSvg(spec.spine === 'v'), colorMode: 'recolorable', fill: accent }
  if (spec.divider) return { svg: agendaDividerInlineSvg(), colorMode: 'recolorable', fill: accent }
  if (spec.arrow) return { svg: agendaArrowInlineSvg(), colorMode: 'recolorable', fill: accent }
  if (spec.timeline) {
    const inner = horizontalTimelineInlineSvg(spec.timeline, { accent, spine: '#94a3b8', showChevrons: true })
    return { svg: inner.replace(/<svg\b([^>]*)>/i, '<svg$1 width="100%" height="100%" preserveAspectRatio="none">'), colorMode: 'recolorable', fill: accent }
  }
  if (spec.iconIndex != null) return { svg: agendaIconInlineSvg(spec.iconIndex), colorMode: 'recolorable', fill: accent }
  return { svg: agendaIconInlineSvg(0), colorMode: 'recolorable', fill: accent }
}

module.exports = {
  AGENDA_GEOM,
  AGENDA_ICON_KEYS,
  AGENDA_LAYOUT_META,
  isAgendaInfographicLayout,
  isAgendaMinimalLayout,
  isAgendaNumberedLayout,
  isAgendaHeroLayout,
  isAgendaThreeColumnLayout,
  isAgendaTimelineLayout,
  isAgendaTwoColumnLayout,
  resolveAgendaMeta,
  agendaGraphicFrame,
  scaleBox,
  agendaChromeSpecs,
  agendaOverlayPlacements,
  agendaDiagramInlineSvg,
  agendaPreviewSvg,
  agendaPreviewSvgFromSchema,
  agendaIconInlineSvg,
  agendaSpineInlineSvg,
  agendaBadgeInlineSvg,
  agendaArrowInlineSvg,
  agendaDividerInlineSvg,
  isAgendaThreeColumnColouredLayout,
  specToThreeColumnContent,
  isAgendaThreeCardsLayout,
  specToThreeCardsContent,
  specToGraphicContent,
};
