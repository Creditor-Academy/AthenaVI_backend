/**
 * Agenda numbered family — SVG chrome, overlays, preview (diagram-style module).
 */
const {
  clampAgendaItemCount,
  createAgendaSpecBuilder,
  overlayBox,
} = require('./agendaSharedSvg');
const {
  agendaNumberedBlocksChromeSpecs,
  agendaNumberedBlocksOverlayPlacements,
} = require('./agendaNumberedBlocks');
const {
  agendaNumberedTimelineChromeSpecs,
  agendaNumberedTimelineOverlayPlacements,
} = require('./agendaNumberedTimeline');

function numberedVariantFromSchema(schema) {
  const variant = schema?.preview?.agendaVariant
  if (variant === 'bold') return 'default'
  if (variant === 'timeline') return 'path'
  if (variant === 'cards' || variant === 'path') return variant
  return 'default'
}

function agendaNumberedChromeSpecs(variant = 'default', itemCount = 4) {
  if (variant === 'path') {
    return agendaNumberedTimelineChromeSpecs()
  }
  if (variant !== 'cards') {
    return agendaNumberedBlocksChromeSpecs()
  }
  const n = clampAgendaItemCount(itemCount)
  const { specs, pushIcon, pushCard, pushBadge } = createAgendaSpecBuilder()
  const cardH = 72
  const gap = 16
  const startY = 130
  for (let i = 0; i < n; i += 1) {
    const y = startY + i * (cardH + gap)
    pushCard(`AGENDA_CARD_${i + 1}`, 280, y, 640, cardH)
    pushBadge(`AGENDA_BADGE_${i + 1}`, 330, y + cardH / 2, 24, i + 1)
    pushIcon(`AGENDA_ICON_${i + 1}`, 400, y + cardH / 2, 18, i)
  }
  return specs
}

function agendaNumberedOverlayPlacements(gx, gy, gw, gh, variant = 'default', opts = {}) {
  if (variant === 'path') {
    return agendaNumberedTimelineOverlayPlacements(gx, gy, gw, gh)
  }
  if (variant !== 'cards') {
    return agendaNumberedBlocksOverlayPlacements(gx, gy, gw, gh)
  }
  const n = clampAgendaItemCount(opts.itemCount)
  const overlay = { items: [], columns: [], milestones: [], heading: null }
  overlay.heading = overlayBox(gx, gy, gw, gh, 200, 40, 600, 64)
  for (let i = 0; i < n; i += 1) {
    const y = variant === 'cards' ? 130 + i * 88 : 130 + i * 80
    overlay.items.push(overlayBox(gx, gy, gw, gh, 360, y, 560, variant === 'cards' ? 64 : 52))
  }
  return overlay
}

module.exports = {
  numberedVariantFromSchema,
  agendaNumberedChromeSpecs,
  agendaNumberedOverlayPlacements,
};
