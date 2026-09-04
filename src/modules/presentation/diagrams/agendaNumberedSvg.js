/**
 * Agenda numbered family — SVG chrome, overlays, preview (diagram-style module).
 */
const {
  AGENDA_GEOM,
  clampAgendaItemCount,
  createAgendaSpecBuilder,
  overlayBox,
} = require('./agendaSharedSvg');
const {
  agendaNumberedBlocksChromeSpecs,
  agendaNumberedBlocksOverlayPlacements,
} = require('./agendaNumberedBlocks');
function numberedVariantFromSchema(schema) {
  const variant = schema?.preview?.agendaVariant
  if (variant === 'bold') return 'default'
  if (variant === 'timeline') return 'path'
  if (variant === 'cards' || variant === 'path') return variant
  return 'default'
}

function agendaNumberedChromeSpecs(variant = 'default', itemCount = 4) {
  if (variant !== 'cards' && variant !== 'path') {
    return agendaNumberedBlocksChromeSpecs()
  }
  const n = clampAgendaItemCount(itemCount)
  const { specs, pushIcon, pushSpine, pushCard, pushBadge, pushDivider } = createAgendaSpecBuilder()

  if (variant === 'cards') {
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
  if (variant === 'path') {
    const pad = 120
    const step = (AGENDA_GEOM.viewW - pad * 2) / (n - 1)
    const pathY = 320
    pushSpine('AGENDA_PATH', pad, pathY - 1.5, AGENDA_GEOM.viewW - pad * 2, 3, false)
    for (let i = 0; i < n; i += 1) {
      const cx = pad + i * step
      pushBadge(`AGENDA_BADGE_${i + 1}`, cx, pathY, 28, i + 1)
    }
    return specs
  }
  const spineX = 300
  pushSpine('AGENDA_SPINE', spineX - 1.5, 120, 3, (n - 1) * 80 + 20, true)
  for (let i = 0; i < n; i += 1) {
    const y = 140 + i * 80
    pushBadge(`AGENDA_BADGE_${i + 1}`, spineX, y, 10, i + 1)
    pushDivider(`AGENDA_DIVIDER_${i + 1}`, spineX + 24, y, 576)
  }
  return specs
}

function agendaNumberedOverlayPlacements(gx, gy, gw, gh, variant = 'default', opts = {}) {
  if (variant !== 'cards' && variant !== 'path') {
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
  agendaNumberedChromeSpecs,
  agendaNumberedOverlayPlacements,
};
