/**
 * Agenda minimal family — SVG chrome, overlays, preview (diagram-style module).
 */
const {
  AGENDA_GEOM,
  clampAgendaItemCount,
  createAgendaSpecBuilder,
  overlayBox,
} = require('./agendaSharedSvg');
const {
  agendaMinimalQuietChromeSpecs,
  agendaMinimalQuietOverlayPlacements,
} = require('./agendaMinimalQuiet');
const {
  agendaEditorialChromeSpecs,
  agendaEditorialOverlayPlacements,
} = require('./agendaEditorialHub');
function minimalVariantFromSchema(schema) {
  const variant = schema?.preview?.agendaVariant
  if (variant === 'editorial' || variant === 'icon_list' || variant === 'cards') return variant === 'cards' ? 'icon_list' : variant
  return 'default'
}

function agendaMinimalChromeSpecs(variant = 'default', itemCount = 4) {
  if (variant === 'editorial') {
    return agendaEditorialChromeSpecs()
  }
  if (variant !== 'editorial' && variant !== 'icon_list' && variant !== 'cards') {
    return agendaMinimalQuietChromeSpecs()
  }
  const n = clampAgendaItemCount(itemCount)
  const { specs, pushIcon, pushSpine, pushCard, pushDivider } = createAgendaSpecBuilder()

  if (variant === 'icon_list' || variant === 'cards') {
    const spineX = 680
    const startY = 130
    const step = 88
    pushSpine('AGENDA_SPINE', spineX - 1.5, startY - 20, 3, (n - 1) * step + 40, true)
    for (let i = 0; i < n; i += 1) {
      const cy = startY + i * step
      pushIcon(`AGENDA_ICON_${i + 1}`, spineX, cy, 24, i)
      pushDivider(`AGENDA_DIVIDER_${i + 1}`, spineX + 36, cy - 2, 260)
    }
    pushCard('AGENDA_TITLE_BLOCK', 48, 100, 200, 120)
    return specs
  }
  pushCard('AGENDA_TITLE_BLOCK', 48, 100, 280, 360)
  for (let i = 0; i < n; i += 1) {
    const y = 140 + i * 72
    pushIcon(`AGENDA_ICON_${i + 1}`, 420, y - 8, 14, i)
    pushDivider(`AGENDA_DIVIDER_${i + 1}`, 400, y, 520)
  }
  return specs
}

function agendaMinimalOverlayPlacements(gx, gy, gw, gh, variant = 'default', opts = {}) {
  if (variant === 'editorial') {
    return agendaEditorialOverlayPlacements(gx, gy, gw, gh)
  }
  if (variant !== 'editorial' && variant !== 'icon_list' && variant !== 'cards') {
    return agendaMinimalQuietOverlayPlacements(gx, gy, gw, gh)
  }
  const n = clampAgendaItemCount(opts.itemCount)
  const overlay = { items: [], columns: [], milestones: [], heading: null }
  overlay.heading = overlayBox(gx, gy, gw, gh, 48, 80, 280, 80)
  const listX = variant === 'icon_list' || variant === 'cards' ? 720 : 400
  for (let i = 0; i < n; i += 1) {
    overlay.items.push(overlayBox(gx, gy, gw, gh, listX, 120 + i * 72, 260, 48))
  }
  return overlay
}

module.exports = {
  agendaMinimalChromeSpecs,
  agendaMinimalOverlayPlacements,
};
