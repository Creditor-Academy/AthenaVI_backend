/**
 * Agenda two-column family — SVG chrome, overlays (diagram-style module).
 */
const {
  createAgendaSpecBuilder,
  overlayBox,
} = require('./agendaSharedSvg');
function twoColVariantFromSchema(schema) {
  const variant = schema?.preview?.agendaVariant
  if (variant === 'split_panel' || variant === 'split_visual') return 'split_visual'
  if (variant === 'asymmetric') return 'asymmetric'
  return 'default'
}

function agendaTwoColumnChromeSpecs(variant = 'default') {
  const { specs, pushIcon, pushSpine, pushCard, pushBadge, pushDivider } = createAgendaSpecBuilder()

  if (variant === 'split_visual' || variant === 'split_panel') {
    pushCard('AGENDA_VISUAL_BLOCK', 48, 100, 420, 400)
    pushIcon('AGENDA_ICON_HERO', 260, 220, 36, 0)
    pushSpine('AGENDA_SPLIT_LINE', 498, 100, 4, 400, true)
    for (let i = 0; i < 4; i += 1) {
      const y = 140 + i * 80
      pushIcon(`AGENDA_ICON_${i + 1}`, 560, y, 18, i)
      pushDivider(`AGENDA_DIVIDER_${i + 1}`, 590, y, 330)
    }
    return specs
  }
  if (variant === 'asymmetric') {
    for (let i = 0; i < 4; i += 1) {
      const y = 160 + i * 85
      const x = 520 + (i % 2) * 60
      pushBadge(`AGENDA_BADGE_${i + 1}`, x, y, 20, i + 1)
      pushDivider(`AGENDA_DIVIDER_${i + 1}`, x + 30, y, 400)
    }
    return specs
  }
  pushSpine('AGENDA_SPLIT_LINE', 498, 100, 4, 400, true)
  pushCard('AGENDA_ZONE_LEFT', 60, 120, 380, 360)
  for (let i = 0; i < 4; i += 1) {
    const y = 150 + i * 75
    pushIcon(`AGENDA_ICON_${i + 1}`, 560, y, 16, i)
    pushDivider(`AGENDA_DIVIDER_${i + 1}`, 590, y, 310)
  }
  return specs
}

function agendaTwoColumnOverlayPlacements(gx, gy, gw, gh) {
  const overlay = { items: [], columns: [], milestones: [], heading: null }
  overlay.heading = overlayBox(gx, gy, gw, gh, 520, 80, 400, 64)
  for (let c = 0; c < 2; c += 1) {
    overlay.columns.push({
      heading: overlayBox(gx, gy, gw, gh, 520, 160 + c * 160, 380, 36),
      items: [overlayBox(gx, gy, gw, gh, 520, 200 + c * 160, 380, 100)],
    })
  }
  return overlay
}

module.exports = {
  agendaTwoColumnChromeSpecs,
  agendaTwoColumnOverlayPlacements,
};
