/**
 * Agenda hero + three-column families — SVG chrome, overlays (diagram-style module).
 */
const {
  AGENDA_GEOM,
  createAgendaSpecBuilder,
  overlayBox,
} = require('./agendaSharedSvg');
const {
  agendaThreeColumnChromeSpecs,
  agendaThreeColumnOverlayPlacements,
} = require('./agendaThreeColumn');
const {
  agendaThreeCardsChromeSpecs,
  agendaThreeCardsOverlayPlacements,
} = require('./agendaThreeCards');
const {
  agendaHeroCardsChromeSpecs,
  agendaHeroCardsOverlayPlacements,
} = require('./agendaHeroCards');
function columnsVariantFromSchema(schema) {
  const variant = schema?.preview?.agendaVariant
  if (variant === 'panels' || variant === 'cards' || variant === 'step' || variant === 'coloured') return variant
  if (variant === 'tiles') return 'step'
  return 'default'
}

function agendaColumnsChromeSpecs(family, variant = 'default') {
  if (family === 'hero' && variant === 'cards') {
    return agendaThreeCardsChromeSpecs({ hero: true })
  }
  if (family === 'hero' && variant !== 'panels') {
    return agendaHeroCardsChromeSpecs()
  }
  if (family === 'three_col' && variant === 'cards') {
    return agendaThreeCardsChromeSpecs()
  }
  if (family === 'three_col' && variant !== 'panels' && variant !== 'step') {
    return agendaThreeColumnChromeSpecs()
  }
  const { specs, pushIcon, pushCard, pushBadge, pushArrow } = createAgendaSpecBuilder()
  const colW = (AGENDA_GEOM.viewW - 120) / 3

  if (variant === 'panels') {
    for (let i = 0; i < 3; i += 1) {
      const x = 60 + i * colW
      pushCard(`AGENDA_PANEL_${i + 1}`, x + 8, 100, colW - 16, 400)
      pushIcon(`AGENDA_ICON_${i + 1}`, x + colW / 2, 180, 36, i)
    }
    return specs
  }
  if (variant === 'step') {
    const centers = [180, 500, 820]
    for (let i = 0; i < 3; i += 1) {
      pushIcon(`AGENDA_ICON_${i + 1}`, centers[i], 220, 48, i)
      if (i < 2) pushArrow(`AGENDA_ARROW_${i + 1}`, centers[i] + 56, 212, centers[i + 1] - centers[i] - 112)
    }
    return specs
  }
  if (variant === 'cards') {
    for (let i = 0; i < 3; i += 1) {
      const x = 50 + i * colW
      pushCard(`AGENDA_CARD_${i + 1}`, x + 12, 140, colW - 24, 340)
      pushBadge(`AGENDA_BADGE_${i + 1}`, x + 52, 200, 22, i + 1)
      pushIcon(`AGENDA_ICON_${i + 1}`, x + colW / 2, 260, 28, i)
    }
    return specs
  }
  for (let i = 0; i < 3; i += 1) {
    const x = 60 + i * colW
    pushCard(`AGENDA_ZONE_${i + 1}`, x + 16, 120, colW - 32, 160)
    pushIcon(`AGENDA_ICON_${i + 1}`, x + colW / 2, 200, 32, i)
  }
  return specs
}

function agendaColumnsOverlayPlacements(gx, gy, gw, gh, family, variant = 'default') {
  if (family === 'hero' && variant === 'cards') {
    return agendaThreeCardsOverlayPlacements(gx, gy, gw, gh, { hero: true })
  }
  if (family === 'hero' && variant !== 'panels') {
    return agendaHeroCardsOverlayPlacements(gx, gy, gw, gh)
  }
  if (family === 'three_col' && variant === 'cards') {
    return agendaThreeCardsOverlayPlacements(gx, gy, gw, gh)
  }
  if (family === 'three_col' && variant !== 'panels' && variant !== 'step') {
    return agendaThreeColumnOverlayPlacements(gx, gy, gw, gh)
  }
  const overlay = { items: [], columns: [], milestones: [], heading: null }
  overlay.heading = overlayBox(gx, gy, gw, gh, 120, 40, 760, 56)
  const colW = (AGENDA_GEOM.viewW - 120) / 3
  for (let i = 0; i < 3; i += 1) {
    const x = 60 + i * colW
    overlay.columns.push({
      heading: overlayBox(gx, gy, gw, gh, x + 16, 300, colW - 32, 40),
      items: [overlayBox(gx, gy, gw, gh, x + 24, 350, colW - 48, 80)],
    })
  }
  return overlay
}

module.exports = {
  agendaColumnsChromeSpecs,
  agendaColumnsOverlayPlacements,
};
