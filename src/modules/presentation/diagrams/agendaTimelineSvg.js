/**
 * Agenda timeline family — SVG chrome, overlays (diagram-style module).
 */
const {
  AGENDA_GEOM,
  clampAgendaItemCount,
  createAgendaSpecBuilder,
  overlayBox,
} = require('./agendaSharedSvg');
function timelineVariantFromSchema(schema) {
  const variant = schema?.preview?.agendaVariant
  if (variant === 'vertical' || variant === 'curved' || variant === 'path') {
    return variant === 'path' ? 'curved' : variant
  }
  return 'default'
}

function agendaTimelineChromeSpecs(variant = 'default', itemCount = 4) {
  const n = clampAgendaItemCount(itemCount)
  const { specs, pushIcon, pushSpine, pushGraphic } = createAgendaSpecBuilder()

  if (variant === 'vertical') {
    const spineX = 500
    const startY = 100
    const step = 90
    pushSpine('AGENDA_SPINE', spineX - 1.5, startY, 3, (n - 1) * step, true)
    for (let i = 0; i < n; i += 1) {
      const cy = startY + i * step
      const side = i % 2 === 0 ? -1 : 1
      pushIcon(`AGENDA_NODE_${i + 1}`, spineX + side * 180, cy, 20, i)
    }
    return specs
  }
  if (variant === 'curved') {
    pushGraphic('AGENDA_CURVE', 80, 200, 840, 280, { curve: true })
    return specs
  }
  pushGraphic('AGENDA_TIMELINE', 48, 220, 904, 120, { timeline: n })
  return specs
}

function agendaTimelineOverlayPlacements(gx, gy, gw, gh, variant = 'default', opts = {}) {
  const n = clampAgendaItemCount(opts.itemCount)
  const overlay = { items: [], columns: [], milestones: [], heading: null }
  overlay.heading = overlayBox(gx, gy, gw, gh, 120, 40, 760, 56)
  const step = (AGENDA_GEOM.viewW - 160) / Math.max(1, n - 1)
  for (let i = 0; i < n; i += 1) {
    if (variant === 'vertical') {
      const cy = 100 + i * 90
      const side = i % 2 === 0 ? 1 : -1
      overlay.milestones.push(overlayBox(gx, gy, gw, gh, 500 + side * 120, cy - 16, 200, 40))
    } else {
      overlay.milestones.push(overlayBox(gx, gy, gw, gh, 80 + i * step, 360, step * 0.8, 48))
    }
  }
  return overlay
}

module.exports = {
  agendaTimelineChromeSpecs,
  agendaTimelineOverlayPlacements,
};
