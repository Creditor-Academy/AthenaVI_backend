/**
 * Agenda timeline family — SVG chrome, overlays (diagram-style module).
 */
const {
  AGENDA_GEOM,
  clampAgendaItemCount,
  createAgendaSpecBuilder,
  overlayBox,
} = require('./agendaSharedSvg');
const {
  agendaTimelineHexChromeSpecs,
  agendaTimelineHexOverlayPlacements,
} = require('./agendaTimelineHex');
const {
  agendaVerticalRoadmapChromeSpecs,
  agendaVerticalRoadmapOverlayPlacements,
} = require('./agendaVerticalRoadmap');
function timelineVariantFromSchema(schema) {
  const variant = schema?.preview?.agendaVariant
  if (variant === 'vertical' || variant === 'curved' || variant === 'path') {
    return variant === 'path' ? 'curved' : variant
  }
  return 'default'
}

function agendaTimelineChromeSpecs(variant = 'default', itemCount = 4) {
  if (variant !== 'vertical' && variant !== 'curved' && variant !== 'path') {
    return agendaTimelineHexChromeSpecs()
  }
  const n = clampAgendaItemCount(itemCount)
  const { specs, pushIcon, pushSpine, pushGraphic } = createAgendaSpecBuilder()

  if (variant === 'vertical') {
    return agendaVerticalRoadmapChromeSpecs()
  }
  if (variant === 'curved') {
    pushGraphic('AGENDA_CURVE', 80, 200, 840, 280, { curve: true })
    return specs
  }
  pushGraphic('AGENDA_TIMELINE', 48, 220, 904, 120, { timeline: n })
  return specs
}

function agendaTimelineOverlayPlacements(gx, gy, gw, gh, variant = 'default', opts = {}) {
  if (variant !== 'vertical' && variant !== 'curved' && variant !== 'path') {
    return agendaTimelineHexOverlayPlacements(gx, gy, gw, gh)
  }
  if (variant === 'vertical') {
    return agendaVerticalRoadmapOverlayPlacements(gx, gy, gw, gh)
  }
  const n = clampAgendaItemCount(opts.itemCount)
  const overlay = { items: [], columns: [], milestones: [], heading: null }
  overlay.heading = overlayBox(gx, gy, gw, gh, 120, 40, 760, 56)
  const step = (AGENDA_GEOM.viewW - 160) / Math.max(1, n - 1)
  for (let i = 0; i < n; i += 1) {
    overlay.milestones.push(overlayBox(gx, gy, gw, gh, 80 + i * step, 360, step * 0.8, 48))
  }
  return overlay
}

module.exports = {
  agendaTimelineChromeSpecs,
  agendaTimelineOverlayPlacements,
};
