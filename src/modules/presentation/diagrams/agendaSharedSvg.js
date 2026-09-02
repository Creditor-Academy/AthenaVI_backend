/**
 * Shared agenda SVG primitives — geometry, layout meta, icons, chrome helpers.
 * Mirrors diagram shared patterns (per-family modules import from here).
 */

const AGENDA_ICON_KEYS = ['calendar', 'chart', 'user', 'target', 'lightbulb', 'flag']

const AGENDA_GEOM = {
  viewW: 1000,
  viewH: 560,
  headingH: 72,
  pad: 48,
  gutter: 16,
  iconR: 24,
  cardRadius: 12,
  spineW: 3,
}

const AGENDA_LAYOUT_META = {
  agenda_minimal_v1: { family: 'minimal', variant: 'default' },
  agenda_editorial_v1: { family: 'minimal', variant: 'editorial' },
  agenda_icon_list_v1: { family: 'minimal', variant: 'icon_list' },
  agenda_cards_v1: { family: 'minimal', variant: 'icon_list' },
  agenda_numbered_v1: { family: 'numbered', variant: 'default' },
  agenda_numbered_cards_v1: { family: 'numbered', variant: 'cards' },
  agenda_numbered_bold_v1: { family: 'numbered', variant: 'bold' },
  agenda_numbered_path_v1: { family: 'numbered', variant: 'path' },
  agenda_numbered_timeline_v1: { family: 'numbered', variant: 'path' },
  agenda_three_columns_hero_v1: { family: 'hero', variant: 'default' },
  agenda_three_panels_v1: { family: 'hero', variant: 'panels' },
  agenda_three_panel_hero_v1: { family: 'hero', variant: 'panels' },
  agenda_three_icons_v1: { family: 'three_col', variant: 'coloured' },
  agenda_three_cards_hero_v1: { family: 'hero', variant: 'cards' },
  agenda_three_columns_v1: { family: 'three_col', variant: 'default' },
  agenda_three_cards_v1: { family: 'three_col', variant: 'cards' },
  agenda_three_step_v1: { family: 'three_col', variant: 'step' },
  agenda_three_tiles_v1: { family: 'three_col', variant: 'step' },
  agenda_timeline_preview_v1: { family: 'timeline', variant: 'default' },
  agenda_vertical_roadmap_v1: { family: 'timeline', variant: 'vertical' },
  agenda_curved_timeline_v1: { family: 'timeline', variant: 'curved' },
  agenda_progress_path_v1: { family: 'timeline', variant: 'curved' },
  agenda_two_column_v1: { family: 'two_col', variant: 'default' },
  agenda_split_visual_v1: { family: 'two_col', variant: 'split_visual' },
  agenda_split_panel_v1: { family: 'two_col', variant: 'split_visual' },
  agenda_asymmetric_v1: { family: 'two_col', variant: 'asymmetric' },
}

const FAMILY_LAYOUT_IDS = {
  minimal: ['agenda_minimal_v1', 'agenda_editorial_v1', 'agenda_cards_v1', 'agenda_icon_list_v1'],
  numbered: ['agenda_numbered_v1', 'agenda_numbered_bold_v1', 'agenda_numbered_timeline_v1', 'agenda_numbered_cards_v1', 'agenda_numbered_path_v1'],
  hero: ['agenda_three_columns_hero_v1', 'agenda_three_cards_hero_v1', 'agenda_three_panel_hero_v1', 'agenda_three_panels_v1'],
  three_col: ['agenda_three_columns_v1', 'agenda_three_cards_v1', 'agenda_three_tiles_v1', 'agenda_three_icons_v1', 'agenda_three_step_v1'],
  timeline: ['agenda_timeline_preview_v1', 'agenda_vertical_roadmap_v1', 'agenda_progress_path_v1', 'agenda_curved_timeline_v1'],
  two_col: ['agenda_two_column_v1', 'agenda_split_panel_v1', 'agenda_asymmetric_v1', 'agenda_split_visual_v1'],
}

function isAgendaInfographicLayout(layoutId) {
  return /^agenda_/i.test(String(layoutId || ''))
}

function isAgendaFamilyLayout(layoutId, family) {
  const id = String(layoutId || '').toLowerCase()
  return (FAMILY_LAYOUT_IDS[family] || []).includes(id)
}

function isAgendaMinimalLayout(layoutId) {
  return isAgendaFamilyLayout(layoutId, 'minimal')
}

function isAgendaNumberedLayout(layoutId) {
  return isAgendaFamilyLayout(layoutId, 'numbered')
}

function isAgendaHeroLayout(layoutId) {
  return isAgendaFamilyLayout(layoutId, 'hero')
}

function isAgendaThreeColumnLayout(layoutId) {
  return isAgendaFamilyLayout(layoutId, 'three_col')
}

function isAgendaTimelineLayout(layoutId) {
  return isAgendaFamilyLayout(layoutId, 'timeline')
}

function isAgendaTwoColumnLayout(layoutId) {
  return isAgendaFamilyLayout(layoutId, 'two_col')
}

function resolveAgendaMeta(schema) {
  const layoutId = String(schema?.layout_id || schema?.id || schema?.layoutId || '')
  const mapped = AGENDA_LAYOUT_META[layoutId]
  if (mapped) return { ...mapped }
  const variant = schema?.preview?.agendaVariant || 'default'
  const mode = schema?.preview?.mode || ''
  const familyByMode = {
    agenda_minimal: 'minimal',
    agenda_numbered: 'numbered',
    agenda_three_columns: 'three_col',
    agenda_three_columns_hero: 'hero',
    process_flow: 'timeline',
    agenda_two_columns: 'two_col',
  }
  return { family: familyByMode[mode] || 'minimal', variant }
}

function agendaGraphicFrame(canvasW, canvasH) {
  const headingY = 52
  const headingH = AGENDA_GEOM.headingH
  const graphicY = headingY + headingH + 24
  const graphicH = Math.min(AGENDA_GEOM.viewH, canvasH - graphicY - 48)
  const graphicW = Math.round(graphicH * (AGENDA_GEOM.viewW / AGENDA_GEOM.viewH))
  const graphicX = Math.round((canvasW - graphicW) / 2)
  return { graphicX, graphicY, graphicW, graphicH, headingY, headingH }
}

function scaleBox(gx, gy, gw, gh, box) {
  const sx = gw / AGENDA_GEOM.viewW
  const sy = gh / AGENDA_GEOM.viewH
  return {
    x: Math.round(gx + box.x * sx),
    y: Math.round(gy + box.y * sy),
    width: Math.max(4, Math.round(box.w * sx)),
    height: Math.max(4, Math.round(box.h * sy)),
    borderRadius: box.borderRadius != null ? Math.round(box.borderRadius * Math.min(sx, sy)) : undefined,
  }
}

function iconPath(key, cx, cy, size) {
  const s = size * 0.38
  const paths = {
    calendar: `M ${cx - s} ${cy - s * 0.3} h ${s * 2} v ${s * 1.4} h ${-s * 2} z M ${cx - s * 0.6} ${cy - s * 0.7} v ${s * 0.5} M ${cx + s * 0.6} ${cy - s * 0.7} v ${s * 0.5}`,
    chart: `M ${cx - s} ${cy + s} V ${cy - s * 0.2} M ${cx} ${cy + s} V ${cy - s * 0.8} M ${cx + s} ${cy + s} V ${cy}`,
    user: `M ${cx} ${cy - s * 0.5} a ${s * 0.45} ${s * 0.45} 0 1 1 0 ${s * 0.9} a ${s * 0.45} ${s * 0.45} 0 1 1 0 ${-s * 0.9} M ${cx - s * 0.7} ${cy + s * 0.9} q ${s * 0.7} ${-s * 0.5} ${s * 1.4} 0`,
    target: `M ${cx} ${cy} m ${-s} 0 a ${s} ${s} 0 1 0 ${s * 2} 0 a ${s} ${s} 0 1 0 ${-s * 2} 0 M ${cx} ${cy} m ${-s * 0.45} 0 a ${s * 0.45} ${s * 0.45} 0 1 0 ${s * 0.9} 0 a ${s * 0.45} ${s * 0.45} 0 1 0 ${-s * 0.9} 0`,
    lightbulb: `M ${cx} ${cy - s * 0.8} q ${s * 0.9} ${s * 0.5} ${s * 0.9} ${s * 1.1} q 0 ${s * 0.6} ${-s * 0.5} ${s * 0.9} h ${-s * 0.8} q ${-s * 0.5} ${-s * 0.3} ${-s * 0.5} ${-s * 0.9} q 0 ${-s * 0.6} ${s * 0.9} ${-s * 1.1}`,
    flag: `M ${cx - s * 0.7} ${cy - s} v ${s * 2} M ${cx - s * 0.7} ${cy - s} h ${s * 1.2} l ${-s * 0.35} ${s * 0.45} l ${s * 0.35} ${s * 0.45} z`,
  }
  return paths[key] || paths.calendar
}

function agendaIconInlineSvg(iconIndex = 0) {
  const key = AGENDA_ICON_KEYS[iconIndex % AGENDA_ICON_KEYS.length]
  const cx = 24
  const cy = 24
  const r = 20
  const d = iconPath(key, cx, cy, r)
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 48" width="100%" height="100%" preserveAspectRatio="xMidYMid meet"><circle cx="${cx}" cy="${cy}" r="${r}" fill="currentColor" opacity="0.12"/><circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="currentColor" stroke-width="2"/><path d="${d}" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/></svg>`
}

function agendaSpineInlineSvg(vertical = true) {
  if (vertical) {
    return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 6 100" width="100%" height="100%" preserveAspectRatio="none"><rect x="1.5" y="0" width="3" height="100" rx="1.5" fill="currentColor"/></svg>'
  }
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 6" width="100%" height="100%" preserveAspectRatio="none"><rect x="0" y="1.5" width="100" height="3" rx="1.5" fill="currentColor"/></svg>'
}

function agendaBadgeInlineSvg(label = '01') {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 56 56" width="100%" height="100%" preserveAspectRatio="xMidYMid meet"><circle cx="28" cy="28" r="26" fill="currentColor"/><text x="28" y="33" text-anchor="middle" fill="#fff" font-size="14" font-weight="800" font-family="system-ui,sans-serif">${label}</text></svg>`
}

function agendaArrowInlineSvg() {
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 16" width="100%" height="100%" preserveAspectRatio="none"><path d="M2 8 H46 M40 3 L50 8 L40 13" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/></svg>'
}

function agendaDividerInlineSvg() {
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 4" width="100%" height="100%" preserveAspectRatio="none"><rect x="0" y="1.5" width="100" height="1" fill="currentColor" opacity="0.35"/></svg>'
}

/** Chrome spec builder — same pattern as diagram family modules. */
function createAgendaSpecBuilder() {
  const specs = []
  return {
    specs,
    pushIcon(slotId, cx, cy, r, iconIndex) {
      specs.push({ slotId, kind: 'graphic', x: cx - r, y: cy - r, w: r * 2, h: r * 2, iconIndex, layer: 4 })
    },
    pushSpine(slotId, x, y, w, h, vertical = true) {
      specs.push({ slotId, kind: 'graphic', x, y, w, h, spine: vertical ? 'v' : 'h', layer: 2 })
    },
    pushCard(slotId, x, y, w, h) {
      specs.push({ slotId, kind: 'shape', x, y, w, h, borderRadius: AGENDA_GEOM.cardRadius, layer: 3 })
    },
    pushBadge(slotId, cx, cy, r, num) {
      specs.push({
        slotId,
        kind: 'graphic',
        x: cx - r,
        y: cy - r,
        w: r * 2,
        h: r * 2,
        badge: String(num).padStart(2, '0'),
        layer: 5,
      })
    },
    pushDivider(slotId, x, y, w) {
      specs.push({ slotId, kind: 'graphic', x, y, w, h: 4, divider: true, layer: 2 })
    },
    pushArrow(slotId, x, y, w) {
      specs.push({ slotId, kind: 'graphic', x, y, w, h: 16, arrow: true, layer: 3 })
    },
    pushGraphic(slotId, x, y, w, h, extra = {}) {
      specs.push({ slotId, kind: 'graphic', x, y, w, h, layer: 2, ...extra })
    },
  }
}

function clampAgendaItemCount(itemCount = 4) {
  return Math.min(6, Math.max(2, itemCount || 4))
}

function overlayBox(gx, gy, gw, gh, x, y, w, h) {
  const sx = gw / AGENDA_GEOM.viewW
  const sy = gh / AGENDA_GEOM.viewH
  return {
    x: Math.round(gx + x * sx),
    y: Math.round(gy + y * sy),
    width: Math.max(24, Math.round(w * sx)),
    height: Math.max(20, Math.round(h * sy)),
  }
}

module.exports = {
  AGENDA_ICON_KEYS,
  AGENDA_GEOM,
  AGENDA_LAYOUT_META,
  isAgendaInfographicLayout,
  isAgendaFamilyLayout,
  isAgendaMinimalLayout,
  isAgendaNumberedLayout,
  isAgendaHeroLayout,
  isAgendaThreeColumnLayout,
  isAgendaTimelineLayout,
  isAgendaTwoColumnLayout,
  resolveAgendaMeta,
  agendaGraphicFrame,
  scaleBox,
  iconPath,
  agendaIconInlineSvg,
  agendaSpineInlineSvg,
  agendaBadgeInlineSvg,
  agendaArrowInlineSvg,
  agendaDividerInlineSvg,
  createAgendaSpecBuilder,
  clampAgendaItemCount,
  overlayBox,
};
