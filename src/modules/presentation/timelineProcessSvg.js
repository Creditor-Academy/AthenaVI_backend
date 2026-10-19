/**
 * Shared SVG geometry for timeline + process layouts (mirrors diagram*Svg.js pattern).
 * Used by catalog previews and canvas graphic elements.
 */

const TIMELINE_GEOM = { viewW: 1000, viewH: 120, nodeR: 22, spineH: 5 }

const PROCESS_LINNER_GEOM = {
  viewW: 1000,
  viewH: 280,
  spineY: 36,
  nodeR: 14,
  phaseR: 52,
  connectorH: 28,
  anchorR: 7,
}

const PROCESS_NUMERIC_GEOM = {
  viewW: 1000,
  viewH: 200,
  slotH: 4,
  badgeR: 36,
}

const ROADMAP_GEOM = { viewW: 1000, viewH: 160, cardH: 100, nodeR: 18 }

function svgWrap(viewW, viewH, inner) {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${viewW} ${viewH}" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">${inner}</svg>`
}

/** Horizontal timeline spine + numbered nodes (preview + canvas). */
function horizontalTimelineInlineSvg(count = 4, { accent = '#6366f1', spine = '#1f2937', showChevrons = true } = {}) {
  const n = Math.max(2, Math.min(6, Number(count) || 4))
  const { viewW, viewH, nodeR, spineH } = TIMELINE_GEOM
  const pad = 48
  const usable = viewW - pad * 2
  const step = usable / (n - 1)
  const cy = viewH / 2
  const parts = [
    `<rect x="${pad}" y="${cy - spineH / 2}" width="${usable}" height="${spineH}" rx="${spineH / 2}" fill="${spine}" opacity="0.85"/>`,
  ]
  for (let i = 0; i < n; i += 1) {
    const cx = pad + i * step
    parts.push(`<circle cx="${cx}" cy="${cy}" r="${nodeR}" fill="${accent}"/>`)
    parts.push(
      `<text x="${cx}" y="${cy + 5}" text-anchor="middle" fill="#fff" font-size="16" font-weight="700" font-family="system-ui,sans-serif">${i + 1}</text>`
    )
    if (showChevrons && i < n - 1) {
      const ax = cx + nodeR + 8
      const bx = pad + (i + 1) * step - nodeR - 8
      if (bx > ax + 12) {
        const mx = (ax + bx) / 2
        parts.push(
          `<path d="M ${ax} ${cy} L ${bx - 8} ${cy} M ${bx - 14} ${cy - 6} L ${bx - 6} ${cy} L ${bx - 14} ${cy + 6}" fill="none" stroke="${spine}" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" opacity="0.55"/>`
        )
        void mx
      }
    }
  }
  return svgWrap(viewW, viewH, parts.join(''))
}

/** Vertical timeline spine + nodes. */
function verticalTimelineInlineSvg(count = 3, { accent = '#6366f1', spine = '#94a3b8' } = {}) {
  const n = Math.max(2, Math.min(5, Number(count) || 3))
  const viewW = 80
  const viewH = 320
  const padY = 24
  const spineX = 28
  const usable = viewH - padY * 2
  const step = usable / (n - 1)
  const parts = [
    `<rect x="${spineX - 1.5}" y="${padY}" width="3" height="${usable}" rx="1.5" fill="${spine}" opacity="0.7"/>`,
  ]
  for (let i = 0; i < n; i += 1) {
    const cy = padY + i * step
    parts.push(`<circle cx="${spineX}" cy="${cy}" r="18" fill="${accent}"/>`)
    parts.push(
      `<text x="${spineX}" y="${cy + 5}" text-anchor="middle" fill="#fff" font-size="13" font-weight="700" font-family="system-ui,sans-serif">${i + 1}</text>`
    )
  }
  return svgWrap(viewW, viewH, parts.join(''))
}

/** Process linner horizontal — spine, nodes, phase circles, connectors. */
function processLinnerHortiInlineSvg(count = 3, { accent = '#6366f1', phase = '#e8b4a0', spine = '#0f172a' } = {}) {
  const n = Math.max(2, Math.min(4, Number(count) || 3))
  const { viewW, viewH, spineY, nodeR, phaseR, connectorH, anchorR } = PROCESS_LINNER_GEOM
  const pad = 56
  const usable = viewW - pad * 2
  const step = usable / (n - 1)
  const parts = [
    `<rect x="${pad}" y="${spineY - 1}" width="${usable}" height="2" fill="${spine}" opacity="0.9"/>`,
  ]
  for (let i = 0; i < n; i += 1) {
    const cx = pad + i * step
    const phaseSize = i % 2 === 1 ? phaseR + 8 : phaseR
    const phaseY = spineY + nodeR + 18 + phaseSize / 2
    parts.push(`<circle cx="${cx}" cy="${spineY}" r="${nodeR}" fill="${spine}"/>`)
    parts.push(
      `<text x="${cx}" y="${spineY + 4}" text-anchor="middle" fill="#fff" font-size="11" font-weight="800" font-family="system-ui,sans-serif">${i + 1}</text>`
    )
    parts.push(`<circle cx="${cx}" cy="${phaseY}" r="${phaseSize}" fill="${phase}" opacity="0.85"/>`)
    parts.push(
      `<rect x="${cx - 1}" y="${phaseY + phaseSize / 2}" width="2" height="${connectorH}" fill="${spine}" opacity="0.75"/>`
    )
    parts.push(
      `<circle cx="${cx}" cy="${phaseY + phaseSize / 2 + connectorH + anchorR}" r="${anchorR}" fill="none" stroke="${spine}" stroke-width="2.5"/>`
    )
    void accent
  }
  return svgWrap(viewW, viewH, parts.join(''))
}

/** Process linner numeric — slot lines + colored badges. */
function processLinnerNumericInlineSvg(count = 3, { colors = ['#a3e635', '#5eead4', '#fb7185', '#d4a574'] } = {}) {
  const n = Math.max(2, Math.min(4, Number(count) || 3))
  const { viewW, viewH, slotH, badgeR } = PROCESS_NUMERIC_GEOM
  const pad = 48
  const usable = viewW - pad * 2
  const colW = usable / n
  const slotY = viewH * 0.38
  const parts = []
  for (let i = 0; i < n; i += 1) {
    const cx = pad + i * colW + colW / 2
    const color = colors[i % colors.length]
    const slotW = colW * 0.72
    parts.push(`<rect x="${cx - slotW / 2}" y="${slotY}" width="${slotW}" height="${slotH}" rx="2" fill="#0f172a" opacity="0.85"/>`)
    parts.push(`<rect x="${cx - slotW / 2 + 4}" y="${slotY + 6}" width="${slotW - 8}" height="6" rx="3" fill="rgba(15,23,42,0.12)"/>`)
    parts.push(`<circle cx="${cx}" cy="${slotY + badgeR + 24}" r="${badgeR}" fill="${color}" opacity="0.9"/>`)
    parts.push(
      `<text x="${cx}" y="${slotY + badgeR + 28}" text-anchor="middle" fill="#fff" font-size="14" font-weight="800" font-family="system-ui,sans-serif">${String(i + 1).padStart(2, '0')}</text>`
    )
  }
  return svgWrap(viewW, viewH, parts.join(''))
}

/** Roadmap — spine + milestone cards. */
function roadmapTimelineInlineSvg(count = 4, { accent = '#6366f1', card = '#f1f5f9', spine = '#94a3b8' } = {}) {
  const n = Math.max(2, Math.min(4, Number(count) || 4))
  const { viewW, viewH, cardH, nodeR } = ROADMAP_GEOM
  const pad = 40
  const usable = viewW - pad * 2
  const colW = usable / n
  const spineY = 28
  const parts = [
    `<rect x="${pad}" y="${spineY - 1}" width="${usable}" height="2" fill="${spine}" opacity="0.55"/>`,
  ]
  for (let i = 0; i < n; i += 1) {
    const cx = pad + i * colW + colW / 2
    const cardW = colW * 0.82
    parts.push(`<circle cx="${cx}" cy="${spineY}" r="${nodeR}" fill="${accent}"/>`)
    parts.push(
      `<text x="${cx}" y="${spineY + 4}" text-anchor="middle" fill="#fff" font-size="11" font-weight="800" font-family="system-ui,sans-serif">${i + 1}</text>`
    )
    parts.push(
      `<rect x="${cx - cardW / 2}" y="${spineY + nodeR + 6}" width="${cardW}" height="${cardH}" rx="8" fill="${card}" stroke="color-mix(in srgb, ${spine} 40%, transparent)" stroke-width="1"/>`
    )
  }
  return svgWrap(viewW, viewH, parts.join(''))
}

/** Milestones with image row + timeline below. */
function milestonesImageTimelineInlineSvg(count = 3, { accent = '#6366f1', image = '#e2e8f0', spine = '#1f2937' } = {}) {
  const n = Math.max(2, Math.min(4, Number(count) || 3))
  const viewW = 1000
  const viewH = 260
  const pad = 48
  const usable = viewW - pad * 2
  const colW = usable / n
  const imgH = 120
  const spineY = imgH + 48
  const parts = []
  for (let i = 0; i < n; i += 1) {
    const cx = pad + i * colW + colW / 2
    const imgW = colW * 0.82
    parts.push(
      `<rect x="${cx - imgW / 2}" y="8" width="${imgW}" height="${imgH}" rx="10" fill="${image}" stroke="#94a3b8" stroke-width="1"/>`
    )
    parts.push(`<circle cx="${cx}" cy="${spineY}" r="18" fill="${accent}"/>`)
    parts.push(
      `<text x="${cx}" y="${spineY + 5}" text-anchor="middle" fill="#fff" font-size="12" font-weight="700" font-family="system-ui,sans-serif">${i + 1}</text>`
    )
  }
  if (n > 1) {
    parts.unshift(
      `<rect x="${pad + colW / 2}" y="${spineY - 2.5}" width="${usable - colW}" height="5" rx="2.5" fill="${spine}" opacity="0.8"/>`
    )
  }
  return svgWrap(viewW, viewH, parts.join(''))
}

const TIMELINE_LAYOUT_META = {
  timeline_horizontal_v1: { family: 'horizontal', variant: 'default' },
  timeline_horizontal_nodes_v1: { family: 'horizontal', variant: 'nodes' },
  timeline_horizontal_cards_v1: { family: 'horizontal', variant: 'cards' },
  timeline_milestones_v1: { family: 'milestones', variant: 'default' },
  timeline_milestones_cards_v1: { family: 'milestones', variant: 'cards' },
  timeline_milestones_path_v1: { family: 'milestones', variant: 'path' },
  timeline_milestones_image_v1: { family: 'milestones_image', variant: 'default' },
  timeline_milestones_image_right_v1: { family: 'milestones_image', variant: 'image_right' },
  timeline_milestones_image_top_v1: { family: 'milestones_image', variant: 'image_top' },
  timeline_roadmap_v1: { family: 'roadmap', variant: 'default' },
  timeline_roadmap_horizontal_v1: { family: 'roadmap', variant: 'horizontal' },
  timeline_roadmap_lanes_v1: { family: 'roadmap', variant: 'lanes' },
  timeline_process_steps_v1: { family: 'process', variant: 'default' },
  timeline_process_horizontal_v1: { family: 'process', variant: 'horizontal' },
  timeline_process_vertical_v1: { family: 'process', variant: 'vertical' },
  timeline_vertical_v1: { family: 'vertical', variant: 'default' },
  timeline_vertical_nodes_v1: { family: 'vertical', variant: 'nodes' },
  timeline_vertical_cards_v1: { family: 'vertical', variant: 'cards' },
}

function resolveTimelineVariant(layoutId, preview = {}) {
  const id = String(layoutId || '').toLowerCase()
  if (TIMELINE_LAYOUT_META[id]) return TIMELINE_LAYOUT_META[id].variant
  return preview?.timelineVariant || 'default'
}

function resolveTimelineMeta(schema = {}) {
  const layoutId = schema?.layout_id || schema?.layoutId || schema?.id || ''
  const id = String(layoutId).toLowerCase()
  const fromMeta = TIMELINE_LAYOUT_META[id]
  if (fromMeta) return fromMeta
  const variant = schema?.preview?.timelineVariant || 'default'
  const mode = schema?.preview?.mode || ''
  const familyByMode = {
    timeline_horizontal: 'horizontal',
    timeline_milestones_image: 'milestones_image',
    timeline_roadmap: 'roadmap',
    timeline_process_steps: 'process',
    timeline_vertical: 'vertical',
  }
  return { family: familyByMode[mode] || 'horizontal', variant }
}

/** Canvas frame for horizontal timeline chrome graphic. */
function horizontalTimelineFrame(canvasW, canvasH, stepCount = 4) {
  const n = Math.max(2, stepCount)
  const insetX = 64
  const headingH = 88
  const insetY = 52
  const chromeH = 120
  const chromeY = insetY + headingH + 24
  const chromeW = canvasW - insetX * 2
  return { x: insetX, y: chromeY, width: chromeW, height: chromeH, n, insetX, insetY, headingH, nodeAreaY: chromeY + chromeH / 2 }
}

/** Single spine segment inline SVG for canvas graphic element. */
function timelineSpineSegmentInlineSvg() {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 10" preserveAspectRatio="none"><rect x="0" y="2.5" width="100" height="5" rx="2.5" fill="currentColor"/></svg>`
}

function timelineNodeInlineSvg() {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 48"><circle cx="24" cy="24" r="22" fill="currentColor"/></svg>`
}

function timelineChevronInlineSvg() {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 16"><path d="M2 8 H22 M16 3 L24 8 L16 13" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/></svg>`
}

function processPhaseCircleInlineSvg() {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 120 120"><circle cx="60" cy="60" r="54" fill="currentColor" opacity="0.85"/></svg>`
}

function processNumericBadgeInlineSvg() {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 72 72"><circle cx="36" cy="36" r="32" fill="currentColor"/></svg>`
}

module.exports = { TIMELINE_GEOM, PROCESS_LINNER_GEOM, PROCESS_NUMERIC_GEOM, ROADMAP_GEOM, TIMELINE_LAYOUT_META, resolveTimelineVariant, resolveTimelineMeta, horizontalTimelineInlineSvg, verticalTimelineInlineSvg, processLinnerHortiInlineSvg, processLinnerNumericInlineSvg, roadmapTimelineInlineSvg, milestonesImageTimelineInlineSvg, horizontalTimelineFrame, timelineSpineSegmentInlineSvg, timelineNodeInlineSvg, timelineChevronInlineSvg, processPhaseCircleInlineSvg, processNumericBadgeInlineSvg };
