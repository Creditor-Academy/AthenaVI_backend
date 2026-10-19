/**
 * Agenda numbered (default) — 2x3 parallelograms, dashed stroke, overlapping numbers.
 */

const AGENDA_NUMBERED_BLOCKS_GEOM = {
  viewW: 1000,
  viewH: 560,
  headingY: 18,
  headingH: 44,
  padX: 48,
  padTop: 112,
  padBottom: 20,
  gapX: 18,
  gapY: 22,
  skew: 30,
  cols: 3,
  rows: 2,
}

const NUMBERED_BLOCK_PALETTE = [
  { main: '#2F9E6B', fill: '#E5F6EC' },
  { main: '#E94B8C', fill: '#FCE8F1' },
  { main: '#7A5C9E', fill: '#EDE6F6' },
  { main: '#5C4E9A', fill: '#E8E4F6' },
  { main: '#3B8FD9', fill: '#E2F0FB' },
  { main: '#D94A8A', fill: '#F9E4EE' },
]

function cellRects() {
  const { viewW, viewH, padX, padTop, padBottom, gapX, gapY, cols, rows } = AGENDA_NUMBERED_BLOCKS_GEOM
  const cellW = (viewW - padX * 2 - gapX * (cols - 1)) / cols
  const cellH = (viewH - padTop - padBottom - gapY * (rows - 1)) / rows
  return Array.from({ length: cols * rows }, (_, i) => {
    const col = i % cols
    const row = Math.floor(i / cols)
    const x = padX + col * (cellW + gapX)
    const y = padTop + row * (cellH + gapY)
    return { x, y, w: cellW, h: cellH, i }
  })
}

function cellMetrics(w, h, skew) {
  const pad = 10
  const titleX = pad + Math.max(skew, 56)
  const titleY = pad + 10
  const titleH = 26
  const titleW = Math.max(40, w - titleX - pad - 12)
  const bodyY = titleY + titleH + 6
  const bodyH = Math.max(36, h - bodyY - pad - 8)
  const bodyW = titleW
  return { pad, titleX, titleY, titleH, titleW, bodyY, bodyH, bodyW }
}

function agendaNumberedBlocksGraphicFrame(canvasW, canvasH) {
  return {
    graphicX: 0,
    graphicY: 0,
    graphicW: canvasW,
    graphicH: canvasH,
    headingY: Math.round(canvasH * 0.03),
    headingH: Math.round(canvasH * 0.078),
  }
}

function agendaNumberedBlockInlineSvg(spec) {
  const w = spec.w
  const h = spec.h
  const color = spec.color
  const fill = spec.fill || color
  const skew = spec.skew || AGENDA_NUMBERED_BLOCKS_GEOM.skew
  const n = spec.n || 1
  const uid = String(spec.slotId || 'n').replace(/[^a-z0-9]/gi, '')
  const pad = 10
  const tlx = pad + skew
  const tly = pad
  const trx = w - pad
  const brx = w - pad - skew
  const bry = h - pad
  const blx = pad
  const d = `M ${tlx} ${tly} L ${trx} ${tly} L ${brx} ${bry} L ${blx} ${bry} Z`
  const m = cellMetrics(w, h, skew)
  const numSize = Math.round(h * 0.46)
  const numX = pad + 4
  const numY = h - 11
  const label = spec.label || `Agenda ${String(n).padStart(2, '0')}`
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="100%" height="100%" preserveAspectRatio="none">
    <defs>
      <filter id="ns-${uid}" x="-20%" y="-20%" width="140%" height="140%">
        <feDropShadow dx="1.2" dy="2.2" stdDeviation="1.4" flood-color="${color}" flood-opacity="0.32"/>
      </filter>
    </defs>
    <path d="${d}" fill="${fill}" stroke="${color}" stroke-width="1.7" stroke-dasharray="5.5 4.2" stroke-linejoin="round"/>
    <text x="${numX}" y="${numY}" fill="${color}" stroke="none" font-size="${numSize}" font-weight="800" font-family="Arial,Helvetica,sans-serif" filter="url(#ns-${uid})">${n}</text>
    <text x="${m.titleX}" y="${m.titleY + m.titleH * 0.78}" fill="${color}" stroke="none" font-size="${Math.round(m.titleH * 0.62)}" font-weight="800" font-family="Arial,Helvetica,sans-serif">${escapeXml(label)}</text>
  </svg>`
}

function escapeXml(value) {
  return String(value || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
}

function agendaNumberedBlocksChromeSpecs() {
  const { skew } = AGENDA_NUMBERED_BLOCKS_GEOM
  return cellRects().map((cell) => {
    const pal = NUMBERED_BLOCK_PALETTE[cell.i]
    return {
      slotId: `AGENDA_NUM_CHROME_${cell.i + 1}`,
      kind: 'graphic',
      blockChrome: true,
      x: cell.x,
      y: cell.y,
      w: cell.w,
      h: cell.h,
      color: pal.main,
      fill: pal.fill,
      n: cell.i + 1,
      skew,
      label: `Agenda ${String(cell.i + 1).padStart(2, '0')}`,
      layer: 4,
    }
  })
}

function agendaNumberedBlocksOverlayPlacements(gx, gy, gw, gh) {
  const { viewW, viewH, headingY, headingH, skew } = AGENDA_NUMBERED_BLOCKS_GEOM
  const sx = gw / viewW
  const sy = gh / viewH
  const box = (x, y, w, h) => ({
    x: Math.round(gx + x * sx),
    y: Math.round(gy + y * sy),
    width: Math.max(24, Math.round(w * sx)),
    height: Math.max(18, Math.round(h * sy)),
  })
  const overlay = {
    heading: box(80, headingY, viewW - 160, headingH),
    items: [],
  }
  for (const cell of cellRects()) {
    const m = cellMetrics(cell.w, cell.h, skew)
    overlay.items.push(box(cell.x + m.titleX, cell.y + m.bodyY, m.bodyW, m.bodyH))
  }
  return overlay
}

function buildPreviewSvg() {
  const specs = agendaNumberedBlocksChromeSpecs()
  const { viewW, viewH } = AGENDA_NUMBERED_BLOCKS_GEOM
  const parts = specs.map((spec) => {
    const inner = agendaNumberedBlockInlineSvg(spec)
    const match = inner.match(/<svg[^>]*>([\s\S]*)<\/svg>/i)
    return `<g transform="translate(${spec.x},${spec.y})">${match ? match[1] : ''}</g>`
  })
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${viewW} ${viewH}">${parts.join('')}</svg>`
}

function agendaNumberedBlocksPreviewSvg() {
  return buildPreviewSvg().replace(/<svg\b([^>]*)>/i, (match, attrs) => {
    let next = attrs
    if (!/\bwidth\s*=/i.test(next)) next += ' width="100%"'
    if (!/\bheight\s*=/i.test(next)) next += ' height="100%"'
    if (!/\bpreserveAspectRatio\s*=/i.test(next)) next += ' preserveAspectRatio="xMidYMid meet"'
    return `<svg${next}>`
  })
}

function specToNumberedBlocksContent(spec) {
  return { svg: agendaNumberedBlockInlineSvg(spec), colorMode: 'original', fill: spec.color }
}

function isAgendaNumberedBlocksLayout(layoutId, family, variant) {
  if (family === 'numbered' && variant !== 'cards' && variant !== 'path' && variant !== 'timeline') return true
  return /agenda_numbered_v1$/i.test(String(layoutId || ''))
}

function isAgendaNumberedBlocksTextSlot(slotId) {
  const sid = String(slotId || '').toUpperCase()
  return sid === 'HEADING' || sid === 'BODY' || /^ITEM_\d+$/.test(sid)
}

module.exports = { AGENDA_NUMBERED_BLOCKS_GEOM, NUMBERED_BLOCK_PALETTE, agendaNumberedBlocksGraphicFrame, agendaNumberedBlockInlineSvg, agendaNumberedBlocksChromeSpecs, agendaNumberedBlocksOverlayPlacements, agendaNumberedBlocksPreviewSvg, specToNumberedBlocksContent, isAgendaNumberedBlocksLayout, isAgendaNumberedBlocksTextSlot };
