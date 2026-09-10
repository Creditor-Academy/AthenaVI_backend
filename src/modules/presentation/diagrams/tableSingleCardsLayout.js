/**
 * Table Single Cards — Investment Report Table (Backend)
 * Layout ID: table_single_cards_v1
 * Features:
 *  - Centered title + subtitle with decorative 3-tone accent pill
 *  - 7 columns with gradient header cards (Teal to Midnight Navy) with top rounded corners
 *  - 4 body rows with card-like cells and alternating/highlight column fills
 *  - Bottom solid Navy "TOTAL" summary row with bold white values and bottom rounded corners
 */

const TABLE_SINGLE_CARDS_GEOM = {
  viewW: 1000,
  viewH: 560,
  headingX: 40,
  headingY: 16,
  headingW: 920,
  headingH: 34,
  subtitleX: 40,
  subtitleY: 52,
  subtitleW: 920,
  subtitleH: 20,

  pillX: 445,
  pillY: 76,
  pillW: 110,
  pillH: 6,

  tableX: 40,
  tableY: 96,
  tableW: 920,
  tableH: 428,

  headerH: 54,
  bodyRowH: 66,
  totalRowH: 54,
  gap: 4,

  cols: 7,
  bodyRows: 4,

  labelW: 176,
  dataColW: 120,
}

const TABLE_SINGLE_CARDS_PALETTE = {
  headers: [
    '#43B5C0',
    '#008CA8',
    '#0073A8',
    '#1C5685',
    '#124372',
    '#06255B',
    '#104F8A',
  ],
  col0Body: '#EEF2F6',
  cellNormal: '#F8FAFC',
  cellHighlight: '#CBD5E1',
  totalCol0: '#0F4C81',
  totalCols: '#14558F',
  textDark: '#1E293B',
  textMuted: '#64748B',
  white: '#FFFFFF',
}

const TABLE_SINGLE_CARDS_DEFAULTS = {
  HEADING: 'Investment Report',
  SUBTITLE: 'This is the sample dummy text insert your desired text here because this is the dummy text.',

  COL_0_HEADER: 'COLUMN 0',
  COL_1_HEADER: 'COLUMN 1',
  COL_2_HEADER: 'COLUMN 2',
  COL_3_HEADER: 'COLUMN 3',
  COL_4_HEADER: 'COLUMN 4',
  COL_5_HEADER: 'COLUMN 5',
  COL_6_HEADER: 'COLUMN 6',

  ROW_1_LABEL: 'This is the sample',
  ROW_2_LABEL: 'dummy text insert your',
  ROW_3_LABEL: 'desired text here because',
  ROW_4_LABEL: 'this is the dummy text.',

  CELL_1_1: '$100.0',
  CELL_1_2: '$100.0',
  CELL_1_3: '$100.0',
  CELL_1_4: '$100.0',
  CELL_1_5: '$100.0',
  CELL_1_6: '$100.0',

  CELL_2_1: '$100.0',
  CELL_2_2: '$100.0',
  CELL_2_3: '$100.0',
  CELL_2_4: '$100.0',
  CELL_2_5: '$100.0',
  CELL_2_6: '$100.0',

  CELL_3_1: '$100.0',
  CELL_3_2: '$100.0',
  CELL_3_3: '$100.0',
  CELL_3_4: '$100.0',
  CELL_3_5: '$100.0',
  CELL_3_6: '$100.0',

  CELL_4_1: '$100.0',
  CELL_4_2: '$100.0',
  CELL_4_3: '$100.0',
  CELL_4_4: '$100.0',
  CELL_4_5: '$100.0',
  CELL_4_6: '$100.0',

  TOTAL_LABEL: 'TOTAL',
  TOTAL_1: '$100.0',
  TOTAL_2: '$100.0',
  TOTAL_3: '$100.0',
  TOTAL_4: '$100.0',
  TOTAL_5: '$100.0',
  TOTAL_6: '$100.0',
}

function colX(c) {
  const g = TABLE_SINGLE_CARDS_GEOM
  if (c === 0) return g.tableX
  return g.tableX + g.labelW + g.gap + (c - 1) * (g.dataColW + g.gap)
}

function colWidth(c) {
  return c === 0 ? TABLE_SINGLE_CARDS_GEOM.labelW : TABLE_SINGLE_CARDS_GEOM.dataColW
}

function bodyRowY(r) {
  const g = TABLE_SINGLE_CARDS_GEOM
  return g.tableY + g.headerH + g.gap + r * (g.bodyRowH + g.gap)
}

function totalRowY() {
  const g = TABLE_SINGLE_CARDS_GEOM
  return g.tableY + g.headerH + g.gap + g.bodyRows * (g.bodyRowH + g.gap)
}

function isTableSingleCardsLayout(layoutId) {
  const id = String(layoutId || '')
  return /table_single_cards_v1$/i.test(id)
}

function isTableSingleCardsTextSlot(slotId) {
  const sid = String(slotId || '').toUpperCase()
  return (
    sid === 'HEADING' ||
    sid === 'SUBTITLE' ||
    /^COL_\d+_HEADER$/.test(sid) ||
    /^ROW_\d+_LABEL$/.test(sid) ||
    /^CELL_\d+_\d+$/.test(sid) ||
    sid === 'TOTAL_LABEL' ||
    /^TOTAL_\d+$/.test(sid)
  )
}

function tableSingleCardsChromeSvg() {
  const g = TABLE_SINGLE_CARDS_GEOM
  const p = TABLE_SINGLE_CARDS_PALETTE

  const pillSvg = `
    <g transform="translate(${g.pillX}, ${g.pillY})">
      <defs>
        <linearGradient id="tblCardPillGrad" x1="0%" y1="0%" x2="100%" y2="0%">
          <stop offset="0%" stop-color="#48CAE4" />
          <stop offset="50%" stop-color="#0096C7" />
          <stop offset="100%" stop-color="#023E8A" />
        </linearGradient>
      </defs>
      <rect x="0" y="0" width="${g.pillW}" height="${g.pillH}" rx="3" fill="url(#tblCardPillGrad)" />
    </g>
  `

  const headerRects = []
  for (let c = 0; c < g.cols; c += 1) {
    const x = colX(c)
    const w = colWidth(c)
    const y = g.tableY
    const h = g.headerH
    const color = p.headers[c] || p.headers[0]

    let d = ''
    if (c === 0) {
      d = `M ${x + 10},${y} L ${x + w},${y} L ${x + w},${y + h} L ${x},${y + h} L ${x},${y + 10} Q ${x},${y} ${x + 10},${y} Z`
    } else if (c === g.cols - 1) {
      d = `M ${x},${y} L ${x + w - 10},${y} Q ${x + w},${y} ${x + w},${y + 10} L ${x + w},${y + h} L ${x},${y + h} Z`
    } else {
      d = `M ${x},${y} L ${x + w},${y} L ${x + w},${y + h} L ${x},${y + h} Z`
    }

    headerRects.push(`<path d="${d}" fill="${color}" />`)
  }

  const bodyCellRects = []
  for (let r = 0; r < g.bodyRows; r += 1) {
    const y = bodyRowY(r)
    const h = g.bodyRowH
    for (let c = 0; c < g.cols; c += 1) {
      const x = colX(c)
      const w = colWidth(c)
      let fill = p.cellNormal
      if (c === 0) fill = p.col0Body
      else if (c === 3 || c === 5) fill = p.cellHighlight

      bodyCellRects.push(`<rect x="${x}" y="${y}" width="${w}" height="${h}" rx="2" fill="${fill}" />`)
    }
  }

  const totalRects = []
  const totY = totalRowY()
  const totH = g.totalRowH
  for (let c = 0; c < g.cols; c += 1) {
    const x = colX(c)
    const w = colWidth(c)
    const color = c === 0 ? p.totalCol0 : p.totalCols

    let d = ''
    if (c === 0) {
      d = `M ${x},${totY} L ${x + w},${totY} L ${x + w},${totY + totH} L ${x + 10},${totY + totH} Q ${x},${totY + totH} ${x},${totY + totH - 10} Z`
    } else if (c === g.cols - 1) {
      d = `M ${x},${totY} L ${x + w},${totY} L ${x + w},${totY + totH - 10} Q ${x + w},${totY + totH} ${x + w - 10},${totY + totH} L ${x},${totY + totH} Z`
    } else {
      d = `M ${x},${totY} L ${x + w},${totY} L ${x + w},${totY + totH} L ${x},${totY + totH} Z`
    }

    totalRects.push(`<path d="${d}" fill="${color}" />`)
  }

  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${g.viewW} ${g.viewH}" width="100%" height="100%">
    ${pillSvg}
    <g id="tableHeaders">${headerRects.join('\n')}</g>
    <g id="tableBodyCards">${bodyCellRects.join('\n')}</g>
    <g id="tableTotalBar">${totalRects.join('\n')}</g>
  </svg>`
}

function tableSingleCardsChromeSpecs() {
  const g = TABLE_SINGLE_CARDS_GEOM
  return [
    {
      slotId: 'TABLE_SINGLE_CARDS_CHROME',
      x: 0,
      y: 0,
      w: g.viewW,
      h: g.viewH,
      color: TABLE_SINGLE_CARDS_PALETTE.totalCol0,
      layer: 4,
    },
  ]
}

function tableSingleCardsOverlay(gx, gy, gw, gh) {
  const g = TABLE_SINGLE_CARDS_GEOM
  const sx = gw / g.viewW
  const sy = gh / g.viewH

  const box = (x, y, w, h) => ({
    x: Math.round(gx + x * sx),
    y: Math.round(gy + y * sy),
    width: Math.max(16, Math.round(w * sx)),
    height: Math.max(12, Math.round(h * sy)),
  })

  const heading = box(g.headingX, g.headingY, g.headingW, g.headingH)
  const subtitle = box(g.subtitleX, g.subtitleY, g.subtitleW, g.subtitleH)

  const colHeaders = []
  for (let c = 0; c < g.cols; c += 1) {
    colHeaders.push(box(colX(c) + 4, g.tableY + 4, colWidth(c) - 8, g.headerH - 8))
  }

  const rowLabels = []
  for (let r = 0; r < g.bodyRows; r += 1) {
    rowLabels.push(box(colX(0) + 12, bodyRowY(r) + 4, colWidth(0) - 24, g.bodyRowH - 8))
  }

  const cells = []
  for (let r = 0; r < g.bodyRows; r += 1) {
    const rowCells = []
    for (let c = 1; c < g.cols; c += 1) {
      rowCells.push(box(colX(c) + 4, bodyRowY(r) + 4, colWidth(c) - 8, g.bodyRowH - 8))
    }
    cells.push(rowCells)
  }

  const totY = totalRowY()
  const totalLabel = box(colX(0) + 12, totY + 4, colWidth(0) - 24, g.totalRowH - 8)
  const totalValues = []
  for (let c = 1; c < g.cols; c += 1) {
    totalValues.push(box(colX(c) + 4, totY + 4, colWidth(c) - 8, g.totalRowH - 8))
  }

  return {
    heading,
    subtitle,
    colHeaders,
    rowLabels,
    cells,
    totalLabel,
    totalValues,
  }
}

function specToTableSingleCardsContent(spec) {
  return { svg: tableSingleCardsChromeSvg(), colorMode: 'recolorable', fill: spec?.color || TABLE_SINGLE_CARDS_PALETTE.totalCol0 }
}

function plainTextFromContent(content = {}) {
  if (typeof content.text === 'string' && content.text.trim()) return content.text
  if (Array.isArray(content.runs)) {
    const joined = content.runs.map((r) => r.text || '').join('')
    if (joined.trim()) return joined
  }
  return ''
}

function filledContent(el, slotId, style) {
  const sid = String(slotId || '').toUpperCase()
  const existing = plainTextFromContent(el?.content)
  const text = existing && existing.toLowerCase() !== 'double-click to edit'
    ? existing
    : (TABLE_SINGLE_CARDS_DEFAULTS[sid] || existing || '')

  return {
    ...(el?.content || {}),
    ...style,
    text,
    runs: null,
    listType: null,
    letterSpacing: style.letterSpacing ?? '0',
    padding: 0,
    paddingX: 0,
    stroke: undefined,
    strokeWidth: 0,
  }
}

function newId(prefix) {
  return `${prefix}-${Math.random().toString(36).slice(2, 9)}`
}

function layoutTableSingleCardsElements(elements, schema, palette = {}, canvas = {}) {
  if (!Array.isArray(elements)) return elements
  const canvasW = canvas.width || 1920
  const canvasH = canvas.height || 1080
  const sx = canvasW / TABLE_SINGLE_CARDS_GEOM.viewW
  const sy = canvasH / TABLE_SINGLE_CARDS_GEOM.viewH
  const overlay = tableSingleCardsOverlay(0, 0, canvasW, canvasH)

  const chromeRe = /^TABLE_SINGLE_CARDS_CHROME$/i
  const prevBySlot = new Map(
    elements
      .filter((el) => chromeRe.test(String(el.slotId || '')))
      .map((el) => [String(el.slotId || '').toUpperCase(), el])
  )
  const filtered = elements.filter(
    (el) => !chromeRe.test(String(el.slotId || '')) && isTableSingleCardsTextSlot(el.slotId)
  )
  const bySlot = new Map(filtered.map((el) => [String(el.slotId || '').toUpperCase(), el]))

  const placeText = (slotId, box, style, role) => {
    const prev = bySlot.get(slotId)
    return {
      id: prev?.id || newId('txt-tblcrd'),
      type: 'text',
      slotId,
      role: prev?.role || role || 'body',
      layer: 12,
      placement: {
        x: box.x,
        y: box.y,
        width: box.width,
        height: box.height,
        rotation: 0,
        opacity: 1,
      },
      content: filledContent(prev, slotId, style),
    }
  }

  const next = []

  // 1. Heading & Subtitle
  next.push(
    placeText('HEADING', overlay.heading, {
      align: 'center',
      verticalAlign: 'center',
      fontSize: 28,
      fontWeight: 800,
      color: TABLE_SINGLE_CARDS_PALETTE.textDark,
      clipToSlot: true,
      lineHeight: 1.15,
    }, 'heading')
  )

  next.push(
    placeText('SUBTITLE', overlay.subtitle, {
      align: 'center',
      verticalAlign: 'center',
      fontSize: 13,
      fontWeight: 500,
      color: TABLE_SINGLE_CARDS_PALETTE.textMuted,
      clipToSlot: true,
      lineHeight: 1.25,
    }, 'subheading')
  )

  // 2. 7 Column Headers
  for (let c = 0; c < TABLE_SINGLE_CARDS_GEOM.cols; c += 1) {
    next.push(
      placeText(`COL_${c}_HEADER`, overlay.colHeaders[c], {
        align: 'center',
        verticalAlign: 'center',
        fontSize: 14,
        fontWeight: 800,
        color: '#FFFFFF',
        clipToSlot: true,
        lineHeight: 1.1,
        letterSpacing: '0.04em',
      }, 'heading')
    )
  }

  // 3. 4 Row Labels
  for (let r = 0; r < TABLE_SINGLE_CARDS_GEOM.bodyRows; r += 1) {
    const rowNum = r + 1
    next.push(
      placeText(`ROW_${rowNum}_LABEL`, overlay.rowLabels[r], {
        align: 'left',
        verticalAlign: 'center',
        fontSize: 13,
        fontWeight: 600,
        color: TABLE_SINGLE_CARDS_PALETTE.textDark,
        clipToSlot: true,
        lineHeight: 1.2,
      }, 'body')
    )
  }

  // 4. 24 Body Cells
  for (let r = 0; r < TABLE_SINGLE_CARDS_GEOM.bodyRows; r += 1) {
    const rowNum = r + 1
    for (let c = 1; c < TABLE_SINGLE_CARDS_GEOM.cols; c += 1) {
      next.push(
        placeText(`CELL_${rowNum}_${c}`, overlay.cells[r][c - 1], {
          align: 'center',
          verticalAlign: 'center',
          fontSize: 14,
          fontWeight: 600,
          color: TABLE_SINGLE_CARDS_PALETTE.textDark,
          clipToSlot: true,
          lineHeight: 1.2,
        }, 'stat')
      )
    }
  }

  // 5. Total Row
  next.push(
    placeText('TOTAL_LABEL', overlay.totalLabel, {
      align: 'center',
      verticalAlign: 'center',
      fontSize: 15,
      fontWeight: 800,
      color: '#FFFFFF',
      clipToSlot: true,
      lineHeight: 1.1,
      letterSpacing: '0.06em',
    }, 'heading')
  )

  for (let c = 1; c < TABLE_SINGLE_CARDS_GEOM.cols; c += 1) {
    next.push(
      placeText(`TOTAL_${c}`, overlay.totalValues[c - 1], {
        align: 'center',
        verticalAlign: 'center',
        fontSize: 15,
        fontWeight: 800,
        color: '#FFFFFF',
        clipToSlot: true,
        lineHeight: 1.1,
      }, 'stat')
    )
  }

  // 6. Chrome SVG
  const chrome = tableSingleCardsChromeSpecs().map((spec) => {
    const prev = prevBySlot.get(spec.slotId.toUpperCase())
    const graphic = specToTableSingleCardsContent(spec)
    return {
      id: prev?.id || newId('shp-tblcrd'),
      type: 'graphic',
      layer: spec.layer || 4,
      placement: {
        x: Math.round(spec.x * sx),
        y: Math.round(spec.y * sy),
        width: Math.max(4, Math.round(spec.w * sx)),
        height: Math.max(4, Math.round(spec.h * sy)),
        rotation: 0,
        opacity: 1,
      },
      content: {
        svg: graphic.svg,
        colorMode: graphic.colorMode,
        fill: graphic.fill,
        alt: spec.slotId,
      },
      role: 'decoration',
      slotId: spec.slotId,
    }
  })

  return [...chrome, ...next]
}

function layoutTableSingleCards(doc, layoutSchema, themeTokens, canvas = {}) {
  if (!doc) return doc
  if (Array.isArray(doc)) {
    return layoutTableSingleCardsElements(doc, layoutSchema, themeTokens?.palette || themeTokens || {}, canvas)
  }
  const palette = themeTokens?.palette || themeTokens || {}
  const size = {
    width: canvas.width || doc.canvas?.width || 1920,
    height: canvas.height || doc.canvas?.height || 1080,
  }
  return { ...doc, elements: layoutTableSingleCardsElements(doc.elements || [], layoutSchema, palette, size) }
}

module.exports = {
  TABLE_SINGLE_CARDS_GEOM,
  TABLE_SINGLE_CARDS_PALETTE,
  TABLE_SINGLE_CARDS_DEFAULTS,
  isTableSingleCardsLayout,
  isTableSingleCardsTextSlot,
  layoutTableSingleCards,
}
