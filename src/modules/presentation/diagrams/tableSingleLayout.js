/**
 * Table Single — Annual Financial Summary Table (Backend)
 * Layout ID: table_single_v1
 * Features:
 *  - Navy left bookmark ribbon with dog-ear fold and 6 circular row icons
 *  - 5 downward chevron/pentagon column badges with distinct accent colors
 *  - 6 rows with alternating soft-shaded fills and bold Net Income highlight
 *  - Clean normal slide background
 */

const TABLE_SINGLE_GEOM = {
  viewW: 1000,
  viewH: 560,
  headingX: 36,
  headingY: 16,
  headingW: 928,
  headingH: 36,
  subtitleX: 36,
  subtitleY: 52,
  subtitleW: 928,
  subtitleH: 22,

  // Left bookmark ribbon
  ribbonX: 40,
  ribbonY: 136,
  ribbonW: 60,
  ribbonH: 376,

  // Table grid
  tableX: 100,
  tableY: 152,
  tableW: 860,
  tableH: 360,

  labelW: 160,
  cols: 5,
  rows: 6,
  colW: 140, // 700 / 5 = 140
  rowH: 60,  // 360 / 6 = 60

  // Chevron badges above data columns
  badgeY: 84,
  badgeH: 68,
}

const TABLE_SINGLE_PALETTE = {
  ribbon: '#123F67',
  ribbonFold: '#0A2640',
  chevrons: ['#7CB342', '#00A3E0', '#006699', '#F58220', '#C67D00'],
  rowEven: '#EEF3F8',
  rowOdd: '#DFE7EE',
  rowHighlight: '#D2DFEB',
  divider: '#FFFFFF',
  textDark: '#1E293B',
  textMuted: '#64748B',
}

const TABLE_SINGLE_DEFAULTS = {
  HEADING: 'Annual Financial Summary Table',
  SUBTITLE: 'Revenue, Cost of Goods, Operations, Gross Profit, EBITDA, Net Income',

  COL_1_HEADER: '20XX',
  COL_2_HEADER: '20XX',
  COL_3_HEADER: '20XX',
  COL_4_HEADER: '20XX',
  COL_4_SUB: 'plan',
  COL_5_HEADER: '20XX',
  COL_5_SUB: 'fact',

  ROW_1_LABEL: 'Revenue',
  ROW_2_LABEL: 'Cost of Goods Sold',
  ROW_3_LABEL: 'Gross Profit',
  ROW_4_LABEL: 'Costs of operations',
  ROW_5_LABEL: 'EBITDA',
  ROW_6_LABEL: 'Net Income',

  CELL_1_1: '150 000 000',
  CELL_1_2: '200 000 000',
  CELL_1_3: '210 000 000',
  CELL_1_4: '350 000 000',
  CELL_1_5: '340 000 000',

  CELL_2_1: '30 000 000',
  CELL_2_2: '60 000 000',
  CELL_2_3: '60 000 000',
  CELL_2_4: '75 000 000',
  CELL_2_5: '80 000 000',

  CELL_3_1: '120 000 000',
  CELL_3_2: '140 000 000',
  CELL_3_3: '150 000 000',
  CELL_3_4: '190 000 000',
  CELL_3_5: '200 000 000',

  CELL_4_1: '30 000 000',
  CELL_4_2: '20 000 000',
  CELL_4_3: '10 000 000',
  CELL_4_4: '25 000 000',
  CELL_4_5: '30 000 000',

  CELL_5_1: '90 000 000',
  CELL_5_2: '120 000 000',
  CELL_5_3: '140 000 000',
  CELL_5_4: '190 000 000',
  CELL_5_5: '190 000 000',

  CELL_6_1: '70 000 000',
  CELL_6_2: '100 000 000',
  CELL_6_3: '110 000 000',
  CELL_6_4: '200 000 000',
  CELL_6_5: '210 000 000',
}

function isTableSingleLayout(layoutId) {
  const id = String(layoutId || '')
  if (/cards/i.test(id)) return false
  return /table_single_v1$/i.test(id)
}

function isTableSingleTextSlot(slotId) {
  const sid = String(slotId || '').toUpperCase()
  return (
    sid === 'HEADING' ||
    sid === 'SUBTITLE' ||
    /^COL_\d+_HEADER$/.test(sid) ||
    /^COL_\d+_SUB$/.test(sid) ||
    /^ROW_\d+_LABEL$/.test(sid) ||
    /^CELL_\d+_\d+$/.test(sid)
  )
}

/** Vector icons for the 6 rows on the ribbon */
function renderRibbonIcons(rx, ry, rw, rowH) {
  const cx = rx + rw / 2
  const icons = [
    // 1. Dollar Location Pin (Revenue)
    `<g transform="translate(${cx}, ${ry + 16 + rowH * 0 + rowH / 2})">
      <circle cx="0" cy="0" r="16" fill="none" stroke="#FFFFFF" stroke-width="1.8"/>
      <path d="M 0,-8 C -4,-8 -7,-5 -7,-1.5 C -7,2.5 0,8 0,8 C 0,8 7,2.5 7,-1.5 C 7,-5 4,-8 0,-8 Z" fill="#FFFFFF"/>
      <text x="0" y="1" font-size="7.5" font-weight="900" fill="#123F67" text-anchor="middle" dominant-baseline="middle" font-family="system-ui, sans-serif">$</text>
    </g>`,

    // 2. Shipping Box with Dollar (Cost of Goods Sold)
    `<g transform="translate(${cx}, ${ry + 16 + rowH * 1 + rowH / 2})">
      <circle cx="0" cy="0" r="16" fill="none" stroke="#FFFFFF" stroke-width="1.8"/>
      <path d="M-8,-2 L0,-6 L8,-2 L0,2 Z" fill="#FFFFFF"/>
      <path d="M-8,-0.5 L-8,5.5 L0,9.5 L0,3.5 Z" fill="#FFFFFF" opacity="0.85"/>
      <path d="M8,-0.5 L8,5.5 L0,9.5 L0,3.5 Z" fill="#FFFFFF" opacity="0.7"/>
      <text x="0" y="1" font-size="7" font-weight="900" fill="#123F67" text-anchor="middle" dominant-baseline="middle" font-family="system-ui, sans-serif">$</text>
    </g>`,

    // 3. Banknote / Cash Bill (Gross Profit)
    `<g transform="translate(${cx}, ${ry + 16 + rowH * 2 + rowH / 2})">
      <circle cx="0" cy="0" r="16" fill="none" stroke="#FFFFFF" stroke-width="1.8"/>
      <rect x="-8.5" y="-5" width="17" height="10" rx="1.5" fill="#FFFFFF"/>
      <circle cx="0" cy="0" r="3.5" fill="#123F67"/>
      <text x="0" y="0.5" font-size="6.5" font-weight="900" fill="#FFFFFF" text-anchor="middle" dominant-baseline="middle" font-family="system-ui, sans-serif">$</text>
    </g>`,

    // 4. Two Interlocking Gears (Costs of operations)
    `<g transform="translate(${cx}, ${ry + 16 + rowH * 3 + rowH / 2})">
      <circle cx="0" cy="0" r="16" fill="none" stroke="#FFFFFF" stroke-width="1.8"/>
      <circle cx="-2.5" cy="1" r="5" fill="#FFFFFF"/>
      <circle cx="-2.5" cy="1" r="2.2" fill="#123F67"/>
      <path d="M-4,-4 L-1,-4 L-1.5,-2.5 L-3.5,-2.5 Z M0.5,-2 L2.5,-0.5 L1.5,1 L-0.5,-0.5 Z M-5.5,5 L-3.5,6 L-4.5,4.2 L-6,3.5 Z" fill="#FFFFFF"/>
      <circle cx="4.5" cy="-3.5" r="3.6" fill="#FFFFFF"/>
      <circle cx="4.5" cy="-3.5" r="1.5" fill="#123F67"/>
    </g>`,

    // 5. Stack of Coins with Dollar (EBITDA)
    `<g transform="translate(${cx}, ${ry + 16 + rowH * 4 + rowH / 2})">
      <circle cx="0" cy="0" r="16" fill="none" stroke="#FFFFFF" stroke-width="1.8"/>
      <ellipse cx="-2" cy="-3.5" rx="5.5" ry="2.2" fill="#FFFFFF"/>
      <path d="M-7.5,-3.5 L-7.5,-0.5 C-7.5,1 -4,2.2 -2,2.2 C0,2.2 3.5,1 3.5,-0.5 L3.5,-3.5 Z" fill="#FFFFFF" opacity="0.85"/>
      <path d="M-7.5,0.5 L-7.5,3.5 C-7.5,5 -4,6.2 -2,6.2 C0,6.2 3.5,5 3.5,3.5 L3.5,0.5 Z" fill="#FFFFFF" opacity="0.7"/>
      <text x="5" y="1" font-size="7.5" font-weight="900" fill="#FFFFFF" text-anchor="middle" dominant-baseline="middle" font-family="system-ui, sans-serif">$</text>
    </g>`,

    // 6. Money Bag with Dollar (Net Income)
    `<g transform="translate(${cx}, ${ry + 16 + rowH * 5 + rowH / 2})">
      <circle cx="0" cy="0" r="16" fill="none" stroke="#FFFFFF" stroke-width="1.8"/>
      <path d="M-3,-6.5 L3,-6.5 L4,-4.5 L-4,-4.5 Z" fill="#FFFFFF"/>
      <ellipse cx="0" cy="1.5" rx="7.5" ry="6.5" fill="#FFFFFF"/>
      <text x="0" y="2" font-size="7.5" font-weight="900" fill="#123F67" text-anchor="middle" dominant-baseline="middle" font-family="system-ui, sans-serif">$</text>
    </g>`,
  ]

  return icons.join('\n')
}

/** Generates the complete background chrome SVG for Table Single */
function tableSingleChromeSvg() {
  const g = TABLE_SINGLE_GEOM
  const p = TABLE_SINGLE_PALETTE

  // 1. Alternating table row rectangles
  const rowRects = []
  for (let r = 0; r < g.rows; r += 1) {
    const y = g.tableY + r * g.rowH
    let fill = r % 2 === 0 ? p.rowEven : p.rowOdd
    if (r === g.rows - 1) fill = p.rowHighlight
    rowRects.push(`<rect x="${g.tableX}" y="${y}" width="${g.tableW}" height="${g.rowH}" fill="${fill}" />`)
  }

  // 2. Vertical column dividers
  const vDividers = []
  vDividers.push(`<line x1="${g.tableX + g.labelW}" y1="${g.tableY}" x2="${g.tableX + g.labelW}" y2="${g.tableY + g.tableH}" stroke="${p.divider}" stroke-width="1.8" />`)
  for (let c = 1; c < g.cols; c += 1) {
    const x = g.tableX + g.labelW + c * g.colW
    vDividers.push(`<line x1="${x}" y1="${g.tableY}" x2="${x}" y2="${g.tableY + g.tableH}" stroke="${p.divider}" stroke-width="1.5" />`)
  }

  // 3. Horizontal row dividers
  const hDividers = []
  for (let r = 1; r < g.rows; r += 1) {
    const y = g.tableY + r * g.rowH
    hDividers.push(`<line x1="${g.tableX}" y1="${y}" x2="${g.tableX + g.tableW}" y2="${y}" stroke="${p.divider}" stroke-width="1.2" />`)
  }

  // 4. Chevron badges above the 5 columns
  const chevrons = []
  for (let c = 0; c < g.cols; c += 1) {
    const x = g.tableX + g.labelW + c * g.colW
    const w = g.colW
    const y = g.badgeY
    const h = g.badgeH
    const arrowDepth = 14
    const color = p.chevrons[c] || p.chevrons[0]

    const path = `M ${x},${y} L ${x + w},${y} L ${x + w},${y + h - arrowDepth} L ${x + w / 2},${y + h} L ${x},${y + h - arrowDepth} Z`
    chevrons.push(`
      <g>
        <path d="${path}" fill="${color}" filter="drop-shadow(0 2px 4px rgba(0,0,0,0.12))"/>
      </g>
    `)
  }

  // 5. Left bookmark ribbon with folded dog-ear corner
  const rx = g.ribbonX
  const ry = g.ribbonY
  const rw = g.ribbonW
  const rh = g.ribbonH
  const ribbonSvg = `
    <rect x="${rx}" y="${ry + 16}" width="${rw}" height="${rh - 16}" rx="4" fill="${p.ribbon}" filter="drop-shadow(2px 3px 6px rgba(0,0,0,0.18))" />
    <path d="M ${rx},${ry + 16} L ${rx + rw},${ry + 16} L ${rx + rw},${ry} L ${rx},${ry} Z" fill="${p.ribbon}" />
    <path d="M ${rx + rw},${ry + 16} L ${rx + rw + 10},${ry + 16} L ${rx + rw},${ry + 26} Z" fill="${p.ribbonFold}" />
    ${renderRibbonIcons(rx, ry, rw, g.rowH)}
  `

  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${g.viewW} ${g.viewH}" width="100%" height="100%">
    <defs>
      <clipPath id="tableRoundedClip">
        <rect x="${g.tableX}" y="${g.tableY}" width="${g.tableW}" height="${g.tableH}" rx="10" ry="10" />
      </clipPath>
    </defs>
    <g clip-path="url(#tableRoundedClip)">
      ${rowRects.join('\n')}
      ${vDividers.join('\n')}
      ${hDividers.join('\n')}
    </g>
    <rect x="${g.tableX}" y="${g.tableY}" width="${g.tableW}" height="${g.tableH}" rx="10" ry="10" fill="none" stroke="#D7DEE7" stroke-width="1.2"/>
    ${chevrons.join('\n')}
    ${ribbonSvg}
  </svg>`
}

function tableSingleChromeSpecs() {
  const g = TABLE_SINGLE_GEOM
  return [
    {
      slotId: 'TABLE_SINGLE_CHROME',
      x: 0,
      y: 0,
      w: g.viewW,
      h: g.viewH,
      color: TABLE_SINGLE_PALETTE.ribbon,
      layer: 4,
    },
  ]
}

function tableSingleOverlay(gx, gy, gw, gh) {
  const g = TABLE_SINGLE_GEOM
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
  const colSubs = []
  for (let c = 0; c < g.cols; c += 1) {
    const x = g.tableX + g.labelW + c * g.colW
    const w = g.colW
    if (c < 3) {
      colHeaders.push(box(x + 4, g.badgeY + 10, w - 8, 36))
      colSubs.push(null)
    } else {
      colHeaders.push(box(x + 4, g.badgeY + 4, w - 8, 26))
      colSubs.push(box(x + 4, g.badgeY + 28, w - 8, 18))
    }
  }

  const rowLabels = []
  for (let r = 0; r < g.rows; r += 1) {
    const y = g.tableY + r * g.rowH
    rowLabels.push(box(g.tableX + 14, y + 4, g.labelW - 24, g.rowH - 8))
  }

  const cells = []
  for (let r = 0; r < g.rows; r += 1) {
    const rowCells = []
    const y = g.tableY + r * g.rowH
    for (let c = 0; c < g.cols; c += 1) {
      const x = g.tableX + g.labelW + c * g.colW
      rowCells.push(box(x + 6, y + 4, g.colW - 12, g.rowH - 8))
    }
    cells.push(rowCells)
  }

  return {
    heading,
    subtitle,
    colHeaders,
    colSubs,
    rowLabels,
    cells,
  }
}

function specToTableSingleContent(spec) {
  return { svg: tableSingleChromeSvg(), colorMode: 'recolorable', fill: spec?.color || TABLE_SINGLE_PALETTE.ribbon }
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
    : (TABLE_SINGLE_DEFAULTS[sid] || existing || '')

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

function layoutTableSingleElements(elements, schema, palette = {}, canvas = {}) {
  if (!Array.isArray(elements)) return elements
  const canvasW = canvas.width || 1920
  const canvasH = canvas.height || 1080
  const sx = canvasW / TABLE_SINGLE_GEOM.viewW
  const sy = canvasH / TABLE_SINGLE_GEOM.viewH
  const overlay = tableSingleOverlay(0, 0, canvasW, canvasH)

  const chromeRe = /^TABLE_SINGLE_CHROME$/i
  const prevBySlot = new Map(
    elements
      .filter((el) => chromeRe.test(String(el.slotId || '')))
      .map((el) => [String(el.slotId || '').toUpperCase(), el])
  )
  const filtered = elements.filter(
    (el) => !chromeRe.test(String(el.slotId || '')) && isTableSingleTextSlot(el.slotId)
  )
  const bySlot = new Map(filtered.map((el) => [String(el.slotId || '').toUpperCase(), el]))

  const placeText = (slotId, box, style, role) => {
    const prev = bySlot.get(slotId)
    return {
      id: prev?.id || newId('txt-tblsng'),
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
      align: 'left',
      verticalAlign: 'center',
      fontSize: 26,
      fontWeight: 800,
      color: TABLE_SINGLE_PALETTE.textDark,
      clipToSlot: true,
      lineHeight: 1.15,
    }, 'heading')
  )

  next.push(
    placeText('SUBTITLE', overlay.subtitle, {
      align: 'left',
      verticalAlign: 'center',
      fontSize: 13,
      fontWeight: 500,
      color: TABLE_SINGLE_PALETTE.textMuted,
      clipToSlot: true,
      lineHeight: 1.25,
    }, 'subheading')
  )

  // 2. Column Header Badges
  for (let c = 0; c < TABLE_SINGLE_GEOM.cols; c += 1) {
    const colNum = c + 1
    next.push(
      placeText(`COL_${colNum}_HEADER`, overlay.colHeaders[c], {
        align: 'center',
        verticalAlign: 'center',
        fontSize: c < 3 ? 20 : 18,
        fontWeight: 800,
        color: '#FFFFFF',
        clipToSlot: true,
        lineHeight: 1,
      }, 'heading')
    )

    if (overlay.colSubs[c]) {
      next.push(
        placeText(`COL_${colNum}_SUB`, overlay.colSubs[c], {
          align: 'center',
          verticalAlign: 'center',
          fontSize: 11,
          fontWeight: 600,
          color: 'rgba(255,255,255,0.92)',
          clipToSlot: true,
          lineHeight: 1,
          letterSpacing: '0.04em',
        }, 'caption')
      )
    }
  }

  // 3. Row Labels
  for (let r = 0; r < TABLE_SINGLE_GEOM.rows; r += 1) {
    const rowNum = r + 1
    const isLast = r === TABLE_SINGLE_GEOM.rows - 1
    next.push(
      placeText(`ROW_${rowNum}_LABEL`, overlay.rowLabels[r], {
        align: 'left',
        verticalAlign: 'center',
        fontSize: 13.5,
        fontWeight: isLast ? 800 : 600,
        color: TABLE_SINGLE_PALETTE.textDark,
        clipToSlot: true,
        lineHeight: 1.2,
      }, 'body')
    )
  }

  // 4. Data Cells (6 rows x 5 columns = 30 cells)
  for (let r = 0; r < TABLE_SINGLE_GEOM.rows; r += 1) {
    const rowNum = r + 1
    const isLast = r === TABLE_SINGLE_GEOM.rows - 1
    for (let c = 0; c < TABLE_SINGLE_GEOM.cols; c += 1) {
      const colNum = c + 1
      next.push(
        placeText(`CELL_${rowNum}_${colNum}`, overlay.cells[r][c], {
          align: 'center',
          verticalAlign: 'center',
          fontSize: 13.5,
          fontWeight: isLast ? 800 : 600,
          color: TABLE_SINGLE_PALETTE.textDark,
          clipToSlot: true,
          lineHeight: 1.2,
        }, 'stat')
      )
    }
  }

  // 5. SVG Chrome Element
  const chrome = tableSingleChromeSpecs().map((spec) => {
    const prev = prevBySlot.get(spec.slotId.toUpperCase())
    const graphic = specToTableSingleContent(spec)
    return {
      id: prev?.id || newId('shp-tblsng'),
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

function layoutTableSingle(doc, layoutSchema, themeTokens, canvas = {}) {
  if (!doc) return doc
  if (Array.isArray(doc)) {
    return layoutTableSingleElements(doc, layoutSchema, themeTokens?.palette || themeTokens || {}, canvas)
  }
  const palette = themeTokens?.palette || themeTokens || {}
  const size = {
    width: canvas.width || doc.canvas?.width || 1920,
    height: canvas.height || doc.canvas?.height || 1080,
  }
  return { ...doc, elements: layoutTableSingleElements(doc.elements || [], layoutSchema, palette, size) }
}

module.exports = {
  TABLE_SINGLE_GEOM,
  TABLE_SINGLE_PALETTE,
  TABLE_SINGLE_DEFAULTS,
  isTableSingleLayout,
  isTableSingleTextSlot,
  layoutTableSingle,
}
