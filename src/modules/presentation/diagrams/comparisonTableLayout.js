/** Custom shapes for comparison_table_v1 and comparison_table_grid_v1 layouts */

function isComparisonTableLayout(layoutId) {
  return /comparison_table_(?!grid)[v0-9]+$/i.test(String(layoutId || '')) || /comparison_table_grid/i.test(String(layoutId || ''))
}

function comparisonTableGeom(canvasW = 1920, canvasH = 1080, isGrid = false) {
  const sx = canvasW / 1920
  const sy = canvasH / 1080
  
  const padX = Math.round(160 * sx)
  const padY = Math.round(80 * sy)
  const headingH = Math.round(120 * sy)
  
  const contentStartY = padY + headingH + Math.round(60 * sy)
  
  const colW = Math.round(650 * sx)
  const leftX = padX
  const rightX = canvasW - padX - colW
  
  const headerH = Math.round(100 * sy)
  const rowH = Math.round(160 * sy)
  const rowGap = Math.round(20 * sy)
  
  const geom = {
    canvasW,
    canvasH,
    headingBox: { x: padX, y: padY, width: canvasW - padX * 2, height: headingH },
    leftHeader: { x: leftX, y: contentStartY, width: colW, height: headerH },
    rightHeader: { x: rightX, y: contentStartY, width: colW, height: headerH },
    rows: []
  }
  
  let currentY = contentStartY + headerH + rowGap
  
  for (let i = 0; i < 3; i++) {
    geom.rows.push({
      left: { x: leftX, y: currentY, width: colW, height: rowH },
      right: { x: rightX, y: currentY, width: colW, height: rowH },
      leftTitle: { x: leftX + Math.round(40 * sx), y: currentY + Math.round(20 * sy), width: colW - Math.round(80 * sx), height: Math.round(50 * sy) },
      leftBody: { x: leftX + Math.round(40 * sx), y: currentY + Math.round(70 * sy), width: colW - Math.round(80 * sx), height: rowH - Math.round(90 * sy) },
      rightTitle: { x: rightX + Math.round(40 * sx), y: currentY + Math.round(20 * sy), width: colW - Math.round(80 * sx), height: Math.round(50 * sy) },
      rightBody: { x: rightX + Math.round(40 * sx), y: currentY + Math.round(70 * sy), width: colW - Math.round(80 * sx), height: rowH - Math.round(90 * sy) }
    })
    currentY += rowH + rowGap
  }

  // Center Pillar
  const pillarW = Math.round(200 * sx)
  const pillarX = (canvasW - pillarW) / 2
  const pillarY = contentStartY - Math.round(40 * sy)
  const pillarH = currentY - contentStartY + Math.round(40 * sy)
  
  geom.centerPillar = { x: pillarX, y: pillarY, width: pillarW, height: pillarH }

  if (isGrid) {
    // In grid mode, the blocks stretch to the edges and touch the center pillar
    geom.leftHeader.x = 0
    geom.leftHeader.width = pillarX
    geom.rightHeader.x = pillarX + pillarW
    geom.rightHeader.width = canvasW - (pillarX + pillarW)
    
    geom.rows.forEach(r => {
      r.left.x = 0
      r.left.width = pillarX
      r.right.x = pillarX + pillarW
      r.right.width = canvasW - (pillarX + pillarW)
      
      r.leftTitle.x = Math.round(100 * sx)
      r.leftTitle.width = pillarX - Math.round(200 * sx)
      r.leftBody.x = Math.round(100 * sx)
      r.leftBody.width = pillarX - Math.round(200 * sx)
      
      r.rightTitle.x = pillarX + pillarW + Math.round(100 * sx)
      r.rightTitle.width = canvasW - (pillarX + pillarW) - Math.round(200 * sx)
      r.rightBody.x = pillarX + pillarW + Math.round(100 * sx)
      r.rightBody.width = canvasW - (pillarX + pillarW) - Math.round(200 * sx)
    })
  }

  return geom
}

const COLORS = {
  leftHeader: '#7dd3fc',
  leftRows: ['#f0f9ff', '#e0f2fe', '#bae6fd'],
  rightHeader: '#fdba74',
  rightRows: ['#fff7ed', '#ffedd5', '#fed7aa']
}

function renderPillarSvg(w, h) {
  // A white rounded pill with a subtle drop shadow
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w + 40} ${h + 40}" width="${w + 40}" height="${h + 40}" style="overflow:visible">
    <defs>
      <filter id="shadow" x="-20%" y="-20%" width="140%" height="140%">
        <feDropShadow dx="0" dy="10" stdDeviation="15" flood-color="#000000" flood-opacity="0.1" />
      </filter>
    </defs>
    <rect x="20" y="20" width="${w}" height="${h}" rx="24" fill="#ffffff" filter="url(#shadow)" />
    
    <!-- "Vs" Text -->
    <text x="${w/2 + 20}" y="100" font-size="48" font-weight="700" fill="#a0aec0" font-family="system-ui, sans-serif" text-anchor="middle">Vs</text>
    
    <!-- Bar Chart Icon -->
    <g transform="translate(${w/2 + 20 - 32}, 210) scale(2.5)" fill="#374151">
      <path d="M4 22H2V12h2v10zM8 22H6V8h2v14zM12 22h-2V4h2v18zM16 22h-2v-6h2v6zM20 22h-2v-9h2v9zM24 22h-2v-4h2v4z"/>
    </g>

    <!-- Gears Icon -->
    <g transform="translate(${w/2 + 20 - 32}, 390) scale(2.5)" fill="#374151">
      <path d="M12 15.5c-1.93 0-3.5-1.57-3.5-3.5s1.57-3.5 3.5-3.5 3.5 1.57 3.5 3.5-1.57 3.5-3.5 3.5zm7.66-2.5l2.25-1.74c.2-.16.26-.44.13-.67l-2.12-3.69c-.12-.22-.39-.31-.62-.22l-2.65 1.07c-.55-.42-1.16-.76-1.81-1.02l-.4-2.82c-.03-.25-.25-.44-.5-.44H9.06c-.25 0-.47.19-.5.44l-.4 2.82c-.65.26-1.26.6-1.81 1.02l-2.65-1.07c-.23-.09-.5 0-.62.22L.96 10.6c-.13.23-.07.51.13.67l2.25 1.74c-.04.35-.06.7-.06 1.06s.02.71.06 1.06L1.09 16.87c-.2.16-.26.44-.13.67l2.12 3.69c.12.22.39.31.62.22l2.65-1.07c.55.42 1.16.76 1.81 1.02l.4 2.82c.03.25.25.44.5.44h4.88c.25 0 .47-.19.5-.44l.4-2.82c.65-.26 1.26-.6 1.81-1.02l2.65 1.07c.23.09.5 0 .62-.22l2.12-3.69c.13-.23.07-.51-.13-.67l-2.25-1.74c.04-.35.06-.7.06-1.06s-.02-.71-.06-1.06z"/>
    </g>
    
    <!-- Lightbulb Icon -->
    <g transform="translate(${w/2 + 20 - 32}, 570) scale(2.5)" fill="#374151">
      <path d="M12 22c1.1 0 2-.9 2-2h-4c0 1.1.9 2 2 2zm-3-4h6v-2H9v2zm3-15C8.13 3 5 6.13 5 10c0 2.38 1.19 4.47 3 5.74V17c0 .55.45 1 1 1h6c.55 0 1-.45 1-1v-1.26c1.81-1.27 3-3.36 3-5.74 0-3.87-3.13-7-7-7z"/>
    </g>
  </svg>`
}

function renderBoxSvg(w, h, color, radius = 16) {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="${w}" height="${h}">
    <rect x="0" y="0" width="${w}" height="${h}" rx="${radius}" fill="${color}" />
  </svg>`
}

function layoutComparisonTable(docOrElements, schema, themeTokens, canvas = {}) {
  let elements = Array.isArray(docOrElements) ? docOrElements : docOrElements?.elements;
  if (!Array.isArray(elements)) return docOrElements;

  const canvasW = canvas.width || 1920
  const canvasH = canvas.height || 1080
  const layoutId = String(schema?.layout_id || '')
  
  if (!isComparisonTableLayout(layoutId)) return docOrElements;
  
  const isGrid = /grid/i.test(layoutId)
  const g = comparisonTableGeom(canvasW, canvasH, isGrid)
  const radius = isGrid ? 0 : 16
  
  let out = []

  elements.forEach((el) => {
    const slotId = String(el.slotId || '').toUpperCase()
    
    if (slotId === 'HEADING') {
      out.push({ ...el, layer: 10, placement: { ...g.headingBox, rotation: 0, opacity: 1 } })
      return
    }

    if (slotId === 'LEFT_HEADER') {
      out.push({ ...el, layer: 10, placement: { ...g.leftHeader, rotation: 0, opacity: 1 }, content: { ...el.content, color: '#ffffff', align: 'center', verticalAlign: 'middle' } })
      return
    }
    if (slotId === 'RIGHT_HEADER') {
      out.push({ ...el, layer: 10, placement: { ...g.rightHeader, rotation: 0, opacity: 1 }, content: { ...el.content, color: '#ffffff', align: 'center', verticalAlign: 'middle' } })
      return
    }

    const rowMatch = slotId.match(/^ROW_(\d+)_(LEFT|RIGHT)_(TITLE|BODY)$/)
    if (rowMatch) {
      const rIdx = parseInt(rowMatch[1], 10) - 1
      const side = rowMatch[2].toLowerCase()
      const type = rowMatch[3]
      
      const rowGeom = g.rows[rIdx]
      if (!rowGeom) return
      
      const geomKey = side + (type === 'TITLE' ? 'Title' : 'Body')
      
      let newEl = {
        ...el,
        layer: 10,
        placement: { ...rowGeom[geomKey], rotation: 0, opacity: 1 },
      }
      
      if (newEl.type === 'shape' || newEl.type === 'text') {
        newEl.content = {
          ...newEl.content,
          color: '#1f2937',
          colorOverride: true,
          align: 'center'
        }
      }
      
      out.push(newEl)
      return
    }

    // Don't push old decorative shapes if we're going to regenerate them
    if (el.role === 'decoration' && String(el.id).startsWith('shp-')) {
      return;
    }

    out.push(el)
  })

  // Add the background boxes
  out.unshift({
    id: 'shp-left-header',
    type: 'graphic',
    layer: 2,
    role: 'decoration',
    placement: { ...g.leftHeader, rotation: 0, opacity: 1 },
    content: { svg: renderBoxSvg(g.leftHeader.width, g.leftHeader.height, COLORS.leftHeader, radius), colorMode: 'preserve' }
  })
  out.unshift({
    id: 'shp-right-header',
    type: 'graphic',
    layer: 2,
    role: 'decoration',
    placement: { ...g.rightHeader, rotation: 0, opacity: 1 },
    content: { svg: renderBoxSvg(g.rightHeader.width, g.rightHeader.height, COLORS.rightHeader, radius), colorMode: 'preserve' }
  })

  g.rows.forEach((r, i) => {
    out.unshift({
      id: `shp-left-row-${i}`,
      type: 'graphic',
      layer: 2,
      role: 'decoration',
      placement: { ...r.left, rotation: 0, opacity: 1 },
      content: { svg: renderBoxSvg(r.left.width, r.left.height, COLORS.leftRows[i], radius), colorMode: 'preserve' }
    })
    out.unshift({
      id: `shp-right-row-${i}`,
      type: 'graphic',
      layer: 2,
      role: 'decoration',
      placement: { ...r.right, rotation: 0, opacity: 1 },
      content: { svg: renderBoxSvg(r.right.width, r.right.height, COLORS.rightRows[i], radius), colorMode: 'preserve' }
    })
  })

  // Add Center Pillar
  out.push({
    id: 'shp-center-pillar',
    type: 'graphic',
    layer: 5,
    role: 'decoration',
    placement: { ...g.centerPillar, x: g.centerPillar.x - 20, y: g.centerPillar.y - 20, width: g.centerPillar.width + 40, height: g.centerPillar.height + 40, rotation: 0, opacity: 1 },
    content: { svg: renderPillarSvg(g.centerPillar.width, g.centerPillar.height), colorMode: 'preserve' }
  })

  if (Array.isArray(docOrElements)) {
    return out;
  }
  return { ...docOrElements, elements: out };
}

module.exports = {
  isComparisonTableLayout,
  comparisonTableGeom,
  layoutComparisonTable
}
