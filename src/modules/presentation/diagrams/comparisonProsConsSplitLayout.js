function isComparisonProsConsSplitLayout(layoutId) {
  return /comparison_pros_cons_split/i.test(layoutId)
}

function renderSplitBackgroundSvg(w, h, colorTop, colorBottom) {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="${w}" height="${h}">
    <rect x="0" y="0" width="${w}" height="${h/2}" fill="${colorTop}" opacity="0.2" />
    <rect x="0" y="${h/2}" width="${w}" height="${h/2}" fill="${colorBottom}" opacity="0.2" />
  </svg>`
}

function renderBigArrowSvg(w, h, color, direction) {
  const arrowHeadH = h * 0.4
  const arrowStemW = w * 0.8
  const offset = (w - arrowStemW) / 2
  
  let path = ''
  if (direction === 'UP') {
    path = `M0,${arrowHeadH} L${w/2},0 L${w},${arrowHeadH} L${w-offset},${arrowHeadH} L${w-offset},${h} L${offset},${h} L${offset},${arrowHeadH} Z`
  } else {
    path = `M${offset},0 L${w-offset},0 L${w-offset},${h-arrowHeadH} L${w},${h-arrowHeadH} L${w/2},${h} L0,${h-arrowHeadH} L${offset},${h-arrowHeadH} Z`
  }

  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="${w}" height="${h}" style="overflow:visible">
    <defs>
      <filter id="shadow" x="-20%" y="-20%" width="140%" height="140%">
        <feDropShadow dx="0" dy="8" stdDeviation="16" flood-color="#000000" flood-opacity="0.15" />
      </filter>
    </defs>
    <path d="${path}" fill="${color}" filter="url(#shadow)" />
  </svg>`
}

function comparisonProsConsSplitGeom(canvasW = 1920, canvasH = 1080) {
  const sx = canvasW / 1920
  const sy = canvasH / 1080
  
  const padX = Math.round(80 * sx)
  const padY = Math.round(80 * sy)
  const headingH = Math.round(120 * sy)
  
  const contentStartY = padY + headingH + Math.round(40 * sy)
  const contentH = canvasH - contentStartY
  
  const halfH = contentH / 2
  const topY = contentStartY
  const bottomY = contentStartY + halfH
  
  // Left arrow blocks
  const arrowW = Math.round(450 * sx)
  const arrowH = Math.round(300 * sy)
  
  // Center arrows vertically within their halves
  const arrowTopY = topY + (halfH - arrowH) / 2
  const arrowBottomY = bottomY + (halfH - arrowH) / 2
  
  // Text columns on right
  const textColsStartX = arrowW + Math.round(120 * sx)
  const availableW = canvasW - textColsStartX - padX
  const colW = Math.round(availableW / 3) - Math.round(40 * sx)
  
  const geom = {
    canvasW,
    canvasH,
    headingBox: { x: padX, y: padY, width: canvasW - padX * 2, height: headingH },
    background: { x: 0, y: contentStartY, width: canvasW, height: contentH },
    prosArrow: { x: padX, y: arrowTopY, width: arrowW, height: arrowH },
    consArrow: { x: padX, y: arrowBottomY, width: arrowW, height: arrowH },
    rows: []
  }
  
  for (let r = 0; r < 3; r++) {
    const colX = textColsStartX + r * (colW + Math.round(40 * sx))
    
    geom.rows.push({
      prosTitle: { x: colX, y: topY + Math.round(80 * sy), width: colW, height: Math.round(40 * sy) },
      prosBody: { x: colX, y: topY + Math.round(130 * sy), width: colW, height: Math.round(100 * sy) },
      consTitle: { x: colX, y: bottomY + Math.round(80 * sy), width: colW, height: Math.round(40 * sy) },
      consBody: { x: colX, y: bottomY + Math.round(130 * sy), width: colW, height: Math.round(100 * sy) },
      prosIcon: { x: colX - Math.round(50 * sx), y: topY + Math.round(80 * sy) },
      consIcon: { x: colX - Math.round(50 * sx), y: bottomY + Math.round(80 * sy) }
    })
  }

  return geom
}

const COLORS = {
  top: '#06b6d4', // Cyan
  bottom: '#f97316' // Orange
}

function layoutComparisonProsConsSplit(docOrElements, schema, themeTokens, canvas = {}) {
  let elements = Array.isArray(docOrElements) ? docOrElements : docOrElements?.elements;
  if (!Array.isArray(elements)) return docOrElements;

  const canvasW = canvas.width || 1920
  const canvasH = canvas.height || 1080
  const layoutId = String(schema?.layout_id || '')
  
  if (!isComparisonProsConsSplitLayout(layoutId)) return docOrElements;
  
  const g = comparisonProsConsSplitGeom(canvasW, canvasH)
  
  let out = []

  elements.forEach((el) => {
    const slotId = String(el.slotId || '').toUpperCase()
    
    if (slotId === 'HEADING') {
      out.push({ ...el, layer: 10, placement: { ...g.headingBox, rotation: 0, opacity: 1 } })
      return
    }

    const rowMatch = slotId.match(/^(PROS|CONS)_(\d+)_(TITLE|BODY)$/)
    if (rowMatch) {
      const side = rowMatch[1] // PROS or CONS
      const rIdx = parseInt(rowMatch[2], 10) - 1
      const type = rowMatch[3]
      
      const rowGeom = g.rows[rIdx]
      if (!rowGeom) return
      
      const geomKey = side.toLowerCase() + (type === 'TITLE' ? 'Title' : 'Body')
      
      let newEl = {
        ...el,
        layer: 10,
        placement: { ...rowGeom[geomKey], rotation: 0, opacity: 1 },
      }
      
      if (newEl.type === 'shape' || newEl.type === 'text') {
        if (type === 'TITLE') {
          newEl.content = {
            ...newEl.content,
            color: side === 'PROS' ? COLORS.top : COLORS.bottom,
            colorOverride: true
          }
        }
      }
      
      out.push(newEl)
      return
    }

    if (el.role === 'decoration' && String(el.id).startsWith('shp-')) {
      return;
    }

    out.push(el)
  })

  // Add Background Split
  out.unshift({
    id: 'shp-split-bg',
    type: 'graphic',
    layer: 1,
    role: 'decoration',
    placement: { ...g.background, rotation: 0, opacity: 1 },
    content: { svg: renderSplitBackgroundSvg(g.background.width, g.background.height, COLORS.top, COLORS.bottom), colorMode: 'preserve' }
  })

  // Add Left Arrows
  out.unshift({
    id: 'shp-pros-arrow',
    type: 'graphic',
    layer: 2,
    role: 'decoration',
    placement: { ...g.prosArrow, rotation: 0, opacity: 1 },
    content: { svg: renderBigArrowSvg(g.prosArrow.width, g.prosArrow.height, COLORS.top, 'UP'), colorMode: 'preserve' }
  })
  // Add PROS text
  out.unshift({
    id: 'txt-pros-arrow',
    type: 'text',
    layer: 3,
    role: 'decoration',
    placement: { x: g.prosArrow.x, y: g.prosArrow.y + g.prosArrow.height * 0.6, width: g.prosArrow.width, height: 100, rotation: 0, opacity: 1 },
    content: { html: 'PROS', align: 'center', verticalAlign: 'middle', fontSize: 60, color: '#ffffff', colorOverride: true, fontWeight: 800 }
  })

  out.unshift({
    id: 'shp-cons-arrow',
    type: 'graphic',
    layer: 2,
    role: 'decoration',
    placement: { ...g.consArrow, rotation: 0, opacity: 1 },
    content: { svg: renderBigArrowSvg(g.consArrow.width, g.consArrow.height, COLORS.bottom, 'DOWN'), colorMode: 'preserve' }
  })
  // Add CONS text
  out.unshift({
    id: 'txt-cons-arrow',
    type: 'text',
    layer: 3,
    role: 'decoration',
    placement: { x: g.consArrow.x, y: g.consArrow.y + g.consArrow.height * 0.2, width: g.consArrow.width, height: 100, rotation: 0, opacity: 1 },
    content: { html: 'CONS', align: 'center', verticalAlign: 'middle', fontSize: 60, color: '#ffffff', colorOverride: true, fontWeight: 800 }
  })
  
  // Add check/cross icons
  g.rows.forEach((r, i) => {
    out.unshift({
      id: `shp-pros-icon-${i}`,
      type: 'graphic',
      layer: 2,
      role: 'decoration',
      placement: { x: r.prosIcon.x, y: r.prosIcon.y, width: 32, height: 32, rotation: 0, opacity: 1 },
      content: { svg: `<svg viewBox="0 0 24 24" fill="none" stroke="${COLORS.top}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>`, colorMode: 'preserve' }
    })
    out.unshift({
      id: `shp-cons-icon-${i}`,
      type: 'graphic',
      layer: 2,
      role: 'decoration',
      placement: { x: r.consIcon.x, y: r.consIcon.y, width: 32, height: 32, rotation: 0, opacity: 1 },
      content: { svg: `<svg viewBox="0 0 24 24" fill="none" stroke="${COLORS.bottom}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>`, colorMode: 'preserve' }
    })
  })

  if (Array.isArray(docOrElements)) {
    return out;
  }
  return { ...docOrElements, elements: out };
}

module.exports = {
  isComparisonProsConsSplitLayout,
  comparisonProsConsSplitGeom,
  layoutComparisonProsConsSplit
}
