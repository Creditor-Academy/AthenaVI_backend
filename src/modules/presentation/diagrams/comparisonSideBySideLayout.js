function isComparisonSideBySideLayout(layoutId) {
  return /comparison_side_by_side/i.test(layoutId)
}

function renderCardSvg(w, h, color) {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w + 40} ${h + 40}" width="${w + 40}" height="${h + 40}" style="overflow:visible">
    <defs>
      <filter id="shadow" x="-20%" y="-20%" width="140%" height="140%">
        <feDropShadow dx="0" dy="16" stdDeviation="24" flood-color="#000000" flood-opacity="0.05" />
      </filter>
    </defs>
    <rect x="20" y="20" width="${w}" height="${h}" rx="24" fill="${color}" filter="url(#shadow)" opacity="0.3" />
    <path d="M44,20 L${w-4},20" stroke="${color}" stroke-width="4" stroke-linecap="round" />
  </svg>`
}

function comparisonSideBySideGeom(canvasW = 1920, canvasH = 1080) {
  const sx = canvasW / 1920
  const sy = canvasH / 1080
  
  const padX = Math.round(160 * sx)
  const padY = Math.round(100 * sy)
  const headingH = Math.round(120 * sy)
  
  const contentStartY = padY + headingH + Math.round(60 * sy)
  const contentH = canvasH - contentStartY - padY
  
  const colGap = Math.round(120 * sx)
  const colW = (canvasW - padX * 2 - colGap) / 2
  
  // Padding inside cards (if variant is cards)
  const cardPadX = Math.round(60 * sx)
  const cardPadY = Math.round(60 * sy)
  
  const textColW = colW - cardPadX * 2
  const titleH = Math.round(80 * sy)
  const bodyH = contentH - cardPadY * 2 - titleH - Math.round(20 * sy)
  
  const geom = {
    canvasW,
    canvasH,
    headingBox: { x: padX, y: padY, width: canvasW - padX * 2, height: headingH },
    
    leftCard: { x: padX, y: contentStartY, width: colW, height: contentH },
    rightCard: { x: padX + colW + colGap, y: contentStartY, width: colW, height: contentH },
    
    leftTitle: { x: padX + cardPadX, y: contentStartY + cardPadY, width: textColW, height: titleH },
    leftBody: { x: padX + cardPadX, y: contentStartY + cardPadY + titleH + Math.round(20 * sy), width: textColW, height: bodyH },
    
    rightTitle: { x: padX + colW + colGap + cardPadX, y: contentStartY + cardPadY, width: textColW, height: titleH },
    rightBody: { x: padX + colW + colGap + cardPadX, y: contentStartY + cardPadY + titleH + Math.round(20 * sy), width: textColW, height: bodyH },
    
    // Centerline geometry
    centerline: {
      x: canvasW / 2,
      y: contentStartY + Math.round(40 * sy),
      width: 2,
      height: contentH - Math.round(80 * sy)
    }
  }

  return geom
}

const COLORS = {
  left: '#3b82f6', // Pastel blue base
  right: '#a855f7' // Pastel purple base
}

function layoutComparisonSideBySide(docOrElements, schema, themeTokens, canvas = {}) {
  let elements = Array.isArray(docOrElements) ? docOrElements : docOrElements?.elements;
  if (!Array.isArray(elements)) return docOrElements;

  const canvasW = canvas.width || 1920
  const canvasH = canvas.height || 1080
  const layoutId = String(schema?.layout_id || '')
  
  const isCards = /_cards/i.test(layoutId)
  const isCenterline = /_centerline/i.test(layoutId)
  
  const g = comparisonSideBySideGeom(canvasW, canvasH)
  
  let out = []

  elements.forEach((el) => {
    const slotId = String(el.slotId || '').toUpperCase()
    
    if (slotId === 'HEADING') {
      out.push({ ...el, layer: 10, placement: { ...g.headingBox, rotation: 0, opacity: 1 }, content: { ...el.content, align: 'center' } })
      return
    }

    if (slotId === 'LEFT_TITLE') {
      out.push({ ...el, layer: 10, placement: { ...g.leftTitle, rotation: 0, opacity: 1 }, content: { ...el.content, color: isCards ? COLORS.left : undefined, colorOverride: isCards, align: 'center' } })
      return
    }
    
    if (slotId === 'LEFT_BODY') {
      out.push({ ...el, layer: 10, placement: { ...g.leftBody, rotation: 0, opacity: 1 } })
      return
    }
    
    if (slotId === 'RIGHT_TITLE') {
      out.push({ ...el, layer: 10, placement: { ...g.rightTitle, rotation: 0, opacity: 1 }, content: { ...el.content, color: isCards ? COLORS.right : undefined, colorOverride: isCards, align: 'center' } })
      return
    }
    
    if (slotId === 'RIGHT_BODY') {
      out.push({ ...el, layer: 10, placement: { ...g.rightBody, rotation: 0, opacity: 1 } })
      return
    }

    if (el.role === 'decoration' && String(el.id).startsWith('shp-')) {
      return;
    }

    out.push(el)
  })

  if (isCards) {
    out.unshift({
      id: 'shp-left-card',
      type: 'graphic',
      layer: 2,
      role: 'decoration',
      placement: { ...g.leftCard, x: g.leftCard.x - 20, y: g.leftCard.y - 20, width: g.leftCard.width + 40, height: g.leftCard.height + 40, rotation: 0, opacity: 1 },
      content: { svg: renderCardSvg(g.leftCard.width, g.leftCard.height, COLORS.left), colorMode: 'preserve' }
    })
    
    out.unshift({
      id: 'shp-right-card',
      type: 'graphic',
      layer: 2,
      role: 'decoration',
      placement: { ...g.rightCard, x: g.rightCard.x - 20, y: g.rightCard.y - 20, width: g.rightCard.width + 40, height: g.rightCard.height + 40, rotation: 0, opacity: 1 },
      content: { svg: renderCardSvg(g.rightCard.width, g.rightCard.height, COLORS.right), colorMode: 'preserve' }
    })
  }

  if (isCenterline) {
    out.unshift({
      id: 'shp-centerline',
      type: 'shape',
      layer: 2,
      role: 'decoration',
      placement: { ...g.centerline, rotation: 0, opacity: 0.2 },
      content: { shape: 'rectangle', fill: '#6b7280' }
    })
  }

  if (!isCards && !isCenterline) {
    // Default mode: just a subtle line above each title
    out.unshift({
      id: 'shp-left-line',
      type: 'shape',
      layer: 2,
      role: 'decoration',
      placement: { x: g.leftTitle.x + g.leftTitle.width / 2 - 40, y: g.leftTitle.y - 20, width: 80, height: 4, rotation: 0, opacity: 1 },
      content: { shape: 'rectangle', fill: COLORS.left }
    })
    
    out.unshift({
      id: 'shp-right-line',
      type: 'shape',
      layer: 2,
      role: 'decoration',
      placement: { x: g.rightTitle.x + g.rightTitle.width / 2 - 40, y: g.rightTitle.y - 20, width: 80, height: 4, rotation: 0, opacity: 1 },
      content: { shape: 'rectangle', fill: COLORS.right }
    })
  }

  if (Array.isArray(docOrElements)) {
    return out;
  }
  return { ...docOrElements, elements: out };
}

module.exports = {
  isComparisonSideBySideLayout,
  comparisonSideBySideGeom,
  layoutComparisonSideBySide
}
